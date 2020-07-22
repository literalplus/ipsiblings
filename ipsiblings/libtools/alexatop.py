import io
import urllib.request
import zipfile

from . import network
from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


def load_alexa_top_list(url=const.ALEXA_URL, filename=const.ALEXA_FILE_NAME):
    """
    Loads the Alexa Top Million List from the given url and returns
    a generator yielding each domain name in ascending order.
    If no url is given libconstants.ALEXA_URL is used.
    http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
    If no filename is given libconstants.ALEXA_FILE_NAME is used (top-1m.csv).
    """
    # top-1m.csv structure:
    # position,domain
    httpresponse = urllib.request.urlopen(url)
    with zipfile.ZipFile(io.BytesIO(httpresponse.read())) as zf:
        with zf.open(filename) as csvfile:
            for line in csvfile.readlines():
                yield line.decode('utf-8')  # .split(',')[0] # domain only


def resolve_top_list_records(top_list, filename=None):
    resolved = []

    for entry in top_list:
        pos, domain = entry.split(',')
        ips = network.resolve_host_dual(domain)
        if not ips:
            continue

        record = (pos, domain, str(ips[0]), str(ips[1]))
        resolved.append(record)

    if filename:
        with open(filename, mode="w") as out:
            for record in resolved:
                out.write(','.join(record))
                out.write('\n')

    return resolved
