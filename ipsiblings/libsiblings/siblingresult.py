# libsiblings/siblingresult.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#
import hashlib
import pathlib


class SiblingResult(object):
    """
    This class is intended to store calculated results and other class members.
    """

    resultfile: str = None

    def __init__(
            self, ip4, ip6, port4, port6, tcpopts4, tcpopts6, sibcand_result_dict=None, domains=None,
            ssh_available=None, ssh_keys=None, trace_set_id=None
    ):
        """
        If sibcand_result_dict is None, the results must be loaded from the accompanying results file.
        """
        self.ip4 = ip4
        self.ip6 = ip6
        self.port4 = port4
        self.port6 = port6
        self.tcpopts4 = tcpopts4
        self.tcpopts6 = tcpopts6
        self.results = sibcand_result_dict
        self.domains = domains
        self.ssh_available = ssh_available
        self.ssh_keys = ssh_keys
        self.trace_set_id = trace_set_id

        if self.ip4 and self.ip6 and self.port4 and self.port6:
            str_to_hash = '{0}_{1}_{2}_{3}'.format(self.ip4, self.port4, self.ip6, self.port6)
            h = hashlib.md5()
            h.update(str_to_hash.encode('utf-8'))
            self.id = h.hexdigest()
        else:
            self.id = None

    def __getstate__(self):
        # modify __dict__ before pickling
        # we do not want to have self.results pickled because file size may increase heavily
        state = self.__dict__.copy()
        del state['results']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)

    @property
    def X(self):
        return self.results

    def append_data(self, outfile, keys, delimiter=';', newline=True):
        outlist = [self.id]
        for key in keys:
            try:
                outlist.append(str(self.results[key]))
            except KeyError:
                outlist.append('')

        outfile.write(delimiter.join(outlist))
        if newline:
            outfile.write('\n')

        self.resultfile = pathlib.Path(outfile.name).name  # keep filename
