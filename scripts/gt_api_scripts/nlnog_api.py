#!/usr/bin/env python3

import io
import sys
import json
import ipaddress
import urllib.request


def usage(commands):
  print('Usage: {0} <command> [<command arg>]'.format(sys.argv[0]))
  print('Available Commands:')
  for k, v in commands.items():
    print('\t{0:55}: {1}'.format(k, v))



def main():
  API = 'https://api.ring.nlnog.net'

  # always do this to retrieve the correct API url from possible redirections, additionally checks connectivity
  try:
    httpresp = urllib.request.urlopen(API)
    cmd_json = json.loads(io.BytesIO(httpresp.read()).getvalue().decode('utf-8'))
  except Exception as e:
    print('Error while contacting API [{0}]: {1} - {2}'.format(API, type(e).__name__, e), file = sys.stderr)
    return 1

  len_argv = len(sys.argv)
  if len_argv != 2:
    usage(cmd_json)
    return 1

  if httpresp.url != API:
    API = httpresp.url
    print('Received current API version URL: {0}'.format(API), file = sys.stderr)

  cmd = sys.argv[1]

  req_url = '{0}/{1}'.format(API, cmd).strip('/') # strip possible '/'

  print('Requesting data from: {0}'.format(req_url), file = sys.stderr)

  httpresponse = urllib.request.urlopen(req_url)
  response = json.loads(io.BytesIO(httpresponse.read()).getvalue().decode('utf-8'))
  # basic structure:
  # { 'info': {'resultcount': x, 'success': 1}, 'results': {'command_keyword': [ <list of items type(str or dict) ] } }

  # resultcount = response['info']['resultcount']
  results = response['results'][list(response['results'].keys())[0]] # always consists of (only one!) key and the values [list of result structures]

  processed_results = 0
  if type(results) == list:
    if results and type(results[0]) == dict: # used for nodes
      for entry in results:
        if cmd.startswith('nodes'):
          if process_node(entry):
            processed_results = processed_results + 1
        else:
          print(entry)
    else:
      print(results)
  else:
    print(results)

  if cmd.startswith('nodes'):
    print('Processed results: {0}'.format(processed_results), file = sys.stderr)

  return 0


def process_node(node):
  # dict keys for nodes/active (sample entry)
  # {'active': 1, 'asn': 237, 'city': 'Ann Arbor', 'countrycode': 'US', 'datacenter': None, 'geo': '42.248588,-83.736888', 'hostname': 'merit01.ring.nlnog.net', 'id': 150, 'ipv4': '192.122.200.171', 'ipv6': '2001:48a8:7fff:13::3', 'participant': 131, 'statecode': None}
  try:
    print('{0},{1},{2}'.format(node['hostname'], ipaddress.ip_address(node['ipv4'].strip()), ipaddress.ip_address(node['ipv6'].strip())))
    return True
  except Exception as e:
    print('IGNORING NODE [{host}, {city}, {cc}] -> Error: {0} - {1}'.format(type(e).__name__, e, host = node['hostname'], city = node['city'], cc = node['countrycode']), file = sys.stderr)
    return False



if __name__ == "__main__":
  sys.exit(main())

# response structure for e.g. nodes:
# {
# "info": {
#   "resultcount": 478,
#   "success": 1
# },
# "results": {
#   "nodes": [
#     {
#       "active": 1,
#       "asn": 50156,
#       "city": "Zaventem",
#       "countrycode": "BE",
#       "datacenter": "Unix-Solutions Datacenter",
#       "geo": "50.875425,4.499401",
#       "hostname": "boxed-it01.ring.nlnog.net",
#       "id": 68,
#       "ipv4": "195.200.224.123",
#       "ipv6": "2001:67c:344:1010:5054:ff:feca:6f60",
#       "participant": 66,
#       "statecode": null
#     },
#
#     ...
#
#     ]
#   }
# }

# response structure error case:
# {
#   "info": {
#     "errormessage": "Error connecting to database: (2005, \"Unknown MySQL server host 'not.the.db.server.ring.nlnog.net' (2)\")",
#     "success": 0
#   }
# }
