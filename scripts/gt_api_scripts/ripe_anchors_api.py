#!/usr/bin/env python3

import io
import sys
import json
import ipaddress
import urllib.request

def main():
  URL = 'https://atlas.ripe.net/api/v2/anchors?format=json'
  anchors = []

  while URL:
    try:
      httpresp = urllib.request.urlopen(URL)
      anchors_json = json.loads(io.BytesIO(httpresp.read()).getvalue().decode('utf-8'))
    except Exception as e:
      print('Error [{0}]: {1} - {2}'.format(URL, type(e).__name__, e), file = sys.stderr)
      return 1

    if not 'error' in anchors_json:
      count = anchors_json['count']
      anchors_temp = anchors_json['results']
      URL = anchors_json['next'] # https://atlas.ripe.net/api/v2/anchors?format=json&page={2,3,4,5,None}
    else:
      print('Request returned error:', file = sys.stderr)
      print('Status: {0}, Code: {1}, Detail: {2}, Title: {3}'.format(anchors_json['error']['status'], anchors_json['error']['code'], anchors_json['error']['detail'], anchors_json['error']['title']), file = sys.stderr)
      # return 1 # do not return here because we may have already queried some anchors

    anchors.extend(anchors_temp)

  if len(anchors) == count:
    print('Successfully fetched all anchor nodes! Now processing filters ...', file = sys.stderr)
  else:
    print('Could only fetch [{0}] nodes of [{1}]'.format(len(anchors), count), file = sys.stderr)

  anchor_counter = 0
  for entry in anchors:
    if entry['is_disabled']:
      print('IGNORED (disabled): {0}, City: {1}, Country: {2}'.format(entry['fqdn'], entry['city'], entry['country']), file = sys.stderr)
      continue
    if entry['is_ipv4_only']:
      print('IGNORED (IPv4 only): {0}, City: {1}, Country: {2}'.format(entry['fqdn'], entry['city'], entry['country']), file = sys.stderr)
      continue

    try:
      print('{0},{1},{2}'.format(entry['fqdn'], ipaddress.ip_address(entry['ip_v4'].strip()), ipaddress.ip_address(entry['ip_v6'].strip())))
      anchor_counter = anchor_counter + 1
    except ValueError as e:
      print('IGNORED ({exc}): {0}, City: {1}, Country: {2}'.format(entry['fqdn'], entry['city'], entry['country'], exc = e), file = sys.stderr)

  print('Processed [{0} of {1}] anchors'.format(anchor_counter, count), file = sys.stderr)

  return 0


if __name__ == '__main__':
  sys.exit(main())

# sample entry in anchor results:
# {
#   "count": 438,
#   "next": "https://atlas.ripe.net/api/v2/anchors?page=2",
#   "previous": null,
#   "results": [
#   {
#     "id": 1213,
#     "type": "Anchor",
#     "fqdn": "ae-dxb-as42473.anchors.atlas.ripe.net",
#     "probe": 6392,
#     "is_ipv4_only": false,
#     "ip_v4": "37.252.245.94",
#     "as_v4": 42473,
#     "ip_v4_gateway": "37.252.245.93",
#     "ip_v4_netmask": "255.255.255.252",
#     "ip_v6": "2a00:11c0:14:aa3::a",
#     "as_v6": 42473,
#     "ip_v6_gateway": "2a00:11c0:14:aa3::1",
#     "ip_v6_prefix": 64,
#     "city": "Dubai",
#     "country": "AE",
#     "geometry": {
#       "type": "Point",
#       "coordinates": [
#         55.1856957,
#         25.0282605
#       ]
#     },
#     "tlsa_record": "",
#     "is_disabled": false
#   },
#   ...
#   ]}
# }
