#!/usr/bin/env python3
#
# load_cdn_ipnets.py
#
# (c) 2019 Marco Starke
#
# Download CDN IP network lists
#

import re
import sys
import json
import ipaddress
import urllib.parse
import urllib.request


# def azure(source_list, region = None):
#   data = []
#   ip4, ip6 = [], []
#
#   data.append(sorted(ip4))
#   data.append(sorted(ip6))
#   return '# azure', data

def cloudflare(source_list, region = None):
  # region parameter not usable -> cloudflare does not provide regional information
  data = [] # add information to networks in outputfile
  ip4, ip6 = [], []
  for url in source_list:
    with urllib.request.urlopen(url) as src:
      for line in src:
        ip = ipaddress.ip_network(line.decode('utf-8').strip())
        if ip.version == 4:
          ip4.append(ip)
        else:
          ip6.append(ip)
  data.append(sorted(ip4))
  data.append(sorted(ip6))
  return '# cloudflare', data

def cloudfront(source_list, region = None):
  # cloudfront ranges are all global -> no region information available
  data = []
  ip4, ip6 = [], []
  for url in source_list:
    with urllib.request.urlopen(url) as src:
      jsonsrc = json.load(src)

    ip4json = jsonsrc['prefixes']
    ip6json = jsonsrc['ipv6_prefixes']

    for entry in ip4json:
      p, s = entry.get('ip_prefix'), entry['service']
      if s.startswith('CLOUDFRONT'):
        ip4.append(ipaddress.ip_network(p))
    for entry in ip6json:
      p, s = entry.get('ipv6_prefix'), entry['service']
      if s.startswith('CLOUDFRONT'):
        ip6.append(ipaddress.ip_network(p))
  data.append(sorted(ip4))
  data.append(sorted(ip6))
  return '# cloudfront', data

def fastly(source_list, region = None):
  data = []
  ip4, ip6 = [], []
  for url in source_list:
    with urllib.request.urlopen(url) as src:
      jsonsrc = json.load(src)

    for net_list in jsonsrc.values():
      for net in net_list:
        ipnet = ipaddress.ip_network(net)
        if ipnet.version == 4:
          ip4.append(ipnet)
        else:
          ip6.append(ipnet)
  data.append(sorted(ip4))
  data.append(sorted(ip6))
  return '# fastly', data

def incapsula(source_list, region = None):
  # no region information available
  data = []
  ip4, ip6 = [], []
  for url in source_list:
    post_data = urllib.parse.urlencode({ 'resp_format': 'text' }).encode()
    with urllib.request.urlopen(url, post_data) as src:
      for line in src:
        ipnet = ipaddress.ip_network(line.decode('utf-8').strip())
        if ipnet.version == 4:
          ip4.append(ipnet)
        else:
          ip6.append(ipnet)
  data.append(sorted(ip4))
  data.append(sorted(ip6))
  return '# incapsula', data

def leaseweb(source_list, region = None):
  data = []
  ip4, ip6 = [], []
  for url in source_list:
    with urllib.request.urlopen(url) as httpresp:
      src = httpresp.read().decode('utf-8')

    src = re.search('<article.*</article>', src, flags = (re.IGNORECASE | re.MULTILINE | re.DOTALL)).group(0) # prefilter
    src = re.search('(<ul>.*</ul>).*<h2.*(<ul>.*</ul>)', src, flags = (re.IGNORECASE | re.MULTILINE | re.DOTALL)) # prefilter
    ip4_html = src.group(1).strip('<ul>').strip('</ul>').strip().lower().split()
    ip6_html = src.group(2).strip('<ul>').strip('</ul>').strip().lower().split()

    for ip4net in ip4_html:
      ip4.append(ipaddress.ip_network(re.search('[0-9a-f:\.\/]+', ip4net).group(0), strict = False))
    for ip6net in ip6_html:
      ip6.append(ipaddress.ip_network(re.search('[0-9a-f:\.\/]+', ip6net).group(0), strict = False))
  data.append(sorted(ip4))
  data.append(sorted(ip6))
  return '# leaseweb', data

def stackpath(source_list, region = None): # previously MaxCDN
  data = []
  ip4, ip6 = [], []
  for url in source_list:
    with urllib.request.urlopen(url) as src:
      for line in src:
        ipnet = ipaddress.ip_network(line.decode('utf-8').strip())
        if ipnet.version == 4:
          ip4.append(ipnet)
        else:
          ip6.append(ipnet)
  data.append(sorted(ip4))
  data.append(sorted(ip6))
  return '# stackpath', data




def usage(args):
  print('Usage: {0} [<outputfile>] [<region>]'.format(args[0]))
  print('If no arguments are given data is printed to stdout.')
  print('[Most CDN providers do not offer any region <-> IP mapping to their published IP ranges!]')

def main(cdn_list):
  if len(sys.argv) > 3:
    usage(sys.argv)
    return 1

  try:
    outputfile = sys.argv[1]
  except:
    outputfile = None

  try:
    region = sys.argv[2]
  except:
    region = None

  cdn_networks = []
  for cdn, data in cdn_list.items():
    source_list, func = data
    cdn_name, networks = func(source_list, region = region)
    cdn_networks.append(cdn_name)
    cdn_networks.extend(networks[0])
    cdn_networks.extend(networks[1])

  if outputfile:
    with open(outputfile, mode = 'w') as outfile:
      outfile.write('\n'.join(map(str, cdn_networks)))
      outfile.write('\n')
  else:
    print('\n'.join(map(str, cdn_networks)), file = sys.stdout)

  return 0


if __name__ == '__main__':
  # { 'function name': [ (url, list, as tuple), function-pointer ] }
  cdn_list = {

    # 'azure': [('https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20190114.xml',), azure], # https://www.microsoft.com/en-us/download/details.aspx?id=41653 / https://www.microsoft.com/en-us/download/details.aspx?id=53602 / https://docs.microsoft.com/en-us/rest/api/cdn/edgenodes/list -> requires authentication

    'cloudflare': [('https://www.cloudflare.com/ips-v4?utm_referrer=https://support.cloudflare.com/hc/en-us/articles/200169186-What-are-Cloudflare-s-IPs-and-IP-ranges-', 'https://www.cloudflare.com/ips-v6?utm_referrer=https://support.cloudflare.com/hc/en-us/articles/200169186-What-are-Cloudflare-s-IPs-and-IP-ranges-'), cloudflare], # https://www.cloudflare.com/ips/

    'cloudfront': [('https://ip-ranges.amazonaws.com/ip-ranges.json',), cloudfront], # https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html

    'fastly': [('https://api.fastly.com/public-ip-list',), fastly], # https://docs.fastly.com/guides/securing-communications/accessing-fastlys-ip-ranges

    'incapsula': [('https://my.incapsula.com/api/integration/v1/ips',), incapsula], # https://support.incapsula.com/hc/en-us/articles/200627570-Restricting-direct-access-to-your-website-Incapsula-s-IP-addresses-

    'leaseweb': [('https://kb.leaseweb.com/customer-portal/cdn/cdn-ip-ranges',), leaseweb],

    'stackpath': [('https://support.stackpath.com/hc/en-us/article_attachments/360002812223/ipblocks.txt',), stackpath], # was MaxCDN - https://support.stackpath.com/hc/en-us/articles/360001091666-IP-Blocks

  }

  sys.exit(main(cdn_list))
