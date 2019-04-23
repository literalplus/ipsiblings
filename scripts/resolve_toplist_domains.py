#!/usr/bin/env python3
#
# (c) Marco Starke
#
# This script resolves top lists (alexa, cisco, majestic) and writes a csv
# position, domain, ip4_list, ip6_list
#
# Alexa Top Million
# http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
#
# Cisco Umbrella Top 1 Million
# http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
# Cisco Umbrella Top TLDs
# http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m-TLD.csv.zip
#
# Majestic Top Million
# http://downloads.majesticseo.com/majestic_million.csv
#


import io
import sys
import socket
import zipfile
import datetime
import urllib.request
import multiprocessing
import multiprocessing.pool


def resolve_host_dual(hoststr):
  addrv6 = set()
  try:
    # [(family, type, proto, canonname, sockaddr)] -> [sockaddr] -> (address, port, flow info, scope id)
    v6 = socket.getaddrinfo(hoststr, None, socket.AF_INET6)
    for addr in v6:
      addrv6.add(addr[4][0])
  except socket.gaierror:
    return None
  except Exception as e:
    print('Exception: {0} - {1} [{2}]'.format(type(e).__name__, e, hoststr))
    return None

  addrv4 = set()
  try:
    # [(family, type, proto, canonname, sockaddr)] -> [sockaddr] -> (address, port)
    v4 = socket.getaddrinfo(hoststr, None, socket.AF_INET)
    for addr in v4:
      addrv4.add(addr[4][0])
  except socket.gaierror:
    return None
  except Exception as e:
    print('Exception: {0} - {1} [{2}]'.format(type(e).__name__, e, hoststr))
    return None

  return (addrv4, addrv6)


def load_from_url(url, toplist_filename = None):

  if toplist_filename: # alexa, cisco
    httpresponse = urllib.request.urlopen(url)
    with zipfile.ZipFile(io.BytesIO(httpresponse.read())) as zf:
      with zf.open(toplist_filename) as csvfile:
        for line in csvfile.readlines():
          yield line.decode('utf-8').strip() # remove any whitespaces
  else: # majestic
    with urllib.request.urlopen(url) as csvfile:
      header = next(csvfile) # unused
      for line in csvfile:
        yield line.decode('utf-8').strip() # remove any whitespaces


def load_from_file(filename, header = False):
  with open(filename, mode = 'r') as infile:
    if header:
      unused = next(infile)
    for line in infile:
      yield line.strip()


def resolve_toplist_records_generator(top_list, filename = None):
  # top-1m.csv structure (alexa, cisco) without header:
  # position,domain
  # majestic_million.csv structure (majestic) including header:
  # GlobalRank,TldRank,Domain,TLD,RefSubNets,RefIPs,IDN_Domain,IDN_TLD,PrevGlobalRank,PrevTldRank,PrevRefSubNets,PrevRefIPs

  counter_resolved = 0
  counter_list_items = 0
  try:
    print('{0} - Resolution started ...'.format(str(datetime.datetime.now())))

    resolved = []

    # determine csv structure (alexa,cisco) vs. (majestic)
    first_row = next(top_list)
    items = first_row.split(',')

    if len(items) < 3: # (alexa,cisco)
      # no header here so we have to deal with the first row as a common entry
      pos, domain = items
      ips = resolve_host_dual(domain)
      if ips:
        record = (pos, domain, ','.join(ips[0]), ','.join(ips[1]))
        resolved.append(record)

      def split(row):
        pos, domain = row.split(',')
        return (pos, domain)

    else: # (majestic)
      # first_row contains header -> discard
      def split(row):
        pos, tldpos, domain, *misc = row.split(',')
        return (pos, domain)

    # start with resolution loop
    for entry in top_list:
      pos, domain = split(entry)
      ips = resolve_host_dual(domain)

      counter_list_items = counter_list_items + 1
      if counter_list_items % 50000 == 0:
        print('{0} - Processed {1} list entries'.format(str(datetime.datetime.now()), counter_list_items))

      if not ips:
        continue

      record = (pos, domain, ','.join(ips[0]), ','.join(ips[1]))
      resolved.append(record)

      counter_resolved = counter_resolved + 1
      if counter_resolved % 1000 == 0:
        print('{0} - Resolved {1} records'.format(str(datetime.datetime.now()), counter_resolved))

    print('{0} - Resolution finished ...'.format(str(datetime.datetime.now())))

  except (Exception, KeyboardInterrupt) as e:
    print('{0} - Exception: {1}'.format(str(datetime.datetime.now()), e))
  finally:
    if filename:
      with open(filename, mode = 'w') as out:
        out.write('position;domain;ip4;ip6\n')
        for record in resolved:
          out.write(';'.join(record))
          out.write('\n')
      print('{0} - Finished writing file ...'.format(str(datetime.datetime.now())))
      return True
    else:
      return resolved


def resolve_process(toplist_part):
  # each process spawns 4 threads
  resolved = []

  part_size = int(len(toplist_part) / 4)
  parts = [ toplist_part[i:i + part_size] for i in range(0, len(toplist_part), part_size) ]
  if len(parts) > 4: # if we have remaining entries just add them to the last list
    parts[3].extend(parts[4])
    del(parts[4])

  results = []
  tp = multiprocessing.pool.ThreadPool(processes = 1)
  for i in range(4):
    res = tp.apply_async(resolve_thread, args = (parts[i],))
    results.append(res)

  finished = [ False for _ in range(4) ]
  while True:
    for i, r in enumerate(results):
      if finished[i]:
        continue
      try:
        while True:
          res = r.get(timeout = 2)
          if res != None: # should never be None
            resolved.extend(res)
            finished[i] = True
            break
      except multiprocessing.TimeoutError:
        continue
    # check if all threads have finished
    if all(finished):
      break

    if resolved:
      print('{0} - Process finished, collected {1} records'.format(str(datetime.datetime.now()), len(resolved)))

  return resolved


def resolve_thread(toplist_part):
  resolved = []
  for pos, domain in toplist_part:
    try:
      ips = resolve_host_dual(domain)
      if not ips:
        continue
      resolved.append((pos, domain, ','.join(ips[0]), ','.join(ips[1])))
    except Exception as e:
      print('Position, Domain [{pos}, {domain}] - Exception: {0} - {1}'.format(type(e).__name__, e, pos = pos, domain = domain))

  if resolved:
    print('{0} - Thread finished, found {1} records'.format(str(datetime.datetime.now()), len(resolved)))

  return resolved


def resolve_multi(toplist, filename = None):
  part_size = int(len(toplist) / 4)
  domain_parts = [ toplist[i:i + part_size] for i in range(0, len(toplist), part_size) ]
  if len(domain_parts) > 4: # if we have remaining entries just add them to the last list
    domain_parts[3].extend(domain_parts[4])
    del(domain_parts[4])

  resolved = []
  try:
    print('{0} - Resolution started ...'.format(str(datetime.datetime.now())))
    with multiprocessing.Pool(4) as pool:
      results = []
      for i in range(4):
        res = pool.apply_async(resolve_process, args = (domain_parts[i],))
        results.append(res)

      finished = [ False for _ in range(4) ]
      while True:
        for i, r in enumerate(results):
          if finished[i]:
            continue
          try:
            while True:
              res = r.get(timeout = 2)
              if res != None: # should never be None
                resolved.extend(res)
                finished[i] = True
                break
          except multiprocessing.TimeoutError:
            continue
        # check if all threads have finished
        if all(finished):
          break

  except KeyboardInterrupt:
    print('KeyboardInterrupt')
  except Exception as e:
    print('Exception: {0} - {1}'.format(type(e).__name__, e))
  finally:
    if resolved:
      resolved = sorted(resolved, key = lambda x: int(x[0])) # sort by position
      if filename:
        with open(filename, mode = 'w') as out:
          out.write('position;domain;ip4;ip6\n')
          for line in resolved:
            out.write(';'.join(line))
            out.write('\n')
        print('{0} - Finished writing file ...'.format(str(datetime.datetime.now())))
      else:
        return resolved
    else:
      print('Nothing to write.')


def usage(argv):
  print("Usage: {0} <list_type> <outputfile> [<domainfile>]".format(argv[0]))
  print("Parameter <list_type> must be one of 'alexa', 'cisco' or 'majestic' to be downloaded and resolved.")
  print("If <list_type> equals 'individual' the 'domainfile' parameter must be also given and expects [index, domain] as format.")


def main():

  if len(sys.argv) < 3 or len(sys.argv) > 4:
    usage(sys.argv)
    return 1

  toplist_provider = sys.argv[1]
  outputfile = sys.argv[2]

  available_lists = { 'alexa': ('http://s3.amazonaws.com/alexa-static/top-1m.csv.zip', 'top-1m.csv'), 'cisco': ('http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip', 'top-1m.csv'), 'majestic': ('http://downloads.majestic.com/majestic_million.csv', None) }

  if toplist_provider not in available_lists.keys() and toplist_provider != 'individual':
    usage(sys.argv)
    return 1

  if toplist_provider == 'individual':
    if len(sys.argv) != 4:
      usage(sys.argv)
      return 1
    toplist_url = None
    toplist_fname = None
    domainfile = sys.argv[3]
  else:
    toplist_url = available_lists[toplist_provider][0]
    toplist_fname = available_lists[toplist_provider][1]
    domainfile = None

  # single process resolution (very slow)
  # domain_generator = load_from_url(url = toplist_url, toplist_filename = toplist_fname)
  # resolve_toplist_records_generator(domain_generator, filename = outputfile)

  if domainfile:
    print('{0} - Loading from file [{1}]'.format(str(datetime.datetime.now()), domainfile))
    domain_list = list(load_from_file(domainfile))
  else:
    print('{0} - Loading {1} top list file from [{2}]'.format(str(datetime.datetime.now()), toplist_provider, toplist_url))
    domain_list = list(load_from_url(url = toplist_url, toplist_filename = toplist_fname))


  if toplist_provider in ('alexa', 'cisco', 'individual'):
    domains = [ tuple(line.split(',')) for line in domain_list ]
  else: # majestic
    domains = [ (line.split(',')[0], line.split(',')[2]) for line in domain_list ]


  # run 4 processes with 4 threads each
  resolve_multi(domains, outputfile)

  return 0



if __name__ == '__main__':
   sys.exit(main())
