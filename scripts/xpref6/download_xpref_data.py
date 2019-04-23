#!/usr/bin/env python3

# requires ssh login with rsa key

import os
import sys
import datetime
import subprocess
import shlex

if len(sys.argv) > 2:
  print(('Usage: %s <dst dir> OR %s (uses current directory for ouptut)') % (sys.argv[0], sys.argv[0]))
  exit(1)

dst_directory = './'

if len(sys.argv) == 2:
  dst_directory = sys.argv[1]

user_server = 'root@192.237.179.190'
src_directory = ':/root/xpref6/data/'

split_size = 10 # maximum number of folders per scp subprocess

existing_data_dirs = sorted([d for d in os.listdir('.') if os.path.isdir(d)])
last_date_str = existing_data_dirs[-1]

yesterday = datetime.datetime.today() - datetime.timedelta(days=1) # exclude today's date
last_date = datetime.datetime.strptime(last_date_str, '%Y-%m-%d_%H-%M-%S')

# print("from: " + str(last_date))
# print("  to: " + str(yesterday))

passed_time = yesterday - last_date # excluding first and last date (2 days missing)

if passed_time.days < 0:
  print('Nothing to do. Up to yesterday in sync ...')
  exit(0)

datetime_list = [yesterday - datetime.timedelta(days=x) for x in reversed(range(passed_time.days + 1))] # + 1 to include the day after last_date

date_list_wildcard_str = [str(datetime.datetime.date(x)) + '_*' for x in datetime_list]

data_list = [date_list_wildcard_str]
if len(date_list_wildcard_str) > split_size:
  data_list = [date_list_wildcard_str[x:x + split_size] for x in range(0, len(date_list_wildcard_str), split_size)]

processes = []

start = datetime.datetime.now()
print('Started at: ' + str(start))

for i, data_to_copy in enumerate(data_list):
  str_data_to_copy = ','.join(data_to_copy)

  if len(data_to_copy) > 1:
    dir_str = user_server + src_directory + r'\{' + str_data_to_copy + r'\}'
  else:
    dir_str = user_server + src_directory + str_data_to_copy

  cmd = 'scp -B -C -q -r ' + dir_str + ' ' + dst_directory
  
  p = subprocess.Popen(shlex.split(cmd), shell=False)

  if p.wait() > 0: # busy wait for each process sequentially to finish
    print(('Error with dates (dataset index %d): \n' + str(data_to_copy)) % (i))
    print('----------------')
  else:
    print('Finished dataset %d (PID: %d).' % (i, p.pid))

end = datetime.datetime.now()
print('Finished at: ' + str(end))

print('Time taken: ' + str(end - start))
