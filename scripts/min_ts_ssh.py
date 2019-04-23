#!/usr/bin/env python3

from scapy.all import *
import random
import subprocess
import shlex
import numpy
from scipy import stats

################################################################################
# originalPkt = sr1(IP(dst="41.191.229.177")/TCP(flags="S",sport=5000,dport=80,seq=12345))
# send(IP(dst="41.191.229.177")/TCP(flags="A",sport=5000,dport=80,seq=originalPkt.ack,ack=originalPkt.seq+1),count=1)
# send(IP(dst="41.191.229.177")/TCP(flags="PA",sport=5000,dport=80,seq=originalPkt.ack,ack=originalPkt.seq+1)/"HEAD / HTTP/1.0\r\nUser-Agent: Testing\r\nHost: yourvserver.net\r\n\r\n",count=1)
# 22:16:16.244168 IP nobody.yourvserver.net.5000 > liq-nlnog01-ke.liquidtelecom.net.http: Flags [S], seq 12345, win 8192, length 0
# 22:16:16.412181 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [S.], seq 4065290309, ack 12346, win 29200, options [mss 1380], length 0
# 22:16:16.461169 IP nobody.yourvserver.net.5000 > liq-nlnog01-ke.liquidtelecom.net.http: Flags [.], ack 1, win 8192, length 0
# 22:16:16.525718 IP nobody.yourvserver.net.5000 > liq-nlnog01-ke.liquidtelecom.net.http: Flags [P.], seq 1:64, ack 1, win 8192, length 63: HTTP: HEAD / HTTP/1.0
# 22:16:16.693994 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [.], ack 64, win 29200, length 0
# 22:16:16.694455 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [P.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently
# 22:16:16.694485 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [F.], seq 187, ack 64, win 29200, length 0
# 22:16:17.345698 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [FP.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently
# 22:16:18.653640 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [FP.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently
# 22:16:21.265614 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [FP.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently
# 22:16:26.489683 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [FP.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently
# 22:16:36.954249 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [FP.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently
# 22:16:57.849580 IP liq-nlnog01-ke.liquidtelecom.net.http > nobody.yourvserver.net.5000: Flags [FP.], seq 1:187, ack 64, win 29200, length 186: HTTP: HTTP/1.1 301 Moved Permanently

# (thesis) root@msvps:~/thesis/ipsiblings/scripts# ./min_ts_ssh.py
# TS:  2870326713 flags:  SA seq:  51009834 ack:  664970652 isn:  664970651
# TCP handshake done ...
# TS:  2870327447 flags:  PA seq:  51009836 ack:  664970653
# TS:  2870328022 flags:  PA seq:  51009837 ack:  664970654
# TS:  2870328571 flags:  PA seq:  51009838 ack:  664970655
# TS:  2870329093 flags:  PA seq:  51009839 ack:  664970656
# TS:  2870329595 flags:  PA seq:  51009840 ack:  664970657
# TS:  2870330090 flags:  PA seq:  51009841 ack:  664970658
# TS:  2870330558 flags:  PA seq:  51009842 ack:  664970659
# TS:  2870331017 flags:  PA seq:  51009843 ack:  664970660
# TS:  2870331464 flags:  FPA seq:  51009844 ack:  664970724
# (thesis) root@msvps:~/thesis/ipsiblings/scripts# ./min_ts_ssh.py
# TS:  3012440277 flags:  SA seq:  682367745 ack:  971255875 isn:  971255874
# TCP handshake done ...
# TS:  3012440898 flags:  PA seq:  682367747 ack:  971255876
# TS:  3012441401 flags:  PA seq:  682367748 ack:  971255877
# TS:  3012441866 flags:  PA seq:  682367749 ack:  971255878
# TS:  3012442335 flags:  PA seq:  682367750 ack:  971255879
# TS:  3012442793 flags:  PA seq:  682367751 ack:  971255880
# TS:  3012443281 flags:  PA seq:  682367752 ack:  971255881
# TS:  3012443728 flags:  PA seq:  682367753 ack:  971255882
# TS:  3012444160 flags:  PA seq:  682367754 ack:  971255883
# TS:  3012444584 flags:  FPA seq:  682367755 ack:  971255947

ip4_ts = [(2356257542, 1553470512.999746), (2356257649, 1553470513.107172), (2356258225, 1553470513.682858), (2356258772, 1553470514.230394), (2356259276, 1553470514.733735), (2356259762, 1553470515.220086), (2356260221, 1553470515.679008), (2356260681, 1553470516.138688), (2356261131, 1553470516.588848), (2356261566, 1553470517.023745)]
ip6_ts = [(3500915629, 1553470484.453332), (3500915732, 1553470484.557086), (3500916261, 1553470485.085887), (3500916780, 1553470485.604144), (3500917255, 1553470486.079692), (3500917712, 1553470486.536418), (3500918153, 1553470486.977905), (3500918581, 1553470487.405209), (3500919009, 1553470487.833384), (3500919423, 1553470488.2475)]

# 4 1000.0977262302607 rsqr4 0.9999999782728238
# 6 1000.131508346862 rsqr6 0.9999999486623758
# tcp_time_distance 1144526.9044295289
# recv_time_distance -28.546414136886597
# raw_timestamp_diff 1144555.4508436657

################################################################################

# RACKSPACE server -> randomization during boot time -> different for IPv4 and IPv6

# IPv4
# TS:  191251811 flags:  SA seq:  4004878946 ack:  1031224942 isn:  1031224941
# TCP handshake done ...
# TS:  191252418 flags:  PA seq:  4004878948 ack:  1031224943
# TS:  191253314 flags:  PA seq:  4004878949 ack:  1031224944
# TS:  191255106 flags:  PA seq:  4004878950 ack:  1031224945
# TS:  191258722 flags:  PA seq:  4004878951 ack:  1031224946
# TS:  191265890 flags:  PA seq:  4004878952 ack:  1031224947
# TS:  191280226 flags:  PA seq:  4004878953 ack:  1031224948
# TS:  191310178 flags:  PA seq:  4004878954 ack:  1031224949
# No more response received ...
# [(191251811, 1553506758.92428), (191251967, 1553506759.080036), (191252418, 1553506759.531201), (191253314, 1553506760.427109), (191255106, 1553506762.219245), (191258722, 1553506765.8353), (191265890, 1553506773.003409), (191280226, 1553506787.339284), (191310178, 1553506817.291186)]

# IPv6
# TS:  1662074116 flags:  SA seq:  1822610038 ack:  992423209 isn:  992423208
# TCP handshake done ...
# TS:  1662074865 flags:  PA seq:  1822610040 ack:  992423210
# TS:  1662075953 flags:  PA seq:  1822610041 ack:  992423211
# TS:  1662078161 flags:  PA seq:  1822610042 ack:  992423212
# TS:  1662082514 flags:  PA seq:  1822610043 ack:  992423213
# TS:  1662091218 flags:  PA seq:  1822610044 ack:  992423214
# TS:  1662109394 flags:  PA seq:  1822610045 ack:  992423215
# No more response received ...
# [(1662074116, 1553506915.133226), (1662074303, 1553506915.319888), (1662074865, 1553506915.883303), (1662075953, 1553506916.970112), (1662078161, 1553506919.178216), (1662082514, 1553506923.530385), (1662091218, 1553506932.234249), (1662109394, 1553506950.410455)]

ip4_ts = [(191251811, 1553506758.92428), (191251967, 1553506759.080036), (191252418, 1553506759.531201), (191253314, 1553506760.427109), (191255106, 1553506762.219245), (191258722, 1553506765.8353), (191265890, 1553506773.003409), (191280226, 1553506787.339284), (191310178, 1553506817.291186)]
ip6_ts = [(1662074116, 1553506915.133226), (1662074303, 1553506915.319888), (1662074865, 1553506915.883303), (1662075953, 1553506916.970112), (1662078161, 1553506919.178216), (1662082514, 1553506923.530385), (1662091218, 1553506932.234249), (1662109394, 1553506950.410455)]

# 4 999.9990278300777 rsqr4 0.9999999999679958
# 6 1000.0322157704825 rsqr6 0.9999999979751264
# tcp_time_distance 1470799.3284666387
# recv_time_distance 156.20894598960876
# raw_timestamp_diff 1470643.119520649

################################################################################

# seems to work, needs to implement ack packets after x data packets sent ?

# 141.0.202.201, 2a01:6600:10c0:808::1
# ip4 = IP(dst = '38.142.60.234')
# ip6 = IPv6(dst = '2605:1080:0:fffc::241') # IPv6(dst = '2607:f238:0:16::2')

# ip4 = IP(dst = '41.191.229.177')
# ip6 = IPv6(dst = '2c0f:fe40:9fef:2:41:191:229:177')

########################################



def frequency(tsvals):
  nr_timestamps = len(tsvals)

  Xi_arr = numpy.zeros(nr_timestamps - 1)
  Vi_arr = numpy.zeros(nr_timestamps - 1)

  offset_recv = tsvals[0][1]
  offset_tcp = tsvals[0][0]

  for i in range(1, nr_timestamps):

    xi = tsvals[i][1] - offset_recv
    vi = tsvals[i][0] - offset_tcp

    Xi_arr[i - 1] = xi
    Vi_arr[i - 1] = vi

  slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)

  return slope_raw, rval * rval



def evaluate(ip4_ts, ip6_ts):
  hz4, rsqr4 = frequency(ip4_ts)
  hz6, rsqr6 = frequency(ip6_ts)

  print('4', hz4, 'rsqr4', rsqr4)
  print('6', hz6, 'rsqr6', rsqr6)

  offset4_tcp = ip4_ts[0][0]
  offset4_recv = ip4_ts[0][1]

  offset6_tcp = ip6_ts[0][0]
  offset6_recv = ip6_ts[0][1]

  tcp_time_distance = (offset6_tcp - offset4_tcp) / numpy.mean([hz4, hz6])
  recv_time_distance = offset6_recv - offset4_recv
  raw_timestamp_diff = abs(tcp_time_distance - recv_time_distance)
  print('tcp_time_distance', tcp_time_distance)
  print('recv_time_distance', recv_time_distance)
  print('raw_timestamp_diff', raw_timestamp_diff)



def get_ts(packet):
  try:
    for opt in packet[TCP].options:
      if opt[0] == 'Timestamp':
        return opt[1] # (TSval, TSecr)
  except:
    pass
  return None


# evaluate(ip4_ts, ip6_ts)
# sys.exit(0)

subprocess.run(shlex.split('iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 185.170.113.68 -j DROP'))
subprocess.run(shlex.split('ip6tables -A OUTPUT -p tcp --tcp-flags RST RST -s 2a03:4000:15:6b9::1337 -j DROP'))

# 212.232.62.10;22,25,53,80,443;2a00:84c0:0:11::2;22,25,53,80;yarnet.ru -> at least IPv4 randomized TS (changes each X seconds)
# 212.232.62.10;SSH-2.0-OpenSSH_6.6.1_hpn13v11 FreeBSD-20140420
# ip4 = IP(dst = '212.232.62.10')
# ip6 = IPv6(dst = '2a00:84c0:0:11::2')

# Linux sends FINPSHACK after 10 timestamps
# ip4 = IP(dst = '31.3.104.43') # NLNOG -> Linux -> randomized Timestamps
# ip6 = IPv6(dst = '2a03:7900:2:0:31:3:104:43') # NLNOG -> Linux -> randomized Timestamps

ip4 = IP(dst = '208.83.20.110') # FreeBSD 2017-09-03 # IP(dst = '192.237.179.190')
ip6 = IPv6(dst = '2607:f178:0:13::2') # FreeBSD 2017-09-03 # IPv6(dst = '2001:4801:7821:77:be76:4eff:fe10:5b8d')

dstport = 22
mss4 = 536 # 1220 # 536
mss6 = 1220

print_payload = True # print payload of ack packets
early_ack = True # does nothing at the moment; early ack the received identifiation string -> TODOOO: implement ...
max_timeout_per_ack = 300 # initially 30 but Linux seem to make use of longer intervals regarding retransmission
ip = ip4
mss = mss4

# payload = 'SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.2\r\n'
# payload = 'SSH-2.0-OpenSSH_7.6p1 This_is_just_a_test_connect_for_research_purposes\r\n'
payload = 'SSH-2.0-OpenSSH_7.6p1 This_is_just_a_test_connect_for_research_purposes{0}\r\n'.format('_a' * 90)

iterations = len(payload)

srcport = random.randint(49152, 65536)
isn = random.randint(0, 2**30)

# split payload
data = []
for i in range(iterations - 1):
  data.append(payload[i])
data.append(payload[len(data):])

timestamps = []

syn = TCP(dport = dstport, sport = srcport, flags = 'S', seq = isn, options = [('MSS', mss), ('WScale', 1), ('Timestamp', (1337, 0)), ('SackOK', None)])
synack = srp1(Ether()/ip/syn, verbose = 0, timeout = 4)

if not synack:
  print('No response received ...')
  exit(0)
else:
  # synack.show()
  if synack[TCP].options:
    ts = get_ts(synack)[0]
    timestamps.append((ts, synack.time))
    print('TS: ', ts, 'flags: ', synack[TCP].flags, 'seq: ', synack[TCP].seq, 'ack: ', synack[TCP].ack, 'isn: ', isn)
  else:
    print('TS: None')
    exit(0)

ts = get_ts(synack)[0]
# ACKs alone DO NOT CONSUME A SEQUENCE NUMBER -> many examples on the net use the ack of the SA packet ...
# FreeBSD is obviously very carefully -> only synack[TCP].ack works
# if problems -> exchange seq = isn, seq = synack[TCP].ack
tsack = TCP(dport = dstport, sport = srcport, flags = 'PA', seq = synack[TCP].ack, ack = synack[TCP].seq + 1, options = [('MSS', mss), ('WScale', 1), ('Timestamp', (1342, ts))])
tsack = ip/tsack
sendp(Ether()/tsack, verbose = 0)

print('TCP handshake done ...')

# exit(0)

dataack = synack
i = 0
tsack = TCP(dport = dstport, sport = srcport, flags = 'PA', seq = dataack[TCP].ack, ack = dataack[TCP].seq + 1, options = [('MSS', mss), ('WScale', 1), ('Timestamp', (1342 + (i + 1) * 4, ts))])/Raw(load = data[i])

# tsack = TCP(dport = dstport, sport = srcport, flags = 'PA', seq = dataack[TCP].ack + len(data[i]), ack = dataack[TCP].seq + 1, options = [('MSS', mss), ('WScale', 1), ('Timestamp', (1342 + (i + 1) * 4, ts))])/Raw(load = data[i])
dataack = srp1(Ether()/ip/tsack, verbose = 0, timeout = 4)
# maybe another packet gets sent containing the identification string ... but we do not capture it ...
if dataack.haslayer(Raw) and print_payload:
  print('Payload: ', str(dataack[Raw].load))

for i in range(1, iterations):

  ts = get_ts(dataack)[0]
  timestamps.append((ts, dataack.time))

  # tsack = TCP(dport = dstport, sport = srcport, flags = 'PA', seq = dataack[TCP].ack + len(data[i]), ack = dataack[TCP].seq + 1, options = [('MSS', mss), ('WScale', 1), ('Timestamp', (1342 + (i + 1) * 4, ts))])/Raw(load = data[i])
  tsack = TCP(dport = dstport, sport = srcport, flags = 'PA', seq = dataack[TCP].ack, ack = dataack[TCP].seq + 1, options = [('MSS', mss), ('WScale', 1), ('Timestamp', (1342 + (i + 1) * 4, ts))])/Raw(load = data[i])
  lastseq = dataack[TCP].seq
  lastack = dataack[TCP].ack
  dataack = srp1(Ether()/ip/tsack, verbose = 0, timeout = max_timeout_per_ack)
  if dataack:
    # dataack.show()
    if dataack[TCP].options:
      print('TS: ', str(next(iter([ t[1][0] for t in dataack[TCP].options if t[0] == 'Timestamp' ]), 'None')), 'flags: ', dataack[TCP].flags, 'seq: ', dataack[TCP].seq, 'ack: ', dataack[TCP].ack)
      if dataack.haslayer(Raw) and print_payload:
        print('Payload: ', str(dataack[Raw].load))
    else:
      print('TS: None')
      exit(0)
  else:
    print('No more response received ...')
    break


print(timestamps)
print('# timestamps received: ', len(timestamps))

subprocess.run(shlex.split('iptables -D OUTPUT -p tcp --tcp-flags RST RST -s 185.170.113.68 -j DROP'))
subprocess.run(shlex.split('ip6tables -D OUTPUT -p tcp --tcp-flags RST RST -s 2a03:4000:15:6b9::1337 -j DROP'))

rst = TCP(dport = dstport, sport = srcport, flags = 'R', seq = lastack, ack = lastseq + 1)
sendp(Ether()/ip/rst, verbose = 0)

exit(0)


################################################################################
################################################################################
################################################################################
################################################################################
# FreeBSD 2017-09-03
# 208.83.20.110, 2607:f178:0:13::2
#
# IPv4
# TS:  1576128507 flags:  SA seq:  2668109751 ack:  407084105 isn:  407084104
# TCP handshake done ...
# TS:  1576129573 flags:  PA seq:  2668109753 ack:  407084106
# TS:  1576130372 flags:  PA seq:  2668109754 ack:  407084107
# TS:  1576131142 flags:  PA seq:  2668109755 ack:  407084108
# TS:  1576131910 flags:  PA seq:  2668109756 ack:  407084109
# TS:  1576132633 flags:  PA seq:  2668109757 ack:  407084110
# TS:  1576133312 flags:  PA seq:  2668109758 ack:  407084111
# TS:  1576133963 flags:  PA seq:  2668109759 ack:  407084112
# TS:  1576134583 flags:  PA seq:  2668109760 ack:  407084113
# TS:  1576135218 flags:  PA seq:  2668109761 ack:  407084114
# TS:  1576135826 flags:  PA seq:  2668109762 ack:  407084115
# TS:  1576136421 flags:  PA seq:  2668109763 ack:  407084116
# TS:  1576137000 flags:  PA seq:  2668109764 ack:  407084117
# TS:  1576137583 flags:  PA seq:  2668109765 ack:  407084118
# TS:  1576138172 flags:  PA seq:  2668109766 ack:  407084119
# TS:  1576138762 flags:  PA seq:  2668109767 ack:  407084120
# TS:  1576139354 flags:  PA seq:  2668109768 ack:  407084121
# TS:  1576139953 flags:  PA seq:  2668109769 ack:  407084122
# TS:  1576140571 flags:  PA seq:  2668109770 ack:  407084123
# TS:  1576141173 flags:  PA seq:  2668109771 ack:  407084124
# TS:  1576141775 flags:  PA seq:  2668109772 ack:  407084125
# TS:  1576142344 flags:  PA seq:  2668109773 ack:  407084126
# TS:  1576142945 flags:  PA seq:  2668109774 ack:  407084127
# TS:  1576143538 flags:  PA seq:  2668109775 ack:  407084128
# TS:  1576144112 flags:  PA seq:  2668109776 ack:  407084129
# TS:  1576144692 flags:  PA seq:  2668109777 ack:  407084130
# TS:  1576145283 flags:  PA seq:  2668109778 ack:  407084131
# TS:  1576145860 flags:  PA seq:  2668109779 ack:  407084132
# TS:  1576146433 flags:  PA seq:  2668109780 ack:  407084133
# TS:  1576147051 flags:  PA seq:  2668109781 ack:  407084134
# TS:  1576147640 flags:  PA seq:  2668109782 ack:  407084135
# TS:  1576148225 flags:  PA seq:  2668109783 ack:  407084136
# TS:  1576148792 flags:  PA seq:  2668109784 ack:  407084137
# TS:  1576149361 flags:  PA seq:  2668109785 ack:  407084138
# TS:  1576149981 flags:  PA seq:  2668109786 ack:  407084139
# TS:  1576150575 flags:  PA seq:  2668109787 ack:  407084140
# TS:  1576150842 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576151024 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576151183 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576151352 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576151544 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576151717 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576151891 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576152084 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576152252 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576152429 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576152604 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576152780 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576152943 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576153121 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576153308 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576153492 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576153656 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576153813 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576153988 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576154160 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576154333 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576154516 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576154692 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576154860 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576155024 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576155196 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576155360 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576155520 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576155710 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576155880 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576156060 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576156250 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576156425 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576156608 flags:  A seq:  2668109790 ack:  407084141
# TS:  1576156774 flags:  A seq:  2668109790 ack:  407084141
################################################################################
# IPv6
# TS:  3626639964 flags:  SA seq:  825933432 ack:  398861255 isn: 398861254
# TCP handshake done ...
# TS:  3626641017 flags:  PA seq:  825933434 ack:  398861256
# TS:  3626641810 flags:  PA seq:  825933435 ack:  398861257
# TS:  3626642570 flags:  PA seq:  825933436 ack:  398861258
# TS:  3626643294 flags:  PA seq:  825933437 ack:  398861259
# TS:  3626643985 flags:  PA seq:  825933438 ack:  398861260
# TS:  3626644642 flags:  PA seq:  825933439 ack:  398861261
# TS:  3626645282 flags:  PA seq:  825933440 ack:  398861262
# TS:  3626645960 flags:  PA seq:  825933441 ack:  398861263
# TS:  3626646585 flags:  PA seq:  825933442 ack:  398861264
# TS:  3626647194 flags:  PA seq:  825933443 ack:  398861265
# TS:  3626647834 flags:  PA seq:  825933444 ack:  398861266
# TS:  3626648464 flags:  PA seq:  825933445 ack:  398861267
# TS:  3626649079 flags:  PA seq:  825933446 ack:  398861268
# TS:  3626649692 flags:  PA seq:  825933447 ack:  398861269
# TS:  3626650284 flags:  PA seq:  825933448 ack:  398861270
# TS:  3626650909 flags:  PA seq:  825933449 ack:  398861271
# TS:  3626651537 flags:  PA seq:  825933450 ack:  398861272
# TS:  3626652133 flags:  PA seq:  825933451 ack:  398861273
# TS:  3626652719 flags:  PA seq:  825933452 ack:  398861274
# TS:  3626653304 flags:  PA seq:  825933453 ack:  398861275
# TS:  3626653889 flags:  PA seq:  825933454 ack:  398861276
# TS:  3626654498 flags:  PA seq:  825933455 ack:  398861277
# TS:  3626655086 flags:  PA seq:  825933456 ack:  398861278
# TS:  3626655662 flags:  PA seq:  825933457 ack:  398861279
# TS:  3626656242 flags:  PA seq:  825933458 ack:  398861280
# TS:  3626656813 flags:  PA seq:  825933459 ack:  398861281
# TS:  3626657383 flags:  PA seq:  825933460 ack:  398861282
# TS:  3626657969 flags:  PA seq:  825933461 ack:  398861283
# TS:  3626658544 flags:  PA seq:  825933462 ack:  398861284
# TS:  3626659124 flags:  PA seq:  825933463 ack:  398861285
# TS:  3626659725 flags:  PA seq:  825933464 ack:  398861286
# TS:  3626660315 flags:  PA seq:  825933465 ack:  398861287
# TS:  3626660882 flags:  PA seq:  825933466 ack:  398861288
# TS:  3626661501 flags:  PA seq:  825933467 ack:  398861289
# TS:  3626662082 flags:  PA seq:  825933468 ack:  398861290
# TS:  3626662352 flags:  A seq:  825933471 ack:  398861291
# TS:  3626662512 flags:  A seq:  825933471 ack:  398861291
# TS:  3626662704 flags:  A seq:  825933471 ack:  398861291
# TS:  3626662892 flags:  A seq:  825933471 ack:  398861291
# TS:  3626663132 flags:  A seq:  825933471 ack:  398861291
# TS:  3626663342 flags:  A seq:  825933471 ack:  398861291
# TS:  3626663604 flags:  A seq:  825933471 ack:  398861291
# TS:  3626663782 flags:  A seq:  825933471 ack:  398861291
# TS:  3626663983 flags:  A seq:  825933471 ack:  398861291
# TS:  3626664177 flags:  A seq:  825933471 ack:  398861291
# TS:  3626664353 flags:  A seq:  825933471 ack:  398861291
# TS:  3626664526 flags:  A seq:  825933471 ack:  398861291
# TS:  3626664692 flags:  A seq:  825933471 ack:  398861291
# TS:  3626664864 flags:  A seq:  825933471 ack:  398861291
# TS:  3626665037 flags:  A seq:  825933471 ack:  398861291
# TS:  3626665192 flags:  A seq:  825933471 ack:  398861291
# TS:  3626665374 flags:  A seq:  825933471 ack:  398861291
# TS:  3626665552 flags:  A seq:  825933471 ack:  398861291
# TS:  3626665738 flags:  A seq:  825933471 ack:  398861291
# TS:  3626665914 flags:  A seq:  825933471 ack:  398861291
# TS:  3626666167 flags:  A seq:  825933471 ack:  398861291
# TS:  3626666372 flags:  A seq:  825933471 ack:  398861291
# TS:  3626666552 flags:  A seq:  825933471 ack:  398861291
# TS:  3626666722 flags:  A seq:  825933471 ack:  398861291
# TS:  3626666932 flags:  A seq:  825933471 ack:  398861291
# TS:  3626667102 flags:  A seq:  825933471 ack:  398861291
# TS:  3626667282 flags:  A seq:  825933471 ack:  398861291
# TS:  3626667462 flags:  A seq:  825933471 ack:  398861291
# TS:  3626667653 flags:  A seq:  825933471 ack:  398861291
# TS:  3626667827 flags:  A seq:  825933471 ack:  398861291
# TS:  3626668002 flags:  A seq:  825933471 ack:  398861291
# TS:  3626668201 flags:  A seq:  825933471 ack:  398861291
# TS:  3626668372 flags:  A seq:  825933471 ack:  398861291
# TS:  3626668544 flags:  A seq:  825933471 ack:  398861291
# TS:  3626668722 flags:  A seq:  825933471 ack:  398861291

################################################################################
################################################################################
################################################################################
################################################################################
################################################################################
################################################################################

## sample tcpdumps
# 41.191.229.177
# 22:23:00.042840 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [S], seq 894030973, win 8192, options [mss 536,wscale 1,TS val 1337 ecr 0,eol], length 0
# 22:23:00.210937 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [S.], seq 862584146, ack 894030974, win 28960, options [mss 1380,nop,nop,TS val 160885774 ecr 1337,nop,wscale 7], length 0
# 22:23:00.253253 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [.], ack 1, win 8192, options [mss 536,wscale 1,TS val 1342 ecr 160885774,eol], length 0
# 22:23:00.290787 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 1:2, ack 1, win 8192, options [mss 536,wscale 1,TS val 1350 ecr 160885774,eol], length 1
# 22:23:00.427918 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 1:42, ack 1, win 227, options [nop,nop,TS val 160885828 ecr 1342], length 41
# 22:23:00.458747 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [.], ack 2, win 227, options [nop,nop,TS val 160885836 ecr 1350], length 0
# 22:23:00.476352 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 1:2, ack 2, win 8192, options [mss 536,wscale 1,TS val 1354 ecr 160885828,eol], length 1
# 22:23:00.644333 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [.], ack 2, win 227, options [nop,nop,TS val 160885882 ecr 1354], length 0
# 22:23:01.057535 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 2:42, ack 2, win 227, options [nop,nop,TS val 160885986 ecr 1354], length 40
# 22:23:01.098525 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 2:3, ack 3, win 8192, options [mss 536,wscale 1,TS val 1358 ecr 160885986,eol], length 1
# 22:23:01.266499 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [.], ack 3, win 227, options [nop,nop,TS val 160886038 ecr 1358], length 0
# 22:23:02.325642 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 3:42, ack 3, win 227, options [nop,nop,TS val 160886303 ecr 1358], length 39
# 22:23:02.382597 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 3:4, ack 4, win 8192, options [mss 536,wscale 1,TS val 1362 ecr 160886303,eol], length 1
# 22:23:02.550612 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [.], ack 4, win 227, options [nop,nop,TS val 160886359 ecr 1362], length 0
# 22:23:04.857534 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 4:42, ack 4, win 227, options [nop,nop,TS val 160886936 ecr 1362], length 38
# 22:23:04.894053 IP nobody.yourvserver.net.62639 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 4:5, ack 5, win 8192, options [mss 536,wscale 1,TS val 1366 ecr 160886936,eol], length 1
# 22:23:05.062156 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [.], ack 5, win 227, options [nop,nop,TS val 160886987 ecr 1366], length 0
# 22:23:09.929575 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 5:42, ack 5, win 227, options [nop,nop,TS val 160888204 ecr 1366], length 37
# 22:23:20.057509 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 5:42, ack 5, win 227, options [nop,nop,TS val 160890736 ecr 1366], length 37
# 22:23:40.346005 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 5:42, ack 5, win 227, options [nop,nop,TS val 160895808 ecr 1366], length 37
# 22:24:20.921517 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [P.], seq 5:42, ack 5, win 227, options [nop,nop,TS val 160905952 ecr 1366], length 37
# 22:25:00.428609 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62639: Flags [F.], seq 42, ack 5, win 227, options [nop,nop,TS val 160915828 ecr 1366], length 0


################################################################################
# 2 min -> >16 timestamps

# 22:28:03.269439 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [S], seq 907156229, win 8192, options [mss 536,wscale 1,TS val 1337 ecr 0,eol], length 0
# 22:28:03.437316 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [S.], seq 2253184412, ack 907156230, win 28960, options [mss 1380,nop,nop,TS val 160961580 ecr 1337,nop,wscale 7], length 0
# 22:28:03.489447 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [.], ack 1, win 8192, options [mss 536,wscale 1,TS val 1342 ecr 160961580,eol], length 0
# 22:28:03.521492 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 1:2, ack 1, win 8192, options [mss 536,wscale 1,TS val 1350 ecr 160961580,eol], length 1
# 22:28:03.674333 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 1:42, ack 1, win 227, options [nop,nop,TS val 160961640 ecr 1342], length 41
# 22:28:03.689304 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 2, win 227, options [nop,nop,TS val 160961643 ecr 1350], length 0
# 22:28:03.721623 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 1:2, ack 2, win 8192, options [mss 536,wscale 1,TS val 1354 ecr 160961640,eol], length 1
# 22:28:03.889474 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 2, win 227, options [nop,nop,TS val 160961694 ecr 1354], length 0
# 22:28:04.333429 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 2:42, ack 2, win 227, options [nop,nop,TS val 160961805 ecr 1354], length 40
# 22:28:04.373612 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 2:3, ack 3, win 8192, options [mss 536,wscale 1,TS val 1358 ecr 160961805,eol], length 1
# 22:28:04.541384 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 3, win 227, options [nop,nop,TS val 160961857 ecr 1358], length 0
# 22:28:05.657488 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 3:42, ack 3, win 227, options [nop,nop,TS val 160962136 ecr 1358], length 39
# 22:28:05.714088 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 3:4, ack 4, win 8192, options [mss 536,wscale 1,TS val 1362 ecr 160962136,eol], length 1
# 22:28:05.882167 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 4, win 227, options [nop,nop,TS val 160962192 ecr 1362], length 0
# 22:28:08.305441 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 4:42, ack 4, win 227, options [nop,nop,TS val 160962798 ecr 1362], length 38
# 22:28:08.346118 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 4:5, ack 5, win 8192, options [mss 536,wscale 1,TS val 1366 ecr 160962798,eol], length 1
# 22:28:08.514044 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 5, win 227, options [nop,nop,TS val 160962850 ecr 1366], length 0
# 22:28:13.593450 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 5:42, ack 5, win 227, options [nop,nop,TS val 160964120 ecr 1366], length 37
# 22:28:13.637692 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 5:6, ack 6, win 8192, options [mss 536,wscale 1,TS val 1370 ecr 160964120,eol], length 1
# 22:28:13.805472 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 6, win 227, options [nop,nop,TS val 160964173 ecr 1370], length 0
# 22:28:24.185459 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 6:42, ack 6, win 227, options [nop,nop,TS val 160966768 ecr 1370], length 36
# 22:28:24.230019 IP nobody.yourvserver.net.62864 > liq-nlnog01-ke.liquidtelecom.net.ssh: Flags [P.], seq 6:7, ack 7, win 8192, options [mss 536,wscale 1,TS val 1374 ecr 160966768,eol], length 1
# 22:28:24.397963 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [.], ack 7, win 227, options [nop,nop,TS val 160966821 ecr 1374], length 0
# 22:28:45.369486 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 7:42, ack 7, win 227, options [nop,nop,TS val 160972064 ecr 1374], length 35
# 22:29:27.737473 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [P.], seq 7:42, ack 7, win 227, options [nop,nop,TS val 160982656 ecr 1374], length 35
# 22:30:03.674737 IP liq-nlnog01-ke.liquidtelecom.net.ssh > nobody.yourvserver.net.62864: Flags [F.], seq 42, ack 7, win 227, options [nop,nop,TS val 160991640 ecr 1374], length 0






################################################################################
# FreeBSD payload 255 -> 253 timestamps with one tcp connection !!! :) -> IPv6
# [(2429715741, 1553995037.989754), (2429715918, 1553995038.173335), (2429716746, 1553995038.995218), (2429717499, 1553995039.752208), (2429718212, 1553995040.460769), (2429718898, 1553995041.146836), (2429719618, 1553995041.867049), (2429720268, 1553995042.517277), (2429720919, 1553995043.167713), (2429721530, 1553995043.779055), (2429722138, 1553995044.387971), (2429722788, 1553995045.036451), (2429723390, 1553995045.639092), (2429724004, 1553995046.252805), (2429724608, 1553995046.857178), (2429725198, 1553995047.44653), (2429725827, 1553995048.075712), (2429726430, 1553995048.679053), (2429727060, 1553995049.309115), (2429727680, 1553995049.929245), (2429728274, 1553995050.523986), (2429728894, 1553995051.144793), (2429729488, 1553995051.73647), (2429730068, 1553995052.31676), (2429730648, 1553995052.905173), (2429731284, 1553995053.532872), (2429731931, 1553995054.179663), (2429732521, 1553995054.771096), (2429733129, 1553995055.37889), (2429733723, 1553995055.971524), (2429734333, 1553995056.581908), (2429734938, 1553995057.186434), (2429735543, 1553995057.792032), (2429736128, 1553995058.376812), (2429736710, 1553995058.95892), (2429737299, 1553995059.547645),(2429737896, 1553995060.150675), (2429738224, 1553995060.472768), (2429738388, 1553995060.638923), (2429738567, 1553995060.815635), (2429738750, 1553995060.999694), (2429738930, 1553995061.17929), (2429739094, 1553995061.343313), (242979271, 1553995061.519302), (2429739448, 1553995061.704315), (2429739618, 1553995061.875768), (2429739798, 1553995062.04767), (2429739968, 1553995062.223953), (2429740138, 1553995062.3919), (2429740310, 1553995062.563376), (2429740490, 153995062.738793), (2429740670, 1553995062.918867), (2429740843, 1553995063.091735), (2429741021, 1553995063.276342), (2429741207, 1553995063.455783), (2429741380, 1553995063.635145), (2429741561, 1553995063.81528), (2429741742, 155399506.991159), (2429741900, 1553995064.155509), (2429742088, 1553995064.339748), (2429742263, 1553995064.511859), (2429742419, 1553995064.67468), (2429742600, 1553995064.850985), (2429742771, 1553995065.019464), (2429742950, 1553995065.20391), (2429743123, 1553995065.371486), (2429743291, 1553995065.543761), (2429743460, 1553995065.71197), (2429743626, 1553995065.875307), (2429743806, 1553995066.055352), (2429743979, 1553995066.227697), (2429744143, 1553995066.391549), (249744323, 1553995066.57149), (2429744508, 1553995066.756724), (2429744678, 1553995066.9276), (2429744848, 1553995067.10351), (2429745028, 1553995067.279673), (2429745218, 1553995067.467424), (2429745400, 1553995067.648893), (2429745570, 553995067.81871), (2429745750, 1553995067.998926), (2429745931, 1553995068.179345), (2429746168, 1553995068.416858), (2429746342, 1553995068.590897), (2429746522, 1553995068.771107), (2429746688, 1553995068.93862), (2429746860, 155399509.115728), (2429747048, 1553995069.304391), (2429747220, 1553995069.475766), (2429747414, 1553995069.663271), (2429747578, 1553995069.830979), (2429747758, 1553995070.007175), (2429747934, 1553995070.182919), (2429748110, 1553995070.35938), (2429748295, 1553995070.543938), (2429748466, 1553995070.71528), (2429748651, 1553995070.899427), (2429748830, 1553995071.078927), (2429749010, 1553995071.259016), (2429749188, 1553995071.442739), (2429749371, 1553995071.619684), (429749538, 1553995071.787496), (2429749708, 1553995071.959163), (2429749888, 1553995072.143476), (2429750058, 1553995072.311847), (2429750248, 1553995072.499343), (2429750418, 1553995072.671198), (2429750608, 1553995072.856965), (242975778, 1553995073.031195), (2429750945, 1553995073.195182), (2429751127, 1553995073.375575), (2429751314, 1553995073.563292), (2429751479, 1553995073.729169), (2429751659, 1553995073.907856), (2429751828, 1553995074.078979), (2429751999, 553995074.25548), (2429752172, 1553995074.420742), (2429752343, 1553995074.593013), (2429752514, 1553995074.76351), (2429752710, 1553995074.959171), (2429752879, 1553995075.128239), (2429753048, 1553995075.303058), (2429753230, 155399505.478624), (2429753400, 1553995075.651122), (2429753575, 1553995075.823564), (2429753746, 1553995075.995212), (2429753908, 1553995076.163268), (2429754086, 1553995076.33496), (2429754258, 1553995076.512011), (2429754448, 1553995076.70336), (2429754628, 1553995076.880497), (2429754818, 1553995077.071357), (2429754998, 1553995077.247494), (2429755178, 1553995077.43125), (2429755358, 1553995077.606975), (2429755550, 1553995077.79912), (2429755727, 1553995077.975337), (249755898, 1553995078.146545), (2429756082, 1553995078.330924), (2429756253, 1553995078.504048), (2429756439, 1553995078.687666), (2429756623, 1553995078.871687), (2429756799, 1553995079.047496), (2429756967, 1553995079.215593), (242975718, 1553995079.386836), (2429757308, 1553995079.559581), (2429757490, 1553995079.739165), (2429757666, 1553995079.915191), (2429757843, 1553995080.091712), (2429758027, 1553995080.276228), (2429758198, 1553995080.45121), (2429758367, 155995080.615482), (2429758530, 1553995080.78509), (2429758719, 1553995080.967928), (2429758883, 1553995081.132865), (2429759065, 1553995081.314189), (2429759248, 1553995081.503526), (2429759418, 1553995081.676465), (2429759608, 1553995081864001), (2429759788, 1553995082.043436), (2429759958, 1553995082.212913), (2429760128, 1553995082.380194), (2429760298, 1553995082.547487), (2429760479, 1553995082.728178), (2429760650, 1553995082.903836), (2429760823, 1553995083.07169), (2429760998, 1553995083.247234), (2429761162, 1553995083.415604), (2429761350, 1553995083.603719), (2429761523, 1553995083.771818), (2429761680, 1553995083.935124), (2429761858, 1553995084.106956), (2429762028, 1553995084.278922), (229762203, 1553995084.451578), (2429762375, 1553995084.623786), (2429762554, 1553995084.803644), (2429762718, 1553995084.975679), (2429762929, 1553995085.180213), (2429763103, 1553995085.351899), (2429763278, 1553995085.527156), (242976351, 1553995085.700237), (2429763619, 1553995085.875193), (2429763802, 1553995086.05076), (2429763966, 1553995086.214706), (2429764129, 1553995086.383505), (2429764318, 1553995086.566767), (2429764478, 1553995086.734795), (2429764658, 153995086.911435), (2429764858, 1553995087.107937), (2429765018, 1553995087.271554), (2429765198, 1553995087.45654), (2429765391, 1553995087.640214), (2429765550, 1553995087.804469), (2429765739, 1553995087.98768), (2429765915, 1553995088164216), (2429766094, 1553995088.343982), (2429766276, 1553995088.524491), (2429766479, 1553995088.72724), (2429766651, 1553995088.899426), (2429766839, 1553995089.087682), (2429767019, 1553995089.267543), (2429767219, 1553995089.467393), (2429767403, 1553995089.651566), (2429767591, 1553995089.839681), (2429767768, 1553995090.016851), (2429767948, 1553995090.200189), (2429768120, 1553995090.369146), (2429768293, 1553995090.549607), (2429768479, 1553995090.727639), (249768659, 1553995090.907861), (2429768827, 1553995091.076037), (2429769027, 1553995091.276169), (2429769219, 1553995091.467783), (2429769399, 1553995091.64811), (2429769598, 1553995091.84824), (2429769778, 1553995092.028669), (2429769948, 1553995092.203973), (2429770118, 1553995092.36718), (2429770288, 1553995092.539578), (2429770468, 1553995092.723148), (2429770638, 1553995092.89161), (2429770818, 1553995093.070038), (2429770999, 1553995093.247382), (2429771179, 155399093.427408), (2429771354, 1553995093.603308), (2429771548, 1553995093.799659), (2429771745, 1553995093.99378), (2429771923, 1553995094.171893), (2429772092, 1553995094.343328), (2429772288, 1553995094.54359), (2429772483, 1553995094.73164), (2429772650, 1553995094.8993), (2429772818, 1553995095.067201), (2429773004, 1553995095.255795), (2429773178, 1553995095.431446), (2429773346, 1553995095.595064), (2429773527, 1553995095.775784), (2429773698, 1553995095.947278), (229773878, 1553995096.126852), (2429774048, 1553995096.303284), (2429774230, 1553995096.479471), (2429774402, 1553995096.65065), (2429774578, 1553995096.826626), (2429774748, 1553995097.004289), (2429774938, 1553995097.195547), (242977518, 1553995097.375761), (2429775298, 1553995097.551981), (2429775468, 1553995097.719562), (2429775654, 1553995097.902736), (2429775826, 1553995098.075371), (2429775991, 1553995098.239313), (2429776154, 1553995098.403301), (2429776330, 153995098.57932) ]

# FreeBSD payload 255 -> 253 timestamps with one tcp connection !!! :) -> IPv4
# [(2282209518, 1553997701.027048), (2282209687, 1553997701.193716), (2282210447, 1553997701.953579), (2282211169, 1553997702.676247), (2282211857, 1553997703.367015), (2282212488, 1553997703.995045), (2282213128, 1553997704.639531), (2282213737, 1553997705.243621), (2282214380, 1553997705.890431), (2282214971, 1553997706.477776), (2282215557, 1553997707.069582), (2282216144, 1553997707.650101), (2282216707, 1553997708.213757), (2282217267, 1553997708.773583), (2282217827, 1553997709.333569), (2282218377, 1553997709.884182), (2282218968, 1553997710.48139), (2282219548, 1553997711.054293), (2282220108, 1553997711.614525), (2282220670, 1553997712.176504), (2282221247, 1553997712.764034), (2282221847, 1553997713.363091), (2282222449, 1553997713.955026), (2282223030, 1553997714.541813), (2282223597, 1553997715.103553), (2282224157, 1553997715.666945), (2282224727, 1553997716.237941), (2282225279, 1553997716.785837), (2282225817, 1553997717.323575), (2282226399, 1553997717.905476), (2282226992, 1553997718.498581), (2282227547, 1553997719.055505), (2282228117, 1553997719.628191), (2282228668, 1553997720.183088), (2282229220, 1553997720.726746), (2282229768, 1553997721.281599), (2282230327, 1553997721.836525), (2282230588, 1553997722.099814), (2282230757, 1553997722.266151), (2282230917, 1553997722.429039), (2282231087, 1553997722.601183), (2282231257, 1553997722.769452), (2282231439, 1553997722.944992), (2282231597, 1553997723.109319), (2282231770, 1553997723.27743), (2282231939, 1553997723.449414), (2282232118, 1553997723.624946), (2282232278, 1553997723.789222), (2282232430, 1553997723.936928), (2282232591, 1553997724.100985), (2282232759, 1553997724.269239), (2282232928, 1553997724.441027), (2282233097, 1553997724.612737), (2282233258, 1553997724.76497), (2282233428, 1553997724.937394), (2282233589, 1553997725.100969), (2282233748, 1553997725.260473), (2282233907, 1553997725.421942), (2282234082, 1553997725.588588), (2282234242, 1553997725.74918), (2282234398, 1553997725.905012), (2282234549, 1553997726.06112), (2282234728, 1553997726.240837), (2282234890, 1553997726.400404), (2282235050, 1553997726.557025), (2282235210, 1553997726.72005), (2282235367, 1553997726.8806), (2282235538, 1553997727.049102), (2282235707, 1553997727.22032), (2282235870, 1553997727.376283), (2282236050, 1553997727.556208), (2282236197, 1553997727.708911), (2282236357, 1553997727.868403), (2282236530, 1553997728.036404), (2282236690, 1553997728.196641), (2282236857, 1553997728.372451), (2282237047, 1553997728.560922), (2282237217, 1553997728.733343), (2282237377, 1553997728.893079), (2282237554, 1553997729.060933), (2282237767, 1553997729.280769), (2282237939, 1553997729.448418), (2282238098, 1553997729.612663), (2282238279, 1553997729.785087), (2282238438, 1553997729.944464), (2282238607, 1553997730.113851), (2282238779, 1553997730.285279), (2282238938, 1553997730.452902), (2282239097, 1553997730.612758), (2282239278, 1553997730.792502), (2282239438, 1553997730.952061), (2282239603, 1553997731.112638), (2282239770, 1553997731.276459), (2282239927, 1553997731.436423), (2282240087, 1553997731.593569), (2282240247, 1553997731.756993), (2282240398, 1553997731.913178), (2282240567, 1553997732.076493), (2282240729, 1553997732.236326), (2282240898, 1553997732.412305), (2282241067, 1553997732.580906), (2282241240, 1553997732.748894), (2282241427, 1553997732.941445), (2282241598, 1553997733.104), (2282241760, 1553997733.268918), (2282241917, 1553997733.428606), (2282242093, 1553997733.600269), (2282242257, 1553997733.764834), (2282242437, 1553997733.944417), (2282242597, 1553997734.112588), (2282242758, 1553997734.273187), (2282242928, 1553997734.440922), (2282243088, 1553997734.601014), (2282243247, 1553997734.761094), (2282243438, 1553997734.944884), (2282243597, 1553997735.112978), (2282243769, 1553997735.280279), (2282243927, 1553997735.440435), (2282244098, 1553997735.604439), (2282244267, 1553997735.774075), (2282244437, 1553997735.944416), (2282244587, 1553997736.096606), (2282244757, 1553997736.264185), (2282244918, 1553997736.424368), (2282245090, 1553997736.596347), (2282245249, 1553997736.756845), (2282245418, 1553997736.932149), (2282245580, 1553997737.088829), (2282245747, 1553997737.261017), (2282245897, 1553997737.412342), (2282246070, 1553997737.576511), (2282246230, 1553997737.736232), (2282246387, 1553997737.896635), (2282246540, 1553997738.047996), (2282246687, 1553997738.200069), (2282246858, 1553997738.36454), (2282247008, 1553997738.521103), (2282247178, 1553997738.6849), (2282247358, 1553997738.864915), (2282247527, 1553997739.040614), (2282247677, 1553997739.193105), (2282247847, 1553997739.360156), (2282248017, 1553997739.524508), (2282248177, 1553997739.688225), (2282248347, 1553997739.860357), (2282248517, 1553997740.028956), (2282248677, 1553997740.188935), (2282248848, 1553997740.360519), (2282249027, 1553997740.536515), (2282249187, 1553997740.697341), (2282249351, 1553997740.860441), (2282249507, 1553997741.020183), (2282249687, 1553997741.196485), (2282249849, 1553997741.356512), (2282249999, 1553997741.512951), (2282250157, 1553997741.66523), (2282250318, 1553997741.828826), (2282250477, 1553997741.98891), (2282250648, 1553997742.156169), (2282250799, 1553997742.312462), (2282250969, 1553997742.476008), (2282251128, 1553997742.636096), (2282251288, 1553997742.80025), (2282251468, 1553997742.976892), (2282251630, 1553997743.140601), (2282251789, 1553997743.300953), (2282251958, 1553997743.468905), (2282252130, 1553997743.636309), (2282252278, 1553997743.784924), (2282252429, 1553997743.937225), (2282252597, 1553997744.109008), (2282252758, 1553997744.264984), (2282252917, 1553997744.428863), (2282253124, 1553997744.632582), (2282253297, 1553997744.804708), (2282253460, 1553997744.97251), (2282253629, 1553997745.136911), (2282253798, 1553997745.304476), (2282253964, 1553997745.472178), (2282254130, 1553997745.636406), (2282254291, 1553997745.801039), (2282254447, 1553997745.960875), (2282254637, 1553997746.148436), (2282254810, 1553997746.316981), (2282254968, 1553997746.476908), (2282255118, 1553997746.632928), (2282255280, 1553997746.788912), (2282255458, 1553997746.968401), (2282255617, 1553997747.128315), (2282255777, 1553997747.292758), (2282255938, 1553997747.448976), (2282256097, 1553997747.60924), (2282256267, 1553997747.776708), (2282256418, 1553997747.933181), (2282256579, 1553997748.085123), (2282256738, 1553997748.2483), (2282256917, 1553997748.426432), (2282257077, 1553997748.589054), (2282257237, 1553997748.744335), (2282257397, 1553997748.908858), (2282257547, 1553997749.059862), (2282257717, 1553997749.23251), (2282257877, 1553997749.393055), (2282258067, 1553997749.580415), (2282258237, 1553997749.75232), (2282258427, 1553997749.937359), (2282258597, 1553997750.105233), (2282258757, 1553997750.268178), (2282258917, 1553997750.432335), (2282259078, 1553997750.585255), (2282259237, 1553997750.752961), (2282259397, 1553997750.912307), (2282259558, 1553997751.064332), (2282259717, 1553997751.22839), (2282259878, 1553997751.392886), (2282260038, 1553997751.545154), (2282260222, 1553997751.728291), (2282260367, 1553997751.880511), (2282260538, 1553997752.048657), (2282260707, 1553997752.220273), (2282260867, 1553997752.380526), (2282261041, 1553997752.552326), (2282261209, 1553997752.716445), (2282261378, 1553997752.884589), (2282261561, 1553997753.068629), (2282261729, 1553997753.240625), (2282261907, 1553997753.41613), (2282262077, 1553997753.59222), (2282262240, 1553997753.752569), (2282262397, 1553997753.912346), (2282262558, 1553997754.064928), (2282262712, 1553997754.220525), (2282262873, 1553997754.380359), (2282263027, 1553997754.540292), (2282263197, 1553997754.709181), (2282263377, 1553997754.885483), (2282263538, 1553997755.044735), (2282263700, 1553997755.212657), (2282263882, 1553997755.388349), (2282264040, 1553997755.547939), (2282264208, 1553997755.72011), (2282264368, 1553997755.880573), (2282264530, 1553997756.036561), (2282264677, 1553997756.192564), (2282264839, 1553997756.352272),(2282265007, 1553997756.516615), (2282265178, 1553997756.684383), (2282265368, 1553997756.880024), (2282265547, 1553997757.063008), (2282265721, 1553997757.228267), (2282265887, 1553997757.396897), (2282266051, 1553997757.560627), (2282266218, 1553997757.728332)]
