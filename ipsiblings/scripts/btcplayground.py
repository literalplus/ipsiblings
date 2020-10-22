import random
import socket
import time
from typing import Iterable

from bitcoin import SelectParams
from bitcoin.core import Hash, b2lx
from bitcoin.messages import *
from bitcoin.net import CInv, CAddress

from ipsiblings.model import JustExit

USE_TESTNET = True
PORT = 18333 if USE_TESTNET else 8333
if USE_TESTNET:
    SelectParams('testnet')
FAKE_TX_HASH = Hash("not your usual tx".encode('utf-8'))
INV_SEND_TS = -1
g_getaddr_send_ts = -1
RUN_ID = int(random.uniform(0, 65535))
g_ver_ts = 0
print(f'run id is {RUN_ID}')


def version_pkt(client_ip, server_ip, nonce):
    msg = msg_version()
    msg.nVersion = 70002
    msg.addrTo.ip = server_ip
    msg.addrTo.port = PORT
    msg.addrFrom.ip = client_ip
    msg.addrFrom.port = PORT
    # msg.nServices = 1  # the default, but important, otherwise they don't want our ADDRs
    if nonce is not None:
        msg.nNonce = nonce
    return msg


def recv_pkt(fake_fil):
    global g_ver_ts, g_getaddr_send_ts
    pkt = MsgSerializable.stream_deserialize(fake_fil)
    if type(pkt) == msg_addr:
        ts_diff = time.time() - g_getaddr_send_ts
        print(f'Yay got ADDR with {len(pkt.addrs)} after {ts_diff:.2f}.')
        for addrx in pkt.addrs:
            addr: CAddress = addrx
            if addr.ip.startswith("2001:db8"):
                print(f' ****************************************** GOT an address cookie: {addr.ip}')
        if len(pkt.addrs) > 10:
            raise JustExit
    elif pkt.command == b'getdata':
        ts_diff = time.time() - INV_SEND_TS
        print(f' GETDATA * {pkt}')
        print(f'GOT GETDATA AFTER {ts_diff} seconds')
    elif type(pkt) == msg_getheaders:
        print(f'they asked for headers. lol do they think')
    elif type(pkt) == msg_version:
        print(f'version! {pkt.strSubVer} height {pkt.nStartingHeight}')
        g_ver_ts = pkt.nTime
    else:
        print(f' <- {pkt}')
    return pkt


def send_pkt(fake_fil, pkt: MsgSerializable):
    pkt.stream_serialize(fake_fil)
    fake_fil.flush()
    pkt_str = str(pkt)
    print(f' -> {pkt_str[:120]}')


def gen_fake_ips(run_id, addr_id, thread_id) -> Iterable[str]:
    # 2001:db8::cafe:beef:XXXX:YYYY:GZZZ
    #   X is run id so that multiple runs don't interfere (65k runs possible)
    #   Y is addr id to tell apart what node we sent this to (65k >>> btc public net size)
    #   G is for multiple threads in a measurement run
    #   Z is for a single address so that we can send >10 addresses
    x_block = f'{run_id:04x}'
    y_block = f'{addr_id:04x}'
    g_block = f'{thread_id:01x}'
    if len(x_block) > 4 or len(y_block) > 4 or len(g_block) > 1:
        raise ValueError(f'One of the address blocks got too long: {x_block} / {y_block} / {g_block}')
    for offset in range(0, 256):
        z_block = f'{offset:03x}'
        yield f'2001:db8::cafe:baaf:{x_block}:{y_block}:{g_block}{z_block}'


def main():
    if USE_TESTNET:
        # server_addr = '3.17.246.73'  # testnet
        server_addr = '127.0.0.1'
    else:
        server_addr = '37.59.47.27'  # mainnet
    client_addr = '10.87.21.23'
    try:
        nce = do_connect(client_addr, server_addr, None)
    except JustExit:
        pass
    print(f'doen')


def do_connect(client_addr, server_addr, nonce):
    global INV_SEND_TS, g_ver_ts, g_getaddr_send_ts
    with socket.socket() as sock:
        sock.connect((server_addr, PORT))
        with sock.makefile(mode='rwb') as fake_fil:
            send_pkt(fake_fil, version_pkt(client_addr, server_addr, nonce))
            remote_ver = recv_pkt(fake_fil)
            print(f'nonce: {remote_ver.nNonce}')
            send_pkt(fake_fil, msg_verack())
            i = 0
            try:
                while True:
                    if i == 3:
                        g_getaddr_send_ts = time.time()
                        print("sending getaddr!")
                        send_pkt(fake_fil, msg_getaddr())
                    elif i == 5:
                        print(f"sending inv for {b2lx(FAKE_TX_HASH)}!")
                        pkt = msg_inv()
                        inv = CInv()
                        inv.type = 1  # TX
                        inv.hash = FAKE_TX_HASH
                        pkt.inv.append(inv)
                        INV_SEND_TS = time.time()
                        send_pkt(fake_fil, pkt)
                    elif i == 4:
                        print(f"sending marker ips")
                        pkt = msg_addr()
                        for fake_ip in gen_fake_ips(RUN_ID, 78, 0xf):
                            addr = CAddress()
                            addr.ip = fake_ip
                            addr.port = 9  # discard
                            addr.nTime = g_ver_ts
                            addr.nServices = 1  # NODE_NETWORK, otherwise they won't always accept the addr
                            pkt.addrs.append(addr)
                        send_pkt(fake_fil, pkt)
                    recv_pkt(fake_fil)
                    i += 1
            except KeyboardInterrupt:
                pass
    return remote_ver.nNonce


if __name__ == '__main__':
    main()
