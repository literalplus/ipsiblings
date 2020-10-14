import hashlib
import socket
import time

from bitcoin import SelectParams
from bitcoin.core import Hash, b2lx
from bitcoin.messages import *
from bitcoin.net import CInv

USE_TESTNET = True
PORT = 18333 if USE_TESTNET else 8333
if USE_TESTNET:
    SelectParams('testnet')
FAKE_TX_HASH = Hash("not your usual tx".encode('utf-8'))
INV_SEND_TS = -1


def version_pkt(client_ip, server_ip, nonce):
    msg = msg_version()
    msg.nVersion = 70002
    msg.addrTo.ip = server_ip
    msg.addrTo.port = PORT
    msg.addrFrom.ip = client_ip
    msg.addrFrom.port = PORT
    if nonce is not None:
        msg.nNonce = nonce
    return msg


def recv_pkt(fake_fil):
    pkt = MsgSerializable.stream_deserialize(fake_fil)
    if pkt.command == b'addr':
        print(f' ADDR * {pkt}')
        print(f'HASH OF ADDR -> {hashlib.sha256(str(pkt).encode("utf-8")).hexdigest()}')
    elif pkt.command == b'getdata':
        ts_diff = time.time() - INV_SEND_TS
        print(f' GETDATA * {pkt}')
        print(f'GOT GETDATA AFTER {ts_diff} seconds')
    else:
        print(f' <- {pkt}')
    return pkt


def send_pkt(fake_fil, pkt: MsgSerializable):
    pkt.stream_serialize(fake_fil)
    fake_fil.flush()
    print(f' -> {pkt}')


def main():
    if USE_TESTNET:
        server_addr = '3.17.246.73'  # testnet
    else:
        server_addr = '37.59.47.27'  # mainnet
    client_addr = '10.87.21.23'
    nce = do_connect(client_addr, server_addr, None)
    print(f'ok lol {nce}')


def do_connect(client_addr, server_addr, nonce):
    global INV_SEND_TS
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
                    if i == 5:
                        print("sending getaddr!")
                        send_pkt(fake_fil, msg_getaddr())
                    elif i == 7:
                        print(f"sending inv for {b2lx(FAKE_TX_HASH)}!")
                        pkt = msg_inv()
                        inv = CInv()
                        inv.type = 1  # TX
                        inv.hash = FAKE_TX_HASH
                        pkt.inv.append(inv)
                        INV_SEND_TS = time.time()
                        send_pkt(fake_fil, pkt)
                    recv_pkt(fake_fil)
                    i += 1
            except KeyboardInterrupt:
                pass
    return remote_ver.nNonce


if __name__ == '__main__':
    main()
