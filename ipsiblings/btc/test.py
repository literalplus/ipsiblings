import socket

from bitcoin import *
from bitcoin.messages import *

PORT = 18333
SelectParams('testnet')


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
    print(f' -> {pkt}')
    return pkt


def send_pkt(fake_fil, pkt: MsgSerializable):
    pkt.stream_serialize(fake_fil)
    fake_fil.flush()


def main():
    server_addr = '3.17.246.73'
    client_addr = '10.87.21.23'
    nce = do_connect(client_addr, server_addr, None)
    print(f'ok lol {nce}')
    do_connect(client_addr, server_addr, nce)
    print('ok done')


def do_connect(client_addr, server_addr, nonce):
    with socket.socket() as sock:
        sock.connect((server_addr, PORT))
        with sock.makefile(mode='rwb') as fake_fil:
            send_pkt(fake_fil, version_pkt(client_addr, server_addr, nonce))
            remote_ver = recv_pkt(fake_fil)
            print(f'nonce: {remote_ver.nNonce}')
            send_pkt(fake_fil, msg_verack())
            remote_verack = recv_pkt(fake_fil)
            send_pkt(fake_fil, msg_getaddr())
            try:
                while True:
                    recv_pkt(fake_fil)
            except KeyboardInterrupt:
                pass
    return remote_ver.nNonce


if __name__ == '__main__':
    main()
