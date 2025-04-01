#!/usr/bin/python3
import socket
import struct
import click


@click.command()
@click.option('--mpkts', default=2048, help='udp max pkt size def: 2048')
@click.option('--ip_rx', default='0.0.0.0', help='ip of sorce stream def: 0.0.0.0')
@click.option('--port_rx', default=7800, help='port of source stream def: 7600')

def main(mpkts,ip_rx,port_rx):

    sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rx.bind((ip_rx, port_rx))

    print("udp_print started...")
    print(f"rx: {ip_rx} : {port_rx}")

    while True:
        data, addr = sock_rx.recvfrom(mpkts)
        print("\n",addr)
        print("\n",data)


if __name__ == '__main__':
    main()

