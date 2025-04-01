#!/usr/bin/python3
import socket
import struct
import click

def get_data(d_n:int, d_bid:int) -> list:
    data_list = []
    for i in range(d_n):
        data_str = (str(d_bid) * (((i+1) // len(str(d_bid))) + 1))[:(i+1)]
        data_block = data_str.encode('utf-8')
        data_list.append(data_block)
    return data_list

@click.command()
@click.option('--mpkts', default=2048, help='udp max pkt size def: 2048')
@click.option('--ip_tx', default='127.0.0.1', help='ip of destination host def: 127.0.0.1')
@click.option('--port_tx', default=7600, help='port of destination hosts def: 7600')
@click.option('--n', default=3, help='amount of test blocks: 3')
@click.option('--bid', default=0, help='block id: 0')

def main(mpkts,ip_tx,port_tx,n,bid):

    #--init--
    sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("sbf_stream_gen started...")
    print(f"rx: {ip_tx} : {port_tx}")
    print(f"n: {n}")
    print(f"bid: {bid}")
    tx_list = get_data(n,bid)
    print (tx_list)
    # ====== TX ======
   
    for tx_data in tx_list:
        sock_tx.sendto(tx_data,(ip_tx, port_tx))
        print("tx data: ", tx_data)

if __name__ == '__main__':
    main()
