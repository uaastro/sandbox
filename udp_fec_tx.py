import socket
import struct
import time
import click
import zfec

@click.command()
@click.option('--mpkts', default=2048, help='udp max pkt size def: 2048')
@click.option('--ip_rx', default='127.0.0.1', help='ip of sorce stream def: 127.0.0.1')
@click.option('--port_rx', default=5600, help='port of source stream def: 5700')
@click.option('--ip_tx', default='127.0.0.1', help='ip of destination host def: 127.0.0.1')
@click.option('--port_tx', default=5680, help='first port of destination hosts def: 5680')
@click.option('--k', default=24, help='fec k param (min fec blocks number to be recoverd) def: 24')
@click.option('--m', default=36, help='fec m param (fec bloks number of fec ring) def: 36')

def main(mpkts,ip_rx,port_rx,ip_tx,port_tx,k,m):

    def fec_encode(d_k,d_m,bloks: list) -> list:
        encoder = zfec.Encoder(d_k, d_m)
        try:
            encoded_blocks = encoder.encode(bloks)
        except Exception as e:
            encoded_blocks = []            
        return encoded_blocks    

    def blocks_encoder(blocks: list) -> list:
        encoded_blocks = []
        max_block_size = 0
        for block in blocks:
            block_size = len(block)
            if block_size > max_block_size:
                max_block_size = block_size
        for block in blocks:
            block_size = len(block)
            if block_size < max_block_size:
                ext_block = b'ff'*(max_block_size-block_size)
                encoded_block = struct.pack("!I"+str(block_size)+"s"+ str(len(ext_block))+"s", block_size, block, ext_block)
            else:
                encoded_block = struct.pack("!I"+str(block_size)+"s", block_size, block)
            encoded_blocks.append(encoded_block)
        return encoded_blocks

    def blocks_decoder(blocks: list) -> list:
        decoded_blocks = []
        for block in blocks:
            cblock_size = len(block)
            block_size, data= struct.unpack("!I"+str((cblock_size - 4))+"s", block)
            decoded_block, add_block = struct.unpack(str(block_size)+"s"+str(len(data) - block_size)+"s", data)
            decoded_blocks.append(decoded_block)
        return decoded_blocks

    def fec_decode(d_k,d_m,bloks: list,b_indexes: list) -> list:
        decoder = zfec.Decoder(d_k, d_m)
        try:
            decoded_blocks = decoder.decode(bloks,b_indexes)
        except Exception as e:
            decoded_blocks = []            
        return decoded_blocks    
    
    #--init--
    sock_tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock_rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_rx.bind((ip_rx, port_rx))

    print("udp_fec_tx started...")
    print(f"rx: {ip_rx} : {port_rx}")
    print(f"rx: {ip_tx} : {port_tx}")
    print(f"k: {k}")
    print(f"m: {m}")

    while True:

        data, addr = sock_rx.recvfrom(mpkts)
        PACKET_SIZE = len(data)

        sock_tx.sendto(data,(ip_tx, port_tx))


if __name__ == '__main__':
    main()

