import zfec
import struct

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
            ext_block = b"\xFF"*(max_block_size-block_size)
            encoded_block = struct.pack("!I"+str(block_size)+"s"+ str(len(ext_block))+"s", block_size, block, ext_block)
        else:
            encoded_block = struct.pack("!I"+str(block_size)+"s", block_size, block)
        encoded_blocks.append(encoded_block)
    return encoded_blocks

def ring_blocks_encoder(rb_id,e_k,e_m, blocks: list) -> list:
    encoded_blocks = []
    block_number = 0
    for block in blocks:
        block_size = len(block)
        encoded_block = struct.pack("!IIII"+str(block_size)+"s",rb_id, block_number, e_k, e_m, block)
        encoded_blocks.append(encoded_block)
        block_number+=1
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

def get_data(ring_size:int, min_block_size:int,ring_number:int ) -> list:
    data_list = []
    for i in range(ring_number):
        for k in range(min_block_size,min_block_size+ring_size):
            data_str = (str(i) * ((k // len(str(i))) + 1))[:k]
            data_block = data_str.encode('utf-8')
            data_list.append(data_block)
    return data_list

k = 3
m = 6
fec_ring_number = 4
data = get_data(k,1,fec_ring_number)
print ("k: ",k," m: ",m," fec_ring_number: ",fec_ring_number)
print('data: ', data)

# ====== TX ======
tx_list = []
fec_ring_id = 0
fec_ring_data = []
for i in range(k):
    fec_ring_data.append(data[i])

print("fec_ring_data: ",fec_ring_data)


encoded_blocks = blocks_encoder(fec_ring_data)
print ('encoded blocks: ',encoded_blocks)
for encoded_block in encoded_blocks:
    print(encoded_block,' : ', len(encoded_block))

#encoded_fragments = fec_encoder.encode(encoded_blocks)
encoded_fragments = fec_encode(k,m,encoded_blocks)
print('encoded data', encoded_fragments)

ring_tx_blocks = ring_blocks_encoder(fec_ring_id,k,m, encoded_fragments)
print ("ring_tx: ", ring_tx_blocks)

tx_list+= ring_tx_blocks
print(ring_tx_blocks)
# ====== RX ======
encoded_blocks = []
encoded_fragments = []
for ring_rx_block in tx_list:
    rx_ring_block_size = len(ring_rx_block)
    rb_id, block_number, e_k, e_m, encoded_block = struct.unpack("!IIII"+str((rx_ring_block_size - 16))+"s", ring_rx_block)
    encoded_fragments.append(encoded_block)
    print (rb_id, block_number, e_k, e_m, encoded_block)

print(encoded_fragments)

received_fragments = [encoded_fragments[0], encoded_fragments[2], encoded_fragments[5]]
print('recived fagments: ', received_fragments)
indexes = [0, 2, 5]

decoded_data = fec_decode(k,m,received_fragments,indexes)
print(decoded_data)

decoded_blocks = blocks_decoder(decoded_data)
print ('decoded blocks: ',decoded_blocks)