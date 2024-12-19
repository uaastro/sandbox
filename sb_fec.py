import zfec

fec_encoder = zfec.Encoder(k=3, m=6)
fec_decoder = zfec.Decoder(k=3,m=6)

data = [b'11111 1',b'22222 2',b'12345 3']
print('data: ', data)
encoded_fragments = fec_encoder.encode(data)
print('encoded data', encoded_fragments)

received_fragments = [encoded_fragments[0], encoded_fragments[2], encoded_fragments[5]]
print('recived fagments: ', received_fragments)
indexes = [0, 2, 5]

decoded_data = fec_decoder.decode(received_fragments,indexes)
print(decoded_data)