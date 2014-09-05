from aes import AES
from os import urandom

random_iv = bytearray(urandom(16))
random_key = bytearray(urandom(16))

data = bytearray(range(256))
data1 = data[:151]
data2 = data[151:]

aes_ctr = AES(mode='ctr', key=random_key, iv=random_iv)
aes_ctr.encrypt(data1)
aes_ctr.encrypt(data2)

data_new = data1 + data2
aes_ctr = AES(mode='ctr', key=random_key, iv=random_iv)
aes_ctr.decrypt(data_new)

print (data == data_new)
