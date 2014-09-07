import os, psutil
from aes import AES

# Pin the Python process to CPU 0 to measure performance
# Note: this code works for psutil 1.2.x, not 2.x!
cpu_count = psutil.NUM_CPUS
p = psutil.Process(os.getpid())
p.set_cpu_affinity([0])

# Perform several encryption / decryption operations

random_iv = bytearray(os.urandom(16))
random_key = bytearray(os.urandom(16))

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
