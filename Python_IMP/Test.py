from pytrivium import Trivium
import numpy as np
from pylfsr import LFSR

# Set 6, vector# 3:
key = [0xfa, 0xa7, 0x54, 0x01, 0xae, 0x5b, 0x08, 0xb5, 0x62, 0x0f]
iv = [0xc7, 0x60, 0xf9, 0x92, 0x2b, 0xc4, 0x5d, 0xf6, 0x8f, 0x28]

engine = Trivium()
engine.initialize(key, iv)

engine.update(8)

output = engine.finalize()

print([hex(i) for i in output])


state = [1, 0, 1]
fpoly = [3, 2]
L = LFSR(initstate=state, fpoly=fpoly, counter_start_zero=False)
print('count \t state \t\toutbit \t seq')
print('-'*50)
for _ in range(15):
    print(L.count, L.state, '', L.outbit, L.seq, sep='\t')
    L.next()
print('-'*50)
print('Output: ', L.seq)
