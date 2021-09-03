import pika
import unicodedata
import subprocess
import codecs

from pylfsr import LFSR
from collections import deque
from itertools import repeat
from sys import version_info
from pytrivium import Trivium


class TrvivumUtil():

    def __init__(self, keyValue, initVector, n):
        self.engine = Trivium()
        self.key = keyValue
        self.iv = initVector
        self.engine.initialize(self.key, self.iv)
        self.engine.update(n)
        self.keystream = self.engine.finalize()
        self.keystream_new = convert_keystream(self.keystream)
        pass


_allbytes = dict([("%02X" % i, i) for i in range(256)])


def _hex_to_bytes(s):
    return [_allbytes[s[i:i+2].upper()] for i in range(0, len(s), 2)]


def hex_to_bits(s):
    return [(b >> i) & 1 for b in _hex_to_bytes(s)
            for i in range(8)]


def bits_to_hex(b):
    return "".join(["%02X" % sum([b[i + j] << j for j in range(8)])
                    for i in range(0, len(b), 8)])


def remove_accents(input_str):
    input_str = input_str.replace(u"\u2018", "\"").replace(
        u"\u2019", "\"").replace(u"\u201c", "\"").replace(u"\u201d", "\"")
    nkfd_form = unicodedata.normalize('NFKD', str(input_str))
    return u"".join([c for c in nkfd_form if not unicodedata.combining(c)])


def convert_keystream(outputKeystream):
    keystream_list = []
    for a in outputKeystream:
        binaryValue = bin(a)
        lengthValue = len(binaryValue)
        if lengthValue < 34:
            for s in range(34-lengthValue):
                keystream_list.append(int(0))
        for c in range(2, lengthValue):
            keystream_list.append(int(bin(a)[c]))
    return keystream_list


def simple_LFSR(messsageLength, initstate, polynomial,fromAttack):
    if fromAttack == False:
        state = [1, 1, 1]
        fpoly = [3, 2]
        keystream = []
        L = LFSR(initstate=state, fpoly=fpoly, counter_start_zero=False)
        for _ in range(messsageLength):
            keystream.append(L.outbit)
            L.next()
        return keystream
    elif fromAttack == True:
        state = initstate
        fpoly = polynomial
        keystream = []
        L = LFSR(initstate=state, fpoly=fpoly, counter_start_zero=False)
        for _ in range(messsageLength):
            keystream.append(L.outbit)
            L.next()
        return keystream

