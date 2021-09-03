import pika
import unicodedata
import subprocess
import codecs
import CipherGen
import sys
import os

from collections import deque
from itertools import repeat
from sys import version_info
from pytrivium import Trivium

key = [0xfa, 0xa7, 0x54, 0x01, 0xae, 0x5b, 0x08, 0xb5, 0x62, 0x0f]
iv = [0xc7, 0x60, 0xf9, 0x92, 0x2b, 0xc4, 0x5d, 0xf6, 0x8f, 0x28]


def main():
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    channel.exchange_declare(exchange='exchangeOne', exchange_type='fanout')

    result = channel.queue_declare(queue='QueueTwo', exclusive=True)
    queue_name = result.method.queue

    channel.queue_bind(exchange='exchangeOne', queue=queue_name)

    print(' [*] Waiting for exchangeOne. To exit press CTRL+C')

    def callback(ch, method, properties, body):
        print(" [x] Received Encrypted %r" % body)
        print("Decrypting Message :")
        decrypted_message = decrypt_message(key, iv, body.decode('utf-8'),2)
        print(" [x] Decrypted Message %r" % decrypted_message)

    channel.basic_consume(
        queue=queue_name, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()


def decrypt_message(keyVal, initVector, cipherMessage, methodType):
    ciphertext_bin = []
    plaintext_bin = []
    if methodType == 1:
        triviumCipher = CipherGen.TrvivumUtil(keyVal, initVector, 7)
        #output = triviumCipher.keystream
        output_new = triviumCipher.keystream_new
        if (any(c.isalpha() for c in cipherMessage)):
            ciphertext_bin = CipherGen.hex_to_bits(cipherMessage)
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(output_new[i] ^ ciphertext_bin[i])
        else:
            ciphertext_bin = list(str(cipherMessage))
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(output_new[i] ^ int(ciphertext_bin[i]))

        plaintext_hex = CipherGen.bits_to_hex(plaintext_bin)
        plaintext = codecs.decode(
            plaintext_hex, 'hex').decode('ascii', 'ignore')
    elif methodType == 2:
        test_keystream = CipherGen.simple_LFSR(224, [1, 1, 1], [3, 2], False)
        if (any(c.isalpha() for c in cipherMessage)):
            ciphertext_bin = CipherGen.hex_to_bits(cipherMessage)
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(test_keystream[i] ^ ciphertext_bin[i])
        else:
            ciphertext_bin = list(str(cipherMessage))
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(
                    test_keystream[i] ^ int(ciphertext_bin[i]))
        plaintext_hex = CipherGen.bits_to_hex(plaintext_bin)
        plaintext = codecs.decode(
            plaintext_hex, 'hex').decode('ascii', 'ignore')
    return plaintext


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
