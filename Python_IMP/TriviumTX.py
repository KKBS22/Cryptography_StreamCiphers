import pika
import CipherGen
import sys
import os
import codecs

from pylfsr import LFSR
from pytrivium import Trivium

key = [0xfa, 0xa7, 0x54, 0x01, 0xae, 0x5b, 0x08, 0xb5, 0x62, 0x0f]
iv = [0xc7, 0x60, 0xf9, 0x92, 0x2b, 0xc4, 0x5d, 0xf6, 0x8f, 0x28]


def generate_message(keyVal, initVector, message, method):
    plaintext = CipherGen.remove_accents(message).upper()
    plaintext_hex = plaintext.encode('utf-8').hex().upper()
    print(plaintext_hex)
    plaintext_bin = CipherGen.hex_to_bits(plaintext_hex)
    n = (len(plaintext_bin)/32)
    if (len(plaintext_bin) % 32 > 0):
        n = round(n)+1
    if method == 1:
        triviumCipher = CipherGen.TrvivumUtil(keyVal, initVector, int(n))
        output = triviumCipher.keystream
        output_new = triviumCipher.keystream_new
    elif method == 2:
        output_new = CipherGen.simple_LFSR(
            len(plaintext_bin), [1, 1, 1], [3, 2], False)
        output = 3

    print(output_new)
    ciphertext = []
    for i in range(len(plaintext_bin)):
        ciphertext.append(output_new[i] ^ plaintext_bin[i])

    if output == 'b' or output == 'B':
        return ''.join(map(str, ciphertext))
    else:
        return CipherGen.bits_to_hex(ciphertext)


def rabbit_send(cipherMessage):
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    channel.exchange_declare(exchange='exchangeOne', exchange_type='fanout')

    channel.basic_publish(exchange='exchangeOne',
                          routing_key='', body=cipherMessage)
    print(" [x] Sent %r" % cipherMessage)
    connection.close()


def send_message(sendStatus, methodType):
    message_transfer = "HELLO ALL WELCOME TO ECE 659"
    print("Actual Message : " + message_transfer)
    cipher_message = generate_message(key, iv, message_transfer, methodType)
    print("Encrypted Message : " + str(cipher_message))
    if sendStatus == True:
        rabbit_send(cipher_message)
    else:
        decrypted_message = decrypt_message(
            key, iv, cipher_message, methodType)
        print("Decrypted Message : " + str(decrypted_message))


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


def main():
    send_message(True, 2)


if __name__ == "__main__":
    main()
