import pika
import sys
import os
import CipherGen
import CryptanalysisLib


def main():
    connection = pika.BlockingConnection(
        pika.ConnectionParameters(host='localhost'))
    channel = connection.channel()

    channel.exchange_declare(exchange='exchangeOne', exchange_type='fanout')

    result = channel.queue_declare(queue='QueueOne', exclusive=True)
    queue_name = result.method.queue

    channel.queue_bind(exchange='exchangeOne', queue=queue_name)

    print(' [*] Waiting for exchangeOne. To exit press CTRL+C')

    def callback(ch, method, properties, body):
        print(" [x] Encrypted %r" % body)
        plain_text = perform_attack(1, body)
        print(plain_text)

    channel.basic_consume(
        queue=queue_name, on_message_callback=callback, auto_ack=True)

    channel.start_consuming()


def perform_attack(attackType, messageBody):
    if attackType == 2:
        keystream_decr = CryptanalysisLib.cipher_attack(
            2, "HELLO", messageBody.decode('utf-8'))
        plaintext_decr = CryptanalysisLib.decrypt_message(
            2, keystream_decr, messageBody.decode('utf-8'))
        return plaintext_decr
    elif attackType == 1:
        keystream_decr = CryptanalysisLib.cipher_attack(
            1, "HELLO", messageBody.decode('utf-8'))
        plaintext_decr = CryptanalysisLib.decrypt_message(
            1, keystream_decr, messageBody.decode('utf-8'))
        return plaintext_decr
    pass


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
