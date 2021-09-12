# Cryptography_StreamCiphers
Implementation of Trivium Stream Cipher and its comparison with a simple LFSR, Learning about its immunity to linear span attacks and the Berlekamp-Massey Algorithm. Using standard cryptanalysis techniques to understand Non-linear LFSR like trivium

# Technology
* Programming : Python
* Tools : Rabbit MQ
* Keywords : Cryptography, Cryptanalysis, Stream-Ciphers, IoT

# Abstract
With the advancement of technology, the Internet of
Things (IoT) brings a huge number of devices that link to each
other and gather massive amounts of data. As a result, IoT secuirity 
requirements are critical. Currently, cryptography is used to
protect networks for authentication, secrecy, data integrity, and
access control. Traditional cryptography protocols, on the other
hand, may not be suitable in all IoT contexts due to the resource
constraints. Therefore, a variety of lightweight cryptography
methods and protocols have been proposed by cryptography
researchers. In this paper, we investigate the state of the art
stream ciphers such as Simple-LFSR, A5/1 and Trivium ciphers
and analyse their internal structure. We further implement the
stream ciphers in software and conduct cryptanalysis such as
known-plaintext attack on them to understand their immunity
to attack. We conclude that Trivium is a secure stream cipher
compared to Simple-LFSR based stream cipher and A5/1
