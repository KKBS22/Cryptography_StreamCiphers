import codecs
import CipherGen
import numpy as np


def Berlekamp_Massey_algorithm(sequence):
    N = len(sequence)
    s = sequence[:]

    for k in range(N):
        if s[k] == 1:
            break
    f = set([k + 1, 0])  # use a set to denote polynomial
    l = k + 1

    g = set([0])
    a = k
    b = 0

    for n in range(k + 1, N):
        d = 0
        for ele in f:
            d ^= s[ele + n - l]

        if d == 0:
            b += 1
        else:
            if 2 * l > n:
                f ^= set([a - b + ele for ele in g])
                b += 1
            else:
                temp = f.copy()
                f = set([b - a + ele for ele in f]) ^ g
                l = n + 1 - l
                g = temp
                a = b
                b = n - l + 1
    return (poly_coeff(f), l)


# output the polynomial
def poly_coeff(polynomial):
    result = []
    lis = sorted(polynomial, reverse=True)
    for i in lis:
        if i == 0:
            result.append(1)
        else:
            result.append(i)

        if i != lis[-1]:
            pass
        return result


def cipher_attack(cryptType, partMessage, cipherText):
    partkeystream = []
    randomkeystream = []
    actualkeystream = []
    plaintext = CipherGen.remove_accents(partMessage).upper()
    plaintext_hex = plaintext.encode('utf-8').hex().upper()
    plaintext_bin = CipherGen.hex_to_bits(plaintext_hex)
    ciphertext_bin = CipherGen.hex_to_bits(cipherText)
    if cryptType == 2:
        print("Performing Known-Plain Text Attack :")
        for a in range(len(plaintext_bin)):
            partkeystream.append(plaintext_bin[a] ^ ciphertext_bin[a])
        randomkeystream = partkeystream[: 7]
        for a in range(32):
            for b in randomkeystream:
                actualkeystream.append(b)
        return actualkeystream
    elif cryptType == 1:
        print("Performing Berlekamp-Massey Attack :")
        for a in range(len(plaintext_bin)):
            partkeystream.append(plaintext_bin[a] ^ ciphertext_bin[a])
        randomkeystream = partkeystream[:9]
        actualkeystream = find_sequence_lfsr(randomkeystream, ciphertext_bin)
        return actualkeystream


def decrypt_message(methodType, keystream, cipherMessage):
    ciphertext_bin = []
    plaintext_bin = []
    if methodType == 1:
        if (any(c.isalpha() for c in cipherMessage)):
            ciphertext_bin = CipherGen.hex_to_bits(cipherMessage)
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(keystream[i] ^ ciphertext_bin[i])
        else:
            ciphertext_bin = list(str(cipherMessage))
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(keystream[i] ^ int(ciphertext_bin[i]))

        plaintext_hex = CipherGen.bits_to_hex(plaintext_bin)
        plaintext = codecs.decode(
            plaintext_hex, 'hex').decode('ascii', 'ignore')
    elif methodType == 2:
        if (any(c.isalpha() for c in cipherMessage)):
            ciphertext_bin = CipherGen.hex_to_bits(cipherMessage)
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(keystream[i] ^ ciphertext_bin[i])
        else:
            ciphertext_bin = list(str(cipherMessage))
            for i in range(len(ciphertext_bin)):
                plaintext_bin.append(
                    keystream[i] ^ int(ciphertext_bin[i]))
        plaintext_hex = CipherGen.bits_to_hex(plaintext_bin)
        plaintext = codecs.decode(
            plaintext_hex, 'hex').decode('ascii', 'ignore')
    return plaintext


def find_sequence_lfsr(randomkeystream, cipherTxt):
    m_value = Berlekamp_Massey_algorithm(randomkeystream)
    print("Solving for simultaneous linear equations :")
    m_stream = randomkeystream[:m_value[1]]
    lhs = np.array([[randomkeystream[2], randomkeystream[1], randomkeystream[0]], [randomkeystream[3],
                                                                                   randomkeystream[2], randomkeystream[1]], [randomkeystream[4], randomkeystream[3], randomkeystream[2]]])
    rhs = np.array(
        [randomkeystream[3], randomkeystream[4], randomkeystream[5]])
    D = np.linalg.inv(lhs)
    E = np.dot(D, rhs)
    polynomial = []
    test = 1
    for a in E:
        if ((a > 0) or (a < 0)):
            polynomial.insert(0, test)
        test += 1
    actualkeystream = CipherGen.simple_LFSR(
        len(cipherTxt), m_stream, polynomial, True)
    return actualkeystream


#valtoreturn = Berlekamp_Massey_algorithm([1, 1, 1, 0, 0, 1, 0])
# print("Testing")
