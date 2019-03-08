#!/usr/bin/env python3

# Homework Number: 4
# Name: Michael Cupka
# ECN Login: mcupka
# Due Date: February 12, 2019


import sys
from BitVector import *

# the bitpattern for the irreducable polynomial used in AED
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []

def encypt(pt_filename: str, enc_key: str, ct_filename: str):

    # to encrypt, we need to do: xor input SA with first 4 words of key schedule
    # then 14 rounds of
    # 1. sub bytes
    # 2. shift rows
    # 3. mix cols (except for last round)
    # 4. add round key

    # get the key schedule
    key_schedule = generateKeySchedule(enc_key)

    getSubTables()

    bv = BitVector(filename=pt_filename)
    output_file = open(ct_filename, 'w')

    while bv.more_to_read:
        # get block
        bitvec = bv.read_bits_from_file(128)
        bitvec.pad_from_right(128 - bitvec.length())

        # The above padding ensures that a full block is operated on. This causes some padding to be present in the
        # decrypted output if padding was needed for encryption.

        # init state array
        statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                statearray[i][j] = bitvec[32*j + 8*i:32*j + 8 * (i + 1)]

        # xor the SA with the first 4 words of the round key
        key_array = [[0 for x in range(4)] for x in range(4)]
        for j in range(4):
            keyword = key_schedule[j]
            for i in range(4):
                key_array[i][j] = keyword[i * 8:i * 8 + 8]

        statearray = stateArrXor(statearray, key_array)

        # Do 14 rounds of processing
        for roundNum in range(14):

            # get round key matrix
            key_array = [[0 for x in range(4)] for x in range(4)]
            for j in range(4):
                roundkw = key_schedule[j + 4 * (roundNum + 1)]
                for i in range(4):
                    key_array[i][j] = roundkw[i * 8:i * 8 + 8]


            statearray = subBytes(statearray)

            statearray = shiftRows(statearray)

            if roundNum != 13:
                statearray = mixCols(statearray)

            statearray = stateArrXor(statearray, key_array)

        # now write the state array to the ciphertext file
        for j in range(4):
            for i in range(4):
                bv_to_print = statearray[i][j]
                hexstr = bv_to_print.get_hex_string_from_bitvector()
                output_file.write(hexstr)


def shiftRows(statearray):
    shifted = [[None for x in range(4)] for x in range(4)]

    for j in range(4):
        shifted[0][j] = statearray[0][j]
    for j in range(4):
        shifted[1][j] = statearray[1][(j + 1) % 4]
    for j in range(4):
        shifted[2][j] = statearray[2][(j + 2) % 4]
    for j in range(4):
        shifted[3][j] = statearray[3][(j + 3) % 4]
    return shifted

def mixCols(statearray):
    mixed = [[0 for x in range(4)] for x in range(4)]

    for j in range(4):
        bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8)
        bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8)
        mixed[0][j] = bv1 ^ bv2 ^ statearray[2][j] ^ statearray[3][j]
    for j in range(4):
        bv1 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8)
        bv2 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8)
        mixed[1][j] = bv1 ^ bv2 ^ statearray[0][j] ^ statearray[3][j]
    for j in range(4):
        bv1 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8)
        bv2 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8)
        mixed[2][j] = bv1 ^ bv2 ^ statearray[0][j] ^ statearray[1][j]
    for j in range(4):
        bv1 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='02'), AES_modulus, 8)
        bv2 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='03'), AES_modulus, 8)
        mixed[3][j] = bv1 ^ bv2 ^ statearray[1][j] ^ statearray[2][j]
    return mixed

# perform subBytes operation
def subBytes(statearray):
    for i in range(4):
        for j in range(4):
            statearray[i][j] = BitVector(intVal = subBytesTable[int(statearray[i][j])], size=8)
    return statearray

# function to get sub tables
def getSubTables():
    c = BitVector(bitstring='001100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

# function to xor two state arrays
def stateArrXor(sa1, sa2):
    for i in range(4):
        for j in range(4):
            sa1[i][j] = sa1[i][j] ^ sa2[i][j]
    return sa1



def generateKeySchedule(key: str) -> list:

    # init schedule list and round constant
    schedule = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)

    # create BitVector from the key
    key_bv = BitVector(textstring=key)

    # get byte sub table
    byte_sub_table = gen_subbytes_table()

    for i in range(8):
        schedule[i] = key_bv[i * 32: i * 32 + 32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = gee(schedule[i - 1], round_constant, byte_sub_table)
            schedule[i] = schedule[i - 8] ^ kwd
        elif(i - (i // 8) * 8) < 4:
            schedule[i] = schedule[i - 8] ^ schedule[i - 1]
        elif (i - (i // 8) * 8) == 4:
            schedule[i] = BitVector(size=0)
            for j in range(4):
                schedule[i] += BitVector(intVal=byte_sub_table[schedule[i - 1][8 * j:8 * j + 8].intValue()], size=8)
            schedule[i] ^= schedule[i - 8]
        elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
            schedule[i] = schedule[i - 8] ^ schedule[i - 1]
        else:
            sys.exit(f"error in key scheduling algorithm for i = {i}")
    return schedule


# function to get the subbytes table
def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable


# g function used to generate the keys
def gee(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[8 * i:8 * i + 8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant


def decrypt(ct_filename: str, enc_key: str, pt_filename: str):


    key_schedule = generateKeySchedule(enc_key)


    getSubTables()

    bv = BitVector(filename=ct_filename)
    output_file = open(pt_filename, 'wb')


    while bv.more_to_read:
        # get a block. reading 256 bits in order to convert from ascii to hex values
        encrypted_text = bv.read_bits_from_file(256)
        bitvec = BitVector(hexstring=encrypted_text.get_bitvector_in_ascii())


        bitvec.pad_from_right(128 - bitvec.length())

        # init state array
        statearray = [[0 for x in range(4)] for x in range(4)]
        for i in range(4):
            for j in range(4):
                statearray[i][j] = bitvec[32 * j + 8 * i:32 * j + 8 * (i + 1)]

        # xor the SA with the first 4 words of the round key
        key_array = [[0 for x in range(4)] for x in range(4)]
        for j in range(4):
            keyword = key_schedule[56 + j]
            for i in range(4):
                key_array[i][j] = keyword[i * 8:i * 8 + 8]

        statearray = stateArrXor(statearray, key_array)

        # Do 14 rounds of processing
        for roundNum in range(14):
            # get round key matrix
            key_array = [[0 for x in range(4)] for x in range(4)]
            for j in range(4):
                roundkw = key_schedule[j + 52 - 4 * roundNum]
                for i in range(4):
                    key_array[i][j] = roundkw[i * 8:i * 8 + 8]


            statearray = invShiftRows(statearray)
            statearray = invSubBytes(statearray)
            statearray = stateArrXor(statearray, key_array)
            if roundNum != 13:
                statearray = invMixCols(statearray)

        # now write the state array to the output file
        for j in range(4):
            for i in range(4):
                bv_to_print = statearray[i][j]
                bv_to_print.write_to_file(output_file)


# inverse shift rows
def invShiftRows(statearray):
    shifted = [[None for x in range(4)] for x in range(4)]

    for j in range(4):
        shifted[0][j] = statearray[0][j]
    for j in range(4):
        shifted[1][j] = statearray[1][(j - 1) % 4]
    for j in range(4):
        shifted[2][j] = statearray[2][(j - 2) % 4]
    for j in range(4):
        shifted[3][j] = statearray[3][(j - 3) % 4]
    return shifted

# inverse mix columns
def invMixCols(statearray):
    mixed = [[0 for x in range(4)] for x in range(4)]

    for j in range(4):
        bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='0e'), AES_modulus, 8)
        bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='0b'), AES_modulus, 8)
        bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='0d'), AES_modulus, 8)
        bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='09'), AES_modulus, 8)
        mixed[0][j] = bv1 ^ bv2 ^ bv3 ^ bv4
    for j in range(4):
        bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='09'), AES_modulus, 8)
        bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='0e'), AES_modulus, 8)
        bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='0b'), AES_modulus, 8)
        bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='0d'), AES_modulus, 8)
        mixed[1][j] = bv1 ^ bv2 ^ bv3 ^ bv4
    for j in range(4):
        bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='0d'), AES_modulus, 8)
        bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='09'), AES_modulus, 8)
        bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='0e'), AES_modulus, 8)
        bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='0b'), AES_modulus, 8)
        mixed[2][j] = bv1 ^ bv2 ^ bv3 ^ bv4
    for j in range(4):
        bv1 = statearray[0][j].gf_multiply_modular(BitVector(hexstring='0b'), AES_modulus, 8)
        bv2 = statearray[1][j].gf_multiply_modular(BitVector(hexstring='0d'), AES_modulus, 8)
        bv3 = statearray[2][j].gf_multiply_modular(BitVector(hexstring='09'), AES_modulus, 8)
        bv4 = statearray[3][j].gf_multiply_modular(BitVector(hexstring='0e'), AES_modulus, 8)
        mixed[3][j] = bv1 ^ bv2 ^ bv3 ^ bv4
    return mixed


# perform subBytes operation
def invSubBytes(statearray):
    for i in range(4):
        for j in range(4):
            statearray[i][j] = BitVector(intVal = invSubBytesTable[int(statearray[i][j])], size=8)
    return statearray


if __name__ == "__main__":
    # get the key from the key file
    keyFile = open("key.txt")
    key = keyFile.read()

    # run the algorithms on the message file and then the encrypted file
    encypt("message.txt", key, "encrypted.txt")
    decrypt("encrypted.txt", key, "decrypted.txt")
