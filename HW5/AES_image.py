#!/usr/bin/env python3
# using python 3.6.7

# Homework Number: 5
# Name: Michael Cupka
# ECN Login: mcupka
# Due Date: February 17, 2019

from BitVector import *
from time import time

########################Copied from my x931 implementation##############################

# the bitpattern for the irreducable polynomial used in AED
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []

def aes_encypt(pt: str, key_schedule: list) -> str:

    # to encrypt, we need to do: xor input SA with first 4 words of key schedule
    # then 14 rounds of
    # 1. sub bytes
    # 2. shift rows
    # 3. mix cols (except for last round)
    # 4. add round key

    # get the key schedule

    bitvec = BitVector(textstring=pt)
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


    ct = ''
    # now write the state array to the ciphertext file
    for j in range(4):
        for i in range(4):
            bv_to_print = statearray[i][j]
            hexstr = bv_to_print.get_text_from_bitvector()
            ct += hexstr
    return ct


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


def x931(v0, dt, totalNum, key_file = 'key.txt') -> list:

    # get the aes enc key from the file
    key = open(key_file).read()


    # part of the encryption algorithm moved to remove redundancy
    key_schedule = generateKeySchedule(key)
    getSubTables()

    # list of pr numbers generated
    pr_nums = []

    v_val = v0
    #generate totalNum random numbers
    for _ in range(totalNum):
        #encypt data and time
        dt_encrypted = BitVector(textstring=aes_encypt(dt.get_text_from_bitvector(), key_schedule))

        #xor with v
        dt_enc_xor_v = dt_encrypted ^ v_val

        #encrypt again to det random number
        r_val = BitVector(textstring=aes_encypt(dt_enc_xor_v.get_text_from_bitvector(), key_schedule))
        pr_nums.append(r_val.int_val())

        #obtain next v_val
        v_val = BitVector(textstring=aes_encypt((dt_encrypted ^ r_val).get_text_from_bitvector(), key_schedule))

    return pr_nums

###############################################################################



def ctr_aes_image(iv, image_file = 'image.ppm', out_file = 'enc_image.ppm', key_file = 'key.txt'):
    # get the AES key from key.txt and generate the key schedule for AES
    key = open(key_file).read()
    key_schedule = generateKeySchedule(key)
    # get sub tables for AES
    getSubTables()

    # open the image file
    image_bv = BitVector(filename=image_file)

    # open the output file
    output_image = open(out_file, 'wb')

    # copy the header of the original file to the output image
    newline_count = 0
    while newline_count < 3:
        one_char = image_bv.read_bits_from_file(8)
        one_char.write_to_file(output_image)
        if one_char.get_bitvector_in_ascii() == '\n':
            newline_count += 1

    # get each block, encrypt, write to file
    while image_bv.more_to_read:
        one_block_bv = image_bv.read_bits_from_file(128)
        one_block_bv.pad_from_right(128 - one_block_bv.length())

        # encypt
        vec = BitVector(intVal=iv, size=128)
        enc_vec_bv = BitVector(textstring=(aes_encypt(vec.get_text_from_bitvector(), key_schedule)))
        enc_block_bv = enc_vec_bv ^ one_block_bv

        iv = (iv + 1) % (pow(2, 128))


        # write to file
        enc_block_bv.write_to_file(output_image)


if __name__ == '__main__':

    # get the initialization vector for the counter encryption
    time_val1 = int(time() * 1000000)
    time_val2 = int(time() * 1000000)
    bv_time1 = BitVector(intVal=time_val1, size=64)
    bv_time2 = BitVector(intVal=time_val2, size=64)
    dt_bitvec = bv_time1 + bv_time2
    v0 = BitVector(textstring='computersecurity')
    init_vec = x931(v0, dt_bitvec, 1)[0]
    ctr_aes_image(init_vec)
    ctr_aes_image(init_vec, 'enc_image.ppm', 'dec_image.ppm')






