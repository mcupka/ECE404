# USING PYTHON 3.6.7

# Homework Number: 6
# Name: Michael Cupka
# ECN Login: mcupka
# Due Date: February 26, 2019

import sys
import os
from PrimeGenerator import PrimeGenerator
from BitVector import *



# function to find the gcd of two integers using euclid's extended algorithm
def gcd_euclid(a: int, b: int) -> int:
    # this algorithm is copied from the lecture 5 slides
    while b:
        a, b = b, a%b
    return a

# funciton to do modular exponentiation using CRT for large numbers (used for decryption)
def exp_mod(a, b, n, p, q):
    # find a^b (mod n), using prime factors p and q of n

    # this code follows the procedure in the lecture slides
    vp = pow(a, (b % (p-1)), p) # implements fermat's little theorem
    vq = pow(a, (b % (q-1)), q)

    bv_p = BitVector(intVal=p)
    bv_q = BitVector(intVal=q)
    q_inv = bv_q.multiplicative_inverse(bv_p).int_val()
    p_inv = bv_p.multiplicative_inverse(bv_q).int_val()

    xp = q * q_inv
    xq = p * p_inv

    return ((vp * xp) + (vq * xq)) % n


def rsa_enc(input_fname: str, output_fname: str):
    e = 65537   #given enc exponent
    pgen = PrimeGenerator(bits=128)

    pq_cond = False
    while(pq_cond == False):

        p, q = (pgen.findPrime(), pgen.findPrime())
        p_bv, q_bv = BitVector(size=128, intVal=p), BitVector(size=128, intVal=q)

        # now test to see if the conditions are met
        pq_cond = True
        # check that the first bits are set
        if p_bv[0] == 0 or q_bv[0] == 0: pq_cond = False
        # check that p and q are not equal
        if p == q: pq_cond = False
        # check that p-1 and q-1 are coprime to e
        if gcd_euclid(p-1, e) != 1 or gcd_euclid(q-1, e) != 1: pq_cond = False
        # if any of the above checks are not passed, a new p and q will be generated and checked

    # save p and q values in text documents for use with the decryption algorithm
    pFile = open('p.txt', 'w')
    qFile = open('q.txt', 'w')
    pFile.write(str(p))
    qFile.write(str(q))
    pFile.close()
    qFile.close()

    e_bv = BitVector(intVal=e)
    d_bv = e_bv.multiplicative_inverse(BitVector(intVal = (p - 1) * (q - 1), size=256))
    d = d_bv.int_val()

    dFile = open('d.txt', 'w')
    dFile.write(str(d))

    # now we can encrypt the plaintext using e, p, and q
    input_bv = BitVector(filename=input_fname)
    output_file = open(output_fname, 'w')
    while input_bv.more_to_read:
        one_block_bv = input_bv.read_bits_from_file(128)
        one_block_bv.pad_from_right(128 - one_block_bv.length()) # pad the final block from the right
        one_block_bv.pad_from_left(128) # pad each block from the left to make 256 bits

        # encrypt the block
        enc_block_bv = BitVector(intVal=pow(one_block_bv.int_val(), e, p * q), size = 256)

        # write the block to the output file in hex format
        hexstr = enc_block_bv.get_hex_string_from_bitvector()
        output_file.write(hexstr)


def rsa_dec(input_fname: str, output_fname: str):
    e = 65537   #given enc exponent

    # get p, q, and d values from the files they are stored in
    pFile = open('p.txt', 'r')
    qFile = open('q.txt', 'r')
    dFile = open('d.txt', 'r')
    p = int(pFile.read())
    q = int(qFile.read())
    d = int(dFile.read())

    # now decrypt the file using d, p, and q
    input_bv = BitVector(filename=input_fname)
    output_file = open(output_fname, 'wb')
    while input_bv.more_to_read:
        # get one block
        one_block_hex_bv = input_bv.read_bits_from_file(512)
        one_block_bv = BitVector(hexstring=one_block_hex_bv.get_bitvector_in_ascii())

        # decrypt the block, removing the zeros from the beginning (the first 128 bits of the decrypted block shoudl be 0)
        dec_block_bv = BitVector(intVal=exp_mod(one_block_bv.int_val(), d, p * q, p, q), size = 128)

        # write the block to the output file
        dec_block_bv.write_to_file(output_file)



if __name__ == "__main__":
    # get the args to determine if we are encrypting or decrypting
    if sys.argv[1] == '-e':
        rsa_enc(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == '-d':
        rsa_dec(sys.argv[2], sys.argv[3])
    else: print('Must use -e or -d flag to encrypt or decrypt')

