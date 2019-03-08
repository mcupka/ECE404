#!/usr/bin/env python3
from BitVector import *
import sys


# Function that uses the logic from lecture to
# test a key.
def try_key(key: str, enc_text: str) -> str:

    # Hardcoded passphrase from lecture code
    PassPhrase = "Hopes and dreams of a million years"

    BLOCKSIZE = 16
    num_bytes = BLOCKSIZE // 8

    # Reduce passphrase to bit array
    bv_iv = BitVector(bitlist=[0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // num_bytes):
        textstr = PassPhrase[i * num_bytes:(i + 1) * num_bytes]
        bv_iv ^= BitVector(textstring=textstr)

    # create BitVector from the encrypted text in encrypted.txt
    encrypted_bv = BitVector(hexstring=enc_text)

    # Reduce the key to a bit array:
    key_bv = BitVector(bitlist=[0] * BLOCKSIZE)
    for i in range(0, len(key) // num_bytes):
        keyblock = key[i * num_bytes:(i + 1) * num_bytes]
        key_bv ^= BitVector(textstring=keyblock)

    # Decrypted message BitVector
    msg_decrypted_bv = BitVector(size=0)

    # XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv  # (U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    output_text = msg_decrypted_bv.get_text_from_bitvector()

    return output_text


# main code to test every possible key
if __name__ == "__main__":

    # get encrypted text from the file
    input_file = open("encrypted.txt")
    enc_text = input_file.read()

    text_to_find = "Cormac McCarthy"

    print('\nTesting keys:\n')

    for test_key in range(pow(2, 16)):
        bv_key = BitVector(intVal=test_key, size=16)
        ascii_key = bv_key.get_bitvector_in_ascii()
        print(ascii_key)
        test_output = try_key(key=ascii_key, enc_text=enc_text)
        if text_to_find in test_output:
            print(f'\nKey value: {ascii_key}\nDecrypted Message:\n{test_output}')
            break
