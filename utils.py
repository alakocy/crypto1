# -*- coding: utf-8 -*-
"""
Created on Sat Feb 24 13:41:01 2018

@author: alakocy
"""


import binascii
import base64
import string
import Crypto
from Crypto.Cipher import AES
from Crypto.Random import random
from copy import deepcopy


###############################################################################
#Conversion Functions

def hex_to_bits(hex_str):
    return binascii.unhexlify(hex_str)

def bits_to_hex(b_str):
    return bytes.decode(binascii.hexlify(b_str))

def b64_to_bits(b64_str):
    return base64.b64decode(b64_str)

def bits_to_b64(b_str):
    return bytes.decode(base64.b64encode(b_str))

###############################################################################
#Operation & Scoring Functions

def onetimepad_xor(b_str_1, b_str_2):
    assert len(b_str_1) == len(b_str_2)
    b_out = b''
    for b_a, b_b in zip(b_str_1, b_str_2):
#        b_out += bytes(chr(b_a^b_b),"utf8")
        b_out += bytes([b_a^b_b])
    return b_out

def single_xor(b_str, b_chr):
    b_out = b''
    for b_a in b_str:
        b_out += bytes(chr(b_a^ord(b_chr)),"utf8")
    return b_out

def repeat_xor(b_str, b_key):
    a = len(b_str)
    b = len(b_key)
#    if a<b:
#        return onetimepad_xor(b_str,b_key[:a])
    b_pad = b''
    i = 0
    while i+b<=a:
        b_pad += b_key
        i += b
    b_pad += b_key[:a%b]
    return onetimepad_xor(b_str,b_pad)

def score_message(str_mess):
    score_int = 0
    ascending_list = ["Z","z","J","j","Q","q","X","x","K","k","V","v","B","b",
                      "P","p","G","g","W","w","Y","y","F","f","M","m","C","c",
                      "U","u","L","l","D","d","H","h","R","r","S","s","N","n",
                      "I","i","O","o","A","a","T","t","E","e"]
    for char in str_mess:
#        if char not in string.printable:
#            return 0
        if char in ascending_list:
            score_int += ascending_list.index(char)
    return score_int

def hamming(b_str_1,b_str_2):
    assert len(b_str_1) == len(b_str_2)
    def bitwise_diff(n1,n2):
        d = 0
        for i in range(8):
            if n1%2 != n2%2: d+=1
            n1,n2 = n1//2,n2//2
        return d
    dist = 0
    for b_a,b_b in zip(b_str_1,b_str_2):
        dist += bitwise_diff(b_a,b_b)
    return dist


def pad_pkcs7(mess_block, block_size=16):
    a = block_size - len(mess_block)
    pad_list = []
    for i in range(a):
        pad_list.append(a)
    mess_pad = bytearray(pad_list)
    return mess_block + mess_pad

def separate_blocks(b_inp, block_size=16):
    blocks = []
    a = len(b_inp)
    i = 0
    while i+block_size<=a:
        blocks.append(b_inp[i:i+block_size])
        i += block_size
    if i < a:
#        b = a - i
        block_comp = b_inp[i:]
        blocks.append(pad_pkcs7(block_comp))
#        for j in range(b):
#            block_comp += bytes('0','utf8')
#        blocks.append(block_comp)
    return blocks

###############################################################################
#Encryption/Decryptior/Break Functions

def detect_single_xor(b_str):
    max_score = (0,0,"")
    for i in range(128):
        cur_score = (0,0,"")
        x_chr = chr(i)
        b_chr = bytes(x_chr,"utf8")
        b_mess = single_xor(b_str,b_chr)
        cur_str = bytes.decode(b_mess)
        cur_score = (i,score_message(cur_str),x_chr)
        if cur_score[1] > max_score[1]:
            max_score = cur_score
            top_mess = cur_str
    return(top_mess, max_score)

def break_repeat_xor(b_str):
    guesses = []
    scores = []
    
    start = 2
    end = 40
    for keysize_guess in range(start,end):
        count = 0
        block = []
        for i in range(4):
            block.append(b_str[i*keysize_guess:(i+1)*keysize_guess])
        hams = []
        for j in range(3,0,-1):
            b_1 = block.pop()
            for k in range(j):
                hams.append(hamming(b_1,block[k]))
                count += 1
        ham = sum(hams)/count
        guesses.append(keysize_guess)
        scores.append(ham/keysize_guess)
    
    best_score = min(scores)
    best_guess = guesses[scores.index(best_score)]
    
    use_scores = []
    use_guesses = []
    
    x = 5
    # Create "Top x" list of keysize guesses to try
    for i in range(x): # Update to 5 when ready
        best_score = min(scores)
        best_guess = guesses[scores.index(best_score)]
        scores.remove(best_score)
        guesses.remove(best_guess)
        use_scores.append(best_score)
        use_guesses.append(best_guess)
    
    inp_len = len(b_str)
    keys = []
    messages = []
    for keysize in use_guesses: # Top 5 keysizes are tested
        a = inp_len//keysize #Length of shortest transposed blocks
        b = inp_len%keysize #Number of transposed blocks with length a+1
    #    transposed_blocks = []
        top_chars = b''
        decoded_blocks = []
        for blk in range(keysize): # Ex: keysize = 5, blk = [0:5]
            if blk<b: # First b blocks get (a+1) bytes
                t_b = bytearray(a+1)
            else: # Remaining blocks get (a) bytes
                t_b = bytearray(a)
            i = 0
            for ind in range(blk,inp_len,keysize):
                t_b[i] = b_str[ind]
                i += 1
    #        transposed_blocks.append(t_b)
            r = detect_single_xor(t_b)
            top_chars += bytes(r[1][2],"utf8")
            decoded_blocks.append(r[0])
        
        keys.append(bytes.decode(top_chars))
        messages.append(bytes.decode(repeat_xor(b_str,top_chars),"utf8"))
    return (use_guesses, keys, messages)


def encrypt_AES(b_p, key, mode):
    cipher = AES.new(key, mode)
    return cipher.encrypt(b_p)

def decrypt_AES(b_c, key, mode):
    cipher = AES.new(key, mode)
    return cipher.decrypt(b_c)

def encrypt_ECB(b_p_inp, b_key):
    disjoined = separate_blocks(b_p_inp)
    joined = b"".join(disjoined)
    return encrypt_AES(joined, b_key, AES.MODE_ECB)

def decrypt_ECB(b_c_inp, b_key):
    padded_ptext = decrypt_AES(b_c_inp, b_key, AES.MODE_ECB)
    print(padded_ptext)
    pad_val = padded_ptext[-1]
    print(pad_val)
    padded_len = len(padded_ptext)
    for i in range(padded_ptext[-1]):
        if padded_ptext[padded_len-i-1] != pad_val:
            return padded_ptext
    return padded_ptext[:len(padded_ptext)-i-1]
    

def encrypt_CBC(b_p_inp, b_key, b_iv):
    def encrypt_block(b_p_block, b_xor_block, b_key):
        assert (len(b_p_block) == 16 and len(b_xor_block) == 16) and len(b_key) == 16
        b_inp_block = onetimepad_xor(b_p_block, b_xor_block)
        assert len(b_inp_block) == 16
        b_block_out = encrypt_AES(b_inp_block, b_key, AES.MODE_ECB)
        return b_block_out
    b_p_blocks = separate_blocks(b_p_inp)
    b_c_mess = b""
    b_xor_block = b_iv
    for b_p_block in b_p_blocks:
        b_xor_block = encrypt_block(b_p_block, b_xor_block, b_key)
        b_c_mess += b_xor_block
    return b_c_mess

def decrypt_CBC(b_c_inp, b_key, b_iv):
    def decrypt_block(b_c_block, b_xor_inp, b_key):
        assert (len(b_c_block) == 16 and len(b_xor_inp) == 16) and len(b_key) == 16
        b_out_block = decrypt_AES(b_c_block, b_key, AES.MODE_ECB)
        b_p_block = onetimepad_xor(b_out_block, b_xor_inp)
        assert len(b_p_block) == 16
        return b_p_block
    b_c_blocks = separate_blocks(b_c_inp)
    b_p_mess = b""
    b_xor_block = b_iv
    for b_c_block in b_c_blocks:
        b_out_block = decrypt_block(b_c_block, b_xor_block, b_key)
        b_xor_block = b_c_block
        b_p_mess += b_out_block
    return b_p_mess

def random_AES_key(keysize = 16):
    key = b""
    for i in range(keysize):
        key += bytes([random.getrandbits(8)])
    return key

def encryption_oracle_2_11(b_p_inp):
    b_key = random_AES_key()
    
    prepend_n_bytes = random.randint(5,10)
    append_n_bytes = random.randint(5,10)
    for i in range(prepend_n_bytes):
        b_p_inp = bytes([random.getrandbits(8)])+b_p_inp
    for j in range(append_n_bytes):
        b_p_inp += bytes([random.getrandbits(8)])
    #0: ECB
    #1: CBC
    decision = random.randint(0,1)
    if decision:
        b_iv = b""
        for k in range(16):
            b_iv += bytes([random.getrandbits(8)])
        return (encrypt_CBC(b_p_inp, b_key, b_iv),"CBC")
    else:
        return (encrypt_ECB(b_p_inp, b_key),"ECB")
    

#Original passes if string len%16 == 0 (i.e. no padding is needed)
#3_17 version passes only if padding exists AND is valid

def validate_pkcs7(b_inp_pt, block_size=16):
    ln = len(b_inp_pt)
    last_block = b_inp_pt[ln-block_size:]
    assert len(last_block) == block_size
    
    test_n = last_block[-1]
    
    if test_n < 1 or test_n > block_size:
        raise Exception("Invalid Padding")
    
    if last_block[block_size-test_n:] != bytes([test_n]*test_n):
        raise Exception("Invalid Padding")
    
    return b_inp_pt
    