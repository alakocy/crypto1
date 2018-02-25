# -*- coding: utf-8 -*-
"""
Created on Sat Feb 24 13:30:18 2018

@author: alakocy
"""

import utils
from utils import Crypto
from utils import deepcopy

def dish_3_17():
    global b_key
    
    str_list = [b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
                b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
                b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
                b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
                b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
                b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
                b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    
    print([len(a) for a in str_list])
    
    used_str = str_list[Crypto.Random.random.randint(0,9)]
#    used_str = str_list[8]
    print("Raw used_str: ",used_str)
    R = utils.separate_blocks(used_str)
    R[-1] = utils.pad_pkcs7(R[-1])
    pad_used_str = b"".join(R)
    print("Pad used_str: ",pad_used_str)
    
    b_iv = Crypto.Random.get_random_bytes(16)
    
    b_ciphertext = utils.encrypt_CBC(used_str, b_key, b_iv)
    
    return b_ciphertext, b_iv

def confirm_3_17(b_ciphertext, b_iv):
    global b_key
    
    b_plaintext = utils.decrypt_CBC(b_ciphertext, b_key, b_iv)
    
    try:
        utils.validate_pkcs7(b_plaintext)
        return True
    except:
        return False
    
    

###############################################################################
#Implementations

#Set 3, Challenge 17:
print("Now we're cooking with what I have")

block_size = 16

global b_key

b_key = Crypto.Random.get_random_bytes(block_size)

take, iv = dish_3_17()

C_orig = utils.separate_blocks(take)

block_ind = len(C_orig)-2

found_str = b""

#set used_str = str_list[8]
#(padded) used_str = b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=\x04\x04\x04\x04'
#last_block = b'cG9pbnQgb2g=\x04\x04\x04\x04'

#C[3][15] is target character (want to try to set this so it decrypts to b'\x01')
#C[2][15] is modifying character (change this to alter target character)

#when C[3] decrypts to b'cG9pbnQgb2g=\x04\x04\x04\x01', confirm_3_17 will return True

C = deepcopy(C_orig)


while block_ind >= 0:
    
    #set ind = 15 (index of target character within current block; iterates backwards from 15 to 0)
    for ind in range(15, -1, -1):
        
        #(block_size - ind) is the pad number (number required for valid padding)
        pad_num = block_size - ind
        
        #iterate i through all 256 characters
        for i in range(256):
            
            #create deep copy, avoid modifying true ciphertext
            c = deepcopy(C)
            
            #for first character, ignore i==1 (assuming plaintext already has valid padding,
            # this would cancel out the target '\x01' and leave the ciphertext unchanged, 
            # which would cause confirm_3_17 to return True nominally. Not an issue after 
            #first character)
            if block_ind == len(c)-2 and i==1:
                continue
            
            #new_block is a replacement for C[block_ind]
            #first (ind) characters of C[block_ind] are copied to new_block
            new_block = C[block_ind][:ind]
            
            #remaining (block_length - ind) characters are modified
            
            new_block += bytes([(C[block_ind][ind]^i)^pad_num])
            
            #after first character, the characters following the target character must be 
            # modified to all equal the pad number
            for j in range(block_size - 1 - ind):
                a = C[block_ind][ind+j+1]
                b = found_str[j]
                new_block += bytes([(a^b)^pad_num])
            
            c[block_ind] = new_block
            test_C = b""
            for blk in c:
                test_C += blk
            
            result = confirm_3_17(test_C, iv)
                      
            if not result:
                continue
            else:
                found_str = bytes(chr(i),'utf8') + found_str

                break

    C.remove(C[-1])
    block_ind -= 1

assert len(C) == 1
assert len(C[0]) == block_size

for ind in range(15, -1, -1):
    pad_num = block_size - ind
    for i in range(256):
        c = deepcopy(C[0])
        new_block = iv[:ind]
        new_block += bytes([(iv[ind]^i)^pad_num])
        for j in range(block_size - 1 - ind):
            a = iv[ind+j+1]
            b = found_str[j]
            new_block += bytes([(a^b)^pad_num])
        result = confirm_3_17(C[0], new_block)

        if not result:
            continue
        else:
            found_str = bytes(chr(i),'utf8') + found_str
            break

print("Message: ",found_str)