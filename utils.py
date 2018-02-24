# -*- coding: utf-8 -*-
"""
Created on Sat Feb 24 09:30:40 2018

@author: alakocy
"""

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
    