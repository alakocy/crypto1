# -*- coding: utf-8 -*-
"""
Created on Sat Feb 24 16:39:35 2018

@author: alakocy
"""

import utils        
                
b64_blob_strs = b"""SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
                Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
                RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
                RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
                SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
                T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
                T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
                UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
                QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
                T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
                VG8gcGxlYXNlIGEgY29tcGFuaW9u
                QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
                QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
                QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
                QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
                QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
                VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
                SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
                SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
                VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
                V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
                V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
                U2hlIHJvZGUgdG8gaGFycmllcnM/
                VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
                QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
                VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
                V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
                SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
                U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
                U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
                VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
                QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
                SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
                VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
                WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
                SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
                SW4gdGhlIGNhc3VhbCBjb21lZHk7
                SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
                VHJhbnNmb3JtZWQgdXR0ZXJseTo=
                QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="""


b64_enc_strs = b64_blob_strs.split(b'\n')

b_key = utils.random_AES_key()

b_nonce = bytes([0]*8)
ctr = 0

b_c_strs = []
min_str_len = 600
max_str_len = 0

for b64_str in b64_enc_strs:
    b_str = utils.b64_to_bits(b64_str)
    b_c_strs.append(utils.endecrypt_CTR(b_str, b_key, b_nonce, ctr))
    if len(b_str) < min_str_len:
        min_str_len = len(b_str)
    if len(b_str) > max_str_len:
        max_str_len = len(b_str)

best_xors = bytes(0)
for char_ind in range(max_str_len):
    max_score = 0
    best_xor = bytes(0)
    for x in range(256):
        b_chars = b""
        for b_c_str in b_c_strs:
            if char_ind >= len(b_c_str):
                continue
            c = x^b_c_str[char_ind]
            try:
                assert chr(c) in string.printable
                b_chars += bytes(chr(c),'utf8')
            except:
                b_chars += bytes([x^b_c_str[char_ind]])
                
#        assert len(b_chars) == 40
        try:
            score = utils.score_message(bytes.decode(b_chars))
        except:
            continue
        if score > max_score:
            max_score = score
            best_xor = bytes([x])
    best_xors += best_xor

def replace_byte(b_str, ind, b_rep):
    new_b = b_str[:ind]
    new_b += b_rep
    new_b += b_str[ind+1:]
    return new_b

#At a certain point, not enough data points to accurately score messages
#Manual replacements of plaintext based on context
replacements = [(0,25,'o'),
                (0,27,' '),
                (6,31,'d'),
                (27,32,'d'),
                (4,33,'e'),
                (4,34,'a'),
                (4,35,'d'),
                (37,36,'n'),
                (37,37,',')]

for rep in replacements:
    best_xors = replace_byte(best_xors, rep[1], bytes([b_c_strs[rep[0]][rep[1]]^ord(rep[2])]))

messes = []
for b_c_str in b_c_strs:
    b_use_str = b_c_str[:len(best_xors)]
    b_use_xor = best_xors[:len(b_use_str)]
    mess = utils.onetimepad_xor(b_use_xor, b_use_str)
    messes.append(mess)
    print(bytes.decode(mess))



