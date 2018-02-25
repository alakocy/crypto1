# -*- coding: utf-8 -*-
"""
Created on Sat Feb 24 16:39:35 2018

@author: alakocy
"""

import utils


b64_enc_mess = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="

b_enc_mess = utils.b64_to_bits(b64_enc_mess)

b_key = b"YELLOW SUBMARINE"

b_nonce = bytes([0]*8)

b_dec_mess = utils.endecrypt_CTR(b_enc_mess, b_key, b_nonce, 0)

print(bytes.decode(b_dec_mess))