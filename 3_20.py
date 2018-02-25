# -*- coding: utf-8 -*-
"""
Created on Sat Feb 24 16:39:35 2018

@author: alakocy
"""

import utils        
                
b64_blob_strs = b"""SSdtIHJhdGVkICJSIi4uLnRoaXMgaXMgYSB3YXJuaW5nLCB5YSBiZXR0ZXIgdm9pZCAvIFBvZXRzIGFyZSBwYXJhbm9pZCwgREoncyBELXN0cm95ZWQ=
                Q3V6IEkgY2FtZSBiYWNrIHRvIGF0dGFjayBvdGhlcnMgaW4gc3BpdGUtIC8gU3RyaWtlIGxpa2UgbGlnaHRuaW4nLCBJdCdzIHF1aXRlIGZyaWdodGVuaW4nIQ==
                QnV0IGRvbid0IGJlIGFmcmFpZCBpbiB0aGUgZGFyaywgaW4gYSBwYXJrIC8gTm90IGEgc2NyZWFtIG9yIGEgY3J5LCBvciBhIGJhcmssIG1vcmUgbGlrZSBhIHNwYXJrOw==
                WWEgdHJlbWJsZSBsaWtlIGEgYWxjb2hvbGljLCBtdXNjbGVzIHRpZ2h0ZW4gdXAgLyBXaGF0J3MgdGhhdCwgbGlnaHRlbiB1cCEgWW91IHNlZSBhIHNpZ2h0IGJ1dA==
                U3VkZGVubHkgeW91IGZlZWwgbGlrZSB5b3VyIGluIGEgaG9ycm9yIGZsaWNrIC8gWW91IGdyYWIgeW91ciBoZWFydCB0aGVuIHdpc2ggZm9yIHRvbW9ycm93IHF1aWNrIQ==
                TXVzaWMncyB0aGUgY2x1ZSwgd2hlbiBJIGNvbWUgeW91ciB3YXJuZWQgLyBBcG9jYWx5cHNlIE5vdywgd2hlbiBJJ20gZG9uZSwgeWEgZ29uZSE=
                SGF2ZW4ndCB5b3UgZXZlciBoZWFyZCBvZiBhIE1DLW11cmRlcmVyPyAvIFRoaXMgaXMgdGhlIGRlYXRoIHBlbmFsdHksYW5kIEknbSBzZXJ2aW4nIGE=
                RGVhdGggd2lzaCwgc28gY29tZSBvbiwgc3RlcCB0byB0aGlzIC8gSHlzdGVyaWNhbCBpZGVhIGZvciBhIGx5cmljYWwgcHJvZmVzc2lvbmlzdCE=
                RnJpZGF5IHRoZSB0aGlydGVlbnRoLCB3YWxraW5nIGRvd24gRWxtIFN0cmVldCAvIFlvdSBjb21lIGluIG15IHJlYWxtIHlhIGdldCBiZWF0IQ==
                VGhpcyBpcyBvZmYgbGltaXRzLCBzbyB5b3VyIHZpc2lvbnMgYXJlIGJsdXJyeSAvIEFsbCB5YSBzZWUgaXMgdGhlIG1ldGVycyBhdCBhIHZvbHVtZQ==
                VGVycm9yIGluIHRoZSBzdHlsZXMsIG5ldmVyIGVycm9yLWZpbGVzIC8gSW5kZWVkIEknbSBrbm93bi15b3VyIGV4aWxlZCE=
                Rm9yIHRob3NlIHRoYXQgb3Bwb3NlIHRvIGJlIGxldmVsIG9yIG5leHQgdG8gdGhpcyAvIEkgYWluJ3QgYSBkZXZpbCBhbmQgdGhpcyBhaW4ndCB0aGUgRXhvcmNpc3Qh
                V29yc2UgdGhhbiBhIG5pZ2h0bWFyZSwgeW91IGRvbid0IGhhdmUgdG8gc2xlZXAgYSB3aW5rIC8gVGhlIHBhaW4ncyBhIG1pZ3JhaW5lIGV2ZXJ5IHRpbWUgeWEgdGhpbms=
                Rmxhc2hiYWNrcyBpbnRlcmZlcmUsIHlhIHN0YXJ0IHRvIGhlYXI6IC8gVGhlIFItQS1LLUktTSBpbiB5b3VyIGVhcjs=
                VGhlbiB0aGUgYmVhdCBpcyBoeXN0ZXJpY2FsIC8gVGhhdCBtYWtlcyBFcmljIGdvIGdldCBhIGF4IGFuZCBjaG9wcyB0aGUgd2Fjaw==
                U29vbiB0aGUgbHlyaWNhbCBmb3JtYXQgaXMgc3VwZXJpb3IgLyBGYWNlcyBvZiBkZWF0aCByZW1haW4=
                TUMncyBkZWNheWluZywgY3V6IHRoZXkgbmV2ZXIgc3RheWVkIC8gVGhlIHNjZW5lIG9mIGEgY3JpbWUgZXZlcnkgbmlnaHQgYXQgdGhlIHNob3c=
                VGhlIGZpZW5kIG9mIGEgcmh5bWUgb24gdGhlIG1pYyB0aGF0IHlvdSBrbm93IC8gSXQncyBvbmx5IG9uZSBjYXBhYmxlLCBicmVha3MtdGhlIHVuYnJlYWthYmxl
                TWVsb2RpZXMtdW5tYWthYmxlLCBwYXR0ZXJuLXVuZXNjYXBhYmxlIC8gQSBob3JuIGlmIHdhbnQgdGhlIHN0eWxlIEkgcG9zc2Vz
                SSBibGVzcyB0aGUgY2hpbGQsIHRoZSBlYXJ0aCwgdGhlIGdvZHMgYW5kIGJvbWIgdGhlIHJlc3QgLyBGb3IgdGhvc2UgdGhhdCBlbnZ5IGEgTUMgaXQgY2FuIGJl
                SGF6YXJkb3VzIHRvIHlvdXIgaGVhbHRoIHNvIGJlIGZyaWVuZGx5IC8gQSBtYXR0ZXIgb2YgbGlmZSBhbmQgZGVhdGgsIGp1c3QgbGlrZSBhIGV0Y2gtYS1za2V0Y2g=
                U2hha2UgJ3RpbGwgeW91ciBjbGVhciwgbWFrZSBpdCBkaXNhcHBlYXIsIG1ha2UgdGhlIG5leHQgLyBBZnRlciB0aGUgY2VyZW1vbnksIGxldCB0aGUgcmh5bWUgcmVzdCBpbiBwZWFjZQ==
                SWYgbm90LCBteSBzb3VsJ2xsIHJlbGVhc2UhIC8gVGhlIHNjZW5lIGlzIHJlY3JlYXRlZCwgcmVpbmNhcm5hdGVkLCB1cGRhdGVkLCBJJ20gZ2xhZCB5b3UgbWFkZSBpdA==
                Q3V6IHlvdXIgYWJvdXQgdG8gc2VlIGEgZGlzYXN0cm91cyBzaWdodCAvIEEgcGVyZm9ybWFuY2UgbmV2ZXIgYWdhaW4gcGVyZm9ybWVkIG9uIGEgbWljOg==
                THlyaWNzIG9mIGZ1cnkhIEEgZmVhcmlmaWVkIGZyZWVzdHlsZSEgLyBUaGUgIlIiIGlzIGluIHRoZSBob3VzZS10b28gbXVjaCB0ZW5zaW9uIQ==
                TWFrZSBzdXJlIHRoZSBzeXN0ZW0ncyBsb3VkIHdoZW4gSSBtZW50aW9uIC8gUGhyYXNlcyB0aGF0J3MgZmVhcnNvbWU=
                WW91IHdhbnQgdG8gaGVhciBzb21lIHNvdW5kcyB0aGF0IG5vdCBvbmx5IHBvdW5kcyBidXQgcGxlYXNlIHlvdXIgZWFyZHJ1bXM7IC8gSSBzaXQgYmFjayBhbmQgb2JzZXJ2ZSB0aGUgd2hvbGUgc2NlbmVyeQ==
                VGhlbiBub25jaGFsYW50bHkgdGVsbCB5b3Ugd2hhdCBpdCBtZWFuIHRvIG1lIC8gU3RyaWN0bHkgYnVzaW5lc3MgSSdtIHF1aWNrbHkgaW4gdGhpcyBtb29k
                QW5kIEkgZG9uJ3QgY2FyZSBpZiB0aGUgd2hvbGUgY3Jvd2QncyBhIHdpdG5lc3MhIC8gSSdtIGEgdGVhciB5b3UgYXBhcnQgYnV0IEknbSBhIHNwYXJlIHlvdSBhIGhlYXJ0
                UHJvZ3JhbSBpbnRvIHRoZSBzcGVlZCBvZiB0aGUgcmh5bWUsIHByZXBhcmUgdG8gc3RhcnQgLyBSaHl0aG0ncyBvdXQgb2YgdGhlIHJhZGl1cywgaW5zYW5lIGFzIHRoZSBjcmF6aWVzdA==
                TXVzaWNhbCBtYWRuZXNzIE1DIGV2ZXIgbWFkZSwgc2VlIGl0J3MgLyBOb3cgYW4gZW1lcmdlbmN5LCBvcGVuLWhlYXJ0IHN1cmdlcnk=
                T3BlbiB5b3VyIG1pbmQsIHlvdSB3aWxsIGZpbmQgZXZlcnkgd29yZCdsbCBiZSAvIEZ1cmllciB0aGFuIGV2ZXIsIEkgcmVtYWluIHRoZSBmdXJ0dXJl
                QmF0dGxlJ3MgdGVtcHRpbmcuLi53aGF0ZXZlciBzdWl0cyB5YSEgLyBGb3Igd29yZHMgdGhlIHNlbnRlbmNlLCB0aGVyZSdzIG5vIHJlc2VtYmxhbmNl
                WW91IHRoaW5rIHlvdSdyZSBydWZmZXIsIHRoZW4gc3VmZmVyIHRoZSBjb25zZXF1ZW5jZXMhIC8gSSdtIG5ldmVyIGR5aW5nLXRlcnJpZnlpbmcgcmVzdWx0cw==
                SSB3YWtlIHlhIHdpdGggaHVuZHJlZHMgb2YgdGhvdXNhbmRzIG9mIHZvbHRzIC8gTWljLXRvLW1vdXRoIHJlc3VzY2l0YXRpb24sIHJoeXRobSB3aXRoIHJhZGlhdGlvbg==
                Tm92b2NhaW4gZWFzZSB0aGUgcGFpbiBpdCBtaWdodCBzYXZlIGhpbSAvIElmIG5vdCwgRXJpYyBCLidzIHRoZSBqdWRnZSwgdGhlIGNyb3dkJ3MgdGhlIGp1cnk=
                WW8gUmFraW0sIHdoYXQncyB1cD8gLyBZbywgSSdtIGRvaW5nIHRoZSBrbm93bGVkZ2UsIEUuLCBtYW4gSSdtIHRyeWluZyB0byBnZXQgcGFpZCBpbiBmdWxs
                V2VsbCwgY2hlY2sgdGhpcyBvdXQsIHNpbmNlIE5vcmJ5IFdhbHRlcnMgaXMgb3VyIGFnZW5jeSwgcmlnaHQ/IC8gVHJ1ZQ==
                S2FyYSBMZXdpcyBpcyBvdXIgYWdlbnQsIHdvcmQgdXAgLyBaYWtpYSBhbmQgNHRoIGFuZCBCcm9hZHdheSBpcyBvdXIgcmVjb3JkIGNvbXBhbnksIGluZGVlZA==
                T2theSwgc28gd2hvIHdlIHJvbGxpbicgd2l0aCB0aGVuPyBXZSByb2xsaW4nIHdpdGggUnVzaCAvIE9mIFJ1c2h0b3duIE1hbmFnZW1lbnQ=
                Q2hlY2sgdGhpcyBvdXQsIHNpbmNlIHdlIHRhbGtpbmcgb3ZlciAvIFRoaXMgZGVmIGJlYXQgcmlnaHQgaGVyZSB0aGF0IEkgcHV0IHRvZ2V0aGVy
                SSB3YW5uYSBoZWFyIHNvbWUgb2YgdGhlbSBkZWYgcmh5bWVzLCB5b3Uga25vdyB3aGF0IEknbSBzYXlpbic/IC8gQW5kIHRvZ2V0aGVyLCB3ZSBjYW4gZ2V0IHBhaWQgaW4gZnVsbA==
                VGhpbmtpbicgb2YgYSBtYXN0ZXIgcGxhbiAvICdDdXogYWluJ3QgbnV0aGluJyBidXQgc3dlYXQgaW5zaWRlIG15IGhhbmQ=
                U28gSSBkaWcgaW50byBteSBwb2NrZXQsIGFsbCBteSBtb25leSBpcyBzcGVudCAvIFNvIEkgZGlnIGRlZXBlciBidXQgc3RpbGwgY29taW4nIHVwIHdpdGggbGludA==
                U28gSSBzdGFydCBteSBtaXNzaW9uLCBsZWF2ZSBteSByZXNpZGVuY2UgLyBUaGlua2luJyBob3cgY291bGQgSSBnZXQgc29tZSBkZWFkIHByZXNpZGVudHM=
                SSBuZWVkIG1vbmV5LCBJIHVzZWQgdG8gYmUgYSBzdGljay11cCBraWQgLyBTbyBJIHRoaW5rIG9mIGFsbCB0aGUgZGV2aW91cyB0aGluZ3MgSSBkaWQ=
                SSB1c2VkIHRvIHJvbGwgdXAsIHRoaXMgaXMgYSBob2xkIHVwLCBhaW4ndCBudXRoaW4nIGZ1bm55IC8gU3RvcCBzbWlsaW5nLCBiZSBzdGlsbCwgZG9uJ3QgbnV0aGluJyBtb3ZlIGJ1dCB0aGUgbW9uZXk=
                QnV0IG5vdyBJIGxlYXJuZWQgdG8gZWFybiAnY3V6IEknbSByaWdodGVvdXMgLyBJIGZlZWwgZ3JlYXQsIHNvIG1heWJlIEkgbWlnaHQganVzdA==
                U2VhcmNoIGZvciBhIG5pbmUgdG8gZml2ZSwgaWYgSSBzdHJpdmUgLyBUaGVuIG1heWJlIEknbGwgc3RheSBhbGl2ZQ==
                U28gSSB3YWxrIHVwIHRoZSBzdHJlZXQgd2hpc3RsaW4nIHRoaXMgLyBGZWVsaW4nIG91dCBvZiBwbGFjZSAnY3V6LCBtYW4sIGRvIEkgbWlzcw==
                QSBwZW4gYW5kIGEgcGFwZXIsIGEgc3RlcmVvLCBhIHRhcGUgb2YgLyBNZSBhbmQgRXJpYyBCLCBhbmQgYSBuaWNlIGJpZyBwbGF0ZSBvZg==
                RmlzaCwgd2hpY2ggaXMgbXkgZmF2b3JpdGUgZGlzaCAvIEJ1dCB3aXRob3V0IG5vIG1vbmV5IGl0J3Mgc3RpbGwgYSB3aXNo
                J0N1eiBJIGRvbid0IGxpa2UgdG8gZHJlYW0gYWJvdXQgZ2V0dGluJyBwYWlkIC8gU28gSSBkaWcgaW50byB0aGUgYm9va3Mgb2YgdGhlIHJoeW1lcyB0aGF0IEkgbWFkZQ==
                U28gbm93IHRvIHRlc3QgdG8gc2VlIGlmIEkgZ290IHB1bGwgLyBIaXQgdGhlIHN0dWRpbywgJ2N1eiBJJ20gcGFpZCBpbiBmdWxs
                UmFraW0sIGNoZWNrIHRoaXMgb3V0LCB5byAvIFlvdSBnbyB0byB5b3VyIGdpcmwgaG91c2UgYW5kIEknbGwgZ28gdG8gbWluZQ==
                J0NhdXNlIG15IGdpcmwgaXMgZGVmaW5pdGVseSBtYWQgLyAnQ2F1c2UgaXQgdG9vayB1cyB0b28gbG9uZyB0byBkbyB0aGlzIGFsYnVt
                WW8sIEkgaGVhciB3aGF0IHlvdSdyZSBzYXlpbmcgLyBTbyBsZXQncyBqdXN0IHB1bXAgdGhlIG11c2ljIHVw
                QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbGk=
                VHVybiBkb3duIHRoZSBiYXNzIGRvd24gLyBBbmQgbGV0IHRoZSBiZWF0IGp1c3Qga2VlcCBvbiByb2NraW4n
                QW5kIHdlIG91dHRhIGhlcmUgLyBZbywgd2hhdCBoYXBwZW5lZCB0byBwZWFjZT8gLyBQZWFjZQ=="""


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
replacements = [(0,28,'r'),
                (20,90,'k'),
                (2,95,'k'),
                (12,97,'k'),
                (28,98,'t'),
                (21,100,' '),
                (41,101,'l'),
                (41,102,'l'),
                (29,103,'e'),
                (29,104,'s'),
                (29,105,'t'),
                (26,106,'h'),
                (26,107,'o'),
                (26,108,'l'),
                (26,109,'e'),
                (26,110,' '),
                (26,111,'s'),
                (26,112,'c'),
                (26,113,'e'),
                (26,114,'n'),
                (26,115,'e'),
                (26,116,'r'),
                (26,117,'y')]

for rep in replacements:
    best_xors = replace_byte(best_xors, rep[1], bytes([b_c_strs[rep[0]][rep[1]]^ord(rep[2])]))

messes = []
for b_c_str in b_c_strs:
    b_use_str = b_c_str[:len(best_xors)]
    b_use_xor = best_xors[:len(b_use_str)]
    mess = utils.onetimepad_xor(b_use_xor, b_use_str)
    messes.append(mess)
    print(bytes.decode(mess))



