#!/usr/bin/env python
#
# Copyright 2012-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import hashlib
import logging
import random
import struct
import base64

from shadowsocks import common
from shadowsocks.crypto import rc4_md5, openssl, sodium, table


method_supported = {}
method_supported.update(rc4_md5.ciphers)
method_supported.update(openssl.ciphers)
method_supported.update(sodium.ciphers)
method_supported.update(table.ciphers)


def random_string(length):
    return os.urandom(length)


cached_keys = {}


def try_cipher(key, method=None):
    Encryptor(key, method)


def EVP_BytesToKey(password, key_len, iv_len):
    # equivalent to OpenSSL's EVP_BytesToKey() with count 1
    # so that we make the same key and iv as nodejs version
    cached_key = '%s-%d-%d' % (password, key_len, iv_len)
    r = cached_keys.get(cached_key, None)
    if r:
        return r
    m = []
    i = 0
    while len(b''.join(m)) < (key_len + iv_len):
        md5 = hashlib.md5()
        data = password
        if i > 0:
            data = m[i - 1] + password
        md5.update(data)
        m.append(md5.digest())
        i += 1
    ms = b''.join(m)
    key = ms[:key_len]
    iv = ms[key_len:key_len + iv_len]
    cached_keys[cached_key] = (key, iv)
    return key, iv

def jfomixup(data, key):
    ret = []
    i = 0
    data_len = len(data)
    j = 0
    key_len = len(key)
    while i < data_len:
        byte = ord(data[i])
        akey = ord(key[j])
        newbyte = byte ^ akey
        ret.append(chr(newbyte))
        i += 1
        j = (j + 1) % key_len
    return b''.join(ret)

A = ord('A')
Z = ord('Z')

def jfoencrypt(func):
    def func_wrapper(self, buf):
        if len(buf) == 0:
            return func(self, buf)

        logging.debug("e:begin=======================================")

        header = []
        len1 = random.randint(11,19)
        logging.debug("e:===>len1:%d" % len1)
        header.append(chr(len1 + A))
        i = 1
        while i < len1:
            header.append(chr(random.randint(A,Z)))
            i = i + 1
        len2 = random.randint(11,25)
        logging.debug("e:===>len2:%d" % len2)
        header.append(chr(len2 + A))
        i = 1
        while i < len2:
            header.append(chr(random.randint(A,Z)))
            i = i + 1

        key = header[len1:len1+len2]
        encrypted_buf = func(buf, key)
        encrypted_buf = base64.b64encode(encrypted_buf)
        encrypted_len = len(encrypted_buf)
        encrypted_len_str = struct.pack('>I', encrypted_len)
        encrypted_len_str = base64.b64encode(encrypted_len_str)
        logging.debug("e:===>encrypted len:%d" % encrypted_len)
        logging.debug("e:===>encrypted len str:%s" % encrypted_len_str)
        logging.debug("e:===>decrypted len:%d" % len(buf))
        if len(buf) < 1000:
            logging.debug(buf)
            pass
        logging.debug("e:end=========================================")

        return b''.join(header) + encrypted_len_str + encrypted_buf
    return func_wrapper

def jfodecrypt(func):
    def func_wrapper(self, buf):
        if buf != None and len(buf) > 0:
            self.remaining_buffer += buf
        buf = self.remaining_buffer
        if len(buf) == 0:
            return buf

        logging.debug("d:begin=======================================")
        logging.debug("d:===>total buf len:%d" % len(buf))

        len1 = ord(buf[0]) - A
        logging.debug("d:===>len1:%d" % len1)
        if len(buf) <= len1:
            logging.debug("d:===>need more data...")
            return b''

        len2= ord(buf[len1]) - A
        logging.debug("d:===>len2:%d" % len2)
        pos = len1 + len2
        if len(buf) < pos + 4:
            logging.debug("d:===>need more data...")
            return b''

        encrypted_len_str = buf[pos:pos+8]
        try:
            encrypted_len_str = base64.b64decode(encrypted_len_str)
        except Exception as e:
            logging.error('%s' % e)
            logging.error(encrypted_len_str)
            shell.print_exception(e)
            raise e
        encrypted_len, = struct.unpack('>I', encrypted_len_str)
        logging.debug("d:===>encrypted_len:%d" % encrypted_len)
        pos += 8
        if len(buf) < pos+encrypted_len:
            logging.debug("d:===>need more data...")
            return b''

        key = buf[len1:len1+len2]
        encrypted_data = buf[pos:pos+encrypted_len]
        try:
            decrypted_data = base64.b64decode(encrypted_data)
        except Exception as e:
            logging.error('%s' % e)
            logging.error(encrypted_data)
            shell.print_exception(e)
            raise e

        decrypted_data = func(decrypted_data, key)
        logging.debug("d:===>decrypted_len:%d" % len(decrypted_data))
        if len(decrypted_data) < 1000:
            logging.debug(decrypted_data)
            pass
        logging.debug("d:end=========================================")

        buf = buf[pos+encrypted_len:]
        self.remaining_buffer = buf
        return decrypted_data + func_wrapper(self, None)
    return func_wrapper


class Encryptor(object):
    def __init__(self, key, method):
        self.remaining_buffer = b'';
        self.key = key
        self.method = method
        self.iv = None
        self.iv_sent = False
        self.cipher_iv = b''
        self.decipher = None
        method = method.lower()
        self._method_info = self.get_method_info(method)
        if self._method_info:
            self.cipher = self.get_cipher(key, method, 1,
                                          random_string(self._method_info[1]))
        else:
            logging.error('method %s not supported' % method)
            sys.exit(1)

    def get_method_info(self, method):
        method = method.lower()
        m = method_supported.get(method)
        return m

    def iv_len(self):
        return len(self.cipher_iv)

    def get_cipher(self, password, method, op, iv):
        password = common.to_bytes(password)
        m = self._method_info
        if m[0] > 0:
            key, iv_ = EVP_BytesToKey(password, m[0], m[1])
        else:
            # key_length == 0 indicates we should use the key directly
            key, iv = password, b''

        iv = iv[:m[1]]
        if op == 1:
            # this iv is for cipher not decipher
            self.cipher_iv = iv[:m[1]]
        return m[2](method, key, iv, op)

    @jfoencrypt
    def encrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.iv_sent:
            return self.cipher.update(buf)
        else:
            self.iv_sent = True
            return self.cipher_iv + self.cipher.update(buf)

    @jfodecrypt
    def decrypt(self, buf):
        if len(buf) == 0:
            return buf
        if self.decipher is None:
            decipher_iv_len = self._method_info[1]
            decipher_iv = buf[:decipher_iv_len]
            self.decipher = self.get_cipher(self.key, self.method, 0,
                                            iv=decipher_iv)
            buf = buf[decipher_iv_len:]
            if len(buf) == 0:
                return buf
        return self.decipher.update(buf)

def encrypt_all(password, method, op, data):
    result = []
    method = method.lower()
    (key_len, iv_len, m) = method_supported[method]
    if key_len > 0:
        key, _ = EVP_BytesToKey(password, key_len, iv_len)
    else:
        key = password
    if op:
        iv = random_string(iv_len)
        result.append(iv)
    else:
        iv = data[:iv_len]
        data = data[iv_len:]
    cipher = m(method, key, iv, op)
    result.append(cipher.update(data))
    return b''.join(result)


CIPHERS_TO_TEST = [
    'aes-128-cfb',
    'aes-256-cfb',
    'rc4-md5',
    'salsa20',
    'chacha20',
    'table',
]


def test_encryptor():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        encryptor = Encryptor(b'key', method)
        decryptor = Encryptor(b'key', method)
        cipher = encryptor.encrypt(plain)
        plain2 = decryptor.decrypt(cipher)
        assert plain == plain2


def test_encrypt_all():
    from os import urandom
    plain = urandom(10240)
    for method in CIPHERS_TO_TEST:
        logging.warn(method)
        cipher = encrypt_all(b'key', method, 1, plain)
        plain2 = encrypt_all(b'key', method, 0, cipher)
        assert plain == plain2


if __name__ == '__main__':
    test_encrypt_all()
    test_encryptor()

