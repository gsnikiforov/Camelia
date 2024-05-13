"""
Юнит-тест для режимов шифрования.
"""

import unittest

from utilities import DECRYPT

from ofb import ofb
from mgm import mgm_encrypt, mgm_decrypt

from camellia import camellia

from random import randint


class TestCipherModes(unittest.TestCase):
    def test_ofb_camellia(self):
        """
        Проверка шифрования в режиме OFB
        при помощи алгоритма Camellia
        со случайно генерируемым ключом.
        """

        iv = 0x80000000000000000000000000000000
        me = 0x10000000000000000000000000000000
        ke = randint(100000, 1000000000)

        cipher, res_type = ofb(camellia, me, ke, iv)
        decipher, _ = ofb(camellia, cipher, ke, iv, DECRYPT, res_type)

        self.assertEqual(hex(decipher), hex(me))


    def test_mgm_camellia(self):
        """
        Проверка шифрования в режиме MGM
        при помощи алгоритма Camellia
        со случайно генерируемым ключом.
        """

        n = 128
        nonce = 0x6 << (n-4)
        message = "Hello darkness, my old friend"
        ass_data = 0xbfee5c7c5fe97718ed6bf376739259fa

        key = randint(100000, 1000000000)
        c, a_d, t, r, r_t = mgm_encrypt(camellia, nonce,
                                  message, ass_data, key)
        m, a = mgm_decrypt(camellia, nonce, c, ass_data,
                           key, t, r, r_t)

        self.assertEqual(message, m)
