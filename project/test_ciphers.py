"""
Юнит-тест для алгоритма Camellia.
"""

import unittest

from utilities import bitsize, DECRYPT
from ciphers.camellia import camellia

from random import randint


class TestCiphers(unittest.TestCase):
    def test_camellia(self):
        """
        Проверка алгоритма Camellia.
        """
        
        key = randint(10000, 100000000)
        message = 0x0123456789abcdeffedcba9876543210

        c, key, r_t = camellia(message, key)
        m, key, r_t = camellia(c, key, DECRYPT, r_t)

        self.assertEqual(m, message)
