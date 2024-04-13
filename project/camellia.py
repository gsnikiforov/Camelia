"""
Шифр Camellia.
"""

from utilities import *


# Константы
SIGMA1 = 0xa09e667f3bcc908b
SIGMA2 = 0xb67ae8584caa73b2
SIGMA3 = 0xc6ef372fe94f82be
SIGMA4 = 0x54ff53a5f1d36f1c
SIGMA5 = 0x10e527fade682d1d
SIGMA6 = 0xb05688c2b3e6c1fd

# S-блоки
SBOX1 = [
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
    35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
    20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
    16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
    82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
    64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
]

SBOX2 = [left_rotation(x, 1) for x in SBOX1]
SBOX3 = [left_rotation(x, 7) for x in SBOX1]
SBOX4 = [SBOX1[left_rotation(x, 1)] for x in range(len(SBOX1))]


def f_function(f_in: int, ke: int) -> int:
    """
    Вспомогательная f-функция для шифрования Camellia.
    """

    x = f_in ^ ke
    t1 = x >> 56
    t2 = (x >> 48) & MASK8
    t3 = (x >> 40) & MASK8
    t4 = (x >> 32) & MASK8
    t5 = (x >> 24) & MASK8
    t6 = (x >> 16) & MASK8
    t7 = (x >> 8) & MASK8
    t8 = x & MASK8
    t1 = SBOX1[t1]
    t2 = SBOX2[t2]
    t3 = SBOX3[t3]
    t4 = SBOX4[t4]
    t5 = SBOX2[t5]
    t6 = SBOX3[t6]
    t7 = SBOX4[t7]
    t8 = SBOX1[t8]
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
    f_out = (y1 << 56) | (y2 << 48) | (y3 << 40) | (y4 << 32) \
        | (y5 << 24) | (y6 << 16) | (y7 << 8) | y8
    return f_out


def fl_function(fl_in: int, ke: int) -> int:
    """
    Вспомогательная fl-функция для шифрования Camellia.
    """

    x1 = fl_in >> 32
    x2 = fl_in & MASK32
    k1 = ke >> 32
    k2 = ke & MASK32
    x2 = x2 ^ left_rotation(x1 & k1, 1)
    x1 = x1 ^ (x2 | k2)
    fl_out = (x1 << 32) | x2
    return fl_out


def fl_inv_function(fl_inv_in: int, ke: int) -> int:
    """
    Вспомогательная fl_inv-функция для шифрования Camellia.
    """

    y1 = fl_inv_in >> 32
    y2 = fl_inv_in & MASK32
    k1 = ke >> 32
    k2 = ke & MASK32
    y1 = y1 ^ (y2 | k2)
    y2 = y2 ^ left_rotation(y1 & k1, 1)
    fl_inv_out = (y1 << 32) | y2
    return fl_inv_out

def camellia(message: int, key: int, encr_mode: f"ENCRYPT / DECRYPT" = ENCRYPT, \
        res_type: object = int) -> list[int, int, object]:
    """
    Шифрует сообщение по алгоритму Camellia.

    Аргументы:
    message     -   сообщение, записанное в 128, 192 или 256 бит
    key         -   ключ шифрования
    encr_mode   -   (необязательный аргумент) определяет, будет
                    ли функция шифровать или расшифровывать
    res_type    -   (необязательный аргумент) тип message. Требуется
                    для корректной расшифровки (encr_mode = DECRYPT)

    Возвращает:
    cipher      -   шифротекст
    key         -   ключ шифрования
    res_type    -   тип message, необходимый для корректной расшифровки
                    (encr_mode = DECRYPT)
    """

    # =====  Подготовка  =====

    message, key, res_type = prepare_args(message, key, res_type)

    kl, kr = 0, 0
    bits_in_key = bitsize(key) # sizeof(key) * BYTE

    # 1. Вычисляем 128-битные значения kl и kr
    if bits_in_key <= 128:
        kl = key

    elif bits_in_key <= 192:
        kl = key >> 64
        kr = ((key & MASK64) << 64) | (~(key & MASK64))

    elif bits_in_key <= 256:
        kl = key >> 128
        kr = key & MASK128

    else:
        raise ValueError(
               f"Key size must vary in (128, 192, 256). Currently {bits_in_k}.")

    # 2. Вычисляем 128-битные значения ka и kb
    d1 = (kl ^ kr) >> 64
    d2 = (kl ^ kr) & MASK64
    d2 = d2 ^ f_function(d1, SIGMA1)
    d1 = d1 ^ f_function(d2, SIGMA2)
    d1 = d1 ^ (kl >> 64)
    d2 = d2 ^ (kl & MASK64)
    d2 = d2 ^ f_function(d1, SIGMA3)
    d1 = d1 ^ f_function(d2, SIGMA4)
    ka = (d1 << 64) | d2
    d1 = (ka ^ kr) >> 64
    d2 = (ka ^ kr) & MASK64
    d2 = d2 ^ f_function(d1, SIGMA5)
    d1 = d1 ^ f_function(d2, SIGMA6)
    kb = (d1 << 64) | d2

    # 3. Вычисляем 64-битные ключи
    # kw1, ..., kw4, k1, ..., k18, ke1, ..., ke4
    if bits_in_key <= 128:
        kw1 = left_rotation(kl, 0) >> 64
        kw2 = left_rotation(kl, 0) & MASK64
        k1 = left_rotation(ka, 0) >> 64
        k2 = left_rotation(ka, 0) & MASK64
        k3 = left_rotation(kl, 15) >> 64
        k4 = left_rotation(kl, 15) & MASK64
        k5 = left_rotation(ka, 15) >> 64
        k6 = left_rotation(ka, 15) & MASK64
        ke1 = left_rotation(ka, 30) >> 64
        ke2 = left_rotation(ka, 30) & MASK64
        k7 = left_rotation(kl, 45) >> 64
        k8 = left_rotation(kl, 45) & MASK64
        k9 = left_rotation(ka, 45) >> 64
        k10 = left_rotation(kl, 60) & MASK64
        k11 = left_rotation(ka, 60) >> 64
        k12 = left_rotation(ka, 60) & MASK64
        ke3 = left_rotation(kl, 77) >> 64
        ke4 = left_rotation(kl, 77) & MASK64
        k13 = left_rotation(kl, 94) >> 64
        k14 = left_rotation(kl, 94) & MASK64
        k15 = left_rotation(ka, 94) >> 64
        k16 = left_rotation(ka, 94) & MASK64
        k17 = left_rotation(kl, 111) >> 64
        k18 = left_rotation(kl, 111) & MASK64
        kw3 = left_rotation(ka, 111) >> 64
        kw4 = left_rotation(ka, 111) & MASK64

    # Для 192- и 256-битных ключей дополнительно находим ke5, ke6
    else:
        kw1 = left_rotation(kl,  0) >> 64
        kw2 = left_rotation(kl, 0) & MASK64
        k1 = left_rotation(kb, 0) >> 64
        k2 = left_rotation(kb, 0) & MASK64
        k3 = left_rotation(kr, 15) >> 64
        k4 = left_rotation(kr, 15) & MASK64
        k5 = left_rotation(ka, 15) >> 64
        k6 = left_rotation(ka, 15) & MASK64
        ke1 = left_rotation(kr, 30) >> 64
        ke2 = left_rotation(kr, 30) & MASK64
        k7 = left_rotation(kb, 30) >> 64
        k8 = left_rotation(kb, 30) & MASK64
        k9 = left_rotation(kl, 45) >> 64
        k10 = left_rotation(kl, 45) & MASK64
        k11 = left_rotation(ka, 45) >> 64
        k12 = left_rotation(ka, 45) & MASK64
        ke3 = left_rotation(kl, 60) >> 64
        ke4 = left_rotation(kl, 60) & MASK64
        k13 = left_rotation(kr, 60) >> 64
        k14 = left_rotation(kr, 60) & MASK64
        k15 = left_rotation(kb, 60) >> 64
        k16 = left_rotation(kb, 60) & MASK64
        k17 = left_rotation(kl, 77) >> 64
        k18 = left_rotation(kl, 77) & MASK64
        ke5 = left_rotation(ka, 77) >> 64
        ke6 = left_rotation(ka, 77) & MASK64
        k19 = left_rotation(kr, 94) >> 64
        k20 = left_rotation(kr, 94) & MASK64
        k21 = left_rotation(ka, 94) >> 64
        k22 = left_rotation(ka, 94) & MASK64
        k23 = left_rotation(kl, 111) >> 64
        k24 = left_rotation(kl, 111) & MASK64
        kw3 = left_rotation(kb, 111) >> 64
        kw4 = left_rotation(kb, 111) & MASK64

    # В случае расшифровки достаточно поменять местами ключи
    if encr_mode == DECRYPT:
        if bits_in_key <= 128:
            kw1, kw3 = kw3, kw1
            kw2, kw4 = kw4, kw2
            k1, k18 = k18, k1
            k2, k17 = k17, k2
            k3, k16 = k16, k3
            k4, k15 = k15, k4
            k5, k14 = k14, k5
            k6, k13 = k13, k6
            k7, k12 = k12, k7
            k8, k11 = k11, k8
            k9, k10 = k10, k9
            ke1, ke4 = ke4, ke1
            ke2, ke3 = ke3, ke2

        else:
            kw1, kw3 = kw3, kw1
            kw2, kw4 = kw4, kw2
            k1, k24 = k24, k1
            k2, k23 = k23, k2
            k3, k22 = k22, k3
            k4, k21 = k21, k4
            k5, k20 = k20, k5
            k6, k19 = k19, k6
            k7, k18 = k18, k7
            k8, k17 = k17, k8
            k9, k16 = k16, k9
            k10, k15 = k15, k10
            k11, k14 = k14, k11
            k12, k13 = k13, k11
            ke1, ke6 = ke6, ke1
            ke2, ke5 = ke5, ke2
            ke3, ke4 = ke4, ke3

    # =====  Непосредственно шифрование  =====

    # d1 содержит левые 64 бита сообщения, d2 - правые
    d1 = message >> 64
    d2 = message & MASK64

    if bits_in_key <= 128:
        d1 = d1 ^ kw1                   # Предварительное забеливание
        d2 = d2 ^ kw2
        d2 = d2 ^ f_function(d1, k1)    # Round 1
        d1 = d1 ^ f_function(d2, k2)    # Round 2
        d2 = d2 ^ f_function(d1, k3)    # Round 3
        d1 = d1 ^ f_function(d2, k4)    # Round 4
        d2 = d2 ^ f_function(d1, k5)    # Round 5
        d1 = d1 ^ f_function(d2, k6)    # Round 6
        d1 = fl_function(d1, ke1)       # FL
        d2 = fl_inv_function(d2, ke2)   # FLINV
        d2 = d2 ^ f_function(d1, k7)    # Round 7
        d1 = d1 ^ f_function(d2, k8)    # Round 8
        d2 = d2 ^ f_function(d1, k9)    # Round 9
        d1 = d1 ^ f_function(d2, k10)   # Round 10
        d2 = d2 ^ f_function(d1, k11)   # Round 11
        d1 = d1 ^ f_function(d2, k12)   # Round 12
        d1 = fl_function(d1, ke3)       # FL
        d2 = fl_inv_function(d2, ke4)   # FLINV
        d2 = d2 ^ f_function(d1, k13)   # Round 13
        d1 = d1 ^ f_function(d2, k14)   # Round 14
        d2 = d2 ^ f_function(d1, k15)   # Round 15
        d1 = d1 ^ f_function(d2, k16)   # Round 16
        d2 = d2 ^ f_function(d1, k17)   # Round 17
        d1 = d1 ^ f_function(d2, k18)   # Round 18
        d2 = d2 ^ kw3                   # Финальное забеливание
        d1 = d1 ^ kw4

    else:
        d1 = d1 ^ kw1                   # Предварительное забеливание
        d2 = d2 ^ kw2
        d2 = d2 ^ f_function(d1, k1)    # Round 1
        d1 = d1 ^ f_function(d2, k2)    # Round 2
        d2 = d2 ^ f_function(d1, k3)    # Round 3
        d1 = d1 ^ f_function(d2, k4)    # Round 4
        d2 = d2 ^ f_function(d1, k5)    # Round 5
        d1 = d1 ^ f_function(d2, k6)    # Round 6
        d1 = fl_function(d1, ke1)       # FL
        d2 = fl_inv_function(d2, ke2)   # FLINV
        d2 = d2 ^ f_function(d1, k7)    # Round 7
        d1 = d1 ^ f_function(d2, k8)    # Round 8
        d2 = d2 ^ f_function(d1, k9)    # Round 9
        d1 = d1 ^ f_function(d2, k10)   # Round 10
        d2 = d2 ^ f_function(d1, k11)   # Round 11
        d1 = d1 ^ f_function(d2, k12)   # Round 12
        d1 = fl_function(d1, ke3)       # FL
        d2 = fl_inv_function(d2, ke4)   # FLINV
        d2 = d2 ^ f_function(d1, k13)   # Round 13
        d1 = d1 ^ f_function(d2, k14)   # Round 14
        d2 = d2 ^ f_function(d1, k15)   # Round 15
        d1 = d1 ^ f_function(d2, k16)   # Round 16
        d2 = d2 ^ f_function(d1, k17)   # Round 17
        d1 = d1 ^ f_function(d2, k18)   # Round 18
        d1 = fl_function(d1, ke5)       # FL
        d2 = fl_inv_function(d2, ke6)   # FLINV
        d2 = d2 ^ f_function(d1, k19)   # Round 19
        d1 = d1 ^ f_function(d2, k20)   # Round 20
        d2 = d2 ^ f_function(d1, k21)   # Round 21
        d1 = d1 ^ f_function(d2, k22)   # Round 22
        d2 = d2 ^ f_function(d1, k23)   # Round 23
        d1 = d1 ^ f_function(d2, k24)   # Round 24
        d2 = d2 ^ kw3                   # Финальное забеливание
        d1 = d1 ^ kw4

    cipher = (d2 << 64) | d1

    if encr_mode == DECRYPT and res_type == str:
        cipher = int_to_str(cipher)

    return cipher, key, res_type
