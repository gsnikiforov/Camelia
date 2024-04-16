"""
Режим шифрования MGM.
"""

from utilities import *
from math import ceil


# ===== Арифметика полей Галуа =====


def mod_gen_p(value: int, gen_p: int) -> int:
    """
    Телепортирует число обратно в поле Галуа.
    """

    while 1:
        vmaxbit = bitsize(value)
        pmaxbit = bitsize(gen_p)

        if vmaxbit < pmaxbit:
            return value

        quotient = 1 << (vmaxbit - pmaxbit)
        value ^= gen_p * quotient


def mul_mod2(a: int, b: int) -> int:
    """
    Умножение mod 2.
    """

    result, offset = 0, 0
    while b:
        if b & 1:
            result ^= a << offset
        offset += 1
        b >>= 1
    return result


def gl_mul(a: int, b: int) -> int:
    """
    Умножение в поле Галуа GL(2^n).
    """

    gen_p = (1 << 32) + (1 << 22) + (1 << 2) + (1 << 1) + 1
    value = mul_mod2(a, b)
    return mod_gen_p(value, gen_p)


# =====  Вспомогательные функции в спецификации MGM  =====


def incr_l(x: int, n: int = 128) -> int:
    """
    Инкрементирует верхние n//2 бит сообщения x.
    """

    g = n // 2
    left_mask, right_mask = chess_mask(n)
    left = (x & left_mask) >> g
    right = x & right_mask

    left = ((left + 1) % (2 ** g)) << g
    return left | right


def incr_r(x: int, n: int = 128) -> int:
    """
    Инкрементирует нижние n//2 бит сообщения x.
    """

    g = n // 2
    left_mask, right_mask = chess_mask(n)
    left = x & left_mask
    right = x & right_mask

    right = (right + 1) % (2 ** g)
    return left | right


def msb(x: int, i: int) -> int:
    """
    Из битового слова    x=(x_1, ..., x_i, ..., x_n)
    возвращает срез msb(x)=(x_1, ..., x_i).
    (n = bitsize(x).)
    """

    if bitsize(x) < i:
        return x

    return x >> (bitsize(x) - i)


def generate_nonce(n: int) -> int:
    """
    Уникальный ключ длиной (n-1) бит.

    В учебных целях он таков, какой ниже, однако
    должен быть уникальным для каждого ключа.
    """

    return 0x6 << (n-4)  # ибо 0x6 == 0b0110


# ===== Непосредственно MGM =====


def mgm_encrypt(
        encr_method: "callable",
        nonce: int, message: int,
        ass_data: int, key: int, 
        s: int = 128) -> \
        "cipher, ass_data, tag, remainder_mes, res_type":
    """
    Шифрование в режиме MGM.

    Аргументы:
    encr_method     - алгоритм шифрования
    nonce           - уникальный вектор длины (n-1) бит
    message         - шифруемое сообщение
    ass_data        - доп. имитозащищаемые данные
    key             - ключ шифрования
    s               - (необязательный аргумент) длина имитовставки

    Возвращает:
    cipher          - шифротекст
    ass_data        - доп. имитозащищаемые данные
    tag             - имитоданные
    remainder_mes   - длина хвоста сообщения в битах
    res_type        - тип шифруемых данных. Необходимо для расшифровки
    """

    # Предварительные ласки

    if s < 32 or s > 128:
        raise ValueError(f"s must be within [32, 128]. Passed {s}, however.")

    message, key, res_type = prepare_args(message, key)

    def lam_encrypt(x): return encr_method(x, key)[0]

    # =====  Подготовка  =====

    n = 128 # длина блоков шифрования в битах
    g = n // 2

    # Кол-ва блоков и длина остатка сообщений
    blocks_mes, remainder_mes = divmod(bitsize(message), n)
    blocks_ass, remainder_ass = divmod(bitsize(ass_data), n)

    tag_pt1, tag_pt2, tag_pt3 = 0, 0, 0

    z = lam_encrypt(1 << bitsize(nonce) | nonce)

    # Вычисление первой части имитовставки
    for i in range(blocks_ass + 1):
        if i != blocks_ass:
            offset = remainder_ass + (blocks_ass - i - 1) * n
            mask = unit_mask(n) << offset
            ass_block = (ass_data & mask) >> offset
        else:
            mask = unit_mask(remainder_ass)
            ass_block = (ass_data & mask) << (n - remainder_ass)

        h = lam_encrypt(z)
        tag_pt1 ^= gl_mul(h, ass_block)
        z = incr_l(z)

    # =====  Шифрование  =====

    cipher = 0
    y = lam_encrypt(nonce)

    for i in range(blocks_mes + 1):
        if i != blocks_mes:
            offset = remainder_mes + (blocks_mes - i - 1) * n
            mask = unit_mask(n) << offset
            message_block = (message & mask) >> offset

            cipher_block = message_block ^ lam_encrypt(y)
        else:
            offset = 0
            mask = unit_mask(remainder_mes)
            message_block = message & mask

            cipher_block = message_block ^ msb(lam_encrypt(y), remainder_mes)

        cipher |= (cipher_block << offset)

        if i == blocks_mes:
            cipher_block <<= n - remainder_mes

        h = lam_encrypt(z)
        tag_pt2 ^= gl_mul(h, cipher_block)

        y = incr_r(y)
        z = incr_l(z)

    #  ===== Вычисление имитовставки  =====

    # Вычисление третьей части имитовставки
    h = lam_encrypt(z)
    aux = pad(bitsize(ass_data), g) << g
    aux |= pad(bitsize(cipher), g)
    tag_pt3 = gl_mul(h, aux)

    tag = lam_encrypt(tag_pt1 ^ tag_pt2 ^ tag_pt3)
    tag = msb(tag, s)

    return cipher, ass_data, tag, remainder_mes, res_type


def mgm_decrypt(
        encr_method: callable,
        nonce: int, cipher: int,
        ass_data: int, key: int,
        tag: int, rem: int, res_type: object = int,
        s: int = 128) -> list[int, int]:
    """
    Шифрование в режиме MGM.

    Аргументы:
    encr_method -   алгоритм шифрования
    nonce       -   уникальный вектор длины (n-1) бит
    cipher      -   шифротекст
    ass_data    -   доп. имитозащищаемые данные
    key         -   ключ шифрования
    tag         -   имитовставка
    rem         -   длина хвоста шифруемого сообщения в битах
    s           -   (необязательный аргумент) длина имитовставки

    Возвращает:
    message     -   расшифрованное сообщение
    ass_data    -   доп. имитозащищаемые данные
    """

    # =====  Предварительные ласки  =====

    if s < 32 or s > 128:
        raise ValueError(f"s must be within [32, 128]. Passed {s}, however.")

    if type(cipher) != int or type(key) != int:
        raise ValueError("Either cipher or key is of inappropriate type (not int).")

    def lam_encrypt(x): return encr_method(x, key)[0]

    # =====  Подготовка  =====

    n = 128 # длина блоков шифрования в битах
    g = n // 2

    # Кол-ва блоков и длина остатка сообщений
    blocks_cip, remainder_cip = ceil((bitsize(cipher) - rem) / n), rem
    blocks_ass, remainder_ass = divmod(bitsize(ass_data), n)

    tag_pt1, tag_pt2, tag_pt3 = 0, 0, 0

    z = lam_encrypt(1 << bitsize(nonce) | nonce)

    # =====  Вычисление имитовставки  =====

    # Вычисление первой части имитовставки
    for i in range(blocks_ass + 1):
        if i != blocks_ass:
            offset = remainder_ass + (blocks_ass - i - 1) * n
            mask = unit_mask(n) << offset
            ass_block = (ass_data & mask) >> offset
        else:
            mask = unit_mask(remainder_ass)
            ass_block = (ass_data & mask) << (n - remainder_ass)

        h = lam_encrypt(z)
        tag_pt1 ^= gl_mul(h, ass_block)
        z = incr_l(z)

    # Вычисление второй части имитовставки
    for i in range(blocks_cip + 1):
        if i != blocks_cip:
            offset = remainder_cip + (blocks_cip - i - 1) * n
            mask = unit_mask(n) << offset
            cipher_block = (cipher & mask) >> offset
        else:
            mask = unit_mask(remainder_cip)
            cipher_block = (cipher & mask) << (n - remainder_cip)

        h = lam_encrypt(z)
        tag_pt2 ^= gl_mul(h, cipher_block)

        z = incr_l(z)

    # Вычисление третьей части имитовставки
    h = lam_encrypt(z)
    aux = pad(bitsize(ass_data), g) << g
    aux |= pad(bitsize(cipher), g)
    tag_pt3 = gl_mul(h, aux)

    tag_decr = lam_encrypt(tag_pt1 ^ tag_pt2 ^ tag_pt3)
    tag_decr = msb(tag_decr, s)

    if tag != tag_decr:
        return None, None

    # =====  Расшифровывание  =====

    message = 0
    y = lam_encrypt(nonce)

    for i in range(blocks_cip + 1):
        if i != blocks_cip:
            offset = remainder_cip + (blocks_cip - i - 1) * n
            mask = unit_mask(n) << offset
            cipher_block = (cipher & mask) >> offset

            message_block = cipher_block ^ lam_encrypt(y)
        else:
            offset = 0
            mask = unit_mask(remainder_cip)
            cipher_block = cipher & mask

            message_block = cipher_block ^ msb(lam_encrypt(y), remainder_cip)

        message |= message_block << offset

        h = lam_encrypt(z)
        tag_pt2 ^= gl_mul(h, message_block)

        y = incr_r(y)
 
    if res_type == str:
        message = int_to_str(message)

    return message, ass_data
