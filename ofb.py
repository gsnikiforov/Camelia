"""
Режим шифрования OFB.
"""

from utilities import *


def ofb(
        encr_method: callable, message: int, key: int,
        iv: int, encr_mode: int = ENCRYPT,
        res_type: object = int) -> tuple[int, object]:
    """
    Шифрование в режиме OFB.

    Из-за симметричности операции ^ шифрование и расшифровывание
    происходят одинаково.

    Аргументы:
    encr_method -   алгоритм шифрования
    message     -   шифруемое сообщение
    key         -   ключ шифрования
    iv          -   вектор инициализации
    encr_mode   -   (необязательный аргумент) определяет, будет
                    ли функция шифровать или расшифровывать
    res_type    -   (необязательный аргумент) тип message. Требуется
                    для корректной расшифровки

    Возвращает:
    cipher      -   шифротекст
    res_type    -   тип message. Требуется для корректной расшифровки
    """

    # =====  Подготовка  =====

    message, key, res_type = prepare_args(message, key, res_type)

    bits = sizeof(iv) * BYTE # размер блоков
    bits_in_message = sizeof(message) * BYTE
    k = iv

    # Определяем количества полных блоков в сообщении
    n = bits_in_message // bits
    n = 1 if n == 0 else n

    remainder = bits_in_message % bits # длина неполного блока

    # =====  Шифрование  =====

    mask = unit_mask(bits) << (bits * (n-1))
    cipher = 0

    for i in range(n):
        k = encr_method(k, key)[0]
        block = mask & message # message & mask
        cipher <<= bits

        cipher |= (k ^ block)

        if i != n-1:
            mask >>= bits
        else:
            mask >>= remainder

    if encr_mode == DECRYPT and res_type == str:
        cipher = int_to_str(cipher)
    
    return cipher, res_type
