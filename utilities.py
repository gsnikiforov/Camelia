from os.path import isfile
from json import    dump as json_dump, load as json_load

# Константы

BYTE = 8
UTF = 16

# Маски
MASK8 = 0xff
MASK32 = 0xffffffff
MASK64 = 0xffffffffffffffff
MASK128 = 0xffffffffffffffffffffffffffffffff

# Флаги шифрования
ENCRYPT = False
DECRYPT = not ENCRYPT


def log(x: int, n: int) -> int:

    if x < 0:
        raise ValueError(f"x > 0 !!! Passed {x}, however.")
    l = 0
    if x == 0:
        return 0
    while (x := x // n):
        l += 1
    return l


def sizeof(x: int | str) -> int:

    if type(x) == int:
        return log(x, 256) + 1

    if type(x) == str:
        return len(x)

    raise ValueError("Functionality for %s is not implemented." % type(x))


def bitsize(x: int) -> int:

    bits = 0
    while x:
        x >>= 1
        bits += 1
    return bits




def unit_mask(n: int) -> int:
    return (1 << n) - 1


def chess_mask(n: int) -> int:
    if n % 2:
        raise ValueError("n must be even. Passed %i." % n)

    g = n // 2
    left = unit_mask(g) << g
    right = unit_mask(n) ^ left
    return left, right


# ===== Сдвиги и выравнивание =====


def left_rotation(a: int, x: int) -> int:
    if x < 0:
        raise ValueError("x must be non-negative!")

    if a == 0:
        return a

    x %= bitsize(a)

    if a == 0:
        return 0

    mask = unit_mask(bitsize(a))
    return mask & ((a << x) | (a >> (bitsize(a) - x)))


def pad(x: any, n: int) -> int:
    if bitsize(x) >= n:
        raise ValueError(f"bitsize({x}) is bigger than {n}.")

    return x << (n - bitsize(x))


# ===== Строковые функциии =====


def contains(s: str, values: iter):
    for i in s:
        if i in values:
            return True
    return False


def check_empty_intersection(s: str, allowed):

    return len( set(s).difference(allowed) ) == 0


def is_number(s: str) -> tuple[bool, int]:
    base = 10
    
    if type(s) == int:
        raise TypeError("s must be str !")

    prefixes = ("0b", "0o", "0x")
    numbers = "0123456789"
    letters = "abcdef"

    allowed2 = frozenset(numbers[:2])
    allowed8 = frozenset(numbers[:8])
    allowed10 = frozenset(numbers)
    allowed16 = set(numbers).union(set(letters))

    for p in prefixes:
        if s.startswith(p):
            if p == "0b":
                allowed, base = allowed2, 2
            elif p == "0o":
                allowed, base = allowed8, 8
            elif p == "0x":
                allowed, base = allowed16, 16
            else:
                allowed, base = allowed10, 10

            return check_empty_intersection(s[2:], allowed), base

    if s.isdigit():
        return True, base

    base = -1

    return False, base


def str_to_int(s: str) -> int:
    
    i = 0
    for l in s[::-1]:
        i <<= UTF
        i |= ord(l)
    return i


def int_to_str(i: int) -> str:

    s = ""
    mask = unit_mask(UTF)
    while i:
        s += chr(i & mask)
        i >>= UTF
    return s


# ===== Файловые операции =====


def file_empty(filename: str) -> bool:

    if not isfile(filename):
        return True

    with open(filename, "r") as file:
        c = file.read(1)
        if not c:
            return True
    return False


def suffix(filename: str) -> str:
    """
    Определяет суффикс файла.
    """

    i = filename.rfind(".")
    return filename[i+1:] if i != -1 else ""


def write_dict_to_json(
        filename, data, sep = " -> ", eol = "", ignore_none = True):
    if isfile(filename):
        mode = "w"
    else:
        mode = "x"
 
    new_data = data.copy()

    for i in data:
        if ignore_none and data[i] == None:
            del new_data[i]

        if type(data[i]) == type:
            new_data[i] = data[i].__name__

        if type(i) == type:
            new_data[i.__name__] = new_data.pop(i)


    with open(filename, mode = mode) as file:
        json_dump(new_data, file, indent = 4)


def read_json(filename) -> dict:
    with open(filename, "r") as file:
        read_data = json_load(file)
    return read_data


# ===== Специфические функции =====


def prepare_args(message: object, key: object, res_type = int) -> tuple[int, int, object]:

    if type(message) == str:
        message = str_to_int(message)
        res_type = str

    if type(key) == str:
        key = str_to_int(key)

    return message, key, res_type

