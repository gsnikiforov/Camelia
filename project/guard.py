import gettext


def new_gettext(phrase):
    phrase = phrase.replace("usage", "методъ")
    phrase = phrase.replace("the following arguments are required", \
            "слѣдующимъ аргументамъ надлежитъ быть указанными")

    return phrase
gettext.gettext = new_gettext

import argparse
import sys


from utilities import *
from guard_utils import *

from ofb import ofb
from mgm import mgm_encrypt, mgm_decrypt
from camellia import camellia

from random import randint
from os import path


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write(
                f"Excusez-moi, {message}.\nНиже я оставлю вашему разумению\
список всех моих способностей:\n\n")
        self.print_help()
        sys.exit(2)


SILENT = False
PROLIX = not SILENT

gprint_voice = SILENT


def gprint(*args, **kwargs) -> None:

    global gprint_voice
    if gprint_voice == PROLIX:
        print(*args, **kwargs)


if __name__ == "__main__":

    parser = MyParser(
        description = DESCRIPTION,
        epilog = FINALE,
        add_help = False)

    parser._positionals.title = "arguments positionnels"
    parser._optionals.title = "факультативные параметры"

    for i in HELP_RU:
        parser.add_argument(*i, **(HELP_RU[i]))

    args = parser.parse_args()  # запуск парсера

    # =====  Обработка аргументов  =====

    gprint_voice = args.prolix
    mode = args.encr_mode
    via = args.using

    res_type = int

    if not args.passage.startswith(IS_STRING) and path.isfile(args.passage):
        with open(args.passage) as file:
            passage = file.read()
    else:
        passage = args.passage
        if not args.passage.startswith(IS_STRING):
            verity, base = is_number(args.passage)
            res_type = str
            if verity:
                passage = int(args.passage, base)
                res_type = int
        else:
            passage = args.passage.removeprefix(IS_STRING)
            res_type = str

    if args.key == None:
        key = randint(100, 100000)
    else:
        key = args.key

    # =====  Озвучивание размышлений  =====

    gprint("Вот какие мысли посещают мой ум:\n")

    type_of_file = "файл" if \
        path.isfile(args.passage) and not args.passage.startswith(IS_STRING)\
        else "простое сообщение"
    gprint("Преобразование:", args.encr_mode)
    gprint("Un régime de cryptage:", via)
    gprint(f"Сообщение: \"{args.passage}\"", "суть", type_of_file)

    # =====  Переменная для шифрования  =====

    iv = 0x80000000000000000000000000000000
    n = 128
    nonce = 0x6 << (n-4)
    ass_data = 0xbfee5c7c5fe97718ed6bf376739259fa
    tag = 1
    rem = 0

    cipher = None
    show_cipher = True

    # =====  Чтение инструкций  =====

    # values заполняется в соответствии с FIELDS
    values = [mode, via, res_type, key, iv, nonce,
              tag, rem, ass_data, passage, cipher]
    var = dict(zip(FIELDS, values))

    if args.input != None:
        d = read_json(args.input)
        d["Return Type"] = types[d["Return Type"]]

        del d["Mode"], d["Message"], d["Cipher"]

        var.update(d)

    # ===== Шифрование  =====

    if var["Mode"] in ("e", "encrypt"):
        if var["Algorithm"] == "camellia":
            var["Cipher"], var["Key"], var["Return Type"] = \
                camellia(var["Message"], var["Key"])

            var["Initialization Vector"], var["Nonce"], var["Associated Data"], \
                var["Tag"], var["Remainder"] = [None] * 5

        elif var["Algorithm"] == "ofb-camellia":
            var["Cipher"], var["Return Type"] = \
                ofb(camellia, var["Message"], var["Key"],
                    var["Initialization Vector"])

            var["Nonce"], var["Associated Data"], var["Tag"], var["Remainder"] = [
                None] * 4

        elif var["Algorithm"] == "mgm-camellia":
            var["Cipher"], var["Associated Data"], var["Tag"], var["Remainder"], \
                var["Return Type"] = mgm_encrypt(
                camellia, var["Nonce"], var["Message"], var["Associated Data"], var["Key"])

            var["Initialization Vector"] = None

        else:
            print(
                f"Покорнѣйше прошу прощенія! Алгоритму {var['Algorithm']} меня не обучали.")
            show_cipher = False

    elif var["Mode"] in ("d", "decrypt"):
        if var["Algorithm"] == "camellia":
            var["Cipher"], var["Key"], var["Return Type"] = \
                camellia(var["Message"], var["Key"],
                         DECRYPT, var["Return Type"])

            var["Initialization Vector"], var["Nonce"], var["Associated Data"], \
                var["Tag"], var["Remainder"] = [None] * 5

        elif var["Algorithm"] == "ofb-camellia":
            var["Cipher"], var["Return Type"] = ofb(
                camellia, var["Message"], var["Key"], var["Initialization Vector"],
                DECRYPT, var["Return Type"])

            var["Nonce"], var["Associated Data"], var["Tag"], var["Remainder"] = [
                None] * 4

        elif var["Algorithm"] == "mgm-camellia":
            var["Cipher"], var["Associated Data"] = mgm_decrypt(
                camellia, var["Nonce"], var["Message"], var["Associated Data"], var["Key"],
                var["Tag"], var["Remainder"], var["Return Type"])

            var["Initialization Vector"] = None

        else:
            print(f"Нижайше приношу извиненія. Алгоритмъ {via} я не разумѣю.")
            show_cipher = False

    # =====  Запись в файл  =====

    if args.output != None:
        should_write = True
        output = args.output
        gprint("Документ:", output, end="\n")

        if not file_empty(output):
            prefix = "\n" if gprint_voice == PROLIX else ""
            print(prefix + f"— Похоже, в \"{output}\" что-то начертано. \
Желают ли ваше превосходительство сей же час переписать оное?")
            respond = input("— ")

            while respond not in acceptable_responses:
                print("— Я превосходно понял ваше прекрасное \
сиятельство, но мне нужен любой изъ данных ответов: " +
                      ", ".join(acceptable_responses) + ".")
                respond = input("— ")

            if respond in nos:
                print(f"— Как пожелают ваше превысокомногосиятельство! \
В таком случае, я оставлю все на круги своя. Ваш шифр: \"{var['Cipher']}\". \
Не смею более задерживать вашу особу.")
                should_write = False
                show_cipher = False
            else:
                print("— Ваше желание для меня закон!\n")

        if should_write:
            write_dict_to_json(output, var, sep=": ", eol="\n\n")

    if show_cipher:
        print("Шифр:", var["Cipher"])
