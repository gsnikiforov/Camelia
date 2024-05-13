
"""
Specially for guard
"""

from argparse import SUPPRESS


IS_STRING = "*"
EXAMPLE = IS_STRING + "../README.md"

encr_modes = (
    "e", "encrypt",
    "d", "decrypt"
)

algorithms = (
    "camellia",
    "ofb-camellia",
    "mgm-camellia",
)

HELP_RU = {
    ("encr_mode", ):
    {
        "type": str,
        "default": encr_modes[0],
        "choices": encr_modes,  # переписывает encr_mode
        "metavar": "encr_mode",
        "help": """
Опредѣляетъ, будетъ ли сообщеніе зашифровано али наоборотъ.
Мой выборъ палъ на %(default)s, но ваше превосходительство 
вольны выбирать изъ доступных:
""" + ", ".join(encr_modes) + "."
    },

    ("passage", ):
    {
        "help": """
Пассажъ либо опусъ, интересующій вашу милость въ засекреченномъ видѣ.
Коли вашей свѣтлости угодно, дабы я въ любомъ случаѣ воспринялъ посланіе 
какъ строку, передъ нею стоитъ поставить """ + IS_STRING + \
        " такимъ манером: " + EXAMPLE + " ."
    },

    ("-h", "--help"):
    {
        "action": "help",
        "default": SUPPRESS,
        "help": "Показать сіе сообщеніе да откланяться."
    },

    ("-u", "--using"):
    {
        "type": str,
        "default": algorithms[0],  # "choices": algorithms,
        "metavar": "МЕТОДЪ",
        "help": """
Методъ шифрованія, коимъ вашему превосходительству
угодно будетъ воспользоваться. На сей часъ въ наличiи """ +
        ", ".join(algorithms) + \
        ". За неимѣнием вашей свѣтлости я выбралъ %(default)s."
    },

    ("-k", "--key"):
    {
        "type": str,
        "metavar": "КЛЮЧИКЪ",
        "help": """
Ключъ шифрованія. Не будучи переданъ вашимъ сіятельствомъ, будетъ выдуманъ мною.
"""
    },

    ("-i", "--input"):
    {
        "type": str,
        "metavar": "ЗАГЛАВІЕ",
        "help": """
Заглавіе брошюры, коей мнѣ надлежитъ руководствоваться. Содержаніе оной превалируетъ надъ переданными аргументами.
"""
    },

    ("-o", "--output"):
    {
        "type": str,
        "metavar": "ЗАГЛАВІЕ",
        "help": """
Названіе опуса, коимъ я озаглавлю шифръ. Безъ названія просто произнесу шифръ.
"""
    },

    ("-p", "--prolix"):
    {
        "action": "store_true",  # store_true = молчаіе
        "help": """
Коль скоро указано, буду писать свои думы въ ходѣ шифрованія.
"""
    }

}


yeses = [
    "д", "да",
    "o", "oui",
    "y", "yes",
]
nos = [
    "н", "нѣтъ",
    "n", "non", "no",
]
acceptable_responses = yeses + nos


DESCRIPTION = "Вашъ карманный шифраторъ, живущій въ терминалѣ."
FINALE = "За симъ я, вашъ покорный слуга, откланяюсь..."

# Не измѣнять!
FIELDS = (
    "Mode", "Algorithm", "Return Type",
    "Key", "Initialization Vector", "Nonce",
    "Tag", "Remainder", "Associated Data",
    "Message", "Cipher"
)


allowed_types = (str, int)
types = {t.__name__: t for t in allowed_types}
