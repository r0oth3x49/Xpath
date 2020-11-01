#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""

Author  : Nasir Khan (r0ot h3x49)
Github  : https://github.com/r0oth3x49
License : MIT


Copyright (c) 2016-2025 Nasir Khan (r0ot h3x49)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the
Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH 
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""

from xpath.common.lib import init, Fore, Back, Style

init(autoreset=True, convert=True)
# colors foreground text:
cyan = Fore.CYAN
green = Fore.GREEN
white = Fore.WHITE
red = Fore.RED
blue = Fore.BLUE
yellow = Fore.YELLOW
magenta = Fore.MAGENTA
black = Fore.BLACK

# colors background text:
background_cyan = Back.CYAN
background_green = Back.GREEN
background_white = Back.WHITE
background_red = Back.RED
background_blue = Back.BLUE
background_yellow = Back.YELLOW
background_magenta = Back.MAGENTA
background_black = Back.BLACK
background_reset = Back.RESET

level_map = {
    "INFO": {
        "color": "green",
        "faint": False,
        "bold": False,
        "normal": True,
        "background": "",
    },
    "WARNING": {
        "color": "yellow",
        "faint": False,
        "bold": False,
        "normal": True,
        "background": "",
    },
    "ERROR": {
        "color": "red",
        "faint": False,
        "bold": True,
        "normal": False,
        "background": "",
    },
    "CRITICAL": {
        "color": "white",
        "faint": False,
        "bold": False,
        "normal": True,
        "background": "red",
    },
    "DEBUG": {
        "color": "blue",
        "faint": False,
        "bold": False,
        "normal": True,
        "background": "",
    },
    "SUCCESS": {
        "color": "white",
        "faint": True,
        "bold": False,
        "normal": False,
        "background": "",
    },
    "NOTICE": {
        "color": "black",
        "faint": False,
        "bold": True,
        "normal": False,
        "background": "",
    },
    "PAYLOAD":{
        "color": "cyan",
        "faint": False,
        "bold": False,
        "normal": True,
        "background": "",
    },
    "START": {
        "color": "white",
        "faint": True,
        "bold": False,
        "normal": False,
        "background": "",
    },
    "END": {
        "color": "white",
        "faint": True,
        "bold": False,
        "normal": False,
        "background": "",
    },
    "TRAFFIC_IN": {
        "color": "black",
        "faint": True,
        "bold": False,
        "normal": False,
        "background": "magenta",
    },
    "TRAFFIC_OUT": {
        "color": "magenta",
        "faint": True,
        "bold": False,
        "normal": False,
        "background": "",
    },
}

color_map = {
    "white": white,
    "black": black,
    "cyan": cyan,
    "green": green,
    "magenta": magenta,
    "blue": blue,
    "yellow": yellow,
    "red": red,
}
bgcolor_map = {
    "white": background_white,
    "black": background_black,
    "cyan": background_cyan,
    "green": background_green,
    "magenta": background_magenta,
    "blue": background_blue,
    "yellow": background_yellow,
    "red": background_red,
}

DIM = Style.DIM
BRIGHT = Style.BRIGHT
NORMAL = Style.NORMAL
RESET = Style.RESET_ALL


def colorize(
    string,
    color="white",
    background="",
    bold=False,
    faint=False,
    normal=False,
    reset=True,
):
    if bold:
        style = BRIGHT
    if faint:
        style = DIM
    if normal:
        style = NORMAL
    if not bold and not faint and not normal:
        style = NORMAL

    reset = RESET
    if color in color_map:
        color = color_map.get(color)
    if background in bgcolor_map:
        background = bgcolor_map.get(background)
        string = f"{background}{string}{reset}"
    if reset:
        text = f"{color}{style}{string}{reset}"
    else:
        text = f"{color}{style}{string}"
    return text
