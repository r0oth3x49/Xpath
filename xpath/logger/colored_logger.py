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

from xpath.common.colors import (
    level_map,
    color_map,
    bgcolor_map,
    DIM,
    BRIGHT,
    NORMAL,
    RESET,
)
from xpath.common.banner import BANNER
from xpath.common.lib import sys, time, logging, collections

log = logging.getLogger(__name__)

class ColoredLogger:
    """
    Xpath custom color logger..
    """

    faint = DIM
    bold = BRIGHT
    reset = RESET
    normal = NORMAL
    color_map = color_map
    level_map = level_map
    bgcolor_map = bgcolor_map
    CustomRecord = collections.namedtuple("Record", ["message", "levelname"])

    def __colorize(
        self,
        string,
        color="white",
        background="",
        bold=False,
        faint=False,
        normal=False,
    ):
        if bold:
            style = self.bold
        if faint:
            style = self.faint
        if normal:
            style = self.normal
        if not bold and not faint and not normal:
            style = self.normal

        reset = self.reset
        if color in self.color_map:
            color = self.color_map.get(color)
        if background in self.bgcolor_map:
            background = self.bgcolor_map.get(background)
            string = f"{background}{string}{reset}"
        text = f"{color}{style}{string}{reset}"
        return text

    def __format(self, record):
        message = record.message
        from pprint import pprint

        spaces = ""
        leading_spaces_count = len(message) - len(message.lstrip())
        if message.startswith("\n"):
            spaces = "\n" * leading_spaces_count
            message = message.lstrip()
        if message.startswith("\t"):
            spaces = "\t" * leading_spaces_count
            message = message.lstrip()
        if message.startswith(" "):
            spaces = " " * leading_spaces_count
            message = message.lstrip()
        levelname = record.levelname
        asctime = time.strftime("%H:%M:%S")
        color_conf = self.level_map.get(levelname)
        levelname = self.__colorize(levelname, **color_conf)
        asctime = self.__colorize(asctime, color="cyan", faint=True)
        start = self.__colorize("[", color="white", faint=True)
        end = self.__colorize("]", color="white", faint=True)
        formatted_message = None
        if record.levelname == "INFO":
            message = self.__colorize(message)
        elif record.levelname == "NOTICE":
            if (
                "might not be injectable" in message
                or "does not seem to be injectable" in message
            ):
                levelname = self.__colorize("WARNING", color="yellow", normal=True)
            else:
                levelname = self.__colorize("INFO", color="green", normal=True)
            message = self.__colorize(message, **color_conf)
        elif record.levelname == "CRITICAL":
            message = self.__colorize(message)
        elif record.levelname == "DEBUG":
            message = self.__colorize(message, **color_conf)
        elif record.levelname == "ERROR":
            message = self.__colorize(message, color="red", normal=False, bold=True)
        elif record.levelname == "SUCCESS":
            message = self.__colorize(message, **color_conf)
            formatted_message = f"{spaces}{message}"
        elif record.levelname == "TRAFFIC_IN":
            message = f"\n[*] starting @ {time.strftime('%H:%M:%S')} /{time.strftime('%Y-%m-%d')}/\n"
            formatted_message = self.__colorize(message, **color_conf)
        elif record.levelname == "TRAFFIC_OUT":
            message = f"\n[*] ending @ {time.strftime('%H:%M:%S')} /{time.strftime('%Y-%m-%d')}/\n"
            formatted_message = self.__colorize(message, **color_conf)
        else:
            message = self.__colorize(f"{spaces}{message}", normal=True)
        if not formatted_message:
            formatted_message = (
                f"{spaces}{start}{asctime}{end} {start}{levelname}{end} {message}"
            )
        return formatted_message

    def info(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="INFO")
        message = self.__format(record=record)
        print(message)

    def debug(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="DEBUG")
        message = self.__format(record=record)
        print(message)

    def error(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="ERROR")
        message = self.__format(record=record)
        print(message)

    def notice(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="NOTICE")
        message = self.__format(record=record)
        print(message)

    def success(self, message, *args, **kwargs):
        log.info(message)
        record = self.CustomRecord(message=message, levelname="SUCCESS")
        message = self.__format(record=record)
        print(message)
        spaces = ""

    def http_error(self, message, *args, **kwargs):
        message = self.__colorize(
            string=message,
            color="white",
            faint=True,
            bold=False,
            normal=False,
            background="",
        )
        print(message)

    def warning(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="WARNING")
        message = self.__format(record=record)
        print(message)

    def critical(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="CRITICAL")
        message = self.__format(record=record)
        print(message)

    def start(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="TRAFFIC_IN")
        message = self.__format(record=record)
        print(message)

    def end(self, message, *args, **kwargs):
        record = self.CustomRecord(message=message, levelname="TRAFFIC_OUT")
        message = self.__format(record=record)
        print(message)

    def read_input(
        self,
        string="",
        color="white",
        faint=False,
        bold=True,
        normal=False,
        background="",
    ):
        """
        :params:
            string: String to show on user stdout
            color: color to set on string for stdout (default: white)
            faint: true/false (default: false)
            bold: true/false (default: true)
            background: background color if you want to set. (default: none)
        """
        message = self.__colorize(
            string=f"{string.strip()} ",
            color="white",
            faint=False,
            bold=True,
            normal=False,
            background="",
        )
        try:
            sys.stdout.write("{}".format(message))
            sys.stdout.flush()
            user_input = input()
            print("")
        except KeyboardInterrupt:
            self.error("\n\nuser quit")
            self.end("ending")
            print("")
            sys.exit(0)
        return user_input.lower()


logger = ColoredLogger()
