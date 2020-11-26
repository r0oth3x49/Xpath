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
    colorize,
    level_map,
    color_map,
    bgcolor_map,
    DIM,
    BRIGHT,
    NORMAL,
    RESET,
)
from xpath.common.banner import BANNER
from xpath.common.lib import os, sys, time, logging, collections

log = logging.getLogger("Xpathlog")


class ColoredFormatter(logging.Formatter):
    """
    Xpath custom color logger..
    """

    def format(self, record):
        message = record.getMessage()
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
        uses_time = self.usesTime()
        if not uses_time:
            asctime = time.strftime("%H:%M:%S")
        if uses_time:
            asctime = self.formatTime(record, datefmt=self.datefmt)
        color_conf = level_map.get(levelname)
        levelname = colorize(levelname, **color_conf)
        asctime = colorize(asctime, color="cyan", faint=True)
        start = colorize("[", color="white", faint=True)
        end = colorize("]", color="white", faint=True)
        formatted_message = None
        if record.levelname == "INFO":
            message = colorize(message)
        elif record.levelname == "NOTICE":
            if (
                "might not be injectable" in message
                or "does not seem to be injectable" in message
            ):
                levelname = colorize("WARNING", color="yellow", normal=True)
            else:
                levelname = colorize("INFO", color="green", normal=True)
            message = colorize(message, **color_conf)
        elif record.levelname == "CRITICAL":
            message = colorize(message)
        elif record.levelname == "DEBUG":
            message = colorize(message)
        elif record.levelname == "ERROR":
            message = colorize(message, color="red", normal=False, bold=True)
        elif record.levelname == "SUCCESS":
            message = colorize(message, **color_conf)
            formatted_message = f"{spaces}{message}"
        elif record.levelname == "START":
            message = f"\n[*] starting @ {time.strftime('%H:%M:%S')} /{time.strftime('%Y-%m-%d')}/\n"
            formatted_message = colorize(message, **color_conf)
        elif record.levelname == "END":
            message = f"\n[*] ending @ {time.strftime('%H:%M:%S')} /{time.strftime('%Y-%m-%d')}/\n"
            formatted_message = colorize(message, **color_conf)
        elif record.levelname == "TRAFFIC_IN":
            message = colorize(message)
        elif record.levelname == "TRAFFIC_OUT":
            message = colorize(message)
        elif record.levelname == "PAYLOAD":
            message = colorize(message, normal=True)
            spaces = ""
        else:
            message = colorize(f"{spaces}{message}", normal=True)
        if not formatted_message:
            formatted_message = (
                f"{spaces}{start}{asctime}{end} {start}{levelname}{end} {message}"
            )
        return formatted_message


class ColoredLogger:
    """Custom colored logger"""

    def __init__(self, logger):

        # set success level
        logging.TRAFFIC_IN = 1
        logging.TRAFFIC_OUT = 8
        logging.PAYLOAD = 9
        logging.NOTICE = 26
        logging.START = 27
        logging.END = 28
        logging.SUCCESS = 70
        logging.addLevelName(logging.END, "END")
        logging.addLevelName(logging.START, "START")
        logging.addLevelName(logging.SUCCESS, "SUCCESS")
        logging.addLevelName(logging.NOTICE, "NOTICE")
        logging.addLevelName(logging.PAYLOAD, "PAYLOAD")
        logging.addLevelName(logging.TRAFFIC_IN, "TRAFFIC_IN")
        logging.addLevelName(logging.TRAFFIC_OUT, "TRAFFIC_OUT")

        stream_handler = logging.StreamHandler()
        stream_formatter = ColoredFormatter(
            "[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S"
        )
        stream_handler.setFormatter(stream_formatter)
        logger.addHandler(stream_handler)
        setattr(
            logger,
            "success",
            lambda message, *args: logger._log(logging.SUCCESS, message, args),
        )
        setattr(
            logger,
            "payload",
            lambda message, *args: logger._log(logging.PAYLOAD, message, args),
        )
        setattr(
            logger,
            "notice",
            lambda message, *args: logger._log(logging.NOTICE, message, args),
        )
        setattr(
            logger,
            "traffic_in",
            lambda message, *args: logger._log(logging.TRAFFIC_IN, message, args),
        )
        setattr(
            logger,
            "traffic_out",
            lambda message, *args: logger._log(logging.TRAFFIC_OUT, message, args),
        )
        setattr(
            logger,
            "start",
            lambda message, *args: logger._log(logging.START, message, args),
        )
        setattr(
            logger,
            "end",
            lambda message, *args: logger._log(logging.END, message, args),
        )
        setattr(
            logger,
            "read_input",
            self.read_input,
        )
        self.logger = logger
        self.stream_handler = stream_handler

    def set_level(self, level, filepath):
        if not os.path.isfile(filepath):
            with open(filepath, "a", encoding="utf-8") as fd:
                pass
        self.stream_handler.setLevel(level)
        handler = logging.FileHandler(filepath, mode="a", encoding="utf-8")
        ff = logging.Formatter("%(message)s")
        handler.setFormatter(ff)
        handler.setLevel(logging.SUCCESS)
        self.logger.addHandler(handler)
        self.logger.setLevel(level)

    def read_input(self, message, batch=False, user_input="", *args, **kwargs):
        """
        :params:
            string: String to show on user stdout
            color: color to set on string for stdout (default: white)
            faint: true/false (default: false)
            bold: true/false (default: true)
            background: background color if you want to set. (default: none)
        """
        message = colorize(
            string=f"{message.strip()} ",
            color="white",
            faint=False,
            bold=True,
            normal=False,
            background="",
        )
        try:
            if not batch:
                sys.stdout.write("{}".format(message))
                sys.stdout.flush()
                ui = input()
                if ui:
                    user_input = ui
                print("")
            if batch:
                sys.stdout.write("{}{}".format(message, user_input))
                sys.stdout.flush()
                print("")
        except KeyboardInterrupt:
            self.error("\n\nuser quit")
            self.end("ending")
            print("")
            sys.exit(0)
        return user_input.lower()


colored_logger = ColoredLogger(logger=log)
logger = colored_logger.logger
set_level = colored_logger.set_level
