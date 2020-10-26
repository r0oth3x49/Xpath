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
from xpath.extractor import (
    TablesExtractor,
    ColumnsExtractor,
    RecordsExtractor,
    DefaultsExtractor,
    DatabasesExtractor,
)
from xpath.common.lib import os, logging
from xpath.common.session import session
from xpath.injector.tests import SQLitest
from xpath.logger.colored_logger import logger

log = logging.getLogger("Xpath")


def perform_injection(url="", data="", cookies=""):
    logger.start("starting")
    session_path = session.generate_filepath(url)
    filepath = os.path.join(session_path, "log")
    handler = logging.FileHandler(filepath)
    logging.basicConfig(
        format="%(message)s", level=logging.INFO, handlers=[handler],
    )
    sqli = SQLitest(url=url, data=data, cookies=cookies, filepath=session_path)
    target = sqli.perform()
    return target


class XPATHInjector(
    DefaultsExtractor,
    DatabasesExtractor,
    TablesExtractor,
    ColumnsExtractor,
    RecordsExtractor,
):
    """Fetches all the things related to MySQL"""

    def __init__(
        self,
        url,
        data="",
        payload="",
        regex="",
        cookies="",
        injected_param="",
        session_filepath="",
    ):
        self.url = url
        self.data = data
        self.payload = payload.replace("0x72306f746833783439", "{banner}")
        self.cookies = cookies
        self.regex = regex
        self.session_filepath = session_filepath
        self._injected_param = injected_param
        self._filepath = os.path.dirname(session_filepath)

    def __end(self, database="", table="", fetched=True):
        new_line = "\n"
        if database and table:
            filepath = os.path.join(self._filepath, "dump")
            filepath = os.path.join(filepath, database)
            filepath = os.path.join(filepath, f"{table}.csv")
            message = (
                f"{new_line}table '{database}.{table}' dumped to CSV file '{filepath}'"
            )
            logger.info(message)
            new_line = ""
        if fetched:
            logger.info(
                f"{new_line}fetched data logged to text files under '{self._filepath}'"
            )
        logger.end("ending")

    def extract_banner(self):
        response = self.banner
        fetched = response.is_injected
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_hostname(self):
        response = self.hostname
        fetched = response.is_injected
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_current_db(self):
        response = self.database
        fetched = response.is_injected
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_current_user(self):
        response = self.user
        fetched = response.is_injected
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_dbs(self):
        response = self.dbs_names
        fetched = response.fetched
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_tables(self, database=""):
        response = self.tbl_names(db=database)
        fetched = response.fetched
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_columns(self, database="", table=""):
        response = self.col_names(db=database, tbl=table)
        fetched = response.fetched
        if fetched:
            log.info("")
        self.__end(fetched=fetched)
        return response

    def extract_records(self, database="", table="", columns=""):
        response = self.data_dump(db=database, tbl=table, cols=columns)
        fetched = response.fetched
        if fetched:
            log.info("")
            self.__end(database=database, table=table, fetched=fetched)
        else:
            self.__end(fetched=fetched)
        return response
