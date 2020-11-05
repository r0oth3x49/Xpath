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
    Search,
    TablesExtractor,
    ColumnsExtractor,
    RecordsExtractor,
    DefaultsExtractor,
    DatabasesExtractor,
)
from xpath.common.session import session
from xpath.injector.tests import SQLitest
from xpath.logger.colored_logger import logger, set_level
from xpath.common.lib import os, logging, collections
from xpath.common.utils import prepare_custom_headers


def perform_injection(
    url="",
    data="",
    host="",
    header="",
    cookies="",
    headers="",
    referer="",
    user_agent="",
    level=1,
    verbosity=1,
    techniques="",
    batch=False,
    flush_session=False,
):
    """
    Perform a requests request.

    Args:
        url: (str): write your description
        data: (array): write your description
        host: (str): write your description
        header: (str): write your description
        cookies: (list): write your description
        headers: (dict): write your description
        referer: (todo): write your description
        user_agent: (str): write your description
        level: (int): write your description
        verbosity: (int): write your description
        techniques: (str): write your description
        batch: (todo): write your description
        flush_session: (str): write your description
    """
    verbose_levels = {
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.PAYLOAD,
        4: logging.TRAFFIC_OUT,
        5: logging.TRAFFIC_IN,
    }
    verbose_level = verbose_levels.get(verbosity, logging.INFO)
    session_path = session.generate_filepath(url, flush_session=flush_session)
    filepath = os.path.join(session_path, "log")
    set_level(verbose_level, filepath)
    logger.start("starting")
    Response = collections.namedtuple(
        "Response",
        [
            "is_injected",
            "payloads",
            "filepath",
            "headers",
            "injection_type",
            "injected_param",
            "session_filepath",
            "recommended_payload",
            "recommended_payload_type",
        ],
    )
    custom_headers = prepare_custom_headers(
        host=host,
        header=header,
        cookies=cookies,
        headers=headers,
        referer=referer,
        user_agent=user_agent,
    )
    levels = {2: "Cookie", 3: "HEADER"}
    if url and not data:
        injection_type = "GET"
    if url and data:
        injection_type = "POST"
    if level == 1:
        if cookies and "*" in cookies:
            level = 2
        if (
            headers
            and "*" in headers
            or referer
            and "*" in referer
            or user_agent
            and "*" in user_agent
        ):
            level = 3
        if level in [2, 3]:
            injection_type = levels.get(level)
    elif level in [2, 3]:
        injection_type = levels.get(level)
    sqli = SQLitest(
        url=url,
        data=data,
        headers=custom_headers,
        filepath=session_path,
        injection_type=injection_type,
        techniques=techniques,
        batch=batch,
    )
    resp = sqli.perform()
    if resp.cookies:
        custom_headers += f"\n{resp.cookies}"
    if resp.headers:
        custom_headers += f"\n{resp.headers}"
    if resp.injection_type and resp.injection_type != injection_type:
        injection_type = resp.injection_type
    resp = Response(
        is_injected=resp.is_vulnerable,
        payloads=resp.payloads,
        filepath=resp.filepath,
        headers=custom_headers,
        injection_type=injection_type,
        injected_param=resp.injected_param,
        session_filepath=resp.session_filepath,
        recommended_payload=resp.recommended_payload,
        recommended_payload_type=resp.recommended_payload_type,
    )
    return resp


class XPATHInjector(
    Search,
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
        headers="",
        injected_param="",
        injection_type="",
        session_filepath="",
        payloads="",
    ):
        """
        Initialize a session.

        Args:
            self: (todo): write your description
            url: (str): write your description
            data: (todo): write your description
            payload: (todo): write your description
            regex: (bool): write your description
            headers: (list): write your description
            injected_param: (str): write your description
            injection_type: (todo): write your description
            session_filepath: (str): write your description
            payloads: (todo): write your description
        """
        self.url = url
        self.data = data
        self.payload = payload
        self.payloads = payloads
        self.headers = headers
        self.regex = regex
        self._injection_type = injection_type
        self.session_filepath = session_filepath
        self._injected_param = injected_param
        self._filepath = os.path.dirname(session_filepath)

    def __end(self, database="", table="", fetched=True):
        """
        Write a new database.

        Args:
            self: (todo): write your description
            database: (todo): write your description
            table: (str): write your description
            fetched: (bool): write your description
        """
        new_line = ""
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
        """
        Extract banner information.

        Args:
            self: (todo): write your description
        """
        response = self.banner
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_hostname(self):
        """
        Extract the hostname from the request.

        Args:
            self: (todo): write your description
        """
        response = self.hostname
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_current_db(self):
        """
        Extract current database.

        Args:
            self: (todo): write your description
        """
        response = self.database
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_current_user(self):
        """
        Extract the current user

        Args:
            self: (todo): write your description
        """
        response = self.user
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_dbs(self):
        """
        Extracts the dbs * dbs

        Args:
            self: (todo): write your description
        """
        response = self.dbs_names
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_tables(self, database=""):
        """
        Extract tables from the database.

        Args:
            self: (todo): write your description
            database: (str): write your description
        """
        response = self.tbl_names(db=database)
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_columns(self, database="", table=""):
        """
        Extract columns from the database.

        Args:
            self: (todo): write your description
            database: (str): write your description
            table: (str): write your description
        """
        response = self.col_names(db=database, tbl=table)
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_records(self, database="", table="", columns=""):
        """
        Extract all the records from the database.

        Args:
            self: (todo): write your description
            database: (str): write your description
            table: (str): write your description
            columns: (list): write your description
        """
        response = self.data_dump(db=database, tbl=table, cols=columns)
        fetched = response.fetched
        if fetched:
            logger.success("")
            self.__end(database=database, table=table, fetched=fetched)
        else:
            self.__end(fetched=fetched)
        return response

    def search_for(self, database="", table="", column=""):
        """
        Search for a given database.

        Args:
            self: (todo): write your description
            database: (str): write your description
            table: (str): write your description
            column: (str): write your description
        """
        search_type = ""
        if database and not table and not column:
            search_type = "database"
        elif database and table and not column:
            search_type = "table"
        elif not database and table and not column:
            search_type = "table"
        elif database and not table and column:
            search_type = "column"
        elif not database and table and column:
            search_type = "column"
        elif not database and not table and column:
            search_type = "column"
        elif database and table and column:
            search_type = "column"
        response = self.search(
            db=database, tbl=table, col=column, search_type=search_type
        )
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response
