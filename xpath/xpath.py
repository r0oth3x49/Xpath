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
from xpath.common.lib import os, ssl, logging, collections
from xpath.common.utils import prepare_custom_headers, prepare_proxy


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
    proxy=None,
    force_ssl=False,
):
    verbose_levels = {
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.PAYLOAD,
        4: logging.TRAFFIC_OUT,
        5: logging.TRAFFIC_IN,
    }
    if not force_ssl:
        # monkeypatch
        ssl._create_default_https_context = ssl._create_unverified_context
    if proxy:
        proxy = prepare_proxy(proxy)
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
            "dbms",
            "filepath",
            "headers",
            "proxy",
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
        proxy=proxy,
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
        dbms=resp.dbms,
        filepath=resp.filepath,
        headers=custom_headers,
        proxy=proxy,
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
        proxy=None,
        dbms=None,
    ):
        self.url = url
        self.data = data
        self.payload = payload
        self.payloads = payloads
        self.headers = headers
        self.regex = regex
        self._injection_type = injection_type
        self.session_filepath = session_filepath
        self._injected_param = injected_param
        self._proxy = proxy
        self._dbms = dbms
        self._filepath = os.path.dirname(session_filepath)

    def __end(self, database="", table="", fetched=True):
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
        response = self.banner
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_hostname(self):
        response = self.hostname
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_current_db(self):
        response = self.database
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_current_user(self):
        response = self.user
        fetched = response.is_injected
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_dbs(self):
        response = self.dbs_names
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_tables(self, database=""):
        response = self.tbl_names(db=database)
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_columns(self, database="", table=""):
        response = self.col_names(db=database, tbl=table)
        fetched = response.fetched
        if fetched:
            logger.success("")
        self.__end(fetched=fetched)
        return response

    def extract_records(self, database="", table="", columns=""):
        response = self.data_dump(db=database, tbl=table, cols=columns)
        fetched = response.fetched
        if fetched:
            logger.success("")
            self.__end(database=database, table=table, fetched=fetched)
        else:
            self.__end(fetched=fetched)
        return response

    def search_for(self, database="", table="", column=""):
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
