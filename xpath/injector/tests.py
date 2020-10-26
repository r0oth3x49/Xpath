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
from xpath.common.lib import (
    re,
    os,
    sys,
    urlparse,
    parse_qs,
    collections,
    compat_urlencode,
    PAYLOAD_STATEMENT,
)
from xpath.common.utils import (
    extract_params,
    prepare_payloads,
    prepare_injection_payload,
    search_dbms_errors,
)
from xpath.common.session import session
from xpath.injector.request import request
from xpath.logger.colored_logger import logger
from xpath.common.colors import black, white, DIM, BRIGHT
from xpath.common.payloads import PREFIX, SUFFIX, REGEX_TESTS, PAYLOADS


class SQLitest:
    """
    A class which will test for SQL injection by testing payloads ..
    """

    def __init__(self, url, data="", cookies="", use_requests=False, filepath=None):
        self.url = url
        self.data = data
        self.cookies = cookies
        self._filepath = filepath
        self._session_filepath = os.path.join(filepath, "session.sqlite")
        self._target_file = os.path.join(filepath, "target.txt")
        self._use_requests = use_requests

    def _parse_target(self):
        ParamResponse = collections.namedtuple(
            "ParamResponse", ["params", "injection_type", "is_custom_injection"]
        )
        params = []
        injection_type = ""
        is_custom_injection = False
        _temp = ParamResponse(
            params=params,
            injection_type=injection_type,
            is_custom_injection=is_custom_injection,
        )
        if self.cookies and not self.data and self.url:
            injection_type = "Cookie"
            params = extract_params(
                value=self.cookies, delimeter=";", injection_type=injection_type
            )
            if "*" in self.cookies:
                # "custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] "
                question = logger.read_input(
                    "custom injection marker ('*') found in option '--cookie'. Do you want to process it? [Y/n/q] "
                )
                if question and question == "q":
                    logger.error("user quit.")
                    logger.end("ending")
                    sys.exit(0)
                if question and question == "n":
                    params = params
                if question == "" or question == "y":
                    is_custom_injection = True
                    injection_type = "(custom) Cookie"
        if self.data and not self.cookies and self.url:
            injection_type = "POST"
            params = extract_params(value=self.data, injection_type=injection_type)
            if "*" in self.data:
                question = logger.read_input(
                    "custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] "
                )
                if question and question == "q":
                    logger.error("user quit.")
                    logger.end("ending")
                    sys.exit(0)
                if question and question == "n":
                    params = params
                if question == "" or question == "y":
                    is_custom_injection = True
                    injection_type = "(custom) POST"
        if self.url and not self.cookies and not self.data:
            injection_type = "GET"
            params = extract_params(value=self.url, injection_type=injection_type)
            if "*" in self.url:
                question = logger.read_input(
                    "custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] "
                )
                if question and question == "q":
                    logger.error("user quit.")
                    logger.end("ending")
                    sys.exit(0)
                if question and question == "n":
                    params = params
                if question == "" or question == "y":
                    is_custom_injection = True
                    injection_type = "URI"
        if params:
            _temp = ParamResponse(
                params=params,
                injection_type=injection_type,
                is_custom_injection=is_custom_injection,
            )
        return _temp

    def is_injectable(
        self,
        url,
        data="",
        cookies="",
        param="",
        injectable_param="",
        injection_type="",
    ):
        payload = ".,))').\".."
        injectable = False
        if url and not data and not cookies:
            url = prepare_injection_payload(url, payload, param=injectable_param)
        if data and not cookies and url:
            data = prepare_injection_payload(data, payload, param=injectable_param)
        if cookies and not data and url:
            cookies = prepare_injection_payload(
                cookies, payload, param=injectable_param
            )
        try:
            resp = request.perform(url, data=data, cookies=cookies)
        except Exception as e:
            pass
        else:
            if resp.text:
                out = search_dbms_errors(resp.text)
                injectable = out.get("vulnerable")
                param = f"{DIM}{white}'{param}'{BRIGHT}{black}"
                if injectable:
                    dbms = out.get('dbms')
                    dbms = f"{DIM}{white}'{dbms}'{BRIGHT}{black}"
                    logger.notice(
                        f"heuristic (basic) test shows that {injection_type} parameter {param} might be injectable (possible DBMS: {dbms})"
                    )
                if not injectable:
                    logger.notice(
                        f"heuristic (basic) test shows that GET parameter {param} might not be injectable"
                    )
        return injectable

    def perform(self):
        vulns = []
        Response = collections.namedtuple(
            "Response",
            [
                "is_vulnerable",
                "payloads",
                "filepath",
                "injected_param",
                "session_filepath",
                "recommended_payload",
                "recommended_payload_type",
            ],
        )
        attemps_counter = 0
        session_data = []
        tested_payloads = []
        successful_payloads = []
        is_resumed = False
        filepath = None
        target_info = self._parse_target()
        try:
            logger.notice("testing connection to the target URL.")
            resp = request.perform(
                self.url, data=self.data, cookies=self.cookies, connection_test=True
            )
        except Exception as error:
            logger.warning("Xpath was not able to establish connection.")
            logger.error(error)
        payloads_list = prepare_payloads(
            prefixes=PREFIX, suffixes=SUFFIX, payloads=PAYLOADS
        )
        try:
            table_name = "tbl_payload"
            session_data = session.fetch_from_table(
                session_filepath=self._session_filepath,
                table_name=table_name,
                cursor=False,
            )
            if session_data:
                is_resumed = True
            for pay in session_data:
                vulns.append(
                    {
                        "injection_type": f"({pay.get('parameter')})",
                        "attempts": pay.get("payload_attemps"),
                        "payload": pay.get("payload"),
                        "title": pay.get("payload_type"),
                        "order": pay.get("payload_order"),
                        "regex": pay.get("regex"),
                        "injected_param": pay.get("param").replace("*", ""),
                    }
                )
        except Exception as error:
            pass
        if not vulns:
            params = target_info.params
            injection_type = target_info.injection_type
            is_custom_injection = target_info.is_custom_injection
            end_detection_phase = False
            is_injected = False
            successful_payload_prefix = ""
            vulnerable_param = ""
            if not params:
                logger.critical(
                    "no parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')."
                )
                logger.end("ending")
                sys.exit(0)
            for entry in params:
                param = entry.get("key")
                param_value = entry.get("value")
                if is_injected:
                    logger.read_input()
                if is_custom_injection and not param_value.endswith("*"):
                    continue
                injectable_param = f"{param}={param_value}" if param_value else ""
                is_injectable = self.is_injectable(
                    self.url,
                    self.data,
                    self.cookies,
                    param=param,
                    injectable_param=injectable_param,
                    injection_type=injection_type,
                )
                logger.info(
                    f"testing for SQL injection on {injection_type} parameter '{param if not is_custom_injection else '#1*'}'"
                )
                next_param_test = False
                for entry in payloads_list:
                    title = entry.get("title")
                    regex = entry.get("regex")
                    order = entry.get("order")
                    payloads = entry.get("payloads")
                    logger.info(f"testing '{title}'")
                    index = 0
                    if successful_payload_prefix:
                        payloads = [
                            pl
                            for pl in payloads
                            if pl.prefix == successful_payload_prefix
                        ]
                    while index < len(payloads):
                        url = self.url
                        data = self.data
                        cookies = self.cookies
                        obj = payloads[index]
                        payload = obj.string
                        prefix = obj.prefix
                        suffix = obj.suffix
                        if self.url and self.cookies and not self.data:
                            cookies = prepare_injection_payload(
                                text=self.cookies,
                                payload=payload,
                                param=injectable_param,
                            )
                        if self.url and not self.data and not self.cookies:
                            url = prepare_injection_payload(
                                text=self.url, payload=payload, param=injectable_param,
                            )
                        if self.url and self.data and not self.cookies:
                            data = prepare_injection_payload(
                                text=self.data, payload=payload, param=injectable_param,
                            )
                        try:
                            if not is_injected:
                                attemps_counter += 1
                            response = request.inject_payload(
                                url=url,
                                regex=REGEX_TESTS,
                                data=data,
                                cookies=cookies,
                                use_requests=self._use_requests,
                            )
                        except KeyboardInterrupt as e:
                            question = logger.read_input(
                                "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit] "
                            )
                            if question and question == "e":
                                end_detection_phase = True
                                break
                            if question and question == "s":
                                break
                            if question and question == "n":
                                next_param_test = True
                                break
                            if question and question.lower() == "q":
                                logger.error("user quit")
                                logger.end("ending")
                                sys.exit(0)
                        else:
                            if response.ok:
                                is_injected = True
                                successful_payload_prefix = prefix
                                _ = session.generate(
                                    session_filepath=self._session_filepath
                                )
                                with open(self._target_file, "w") as fd:
                                    fd.write(
                                        f"{self.url} ({'GET' if 'cookie' in injection_type.lower() else injection_type}) # {' '.join(sys.argv)}"
                                    )
                                if param:
                                    message = f"{injection_type} parameter '{DIM}{white}{param}{BRIGHT}{black}' is '{DIM}{white}{title}{BRIGHT}{black}' injectable"
                                else:
                                    message = f"{injection_type} parameter is '{DIM}{white}{title}{BRIGHT}{black}' injectable"
                                logger.notice(message)
                                vulns.append(
                                    {
                                        "injection_type": f"({injection_type})",
                                        "attempts": attemps_counter,
                                        "payload": payload,
                                        "title": title,
                                        "order": order,
                                        "regex": regex,
                                        "injected_param": injectable_param.replace(
                                            "*", ""
                                        ),
                                    }
                                )
                                _ = session.dump(
                                    session_filepath=self._session_filepath,
                                    query=PAYLOAD_STATEMENT,
                                    values=(
                                        str(title),
                                        order,
                                        attemps_counter,
                                        payload,
                                        injection_type,
                                        regex,
                                        "test",
                                        injectable_param,
                                    ),
                                )
                                vulnerable_param = param
                                break
                            index += 1
                    if end_detection_phase or next_param_test:
                        break
                if not is_injected:
                    _param = f"{DIM}{white}'{param}'{BRIGHT}{black}"
                    logger.notice(
                        f"{injection_type} parameter {_param} does not seem to be injectable"
                    )
                if end_detection_phase:
                    if not is_injected:
                        logger.critical(
                            "all tested parameters do not appear to be injectable"
                        )
                    break
                if is_injected and not next_param_test:
                    if vulnerable_param:
                        message = f"{injection_type} parameter '{vulnerable_param}' is vulnerable. Do you want to keep testing the others (if any)? [y/N] "
                    else:
                        message = f"{injection_type} parameter is vulnerable. Do you want to keep testing the others (if any)? [y/N] "
                    question = logger.read_input(message)
                    if question and question == "n":
                        break

        if vulns and isinstance(vulns, list):
            vulns = sorted(
                vulns,
                key=lambda k: k.get("order")
                if k.get("order")
                else k.get("payload_order"),
                reverse=True,
            )
            injection_type = vulns[0].get("injection_type")
            injected_param = vulns[0].get("injected_param")
            recommended_payload = vulns[0].get("payload")
            recommended_payload_type = vulns[0].get("regex")
            param = injected_param
            if not param and self.cookies:
                params = extract_params(
                    self.cookies, delimeter=";", injection_type="Cookie"
                )
                payload = prepare_injection_payload(
                    self.cookies, recommended_payload, param=""
                ).replace("%20", " ")
                param = ""
                for p in params:
                    _param = f"{p.get('key')}={p.get('value').replace('*', '')}"
                    _ = f"{_param}{recommended_payload}"
                    if _ in payload.strip():
                        param = _param
                        break
            if not is_resumed:
                message = f"xpath identified the following injection point(s) with a total of {attemps_counter} HTTP(s) requests:"
            if is_resumed:
                message = "xpath resumed the following injection point(s) from stored session:"
            logger.success(message)
            if param:
                _param = param.split("=")[0] if "=" in param else param
                injection_type = f"{_param} {injection_type}"
            logger.success(f"---\nParameter: {injection_type}")
            text = "    Type: error-based\n    Title: {title}\n    Payload: {_payload}"
            ok = []
            for v in vulns:
                title = v.get("title").strip()
                pl = v.get("payload").strip()
                if pl[0].lower() in ["a", "o"]:
                    pl = f" {pl}"
                if param:
                    pl = f"{param}{pl}"
                ok.append(text.format(title=title, _payload=pl))
            logger.success("\n\n".join(ok))
            logger.success("---")
            resp = Response(
                is_vulnerable=True,
                payloads=vulns,
                filepath=self._filepath,
                injected_param=injected_param,
                session_filepath=self._session_filepath,
                recommended_payload=recommended_payload,
                recommended_payload_type=recommended_payload_type,
            )
        else:
            resp = Response(
                is_vulnerable=False,
                payloads=vulns,
                filepath=None,
                injected_param=None,
                session_filepath=None,
                recommended_payload=None,
                recommended_payload_type=None,
            )
        return resp
