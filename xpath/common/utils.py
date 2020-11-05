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
    html,
    chardet,
    binascii,
    urlparse,
    parse_qs,
    useragent,
    NO_DEFAULT,
    SQL_ERRORS,
    collections,
    compat_urlencode,
)
from xpath.logger.colored_logger import logger
from xpath.common.prettytable import PrettyTable, from_db_cursor

INVALID_URL = False


def to_hex(value):
    """
    Convert a hexadecimal value.

    Args:
        value: (todo): write your description
    """
    return f"0x{binascii.hexlify(value.encode()).decode()}"


def prettifier(cursor_or_list, field_names="", header=False):
    """
    Prettifier.

    Args:
        cursor_or_list: (list): write your description
        field_names: (str): write your description
        header: (str): write your description
    """
    fields = []
    Prettified = collections.namedtuple("Prettified", ["data", "entries"])
    if field_names:
        fields = re.sub(" +", "", field_names).split(",")
    table = PrettyTable(field_names=[""] if not fields else fields)
    table.align = "l"
    table.header = header
    entries = 0
    for d in cursor_or_list:
        if d and isinstance(d, str):
            d = (d,)
        table.add_row(d)
        entries += 1
    _temp = Prettified(data=table, entries=entries)
    return _temp


def parse_http_error(error):
    """
    Parse an http response.

    Args:
        error: (todo): write your description
    """
    Response = collections.namedtuple(
        "Response", ["text", "headers", "status_code", "reason", "error"]
    )
    text = ""
    status_code = 0
    headers = {}
    error_msg = ""
    reason = ""
    if hasattr(error, "response"):
        text = unescape_html(error.response)
        status_code = error.response.status_code
        reason = error.response.reason
        headers = error.response.headers
        error_msg = f"{status_code} ({reason})"
    else:
        text = unescape_html(error)
        status_code = error.code
        reason = error.reason
        headers = dict(error.info())
        error_msg = f"{status_code} ({reason})"
    return Response(
        text=text,
        headers=headers,
        status_code=status_code,
        reason=reason,
        error=error_msg,
    )


def parse_http_response(resp):
    """
    Parse a json response.

    Args:
        resp: (todo): write your description
    """
    Response = collections.namedtuple(
        "Response", ["ok", "text", "headers", "status_code", "reason", "error"]
    )
    text = ""
    status_code = 0
    headers = {}
    error_msg = ""
    reason = ""
    if hasattr(resp, "text"):
        text = resp.text
        status_code = resp.status_code
        reason = resp.reason
        headers = resp.headers
        ok = bool(200 == status_code)
        error_msg = f"{status_code} ({reason})"
    else:
        text = unescape_html(resp)
        status_code = resp.status
        ok = bool(200 == status_code)
        reason = resp.reason
        headers = dict(resp.info())
        error_msg = f"{status_code} ({reason})"
    return Response(
        ok=ok,
        text=text,
        headers=headers,
        status_code=status_code,
        reason=reason,
        error=error_msg,
    )


def unescape_html(resp, show=False):
    """
    Escape html.

    Args:
        resp: (todo): write your description
        show: (bool): write your description
    """
    response = ""
    if hasattr(resp, "read"):
        response = resp.read()
    if hasattr(resp, "content"):
        response = resp.content
    encoding = chardet.detect(response)["encoding"]
    if not encoding:
        # force the decode to be utf-8
        encoding = "utf-8"
    if show:
        logger.debug(f"declared web page charset '{encoding}'")
    if response and not isinstance(response, str):
        response = response.decode(encoding, errors="ignore")
    data = html.unescape(response)
    return data


def prepare_custom_headers(
    host="", header="", cookies="", headers="", referer="", user_agent=""
):
    """
    Prepares the http headers.

    Args:
        host: (str): write your description
        header: (str): write your description
        cookies: (todo): write your description
        headers: (str): write your description
        referer: (todo): write your description
        user_agent: (str): write your description
    """
    custom_headers = ""
    if host:
        custom_headers += f"Host: {host}\n"
    if user_agent:
        custom_headers += f"User-agent: {user_agent}\n"
    if referer:
        custom_headers += f"Referer: {referer}\n"
    if header and ":" in header:
        custom_headers += f"{header}\n"
    if headers and ":" in headers:
        if "\\n" in headers:
            headers = headers.replace("\\n", "\n")
        custom_headers += f"{headers}\n"
    if cookies:
        custom_headers += f"Cookie: {cookies}"
    custom_headers = "\n".join([i.strip() for i in custom_headers.rstrip().split("\n")])
    return custom_headers


def value_cleanup(value):
    """
    Strips and cleanups.

    Args:
        value: (todo): write your description
    """
    return re.sub(r"\s+", " ", re.sub(r"\(+", "", value))


def search_regex(
    pattern, string, default=NO_DEFAULT, fatal=True, flags=0, group=None,
):
    """
    Perform a regex search on the given string, using a single or a list of
    patterns returning the first matching group.
    In case of failure return a default value or raise a WARNING or a
    RegexNotFoundError, depending on fatal, specifying the field name.
    """
    if isinstance(pattern, str):
        mobj = re.search(pattern, string, flags)
    else:
        for p in pattern:
            mobj = re.search(p, string, flags)
            if mobj:
                break

    if mobj:
        if group is None:
            # return the first matching group
            value = next(g for g in mobj.groups() if g is not None)
        else:
            value = re.sub(r"\(+", "", mobj.group(group))
        if not value:
            value = "<blank_value>"
        value = value_cleanup(value)
        return value
    elif default is not NO_DEFAULT:
        return default
    elif fatal:
        logger.warning("unable to filter out values..")
    else:
        logger.warning("unable to filter out values..")


def cloudflare_decode(encoded_string):
    """
    Decode the decoded string.

    Args:
        encoded_string: (str): write your description
    """
    decoded = ""
    r = int(encoded_string[:2], 16)
    decoded = "".join(
        [
            chr(int(encoded_string[i : i + 2], 16) ^ r)
            for i in range(2, len(encoded_string), 2)
        ]
    )
    if decoded:
        decoded = re.sub(r"(?:(?:injected)?~(?:0|\()?(.+?)(?:1|~END)?)", r"\1", decoded)
    return decoded


def detect_cloudflare_protection(response):
    """
    Check if cloudflare is enabled

    Args:
        response: (todo): write your description
    """
    # This is a check some websites tends to protect data using cloudflare
    # such as email address so that automated bots cannot detect
    is_protected = False
    if response:
        mobj = re.search(r'(?is)(?:data-cfemail="(?P<xpath_data>(.+?))")', response)
        if not mobj:
            mobj = re.search(
                r'(?is)(?:<script\sdata-cfasync="false"\ssrc="(.+?)cloudflare(.+?)"></script>)',
                response,
            )
        if not mobj:
            mobj = re.search(r"(?is)(?:>\[(.+?)\sprotected\])", response)
        if mobj:
            is_protected = True
    return is_protected


def extract_encoded_data(response):
    """
    Extract the response and return the response.

    Args:
        response: (todo): write your description
    """
    return search_regex(
        pattern=r'(?is)(?:data-cfemail="(?P<xpath_data>(.+?))")',
        string=response,
        default="",
        group="xpath_data",
    )


def search_dbms_errors(html):
    """check SQL error is in HTML or not"""
    for db, errors in SQL_ERRORS.items():
        for error in errors:
            if re.compile(error).search(html):
                return {"vulnerable": True, "dbms": db, "error": error}
    return {"vulnerable": False, "dbms": None, "error": None}


def prepare_payloads(prefixes, suffixes, payloads, techniques=""):
    """
    Prepare payloads_to_payloads.

    Args:
        prefixes: (str): write your description
        suffixes: (str): write your description
        payloads: (todo): write your description
        techniques: (str): write your description
    """
    Payload = collections.namedtuple("Payload", ["prefix", "suffix", "string"])
    urle = compat_urlencode
    techniques_dict = {
        "X": [1, 2, 3],
        "E": [4, 5],
        "F": [6, 7, 8, 9],
        "D": [10],
        "B": [11],
        "G": [12, 13],
        "J": [14, 15],
    }
    techniques_to_test = []
    if techniques:
        techniques = techniques.strip()
        [techniques_to_test.extend(techniques_dict.get(i)) for i in techniques]
    _temp = []
    for entry in payloads:
        order = entry.get("order")
        if techniques and techniques_to_test and order not in techniques_to_test:
            continue
        pl = [
            Payload(prefix=urle(i), suffix=k, string=f"{i}{j}{k}")
            for i in prefixes
            for j in entry.get("payloads")
            for k in suffixes
        ]
        entry.update({"payloads": pl})
        _temp.append(entry)
    return _temp


def prepare_request(url, data, custom_headers, use_requests=False):
    """
    Prepare a request.

    Args:
        url: (str): write your description
        data: (dict): write your description
        custom_headers: (dict): write your description
        use_requests: (bool): write your description
    """
    Response = collections.namedtuple("Response", ["raw", "headers"])
    request_type = "GET"
    if url and data:
        request_type = "POST"
    parsed = urlparse.urlparse(url)
    path = parsed.path if not parsed.query else f"{parsed.path}?{parsed.query}"
    if not path:
        path = "/"
    if not custom_headers:
        custom_headers = f"User-agent: {useragent}"
    if custom_headers and "user-agent" not in custom_headers.lower():
        custom_headers += f"\nUser-agent: {useragent}"
    if custom_headers and "host" not in custom_headers.lower():
        custom_headers += f"\nHost: {parsed.netloc}"
    custom_headers = "\n".join(
        [i.strip() for i in custom_headers.split("\n") if i.strip()]
    )
    raw = f"{request_type} {path} HTTP/1.1\n"
    raw += f"{custom_headers if custom_headers else ''}\n"
    header = {}
    headers = custom_headers.split("\n")
    for i in headers:
        sph = [i.strip() for i in i.split(":")]
        header.update({sph[0]: sph[1]})
    if not use_requests:
        _temp = []
        for key, value in header.items():
            _temp.append((key, value))
        custom_headers = _temp
    else:
        custom_headers = header
    resp = Response(raw=raw, headers=custom_headers)
    return resp


def prepare_response(resp):
    """
    Prepares the http response.

    Args:
        resp: (todo): write your description
    """
    raw_response = f"({resp.status_code} {resp.reason}):\n"
    raw_headers = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
    raw_response += f"{raw_headers}"
    return raw_response


def extract_params(value, delimeter="", injection_type=""):
    """
    Extracts params.

    Args:
        value: (str): write your description
        delimeter: (str): write your description
        injection_type: (str): write your description
    """
    params = []
    injection_type = injection_type.upper()
    if injection_type == "HEADER":
        delimeter = "\n"
        out = [i.strip() for i in value.split(delimeter)]
        params = [
            {"key": i.split(":")[0].strip(), "value": i.split(":")[-1].strip()}
            for i in out
            if i
        ]
    if injection_type == "COOKIE":
        if not delimeter:
            if ":" in value:
                value = value.split(":")[-1]
            delimeter = ";"
        out = [i.strip() for i in value.split(delimeter)]
        params = [
            {"key": i.split("=")[0].strip(), "value": i.split("=")[-1].strip()}
            for i in out
            if i
        ]
    if injection_type == "POST":
        params = parse_qs(value)
        params = [{"key": k, "value": "".join(v)} for k, v in params.items()]
    if injection_type == "GET":
        parsed = urlparse.urlparse(value)
        path = parsed.path
        params = parse_qs(parsed.query)
        params = [{"key": k, "value": "".join(v)} for k, v in params.items()]
        if not params and path and path != "/":
            params = [{"key": "#1*", "value": "*"}]
    return params


def prepare_injection_payload(text, payload, param="", unknown_error_counter=0):
    """
    Prepares the payload of payload.

    Args:
        text: (str): write your description
        payload: (todo): write your description
        param: (str): write your description
        unknown_error_counter: (todo): write your description
    """
    global INVALID_URL
    prepared_payload = ""
    if "*" in text:
        init, last = text.split("*")
        prepared_payload = "{data}".format(data=init + payload + last)
    else:
        if param:
            text = text.strip()
            param = param.strip()
            text = text.replace(param, param + payload)
            prepared_payload = "{data}".format(data=text)
        else:
            prepared_payload = "{data}".format(data=text + payload)
    if unknown_error_counter >= 1 or INVALID_URL:
        INVALID_URL = True
        prepared_payload = prepared_payload.replace(" ", "%20")
    return prepared_payload


def clean_up_payload(payload, replaceable_string="0x72306f746833783439"):
    """
    Clean up the payload and replace the payload.

    Args:
        payload: (str): write your description
        replaceable_string: (str): write your description
    """
    return payload.replace(replaceable_string, "{banner}")


def prepare_payload_request(self, payload, unknown_error_counter=0):
    """
    Prepares the request.

    Args:
        self: (todo): write your description
        payload: (str): write your description
        unknown_error_counter: (todo): write your description
    """
    Response = collections.namedtuple("Response", ["url", "data", "regex", "headers"])
    url = self.url
    data = self.data
    regex = self.regex
    headers = self.headers
    it = self._injection_type.upper()
    if "GET" in it or "URI" in it:
        url = self._perpare_querystring(
            self.url, payload, unknown_error_counter=unknown_error_counter
        )
    if "POST" in it:
        # POST
        data = self._perpare_querystring(
            self.data, payload, unknown_error_counter=unknown_error_counter
        )
    if "HEADER" in it or "COOKIE" in it:
        # headers
        headers = self._perpare_querystring(
            self.headers, payload, unknown_error_counter=unknown_error_counter
        )
    return Response(url=url, data=data, regex=regex, headers=headers)
