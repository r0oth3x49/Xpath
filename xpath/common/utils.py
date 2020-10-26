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
    urlparse,
    parse_qs,
    NO_DEFAULT,
    SQL_ERRORS,
    collections,
    compat_urlencode
)
from xpath.logger.colored_logger import logger
from xpath.common.prettytable import PrettyTable, from_db_cursor


def prettifier(cursor_or_list, field_names="", header=False):
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

def unescape_html(resp):
    response = ""
    if hasattr(resp, "read"):
        response = resp.read()
    if hasattr(resp, "content"):
        response = resp.content
    encoding = chardet.detect(response)["encoding"]
    if response and not isinstance(response, str):
        response = response.decode(encoding, errors="ignore")
    data = html.unescape(response)
    return data


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

    # _name = name

    if mobj:
        if group is None:
            # return the first matching group
            return next(g for g in mobj.groups() if g is not None)
        else:
            return re.sub(r"\(+", "", mobj.group(group))
    elif default is not NO_DEFAULT:
        return default
    elif fatal:
        logger.warning("unable to filter out values..")
    else:
        logger.warning("unable to filter out values..")


def cloudflare_decode(encoded_string):
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


def prepare_payloads(prefixes, suffixes, payloads):
    Payload = collections.namedtuple("Payload", ["prefix", "suffix", "string"])
    urle = compat_urlencode
    for entry in payloads:
        pl = [
            Payload(prefix=urle(i), suffix=k, string=f"{i}{j}{k}")
            for i in prefixes
            for j in entry.get("payloads")
            for k in suffixes
        ]
        entry.update({"payloads": pl})
    return payloads


def extract_params(value, delimeter="", injection_type=""):
    params = []
    injection_type = injection_type.upper()
    if injection_type == "COOKIE":
        if not delimeter:
            delimeter = ";"
        out = [i.strip() for i in value.split(delimeter)]
        params = [
            {"key": i.split("=")[0].strip(), "value": i.split("=")[-1].strip(),}
            for i in out
            if i
        ]
    if injection_type == "POST":
        params = parse_qs(value)
        params = [{"key": k, "value": "".join(v)} for k, v in params.items()]
    if injection_type == "GET":
        parsed = urlparse.urlparse(value)
        params = parse_qs(parsed.query)
        params = [{"key": k, "value": "".join(v)} for k, v in params.items()]
    return params


def prepare_injection_payload(text, payload, param=""):
    prepared_payload = ""
    if "*" in text:
        init, last = text.split("*")
        prepared_payload = "{data}".format(
            data=init + payload.replace(" ", "%20") + last
        )
    else:
        if param:
            prepared_payload = "{data}".format(
                data=text.replace(param, param + payload.replace(" ", "%20"))
            )
        else:
            prepared_payload = "{data}".format(data=text + payload.replace(" ", "%20"))
    return prepared_payload
