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
    requests,
    urlparse,
    useragent,
    collections,
    compat_urlerr,
    compat_opener,
    compat_request,
    compat_urlopen,
    compat_httperr,
)
from xpath.common.utils import (
    search_regex,
    unescape_html,
    cloudflare_decode,
    extract_encoded_data,
    detect_cloudflare_protection,
)


class HTTPRequestHandler:
    """
    Xpath requests handler
    """

    def inject_payload(
        self, url, regex, data="", cookies="", use_requests=False, timeout=30
    ):
        ok = False
        text = ""
        result = ""
        error = ""
        status_code = 0
        Response = collections.namedtuple(
            "Response", ["ok", "status_code", "text", "result", "error"],
        )
        _temp = Response(
            ok=ok, status_code=status_code, text=text, result=result, error=error,
        )
        if not data:
            try:
                if not use_requests:
                    opener = compat_opener()
                    opener.addheaders = [
                        ("Cookie", "%s" % cookies),
                        ("User-Agent", "%s" % useragent),
                    ]
                    resp = opener.open(url, timeout=timeout)
                else:
                    headers = {"User-Agent": useragent, "Cookie": cookies}
                    resp = requests.get(url, headers=headers, timeout=timeout)
                    resp.raise_for_status()
            except (compat_httperr, requests.exceptions.HTTPError) as e:
                text = ""
                code = 0
                if hasattr(e, "response"):
                    text = e.response.text
                    code = e.response.status_code
                    reason = e.response.reason
                    error = f"{code} ({reason})"
                else:
                    text = str(e)
                    if hasattr(e, "code"):
                        code = e.code
                        reason = e.reason
                        error = f"{code} ({reason})"
                status_code = code
            except compat_urlerr as e:
                raise str(e)
            except Exception as e:
                raise str(e)
            else:
                text = unescape_html(resp)
                status_code = (
                    resp.status if hasattr(resp, "status") else resp.status_code
                )
        if data:
            try:
                if not use_requests:
                    data = data.encode("utf-8")
                    opener = compat_opener()
                    opener.addheaders = [
                        ("Cookie", "%s" % cookies),
                        ("User-Agent", "%s" % useragent),
                    ]
                    resp = opener.open(url, data, timeout=timeout)
                else:
                    headers = {"User-Agent": useragent, "Cookie": cookies}
                    resp = requests.get(
                        url, data=data, headers=headers, timeout=timeout
                    )
                    resp.raise_for_status()
            except compat_httperr as e:
                text = ""
                code = 0
                if hasattr(e, "response"):
                    text = e.response.text
                    code = e.response.status_code
                    reason = e.response.reason
                    error = f"{code} ({reason})"
                else:
                    text = str(e)
                    if hasattr(e, "code"):
                        code = e.code
                        reason = e.reason
                        error = f"{code} ({reason})"
                status_code = code
            except compat_urlerr as e:
                raise str(e)
            except Exception as e:
                raise str(e)
            else:
                text = unescape_html(resp)
                status_code = (
                    resp.status if hasattr(resp, "status") else resp.status_code
                )
        is_protected = detect_cloudflare_protection(text)
        if is_protected:
            result = cloudflare_decode(extract_encoded_data(text))
            _temp = Response(
                ok=True if result else False,
                status_code=status_code,
                text="",  # text, we can add response html here
                result=result,
                error=error,
            )
        if not is_protected:
            result = search_regex(
                pattern=regex, string=text, default="", group="xpath_data",
            )
            _temp = Response(
                ok=True if result else False,
                status_code=status_code,
                text="",  # text, we can add response html here
                result=result,
                error=error,
            )
        return _temp

    def perform(
        self,
        url,
        data="",
        headers="",
        cookies="",
        timeout=20,
        use_requests=False,
        connection_test=False,
    ):
        Response = collections.namedtuple("Response", ["ok", "text", "headers"])
        ok = False
        text = None
        headers = {}
        if connection_test:
            parsed = urlparse.urlparse(url)
            url = f"{parsed.scheme}://{parsed.netloc}"
        http_response = Response(ok=ok, text=text, headers=headers)
        if not data:
            try:
                if not use_requests:
                    opener = compat_opener()
                    opener.addheaders = [
                        ("Cookie", "%s" % cookies),
                        ("User-Agent", "%s" % useragent),
                    ]
                    resp = opener.open(url, timeout=timeout)
                else:
                    headers = {"User-Agent": useragent, "Cookie": cookies}
                    resp = requests.get(url, headers=headers, timeout=timeout)
                    resp.raise_for_status()
                text = unescape_html(resp)
                status_code = (
                    resp.status_code if hasattr(resp, "status_code") else resp.status
                )
                ok = bool(200 == status_code)
                headers = (
                    resp.headers if hasattr(resp, "headers") else dict(resp.info())
                )
                http_response = Response(ok=ok, text=text, headers=headers)
            except Exception as error:
                raise str(error)
        if data:
            try:
                if not use_requests:
                    data = data.encode("utf-8")
                    opener = compat_opener()
                    opener.addheaders = [
                        ("Cookie", "%s" % cookies),
                        ("User-Agent", "%s" % useragent),
                    ]
                    resp = opener.open(url, data, timeout=timeout)
                else:
                    headers = {"User-Agent": useragent, "Cookie": cookies}
                    resp = requests.get(
                        url, data=data, headers=headers, timeout=timeout
                    )
                    resp.raise_for_status()
                text = unescape_html(resp)
                status_code = (
                    resp.status_code if hasattr(resp, "status_code") else resp.status
                )
                ok = bool(200 == status_code)
                headers = (
                    resp.headers if hasattr(resp, "headers") else dict(resp.info())
                )
                http_response = Response(ok=ok, text=text, headers=headers)
            except Exception as error:
                raise str(error)
        return http_response


request = HTTPRequestHandler()
