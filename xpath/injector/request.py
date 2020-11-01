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
    compat_urlencode,
)
from xpath.common.utils import (
    search_regex,
    unescape_html,
    prepare_request,
    parse_http_error,
    prepare_response,
    cloudflare_decode,
    parse_http_response,
    extract_encoded_data,
    detect_cloudflare_protection,
)
from xpath.logger.colored_logger import logger


class HTTPRequestHandler:
    """
    Xpath requests handler
    """

    def inject_payload(
        self, url, regex, data="", headers="", use_requests=False, timeout=30
    ):
        req = prepare_request(
            url=url, data=data, custom_headers=headers, use_requests=use_requests
        )
        raw = req.raw
        custom_headers = req.headers
        logger.traffic_out(f"HTTP request:\n{raw}")
        ok = False
        text = ""
        result = ""
        error = ""
        status_code = 0
        reason = ""
        headers = {}
        Response = collections.namedtuple(
            "Response",
            ["ok", "status_code", "text", "result", "headers", "reason", "error"],
        )
        _temp = Response(
            ok=ok,
            status_code=status_code,
            text=text,
            result=result,
            headers=headers,
            reason=reason,
            error=error,
        )
        if not data:
            try:
                if not use_requests:
                    opener = compat_opener()
                    opener.addheaders = custom_headers
                    resp = opener.open(url, timeout=timeout)
                else:
                    resp = requests.get(url, headers=custom_headers, timeout=timeout)
                    resp.raise_for_status()
            except (compat_httperr, requests.exceptions.HTTPError) as e:
                error_resp = parse_http_error(e)
                text = error_resp.text
                headers = error_resp.headers
                status_code = error_resp.status_code
                error = error_resp.error
                reason = error_resp.reason
            except compat_urlerr as e:
                logger.error(e)
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                raise e
            else:
                http_response = parse_http_response(resp)
                headers = http_response.headers
                text = http_response.text
                status_code = http_response.status_code
                reason = http_response.reason
        if data:
            try:
                if not use_requests:
                    data = data.encode("utf-8")
                    opener = compat_opener()
                    opener.addheaders = custom_headers
                    resp = opener.open(url, data, timeout=timeout)
                else:
                    resp = requests.get(
                        url, data=data, headers=custom_headers, timeout=timeout
                    )
                    resp.raise_for_status()
            except (compat_httperr, requests.exceptions.HTTPError) as e:
                error_resp = parse_http_error(e)
                text = error_resp.text
                headers = error_resp.headers
                status_code = error_resp.status_code
                error = error_resp.error
                reason = error_resp.reason
            except compat_urlerr as e:
                logger.error(e)
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                raise e
            else:
                http_response = parse_http_response(resp)
                headers = http_response.headers
                text = http_response.text
                status_code = http_response.status_code
                reason = http_response.reason
        is_protected = detect_cloudflare_protection(text)
        if is_protected:
            result = cloudflare_decode(extract_encoded_data(text))
            _temp = Response(
                ok=True if result else False,
                status_code=status_code,
                text="",  # text, we can add response html here
                result=result,
                error=error,
                reason=reason,
                headers=headers,
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
                reason=reason,
                headers=headers,
            )
        raw_response = prepare_response(_temp)
        logger.traffic_in(f"HTTP Response {raw_response}")
        return _temp

    def perform(
        self,
        url,
        data="",
        headers="",
        timeout=30,
        use_requests=False,
        connection_test=False,
    ):
        Response = collections.namedtuple(
            "Response", ["ok", "status_code", "text", "headers", "reason", "error_msg"]
        )
        ok = False
        text = None
        reason = ""
        error_msg = ""
        show_charset = False
        if connection_test:
            parsed = urlparse.urlparse(url)
            url = f"{parsed.scheme}://{parsed.netloc}"
            show_charset = True
        http_response = Response(
            ok=ok,
            text=text,
            status_code="",
            headers=headers,
            reason="",
            error_msg=error_msg,
        )
        req = prepare_request(
            url=url, data=data, custom_headers=headers, use_requests=use_requests
        )
        raw = req.raw
        custom_headers = req.headers
        logger.traffic_out(f"HTTP request:\n{raw}")
        headers = {}
        if not data:
            try:
                if not use_requests:
                    opener = compat_opener()
                    opener.addheaders = custom_headers
                    resp = opener.open(url, timeout=timeout)
                else:
                    resp = requests.get(url, headers=custom_headers, timeout=timeout)
                    resp.raise_for_status()
                http_response = parse_http_response(resp)
                ok = http_response.ok
                headers = http_response.headers
                text = http_response.text
                status_code = http_response.status_code
                reason = http_response.reason
                http_response = Response(
                    ok=ok,
                    text=text,
                    status_code=status_code,
                    headers=headers,
                    reason=reason,
                    error_msg=error_msg,
                )
            except (compat_httperr, requests.exceptions.HTTPError) as e:
                error_resp = parse_http_error(e)
                text = error_resp.text
                status_code = error_resp.status_code
                headers = error_resp.headers
                error_msg = error_resp.error
                reason = error_resp.reason
                http_response = Response(
                    ok=True,
                    text=text,
                    status_code=status_code,
                    headers=headers,
                    reason=reason,
                    error_msg=error_msg,
                )
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                raise e
        if data:
            try:
                if not use_requests:
                    data = data.encode("utf-8")
                    opener = compat_opener()
                    opener.addheaders = custom_headers
                    resp = opener.open(url, data, timeout=timeout)
                else:
                    resp = requests.get(
                        url, data=data, headers=custom_headers, timeout=timeout
                    )
                    resp.raise_for_status()
                http_response = parse_http_response(resp)
                ok = http_response.ok
                headers = http_response.headers
                text = http_response.text
                status_code = http_response.status_code
                reason = http_response.reason
                http_response = Response(
                    ok=ok,
                    text=text,
                    status_code=status_code,
                    headers=headers,
                    reason=reason,
                    error_msg=error_msg,
                )
            except (compat_httperr, requests.exceptions.HTTPError) as e:
                error_resp = parse_http_error(e)
                text = error_resp.text
                status_code = error_resp.status_code
                headers = error_resp.headers
                error_msg = error_resp.error
                reason = error_resp.reason
                http_response = Response(
                    ok=True,
                    text=text,
                    status_code=status_code,
                    headers=headers,
                    reason=reason,
                    error_msg=error_msg,
                )
            except KeyboardInterrupt as e:
                raise e
            except Exception as e:
                raise e
        raw_response = prepare_response(http_response)
        logger.traffic_in(f"HTTP Response {raw_response}")
        return http_response


request = HTTPRequestHandler()
