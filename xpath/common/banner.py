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

from xpath import __version__
from xpath.common.colors import colorize
from xpath.common.colors import BRIGHT, yellow


VERSION = colorize(string=f"{__version__}", color="yellow", bold=True)
START_BRACES = colorize(string="{", color="white", normal=True)
END_BRACES = f'{colorize(string="}", color="white", normal=True)}'
END_BRACES = f"{END_BRACES}{BRIGHT}{yellow}"
VERSION_STRING = f"{START_BRACES}{VERSION}{END_BRACES}"
GITHUB_URL = colorize(
    string="https://github.com/r0oth3x49/Xpath", color="white", normal=True
)
LEGAL_DISCLAIMER = "[!] Legal disclaimer: Usage of xpath for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developer assume no liability and is not responsible for any misuse or damage caused by this program."
LEGAL_DISCLAIMER = colorize(string=LEGAL_DISCLAIMER, color="white", normal=True)
I1 = colorize(string="'", color="yellow", normal=True, background="red")
I1 = f"{I1}{BRIGHT}{yellow}"
I2 = colorize(string='"', color="yellow", normal=True, background="red")
I2 = f"{I2}{BRIGHT}{yellow}"
I3 = colorize(string=")", color="yellow", normal=True, background="red")
I3 = f"{I3}{BRIGHT}{yellow}"

XPATH_BANNER = """
 _    _        ___ 
\  \/  /___   __H__ _    %s
 \    /| . |___[%s]_| |_
 /    \|  _| .'[%s]_|   |
/_ /\ _|_| |__,[%s] |_|_| 
                v..      %s

%s
""" % (
    VERSION_STRING,
    I1,
    I2,
    I3,
    GITHUB_URL,
    LEGAL_DISCLAIMER,
)

BANNER = colorize(string=XPATH_BANNER, color="yellow", bold=True)
print(BANNER)
