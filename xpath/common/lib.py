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

import re
import os
import ssl
import sys
import csv
import time
import html
import shutil
import chardet
import sqlite3
import logging
import argparse
import requests
import binascii
import collections
from os.path import expanduser
import urllib.parse as urlparse
from urllib.parse import parse_qs
import urllib.request as compat_urllib
from colorama import init, Fore, Back, Style
from urllib.error import HTTPError as compat_httperr
from urllib.error import URLError as compat_urlerr
from urllib.parse import urlparse as compat_urlparse
from urllib.parse import quote as compat_urlencode
from urllib.request import build_opener as compat_opener
from urllib.request import Request as compat_request
from urllib.request import urlopen as compat_urlopen
from urllib.request import ProxyHandler

NO_DEFAULT = object()

useragent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"


SESSION_STATEMENETS = """
DROP TABLE IF EXISTS tbl_payload;
DROP TABLE IF EXISTS tbl_databases;
CREATE TABLE tbl_payload (
 payload_id integer PRIMARY KEY AUTOINCREMENT,
 payload_type text NOT NULL,
 payload_order integer NOT NULL,
 payload_attemps integer NOT NULL,
 payload text NOT NULL,
 parameter text NOT NULL,
 regex text NOT NULL,
 type text NOT NULL,
 param text,
 dbms text
);
CREATE TABLE tbl_databases (
 dbs_id integer PRIMARY KEY AUTOINCREMENT,
 dbname text
);
"""

DB_TABLES = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{tbl_name}` (
 tbl_id integer PRIMARY KEY AUTOINCREMENT,
 tblname text
);
"""

TBL_COLUMNS = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{tbl_name}` (
 col_id integer PRIMARY KEY AUTOINCREMENT,
 colname text
);
"""

TBL_RECS = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{tbl_name}` (
 `index` integer,
 `column_name` text,
 `column_value` text
);
"""

TBL_SEARCH = """
DROP TABLE IF EXISTS `{name}`;
CREATE TABLE `{name}` (
 `index` integer,
 `value` text,
 `search_type` text
);
"""

PAYLOAD_STATEMENT = """
INSERT 
    INTO tbl_payload (`payload_type`, `payload_order`, `payload_attemps`, `payload`, `parameter`, `regex`, `type`, `param`, `dbms`)
VALUES  (?, ?, ?, ?, ?, ?, ?, ?, ?);
"""
DBS_STATEMENT = """
INSERT 
    INTO tbl_databases (`dbname`)
VALUES  ("{dbname}");
"""
TBLS_STATEMENT = """
INSERT 
    INTO `{tbl_name}` (`tblname`)
VALUES  ('{tblname}');
"""
COLS_STATEMENT = """
INSERT 
    INTO `{tbl_name}` (`colname`)
VALUES  ("{colname}");
"""

SEARCH_STATEMENT = """
INSERT 
    INTO `{name}` (`index`, `value`, `search_type`)
VALUES  (?, ?, ?);
"""

SQL_ERRORS = {
    "MySQL": (
        r"SQL syntax.*?MySQL",
        r"Warning.*?mysql_.*",
        r"Warning.*?\Wmysqli?_",
        r"MySQL Query fail.*",
        r"valid MySQL result",
        r"SQL syntax.*MariaDB server",
        r".ou\s+.*SQL\s+syntax.*",
        r".atabase\s*Query\s*Failed.*",
        r"MySqlException \(0x",
        r"valid MySQL result",
        r"check the manual that (corresponds to|fits) your (MySQL|MariaDB|Drizzle) server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc",
        r"Zend_Db_(Adapter|Statement)_Mysqli_Exception",
        r"SQLSTATE\[\d+\]: Syntax error or access violation",
        r"MemSQL does not support this type of query",
        r"is not supported by MemSQL",
        r"unsupported nested scalar subselect",
        r"MySqlException",
        r"valid MySQL result",
        r"Pdo[./_\\]Mysql",
        r"Unknown column '[^ ]+' in 'field list'",
        r"(?is)(?:A Database error Occurred)",
        
    ),
    "PostgreSQL": (
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_.*",
        r"Warning.*PostgreSQL",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s\ssyntax error at or near ",
        r"ERROR: parser: parse error at or near",
        r"PostgreSQL query failed",
        r"org\.postgresql\.jdbc",
        r"Pdo[./_\\]Pgsql",
        r"PSQLException",
    ),
    "Microsoft SQL Server": (
        r"Driver.* SQL[\-\_\ ]*Server",
        r"OLE DB.* SQL Server",
        r"(\W|\A)SQL Server.*Driver",
        r"Warning.*odbc_.*",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"Warning.*?\W(mssql|sqlsrv)_",
        r"Msg \d+, Level \d+, State \d+",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for ODBC Drivers",
        r"Warning.*(mssql|sqlsrv)_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"com\.microsoft\.sqlserver\.jdbc\.SQLServerException",
        r"\[SQL Server\]",
        r"ODBC SQL Server Driver",
        r"ODBC Driver \d+ for SQL Server",
        r"SQLServer JDBC Driver",
        r"macromedia\.jdbc\.sqlserver",
        r"com\.jnetdirect\.jsql",
        r".*icrosoft\s+VBScript\s+runtime\s+error\s+.*",
        r"Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
        r"Pdo[./_\\](Mssql|SqlSrv)",
        r"SQL(Srv|Server)Exception",
    ),
    "Microsoft Access": (
        r"Microsoft Access Driver",
        r"Access Database Engine",
        r"Microsoft JET Database Engine",
        r".*Syntax error.*query expression",
    ),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Warning.*oci_.*",
        "Microsoft OLE DB Provider for Oracle",
    ),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error"),
    "SQLite": (r"SQLite/JDBCDriver", r"System.Data.SQLite.SQLiteException"),
    "Informix": (r"Warning.*ibase_.*", r"com.informix.jdbc"),
    "Sybase": (r"Warning.*sybase.*", r"Sybase message"),
}

__ALL__ = [
    "re",
    "sys",
    "time",
    "sqlite3",
    "argparse",
    "useragent",
    "compat_urllib",
    "compat_request",
    "compat_urlopen",
    "compat_urlerr",
    "compat_httperr",
    "compat_urlencode",
    "compat_opener",
    "compat_urlparse",
    "PREFIX",
    "SUFIX",
    "PAYLOADS",
    "DB_TABLES",
    "TBL_COLUMNS",
    "PAYLOAD_STATEMENT",
    "DBS_STATEMENT",
    "TBLS_STATEMENT",
    "COLS_STATEMENT",
    "SQL_ERRORS",
]
