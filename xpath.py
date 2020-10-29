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
import xpath
import argparse
from xpath.logger.colored_logger import logger


def main():
    examples = "python %(prog)s http://www.site.com/vuln.php?id=1 --dbs\n\n"
    version = "Xpath {version}".format(version=f"{xpath.__version__}")
    description = "A cross-platform python based automated tool to detect and exploit error-based sql injections."
    parser = argparse.ArgumentParser(
        usage="python %(prog)s -u URL [OPTIONS]",
        description=description,
        conflict_handler="resolve",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    general = parser.add_argument_group("General")
    general.add_argument("-h", "--help", action="help", help="Shows the help.")
    general.add_argument(
        "-v", "--version", action="version", version=version, help="Shows the version."
    )

    target = parser.add_argument_group(
        "Target",
        description="At least one of these options has to be provided to define the\ntarget(s)",
    )
    target.add_argument(
        "-u",
        "--url",
        dest="url",
        type=str,
        help="Target URL (e.g. 'http://www.site.com/vuln.php?id=1).",
        required=True,
    )
    request = parser.add_argument_group(
        "Request",
        description="These options can be used to specify how to connect to the target URL",
    )
    request.add_argument(
        "--data",
        dest="data",
        type=str,
        help='Data string to be sent through POST (e.g. "id=1")',
        default=None,
    )
    request.add_argument(
        "--cookie",
        dest="cookie",
        type=str,
        help='HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")',
        default=None,
    )
    enumeration = parser.add_argument_group(
        "Enumeration",
        description=(
            "These options can be used to enumerate the back-end database"
            "\nmanagment system information, structure and data contained in the\ntables."
        ),
    )
    enumeration.add_argument(
        "-b",
        "--banner",
        dest="banner",
        action="store_true",
        help="Retrieve DBMS banner",
    )
    enumeration.add_argument(
        "--current-user",
        dest="current_user",
        action="store_true",
        help="Retrieve DBMS current user",
    )
    enumeration.add_argument(
        "--current-db",
        dest="current_db",
        action="store_true",
        help="Retrieve DBMS current database",
    )
    enumeration.add_argument(
        "--hostname",
        dest="hostname",
        action="store_true",
        help="Retrieve DBMS server hostname",
    )
    enumeration.add_argument(
        "--dbs", dest="dbs", action="store_true", help="Enumerate DBMS databases",
    )
    enumeration.add_argument(
        "--tables",
        dest="tables",
        action="store_true",
        help="Enumerate DBMS database tables",
    )
    enumeration.add_argument(
        "--columns",
        dest="columns",
        action="store_true",
        help="Enumerate DBMS database table columns",
    )
    enumeration.add_argument(
        "--dump",
        dest="dump",
        action="store_true",
        help="Dump DBMS database table entries",
    )
    enumeration.add_argument(
        "--search",
        dest="search",
        action="store_true",
        help="Search column(s), table(s) and/or database name(s)",
    )
    enumeration.add_argument(
        "-D", dest="db", type=str, help="DBMS database to enumerate", default=None,
    )
    enumeration.add_argument(
        "-T",
        dest="tbl",
        type=str,
        help="DBMS database tables(s) to enumerate",
        default=None,
    )
    enumeration.add_argument(
        "-C",
        dest="col",
        type=str,
        help="DBMS database table column(s) to enumerate",
        default=None,
    )
    examples = parser.add_argument_group("Example", description=examples)

    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        exit(0)

    resp = xpath.perform_injection(url=args.url, data=args.data, cookies=args.cookie)
    if resp.is_vulnerable:
        injected_param = resp.injected_param
        session_filepath = resp.session_filepath
        recommended_payload = resp.recommended_payload
        recommended_payload_type = resp.recommended_payload_type
        target = xpath.XPATHInjector(
            url=args.url,
            data=args.data,
            cookies=args.cookie,
            payload=recommended_payload,
            regex=recommended_payload_type,
            injected_param=injected_param,
            session_filepath=session_filepath,
        )
        if args.search:
            target.search_for(database=args.db, table=args.tbl, column=args.col)
        else:
            if not args.dbs and (
                args.hostname or args.current_user or args.current_db or args.banner
            ):
                if args.banner:
                    target.extract_banner()
                if args.current_user:
                    target.extract_current_user()
                if args.current_db:
                    target.extract_current_db()
                if args.hostname:
                    target.extract_hostname()
            if args.dbs:
                target.extract_dbs()
            if args.db and args.tables:
                target.extract_tables(database=args.db)
            if args.db and args.tbl and args.columns:
                target.extract_columns(database=args.db, table=args.tbl)
            if args.db and args.tbl and args.col:
                target.extract_records(database=args.db, table=args.tbl, columns=args.col)


if __name__ == "__main__":
    main()
