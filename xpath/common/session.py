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
    os,
    re,
    csv,
    sqlite3,
    urlparse,
    expanduser,
    SESSION_STATEMENETS,
)


class SessionFactory:

    """Session generation class for XPath"""

    def _dict_factory(self, cursor, row):
        _temp = {}
        for idx, col in enumerate(cursor.description):
            _temp[col[0]] = row[idx]
        return _temp

    def fetchall(self, session_filepath="", query=""):
        conn = sqlite3.connect(session_filepath)
        conn.row_factory = self._dict_factory
        cursor = conn.execute(query)
        return cursor.fetchall()

    def fetch_cursor(self, session_filepath="", query=""):
        conn = sqlite3.connect(session_filepath)
        cursor = conn.cursor()
        cursor.execute(query)
        return cursor

    def fetch_count(self, session_filepath, table_name=""):
        QUERY = "SELECT COUNT(*) AS `count` FROM `{}`;".format(table_name)
        try:
            response = self.fetchall(session_filepath=session_filepath, query=QUERY)
            if response:
                response = response.pop().get("count")
        except:
            response = 0
        return response

    def generate_table(self, session_filepath="", query=""):
        conn = sqlite3.connect(session_filepath)
        conn.executescript(query)
        conn.commit()
        conn.close()

    def execute_query(self, session_filepath="", query=""):
        conn = sqlite3.connect(session_filepath)
        conn.executescript(query)
        conn.commit()
        conn.close()

    def generate_filepath(self, target):
        filepath = ""
        user = expanduser("~")
        target = urlparse.urlparse(target).netloc
        filepath = os.path.join(user, ".Xpath")
        filepath = os.path.join(filepath, target)
        try:
            os.makedirs(filepath)
        except:
            pass
        return filepath

    def dump_to_csv(self, cursor, filepath="", database="", table=""):
        ok = False
        filepath = os.path.dirname(filepath)
        dump = os.path.join(filepath, "dump")
        dbfilepath = os.path.join(dump, database)
        try:
            os.makedirs(dbfilepath)
        except:
            pass
        if os.path.exists(dbfilepath):
            filepath = os.path.join(dbfilepath, f"{table}.csv")
            with open(filepath, "w") as fd:
                csv_writer = csv.writer(fd, delimiter=",")
                csv_writer.writerow([i[0] for i in cursor.description])
                csv_writer.writerows(cursor)
                ok = True
        return ok

    def generate(self, session_filepath=""):
        if session_filepath and not os.path.isfile(session_filepath):
            conn = sqlite3.connect(session_filepath)
            conn.executescript(SESSION_STATEMENETS)
            conn.commit()
            conn.close()
        if (
            session_filepath
            and os.path.isfile(session_filepath)
            and os.stat(session_filepath).st_size == 0
        ):
            conn = sqlite3.connect(session_filepath)
            conn.executescript(SESSION_STATEMENETS)
            conn.commit()
            conn.close()
        return session_filepath

    def dump(self, session_filepath="", query="", values=None):
        try:
            conn = sqlite3.connect(session_filepath)
            cursor = conn.cursor()
            if values:
                cursor.execute(query, values)
            else:
                cursor.execute(query)
            conn.commit()
            conn.close()
        except KeyboardInterrupt:
            pass

    def drop_table(
        self,
        session_filepath,
        table_name,
        columns=None,
        query=None,
        auto_create=False,
        exec_query=False,
    ):
        DROP_QUERY = f"DROP TABLE IF EXISTS `{table_name}`;"
        is_successful = True
        try:
            self.generate_table(session_filepath=session_filepath, query=DROP_QUERY)
            if auto_create and columns and isinstance(columns, list):
                CREATE_QUERY = f"CREATE TABLE `{table_name}` ("
                CREATE_QUERY += ", ".join([f"{i} text" for i in columns])
                CREATE_QUERY += ");"
                self.generate_table(
                    session_filepath=session_filepath, query=CREATE_QUERY
                )
            if exec_query and query:
                self.generate_table(session_filepath=session_filepath, query=query)
        except:
            is_successful = False
        return is_successful

    def fetch_from_table(
        self,
        session_filepath,
        table_name,
        group_by_columns="",
        where_condition="",
        cursor=True,
    ):
        QUERY = f"SELECT * FROM `{table_name}`"
        if where_condition:
            QUERY += f" WHERE {where_condition}"
        if group_by_columns:
            QUERY += f" GROUP BY {group_by_columns}"
        QUERY += ";"
        if cursor:
            cursor = self.fetch_cursor(session_filepath=session_filepath, query=QUERY)
        if not cursor:
            cursor = self.fetchall(session_filepath=session_filepath, query=QUERY)
        return cursor

    def save(
        self,
        session_filepath,
        table_name,
        columns=None,
        records=None,
        clean_insert=False,
    ):

        steps = len(columns)
        total_records = len(records)
        chunks = [records[x : x + steps] for x in range(0, total_records, steps)]
        if clean_insert:
            self.execute_query(
                session_filepath=session_filepath, query=f"DELETE FROM `{table_name}`",
            )
        values = ", ".join(["?" for i in range(len(columns))])
        columns = ", ".join([f"`{c}`" for c in columns])
        PREPARED_STATEMENT = (
            f"INSERT OR REPLACE INTO `{table_name}` ({columns}) VALUES ({values});"
        )
        for chunk in chunks:
            is_data_fetched = bool(steps == len(chunk))
            if is_data_fetched:
                retval = session.dump(
                    session_filepath=session_filepath,
                    query=PREPARED_STATEMENT,
                    values=chunk,
                )


session = SessionFactory()
