#!/usr/bin/python
#######################################################
#   xpath tool v2.0 - Automated Xpath Sql Injection   #
#       Author: Nasir khan (r0ot h3x49)               #
#######################################################

import sys
user_agent_win = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/30.0.1599.17 Safari/537.36"
user_agent_unix = "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20150101 Firefox/47.0 (Chrome)"
user_agent_default = "Xpath/2.0#stable Nasir Khan (http://r0oth3x49.herokuapp.com)"
Drop   = "DROP TABLE IF EXISTS %s;"
Create = "CREATE TABLE %s (SessionId INTEGER PRIMARY KEY, %s);"
Insert = "INSERT INTO %s (%s) VALUES(%s);"
Show   = "SELECT * FROM %s;"
Alter  = "ALTER TABLE %s ADD %s;"
Prev   = "SELECT %s FROM %s;"
Update = "UPDATE %s SET %s=%s WHERE SessionId=1;"
DumpShow = "SELECT %s from %s;"



if sys.version_info[:2] >= (3, 0): # For Python 3.x.x
    import urllib.request as compat_urllib
    from   urllib.request import Request as compat_request
    from   urllib.request import urlopen as compat_urlopen
    from   urllib.error import HTTPError as compat_httperr
    from   urllib.error import URLError as compat_urlerr
    from   urllib.parse import urlparse as compat_urlparse
    from   urllib.request import build_opener as compat_opener
    from beauti import PrettyTable as compat_prettytable
    from beauti import from_db_cursor as compat_cursor
    from beauti import Color as compat_color
    from time import time as compat_timer
    from time import strftime as compat_strftime
    from time import sleep as compat_sleep
    from requests import get as compat_get
    from requests import post as compat_post 
    from itertools import product as compat_product
    from sqlite3 import connect as compat_connect
    from os.path import expanduser as compat_user
    from os.path import exists as compat_exist
    from _Session import Session as compat_session
    import optparse as compat_option
    from csv import writer as compat_writer
    from httplib import HTTPException as compat_timeout
    uni, pyver = str, 3
    
else:     # For Python 2.7.x
    import urllib2 as compat_urllib
    from urllib2 import Request as compat_request
    from urllib2 import urlopen as compat_urlopen
    from urllib2 import URLError as compat_urlerr
    from urllib2 import HTTPError as compat_httperr
    from urlparse import urlparse as compat_urlparse
    from urllib2 import build_opener as compat_opener
    from beauti import PrettyTable as compat_prettytable
    from beauti import from_db_cursor as compat_cursor
    from beauti import Color as compat_color
    from time import time as compat_timer
    from time import strftime as compat_strftime
    from time import sleep as compat_sleep
    from requests import get as compat_get
    from requests import post as compat_post
    from itertools import product as compat_product
    from sqlite3 import connect as compat_connect
    from os.path import expanduser as compat_user
    from _Session import Session as compat_session
    from os.path import exists as compat_exist
    from csv import writer as compat_writer
    import optparse as compat_option  
    from httplib import HTTPException as compat_timeout
    uni, pyver = unicode, 2


__ALL__ = [ 'Drop',
			'Create',
			'Insert',
			'Show',
            'Alter',
            'Prev',
            'Update',
			'compat_urllib',
			'compat_request',
			'compat_urlerr',
			'compat_urlopen',
			'compat_httperr',
			'compat_urlparse',
			'compat_opener',
			'compat_prettytable',
			'compat_timer',
			'compat_strftime',
			'compat_sleep',
			'compat_get',
			'compat_post',
			'user_agent_win',
			'user_agent_unix',
			'compat_color',
			'compat_product',
			'user_agent_default',
			'compat_connect',
			'compat_user',
			'compat_exist',
			'compat_session',
            'compat_option'
            'compat_cursor',
            'compat_writer',
            'compat_timeout',]