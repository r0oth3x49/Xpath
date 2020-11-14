[![GitHub release](https://img.shields.io/badge/release-v3.0-brightgreen?style=flat-square)](https://github.com/r0oth3x49/Xpath/releases/tag/v3.0)
[![GitHub stars](https://img.shields.io/github/stars/r0oth3x49/Xpath.svg?style=flat-square)](https://github.com/r0oth3x49/Xpath/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/r0oth3x49/Xpath.svg?style=flat-square)](https://github.com/r0oth3x49/Xpath/network)
[![GitHub issues](https://img.shields.io/github/issues/r0oth3x49/Xpath.svg?style=flat-square)](https://github.com/r0oth3x49/Xpath/issues)
[![GitHub license](https://img.shields.io/github/license/r0oth3x49/Xpath.svg?style=flat-square)](https://github.com/r0oth3x49/Xpath/blob/master/LICENSE)

# Xpath
**A python based cross-platform tool that automates the process of detecting and exploiting error-based injection security flaws.**

[![Xpath3-0.png](https://i.postimg.cc/x1YTx1bc/Xpath3-0.png)](https://postimg.cc/F7W41mp4)


## ***Requirements***

- Python 3
- Python `pip3`
- Python module `requests`
- Python module `colorama`
- Python module `chardet`

## ***Module Installation***

    pip install -r requirements.txt

## ***Tested on***

- Windows 7/8/8.1/10
- Ubuntu-LTS (tested with super user)

## ***Download Xpath***

You can download the latest version of udemy-dl by cloning the GitHub repository.

    git clone https://github.com/r0oth3x49/Xpath.git

## ***Fatures***
 - Supports error based MySQL/PostgreSQL injections.
 - Supports all types (HEADERS/COOKIE//POST/GET) for the listed dbms.
 - Added switch to support proxy option `--proxy`.
 - Added swicth to force SSL connection `--force-ssl`.
 - Ability to search for db/table/column `--search`.


## **Advanced Usage**

<pre><code>
Author: Nasir khan (<a href="http://r0oth3x49.herokuapp.com/">r0ot h3x49</a>)

usage: python xpath.py -u URL [OPTIONS]

A cross-platform python based automated tool to detect and exploit error-based sql injections.

General:
  -h, --help          Shows the help.
  --version           Shows the version.
  -v VERBOSE          Verbosity level: 1-5 (default 1).
  --batch             Never ask for user input, use the default behavior
  --flush-session     Flush session files for current target

Target:
  At least one of these options has to be provided to define the
  target(s)

  -u URL, --url URL   Target URL (e.g. 'http://www.site.com/vuln.php?id=1).

Request:
  These options can be used to specify how to connect to the target URL

  -A , --user-agent   HTTP User-Agent header value
  -H , --header       Extra header (e.g. "X-Forwarded-For: 127.0.0.1")
  --host              HTTP Host header value
  --data              Data string to be sent through POST (e.g. "id=1")
  --cookie            HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
  --referer           HTTP Referer header value
  --headers           Extra headers (e.g. "Accept-Language: fr\nETag: 123")

Detection:
  These options can be used to customize the detection phase

  --level             Level of tests to perform (1-3, default 1)

Techniques:
  These options can be used to tweak testing of specific SQL injection
  techniques

  --technique TECH    SQL injection techniques to use (default "XEFDBGJ")

Enumeration:
  These options can be used to enumerate the back-end database
  managment system information, structure and data contained in the
  tables.

  -b, --banner        Retrieve DBMS banner
  --current-user      Retrieve DBMS current user
  --current-db        Retrieve DBMS current database
  --hostname          Retrieve DBMS server hostname
  --dbs               Enumerate DBMS databases
  --tables            Enumerate DBMS database tables
  --columns           Enumerate DBMS database table columns
  --dump              Dump DBMS database table entries
  --search            Search column(s), table(s) and/or database name(s)
  -D DB               DBMS database to enumerate
  -T TBL              DBMS database tables(s) to enumerate
  -C COL              DBMS database table column(s) to enumerate

Example:
  python xpath.py http://www.site.com/vuln.php?id=1 --dbs
</code></pre>


## **Legal disclaimer**

    Usage of xpath for attacking targets without prior mutual consent is illegal.
    It is the end user's responsibility to obey all applicable local,state and federal laws. 
    Developer assume no liability and is not responsible for any misuse or damage caused by this program.


## **TODO**
 - Add support for all other DBMS injection
 - Add support to multitarget injection from file.
 - Add support for union based/booelan/time based SQL injections.