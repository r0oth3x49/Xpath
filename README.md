## Xpath Automated SQL Injection
#### Date 
11-02-2016
#### Requirements
Python27<br />
Prettytable<br />
Request<br />
Colorama<br/>
##### How to install requierd modules.
pip install PrettyTable <br />
##### Tested
Windows 7<br />
Kali linux 2.0
#### Usage

xpath tool v1.0 - Automated Xpath Sql Injection<br />
Author: Nasir khan (r0ot h3x49) r0oth3x49@gmail.com<br />
Usage: xpath.py -u <target> [options]<br />

Options:<br />
  -h, --help           show this help message and exit

  Target:<br />
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL  Target URL (e.g. "http://www.site.com/vuln.php?id=1")

  Request:<br />
    These options can be used to specify how to connect to the target URL

    --data=DATA        Data string to be sent through POST

  Enumeration:<br />
    These options can be used to enumerate the back-end database
    managment system information, structure and data contained in the
    tables.

    -b, --banner       Retrieve DBMS banner
    --current-user     Retrieve DBMS current user
    --current-db       Retrieve DBMS current database
    --hostname         Retrieve DBMS server hostname
    --dbs              Enumerate DBMS databases
    --tables           Enumerate DBMS database tables
    --columns          Enumerate DBMS database table columns
    --dump             Dump DBMS database table entries
    -D DB              DBMS database to enumerate
    -T TBL             DBMS database tables(s) to enumerate
    -C COL             DBMS database table column(s) to enumerate
    
  Example:<br />
    xpath.py -u "http://www.test.com/index.php?id=1" --dbs<br />
    xpath.py -u "http://www.test.com/" --data "index.php?id=1" --dbs
  
###  legal disclaimer:
      Usage of xpath for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developer assume no liability and are not responsible for any misuse or damage caused by this program.
