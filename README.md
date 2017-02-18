## Xpath Automated SQL Injection
<p>Xpath is a python open source Sql injector that automates the process of detecting and exploiting error-based injection security flaws.
At the moment, DBMS supported by Xpath is mysql.
Please note that this project is an early state. As such, you might find bugs, flaws or mulfunctions.
Use it at your own risk!.</p>
[![tortest.png](https://s24.postimg.org/71roj8cw5/tortest.png)](https://postimg.org/image/c0f6xrgox/)
### Date 
<li>18-02-2017
### Requirements
#### Python27<br /><p>
<li> requests <br />
<li> colorama</p>
### How to install requierd modules.
<p>pip install [required module] </p>
### Tested on
<p><li>Windows 7/8 <br />
<li>Kali linux 2.0
<li>Mac 10.9.5 </p> 
### Installation
<p>You can download the latest version of Xpath by cloning the GitHub repository:</p>
<pre><code>git clone https://github.com/r0oth3x49/Xpath.git</code></pre>
### Usage
<pre><code>
xpath tool v2.0 - Automated Xpath Sql Injection
Author: Nasir khan (<a href="http://r0oth3x49.herokuapp.com/">r0ot h3x49</a>)
Usage: xpath.py [options]
Options:
  -h, --help           Show basic help message and exit
  --version            Show program's version number and exit
  Target:
    At least one of these options has to be provided to define the target(s)	
    -u URL, --url=URL  Target URL (e.g. "http://www.site.com/vuln.php?id=1")
  Request:
    These options can be used to specify how to connect to the target URL
    --data=DATA        Data string to be sent through POST
    --tor              Use Tor anonymity network
    --new-id           Request for new identity to Tor anonymity network
    --timeout=TIMEOUT  Seconds to wait before timeout connection (default 30)
  Techniques:
    These options can be used to tweak testing of specific SQL injection techniques
    --technique=TECH   SQL injection techniques to use  (default 'X')
                       error-based (DOUBLE/BIGINT) Injection (--technique=D)
                       error-based   (Geometric)   Injection (--technique=G)
                       error-based     (FLOOR)     Injection (--technique=E)
  Enumeration:
    These options can be used to enumerate the back-end database
    managment system information, structure and data contained in the tables.
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
  Example:
    xpath.py -u http://www.test.com/index.php?id=1 --dbs<br />
    xpath.py -u http://www.test.com/ --data "index.php?id=1" --dbs
  </code></pre>
### Legal disclaimer
    Usage of xpath for attacking targets without prior mutual consent is illegal.
    It is the end user's responsibility to obey all applicable local,state and federal laws. 
    Developer assume no liability and is not responsible for any misuse or damage caused by this program.
