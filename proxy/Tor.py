import os,proxy
Xtract = os.chdir("..")
from Xtract import (
    compat_color,
    compat_get,
    compat_strftime,
    compat_sleep
    )

class Tor:

    @property
    def compat_proxy_connect(self):
        Proxy = proxy.Proxy()
        Proxy.SetDefaultProxy
        r = compat_get('http://my-ip.herokuapp.com/')
        resp = r.text
        sp = resp.replace('\n','')
        default_ip = (((sp.split(':')[-1]).replace('}','')).replace('"','')).replace(' ','')
        print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: configuring tor proxy "
        Proxy.ConfigureProxy
        try:
            r = compat_get('http://my-ip.herokuapp.com/')
        except:
            print compat_color.fr + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: proxy connection error, make sure tor services are running..."
            Proxy.SetDefaultProxy
        resp = r.text
        sp = resp.replace('\n','')
        proxy_ip = (((sp.split(':')[-1]).replace('}','')).replace('"','')).replace(' ','')
        if default_ip != proxy_ip:
            print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: proxy configured successfully."
            print compat_color.fg + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: network traffic will go through : (%s)\n" % (proxy_ip)
        else:
            print compat_color.fr + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: proxy configuration is failed\n"

    @property
    def compat_proxy_newid(self):
        Proxy = proxy.Proxy()
        Proxy.SetDefaultProxy
        r = compat_get('http://my-ip.herokuapp.com/')
        resp = r.text
        sp = resp.replace('\n','')
        default_ip = (((sp.split(':')[-1]).replace('}','')).replace('"','')).replace(' ','')
        print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: configuring tor proxy..."
        compat_sleep(1)
        print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: requesting new identity..."
        compat_sleep(1)
        _resp = Proxy.NewIdentity
        compat_sleep(1)
        if '250 OK' in _resp:
            print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: request was successfull."
            Proxy.ConfigureProxy
        else:
             print compat_color.fr + compat_color.sd + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: request was unsuccessfull, make sure tor services are running .."
        r = compat_get('http://my-ip.herokuapp.com/')
        resp = r.text
        sp = resp.replace('\n','')
        proxy_ip = (((sp.split(':')[-1]).replace('}','')).replace('"','')).replace(' ','')
        if default_ip != proxy_ip:
             print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: proxy configured successfully."
             print compat_color.fg + compat_color.sn + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: network traffic will go through : (%s)\n" % (proxy_ip)
        else:
             print compat_color.fr + compat_color.sb + "["+compat_strftime("%H:%M:%S")+"] [INFO] TOR: proxy configuration is failed\n"