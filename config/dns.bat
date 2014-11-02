D:
chdir D:\work\project\shadow\shadowsocks
@rem start /MIN /wait C:\Python27\python dnsrelay.py -c config/dns.cfg || pause

netsh interface ipv4 set dns name="无线网络连接" source=static addr=127.0.0.1 register=PRIMARY

D:\work\cygwin64\bin\python2.7.exe dnsrelay.py

netsh interface ipv4 set dns name="无线网络连接" source=dhcp

pause
