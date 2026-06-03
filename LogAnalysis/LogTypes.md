Each log is outputted differently, so it is encouraging to understand each and mastering a few will make the others easy.

**Application:** Application logs are messages from specific apps that provide information into their status, errors, warnings and other operative details. 

```log
2026-05-04 11:35:01 INFO Server started on port 8080  
2026-05-04 11:35:05 INFO User 'john_doe' logged in  
2026-05-04 11:35:10 ERROR Database connection failed: timeout  
2026-05-04 11:35:15 WARN Retry attempt 1 for database connection  
2026-05-04 11:35:18 INFO Database connection established
```

**Audit**: Events, actions, and changes that occur within the system or an application, giving a history of user activities and system behavior.

**User activity audit log**
```
2026-05-04 12:30:01 USER=john_doe ACTION=LOGIN STATUS=SUCCESS IP=192.168.1.10  
2026-05-04 12:31:15 USER=john_doe ACTION=VIEW_RECORD RECORD_ID=EMP1001 STATUS=SUCCESS  
2026-05-04 12:32:10 USER=john_doe ACTION=UPDATE_RECORD RECORD_ID=EMP1001 FIELD=salary OLD=5000 NEW=5500  
2026-05-04 12:33:05 USER=john_doe ACTION=LOGOUT STATUS=SUCCESS
```

**Security**: Security events such as logins, permission alteration, firewall activity, and other alerts that impact system security.

**IDS/SIEM**
```log
2026-05-04 12:10:12 ALERT TYPE=BRUTE_FORCE  
SRC_IP=203.0.113.45 TARGET=192.168.1.10  
ATTEMPTS=15 STATUS=BLOCKED SEVERITY=HIGH  
  
2026-05-04 12:11:03 ALERT TYPE=MALWARE_ACTIVITY  
HOST=server01 FILE=/tmp/suspicious.sh ACTION=QUARANTINED SEVERITY=CRITICAL  
  
2026-05-04 12:12:30 ALERT TYPE=PRIVILEGE_ESCALATION  
USER=user1 ACTION=DENIED SEVERITY=HIGH
```

**System**: Kernel activities, system errors, boot sequences, and hardware status, assisting in diagnosing system issues.

**General system activity**
```log
May 4 11:15:02 server01 systemd[1]: Started Daily Cleanup of Temporary Directories.  
May 4 11:15:05 server01 sshd[1024]: Accepted password for user1 from 192.168.1.20 port 53422 ssh2  
May 4 11:15:07 server01 sshd[1024]: pam_unix(sshd:session): session opened for user user1  
May 4 11:16:10 server01 sudo[1050]: user1 : TTY=pts/0 ; PWD=/home/user1 ; COMMAND=/bin/apt update
```

**System error and warning**
```log
May 4 11:21:15 server01 systemd[1]: mysql.service: Main process exited, code=exited, status=1/FAILURE  
May 4 11:21:16 server01 systemd[1]: mysql.service: Failed with result 'exit-code'.  
May 4 11:22:05 server01 CRON[1100]: (root) CMD (backup.sh)
```

**Authentication**
```log
May  4 11:25:44 server01 sshd[1201]: Failed password for invalid user admin from 203.0.113.50 port 60234 ssh2
May  4 11:25:47 server01 sshd[1201]: Failed password for invalid user admin from 203.0.113.50 port 60234 ssh2
May  4 11:25:50 server01 sshd[1201]: Connection closed by 203.0.113.50 port 60234 [preauth]
May  4 11:26:10 server01 sshd[1210]: Accepted publickey for user2 from 192.168.1.30 port 51512 ssh2
```

**Network**: Activity and communication within a network capturing information about events, connections, and data transfer.

**Basic firewall traffic log**
```firewall
2026-05-04T11:05:33Z DEVICE=Firewall01 ACTION=ALLOW  
SRC_IP=192.168.1.25 SRC_PORT=49821  
DST_IP=142.250.190.78 DST_PORT=443  
PROTOCOL=TCP BYTES_SENT=1500 BYTES_RECEIVED=3200
```

**Database**: Activities that happen in a database system, like queries performed, actions, and updates.
```sql
2026-05-04 10:15:23 INFO [connection] User 'admin' connected from 192.168.1.10  
2026-05-04 10:15:25 QUERY [select] SELECT * FROM customers WHERE id = 101;  
2026-05-04 10:15:25 INFO [execution] Query executed successfully in 12 ms
```

**Web Server**: Requested processed by web servers, Including URLs, source IP addresses, request types, status code, response code, data transferred and more.
```nginx
cat access.log
54.36.149.64 - - [25/Aug/2023:00:05:36 +0000] "GET /admin HTTP/1.1" 200 8260 "-" "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)" 191.96.106.80 - - [25/Aug/2023:00:33:11 +0000] "GET /TryHackMe/rooms/docker-rodeo/dockerregistry/catalog1.png HTTP/1.1" 200 19594 "https://tryhackme.com/" "Mozi> 54.36.148.244 - - [25/Aug/2023:00:34:46 +0000] "GET /TryHackMe/?C=D;O=D HTTP/1.1" 200 5879 "-" "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot>
66.249.66.68 - - [25/Aug/2023:00:35:53 +0000] "GET /TryHackMe%20Designs/ HTTP/1.1" 200 5973 "-" "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) 200 19594 "https://tryhackme.com/" "Mozi>
```

# Log File Locations
Below is the common log files locations.

**Web Servers**
**Nginx**
```nginx
**Access Logs**: /var/log/nginx/access.log
**Error Logs**: /var/log/nginx/error.log
```

**Apache**
``` bash
Access Logs: /var/log/apache2/access.log
Error Logs: /var/log/apache2/error.log
```

**Databases**
```sql
MySQL: /var/log/mysql/error.log
PostgreSQL: /var/log/postgresql-{version}-main.log
```

**Web Application**

```bash
**PHP**: /var/log/php/error.log
```

**Operating Systems**
**Linux & Windows**

``` bash
General Systems Logs: /var/log/syslog
Authentication: /var/log/auth.log
PowerShell: C:\Users\<username>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
Linux: history // Note: History isnt always reliable as it can be cleared via history -c

```

**Firewalls & IDS/IPS**
``` bash
**iptables**: /var/log/iptables.log
**Snort**: /var/log/snort
```
