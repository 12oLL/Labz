# Introduction
Wasgooood everyone. Today ill be going through logs, showing you how to detect different anomalies such as malware, C2, Process Injection and others. We will use different techniques and to go through them, utilizing PowerShell's **Get-WinEvent** and **Sysmon** in **Event Viewer**. I will keep the process simple, starting with what to look for, filters, and analyzation results. 

# Targets
Before starting to read any log file, you need to have an objective to achieve. Going through them blindly is exhausting and pointless, eventually burning you out. Let's go through different reasons of what you might be looking for.
## Detecting Malware
There are alot of types of malware. In this case, I will analyze RATs and C2 servers. A RAT typically comes with a client-server model whereas a C2 usually connect to ports such as **80, 8080, 53** and others.

Take a look at the following XML query
``` xml
<RuleGroup name="Ports + OneDrive Filter" groupRelation="or">  
<NetworkConnect onmatch="include">  
<DestinationPort condition="is">1034</DestinationPort>  
<DestinationPort condition="is">1604</DestinationPort>  
</NetworkConnect>  
<NetworkConnect onmatch="exclude">  
<Image condition="end with">OneDrive.exe</Image>  
</NetworkConnect>  
</RuleGroup>
```
We are filtering logs to match our needs. We are looking for **DestinationPorts** that equal to **1034** and **1604**, which are uncommonly used and would be suspicious if active, as well as excluding any network connection from **OneDrive**, reducing unnecessary noise.

XML filtering allows for more detailed logs filtering. To filter using XML, open Event Viewer -> Security -> Filter Current Log -> XML -> Check the Edit query manually box -> Add your query.

To detect it using PowerShell, we will use the following:
```powershell
Get-WinEvent -Path C:\Users\Zzz\Desktop\Sessa\Practice\Hunting_Rats.evtx -FilterXPath '*/System/EventID=3 and */EventData/Data[@Name="DestinationPort"] and */EventData/Data=8080 and */EventData/Data=4444 and */EventData/Data=4443'
```
As you can see we can add multiple protocols as there isnt a single magic protocol that is always used. If there is any connection, results will look like this.
![PowerShell.png](images/PowerShell.png)

# Mimikatz
Mimikatz is commonly used to dump credentials from memory along with other Windows post exploitation activity. It is mainly known for dumping Local Security Authority Subsystem Service (LSASS).
The key for detecting Mimikatz is monitoring file creation, execution of file from an elevated process, creation of remote threads, and common processes Mimikatz created.

We will first start by looking directly for the name mimikatz. Although this is very easy for attackers to bypass by simply renaming the file, it is still good to know.
```xml
<RuleGroup name="Mimikatz File Creationz" groupRelation="or">
  <FileCreate onmatch="include">
    <TargetFilename condition="contains">mimikatz</TargetFilename>
  </FileCreate>
</RuleGroup>
```
Moving on to a more efficient way, we will filter for abnormal LSASS behavior.
```xml
<RuleGroup name="Suspicious LSASS Access" groupRelation="or">
  <ProcessAccess onmatch="include">
    <TargetImage condition="end with">lsass.exe</TargetImage>
    <GrantedAccess condition="contains">0x1fffff</GrantedAccess>
  </ProcessAccess>
</RuleGroup>
```
This filters for any successful attempts to access lsass.exe. lsass.exe is crucial as it stores user credentials, NTLM hashes, and Kerberos tickets. To monitor for just attempts of accessing lsass.exe remove the rule of **0x1fffff**.
![Mimi.png](images/Mimi.png)

We can see over here **Mimikatz.exe** is targeting **lsass.exe**. **GrantedAccess** 0x1010 means mimikatz can read memory from LSASS.

Lets use PowerShell to detect abnormal LSASS behavior:
```powershell
Get-WinEvent -Path <PATH> -FilterXPath '*/System/EventID=10 and */EventData/Data[@Name="TargetImage"] and */EventData/Data="C:\Windows\system32\lsass.exe"'
ProviderName: Microsoft-Windows-Sysmon TimeCreated Id LevelDisplayName Message ----------- -- ---------------- ------- 1/5/2021 3:22:52 AM 10 Information Process accessed:...
```
We filtered for Event ID 10 for lsass.exe which triggers when a process accesses another process's memory. This helps finding if any credential dumping activity is happening.

With PowerShell you can filter multiple Event IDs, leading you to a better detection chance. As you can see, if there is a process that was accesses, you will get the previous results.
# Persistence
Lets hunt for persistence. Persistence is used so that attackers can remain in the system after compromise. The key is looking for **File Creation & Registry Modification events**. We can use both Event Viewer or PowerShell.  In this module im using logs provided by Tryhackme, hence the THM seen everywhere. 
## Startup
Lets hunt for **Startup Persistence**. Startup persistence is where malware runs as you boot your device, making it available at all times.

**Event Viewer**:
```xml
<RuleGroup name="" groupRelation="or">  
<FileCreate onmatch="include">  
<TargetFilename name="T1023" condition="contains">\Start Menu</TargetFilename>  
<TargetFilename name="T1165" condition="contains">\Startup\</TargetFilename>  
</FileCreate>  
</RuleGroup>
```

You can also filter using Event IDs. For File Creation we filter for Event ID 11.
![11 1.png](images/11 1.png)
![zzx.png](images/zzx.png)

## Registry Key
Persistence tend to create and play with Registry. Monitoring for registry changes can help you find what you are looking for.

**Event Viewer**:
```xml
<RuleG![Reg.png](images/Reg.png)roup name="Registry Persistence Monitoring" groupRelation="or">  
<RegistryEvent onmatch="include">  
<TargetObject condition="contains">CurrentVersion\\Run</TargetObject>  
<TargetObject condition="contains">Group Policy\\Scripts</TargetObject> 
<TargetObject condition="contains">CurrentVersion\\Windows\\Run</TargetObject>  
</RegistryEvent>  
</RuleGroup>
```
Here we monitor for registry paths that are commonly abused for persistence, as they are used to autorun at startup.

![Reg 1.png](images/Reg 1.png)

We can see at the **Image** column that the registry was modified. **TargetObject** is the action that was done. As we can see, **malicious.exe** was added to the path **HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Persistence**. 
Going to Registry Editor, we can see the following:
![mal.png](images/mal.png)

# Evasion
Hackers use various methods to evade detection and bypass anti-virus and detection. In today's case, we will focus on **Alternate Data Streams (ADS)** & **Remote Threads.**
## ADS
Alternate Data Stream is a technique used by malware where it hides its files by saving it in a different stream apart from **$DATA**. As we are using Sysmon, it has Event IDs to detect newly created and accessed streams, assisting us to hunt and detect malware using **ADS**.

To filter for ADS, there are multiple ways. First would be using Event ID 15. This ID hashe and logs any NTFS Streams that are included in the Sysmon configuration file. 

```xml
<RuleGroup name="Sussy baka" groupRelation="or">

<FileCreateStreamHash onmatch="include">

<TargetFilename condition="ends with">\Zone.Identifier</TargetFilename>

<TargetFilename condition="ends with">.hta</TargetFilename>  
<TargetFilename condition="ends with">.bat</TargetFilename>  
<TargetFilename condition="ends with">.cmd</TargetFilename>  
<TargetFilename condition="ends with">.js</TargetFilename>  
<TargetFilename condition="ends with">.vbs</TargetFilename>  
<TargetFilename condition="ends with">.ps1</TargetFilename>

<TargetFilename condition="contains">\Users\</TargetFilename>  
<TargetFilename condition="contains">\Downloads\</TargetFilename>  
<TargetFilename condition="contains">\Temp\7z</TargetFilename>  
<TargetFilename condition="contains">\AppData\Local\Temp\</TargetFilename>

</FileCreateStreamHash>

</RuleGroup>
```
Ok thats alot of rules, lets break it down.
**Zone.Identifier**: Detects when a file is marked as downloaded from the internet by logging the creation of the Zone.Identifier alternate data stream.
**File extensions**: Logs for files with the mentioned extensions.
**User-writable & staging paths**: Limits detection to files in commonly abused directories such as \Downloads, \Temp, \AppData and others.

Lets take a look at the logs in Event Viewer
![155.png](images/155.png)
We can see in **Image*** PowerShell_ISE was used to hide data inside **not_malicious.exe** via ADS and named it **malware**.
## Remote Threads
Remote Threads is process injection where a process creates and runs a thread in another process's memory space. Each program runs their own processes, but with remote threads, Program A forces program B to run code that Program B didn't start itself. 

As we will be working with classic DLL Injections, we need to have an idea on how it works.

1. Locate the targeted process and create a handle to it.
2. Allocate the space for injecting the path of the DLL file.
3. Write the path of the DLL into the allocated space.
4. Execute the DLL by creating a remote thread.
![DLL.webp](images/DLL.webp)

It is a simple method but with the downsides of needing to save the malicious DLL on disk space and it is visible in the import table.

Lets monitor for Remote Thread Creation using PowerShell.
```powershell
Get-WinEvent -Path <path to log> -FilterXPath '*/System/EventID=8'
TimeCreated Id LevelDisplayName Message ----------- -- ---------------- ------- 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:...
```
The Event ID 8 in Sysmon is specifically made for Remote Thread detection. To understand what Event ID to use when monitoring is crucial. Below is a few key Event IDs.
```bash
1: Process Creation
2: Modification of file creation time
3: Network Connection (TCP/UDP)
8: CreateRemoteThread
10: Process opening another process
11: File Creation
12: Registry creation and delete.
```
For more about Sysmon and Event IDs click [here](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
Moving forward with Event Viewer:
![RT.png](images/RT.png)
**SourceImage** tells us that Powershell.exe initiated a **remote thread** within **notepad.exe**, indicating possible process injection.

Let's use PowerShell now:
```powershell
Get-WinEVent -Path <PATH> -FilterXPath '*/System/EventID=8'
ProviderName: Microsoft-Windows-Sysmon TimeCreated Id LevelDisplayName Message ----------- -- ---------------- ------- 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:... 7/3/2019 8:39:30 PM 8 Information CreateRemoteThread detected:...
```
Event ID 8 triggers when a remote thread is created by a process. A good practice is after using PowerShell for filtering, you can take note of the timestamp of the logs that complied with the rule and open Event Viewer for clearer details.
# Conclusion
This was all for today. Reading and analyzing logs using Sysmon, Event Viewer, and PowerShell is crucial as a cybersecurity professional. As we all know, practice is the most important key. Below is 2 repos to further practice your log analysis.
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [SysmonResources](https://github.com/jymcheong/SysmonResources)
