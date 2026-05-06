As a SOC analyst, one of your main tasks is analyzing network traffic. Here is a guide and little practical examples about various types of data exfiltration and how to detect it using [Wireshark](https://www.wireshark.org/).

![](https://cdn-images-1.medium.com/max/800/1*kZ6VswTemGSRWSwPzjjEPA.png)

### What is data exfiltration?

Data exfiltration is the process of unauthorized transfer of data of sensitive information from a device, network or computer to an outside destination without permission. Data exfiltration is the last stage in the cyber kill chain, where the attacker exports the data of the victim.

### Indicators and techniques

We are going to discuss two main targets **Network-based** and **Host-based**.

**Network-based**   
For a network-based attack, you’d want to look for suspicious HTTP/HTTPS uploads to cloud and FTP or DNS tunnelling. Of course these arent the only indicators, but the most alarming and obvious.

**Host-based**  
For Host-based data exfiltration, some of the indicators are unusual file access patterns, such as large files being compressed to .rar or .7z extensions, repeated failed login attempts, and large uploads to cloud services (Google Drive, Dropbox etc).

**Genreal IoAs & triage signals**  
We discussed Host-based and Network-based data exfiltration, but there are more types such as cloud data exfiltration and covert & encoding techniques such as tunnelling and base64.  
But we are not going to delve into that, as this is focused on bringing awareness and an introduction to detection and anomalies. These are some signs to look for:   
Large outbound volume to external IPs/Domains, unknown destination domains, suspicious processes/command lines, many file read events followed by an outbound conneciton, multipart/streamed uplods.

Data exfiltration is a high-impact threat that combines opportunistic methods, legitimate tools and creative covert channels to move sensitive assets outside an organisation. Effective detection requires focus on single-alerts and more on rapid correlation across host, network and cloud telemetry. By doing that, you identify who accessed data, what was transferred, how and where it was sent.

#### DNS

DNS tunnelling is one of the most common ways adversaries exfiltrate data. It is used for transferring data from a host device to a suspicious usually long domain (30+ characters) with many requests to that domain without a response.

#### IoA

- Many DNS queries are sent to a single external domain, especially with very high counts.  
    - Long subdomain labels or unusually long full query names (>60–100 characters).  
    - High entropy or Base32/Base64-like patterns in the query name (lots of mixed up case letters, — and = are signs of Base64).

Before starting our Wireshark analysis, we need to know what to look for inside **DNS** packets. We are going to focus on two main things, **requests** and **responses**.

**DNS requests**: DNS requests (queries) are the packets sent from the client to the DNS server.

**DNS reponses**: Packets from the **server** to the **client.**

This is what normal DNS traffic should look like. The catch here is the domains length particularly. The filter `frame.len < 60` shows us queries to domains with less than 60 characters.

![](https://cdn-images-1.medium.com/max/800/1*UjB4jK16gOBmfmPRjB2xoA.png)

Now we want to look for DNS requests, we will use the filter `dns.flags.response == 0.`

![](https://cdn-images-1.medium.com/max/800/1*yj2_tf1Y4nEAG20tjZ6qzg.png)

We can see some long random-looking subdomains. After finding such, we will filter to the **domain tunnelcorp.net** using `dns.flags.response == 0 and dns.qry.name contains "tunnelcorp"`.

![](https://cdn-images-1.medium.com/max/800/1*VmjtXnfbgoZ26vRVV--bWg.png)

We can also search for subdomains that are long, because that is one of the main indicators of a C2 server. Malware usually encodes data into subdomains like Base32/Base64. To do so, we use `dns && frame.len > 70`

![](https://cdn-images-1.medium.com/max/800/1*7P8ALwlqA79TNdkxyIc3iQ.png)

This a successful search and finding of DNS tunnelling. We can see:

- Some internal hosts are compromised.
- Hosts are sending data in chunks.
- One external domain is receiving all the data.

Lastly, to spot DNS tunnelling we focus on the following:

- Large DNS requests with no response.
- Long random charactrer subdomains.
- Repeated requests to the same domain.

#### FTP

FTP is one of the oldest protocols for transferring files. Attackers use it to transfer large amount of data off a network, often via compromised credentials or misconfigured servers. The detection relies on a mix of packet inspection (FTP), server logs, SSH session metadata, and network flow/size/pattern analysis.

**IoA**  
- **USER** and **pass** commands (cleartext credentials).  
- **Stor** (upload) and **RETR** (download) commands; repeated or large transfers.  
- Large data connections to unusual external IPs, especially outside business hours.  
- Data channel opening on ephemeral ports (PASV) paired with large payloads.

#### **Isolating FTP control & data**

First, lets filter to find FTP only, using the Wireshark filter `**_ftp || ftp-data`_**

![](https://cdn-images-1.medium.com/max/800/1*xyLc_XBTNEk7VyL9IuG6MQ.png)

This will only give us FTP control traffic

#### Looking for credentials

To filter to only login attempts you type `**_ftp.request.command == “USER” || ftp.request.command == “PASS”`._**

![](https://cdn-images-1.medium.com/max/800/1*InRhzeIMxC08BlN803E7FQ.png)

This will give us login attempts showing USER and PASS

#### Searching anomalies

When data is being exfiltrated via FTP, the data is harvested and stored in extensions such as .txt , .pdf or csv. To look for anomalies, we type `**_ftp contains “STOR”_**`. STOR is a command indicating an upload, and **RETR** is download.

![](https://cdn-images-1.medium.com/max/800/1*AQ2eVnCCMmXY-FVrFy81_w.png)

To get a better view of the TCP stream, right-click on the packet → Follow → TCP Stream. This will give you the following clearer view.

![](https://cdn-images-1.medium.com/max/800/1*ffyrFdEL0gy6vp0VY-AOEg.png)

![](https://cdn-images-1.medium.com/max/800/1*MfOUDPhiSThm9u41OAErTw.png)

To search for a specific extension you can use the command `**_ftp contains “csv”_**`. You will receive packets where data is being stored in a comma-separated values file (csv).

![](https://cdn-images-1.medium.com/max/800/1*shrIndpQiZOT0Oz-XtOmHw.png)

#### Payloads

A big indicator of a FTP attack is a large payload size. To search and identify such payloads, we use the capture filter `**_ftp && frame.len > 90_**`.

![](https://cdn-images-1.medium.com/max/800/1*HiOV5T42ISeLQW2B4V12EA.png)

When it comes to payloads, a size of < 200 bytes isn’t suspicious, but in this case the context matters. In this case, we can see a login attempt through a default username guest and a weak password guest as well.  
After the successful login attempt, STOR command is being used to send data to a .csv file. The data being sent is THM{ftp_exfil_hidden flag}, which is a CTF from a THM lab in this case, but this is the demonstration of how data exfiltration through FTP would look like in real-world scenarios.

### HTTP

Data exfiltration vita HTTP is when an attacker moves sensitive data out of a target network using HTTP as transport. HTTP is a commonly abused protocol because it blends with normal web traffic, can traverse firewalls and proxies, and can be obfuscated (encoding, encryption, tunnelling). To detect a HTTP attack as SOC analysts, we aim to identify signs of HTTP-based exfiltration in packet captures using **Wireshark** and logs using **Splunk**.

Identifying and responding to HTTP attacks is important due to the following reasons:  
- HTTP attacks are very common. Attackers hide exfiltration in the noise of legitimate web usage.  
- Successful detection stop data breaches and help trace attacker activity post-compromise.  
- Organizations must detect and respond to protect sensitive data and meet compliance requirements.

#### How is HTTP used for data exfiltration?

To detect HTTP attacks, we need to look for and understand the following request methods. The following are methods attackers use and indicators to look for.

**POST Uploads**: A common request method to send data to a server. A suspicious POST request is a large amount of data being sent to a attacker-controlled host or cloud storage.  
**GET Requests**: GET requests with encoded data is a common technique adversaries use. Data being squeezed into query strings or path segments for low-and-slow exfiltration.   
**Use of common services**: Exfiltration masked as uploads to popular services or attacker-controller subdomains under reputable domains.  
**Chunked transfer/multipart**: Large payloads split into multiple requests to avoid size thresholds.  
**HTTPS/TLS tunnelling**: The encrypted channel hides the payload. Detection requirest TLS inspection, SNI analysis, or metadata-based detection  
**Staging via cloud services**: Uploading to trusted cloud services like Dropbox/Github/Gist and then fetch externally.

Lastly, it is important to take note that not all attacks are sudden and will be spiked on a network traffic. Most of the time it could be a low-and-slow approach, where adversaries take their time encrypting/encoding, and use legitimate services to evade detection. This is why connecting the dots and gathering context is the key approach during analysis.

#### IoA

**Common network indicators**:  
- Unusually large HTTP POST requests to external and unexpected hosts.  
- HTTP requests to domains with low reputation or uncommon in daily traffic.  
- Frequent small requests (beaconing) to the same host followed by a large upload.  
- Chunked or multipart transfers where requests compose large files.

#### Wireshark HTTP analysis

We can use Wireshark to analyze ad look for HTTP attacks. We start by filtering to only HTTP traffic using the **http** filter. After that, we go ahead and filter out an HTTP method like POST `http.request.method == "POST” && frame.len > 300`.

![](https://cdn-images-1.medium.com/max/800/1*xm7ZjInX-JdWjBLDkR6Rug.png)

As we can see in HTTP Stream, a POST upload to github.com with the   
Lets break the filter down:  
**http.request.method**: Filtering specific methods such as POST,GET or HEAD.  
**frame.len**: Filters out a specific frame length, a large frame length could be an indicator to an attack.  
Tip: Check out the TCP/HTTP stream of the packet for cleartext details.

### ICMP

ICMP is a network layer protocol used for diagnostics and controls like **ping**. Because it is commonly allowed through firewalls and typically inspected less strictly than TCP/UDP, ICMP can be abused to tunnel and exfiltrate data. Malicious actors encode data into ICMP payloads (echo request/reply, timestamp,info) and send it to a remote listener under their control.

#### How ICMP is used for exfiltration

**ICMP echo (type 8) / reply (type 0) tunnelling**: Attackers place encoded **base64** or **hex** chunks of files inside **ICMP** payloads.   
**Custom ICMP types/code**: Using uncommon ICMP types or non-zero codes to avoid signature-based detections.  
**Fragmentation & reassembly**: Large payloads split across multiple packets  
**Encryption/obfuscation**: Encrypting payloads e.g using base64 to look like random data.

#### Indication of maliciousness

- Persistent ICMP sessions to an external host not used for legitimate monitoring.  
- Unusually large ICMP payloads or frequent ICMP with payload larger than a typical ping size.  
- ICMP payloads that contain high-entropy data or patterns consistent with base64/hex.  
- Bursts of ICMP immediately followed by no other legitimate application traffic from the same host.

#### Wireshark analysis

Again, Wireshark can be used for analyzing ICMP packets. It is important to know where to look and what to identify while analyzing.

#### IoA

**ICMP packet volumes**: A single host sending large amount of ICMP echo requests to an external IP.  
**Large frame.len or icmp.payload**: Pings with payloads much larger than the typical (e.g > 64 bytes).  
**ICMP type/code unusual values**: Unusual use of timestamp (13/14) or custom codes.  
**Periodicity**: even timing of ICMP packets carrying similiar-sized paylods.

Using the capture command `icmp.type == 8 && frame.len > 100`, we receive malicious packets, as a usual ICMP ping is ~74 bytes, whic makes anything above a 100 bytes suspicious.

![](https://cdn-images-1.medium.com/max/800/1*RfYROMDugGlQVV4aePBDXA.png)

As we can see, this packet has 148 bytes, which is way over the usual ICMP bytes. The text is in hex but it is truncated in cleartext on the right side.

### Conclusion

Data exfiltration through DNS,FTP, and HTTP and other protocols usually does not have one big red flag to look for that indicates an IoA/IoC, but rather analyzing multiple factors and connecting the dots, which is a common approach in network traffic analysis. Knowing where and what to look for is the important part, allowing you to find the malicious actor and respond accordingly.
