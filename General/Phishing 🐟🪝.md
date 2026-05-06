Phishing is the most common attack to gaining unauthorized access. It targets individuals and organizations instead of the security directly, which makes it succeed due to missing factors. Today we are discussing 5 common types of phishing attacks, with examples and prevention tips.

![](https://cdn-images-1.medium.com/max/800/1*pngpf7-PTA7J-VZCmmKwEQ.png)

### Email Phishing

Email phishing is a common social engineering tactic, targeting companies and individuals by separate or combined techniques such as **Typosquatting**, **Spoofing, Spear phishing, whaling** and many others. The goals is to compromise the victim by sending an embedded code in a file that runs as **C2 server** or pretending to be an employee in a company asking a senior to download a file that compromises the system.

![](https://cdn-images-1.medium.com/max/800/1*toCmtHMn9J_18sgsfhFNnQ.png)

An example of email spoofing: **Apple Support** [dontreply-App1e@support.com](mailto:dontreply-veryrealemail@kmd.com)

The sender is trying to impersonate Apple, but the address does not match or usually gibberish.

### Spear Phishing

Spear phishing is a social engineering technique that is used to gather information about a company or a person before the phishing attempt. Information can be gathered through OSINT (Open Source Intelligence).

![](https://cdn-images-1.medium.com/max/800/1*ODkqgFnSlnwza-OEb8hTMg.png)

What specializes spear phishing is that its a more accurate approach rather than a random phone call the victim might get, easily indicating its a scam attempt.

Lets say you work in a library and you are waiting to receive the list of books wanted by the library for you to get for them. The owner send you a word document named **Books_Order March**, you open the file the document and accept any requests shown by **Word**, but then the sender wasn’t the actual person you were expecting, but someone who researched you knowing where you work and what you are expecting and the

Lets say you work in a library and you are waiting to receive the list of books wanted by the library for you to get for them. The owner send you a word document named **Books_Order March**, you open the file the document and accept any requests shown by **Word**, but then the sender wasn’t the actual person you were expecting, but someone who researched you knowing where you work and what you are expecting and the document you got was infected using Word OLE feature (Object linking and embedding) which could have spyware, infostealer, ransomware, or whatsoever the attacker desired.

### Whaling

Whaling is an approach that targets high positions in organizations, giving the attacker administrator levels of access instead of a low level access through employers. This approach can also be executed using the previous strategies in **Spear Phishing**, where the attacker gathers information about the desired target of the company through OSINT. LinkedIn is a great field where information like emails, numbers, locations and interests regarding companies and individuals can be found.

![](https://cdn-images-1.medium.com/max/800/1*WRfsgGjnOkMIfnKTgwCnDQ.png)

### Smishing & Vishing

Smishing (SMS Phishing) and Vishing (Voice Call Phishing) are methods heavily used by attackers recently and especially integrated with AI. SMS Phishing is when the victim receives a message on their personal phone number, just like an email but without the need of internet access, making the victim reachable at anytime. This can be dangerous by impersonating social media apps like WhatsApp, ISP, Shopee and other services the user is familiar with. Messages might include links where users are requested to download or login their credentials, where their information sit on the attacker’s server allowing them to sell that information or access it.

![](https://cdn-images-1.medium.com/max/800/1*Ails51qOJF-Xi_tAu4esBg.png)

**Voice Call Phishing** is an old approach where targets receive calls from different country code numbers, impersonators, and friends or colleagues. By combining AI, attackers recently upgraded this approach, where they get phone numbers that are leaked through data breaches or used in old lists where attempts were successful or the victim pick up the calls. After gathering a list of numbers, they would call without speaking, recording the voice of the victim for the duration of the call and using it for other attacks such as **Spear Phishing** or **Whaling.**

For example, you call a CEO of a company and when they pick up you just record their voice while speaking to them. After that, you can use their voice to use it to gain access by speaking to an employee to wire a transfer or gain access. This has been successful alot recently and is scarily accurate.

### Angler Phishing

Angler phishing is a one of the most common phishing methods. It is the impersonation of legitimate customer service accounts on social media platforms or companies such as PayPal, Amazon, and Microsoft. This approach is used by attackers to send emails or call customers informing them about purchases, credentials update, and promotions.

Emails can have spoofed domain and SMS messages can have urgency and links embedded. The targets of this attack can be random, but when combined with **Spear Phishing** and **OSINT**, attackers can find dissatisfied customers or desperate individuals and lure them into their trap.

Lets say you receive a call from your telecom company. They inform you that your number is going to be disabled and ask you for your information such as passport and perhaps other credentials to their app or even an amount of money. By complying, you lose so much without realizing and especially if you grant them access to perhaps to your account on a supposed application or your banking details.

![](https://cdn-images-1.medium.com/max/800/1*UUIV0jpU5asgjPg55SWBuA.png)

### Mitigation

Although the risks of these attacks are high and very it is common that you might face some of them, there is ways to avoid them. As you might have seen, there is common factors that are available in all of these attacks. The most important factor for handling phishing attacks is **security awareness**. Attacks happens to everyone and no one is immune to them, but the difference is how you perceive it.

Lacking security awareness is the most critical factor, because if it is missing, despite having the tools and technology to to scan and analyse a phishing attempt, it passes and goes through due to the individual’s lack of awareness. Following awareness comes **staying updated** to the latest attacks and how they are developing, because the attack types don’t change, they only get enhanced. This isn’t just important for those in the security field, but for everyday casual users on the internet.

### Tools

Here are some recommended tools for phishing analysis. Each tool can be used depending on the need. For example CyberChef can be used to decode Base64 content (or any other encoding), VirusTotal can check a file hash using antivirus engines like Kaspersky or McAfee to see if it matches anything malicious and so on.

**Decoding & Threat Intelligence:** [VirusTotal](https://www.virustotal.com/gui/), [URL extractor](https://www.convertcsv.com/url-extractor.htm), [CyberChef](https://gchq.github.io/CyberChef/), [Talos](https://talosintelligence.com/talos_file_reputation).

**Malware Sandboxes**

To analyze malware, it is recommended to do so in a protected environment to prevent getting the main machine infected. Below are common great tools for containing malware.

[Hybrid Analysis](https://www.notion.so/Malware-Analysis-30112883632d80a784dad234ef59a83e?pvs=21)

**Interactive Malware Analysis**: [https://app.any.run/](https://app.any.run/), [https://www.joesecurity.org/](https://www.joesecurity.org/)

[PhishTool](https://www.phishtool.com/)

### Conclusion

With the coming years, attacks will keep increasing and will get more sophisticated as time comes. It is important to understand the basics as an attack can occur to anyone, even experts aware and capable of responding. Stay updated, use third party apps or websites to scan links, files, or IPs. Being proactive will prevent harsh losses when you suffer an attack, it is in your hands to prepare now.
