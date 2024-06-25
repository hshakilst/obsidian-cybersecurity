---
tags:
  - htb
  - machine
  - windows
date: 2024-06-23
---
## Recon
**10.129.144.220**
### Nmap IPv4
```text
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-06-23 05:58:37Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: AXLLE
|   NetBIOS_Domain_Name: AXLLE
|   NetBIOS_Computer_Name: MAINFRAME
|   DNS_Domain_Name: axlle.htb
|   DNS_Computer_Name: MAINFRAME.axlle.htb
|   DNS_Tree_Name: axlle.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2024-06-23T05:59:34+00:00
|_ssl-date: 2024-06-23T06:00:14+00:00; +5s from scanner time.
| ssl-cert: Subject: commonName=MAINFRAME.axlle.htb
| Issuer: commonName=MAINFRAME.axlle.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-19T11:25:03
| Not valid after:  2024-11-18T11:25:03
| MD5:   acc1:ec10:1311:0c34:c548:bd34:8cce:53f9
| SHA-1: 9d6c:ac58:e52c:a711:9ffa:795f:171b:555c:cf0e:7fc9
| -----BEGIN CERTIFICATE-----
| MIIC6jCCAdKgAwIBAgIQVVwvBVAJjJ9KU24nlGQGOjANBgkqhkiG9w0BAQsFADAe
| MRwwGgYDVQQDExNNQUlORlJBTUUuYXhsbGUuaHRiMB4XDTI0MDUxOTExMjUwM1oX
| DTI0MTExODExMjUwM1owHjEcMBoGA1UEAxMTTUFJTkZSQU1FLmF4bGxlLmh0YjCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2LCqLiWgbUAoZDZqpnkO4I
| ydQrIBAT5BX0+R+OnEibrVE2pSqV0nfp4hAv1672OFsWB3iM8aDYDAmER5g+LRoz
| LkwyaeChgvzafcywL7RFAuW+1fCgbygdQTjvmEJwwwb6ZSbzZGAVMyXzEoKZBYsb
| 9jpgDdv9ukaQFFWSSVWMynwXDOVK/EYEDdD1NtLAdziNqe73n1nR+AibPz4ZW7Em
| pCz0g3Ir+Ql1MOY09sWoZ0TvzA/5LTSDd0ivH+VlfFQT12cNbdIZKSCwtOmjiuka
| T7URoEx4kMNVKKmj9M4CBTp4fUwECdwDYr/XHZE6MiZBd6T24AAYL16M2OQotyEC
| AwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqG
| SIb3DQEBCwUAA4IBAQDJHGe0pLywnHy+zofiDksI30sdsz7fNdstVz7IxZ07Cu1g
| 2mbiULCg/HYIWFMx1dJ5g/kwhiP7zswp/5VrJVTsCcSbxaVrIsu9apYN3LjGBxHh
| E4TTnljPtZSJSINyAdLMkeYT1N8502ZkaP8Ofeliwb6/IoDiPdmMyiWIJl23es4F
| kM705n8BiWJ3hpFHSpTUYNfiMbGmkneig9V9K1SQkf+ERezuQR1OPrX/JuAtpvcg
| ll8a4lhwT+mpf8LvcLl1NPoMgtrG+c7bb1tHgBLDrIvZ6fQAS/A4s5QKjbkn/Ew7
| iATUIyWSRw8YVEflYv8Qr7qynrY2aKhUB1UP1Znx
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
51081/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
51082/tcp open  msrpc         syn-ack Microsoft Windows RPC
52157/tcp open  msrpc         syn-ack Microsoft Windows RPC
54082/tcp open  msrpc         syn-ack Microsoft Windows RPC
54097/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: MAINFRAME; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42574/tcp): CLEAN (Timeout)
|   Check 2 (port 20385/tcp): CLEAN (Timeout)
|   Check 3 (port 58889/udp): CLEAN (Timeout)
|   Check 4 (port 63781/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 4s, deviation: 0s, median: 4s
| smb2-time: 
|   date: 2024-06-23T05:59:35
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

### RPC Enumeration
```text
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Retrieving endpoint list from 10.129.144.220
Protocol: [MS-NRPC]: Netlogon Remote Protocol 
Provider: netlogon.dll 
UUID    : 12345678-1234-ABCD-EF00-01234567CFFB v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[54082]
          ncalrpc:[NETLOGON_LRPC]
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: [MS-RAA]: Remote Authorization API Protocol 
Provider: N/A 
UUID    : 0B1C2170-5732-4E0E-8CD3-D9B16F3B84D7 v0.0 RemoteAccessCheck
Bindings: 
          ncalrpc:[NETLOGON_LRPC]
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]
          ncalrpc:[NETLOGON_LRPC]
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: N/A 
Provider: N/A 
UUID    : 51A227AE-825B-41F2-B4A9-1AC9557A1018 v1.0 Ngc Pop Key Service
Bindings: 
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: N/A 
Provider: N/A 
UUID    : 8FB74744-B2FF-4C00-BE0D-9EF9A191FE1B v1.0 Ngc Pop Key Service
Bindings: 
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: N/A 
Provider: N/A 
UUID    : B25A52BF-E5DD-4F4A-AEA6-8CA7272A0E86 v2.0 KeyIso
Bindings: 
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: [MS-LSAT]: Local Security Authority (Translation Methods) Remote 
Provider: lsasrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AB v0.0 
Bindings: 
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: [MS-DRSR]: Directory Replication Service (DRS) Remote Protocol 
Provider: ntdsai.dll 
UUID    : E3514235-4B06-11D1-AB04-00C04FC2DCD2 v4.0 MS NT Directory DRS Interface
Bindings: 
          ncacn_np:\\MAINFRAME[\pipe\f4a3a7a5b1ae2d19]
          ncacn_http:10.129.144.220[51081]
          ncalrpc:[NTDS_LPC]
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: N/A 
Provider: sysntfy.dll 
UUID    : C9AC6DB5-82B7-4E55-AE8A-E464ED7B4277 v1.0 Impl friendly name
Bindings: 
          ncalrpc:[OLE7ABB8B597DAA444D2128B324F83A]
          ncacn_ip_tcp:10.129.144.220[49668]
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]
          ncalrpc:[LRPC-64ed19d0370bff7606]
          ncalrpc:[IUserProfile2]
          ncalrpc:[LRPC-f64a2cdf882114c4aa]
          ncalrpc:[senssvc]
          ncalrpc:[LRPC-3b44295f94eb88cf3e]
          ncalrpc:[LRPC-bab3ef6fc081680a4b]

Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol 
Provider: samsrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[49664]
          ncalrpc:[MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b]
          ncalrpc:[samss lpc]
          ncalrpc:[SidKey Local End Point]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSA_EAS_ENDPOINT]
          ncalrpc:[lsacap]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncacn_np:\\MAINFRAME[\pipe\lsass]

Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[49665]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\MAINFRAME[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc0C6810]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0 
Bindings: 
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\MAINFRAME[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc0C6810]
          ncalrpc:[WMsgKRpc0C7431]

Protocol: N/A 
Provider: N/A 
UUID    : FC48CD89-98D6-4628-9839-86F7A3E4161A v1.0 
Bindings: 
          ncalrpc:[dabrpc]
          ncalrpc:[csebpub]
          ncalrpc:[LRPC-f83faa4de8c114e8bd]
          ncalrpc:[LRPC-4b94c31ccaa29d63b0]
          ncalrpc:[LRPC-4f18be48960c640a08]
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : D09BDEB5-6171-4A34-BFE2-06FA82652568 v1.0 
Bindings: 
          ncalrpc:[csebpub]
          ncalrpc:[LRPC-f83faa4de8c114e8bd]
          ncalrpc:[LRPC-4b94c31ccaa29d63b0]
          ncalrpc:[LRPC-4f18be48960c640a08]
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-4b94c31ccaa29d63b0]
          ncalrpc:[LRPC-4f18be48960c640a08]
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-4f18be48960c640a08]
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]
          ncalrpc:[LRPC-dd716893d1450ae909]
          ncalrpc:[LRPC-0c14d077b50956aa91]

Protocol: N/A 
Provider: N/A 
UUID    : 697DCDA9-3BA9-4EB2-9247-E11F1901B0D2 v1.0 
Bindings: 
          ncalrpc:[LRPC-f83faa4de8c114e8bd]
          ncalrpc:[LRPC-4b94c31ccaa29d63b0]
          ncalrpc:[LRPC-4f18be48960c640a08]
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 9B008953-F195-4BF9-BDE0-4471971E58ED v1.0 
Bindings: 
          ncalrpc:[LRPC-4b94c31ccaa29d63b0]
          ncalrpc:[LRPC-4f18be48960c640a08]
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 0D47017B-B33B-46AD-9E18-FE96456C5078 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 95406F0B-B239-4318-91BB-CEA3A46FF0DC v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 4ED8ABCC-F1E2-438B-981F-BB0E8ABC010C v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 0FF1F646-13BB-400A-AB50-9A78F2B7A85A v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 6982A06E-5FE2-46B1-B39C-A2C545BFA069 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 082A3471-31B6-422A-B931-A54401960C62 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : FAE436B0-B864-4A87-9EDA-298547CD82F2 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : E53D94CA-7464-4839-B044-09A2FB8B3AE5 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 178D84BE-9291-4994-82C6-3F909ACA5A03 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 4DACE966-A243-4450-AE3F-9B7BCB5315B8 v2.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 1832BCF6-CAB8-41D4-85D2-C9410764F75A v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : C521FACF-09A9-42C5-B155-72388595CBF0 v0.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 2C7FD9CE-E706-4B40-B412-953107EF9BB0 v0.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 88ABCBC3-34EA-76AE-8215-767520655A23 v0.0 
Bindings: 
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 76C217BC-C8B4-4201-A745-373AD9032B1A v1.0 
Bindings: 
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 55E6B932-1979-45D6-90C5-7F6270724112 v1.0 
Bindings: 
          ncalrpc:[LRPC-71be4316e04b5537c9]
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 857FB1BE-084F-4FB5-B59C-4B2C4BE5F0CF v1.0 
Bindings: 
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 20C40295-8DBA-48E6-AEBF-3E78EF3BB144 v2.0 
Bindings: 
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 2513BCBE-6CD4-4348-855E-7EFB3C336DD3 v2.0 
Bindings: 
          ncalrpc:[OLE79EACC398D45562AF679FC3C1547]
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 0D3E2735-CEA0-4ECC-A9E2-41A2D81AED4E v1.0 
Bindings: 
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : C605F9FB-F0A3-4E2A-A073-73560F8D9E3E v1.0 
Bindings: 
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 1B37CA91-76B1-4F5E-A3C7-2ABFC61F2BB0 v1.0 
Bindings: 
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 8BFC3BE1-6DEF-4E2D-AF74-7C47CD0ADE4A v1.0 
Bindings: 
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 2D98A740-581D-41B9-AA0D-A88B9D5CE938 v1.0 
Bindings: 
          ncalrpc:[LRPC-dbffa87ba3c8e1f49f]
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : DD59071B-3215-4C59-8481-972EDADC0F6A v1.0 
Bindings: 
          ncalrpc:[actkernel]
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 0361AE94-0316-4C6C-8AD8-C594375800E2 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 5824833B-3C1A-4AD2-BDFD-C31D19E23ED2 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : BDAA0970-413B-4A3E-9E5D-F6DC9D7E0760 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 3B338D89-6CFA-44B8-847E-531531BC9992 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 8782D3B9-EBBD-4644-A3D8-E8725381919B v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 085B0334-E454-4D91-9B8C-4134F9E793F3 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : 4BEC6BB8-B5C2-4B6F-B2C1-5DA5CF92D0D9 v1.0 
Bindings: 
          ncalrpc:[umpo]

Protocol: N/A 
Provider: N/A 
UUID    : E40F7B57-7A25-4CD3-A135-7F7D3DF9D16B v1.0 
Bindings: 
          ncalrpc:[LRPC-1e48708adcc43c280f]

Protocol: N/A 
Provider: N/A 
UUID    : 880FD55E-43B9-11E0-B1A8-CF4EDFD72085 v1.0 KAPI Service endpoint
Bindings: 
          ncalrpc:[LRPC-6c59641c5784f92740]
          ncalrpc:[OLE59D000C052B5EFBA22D79E4F18CB]
          ncalrpc:[LRPC-dd716893d1450ae909]

Protocol: N/A 
Provider: N/A 
UUID    : 5222821F-D5E2-4885-84F1-5F6185A0EC41 v1.0 
Bindings: 
          ncalrpc:[LRPC-b0e1543d75290d5efb]

Protocol: N/A 
Provider: nsisvc.dll 
UUID    : 7EA70BCF-48AF-4F6A-8968-6A440754D5FA v1.0 NSI server endpoint
Bindings: 
          ncalrpc:[LRPC-1746db90a12195516e]

Protocol: N/A 
Provider: N/A 
UUID    : A500D4C6-0DD1-4543-BC0C-D5F93486EAF8 v1.0 
Bindings: 
          ncalrpc:[LRPC-c2c53dbcd8de41f17f]
          ncalrpc:[LRPC-0c14d077b50956aa91]

Protocol: N/A 
Provider: dhcpcsvc6.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 v1.0 DHCPv6 Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc6]
          ncalrpc:[dhcpcsvc]

Protocol: N/A 
Provider: dhcpcsvc.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 v1.0 DHCP Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc]

Protocol: N/A 
Provider: nrpsrv.dll 
UUID    : 30ADC50C-5CBC-46CE-9A0E-91914789E23C v1.0 NRP server endpoint
Bindings: 
          ncalrpc:[LRPC-cd6d1932c565846320]
          ncalrpc:[DNSResolver]

Protocol: [MS-EVEN6]: EventLog Remoting Protocol 
Provider: wevtsvc.dll 
UUID    : F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0 Event log TCPIP
Bindings: 
          ncacn_ip_tcp:10.129.144.220[49666]
          ncacn_np:\\MAINFRAME[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: gpsvc.dll 
UUID    : 2EB08E3E-639F-4FBA-97B1-14F878961076 v1.0 Group Policy RPC Interface
Bindings: 
          ncalrpc:[LRPC-1bd87b8be29f4e6095]

Protocol: N/A 
Provider: N/A 
UUID    : 3A9EF155-691D-4449-8D05-09AD57031823 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[49667]
          ncalrpc:[LRPC-e3e110011d32cd7036]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\MAINFRAME[\PIPE\atsvc]
          ncalrpc:[LRPC-46033bd38f9cd00a85]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: schedsvc.dll 
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[49667]
          ncalrpc:[LRPC-e3e110011d32cd7036]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\MAINFRAME[\PIPE\atsvc]
          ncalrpc:[LRPC-46033bd38f9cd00a85]

Protocol: N/A 
Provider: N/A 
UUID    : 33D84484-3626-47EE-8C6F-E7E98B113BE1 v2.0 
Bindings: 
          ncalrpc:[LRPC-e3e110011d32cd7036]
          ncalrpc:[ubpmtaskhostchannel]
          ncacn_np:\\MAINFRAME[\PIPE\atsvc]
          ncalrpc:[LRPC-46033bd38f9cd00a85]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 378E52B0-C0A9-11CF-822D-00AA0051E40F v1.0 
Bindings: 
          ncacn_np:\\MAINFRAME[\PIPE\atsvc]
          ncalrpc:[LRPC-46033bd38f9cd00a85]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 1FF70682-0A51-30E8-076D-740BE8CEE98B v1.0 
Bindings: 
          ncacn_np:\\MAINFRAME[\PIPE\atsvc]
          ncalrpc:[LRPC-46033bd38f9cd00a85]

Protocol: N/A 
Provider: schedsvc.dll 
UUID    : 0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53 v1.0 
Bindings: 
          ncalrpc:[LRPC-46033bd38f9cd00a85]

Protocol: N/A 
Provider: N/A 
UUID    : 7F1343FE-50A9-4927-A778-0C5859517BAC v1.0 DfsDs service
Bindings: 
          ncacn_np:\\MAINFRAME[\PIPE\wkssvc]
          ncalrpc:[LRPC-1516ba3cf352c7da32]

Protocol: N/A 
Provider: N/A 
UUID    : EB081A0D-10EE-478A-A1DD-50995283E7A8 v3.0 Witness Client Test Interface
Bindings: 
          ncalrpc:[LRPC-1516ba3cf352c7da32]

Protocol: N/A 
Provider: N/A 
UUID    : F2C9B409-C1C9-4100-8639-D8AB1486694A v1.0 Witness Client Upcall Server
Bindings: 
          ncalrpc:[LRPC-1516ba3cf352c7da32]

Protocol: N/A 
Provider: N/A 
UUID    : 3473DD4D-2E88-4006-9CBA-22570909DD10 v5.1 WinHttp Auto-Proxy Service
Bindings: 
          ncalrpc:[194bc03a-534e-453f-98b5-3affe0b23e59]
          ncalrpc:[LRPC-a12c0614ba52c47140]

Protocol: N/A 
Provider: N/A 
UUID    : 3F787932-3452-4363-8651-6EA97BB373BB v1.0 NSP Rpc Interface
Bindings: 
          ncalrpc:[LRPC-111cd563b8201d80df]
          ncalrpc:[OLECDDB45E747A531D3A65D7EE8D878]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 2FB92682-6599-42DC-AE13-BD2CA89BD11C v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-a8566c59785ea2f8ed]
          ncalrpc:[LRPC-3a6796b75f3adf886a]
          ncalrpc:[LRPC-f4cd2fc61d573ef770]
          ncalrpc:[LRPC-272e0dd046a3af4693]

Protocol: N/A 
Provider: N/A 
UUID    : F47433C3-3E9D-4157-AAD4-83AA1F5C2D4C v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-3a6796b75f3adf886a]
          ncalrpc:[LRPC-f4cd2fc61d573ef770]
          ncalrpc:[LRPC-272e0dd046a3af4693]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 7F9D11BF-7FB9-436B-A812-B2D50C5D4C03 v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-f4cd2fc61d573ef770]
          ncalrpc:[LRPC-272e0dd046a3af4693]

Protocol: N/A 
Provider: BFE.DLL 
UUID    : DD490425-5325-4565-B774-7E27D6C09C24 v1.0 Base Firewall Engine API
Bindings: 
          ncalrpc:[LRPC-272e0dd046a3af4693]

Protocol: N/A 
Provider: N/A 
UUID    : 13560FA9-8C09-4B56-A1FD-04D083B9B2A1 v1.0 
Bindings: 
          ncalrpc:[LRPC-d057a9c87f899e65c2]
          ncalrpc:[OLE6DFE63A7F38AE8D5C8A6FB857D9A]

Protocol: N/A 
Provider: N/A 
UUID    : C2D1B5DD-FA81-4460-9DD6-E7658B85454B v1.0 
Bindings: 
          ncalrpc:[LRPC-d057a9c87f899e65c2]
          ncalrpc:[OLE6DFE63A7F38AE8D5C8A6FB857D9A]

Protocol: N/A 
Provider: N/A 
UUID    : F44E62AF-DAB1-44C2-8013-049A9DE417D6 v1.0 
Bindings: 
          ncalrpc:[LRPC-d057a9c87f899e65c2]
          ncalrpc:[OLE6DFE63A7F38AE8D5C8A6FB857D9A]

Protocol: N/A 
Provider: N/A 
UUID    : B37F900A-EAE4-4304-A2AB-12BB668C0188 v1.0 
Bindings: 
          ncalrpc:[LRPC-d057a9c87f899e65c2]
          ncalrpc:[OLE6DFE63A7F38AE8D5C8A6FB857D9A]

Protocol: N/A 
Provider: N/A 
UUID    : ABFB6CA3-0C5E-4734-9285-0AEE72FE8D1C v1.0 
Bindings: 
          ncalrpc:[LRPC-d057a9c87f899e65c2]
          ncalrpc:[OLE6DFE63A7F38AE8D5C8A6FB857D9A]

Protocol: N/A 
Provider: N/A 
UUID    : C49A5A70-8A7F-4E70-BA16-1E8F1F193EF1 v1.0 Adh APIs
Bindings: 
          ncalrpc:[OLE81221C4F0198D04DF892122EB6D3]
          ncalrpc:[TeredoControl]
          ncalrpc:[TeredoDiagnostics]
          ncalrpc:[LRPC-a6fb5f071019578253]

Protocol: N/A 
Provider: N/A 
UUID    : C36BE077-E14B-4FE9-8ABC-E856EF4F048B v1.0 Proxy Manager client server endpoint
Bindings: 
          ncalrpc:[TeredoControl]
          ncalrpc:[TeredoDiagnostics]
          ncalrpc:[LRPC-a6fb5f071019578253]

Protocol: N/A 
Provider: N/A 
UUID    : 2E6035B2-E8F1-41A7-A044-656B439C4C34 v1.0 Proxy Manager provider server endpoint
Bindings: 
          ncalrpc:[TeredoControl]
          ncalrpc:[TeredoDiagnostics]
          ncalrpc:[LRPC-a6fb5f071019578253]

Protocol: N/A 
Provider: iphlpsvc.dll 
UUID    : 552D076A-CB29-4E44-8B6A-D15E59E2C0AF v1.0 IP Transition Configuration endpoint
Bindings: 
          ncalrpc:[LRPC-a6fb5f071019578253]

Protocol: N/A 
Provider: N/A 
UUID    : 29770A8F-829B-4158-90A2-78CD488501F7 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[49670]
          ncacn_np:\\MAINFRAME[\pipe\SessEnvPublicRpc]
          ncalrpc:[SessEnvPrivateRpc]
          ncalrpc:[LRPC-bab3ef6fc081680a4b]

Protocol: N/A 
Provider: certprop.dll 
UUID    : 30B044A5-A225-43F0-B3A4-E060DF91F9C1 v1.0 
Bindings: 
          ncalrpc:[LRPC-e11e67225483439fd3]

Protocol: N/A 
Provider: N/A 
UUID    : 0D3C7F20-1C8D-4654-A1B3-51563B298BDA v1.0 UserMgrCli
Bindings: 
          ncalrpc:[LRPC-cbbb3344f7d731fceb]
          ncalrpc:[OLE6F6FB2EBA05C9B6741F030D65D4D]

Protocol: N/A 
Provider: N/A 
UUID    : B18FBAB6-56F8-4702-84E0-41053293A869 v1.0 UserMgrCli
Bindings: 
          ncalrpc:[LRPC-cbbb3344f7d731fceb]
          ncalrpc:[OLE6F6FB2EBA05C9B6741F030D65D4D]

Protocol: N/A 
Provider: N/A 
UUID    : 1A0D010F-1C33-432C-B0F5-8CF4E8053099 v1.0 IdSegSrv service
Bindings: 
          ncalrpc:[LRPC-211ab2791093067acc]

Protocol: N/A 
Provider: srvsvc.dll 
UUID    : 98716D03-89AC-44C7-BB8C-285824E51C4A v1.0 XactSrv service
Bindings: 
          ncalrpc:[LRPC-211ab2791093067acc]

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Provider: spoolsv.exe 
UUID    : 76F03F96-CDFD-44FC-A22C-64950A001209 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[51082]
          ncalrpc:[LRPC-578a657b215a683b66]

Protocol: N/A 
Provider: spoolsv.exe 
UUID    : 4A452661-8290-4B36-8FBE-7F4093A94978 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[51082]
          ncalrpc:[LRPC-578a657b215a683b66]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : AE33069B-A2A8-46EE-A235-DDFD339BE281 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[51082]
          ncalrpc:[LRPC-578a657b215a683b66]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[51082]
          ncalrpc:[LRPC-578a657b215a683b66]

Protocol: [MS-RPRN]: Print System Remote Protocol 
Provider: spoolsv.exe 
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[51082]
          ncalrpc:[LRPC-578a657b215a683b66]

Protocol: N/A 
Provider: sysmain.dll 
UUID    : B58AA02E-2884-4E97-8176-4EE06D794184 v1.0 
Bindings: 
          ncalrpc:[LRPC-dff9fcb3cd5b48caf2]

Protocol: N/A 
Provider: N/A 
UUID    : 1D45E083-478F-437C-9618-3594CED8C235 v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : 98CD761E-E77D-41C8-A3C0-0FB756D90EC2 v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : D22895EF-AFF4-42C5-A5B2-B14466D34AB4 v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : E38F5360-8572-473E-B696-1B46873BEEAB v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : 95095EC8-32EA-4EB0-A3E2-041F97B36168 v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : FD8BE72B-A9CD-4B2C-A9CA-4DED242FBE4D v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : 4C9DBF19-D39E-4BB9-90EE-8F7179B20283 v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : D4051BDE-9CDD-4910-B393-4AA85EC3C482 v1.0 
Bindings: 
          ncalrpc:[LRPC-747b87d7b9f10bc24e]
          ncalrpc:[OLEEBC95C3F6F2C80FF6BAB1D34B99C]

Protocol: N/A 
Provider: N/A 
UUID    : 7DF1CEAE-DE4E-4E6F-AB14-49636E7C2052 v1.0 
Bindings: 
          ncalrpc:[LRPC-07e8359f47d09e3e88]

Protocol: [MS-CMPO]: MSDTC Connection Manager: 
Provider: msdtcprx.dll 
UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0 
Bindings: 
          ncalrpc:[LRPC-2af373588d633a87ff]
          ncalrpc:[OLE541675A162AF2C50622F1984F722]
          ncalrpc:[LRPC-d4d38577a52121a6dc]
          ncalrpc:[LRPC-d4d38577a52121a6dc]
          ncalrpc:[LRPC-d4d38577a52121a6dc]

Protocol: N/A 
Provider: N/A 
UUID    : 509BC7AE-77BE-4EE8-B07C-0D096BB44345 v1.0 
Bindings: 
          ncalrpc:[LRPC-dad1b8e8249be5d569]
          ncalrpc:[OLEDA389D471F1C9A7E5E38FECD92A5]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol 
Provider: services.exe 
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[54087]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 12E65DD8-887F-41EF-91BF-8D816C42C2E7 v1.0 Secure Desktop LRPC interface
Bindings: 
          ncalrpc:[WMsgKRpc0C7431]

Protocol: N/A 
Provider: N/A 
UUID    : 2F5F6521-CB55-1059-B446-00DF0BCE31DB v1.0 Unimodem LRPC Endpoint
Bindings: 
          ncalrpc:[unimdmsvc]
          ncalrpc:[tapsrvlpc]
          ncacn_np:\\MAINFRAME[\pipe\tapsrv]

Protocol: N/A 
Provider: N/A 
UUID    : 650A7E26-EAB8-5533-CE43-9C1DFCE11511 v1.0 Vpn APIs
Bindings: 
          ncalrpc:[LRPC-cb6411e0b33a18fbca]
          ncalrpc:[VpnikeRpc]
          ncalrpc:[RasmanLrpc]
          ncacn_np:\\MAINFRAME[\PIPE\ROUTER]

Protocol: [MS-DNSP]: Domain Name Service (DNS) Server Management 
Provider: dns.exe 
UUID    : 50ABC2A4-574D-40B3-9D66-EE4FD5FBA076 v5.0 
Bindings: 
          ncacn_ip_tcp:10.129.144.220[54097]

Protocol: N/A 
Provider: N/A 
UUID    : D249BD56-4CC0-4FD3-8CE6-6FE050D590CB v0.0 
Bindings: 
          ncalrpc:[LRPC-767982f9c4968aa410]

Protocol: N/A 
Provider: N/A 
UUID    : D8140E00-5C46-4AE6-80AC-2F9A76DF224C v0.0 
Bindings: 
          ncalrpc:[LRPC-767982f9c4968aa410]

Protocol: N/A 
Provider: N/A 
UUID    : B1EF227E-DFA5-421E-82BB-67A6A129C496 v0.0 
Bindings: 
          ncalrpc:[LRPC-d54abb629f9596302e]
          ncalrpc:[OLE12161719CD3CA8F60199304B46F0]

Protocol: N/A 
Provider: N/A 
UUID    : 0FC77B1A-95D8-4A2E-A0C0-CFF54237462B v0.0 
Bindings: 
          ncalrpc:[LRPC-d54abb629f9596302e]
          ncalrpc:[OLE12161719CD3CA8F60199304B46F0]

Protocol: N/A 
Provider: N/A 
UUID    : 8EC21E98-B5CE-4916-A3D6-449FA428A007 v0.0 
Bindings: 
          ncalrpc:[LRPC-d54abb629f9596302e]
          ncalrpc:[OLE12161719CD3CA8F60199304B46F0]

Protocol: N/A 
Provider: pcasvc.dll 
UUID    : 0767A036-0D22-48AA-BA69-B619480F38CB v1.0 PcaSvc
Bindings: 
          ncalrpc:[LRPC-0f00874552396cdb28]

Protocol: [MS-FRS2]: Distributed File System Replication Protocol 
Provider: dfsrmig.exe 
UUID    : 897E2E5F-93F3-4376-9C9C-FD2277495C27 v1.0 Frs2 Service
Bindings: 
          ncacn_ip_tcp:10.129.144.220[52157]
          ncalrpc:[OLE7537D88108E47B29F2056B1D60B3]

Protocol: N/A 
Provider: N/A 
UUID    : A4B8D482-80CE-40D6-934D-B22A01A44FE7 v1.0 LicenseManager
Bindings: 
          ncalrpc:[LicenseServiceEndpoint]

Protocol: N/A 
Provider: N/A 
UUID    : BF4DC912-E52F-4904-8EBE-9317C1BDD497 v1.0 
Bindings: 
          ncalrpc:[LRPC-14e7d91779b8c7a852]
          ncalrpc:[OLEC70518A241B6F8B3C10F47294947]

Protocol: N/A 
Provider: N/A 
UUID    : F3F09FFD-FBCF-4291-944D-70AD6E0E73BB v1.0 
Bindings: 
          ncalrpc:[LRPC-614f1f8e0fa97e6da4]

[*] Received 449 endpoints.
```

### Nmap IPv6 - dead:beef::2b7a:9a27:863c:370
```text
25/tcp   open  smtp          syn-ack hMailServer smtpd
| smtp-commands: MAINFRAME, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp   open  domain        syn-ack Simple DNS Plus
80/tcp   open  http          syn-ack Microsoft IIS httpd 10.0
|_http-title: Axlle Development
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-favicon: Unknown favicon MD5: FAF2C069F86E802FD21BF15DC8EDD2DC
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2024-06-24 04:19:48Z)
135/tcp  open  msrpc         syn-ack Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack
464/tcp  open  kpasswd5?     syn-ack
593/tcp  open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack
3268/tcp open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: axlle.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack
3389/tcp open  ms-wbt-server syn-ack Microsoft Terminal Services
| ssl-cert: Subject: commonName=MAINFRAME.axlle.htb
| Issuer: commonName=MAINFRAME.axlle.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-05-19T11:25:03
| Not valid after:  2024-11-18T11:25:03
| MD5:   acc1:ec10:1311:0c34:c548:bd34:8cce:53f9
| SHA-1: 9d6c:ac58:e52c:a711:9ffa:795f:171b:555c:cf0e:7fc9
| -----BEGIN CERTIFICATE-----
| MIIC6jCCAdKgAwIBAgIQVVwvBVAJjJ9KU24nlGQGOjANBgkqhkiG9w0BAQsFADAe
| MRwwGgYDVQQDExNNQUlORlJBTUUuYXhsbGUuaHRiMB4XDTI0MDUxOTExMjUwM1oX
| DTI0MTExODExMjUwM1owHjEcMBoGA1UEAxMTTUFJTkZSQU1FLmF4bGxlLmh0YjCC
| ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM2LCqLiWgbUAoZDZqpnkO4I
| ydQrIBAT5BX0+R+OnEibrVE2pSqV0nfp4hAv1672OFsWB3iM8aDYDAmER5g+LRoz
| LkwyaeChgvzafcywL7RFAuW+1fCgbygdQTjvmEJwwwb6ZSbzZGAVMyXzEoKZBYsb
| 9jpgDdv9ukaQFFWSSVWMynwXDOVK/EYEDdD1NtLAdziNqe73n1nR+AibPz4ZW7Em
| pCz0g3Ir+Ql1MOY09sWoZ0TvzA/5LTSDd0ivH+VlfFQT12cNbdIZKSCwtOmjiuka
| T7URoEx4kMNVKKmj9M4CBTp4fUwECdwDYr/XHZE6MiZBd6T24AAYL16M2OQotyEC
| AwEAAaMkMCIwEwYDVR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqG
| SIb3DQEBCwUAA4IBAQDJHGe0pLywnHy+zofiDksI30sdsz7fNdstVz7IxZ07Cu1g
| 2mbiULCg/HYIWFMx1dJ5g/kwhiP7zswp/5VrJVTsCcSbxaVrIsu9apYN3LjGBxHh
| E4TTnljPtZSJSINyAdLMkeYT1N8502ZkaP8Ofeliwb6/IoDiPdmMyiWIJl23es4F
| kM705n8BiWJ3hpFHSpTUYNfiMbGmkneig9V9K1SQkf+ERezuQR1OPrX/JuAtpvcg
| ll8a4lhwT+mpf8LvcLl1NPoMgtrG+c7bb1tHgBLDrIvZ6fQAS/A4s5QKjbkn/Ew7
| iATUIyWSRw8YVEflYv8Qr7qynrY2aKhUB1UP1Znx
|_-----END CERTIFICATE-----
|_ssl-date: 2024-06-24T04:20:55+00:00; 0s from scanner time.
Service Info: Host: MAINFRAME; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 39433/tcp): CLEAN (Timeout)
|   Check 2 (port 22704/tcp): CLEAN (Timeout)
|   Check 3 (port 33850/udp): CLEAN (Timeout)
|   Check 4 (port 37271/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-06-24T04:20:17
|_  start_date: N/A
```

### HTTP Enumeration - axlle.htb
```text
Our website is currently down for maintenance.

We apologise for the inconvenience and appreciate your patience as we work to improve our online presence.

If you have any outstanding invoices or requests, please email them to accounts@axlle.htb in Excel format. Please note that all macros are disabled due to our security posture.

We will be back as soon as possible. Thank you for your understanding.
```

- [ ] Found the attack vector that should be some sort of email.
- [ ] Rich text format payload.
- [ ] Condition ?