---
tags:
  - forensic
  - windows
  - prefetch
  - file-system
date: 2024-06-20
---
## Prefetch: The Little Snitch That Tells on You

Incident Response and forensic analysts use the contents of prefetch files in investigations to gather information, such as the source from which an executable was launched, how many times it was executed, what files it touched, and the date and time it was launched. A prefetch file is like the little brother that tells the parents who broke the lamp.

Prefetching is a Windows memory management process in which the operating system pre-loads resources from disk into memory as a means of speeding up the loading time for applications. As part of its process, a .pf file is created in the C:\Windows\Prefetch directory and updated each subsequent time the application is executed. The .pf file contains a list of resources, including files and directories that the executable referenced during execution, which is used to pre-load those resources the next time the application is executed.

![[Pasted image 20240620150529.png]]

Figure 1- Example Prefetch Directory Listing

The .pf file naming convention is `<executable name>` in all caps, followed by a hyphen and a series of eight (8) letters and numbers (which is the hash value of the path where the executable is located on the filesystem), and lastly, a .pf extension. The astute observer will note from the previous figure that some of the executables have more than one (1) entry. There are two (2) reasons for this. The first is that certain executables such as svchost.exe and rundll32.exe can execute multiple times, spawning separate sub-processes. The operating system notes this and creates separate entries denoted by a different hash, which is the hash of the executable path and the command line used to start the application.

The second reason for the presence of an additional entry is that an application with the same name is executed from a different location. Attackers will sometimes use the names of common applications to hide their activities. This may get by some security systems; however, by reviewing the entries within the .pf file, the true path to the location of the executable is disclosed.

Another item to note is that there are two (2) instances when prefetch files may not be available on the system: when the Windows system is a server, or when the operating system drives are solid state drives (SSDs). This is because the Prefetch process doesn’t offer the same benefits in finding and loading files from disk. The following registry key is used to determine whether the Prefetch process is configured.

**_HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\Prefetech Parameters_**

Name: EnablePrefetcher

Type: REG_DWORD

Values:

            0 – Disabled

            1 – Application launch prefetching enabled

            2 – Boot prefetching enabled

            3 – Application launch and boot prefetching enabled

## How Investigators Use Prefetch File Contents

The prefetch file, while not intended for analysis, can provide a wealth of information for an investigator. When opened, a prefetch file can show:

- Creation date – timestamped with the local time of the machine
- Date/time of last execution time – timestamped with the local time of the machine
- Run count – the number of times the executable has been launched
- Other run times – limited to the previous eight (8) executions
- Directories and files referenced – includes other executables
- Volumes and file paths – the location from which files were accessed

![[Pasted image 20240620150604.png]]

Figure 2 - Example Prefetch Tool PECmd Output

Note the Prefetch process is not a tracer or monitor program for applications; the data contained within each .pf file is only a snapshot of the executable and the files with which it interacts for the purpose of speeding up loading. As such, the Prefetch process snapshot is created ten (10) seconds after application execution to capture library and file references for subsequent loads. When reviewed, these records can be helpful to investigators in identifying potentially malicious directory paths, binaries, and data files with which an executable might be coded to interact.

In the figure below, a threat actor was attempting to use 7-Zip to compress files before exfiltration. The figure helps to illustrate that the application is interacting with data files named **FILE01, FILE02,** etc. from the **TEMP** directory within the first (10) seconds of execution. This information could be used to determine what kind of data might have been exfiltrated and where the files were on the file system for potential recovery.

![[Pasted image 20240620150805.png]]

Figure 3 - Example of File Interaction Captured Within 10 Second Snapshot

Another area where prefetch analysis can be helpful is in malware analysis. As already noted, the prefetch file contains information about the files and directories with which an executable interacts. This can not only identify files that might be downloaded but can also identify other malicious activities, such as accessing files located in unusual locations. This can be particularly helpful when tracing down the file(s) responsible for the malicious activity. Take, for instance, a search order hijacking attack, in which the attacker places a malicious .DLL file in a location where it is loaded before the legitimate file (more details on the attack here: [https://malwareandstuff.com/the-dll-search-order-and-hijacking-it/](https://malwareandstuff.com/the-dll-search-order-and-hijacking-it/)).

To demonstrate how prefetch file analysis can uncover this type of attack, let’s look at the following example. The Steam application uses the **WSOCK32.DLL**, finding it on the test machine under C:\Windows\SYSWOW64\, using the systems search order to find it.

![[Pasted image 20240620150834.png]]

Figure 4 - Steam Using WSOCK32.DLL from SYSWOW64

Noting this, the attacker knows that the default search order will look in the directory where the application is launched first. The attacker places their version of the DLL higher in the search order path, to be executed before the real DLL. The figure below shows the malicious DLL being executed from the application directory, which is searched before the system directories, thus compromising the system.

![[Pasted image 20240620150914.png]]

Figure 5 - Steam Using Malicious WSOCK32.DLL Using Search Order

Prefetch analysis is one (1) of the few ways that security analysts can gain understanding of application interactions in the absence of more robust EDR tools that map out process flows.

## Prefetch Analysis Tools

There are several tools available for reviewing the contents of prefetch files, including Eric Zimmerman’s PECmd command line tool and NirSoft’s WinPrefetchView.

PECmd is used for opening and reviewing the contents of .pf files. It supports several functions, including processing a single file or a directory of prefetch files. It can also output the .pf file information in a number of formats, including JSON, CSV, and HTML, as well as standard out. Zimmerman’s tool can be downloaded from GitHub at [https://github.com/EricZimmerman/PECmd](https://github.com/EricZimmerman/PECmd).

Like PECmd, WinPrefetchView can open and review the individual contents of a .pf or pull in an entire prefetch directory.

![[Pasted image 20240620151000.png]]

Figure 6 - WinPrefetchView from NirSoft

WinPrefetchView allows for the quick location and review of specific .pf files. However, it is limited in its report export functions allowing only HTML output. WinPrefetchView can be downloaded at [https://www.nirsoft.net/utils/win_prefetch_view.html](https://www.nirsoft.net/utils/win_prefetch_view.html).

In closing, prefetch files are little snitches spilling their contents, providing information that may not otherwise be available in an investigation. Additionally, information derived from files can provide critical information that management, legal, and cyber insurance might need, such as what files were accessed, when they were accessed, and what kind of information might be in those files, laying the groundwork for communications, disclosure, and exposure. Lastly, analysts can use the information derived from prefetch data to corroborate and validate other forensic artifact data, further solidifying the timeline of events.

## References
+ [TrustedSec: The Little Snitch That Tells On You](https://trustedsec.com/blog/prefetch-the-little-snitch-that-tells-on-you)
+ [Velociraptor Artifact Reference: Windows.Forensics.Prefetch](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/)