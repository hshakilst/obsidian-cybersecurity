---
tags:
  - forensic
  - windows
  - usnjournal
  - file-system
date: 2024-06-20
---
**What is Usn Journal?**
The USN Journal (Update Sequence Number Journal) is the journaling functionality of NTFS. USN Journal maintains change logs made to the files on the NTFS and ReFS volumes. USN journal contains file or folder creation, deletion, and modification details. NTFS appends new records to the end of the USN Journal stream and it can be retrieved in the event of system crash or restore.

Since Windows 7, Windows maintains (by default) a journal of filesystem changes to a volume in a special NTFS metafile at $Extend\$UsnJrnl. This file has 2 alternate data streams (ADS) – $Max which contains data such as the maximum size and $J which contains the data about the changes.

The main usage of this file is by backup applications, to determine which files have been changed since the last backup operation.

In this blog post, we explain the usage of UsnJrnl in DFIR, walk through the process of efficient extraction for forensic purposes and provide the community with our own tool.

**Why do we need it?**

The USN records contain valuable information:

- Timestamp – The timestamp of the file change
- Filename – The name of the file that changed.
- Attribute – Mainly used to determine between file and directory
- Reason — The action which occurred, examples are:
    - CLOSE
    - DATA_EXTEND
    - DATA_OVERWRITE
    - DATA_TRUNCATION
    - FILE_CREATE
    - FILE_DELETE
    - RENAME_NEW_NAME
    - SECURITY_CHANGE

**Forensics usage**
During DFIR operation, this data can be useful to us in many ways:

- Sometimes attackers are familiar with different forensics methodologies and they can try to sabotage evidence, for example, by deleting the prefetch files. In this case, the record in the usnjrnl can be indicative and reveal the change times.
- This file can be used to detect files that were dropped to the disk, which is useful when building the timeline of occurrences.
- Attackers may try to delete their tools to avoid detection. While the file won’t appear in the file system, the deletion record will appear in the UsnJrnl.

Additional data about the USN can be found at the following great resources

- [Velociraptor- IR the-windows-usn-journal-f0c55c9010e](https://medium.com/velociraptor-ir/the-windows-usn-journal-f0c55c9010e)
- [F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf](http://forensicinsight.org/wp-content/uploads/2013/07/F-INSIGHT-Advanced-UsnJrnl-Forensics-English.pdf)