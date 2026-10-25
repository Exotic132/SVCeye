# SVCeye

**SVCeye** is a lightweight, custom Python utility designed for authorized security auditing, local system enumeration, and privilege escalation vector discovery on Windows environments. Built for security professionals, penetration testers, and defenders looking to audit system posture.

---

## Features

SVCeye automates the discovery of common Windows misconfigurations and security weaknesses:

* **Service Path Auditing:** Scans all system services, categorizing them into **Quoted** and **Unquoted** paths, while highlighting **Missing / Non-existent** service binaries prone to binary replacement.
* **ACL & Permission Inspection:** Evaluates file access permissions on service binary paths using native Windows `icacls`.
* **Vulnerable Registry Auditing:** Scans high-risk configuration keys such as `AlwaysInstallElevated` (HKLM & HKCU) and LSA Protection (`RunAsPPL`).
* **Privilege & Token Verification:** Identifies high-privilege tokens and rights such as `SeImpersonatePrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege`.
* **Credential Hive Extraction:** Safely attempts registry backups of the `SAM` and `SYSTEM` hives to `C:\temp` for offline analysis (requires Administrative privileges).
* **Autorun & Persistence Check:** Enumerates `Run` and `RunOnce` registry persistence keys across both HKLM and HKCU.

---

## Prerequisites

* **Operating System:** Windows 7, 10, 11, or Windows Server.
* **Python Version:** Python 3.x installed on the target machine.

---

## Installation & Usage

Clone the repository and run the script with your desired flags:

```bash
git clone [https://github.com/Exotic132/SVCeye.git](https://github.com/Exotic132/SVCeye.git)

cd SVCeye

python svceye.py -h
```
