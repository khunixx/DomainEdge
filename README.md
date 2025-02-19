**README.md**

# DomainEdge

DomainEdge is a bash script designed to automate the enumeration and exploitation process within an Active Directory (AD) environment. By combining multiple scanning and exploitation tools, it allows red teams and penetration testers to streamline their AD discovery, enumeration, and exploitation workflow.

---

## Table of Contents
1. [Overview](#overview)  
2. [Features](#features)  
3. [Prerequisites](#prerequisites)  
4. [Tested On](#tested-on)  
5. [Usage](#usage)  
6. [Script Workflow](#script-workflow)  
7. [Disclaimer](#disclaimer)

---

## Overview
DomainEdge aims to:
- Scan and identify live hosts in your target network range.  
- Enumerate key AD services, shares, and configurations.  
- Attempt basic to advanced exploitation techniques on discovered vulnerabilities.  
- Produce a comprehensive PDF report of all findings.

**Use Cases**:
- Red team engagements.
- Internal penetration tests.
- Learning and practicing AD enumeration techniques.

---

## Features
1. **Automated Dependency Check**  
   - Ensures required packages (**nmap**, **masscan**, **crackmapexec**, **impacket**, **smbclient**, **enscript**, **ghostscript**) are installed.

2. **Flexible Scanning Modes**  
   - **Basic**: Quick host discovery and port scan.  
   - **Intermediate**: Extended port scan and key service identification.  
   - **Full**: Comprehensive TCP/UDP scans for an in-depth view.

3. **Active Directory Enumeration**  
   - Domain Controller and DHCP discovery.  
   - SMB share enumeration.  
   - Extraction of users, groups, password policies, and group membership (e.g., Domain Admins).

4. **Exploitation Tiers**  
   - **Basic**: Nmap vulnerability scripts.  
   - **Intermediate**: Password spraying attacks via `crackmapexec`.  
   - **Full**: Kerberos ticket retrieval with `impacket-GetNPUsers`.

5. **Automated Reporting**  
   - Aggregates findings from scans, enumeration, and exploitation.  
   - Generates a final PDF report (`results.pdf`).

---

## Prerequisites
This script checks for and installs the following tools if they are not already present:
- [**nmap**](https://nmap.org/)  
- [**masscan**](https://github.com/robertdavidgraham/masscan)  
- [**crackmapexec**](https://github.com/Porchetta-Industries/CrackMapExec)  
- [**impacket**](https://github.com/fortra/impacket)  
- [**smbclient**](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)  
- [**enscript**](https://packages.debian.org/enscript)  
- [**ghostscript**](https://ghostscript.com/)

> **Note**: The script relies on `apt-get` to install packages, so it’s primarily tested on **Debian/Ubuntu-based** systems.

---

## Tested On
- **Kali Linux** (Debian-based)
- **Ubuntu 20.04+**

It may work on other Debian/Ubuntu derivatives as well, provided the above tools can be installed via `apt-get`.

---

## Usage

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/khunixx/DomainEdge.git
   cd DomainEdge
   ```

2. **Make the Script Executable** (if needed):
   ```bash
   chmod +x ad_enum_exploit.sh
   ```

3. **Run the Script**:
   ```bash
   sudo ./ad_enum_exploit.sh
   ```
   > The script requires `sudo` privileges because it needs to install packages and perform network scans that typically require elevated privileges.

4. **Follow the Prompts**:
   - You’ll be asked for an output directory name, network range, AD domain credentials, and your desired scanning, enumeration, and exploitation modes.  
   - After completion, a comprehensive **results.pdf** report will be created in the chosen directory.

---

## Script Workflow

1. **CHECK**  
   - Verifies script is run as root.  
   - Checks for installed dependencies and installs missing packages.

2. **INPUT**  
   - Prompts for and confirms user-defined parameters:  
     - Directory name for storing results  
     - Network range  
     - Domain credentials (username/password)  
     - Choice of scanning, enumeration, and exploitation modes

3. **UP**  
   - Detects active hosts within the specified range.  
   - Prepares directories for each active host’s scan results.

4. **SCAN**  
   - Executes the selected scanning level: Basic, Intermediate, or Full.  
   - Conducts targeted `nmap` (and possibly `masscan`) scans.

5. **ENUM**  
   - Performs AD enumeration based on chosen mode (Basic, Intermediate, Full):  
     - Identifies Domain Controller, DHCP server.  
     - Enumerates shares, users, groups, password policies, etc.

6. **EXPLOIT**  
   - Based on the exploitation mode (Basic, Intermediate, Full):  
     - Runs `nmap` vuln scripts.  
     - Attempts password spraying.  
     - Retrieves Kerberos tickets with `impacket`.

7. **RESULTS**  
   - Combines data from the SCAN, ENUM, and EXPLOIT steps.  
   - Generates a comprehensive PDF report (`results.pdf`).


