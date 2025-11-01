(don’t run on systems you don’t own, do not misuse)
Use at your own risk. Author is not responsible for data loss or misuse.


ADS SCANNER

A Digital Forensics Utility for Detecting, Viewing, Deleting, and Restoring Alternate Data Streams (ADS) on Windows

---

INTRODUCTION

WHAT IS ADS?

Alternate Data Streams (ADS) are hidden data segments within files on NTFS (New Technology File System) drives in Windows.
They allow multiple data streams to be associated with a single file. While they have legitimate uses (e.g., storing file metadata), attackers can exploit ADS to hide malicious payloads, scripts, or confidential information.


WHAT DOES THIS TOOL DO?

**ADS Scanner** is a command-line forensic tool built in Python to:

* Detect **hidden ADS streams** in any directory.
* Identify **suspicious or uncommon ADS** based on a whitelist.
* Allow you to **view, backup, delete, and restore** ADS streams safely.
* Maintain logs and hashes of detected streams for forensic records.

---

OVERVIEW

This tool performs a recursive scan of the given directory and:

* Lists all files that contain Alternate Data Streams.
* Flags suspicious ones (not in the safe list).
* Logs results to `log/suspicious_ads.txt`.
* Tracks known ADS hashes in `log/ads_state.json`.
* Allows restoration of deleted ADS from backups in `log/ads_backups/`.

---

FILE STRUCTURE

```
C:.
│
├── readme.MD                # Documentation (this file)
├── requirements.txt         # Dependencies (if any)
├── scanner.py               # Main source code for ADS Scanner
├── setup.py                 # Setup file for packaging and CLI entry
├── structure.txt            # Directory structure output
│
├── ads_scanner.egg-info/    # Metadata generated after setup install
│
├── log/
│   ├── ads_state.json       # Tracks previously scanned ADS with hashes
│   ├── suspicious_ads.txt   # Log file of all detected ADS
│   └── ads_backups/         # Folder storing ADS backups (.bin + .meta.json)
│
└── __pycache__/             # Compiled Python cache files
```

WHAT EACH FILE DOES

| File                       | Purpose                                                                          |
| -------------------------- | -------------------------------------------------------------------------------- |
| **scanner.py**             | Main script implementing scan, view, delete, restore, list, and clear functions. |
| **setup.py**               | Allows the tool to be installed and used system-wide via CLI (`ads_scanner`).    |
| **requirements.txt**       | Lists external dependencies (if any).                                            |
| **log/suspicious_ads.txt** | Stores details of detected ADS including SHA-256 hashes and timestamps.          |
| **log/ads_state.json**     | Maintains state of previously scanned ADS to prevent duplicates.                 |
| **log/ads_backups/**       | Stores deleted ADS data and metadata for recovery.                               |
| **structure.txt**          | Directory listing output (for internal reference).                               |

---

COMMANDS AND THEIR USAGE

| Function          | Command                                         | Example Command                                                          | Description                                                                                                           |
| ----------------- | ----------------------------------------------- | ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| **Scan**          | `ads_scanner -s <path> --show_all=<true/false>` | `ads_scanner -s "C:\Users\Ayesha\Documents" --show_all=false`            | Scans a directory recursively for ADS. When `--show_all=false`, only suspicious streams are listed; `true` shows all. |
| **View**          | `ads_scanner -v "<file>:<stream>"`              | `ads_scanner -v "C:\test.txt:hidden.txt"`                                | Displays the hidden content stored in a specific ADS stream.                                                          |
| **Delete**        | `ads_scanner -d "<file>:<stream>"`              | `ads_scanner -d "C:\test.txt:hidden.txt"`                                | Deletes the specified ADS stream **after creating a backup** (`.bin` + `.meta.json`).                                 |
| **Restore**       | `ads_scanner -r <filename_or_path>`             | `ads_scanner -r hidden.txt` OR `ads_scanner -r "C:\test.txt:hidden.txt"` | Restores a deleted ADS stream from the backup directory. Can be restored by filename or full path.                    |
| **List Backups**  | `ads_scanner -lb`                               | `ads_scanner -lb`                                                        | Lists all existing ADS backups with original paths and timestamps.                                                    |
| **Clear Backups** | `ads_scanner -cb`                               | `ads_scanner -cb`                                                        | Deletes all stored ADS backups after user confirmation.                                                               |
| **Help**          | `ads_scanner -h`                                | `ads_scanner -h`                                                         | Displays all available commands and their usage.                                                                      |

---

SYSTEM REQUIREMENTS

| Requirement          | Description                                            |
| -------------------- | ------------------------------------------------------ |
| **Operating System** | Windows 10 or later                                    |
| **File System**      | NTFS (required for Alternate Data Streams)             |
| **Python Version**   | 3.8 or higher                                          |
| **Permissions**      | Administrator rights may be needed for protected files |

---

INSTALLATION PROCESS

### 🔹 Option 1: Run Directly

1. Clone or download the repository.
2. Navigate to the folder:

   ```bash
   cd C:\path\to\ADS_Scanner
   ```
3. Run directly using Python:

   ```bash
   python scanner.py -h
   ```

### 🔹 Option 2: Install as a CLI Tool

1. Install using setup.py (go to the project dir):

   ```bash
   pip install .
   ```
2. Once installed, run the tool from anywhere:

   ```bash
   ads_scanner -h
   ```

---
### 🔹 Option 3: Install .exe file
Make it runnable from any folder (so you can just type ads_scanner)

Create a permanent program folder (admin required for Program Files):

mkdir "C:\Program Files\ads_scanner"
copy "C:\Users\Alice\Downloads\ads_scanner.exe" "C:\Program Files\ads_scanner\ads_scanner.exe"


Add that folder to system PATH (Admin):

setx /M PATH "%PATH%;C:\Program Files\ads_scanner"


Close and re-open the Command Prompt and run:

ads_scanner -h


If the you cannot run as Admin, you can add the folder to your user PATH instead (omit /M) or place the .exe in a folder that’s already in PATH.


CREATING AND TESTING ADS

1. Create a hidden ADS manually:

   ```bash
   echo HiddenData > test.txt:hidden.txt
   ```
2. Verify it using ADS Scanner:

   ```bash
   ads_scanner -s .
   ```
3. View its contents:

   ```bash
   ads_scanner -v "test.txt:hidden.txt"
   ```
4. Delete and backup it:

   ```bash
   ads_scanner -d "test.txt:hidden.txt"
   ```
5. Restore it later:

   ```bash
   ads_scanner -r hidden.txt
   ```
6. View existing backups:

   ```bash
   ads_scanner -lb
   ```
7. Clear all backups if needed:

   ```bash
   ads_scanner -cb
   ```

---

LOGS AND BACKUP STRUCTURE

All outputs, logs, and backups are automatically created inside the `log` directory.

```
log/
│
├── suspicious_ads.txt
│    ├─ File: C:\test.txt
│    ├─ Stream: hidden.txt
│    ├─ ADS Path: C:\test.txt:hidden.txt
│    ├─ SHA-256: <hash>
│    └─ Timestamp: 2025-11-01 17:42:00
│
├── ads_state.json
│    └─ Stores previous ADS paths + SHA-256 hashes to prevent duplicates
│
└── ads_backups/
     ├── test_txt_hidden.txt_backup.bin       # Binary data of deleted ADS
     ├── test_txt_hidden.txt_backup.meta.json # Metadata (original path, deletion time)
```

Each deleted ADS is backed up as:

* **`<name>_backup.bin`** → Raw binary contents of the ADS stream.
* **`<name>_backup.meta.json`** → Metadata including original path and deletion timestamp.

During restoration, the tool reads this metadata to restore the stream to its exact file and name.

---

NOTES

* Works **only** on NTFS file systems.
* Administrator privileges may be required for scanning system files.
* Use caution before deleting ADS linked to legitimate system processes.
* All logs and backups are stored locally; no internet access is required.

---

AUTHOR

**Ayesha**
