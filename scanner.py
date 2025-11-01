import os
import argparse
import hashlib
import json
from datetime import datetime
import shutil

SAFE_STREAMS = [
    "Zone.Identifier",
    "WofCompressedData",
    "AlternateDataStreams",
    "com.apple.quarantine",
    "desktop.ini:$DATA",
    "Thumbs.db:$DATA",
    "SummaryInformation",
    "DocumentSummaryInformation",
    "Encryptable",
    "AFP_AfpInfo",
    "AFP_Resource",
    "::$DATA"
]

STATE_FILE = "log/ads_state.json"
BACKUP_DIR = "log/ads_backups"

# ---------------- Helper Functions ---------------- #

def is_suspicious_ads(ads_line):
    if ":$DATA" not in ads_line:
        return True
    parts = ads_line.split()
    for part in parts:
        if ":$DATA" in part:
            stream_full = part
            break
    else:
        return True
    try:
        _, stream_name, _ = stream_full.split(":", 2)
    except ValueError:
        return True
    return stream_name not in SAFE_STREAMS


def sha256_of_ads(base_file, stream_name):
    ads_path = f"{base_file}:{stream_name}"
    try:
        with open(ads_path, "rb") as f:
            content = f.read()
            return hashlib.sha256(content).hexdigest()
    except Exception:
        return None


def parse_dir_r_output(output, show_all=False):
    results = []
    current_dir = None
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("directory of"):
            current_dir = line.split("of")[-1].strip()
        elif ':' in line and "$DATA" in line:
            parts = line.split()
            file_stream = None
            for part in parts:
                if ":$DATA" in part:
                    file_stream = part
                    break
            if file_stream and ':' in file_stream:
                base_file, stream_name = file_stream.split(":", 1)
                full_file_path = os.path.join(current_dir, base_file)
                if show_all or is_suspicious_ads(line):
                    results.append((full_file_path, stream_name, line))
    return results


def load_logged_ads():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return set(tuple(i) for i in json.load(f))
    return set()


def save_logged_ads(entries):
    os.makedirs("log", exist_ok=True)
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump([list(i) for i in entries], f, indent=2)

# ---------------- Commands ---------------- #

# Scan Directory for ADS
def scan_directory(directory, show_all=False):
    import time
    start_time = time.time()

    print("\nScanning.... This may take a moment.\n")
    try:
        output = os.popen(f'dir /S /R "{directory}"').read()

        total_files_scanned = sum(
            1 for line in output.splitlines()
            if line.strip().lower().endswith(
                (".txt", ".exe", ".jpg", ".png", ".docx", ".pdf", ".ps1", ".bat", ".zip", ".dll")
            )
        )

        all_ads_entries = parse_dir_r_output(output, show_all=True)
        ads_entries = parse_dir_r_output(output, show_all=show_all)

        suspicious_count = len(ads_entries)
        safe_skipped_count = len(all_ads_entries) - suspicious_count if not show_all else 0

        if not ads_entries:
            print("\nNO SUSPICIOUS ADS FOUND.")
            return

        already_logged = load_logged_ads()
        new_logged = set()
        log_entries = []

        for base_file, stream_name, raw_line in ads_entries:
            ads_path = f"{base_file}:{stream_name}"
            hash_val = sha256_of_ads(base_file, stream_name)

            print(f"\nADS FOUND IN: {base_file}")
            print(f"   -> Stream: {stream_name}")
            print(f"   -> ADS Path: {ads_path}")
            print(f"   -> Raw Line: {raw_line}")

            entry_id = (ads_path, hash_val)
            if hash_val and entry_id not in already_logged:
                new_logged.add(entry_id)
                log_entries.extend([
                    f"\nFile: {base_file}",
                    f"Stream: {stream_name}",
                    f"ADS Path: {ads_path}",
                    f"Raw Entry: {raw_line}",
                    f"SHA-256: {hash_val}",
                    "-" * 50
                ])

        os.makedirs("log", exist_ok=True)
        if log_entries:
            log_entries.append("\n" + "="*60)
            log_entries.append(f"Scan Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            log_entries.append(f"Scanned Directory: {directory}")
            log_entries.append("="*60 + "\n")

            with open("log/suspicious_ads.txt", "a", encoding="utf-8") as f:
                f.write("\n".join(log_entries))

            save_logged_ads(already_logged.union(new_logged))
            print("\nNew suspicious ADS saved to log/suspicious_ads.txt")
        else:
            print("\nNo new suspicious ADS were added to the log.")

        duration = time.time() - start_time
        print(f"\nScan complete: {suspicious_count} suspicious ADS found, "
              f"{safe_skipped_count} safe ADS skipped, across {total_files_scanned} files in {duration:.2f} seconds.")
        print("Log saved to: log/suspicious_ads.txt")

    except Exception as e:
        print(f"Error: {e}")

# View ADS Content
def view_ads(ads_path):
    try:
        with open(ads_path, "r", encoding="utf-8") as f:
            print("\n--- ADS Content Start ---")
            print(f.read().strip())
            print("--- ADS Content End ---\n")
    except Exception as e:
        print(f"⚠ Could not read ADS content: {e}")

# Delete ADS with Backup
def delete_ads(ads_path):
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        base_name = ads_path.replace(':', '_').replace('\\', '_').replace('/', '_')
        backup_bin = os.path.join(BACKUP_DIR, f"{base_name}_backup.bin")
        backup_meta = os.path.join(BACKUP_DIR, f"{base_name}_backup.meta.json")

        if ':' not in ads_path:
            print("⚠ Please provide the full ADS path (e.g., C:\\Users\\Ayesha\\Documents\\main.txt:hidden.txt)")
            return

        confirm = input(f"Are you sure you want to delete this ADS stream? (y/n): ").lower()
        if confirm != 'y':
            print("Cancelled.")
            return

        # --- BACKUP ADS CONTENT ---
        try:
            with open(ads_path, "rb") as src, open(backup_bin, "wb") as dst:
                shutil.copyfileobj(src, dst)
            with open(backup_meta, "w", encoding="utf-8") as meta:
                json.dump({
                    "original_ads_path": ads_path,
                    "deleted_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }, meta, indent=2)
            print(f"Backup saved at: {backup_bin}")
        except Exception as e:
            print(f"⚠ Backup failed: {e}")

        # --- DELETE ADS STREAM (Python method, not cmd) ---
        try:
            # Open in write mode and truncate (clear) the stream, then delete it
            with open(ads_path, "wb") as f:
                pass
            os.remove(ads_path)
            print(f"✅ Successfully deleted ADS stream: {ads_path}")
        except FileNotFoundError:
            print(f"⚠ Stream not found: {ads_path}")
        except Exception as e:
            print(f"⚠ Failed to delete ADS stream: {e}")

    except Exception as e:
        print(f"⚠ Could not delete ADS stream: {e}")


# Restore ADS from Backup
def restore_ads(identifier):
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)

        # Normalize the identifier (ADS path or filename)
        if ":" in identifier:
            filename = identifier.replace(':', '_')
        else:
            filename = identifier

        backup_bin = None
        backup_meta = None

        # Find the correct backup file
        for file in os.listdir(BACKUP_DIR):
            if os.path.basename(filename) in file and file.endswith("_backup.bin"):
                backup_bin = os.path.join(BACKUP_DIR, file)
                backup_meta = backup_bin.replace("_backup.bin", "_backup.meta.json")
                break

        if not backup_bin:
            print(f"⚠ No matching backup found for '{identifier}'")
            return

        # Get original ADS path
        target_path = None
        if os.path.exists(backup_meta):
            with open(backup_meta, "r", encoding="utf-8") as f:
                meta = json.load(f)
                target_path = meta.get("original_ads_path")

        if not target_path:
            target_path = identifier

        # Make sure base file exists before restoring the stream
        base_file = target_path.split(":", 1)[0]
        if not os.path.exists(base_file):
            print(f"⚠ Base file '{base_file}' not found. Cannot restore ADS.")
            return

        # --- SAFE RESTORE (append to ADS only, do not overwrite main file) ---
        with open(backup_bin, "rb") as src, open(target_path, "ab") as dst:
            shutil.copyfileobj(src, dst)

        print(f"✅ Restored ADS stream to: {target_path}")

    except Exception as e:
        print(f"⚠ Could not restore ADS: {e}")

# List Available Backups
def list_backups():
    """List all available ADS backups"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backups = [f for f in os.listdir(BACKUP_DIR) if f.endswith("_backup.bin")]

    if not backups:
        print("No backups found.")
        return

    print("\nAvailable ADS Backups:")
    for f in backups:
        meta_file = f.replace("_backup.bin", "_backup.meta.json")
        meta_path = os.path.join(BACKUP_DIR, meta_file)
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as meta:
                data = json.load(meta)
                print(f"  • {f}")
                print(f"    ↳ Original: {data.get('original_ads_path')}")
                print(f"    ↳ Deleted On: {data.get('deleted_on')}")
        else:
            print(f"  • {f}")
    print()

# Clear All Backups
def clear_backups():
    """Clear all ADS backups after confirmation"""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    files = os.listdir(BACKUP_DIR)
    if not files:
        print("No backups to delete.")
        return

    confirm = input("Are you sure you want to delete all backups? (y/n): ").lower()
    if confirm != 'y':
        print("Cancelled.")
        return

    for f in files:
        os.remove(os.path.join(BACKUP_DIR, f))
    print("All backups cleared successfully.")


# ---------------- CLI Entry Point ---------------- #

def main():
    parser = argparse.ArgumentParser(
        prog="ads_scanner",
        description="A command-line tool to detect, view, delete, and restore Alternate Data Streams (ADS) on Windows."
    )
    parser.add_argument("-s", "--scan", help="Scan a directory for ADS", metavar="<path>")
    parser.add_argument("-v", "--view", help="View content of a specific ADS stream", metavar="<ads_path>")
    parser.add_argument("-d", "--delete", help="Delete a specific ADS stream (with confirmation and backup)", metavar="<ads_path>")
    parser.add_argument("-r", "--restore", help="Restore an ADS stream by filename or full path", metavar="<filename_or_path>")
    parser.add_argument("--show_all", default="false", help="Set to true to show all ADS including harmless ones")
    parser.add_argument("-lb", "--list_backups", action="store_true", help="List all ADS backups")
    parser.add_argument("-cb", "--clear_backups", action="store_true", help="Clear all ADS backups after confirmation")


    args = parser.parse_args()

    if args.scan:
        scan_directory(args.scan, show_all=(args.show_all.lower() == "true"))
    elif args.view:
        view_ads(args.view)
    elif args.delete:
        delete_ads(args.delete)
    elif args.restore:
        restore_ads(args.restore)
    elif args.list_backups:
        list_backups()
    elif args.clear_backups:
        clear_backups()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
