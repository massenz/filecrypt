import csv
import os
import shutil
from typing import List, Tuple, Set

"""Updates the key/archive pairs in the keys.csv file, and removes unused keys.

This is a utility script performs the following tasks:
    1. Reads the keys.csv file to get a list of archive/key pairs.
    2. Scans the snap_directory for existing archive files.
    3. Filters the archive/key pairs to only include those corresponding to actual archive files.
    4. Identifies zero-byte key files.
    5. Moves obsolete key files to a backup directory.
    
This is not part of the `crytto` package, and is not installed with it.
"""
# File paths
#
# Directory containing key files and
# the CSV file
KEYS_DIRECTORY = "/path/to/private/keys"

# Directory to move obsolete key entries
BACKUP_DIRECTORY = os.path.join(KEYS_DIRECTORY, "backup")

# Directory containing archive files
SNAP_DIRECTORY = "/usr/local/archives"

# Full path to CSV file, containing archive and key pairs
KEYFILE = os.path.join(KEYS_DIRECTORY, "keys.csv")

# Full path to backup CSV file
KEYFILE_BACKUP = os.path.join(BACKUP_DIRECTORY, "keys.csv.bak")

# Ensure the backup directory exists
os.makedirs(BACKUP_DIRECTORY, exist_ok=True)


# Read CSV and create a list of (archive, key) pairs
def parse_csv(file_path: str) -> List[Tuple[str, str]]:
    pairs = []
    if not os.path.exists(file_path):
        raise FileNotFoundError(file_path)  # Return empty list if CSV doesn't exist
    with open(file_path, newline='') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if len(row) == 2:
                pairs.append((row[0].strip(), row[1].strip()))
    return pairs


# Scan snap_directory and return the set of filenames
def get_existing_files(directory: str) -> set:
    return {f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))}


# Filter (archive, key) pairs corresponding to actual snap files
def filter_valid_key_pairs(existing_files: Set[str], pairs: List[Tuple[str, str]]) -> List[
    Tuple[str, str]]:
    return [(archive, key) for archive, key in pairs if archive in existing_files]


# Identify zero-byte key files
def find_zero_size_files(key_pairs: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Finds zero-byte key files from a list of (archive, key) pairs.

    :param key_pairs: List of (archive, key) pairs.
    :return: List of (archive, key) pairs where the key file is zero-byte.
    """
    return [(archive, key) for archive, key in key_pairs if
            os.path.exists(key) and os.path.getsize(key) == 0]


def move_obsolete_keys(keys_dir: str, valid_pairs: List[Tuple[str, str]], backup_dir: str) -> List[
    str]:
    """Moves all keys in keys_dir to backup_dir if they are not in the valid_pairs list.

    :param valid_pairs: contains a list of (archive, key path) pairs.
    :param keys_dir: directory containing the key files.
    :param backup_dir: directory to move the obsolete key files.
    """
    # Extract valid key file paths
    valid_keys = {key for _, key in valid_pairs}
    moved_keys = []
    # Iterate over all files in keys_dir
    for key_file in os.listdir(keys_dir):
        if not key_file.endswith(".enc"):
            continue
        key_path = os.path.join(keys_dir, key_file)

        # Only move files (ignore directories)
        if os.path.isfile(key_path) and key_path not in valid_keys:
            backup_path = os.path.join(backup_dir, key_file)
            shutil.move(key_path, backup_path)
            moved_keys.append(key_path)
    return moved_keys


# Save the updated key pairs to the CSV, backing up the old one
def save_updated_pairs(pairs: List[Tuple[str, str]], original_csv: str, backup_csv: str) -> None:
    if os.path.exists(original_csv):
        shutil.move(original_csv, backup_csv)  # Backup old CSV
    with open(original_csv, "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerows(pairs)


# Main function
def update_keys() -> None:
    """We update the keys.csv file by removing entries for archives that no longer exist.

    We also look for zero-byte key files and move obsolete keys to a backup directory.
    """
    existing_files: Set[str] = get_existing_files(SNAP_DIRECTORY)
    original_pairs: List[Tuple[str, str]] = parse_csv(KEYFILE)

    valid_pairs: List[Tuple[str, str]] = filter_valid_key_pairs(existing_files, original_pairs)

    # Remove unusable keys from the valid list
    zero_byte_files: List[Tuple[str, str]] = find_zero_size_files(valid_pairs)
    final_pairs = [pair for pair in valid_pairs if pair not in zero_byte_files]

    # Move obsolete keys to a backup folder.
    moved_keys: List[str] = move_obsolete_keys(KEYS_DIRECTORY, valid_pairs, BACKUP_DIRECTORY)

    # Save updated pairs
    save_updated_pairs(final_pairs, KEYFILE, KEYFILE_BACKUP)

    # Print results
    print("\nZero-byte key files:") if len(zero_byte_files) > 0 else print("\nNo zero-byte key files found.")
    for archive, key in zero_byte_files:
        print(f"Archive: {archive} → Zero-byte key file: {key}")
    print("\nMoved obsolete key files to backup:") if len(moved_keys) > 0 else print("\nNo obsolete key files moved.")
    for i, key in enumerate(moved_keys):
        print(f"Moved: {key}")

    print(f"\nRetained {len(final_pairs)} valid key pairs")
    print("Saved to:", KEYFILE)


if __name__ == "__main__":
    update_keys()
