import csv
import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import tempfile
import shutil

from tools.find_0_keys import (
    get_existing_files,
    filter_valid_key_pairs,
    find_zero_size_files,
    move_obsolete_keys,
    parse_csv,
)


class TestKeyProcessing(unittest.TestCase):

    def setUp(self):
        """Setup temporary directories and test files."""
        self.test_snap_dir = tempfile.mkdtemp()
        self.test_keys_dir = tempfile.mkdtemp()
        self.backup_dir = os.path.join(self.test_keys_dir, "backup")
        os.makedirs(self.backup_dir, exist_ok=True)

        self.csv_file = os.path.join(self.test_keys_dir, "keys.csv")
        self.keys_old_file = os.path.join(self.test_keys_dir, "keys.csv.bak")

        # Create test archive files
        self.snapshots = ["snap1.tar.gz", "snap2.tar.gz"]
        for snap in self.snapshots:
            open(os.path.join(self.test_snap_dir, snap), 'w').close()

        # Create test key files
        self.keys = {
            "snap1.tar.gz": os.path.join(self.test_keys_dir, "key1.enc"),
            "snap2.tar.gz": os.path.join(self.test_keys_dir, "key2.enc"),
            "missing.tar.gz": os.path.join(self.test_keys_dir, "key_missing.enc")
        }

        # Write key files
        for key_path in self.keys.values():
            with open(key_path, 'w') as f:
                f.write("test")

        # Write CSV
        with open(self.csv_file, "w", newline='') as csvfile:
            writer = csv.writer(csvfile)
            for snap, key in self.keys.items():
                writer.writerow([snap, key])

    def tearDown(self):
        """Clean up temporary files and directories."""
        shutil.rmtree(self.test_snap_dir)
        shutil.rmtree(self.test_keys_dir)

    def test_get_existing_files(self):
        """Ensure archive files are detected correctly."""
        files = get_existing_files(self.test_snap_dir)
        self.assertEqual(set(files), set(self.snapshots))

    def test_filter_valid_key_pairs(self):
        """Ensure valid key pairs are extracted correctly."""
        pairs = parse_csv(self.csv_file)
        existing_files = set(self.snapshots)

        filtered_pairs = filter_valid_key_pairs(existing_files, pairs)
        expected_pairs = [(snap, self.keys[snap]) for snap in self.snapshots]

        self.assertEqual(filtered_pairs, expected_pairs)

    def test_find_zero_size_files(self):
        """Ensure zero-byte key files are detected."""
        # Make one key file zero-size
        open(self.keys["snap2.tar.gz"], 'w').close()

        pairs = [(snap, key) for snap, key in self.keys.items() if os.path.exists(key)]
        zero_files = find_zero_size_files(pairs)

        self.assertEqual(zero_files, [("snap2.tar.gz", self.keys["snap2.tar.gz"])])

    def test_move_obsolete_keys(self):
        """Ensure obsolete key files are moved correctly."""
        existing_pairs = [(snap, self.keys[snap]) for snap in self.snapshots]

        moved_keys = move_obsolete_keys(self.test_keys_dir, existing_pairs, self.backup_dir)
        expected_moved = [self.keys["missing.tar.gz"]]

        self.assertEqual(moved_keys, expected_moved)
        self.assertFalse(os.path.exists(os.path.join(self.test_keys_dir, "key_missing.enc")))
        self.assertTrue(os.path.exists(os.path.join(self.backup_dir, "key_missing.enc")))


if __name__ == '__main__':
    unittest.main()
