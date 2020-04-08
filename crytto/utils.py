# Copyright AlertAvert.com (c) 2015. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from collections import namedtuple
import csv
from datetime import datetime as d
import logging
import os
from pathlib import Path
from tempfile import mkstemp

import time
import yaml

from sh import openssl, ErrorReturnCode, shred as _shred

from crytto import BACKUP_EXT


class EncryptConfiguration(object):

    DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
    LOG_FORMAT = "%(asctime)s [%(levelname)-5s] %(message)s"

    def __init__(self, conf_file):
        self.out = None
        self.private = None
        self.public = None
        self.secrets_dir = None
        self.shred = None
        self.store = None
        self._log = logging.getLogger(self.__class__.__name__)
        self.parse_configuration_file(conf_file)

    @property
    def log(self):
        return self._log

    def parse_configuration_file(self, conf_file):
        with open(conf_file) as cfg:
            configs = yaml.safe_load(cfg)

        # First, let's get some logging going.
        if "logging" in configs:
            self._configure_logging(configs.get("logging"))

        keys = configs.get("keys")
        if not keys:
            self.log.error("The `keys:` section is required, cannot proceed without.")
            raise RuntimeError("Missing `keys` in {}".format(conf_file))

        self.private = keys.get("private")
        self.public = keys.get("public")
        self.secrets_dir = keys.get("secrets")

        if not os.path.isdir(self.secrets_dir):
            self.log.warning("Directory '%s' does not exist, trying to create it", self.secrets_dir)
            try:
                os.makedirs(self.secrets_dir, mode=0o775)
            except OSError as err:
                self.log.error("Cannot create directory '%s': %s", self.secrets_dir, err)
                raise RuntimeError(err)

        self.store = configs.get("store")

        # If the `out` key is not present, the current directory is used.
        self.out = configs.get("out", os.getcwd())

        # Unless otherwise specified, we will securely destroy the original plaintext file.
        self.shred = configs.get("shred", True)

    def _configure_logging(self, log_config):
        handler = logging.StreamHandler()
        if "logdir" in log_config:
            handler = logging.FileHandler(os.path.join(log_config.get("logdir"), "crytto.log"))
        formatter = logging.Formatter(
            fmt=log_config.get("format", EncryptConfiguration.LOG_FORMAT),
            datefmt=log_config.get("datefmt", EncryptConfiguration.DATE_FORMAT),
        )
        handler.setFormatter(formatter)
        self._log.setLevel(log_config.get("level", "WARN"))
        self._log.addHandler(handler)
        self.log.debug("Logging configuration complete")


class SelfDestructKey(object):
    """A self-destructing key: it will shred its contents when it gets deleted.

       This key also encrypts itself with the ``keypair`` before writing itself out to a file.

       As a convenience, it can be automatically converted to an array of bytes with the
       unencrypted contents of the file via the ``__bytes__()`` special method.
    """

    def __init__(self, encrypted_key, keypair):
        """Creates an encryption key, using the given keypair to encrypt/decrypt it.

        The plaintext version of this key is kept in a temporary file that will be securely
        destroyed upon this object becoming garbage collected.

        :param encrypted_key: the encrypted version of this key is kept in this file: if it
            does not exist, it will be created when this key is saved
        :type encrypted_key: str
        :param keypair: a tuple containing the (private, public) key pair that will be used to
            decrypt and encrypt (respectively) this key.
        :type keypair: collections.namedtuple (Keypair)
        """
        self._plaintext = mkstemp()[1]
        self.encrypted = encrypted_key
        self.key_pair = keypair
        if not os.path.exists(encrypted_key):
            openssl("rand", "-out", self._plaintext, "32")
        else:
            with open(encrypted_key, "rb") as secret:
                openssl(
                    "rsautl",
                    "-decrypt",
                    "-inkey",
                    keypair.private,
                    _in=secret,
                    _out=self._plaintext,
                )

    @property
    def keyfile(self):
        """The name of the file that contains the unencrypted (plaintext) version of this key."""
        return self._plaintext

    def __bytes__(self):
        """The plaintext contents of the key file.

        Convenience function to automatically convert this object to something immediately
        usable during decryption.
        """
        with open(self._plaintext, "rb") as pf:
            return pf.read()

    def __del__(self):
        try:
            if not os.path.exists(self.encrypted):
                self._save()
            shred(self._plaintext)
        except ErrorReturnCode as rcode:
            raise RuntimeError(
                "Error running: `{cmd}`\n"
                "The error was: {err}\n"
                "We could not shred the plaintext passphrase in file '{plain}' or encrypt it "
                "to file {enc}.  You will have to securely delete the plaintext "
                "version using something like `shred -uz {plain}`.".format(
                    plain=self._plaintext,
                    enc=self.encrypted,
                    err=rcode.stderr.decode("utf-8"),
                    cmd=rcode.full_cmd,
                )
            )

    def _save(self):
        """ Encrypts the contents of the key and writes it out to disk. """
        if not os.path.exists(self.key_pair.public):
            raise RuntimeError("Encryption key file '%s' not found" % self.key_pair.public)
        with open(self._plaintext, "rb") as selfkey:
            openssl(
                "rsautl",
                "-encrypt",
                "-pubin",
                "-inkey",
                self.key_pair.public,
                _in=selfkey,
                _out=self.encrypted,
            )


def shred(filename):
    """Will securely destroy the `filename` using Linux `shred` utility."""
    try:
        _shred("-uz", filename)
    except ErrorReturnCode as rcode:
        raise RuntimeError(
            "Could not securely destroy '%s' (%d): %s", filename, rcode.exit_code, rcode.stderr
        )


Keypair = namedtuple("Keypair", ["private", "public"])

KeystoreEntry = namedtuple("KeystoreEntry", ["secret", "encrypted"])


class KeystoreManager(object):
    """Manages the keystore, where we keep the association between one-time keys and files.

    There is a need to track which key was used when encrypting which file, so that we can easily
    decrypt them when necessary.

    This store uses the simplest approach, a CSV file with two entries per row: the encrypted
    file, whose name only is stored, and the full path to the encryption passphrase; the
    encrypted file name is the lookup key and must be unique.

    We assume that the file size is such that sequential traversal and append-only semantics
    will NOT cause any major performance impact.
    """
    def __init__(self, filestore, verbose=False):
        """ Creates a new `Keystore` from the stored `filestore`

        :param filestore: the filename where the key mappings are stored
        :param verbose: if `True` we emit debug logs
        """
        self._filestore = Path(filestore)
        self.modified = False
        if not self._filestore.exists():
            # The keystore needs creating.
            with open(filestore, "wt") as keystore:
                keystore.write(f"# Crytto keystore file, created at: {time.ctime()}\n#\n")
            self.modified = True
        self._log = logging.getLogger(self.__class__.__name__)
        self._log.setLevel(logging.DEBUG if verbose else logging.INFO)
        self._data = self._load()

    def __del__(self):
        """Destructor, saves keystore if it has been modified"""
        if not self.modified:
            return
        self._save()

    def _load(self):
        data = dict()
        self._log.debug(f"Loading key mappings from {self.filestore}")
        with self._filestore.open() as store:
            reader = csv.DictReader(store, fieldnames=('enc', 'key'), skipinitialspace=True)
            for row in reader:
                encrypted = row['enc']
                if encrypted.startswith('#'):
                    continue
                data[encrypted] = row['key']
        self._log.debug(f"Loaded {len(data)} entries")
        return data

    def _save(self):
        if self._filestore.exists():
            self._filestore.rename(self.filestore + ".bak")
        with self._filestore.open('wt') as store:
            store.write(f"# Crytto keystore file\n")
            store.write(f"# Created at {d.isoformat(d.now())}\n")
            store.write(f"#\n")
            writer = csv.writer(store, lineterminator="\n")
            for k, v in self._data.items():
                writer.writerow((k, v))

    @property
    def filestore(self):
        return str(self._filestore)

    @property
    def key_data(self):
        return self._data

    def lookup(self, filename):
        """Looks up for the given filename for any entry and returns the row contents.

        :param filename: the name of the file to look up, without any path components (if
            present, they will be stripped out before the lookup)
        :type filename: str

        :return: the ``namedtuple`` that represents a row in this store
        :rtype: KeystoreEntry
        """
        filename = Path(filename).name
        if filename in self._data:
            return KeystoreEntry(encrypted=filename, secret=self._data.get(filename))

    def add_entry(self, entry):
        """Adds a new entry at the end of the key store.

        :param entry: the tuple containing the plaintext, secret and encrypted filenames.
        :type entry: KeystoreEntry
        """
        encrypted = Path(entry.encrypted)
        self._log.debug(f"Adding entry for {encrypted}: {entry.secret}")
        self._data[encrypted.name] = entry.secret
        self.modified = True

    def remove(self, entry):
        """ Removes an entry from the store.

        :param entry: the full row to remove, or just the name of the encrypted file for the row.
        :type entry: str or KeystoreEntry

        :return: ```True``` if the entry was successfully removed
        :rtype: bool
        """
        if isinstance(entry, KeystoreEntry):
            entry = entry.encrypted
        if self._data.pop(Path(entry).name, None):
            self._log.debug(f"Removed entry for {entry}")
            self.modified = True
            return True
        else:
            self._log.warning(f"Failed to remove entry for {entry}")
            return False
