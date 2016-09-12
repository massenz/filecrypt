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
import os
from tempfile import mkstemp
from sh import openssl, ErrorReturnCode, shred as _shred


__author__ = 'Marco Massenzio'
__email__ = 'marco@alertavert.com'


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
            openssl('rand', '32', '-out', self._plaintext)
        else:
            with open(encrypted_key, 'rb') as secret:
                openssl('rsautl', '-decrypt', '-inkey', keypair.private,
                        _in=secret, _out=self._plaintext)

    @property
    def keyfile(self):
        """The name of the file that contains the unencrypted (plaintext) version of this key."""
        return self._plaintext

    def __bytes__(self):
        """The plaintext contents of the key file.

        Convenience function to automatically convert this object to something immediately
        usable during decryption.
        """
        with open(self._plaintext, 'rb') as pf:
            return pf.read()

    def __del__(self):
        try:
            if not os.path.exists(self.encrypted):
                self._save()
            shred(self._plaintext)
        except ErrorReturnCode as rcode:
            raise RuntimeError(
                "Either we could not save encrypted or not shred the plaintext passphrase "
                "in file {plain} to file {enc}.  You will have to securely delete the plaintext "
                "version using something like `shred -uz {plain}".format(
                    plain=self._plaintext, enc=self.encrypted))

    def _save(self):
        """ Encrypts the contents of the key and writes it out to disk.

        :param dest: the full path of the file that will hold the encrypted contents of this key.
        :param key: the name of the file that holds an encryption key (the PUBLIC part of a key pair).
        :return: None
        """
        if not os.path.exists(self.key_pair.public):
            raise RuntimeError("Encryption key file '%s' not found" % self.key_pair.public)
        with open(self._plaintext, 'rb') as selfkey:
            openssl('rsautl', '-encrypt', '-pubin', '-inkey', self.key_pair.public,
                    _in=selfkey, _out=self.encrypted)


def shred(filename):
    """Will securely destroy the `filename` using Linux `shred` utility."""
    try:
        _shred('-uz', filename)
    except ErrorReturnCode as rcode:
        raise RuntimeError("Could not securely destroy '%s' (%d): %s", filename,
                           rcode.exit_code, rcode.stderr)


KeystoreEntry = namedtuple('KeystoreEntry', 'plaintext secret encrypted')


class KeystoreManager(object):
    """Manages the keystore, where we keep the association between one-time keys and files.

    There is a need to track which key was used when encrypting which file, so that we can easily
    decrypt them when necessary.

    This store uses the simplest approach, a CSV file with three entries per row: the original
    unencrypted file, the encryption key file name and the encrypted file; they are all stored as
    absolute paths and kept in no particular order.

    We assume that the file size is such that sequential traversal and append-only semantics will NOT
    cause any major performance impact.
    """

    def __init__(self, filestore):
        if not os.path.exists(filestore):
            raise ValueError("%s does not exist", filestore)
        self.filestore = os.path.abspath(filestore)

    def lookup(self, filename):
        """Looks up for the given filename for any entry and returns the row contents.

        :param filename: the name (relative or absolute) to look up, in any of the rows,
        for any of the entries (be it the plaintext file, or the key name, or the encrypted file).
        :type filename: str

        :return: the ``namedtuple`` that represents a row in this store
        :rtype: KeystoreEntry
        """
        with open(self.filestore, 'rt') as store:
            reader = csv.reader(store)
            for row in reader:
                for item in row:
                    if item.endswith(filename):
                        return KeystoreEntry(plaintext=row[0],
                                             secret=row[1],
                                             encrypted=row[2])

    def add_entry(self, entry):
        """Adds a new entry at the end of the key store.

        :param entry: the tuple containing the plaintext, secret and encrypted filenames.
        :type entry: KeystoreEntry
        """
        with open(self.filestore, 'at') as store:
            writer = csv.writer(store)
            writer.writerow(entry)

