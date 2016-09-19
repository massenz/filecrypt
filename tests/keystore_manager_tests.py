# @copyright: AlertAvert.com (c) 2015. All rights reserved.
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

import unittest
from tempfile import mkstemp

from filecrypt.utils import KeystoreEntry, KeystoreManager


class KeystoreManagerTests(unittest.TestCase):

    def setUp(self):
        self.store = KeystoreManager('data/test_keys.csv')

    def test_lookup(self):
        ll = self.store.lookup('pass-key-315.enc')
        self.assertEqual('/data/20160827_snapshot.tar.gz.enc', ll.encrypted)

        ll = self.store.lookup('20160827_snapshot.tar.gz')
        self.assertEqual('/data/keys/pass-key-315.enc', ll.secret)
        self.assertEqual('/data/20160827_snapshot.tar.gz.enc', ll.encrypted)

    def test_fails_with_nofile(self):
        with self.assertRaises(ValueError):
            store = KeystoreManager('/foo/bar')

    def test_add_entry(self):
        self.store = KeystoreManager(mkstemp()[1])
        new_entry = KeystoreEntry(plaintext='/tmp/plain.txt',
                                  secret='/tmp/secret.enc',
                                  encrypted='/tmp/plain.txt.enc')
        self.store.add_entry(new_entry)
        self.assertEqual(new_entry, self.store.lookup('plain.txt'))
