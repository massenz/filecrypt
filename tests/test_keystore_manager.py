# @copyright: AlertAvert.com (c) 2015. All rights reserved.


import os
from tempfile import mkstemp

from crytto.utils import KeystoreEntry, KeystoreManager
from tests import common


class KeystoreManagerTests(common.TestBase):

    def setUp(self):
        super().setUp()
        self.store = KeystoreManager(os.path.join(self.data_dir, 'test_keys.csv'))

    def test_lookup(self):
        ll = self.store.lookup('pass-key-315.enc')
        self.assertEqual('/data/20160827_snapshot.tar.gz.enc', ll.encrypted)

        ll = self.store.lookup('20160827_snapshot.tar.gz.enc')
        self.assertEqual('/data/keys/pass-key-315.enc', ll.secret)
        self.assertEqual('/data/20160827_snapshot.tar.gz.enc', ll.encrypted)

    def test_fails_with_nofile(self):
        with self.assertRaises(ValueError):
            store = KeystoreManager('/foo/bar')

    def test_add_entry(self):
        self.store = KeystoreManager(mkstemp()[1])
        new_entry = KeystoreEntry(secret='/tmp/secret.enc',
                                  encrypted='/tmp/plain.txt.enc')
        self.store.add_entry(new_entry)
        self.assertEqual(new_entry, self.store.lookup('plain.txt.enc'))
