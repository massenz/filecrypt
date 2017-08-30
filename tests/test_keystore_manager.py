# @copyright: AlertAvert.com (c) 2015. All rights reserved.


import os
from tempfile import mkstemp

from crytto.utils import KeystoreEntry, KeystoreManager
from tests import common


class KeystoreManagerTests(common.TestBase):

    def setUp(self):
        super().setUp()
        self.store = KeystoreManager(os.path.join(self.data_dir, 'test_keys.csv'))
        _, tmpstore = mkstemp(suffix='.csv')
        self.tmp_store = KeystoreManager(tmpstore)

    def tearDown(self):
        if self.tmp_store:
            os.remove(self.tmp_store.filestore)
            if os.path.exists(self.tmp_store.filestore + '.bak'):
                os.remove(self.tmp_store.filestore + '.bak')

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
        new_entry = KeystoreEntry(secret='/tmp/secret.enc',
                                  encrypted='/tmp/plain.txt.enc')
        self.tmp_store.add_entry(new_entry)
        self.assertEqual(new_entry, self.tmp_store.lookup('plain.txt.enc'))

    def test_can_remove(self):
        entries = [
            KeystoreEntry(secret='/tmp/zek1', encrypted='/var/tmp/doc.c.enc'),
            KeystoreEntry(secret='/tmp/zek44', encrypted='/var/tmp/my-doc.hpp.enc'),
            KeystoreEntry(secret='/tmp/zek2', encrypted='/var/tmp/another.doc.enc'),
        ]
        for entry in entries:
            self.tmp_store.add_entry(entry)

        self.assertTrue(self.tmp_store.remove(entries[2]))
        self.assertIsNone(self.tmp_store.lookup('another.doc.enc'))

        self.assertTrue(self.tmp_store.remove('/var/tmp/doc.c.enc'))
        self.assertIsNone(self.tmp_store.lookup('doc.c.enc'))

        self.assertFalse(self.tmp_store.remove('bogus.entry'))
        self.assertFalse(self.tmp_store.remove(KeystoreEntry('/tmp/zek444',
                                                             '/var/tmp/non-exist.doc.enc')))

    def test_prune(self):
        _, k = mkstemp(suffix='.key')
        _, e = mkstemp(suffix='.enc')
        self.tmp_store.add_entry(KeystoreEntry(k, e))
        self.tmp_store.add_entry(KeystoreEntry("/tmp/bogus", e))
        self.tmp_store.add_entry(KeystoreEntry(k, "/home/docs.doc"))

        self.assertIsNotNone(self.tmp_store.lookup("/home/docs.doc"))
        self.assertIsNotNone(self.tmp_store.lookup("/tmp/bogus"))
        self.tmp_store.prune()

        self.assertIsNone(self.tmp_store.lookup("/home/docs.doc"))
        self.assertIsNone(self.tmp_store.lookup("/tmp/bogus"))
        self.assertEqual(KeystoreEntry(k, e), self.tmp_store.lookup(e))


class KeystoreEntryTest(common.TestBase):
    def test_equality(self):
        e1 = KeystoreEntry(secret='/tmp/zek', encrypted='/var/tmp/doc.c')
        e2 = KeystoreEntry(secret='/tmp/zek', encrypted='/var/tmp/doc.c')
        self.assertEqual(e1, e2)

        e3 = KeystoreEntry(secret='/tmp/zek2', encrypted='/var/tmp/doc.c')
        self.assertNotEqual(e1, e3)

    def test_instance(self):
        e1 = KeystoreEntry(secret='/tmp/zek', encrypted='/var/tmp/doc.c')
        self.assertTrue(isinstance(e1, KeystoreEntry))
