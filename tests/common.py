# Copyright AlertAvert.com (c) 2017. All rights reserved.
# Created by Marco Massenzio (marco@alertavert.com), 2017-09-03

import os
import tempfile
import unittest


class TestBase(unittest.TestCase):
    def setUp(self):
        self.tests_dir = os.path.dirname(os.path.realpath(__file__))
        self.data_dir = os.path.join(self.tests_dir, "data")

    @staticmethod
    def temp_filename(suffix=None):
        """ Returns a valid, but non-existent temporary file name."""
        filename = tempfile.mkstemp(suffix=suffix)[1]
        if os.path.exists(filename):
            os.remove(filename)
        return filename
