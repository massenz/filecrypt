#!/usr/bin/env python
#
# @copyright: AlertAvert.com (c) 2015. All rights reserved.

import unittest

import os

from crytto.main import establish_secret
from crytto.utils import KeystoreManager


class TestBase(unittest.TestCase):
    def setUp(self):
        self.tests_dir = os.path.dirname(os.path.realpath(__file__))
        self.data_dir = os.path.join(self.tests_dir, "data")
