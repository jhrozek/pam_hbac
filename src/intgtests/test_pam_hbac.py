#!/usr/bin/env python

import unittest
import os
import shutil

import pypamtest

class PamHbacTestCase(unittest.TestCase):
    def setUp(self):
        if os.getenv("PAM_WRAPPER") == None:
            raise ValueError("PAM_WRAPPER is not initialized\n")

        self.pwrap_servicedir = os.getenv("PAM_WRAPPER_SERVICE_DIR")
        if self.pwrap_servicedir == None:
            raise ValueError("The PAM_WRAPPER_SERVICE_DIR variable is unset\n")

        if not os.access(self.pwrap_servicedir, os.O_RDWR):
            raise IOError("Cannot access %s\n", self.pwrap_servicedir)

    def tearDown(self):
        print self.pwrap_servicedir
        #shutil.rmtree(self.pwrap_servicedir, True)

class PamHbacTestAllowAll(PamHbacTestCase):
    def setUp(self):
        super(PamHbacTestAllowAll, self).setUp()

    def tearDown(self):
        super(PamHbacTestAllowAll, self).tearDown()

    def test_allow_all(self):
        pass

if __name__ == "__main__":
    unittest.main()
