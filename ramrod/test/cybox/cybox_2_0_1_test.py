# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.cybox
import ramrod.utils as utils


class Cybox_2_0_1_Test(unittest.TestCase):
    UPDATER = ramrod.cybox.Cybox_2_0_1_Updater

    XML_VERSIONS = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="2" cybox_minor_version="0" cybox_update_version="1">
    </cybox:Observables>
    """

    @classmethod
    def setUpClass(cls):
        cls._versions = StringIO(cls.XML_VERSIONS)

    def test_get_version(self):
        root = utils.get_etree_root(self._versions)
        version = self.UPDATER.get_version(root)
        self.assertEqual(version, self.UPDATER.VERSION)

    def test_update_version(self):
        valid_versions = ramrod.cybox.CYBOX_VERSIONS
        idx = valid_versions.index
        version_to = valid_versions[idx(self.UPDATER.VERSION)+1:]

        for version in version_to:
            updated = ramrod.update(self._versions, to_=version)
            updated_root = updated.document.getroot()
            updated_version = self.UPDATER.get_version(updated_root)
            self.assertEqual(version, updated_version)

if __name__ == "__main__":
    unittest.main()
