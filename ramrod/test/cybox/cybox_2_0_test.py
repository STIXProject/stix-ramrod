# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.cybox
import ramrod.utils as utils

class Cybox_2_0_Test(unittest.TestCase):
    XML_VERSIONS = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="2" cybox_minor_version="0">
    </cybox:Observables>
    """

    updater_klass = ramrod.cybox.Cybox_2_0_Updater

    @classmethod
    def setUpClass(cls):
        cls._versions = StringIO(cls.XML_VERSIONS)

    def test_get_version(self):
        root = utils.get_etree_root(self._versions)
        version = self.updater_klass.get_version(root)
        self.assertEqual(version, self.updater_klass.VERSION)

    def test_update_version(self):
        version_to = ('2.0.1', '2.1')

        for version in version_to:
            updated = ramrod.update(self._versions, to_=version)
            updated_root = updated.document.getroot()
            updated_version = self.updater_klass.get_version(updated_root)
            self.assertEqual(version, updated_version)


if __name__ == "__main__":
    unittest.main()