# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.stix
import ramrod.stix.stix_1_1_1
import ramrod.utils as utils
from ramrod.test import _BaseVocab

UPDATER_MOD = ramrod.stix.stix_1_1_1
UPDATER = UPDATER_MOD.STIX_1_1_1_Updater

PACKAGE_TEMPLATE = \
"""
<stix:STIX_Package
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:stixCommon="http://stix.mitre.org/common-1"
    xmlns:campaign="http://stix.mitre.org/Campaign-1"
    xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:et="http://stix.mitre.org/ExploitTarget-1"
    xmlns:ttp="http://stix.mitre.org/TTP-1"
    xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
    xmlns:example="http://example.com/"
    xmlns:ramrod="http://ramrod.test/"
    version="1.1.1">
    %s
</stix:STIX_Package>
"""

class STIX_1_1_1_Test(unittest.TestCase):
    XML_VERSIONS = PACKAGE_TEMPLATE % ""

    @classmethod
    def setUpClass(cls):
        cls._versions = StringIO(cls.XML_VERSIONS)

    def test_get_version(self):
        root = utils.get_etree_root(self._versions)
        version = UPDATER.get_version(root)
        self.assertEqual(version, UPDATER.VERSION)

    def test_update_version(self):
        valid_versions = ramrod.stix.STIX_VERSIONS
        idx = valid_versions.index
        version_to = valid_versions[idx(UPDATER.VERSION)+1:]

        for version in version_to:
            updated = ramrod.update(self._versions, to_=version)
            updated_root = updated.document.as_element()
            updated_version = UPDATER.get_version(updated_root)
            self.assertEqual(version, updated_version)


class IndicatorTypeVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.STIX_1_1_1_Updater
    VOCAB_KLASS = UPDATER_MOD.DiscoveryMethodVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <stix:Indicators>
        <stix:Indicator xsi:type="indicator:IndicatorType">
            <indicator:Type xsi:type="stixVocabs:DiscoveryMethodVocab-1.0">Fraud Detection</indicator:Type>
        </stix:Indicator>
    </stix:Indicators>
    """
    XML = PACKAGE_TEMPLATE % (VOCAB_XML)

if __name__ == "__main__":
    unittest.main()