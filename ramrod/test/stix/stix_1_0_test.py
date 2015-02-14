# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.stix
import ramrod.stix.stix_1_0
import ramrod.utils as utils
from ramrod.test import (_BaseVocab, _BaseDisallowed)

UPDATER_MOD = ramrod.stix.stix_1_0
UPDATER = UPDATER_MOD.STIX_1_0_Updater

PACKAGE_TEMPLATE = \
"""
<stix:STIX_Package
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:stix="http://stix.mitre.org/stix-1"
    xmlns:stixCommon="http://stix.mitre.org/common-1"
    xmlns:indicator="http://stix.mitre.org/Indicator-2"
    xmlns:ttp="http://stix.mitre.org/TTP-1"
    xmlns:stixVocabs="http://stix.mitre.org/default_vocabularies-1"
    xmlns:stix-capec="http://stix.mitre.org/extensions/AP#CAPEC2.5-1"
    xmlns:stix-maec="http://stix.mitre.org/extensions/Malware#MAEC4.0-1"
    xmlns:example="http://example.com/"
    version="1.0">
    %s
</stix:STIX_Package>
"""

class STIX_1_0_Test(unittest.TestCase):
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

class MotivationVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.STIX_1_0_Updater
    VOCAB_KLASS = UPDATER_MOD.MotivationVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <stix:Indicators>
        <stix:Indicator xsi:type="indicator:IndicatorType" version='2.0'>
            <indicator:Type xsi:type="stixVocabs:MotivationVocab-1.0">Ideological - Anti-Establisment</indicator:Type>
        </stix:Indicator>
    </stix:Indicators>
    """
    XML = PACKAGE_TEMPLATE % (VOCAB_XML)


class POSVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.STIX_1_0_Updater
    VOCAB_KLASS = UPDATER_MOD.PlanningAndOperationalSupportVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <stix:Indicators>
        <stix:Indicator xsi:type="indicator:IndicatorType" version='2.0'>
            <indicator:Type xsi:type="stixVocabs:PlanningAndOperationalSupportVocab-1.0">Planning </indicator:Type>
        </stix:Indicator>
    </stix:Indicators>
    """
    XML = PACKAGE_TEMPLATE % (VOCAB_XML)

class DisallowedMAEC(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedMAEC
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Behavior>
                <ttp:Malware>
                    <ttp:Malware_Instance xsi:type="stix-maec:MAEC4.0InstanceType">
                        <stix-maec:MAEC/>
                    </ttp:Malware_Instance>
                </ttp:Malware>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)


class DisallowedMalware(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedMalware
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Behavior>
                <ttp:Malware>
                    <ttp:Malware_Instance xsi:type="stix-maec:MAEC4.0InstanceType">
                        <stix-maec:MAEC/>
                    </ttp:Malware_Instance>
                </ttp:Malware>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)

class DisallowedCAPEC(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedCAPEC
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Behavior>
                <ttp:Attack_Patterns>
                    <ttp:Attack_Pattern xsi:type="stix-capec:CAPEC2.5InstanceType">
                        <stix-capec:CAPEC Name="This cannot be translated" Status="Draft"/>
                    </ttp:Attack_Pattern>
                </ttp:Attack_Patterns>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)


class DisallowedAttackPatterns(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedAttackPatterns
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Behavior>
                <ttp:Attack_Patterns>
                    <ttp:Attack_Pattern xsi:type="stix-capec:CAPEC2.5InstanceType">
                        <stix-capec:CAPEC Name="This cannot be translated" Status="Draft"/>
                    </ttp:Attack_Pattern>
                </ttp:Attack_Patterns>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)


if __name__ == "__main__":
    unittest.main()