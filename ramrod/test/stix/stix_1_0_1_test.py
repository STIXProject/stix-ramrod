# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.stix
import ramrod.stix.stix_1_0_1
import ramrod.utils as utils
from ramrod.test import (_BaseVocab, _BaseDisallowed, _BaseTrans)

UPDATER_MOD = ramrod.stix.stix_1_0_1
UPDATER = UPDATER_MOD.STIX_1_0_1_Updater

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
    xmlns:stix-capec="http://stix.mitre.org/extensions/AP#CAPEC2.6-1"
    xmlns:stix-maec="http://stix.mitre.org/extensions/Malware#MAEC4.0-1"
    xmlns:example="http://example.com/"
    xmlns:ramrod="http://ramrod.test/"
    version="1.0.1">
    %s
</stix:STIX_Package>
"""

class STIX_1_0_1_Test(unittest.TestCase):
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
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    VOCAB_KLASS = UPDATER_MOD.IndicatorTypeVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <stix:Indicators>
        <stix:Indicator xsi:type="indicator:IndicatorType">
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.0">C2</indicator:Type>
        </stix:Indicator>
    </stix:Indicators>
    """
    XML = PACKAGE_TEMPLATE % (VOCAB_XML)

class MotivationVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    VOCAB_KLASS = UPDATER_MOD.MotivationVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <stix:Indicators>
        <stix:Indicator xsi:type="indicator:IndicatorType">
            <indicator:Type xsi:type="stixVocabs:MotivationVocab-1.0.1">Policital</indicator:Type>
        </stix:Indicator>
    </stix:Indicators>
    """
    XML = PACKAGE_TEMPLATE % (VOCAB_XML)


class DisallowedMAEC(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
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
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
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
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedCAPEC
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Behavior>
                <ttp:Attack_Patterns>
                    <ttp:Attack_Pattern xsi:type="stix-capec:CAPEC2.6InstanceType">
                        <stix-capec:CAPEC Name="This cannot be translated" Status="Draft"/>
                    </ttp:Attack_Pattern>
                </ttp:Attack_Patterns>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)


class DisallowedAttackPatterns(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedAttackPatterns
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Behavior>
                <ttp:Attack_Patterns>
                    <ttp:Attack_Pattern xsi:type="stix-capec:CAPEC2.6InstanceType">
                        <stix-capec:CAPEC Name="This cannot be translated" Status="Draft"/>
                    </ttp:Attack_Pattern>
                </ttp:Attack_Patterns>
            </ttp:Behavior>
        </stix:TTP>
    </stix:TTPs>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)


class DisallowedDateTime(_BaseDisallowed):
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedDateTime
    DISALLOWED_COUNT = 2
    DISALLOWED_XML = \
    """
     <stix:Campaigns>
        <stix:Campaign xsi:type="campaign:CampaignType">
            <campaign:Activity xsi:type="ramrod:NOT_A_REAL_CONCRETE_IMPL_ActivityType">
                <stixCommon:Date_Time>2002-05-30T09:30:10+06:00</stixCommon:Date_Time>
            </campaign:Activity>
            <campaign:Activity xsi:type="ramrod:NOT_A_REAL_CONCRETE_IMPL_ActivityType">
                <stixCommon:Date_Time>THIS CANNOT BE TRANSLATED</stixCommon:Date_Time>
            </campaign:Activity>
            <campaign:Activity xsi:type="ramrod:NOT_A_REAL_CONCRETE_IMPL_ActivityType">
                <stixCommon:Date_Time>THIS CANNOT BE TRANSLATED</stixCommon:Date_Time>
            </campaign:Activity>
        </stix:Campaign>
    </stix:Campaigns>
    """
    XML = PACKAGE_TEMPLATE % (DISALLOWED_XML)


class TransCommonContributors(_BaseTrans):
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransCommonContributors
    TRANS_XPATH = "//stix:Information_Source/stixCommon:ContributingSources//stixCommon:Source/stixCommon:Identity/stixCommon:Name"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1  # Just instances of  stixCommon:Contributors are looked for
    TRANS_XML = \
    """
    <stix:Information_Source>
        <stixCommon:Contributors>
            <stixCommon:Contributor>
                <stixCommon:Name>{0}</stixCommon:Name>
            </stixCommon:Contributor>
            <stixCommon:Contributor>
                <stixCommon:Name>{0}</stixCommon:Name>
            </stixCommon:Contributor>
        </stixCommon:Contributors>
    </stix:Information_Source>
    """.format(TRANS_VALUE)
    XML = PACKAGE_TEMPLATE % (TRANS_XML)


class TransTTPExploitTargets(_BaseTrans):
    UPDATER = UPDATER_MOD.STIX_1_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransTTPExploitTargets
    TRANS_XPATH = "//stix:TTP/ttp:Exploit_Targets//stixCommon:Exploit_Target//et:Title"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 3
    TRANS_XML = \
    """
    <stix:TTPs>
        <stix:TTP xsi:type="ttp:TTPType">
            <ttp:Exploit_Targets>
                <stixCommon:Exploit_Target xsi:type="et:ExploitTargetType">
                    <et:Title>{0}</et:Title>
                </stixCommon:Exploit_Target>
                <stixCommon:Exploit_Target xsi:type="et:ExploitTargetType">
                    <et:Title>{0}</et:Title>
                </stixCommon:Exploit_Target>
                <stixCommon:Exploit_Target xsi:type="et:ExploitTargetType">
                    <et:Title>{0}</et:Title>
                </stixCommon:Exploit_Target>
            </ttp:Exploit_Targets>
        </stix:TTP>
    </stix:TTPs>
    """.format(TRANS_VALUE)
    XML = PACKAGE_TEMPLATE % (TRANS_XML)

if __name__ == "__main__":
    unittest.main()