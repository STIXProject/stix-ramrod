# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.cybox
import ramrod.utils as utils

class Cybox_2_0_Test(unittest.TestCase):
    UPDATER = ramrod.cybox.Cybox_2_0_Updater

    XML_VERSIONS = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="2" cybox_minor_version="0">
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


class CommaTest(unittest.TestCase):
    UPDATER = ramrod.cybox.Cybox_2_0_Updater

    ATTACKERS = [
        'attacker@example.com',
        'attacker1@example.com',
        'attacker@bad.example.com'
    ]

    ESCAPED = "Et tu&comma; Brute?"
    UNESCAPED = ESCAPED.replace("&comma;", ",")

    NEW_DELIMITER = "##comma##"

    XML_COMMAS = \
    """
    <cybox:Object xsi:type="EmailMessageObj:EmailMessageObjectType"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
        xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2">
        <cybox:Properties>
            <EmailMessageObj:Header>
                <EmailMessageObj:From category="e-mail">
                    <AddressObj:Address_Value condition="Equals" apply_condition="ANY">%s</AddressObj:Address_Value>
                </EmailMessageObj:From>
                <EmailMessageObj:Subject condition="Equals"><![CDATA[%s]]></EmailMessageObj:Subject>
            </EmailMessageObj:Header>
        </cybox:Properties>
    </cybox:Object>
    """ % (",".join(ATTACKERS), ESCAPED)

    @classmethod
    def setUpClass(cls):
        cls._xml = StringIO(cls.XML_COMMAS)

    def test_lists(self):
        nsmap = {'AddressObj': 'http://cybox.mitre.org/objects#AddressObject-2'}
        updater = self.UPDATER()
        root = utils.get_etree_root(self._xml)

        updater._update_lists(root)
        address_value = root.xpath('.//AddressObj:Address_Value', namespaces=nsmap)[0].text
        self.assertEqual(address_value, self.NEW_DELIMITER.join(self.ATTACKERS))

    def test_commas(self):
        nsmap = {'EmailMessageObj': 'http://cybox.mitre.org/objects#EmailMessageObject-2'}
        updater = self.UPDATER()
        root = utils.get_etree_root(self._xml)

        updater._update_lists(root)
        subject = root.xpath('.//EmailMessageObj:Subject', namespaces=nsmap)[0].text
        self.assertEqual(subject, self.UNESCAPED)



class OptionalsTest(unittest.TestCase):
    UPDATER = ramrod.cybox.Cybox_2_0_Updater





if __name__ == "__main__":
    unittest.main()