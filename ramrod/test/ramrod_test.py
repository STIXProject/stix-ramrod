# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import unittest
import StringIO

# external
from lxml import etree

# internal
import ramrod
import ramrod.stix
import ramrod.cybox
import ramrod.errors as errors


class STIXVersionTest(unittest.TestCase):

    NO_VERSION_XML = \
    """
     <stix:STIX_Package
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:stix="http://stix.mitre.org/stix-1"
        id="example:STIXPackage-33fe3b22-0201-47cf-85d0-97c02164528d">
    </stix:STIX_Package>
    """

    GOOD_VERSION_XML = \
    """
    <stix:STIX_Package
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:stix="http://stix.mitre.org/stix-1"
        id="example:STIXPackage-33fe3b22-0201-47cf-85d0-97c02164528d"
        version="42">
    </stix:STIX_Package>
    """

    UPGRADABLE_XML = \
    """
    <stix:STIX_Package
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:stix="http://stix.mitre.org/stix-1"
        id="example:STIXPackage-33fe3b22-0201-47cf-85d0-97c02164528d"
        version="1.0">
    </stix:STIX_Package>
    """

    @classmethod
    def setUpClass(cls):
        cls._bad_version = StringIO.StringIO(cls.GOOD_VERSION_XML)
        cls._upgradable = StringIO.StringIO(cls.UPGRADABLE_XML)
        cls._no_version = StringIO.StringIO(cls.NO_VERSION_XML)

    def test_invalid_supplied_from_version(self):
        self.assertRaises(
            errors.InvalidVersionError,
            ramrod.update, self._upgradable, from_=42
        )

    def test_invalid_supplied_to_version(self):
        self.assertRaises(
            errors.InvalidVersionError,
            ramrod.update, self._upgradable, to_=42
        )

    def test_invalid_input_version(self):
        self.assertRaises(
            errors.InvalidVersionError,
            ramrod.update, self._bad_version
        )

    def test_no_input_version(self):
        self.assertRaises(
            errors.UnknownVersionError,
            ramrod.update, self._no_version
        )


class CYBOXVersionTest(unittest.TestCase):

    NO_VERSION_XML = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1">
    </cybox:Observables>
    """

    GOOD_VERSION_XML = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="4" cybox_minor_version="2">
    </cybox:Observables>
    """

    UPGRADABLE_XML = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="2" cybox_minor_version="0">
    </cybox:Observables>
    """

    @classmethod
    def setUpClass(cls):
        cls._bad_version = StringIO.StringIO(cls.GOOD_VERSION_XML)
        cls._upgradable = StringIO.StringIO(cls.UPGRADABLE_XML)
        cls._no_version = StringIO.StringIO(cls.NO_VERSION_XML)

    def test_invalid_supplied_from_version(self):
        self.assertRaises(
            errors.InvalidVersionError,
            ramrod.update, self._upgradable, from_=42
        )

    def test_invalid_supplied_to_version(self):
        self.assertRaises(
            errors.InvalidVersionError,
            ramrod.update, self._upgradable, to_=42
        )

    def test_invalid_input_version(self):
        self.assertRaises(
            errors.InvalidVersionError,
            ramrod.update, self._bad_version
        )

    def test_no_input_version(self):
        self.assertRaises(
            errors.UnknownVersionError,
            ramrod.update, self._no_version
        )


class DocumentTest(unittest.TestCase):
    STIX_PACKAGE_XML = \
    """
    <stix:STIX_Package
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:stix="http://stix.mitre.org/stix-1"
        id="example:STIXPackage-33fe3b22-0201-47cf-85d0-97c02164528d"
        version="1.0">
    </stix:STIX_Package>
    """

    OBSERVABLES_XML = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="2" cybox_minor_version="0">
    </cybox:Observables>
    """

    UNKNOWN_XML = \
    """
    <Unknown id="foobar-1"/>
    """

    @classmethod
    def setUpClass(cls):
        cls._cybox_observables = StringIO.StringIO(cls.OBSERVABLES_XML)
        cls._stix_package = StringIO.StringIO(cls.STIX_PACKAGE_XML)
        cls._unknown = StringIO.StringIO(cls.UNKNOWN_XML)

    def test_unknown(self):
        self.assertRaises(
            errors.UpdateError,
            ramrod.update, self._unknown
        )

    def test_stix_package(self):
        updated = ramrod.update(self._stix_package)
        self.assertTrue(updated.document)

    def test_cybox_observables(self):
        updated = ramrod.update(self._cybox_observables)
        self.assertTrue(updated.document)


class ResultDocumentTest(unittest.TestCase):
    XML = """<test>foobar</test>"""

    @classmethod
    def setUpClass(cls):
        cls._xml = etree.fromstring(cls.XML)
        cls._result = ramrod.ResultDocument(cls._xml)

    def test_unicode(self):
        self.assertEqual(unicode(self.XML).strip(), unicode(self._result).strip())

    def test_str(self):
        self.assertEqual(str(self.XML).strip(), str(self._result).strip())

    def test_as_element(self):
        self.assertTrue(isinstance(self._result.as_element(), etree._Element))

    def test_as_element_tree(self):
        self.assertTrue(
            isinstance(self._result.as_element_tree(), etree._ElementTree)
        )

    def test_as_stringio(self):
        sio = self._result.as_stringio()
        val = sio.getvalue().strip()
        self.assertEqual(val, self.XML)

if __name__ == "__main__":
    unittest.main()