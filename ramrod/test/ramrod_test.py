# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.stix
import ramrod.cybox


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
        cls._bad_version = StringIO(cls.GOOD_VERSION_XML)
        cls._upgradable = StringIO(cls.UPGRADABLE_XML)
        cls._no_version = StringIO(cls.NO_VERSION_XML)

    def test_invalid_supplied_from_version(self):
        self.assertRaises(
            ramrod.InvalidVersionError,
            ramrod.update, self._upgradable, from_=42
        )

    def test_invalid_supplied_to_version(self):
        self.assertRaises(
            ramrod.InvalidVersionError,
            ramrod.update, self._upgradable, to_=42
        )

    def test_invalid_input_version(self):
        self.assertRaises(
            ramrod.InvalidVersionError,
            ramrod.update, self._bad_version
        )

    def test_no_input_version(self):
        self.assertRaises(
            ramrod.UnknownVersionError,
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
        cls._bad_version = StringIO(cls.GOOD_VERSION_XML)
        cls._upgradable = StringIO(cls.UPGRADABLE_XML)
        cls._no_version = StringIO(cls.NO_VERSION_XML)

    def test_invalid_supplied_from_version(self):
        self.assertRaises(
            ramrod.InvalidVersionError,
            ramrod.update, self._upgradable, from_=42
        )

    def test_invalid_supplied_to_version(self):
        self.assertRaises(
            ramrod.InvalidVersionError,
            ramrod.update, self._upgradable, to_=42
        )

    def test_invalid_input_version(self):
        self.assertRaises(
            ramrod.InvalidVersionError,
            ramrod.update, self._bad_version
        )

    def test_no_input_version(self):
        self.assertRaises(
            ramrod.UnknownVersionError,
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
        cls._cybox_observables = StringIO(cls.OBSERVABLES_XML)
        cls._stix_package = StringIO(cls.STIX_PACKAGE_XML)
        cls._unknown = StringIO(cls.UNKNOWN_XML)

    def test_unknown(self):
        self.assertRaises(
            ramrod.UpdateError,
            ramrod.update, self._unknown
        )

    def test_stix_package(self):
        updated = ramrod.update(self._stix_package)
        self.assertTrue(updated.document)

    def test_cybox_observables(self):
        updated = ramrod.update(self._cybox_observables)
        self.assertTrue(updated.document)


if __name__ == "__main__":
    unittest.main()