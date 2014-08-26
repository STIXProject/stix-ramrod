from ramrod.update import (UnknownVersionException,
    UntranslatableFieldException, UpdateException, IncorrectVersionException)

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')

class STIX_1_0_Updater(object):
    def __init__(self):
        pass

    def can_update(self, root):
        """Determines if the input document can be upgraded from STIX v1.0 to
        STIX v1.0.1.

        A STIX document cannot be upgraded if any of the following constructs
        are found in the document:

        * MAEC 4.0 Malware extension
        * CAPEC 2.5 Attack Pattern extension
        * CIQ Identity 3.0 Extension

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.

        Returns:
            bool: True if the document can be updated, False otherwise.

        """
        nsmap = {"xsi":  "http://www.w3.org/2001/XMLSchema-instance"}
        xpath = "//*[@xsi:type]"
        nodes = root.xpath(xpath, namespaces=nsmap)

        disallowed = ("MAEC4.0InstanceType", "CAPEC2.5InstanceType",
                      "CIQIdentity3.0InstanceType")

        for node in nodes:
            xsi_type = node.attrib["{http://www.w3.org/2001/XMLSchema-instance}type"]
            type_ = xsi_type.split(":")[1]

            if type_ in disallowed:
                return False

        return True

    def clean(self, root):
        pass

    def update(self, root, force=False):
        """Attempts to update an input STIX v1.0 document to STIX v1.0.1

        Args:
            root: TODO fill out
            force: TODO fill out

        Returns:
            None

        Raises:
            IncorrectVersionException: TODO fill out
        
        """
        pass


class STIX_1_0_1_Updater(object):
    def __init__(self):
        pass

    def can_update(self, root):
        """Determines if the input document can be upgraded from STIX v1.0.1
        to STIX v1.1.

        A STIX document cannot be upgraded if any of the following constructs
        are found in the document:

         * TODO: Add constructs

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.

        Returns:
            bool: True if the document can be updated, False otherwise.

        """

    def clean(self, root):
        pass

    def update(self, root, force=False):
        pass


class STIX_1_1_Updater(object):
    def __init__(self):
        pass

    def can_update(self, root):
        """Determines if the input document can be upgraded from STIX v1.1
        to STIX v1.1.1.

        A STIX document cannot be upgraded if any of the following constructs
        are found in the document:

        * TODO: Add constructs

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.

        Returns:
            bool: True if the document can be updated, False otherwise.

        """

    def clean(self, root):
        pass

    def update(self, root, force=False):
        pass


def update(doc, version='1.1.1', force=False):
    pass