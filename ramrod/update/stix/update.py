from ramrod.update import (UnknownVersionException,
    UntranslatableFieldException, UpdateException)

class STIXUpdater(object):
    def __init__(self):
        pass

    def can_update_1_0(self, root):
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


    def can_update_1_0_1(self, root):
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

    def can_update_1_1(self, root):
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

    def update_stix_1_0(self, root):
        return True

    def update_stix_1_0_1(self, root):
        return True

    def update_stix_1_1(self, root):
        return True

    def can_update(self, root, version='1.1.1'):
        return True

    def update_stix(self, root, version='1.1.1'):
        self.can_update(root, version)

        try:
            version = root.attrib['version']
        except:
            pass