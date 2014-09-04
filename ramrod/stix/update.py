import copy

from ramrod import *

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')


class STIX_1_0_Updater(_BaseUpdater):
    STIX_VERSION = '1.0'
    NSMAP = {'campaign': 'http://stix.mitre.org/Campaign-1',
             'stix-capec': 'http://stix.mitre.org/extensions/AP#CAPEC2.5-1',
             'ciqAddress': 'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1',
             'stix-ciq': 'http://stix.mitre.org/extensions/Identity#stix-ciq3.0-1',
             'coa': 'http://stix.mitre.org/CourseOfAction-1',
             'et': 'http://stix.mitre.org/ExploitTarget-1',
             'genericStructuredCOA': 'http://stix.mitre.org/extensions/StructuredCOA#Generic-1',
             'genericTM': 'http://stix.mitre.org/extensions/TestMechanism#Generic-1',
             'incident': 'http://stix.mitre.org/Incident-1',
             'indicator': 'http://stix.mitre.org/Indicator-2',
             'stix-maec': 'http://stix.mitre.org/extensions/Malware#MAEC4.0-1',
             'marking': 'http://data-marking.mitre.org/Marking-1',
             'stix-openioc': 'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1',
             'stix-oval': 'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1',
             'simpleMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1',
             'snortTM': 'http://stix.mitre.org/extensions/TestMechanism#Snort-1',
             'stix': 'http://stix.mitre.org/stix-1',
             'stixCommon': 'http://stix.mitre.org/common-1',
             'stixVocabs': 'http://stix.mitre.org/default_vocabularies-1',
             'ta': 'http://stix.mitre.org/ThreatActor-1',
             'tlpMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1',
             'ttp': 'http://stix.mitre.org/TTP-1',
             'stix-cvrf': 'http://stix.mitre.org/extensions/Vulnerability#CVRF-1',
             'yaraTM': 'http://stix.mitre.org/extensions/TestMechanism#YARA-1'}


    def __init__(self):
        self.cleaned_fields = None


    def _get_disallowed(self, root):
        nsmap = {"xsi":  "http://www.w3.org/2001/XMLSchema-instance"}
        xpath = "//*[@xsi:type]"
        nodes = root.xpath(xpath, namespaces=nsmap)

        disallowed = ("MAEC4.0InstanceType", "CAPEC2.5InstanceType",
                      "stix-ciq3.0InstanceType")

        instances = []
        for node in nodes:
            xsi_type = node.attrib[TAG_XSI_TYPE]
            type_ = xsi_type.split(":")[1]

            if type_ in disallowed:
                instances.append(type_)

        return instances


    def _check_version(self, root):
        expected = STIX_1_0_Updater.STIX_VERSION
        found = root.attrib.get('version')

        if not found:
            raise UnknownVersionError()

        if found != expected:
            raise InvalidVersionError(expected, found)


    def check_update(self, root):
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

        Raises:
            UnknownVersionError: If the input document does not have a version.
            InvalidVersionError: If the version of the input document
                is not ``1.0``.
            UpdateError: If the input document contains fields which cannot
                be updated.

        """
        self._check_version(root)

        disallowed = self._get_disallowed()
        if disallowed:
            raise UpdateError(disallowed)



    def clean(self, root):
        """Attempts to remove untranslatable fields from the input document.

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.

        Returns:
            list: A list of lxml.etree._Element instances of objects removed
            from the input document.

        """
        removed = []
        disallowed = self._get_disallowed(root)

        for node in disallowed:
            dup = copy.deepcopy(node)
            self._remove_xml_node(node)
            removed.append(dup)

        self.cleaned_fields = tuple(removed)


    def _remove_schemalocations(self, root):
        self._remove_xml_attribute(root, TAG_SCHEMALOCATION)



    def _update_versions(self, root):
        xpath_versions = ("//indicator:Indicator[@version] | "
                          "stix:Indicator[@version] | "
                          "stixCommon:Indicator[@version] | "
                          "incident:Incident[@version] | "
                          "stix:Incident[@version] | "
                          "stixCommon:Incident[@version] | "
                          "ttp:TTP[@version] | "
                          "stix:TTP[@version] | "
                          "stixCommon:TTP[@version] | "
                          "coa:Course_Of_Action[@version] | "
                          "stix:Course_Of_Action[@version] | "
                          "stixCommon:Course_Of_Action[@version] |"
                          "ta:Threat_Actor[@version]| "
                          "stix:Threat_Actor[@version] | "
                          "stixCommon:Threat_Actor[@version] | "
                          "campaign:Campaign[@version] | "
                          "stix:Campaign[@version] | "
                          "stixCommon:Campaign[@version] | "
                          "et:Exploit_Target[@version] | "
                          "stix:Exploit_Target[@version] | "
                          "stixCommon:Exploit_Target[@version]")

        nodes = root.xpath(xpath_versions, namespaces=self.NSMAP)
        for node in nodes:
            tag = node.tag
            name = tag[tag.index("}")+1:]

            if name == "Indicator":
                node.attrib['version'] = '2.0.1'
            else:
                node.attrib['version'] = '1.0.1'


    def _update_vocabs(self, root):
        vocabs = {
            'MotivationVocab-1.0': 'MotivationVocab-1.0.1',
            'PlanningAndOperationalSupportVocab-1.0': 'PlanningAndOperationalSupportVocab-1.0.1'
        }

        values = {
            "Ideological - Anti-Establisment": "Ideological - Anti-Establishment",
            "Planning - Open-Source Intelligence (OSINT) Gethering": "Planning - Open-Source Intelligence (OSINT) Gathering",
            "Planning ": "Planning"
        }

        nsmap = {"xsi":  NS_XSI}
        xpath = "//*[@xsi:type]"
        nodes = root.xpath(xpath, namespaces=nsmap)

        for node in nodes:
            xsi_type = node.attrib[TAG_XSI_TYPE]
            alias, type_ = xsi_type.split(":")

            if type_ in vocabs:
                # Update the xsi:type attribute to identify the new
                # controlled vocabulary
                new_xsi_type = "%s:%s" % (alias, vocabs[type_])
                node.attrib[TAG_XSI_TYPE] = new_xsi_type

                # Update the node value if there is a new value in the updated
                # controlled vocabulary
                value = node.text
                node.text = values.get(value, value)

    def _update(self, root):
        self._remove_schemalocations(root)
        self._update_versions(root)
        self._update_vocabs(root)


    def update(self, root, force=False):
        """Attempts to update an input STIX v1.0 document to STIX v1.0.1.

        This method performs the following changes:
        * Removes schemaLocations
        * STIX_Package/@version 1.0 => 1.0.1
        * MotivationVocab 1.0 => 1.0.1
          * "Ideological - Anti-Establisment" => "Ideological - Anti-Establishment"
        * PlanningAndOperationalSupportVocab 1.0 => 1.0.1
          * "Planning " => "Planning"
          * "Planning - Open-Source Intelligence (OSINT) Gethering" => "Planning - Open-Source Intelligence (OSINT) Gathering"
        * Threat_Actor/@version 1.0 => 1.0.1
        * TTP/@version 1.0 => 1.0.1
        * Campaign/@version 1.0 => 1.0.1
        * COA/@version 1.0 => 1.0.1
        * Incident/@version 1.0 => 1.0.1
        * Indicator/@version 2.0 => 2.0.1
        * Campaign/@version 1.0 => 1.0.1
        * Exploit Target@version 1.0 => 1.0.1

        Untranslatable items:
        * MAEC 4.0 Malware extension
        * CAPEC 2.5 Attack Pattern extension
        * CIQ Identity 3.0 Extension

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.
            force: If True, untranslatable fields are removed from the input
                document. If False, an UpdateError is raised
                when an untranslatable field is encountered.

        Returns:
            None

        Raises:
            UnknownVersionError: If the input document does not have a version.
            InvalidVersionError: If the version of the input document
                is not ``1.0``.
            UntranslatableFieldsError: If the`force` param is set to
                ``False`` and an untranslatable field is encountered in the
                input document.

        """

        try:
            self.check_update(root)
            self._update(root)
        except UpdateError:
            if force:
                self.clean(root)
                self._update(root)

        return root


class STIX_1_0_1_Updater(_BaseUpdater):
    NSMAP = {'campaign': 'http://stix.mitre.org/Campaign-1',
             'stix-capec': 'http://stix.mitre.org/extensions/AP#CAPEC2.6-1',
             'ciqAddress': 'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1',
             'coa': 'http://stix.mitre.org/CourseOfAction-1',
             'et': 'http://stix.mitre.org/ExploitTarget-1',
             'genericStructuredCOA': 'http://stix.mitre.org/extensions/StructuredCOA#Generic-1',
             'genericTM': 'http://stix.mitre.org/extensions/TestMechanism#Generic-1',
             'incident': 'http://stix.mitre.org/Incident-1',
             'indicator': 'http://stix.mitre.org/Indicator-2',
             'stix-maec': 'http://stix.mitre.org/extensions/Malware#MAEC4.0-1',
             'marking': 'http://data-marking.mitre.org/Marking-1',
             'stix-openioc': 'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1',
             'stix-oval': 'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1',
             'simpleMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1',
             'snortTM': 'http://stix.mitre.org/extensions/TestMechanism#Snort-1',
             'stix': 'http://stix.mitre.org/stix-1',
             'stix-ciq': 'http://stix.mitre.org/extensions/Identity#stix-ciq3.0-1',
             'stixCommon': 'http://stix.mitre.org/common-1',
             'stixVocabs': 'http://stix.mitre.org/default_vocabularies-1',
             'ta': 'http://stix.mitre.org/ThreatActor-1',
             'tlpMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1',
             'ttp': 'http://stix.mitre.org/TTP-1',
             'stix-cvrf': 'http://stix.mitre.org/extensions/Vulnerability#CVRF-1',
             'yaraTM': 'http://stix.mitre.org/extensions/TestMechanism#YARA-1'}


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


class STIX_1_1_Updater(_BaseUpdater):
    NSMAP = {'TOUMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1',
             'campaign': 'http://stix.mitre.org/Campaign-1',
             'coa': 'http://stix.mitre.org/CourseOfAction-1',
             'et': 'http://stix.mitre.org/ExploitTarget-1',
             'genericStructuredCOA': 'http://stix.mitre.org/extensions/StructuredCOA#Generic-1',
             'genericTM': 'http://stix.mitre.org/extensions/TestMechanism#Generic-1',
             'incident': 'http://stix.mitre.org/Incident-1',
             'indicator': 'http://stix.mitre.org/Indicator-2',
             'marking': 'http://data-marking.mitre.org/Marking-1',
             'simpleMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1',
             'snortTM': 'http://stix.mitre.org/extensions/TestMechanism#Snort-1',
             'stix': 'http://stix.mitre.org/stix-1',
             'stix-capec': 'http://stix.mitre.org/extensions/AP#CAPEC2.7-1',
             'stix-ciqaddress': 'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1',
             'stix-stix-ciq': 'http://stix.mitre.org/extensions/Identity#stix-ciq3.0-1',
             'stix-cvrf': 'http://stix.mitre.org/extensions/Vulnerability#CVRF-1',
             'stix-maec': 'http://stix.mitre.org/extensions/Malware#MAEC4.1-1',
             'stix-openioc': 'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1',
             'stix-oval': 'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1',
             'stixCommon': 'http://stix.mitre.org/common-1',
             'stixVocabs': 'http://stix.mitre.org/default_vocabularies-1',
             'ta': 'http://stix.mitre.org/ThreatActor-1',
             'tlpMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1',
             'ttp': 'http://stix.mitre.org/TTP-1',
             'yaraTM': 'http://stix.mitre.org/extensions/TestMechanism#YARA-1'}


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
