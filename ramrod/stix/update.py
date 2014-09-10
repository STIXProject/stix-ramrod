import copy
from lxml import etree

from ramrod import (_BaseUpdater, UpdateError, UnknownVersionError,
                    InvalidVersionError, TAG_XSI_TYPE, NS_XSI)

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')

class STIX_1_0_Updater(_BaseUpdater):
    STIX_VERSION = '1.0'

    NSMAP = {
        'campaign': 'http://stix.mitre.org/Campaign-1',
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
        'yaraTM': 'http://stix.mitre.org/extensions/TestMechanism#YARA-1'
    }

    DISALLOWED_NAMESPACES = (
        'http://stix.mitre.org/extensions/AP#CAPEC2.5-1',
        'http://stix.mitre.org/extensions/Malware#MAEC4.0-1',
    )

    # STIX v1.0 NS => STIX v1.0.1 SCHEMALOC
    UPDATE_SCHEMALOC_MAP = {
        'http://data-marking.mitre.org/Marking-1': 'http://stix.mitre.org/XMLSchema/data_marking/1.0.1/data_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/simple_marking/1.0.1/simple_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.0.1/tlp.xsd',
        'http://stix.mitre.org/Campaign-1': 'http://stix.mitre.org/XMLSchema/campaign/1.0.1/campaign.xsd',
        'http://stix.mitre.org/CourseOfAction-1': 'http://stix.mitre.org/XMLSchema/course_of_action/1.0.1/course_of_action.xsd',
        'http://stix.mitre.org/ExploitTarget-1': 'http://stix.mitre.org/XMLSchema/exploit_target/1.0.1/exploit_target.xsd',
        'http://stix.mitre.org/Incident-1': 'http://stix.mitre.org/XMLSchema/incident/1.0.1/incident.xsd',
        'http://stix.mitre.org/Indicator-2': 'http://stix.mitre.org/XMLSchema/indicator/2.0.1/indicator.xsd',
        'http://stix.mitre.org/TTP-1': 'http://stix.mitre.org/XMLSchema/ttp/1.0.1/ttp.xsd',
        'http://stix.mitre.org/ThreatActor-1': 'http://stix.mitre.org/XMLSchema/threat_actor/1.0.1/threat_actor.xsd',
        'http://stix.mitre.org/common-1': 'http://stix.mitre.org/XMLSchema/common/1.0.1/stix_common.xsd',
        'http://stix.mitre.org/default_vocabularies-1': 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.0.1/stix_default_vocabularies.xsd',
        # 'http://stix.mitre.org/extensions/AP#CAPEC2.5-1': 'http://stix.mitre.org/XMLSchema/extensions/attack_pattern/capec_2.6.1/1.0.1/capec_2.6.1.xsd',  # DISALLOWED
        'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/address/ciq_address_3.0/1.0.1/ciq_address_3.0.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_identity_3.0/1.0.1/ciq_identity_3.0.xsd',
        # 'http://stix.mitre.org/extensions/Malware#MAEC4.0-1': 'http://stix.mitre.org/XMLSchema/extensions/malware/maec_4.0.1/1.0.1/maec_4.0.1.xsd',  # DISALLOWED
        'http://stix.mitre.org/extensions/StructuredCOA#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/structured_coa/generic/1.0.1/generic.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/generic/1.0.1/generic.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/oval_5.10/1.0.1/oval_5.10.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/open_ioc_2010/1.0.1/open_ioc_2010.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.0.1/snort.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#YARA-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.0.1/yara.xsd',
        'http://stix.mitre.org/extensions/Vulnerability#CVRF-1': 'http://stix.mitre.org/XMLSchema/extensions/vulnerability/cvrf_1.1/1.0.1/cvrf_1.1.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.0.1/stix_core.xsd'
    }

    UPDATE_VOCAB_NAMES = {
        'MotivationVocab-1.0': 'MotivationVocab-1.0.1',
        'PlanningAndOperationalSupportVocab-1.0': 'PlanningAndOperationalSupportVocab-1.0.1'
    }

    UPDATE_VOCAB_TERMS = {
        "Ideological - Anti-Establisment": "Ideological - Anti-Establishment",
        "Planning - Open-Source Intelligence (OSINT) Gethering": "Planning - Open-Source Intelligence (OSINT) Gathering",
        "Planning ": "Planning"
    }


    def __init__(self):
        self.cleaned_fields = None


    def _get_disallowed(self, root):
        nsmap = {"xsi":  "http://www.w3.org/2001/XMLSchema-instance"}
        xpath = "//*[@xsi:type]"
        nodes = root.xpath(xpath, namespaces=nsmap)

        disallowed = ("MAEC4.0InstanceType", "CAPEC2.5InstanceType")

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

        * STIX_Package/@version != '1.0'
        * MAEC 4.0 Malware extension
        * CAPEC 2.5 Attack Pattern extension

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

        disallowed = self._get_disallowed(root)
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


    def _update_versions(self, root):
        xpath_versions = ("//stix:STIX_Package | "
                          "indicator:Indicator[@version] | "
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
            tag = etree.QName(node)
            name = tag.localname

            if name == "Indicator":
                node.attrib['version'] = '2.0.1'
            else:
                node.attrib['version'] = '1.0.1'


    def _update(self, root):
        updated = self._update_namespaces(root)

        self._update_schemalocs(updated)
        self._update_versions(updated)
        self._update_vocabs(updated)

        return updated


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

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.
            force: If True, untranslatable fields are removed from the input
                document. If False, an UpdateError is raised
                when an untranslatable field is encountered.

        Returns:
            An updated copy of the input `root` document. If `force` is
            ``True``, untranslatable items are removed from the document.

            The ``cleaned_fields`` instance attribute contains a copy of
            all the fields that were removed after calling ``updated()``.

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
            updated = self._update(root)
        except UpdateError:
            if force:
                self.clean(root)
                updated = self._update(root)
            else:
                raise

        return updated


class STIX_1_0_1_Updater(_BaseUpdater):
    NSMAP = {
        'campaign': 'http://stix.mitre.org/Campaign-1',
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
        'yaraTM': 'http://stix.mitre.org/extensions/TestMechanism#YARA-1'
    }

    # STIX v1.1 NS => SCHEMALOC
    UPDATE_SCHEMALOC_MAP = {
        'http://data-marking.mitre.org/Marking-1': 'http://stix.mitre.org/XMLSchema/data_marking/1.1/data_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/simple/1.1/simple_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.1/tlp_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/terms_of_use/1.0/terms_of_use_marking.xsd',
        'http://stix.mitre.org/Campaign-1': 'http://stix.mitre.org/XMLSchema/campaign/1.1/campaign.xsd',
        'http://stix.mitre.org/CourseOfAction-1': 'http://stix.mitre.org/XMLSchema/course_of_action/1.1/course_of_action.xsd',
        'http://stix.mitre.org/ExploitTarget-1': 'http://stix.mitre.org/XMLSchema/exploit_target/1.1/exploit_target.xsd',
        'http://stix.mitre.org/Incident-1': 'http://stix.mitre.org/XMLSchema/incident/1.1/incident.xsd',
        'http://stix.mitre.org/Indicator-2': 'http://stix.mitre.org/XMLSchema/indicator/2.1/indicator.xsd',
        'http://stix.mitre.org/TTP-1': 'http://stix.mitre.org/XMLSchema/ttp/1.1/ttp.xsd',
        'http://stix.mitre.org/ThreatActor-1': 'http://stix.mitre.org/XMLSchema/threat_actor/1.1/threat_actor.xsd',
        'http://stix.mitre.org/common-1': 'http://stix.mitre.org/XMLSchema/common/1.1/stix_common.xsd',
        'http://stix.mitre.org/default_vocabularies-1': 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.0/stix_default_vocabularies.xsd',
        'http://stix.mitre.org/extensions/AP#CAPEC2.7-1': 'http://stix.mitre.org/XMLSchema/extensions/attack_pattern/capec_2.7/1.0/capec_2.7_attack_pattern.xsd',
        'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/address/ciq_3.0/1.1/ciq_3.0_address.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.1/ciq_3.0_identity.xsd',
        'http://stix.mitre.org/extensions/Malware#MAEC4.1-1': 'http://stix.mitre.org/XMLSchema/extensions/malware/maec_4.1/1.0/maec_4.1_malware.xsd',
        'http://stix.mitre.org/extensions/StructuredCOA#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/structured_coa/generic/1.1/generic_structured_coa.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/generic/1.1/generic_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/oval_5.10/1.1/oval_5.10_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/open_ioc_2010/1.1/open_ioc_2010_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.1/snort_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#YARA-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.1/yara_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/Vulnerability#CVRF-1': 'http://stix.mitre.org/XMLSchema/extensions/vulnerability/cvrf_1.1/1.1/cvrf_1.1_vulnerability.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.1/stix_core.xsd',
    }


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
    NSMAP = {
        'TOUMarking': 'http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1',
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
        'yaraTM': 'http://stix.mitre.org/extensions/TestMechanism#YARA-1'
    }

    # STIX v1.1.1 NS => SCHEMALOC
    UPDATE_SCHEMALOC_MAP = {
        'http://data-marking.mitre.org/Marking-1': 'http://stix.mitre.org/XMLSchema/data_marking/1.1.1/data_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/simple/1.1.1/simple_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.1.1/tlp_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/terms_of_use/1.0.1/terms_of_use_marking.xsd',
        'http://stix.mitre.org/Campaign-1': 'http://stix.mitre.org/XMLSchema/campaign/1.1.1/campaign.xsd',
        'http://stix.mitre.org/CourseOfAction-1': 'http://stix.mitre.org/XMLSchema/course_of_action/1.1.1/course_of_action.xsd',
        'http://stix.mitre.org/ExploitTarget-1': 'http://stix.mitre.org/XMLSchema/exploit_target/1.1.1/exploit_target.xsd',
        'http://stix.mitre.org/Incident-1': 'http://stix.mitre.org/XMLSchema/incident/1.1.1/incident.xsd',
        'http://stix.mitre.org/Indicator-2': 'http://stix.mitre.org/XMLSchema/indicator/2.1.1/indicator.xsd',
        'http://stix.mitre.org/TTP-1': 'http://stix.mitre.org/XMLSchema/ttp/1.1.1/ttp.xsd',
        'http://stix.mitre.org/ThreatActor-1': 'http://stix.mitre.org/XMLSchema/threat_actor/1.1.1/threat_actor.xsd',
        'http://stix.mitre.org/common-1': 'http://stix.mitre.org/XMLSchema/common/1.1.1/stix_common.xsd',
        'http://stix.mitre.org/default_vocabularies-1': 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd',
        'http://stix.mitre.org/extensions/AP#CAPEC2.7-1': 'http://stix.mitre.org/XMLSchema/extensions/attack_pattern/capec_2.7/1.0.1/capec_2.7_attack_pattern.xsd',
        'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/address/ciq_3.0/1.1.1/ciq_3.0_address.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.1.1/ciq_3.0_identity.xsd',
        'http://stix.mitre.org/extensions/Malware#MAEC4.1-1': 'http://stix.mitre.org/XMLSchema/extensions/malware/maec_4.1/1.0.1/maec_4.1_malware.xsd',
        'http://stix.mitre.org/extensions/StructuredCOA#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/structured_coa/generic/1.1.1/generic_structured_coa.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/generic/1.1.1/generic_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/oval_5.10/1.1.1/oval_5.10_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/open_ioc_2010/1.1.1/open_ioc_2010_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.1.1/snort_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#YARA-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.1.1/yara_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/Vulnerability#CVRF-1': 'http://stix.mitre.org/XMLSchema/extensions/vulnerability/cvrf_1.1/1.1.1/cvrf_1.1_vulnerability.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.1.1/stix_core.xsd'
    }


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

