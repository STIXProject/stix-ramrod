from lxml import etree
from ramrod import (_Vocab, UpdateError, _DisallowedFields, TAG_XSI_TYPE,
    DEFAULT_UPDATE_OPTIONS)
from ramrod.utils import (remove_xml_element, copy_xml_element, get_type_info,
    get_ext_namespace)
from ramrod.stix import _STIXUpdater
from ramrod.cybox import Cybox_2_0_Updater


class MotivationVocab(_Vocab):
    TYPE = 'MotivationVocab-1.0.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.0.1/stix_default_vocabularies.xsd#MotivationVocab-1.0.1'
    VOCAB_NAME = 'STIX Default Motivation Vocabulary'
    TERMS = {
        "Ideological - Anti-Establisment": "Ideological - Anti-Establishment",
    }


class PlanningAndOperationalSupportVocab(_Vocab):
    TYPE = 'PlanningAndOperationalSupportVocab-1.0.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.0.1/stix_default_vocabularies.xsd#PlanningAndOperationalSupportVocab-1.0.1',
    VOCAB_NAME = 'STIX Default Planning and Operational Support Vocabulary'
    TERMS = {
        "Planning - Open-Source Intelligence (OSINT) Gethering": "Planning - Open-Source Intelligence (OSINT) Gathering",
        "Planning ": "Planning"
    }


class DisallowedMAEC(_DisallowedFields):
    CTX_TYPES = {
        "MAEC4.0InstanceType": "http://stix.mitre.org/extensions/Malware#MAEC4.0-1"
    }


class DisallowedMalware(_DisallowedFields):
    XPATH = ".//ttp:Malware"
    NS_MAEC_EXT = "http://stix.mitre.org/extensions/Malware#MAEC4.0-1"

    @classmethod
    def _check_maec(cls, node):
        """Returns ``False`` if a child node does not contain an ``xsi:type``
        referring to the MAEC Malware extension. Returns ``True`` if every
        child node is an instance of the MAEC Malware extension.

        """
        for child in node.iterchildren():
            if TAG_XSI_TYPE not in child.attrib:
                return False

            ns = get_ext_namespace(child)
            if ns != cls.NS_MAEC_EXT:
                return False

        return True


    @classmethod
    def _interrogate(cls, nodes):
        return [x for x in nodes if cls._check_maec(x)]


class DisallowedCAPEC(_DisallowedFields):
    CTX_TYPES = {
        "CAPEC2.5InstanceType": "http://stix.mitre.org/extensions/AP#CAPEC2.5-1"
    }


class DisallowedAttackPatterns(_DisallowedFields):
    XPATH = ".//ttp:Attack_Patterns"
    NS_CAPEC_EXT = "http://stix.mitre.org/extensions/AP#CAPEC2.5-1"

    @classmethod
    def _check_capec(cls, node):
        """Returns ``False`` if a child node does not contain an ``xsi:type``
        referring to the CAPEC Attack Pattern extension. Returns ``True`` if
        every child node is an instance of the CAPEC Attack Pattern extension.

        """
        for child in node.iterchildren():
            if TAG_XSI_TYPE not in child.attrib:
                return False

            ns = get_ext_namespace(child)
            if ns != cls.NS_CAPEC_EXT:
                return False

        return True


    @classmethod
    def _interrogate(cls, nodes):
        return [x for x in nodes if cls._check_capec(x)]


class STIX_1_0_Updater(_STIXUpdater):
    """Updates STIX v1.0 content to STIX v1.0.1.

    The following fields and types are translated:
    * MotivationVocab-1.0 upgraded to MotivationVocab-1.0.1
    * PlanningAndOperationalSupportVocab-1.0 updated to
      PlanningAndOperationalSupportVocab 1.0.1

    The following fields and types cannot be translated:
    * MAEC 4.0 Malware extension instances
    * CAPEC 2.5 Attack Pattern extension instances
    * TTP:Malware nodes that contain only MAEC Malware_Instance children
    * TTP:Attack_Patterns nodes that contain only CAPEC Attack Pattern
      instance children

    """
    VERSION = '1.0'

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

    DISALLOWED = (
        DisallowedCAPEC,
        DisallowedMAEC,
        DisallowedMalware,
        DisallowedAttackPatterns,
    )

    # STIX v1.0.1 NS => STIX v1.0.1 SCHEMALOC
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
        'http://stix.mitre.org/extensions/AP#CAPEC2.6-1': 'http://stix.mitre.org/XMLSchema/extensions/attack_pattern/capec_2.6.1/1.0.1/capec_2.6.1.xsd',
        'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/address/ciq_address_3.0/1.0.1/ciq_address_3.0.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_identity_3.0/1.0.1/ciq_identity_3.0.xsd',
        'http://stix.mitre.org/extensions/Malware#MAEC4.0-1': 'http://stix.mitre.org/XMLSchema/extensions/malware/maec_4.0.1/1.0.1/maec_4.0.1.xsd',
        'http://stix.mitre.org/extensions/StructuredCOA#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/structured_coa/generic/1.0.1/generic.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/generic/1.0.1/generic.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/oval_5.10/1.0.1/oval_5.10.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/open_ioc_2010/1.0.1/open_ioc_2010.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.0.1/snort.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#YARA-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.0.1/yara.xsd',
        'http://stix.mitre.org/extensions/Vulnerability#CVRF-1': 'http://stix.mitre.org/XMLSchema/extensions/vulnerability/cvrf_1.1/1.0.1/cvrf_1.1.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.0.1/stix_core.xsd',
    }

    UPDATE_VOCABS = {
        'MotivationVocab-1.0': MotivationVocab,
        'PlanningAndOperationalSupportVocab-1.0': PlanningAndOperationalSupportVocab
    }

    def __init__(self):
        super(STIX_1_0_Updater, self).__init__()
        self._init_cybox_updater()


    def _init_cybox_updater(self):
        updater_klass = Cybox_2_0_Updater
        updater = updater_klass()
        updater.NSMAP = dict(self.NSMAP.items() + updater_klass.NSMAP.items())
        updater.XPATH_ROOT_NODES = (
            "//stix:Observables | "
            "//incident:Structured_Description | "
            "//ttp:Observable_Characterization"
        )
        updater.XPATH_VERSIONED_NODES = updater.XPATH_ROOT_NODES
        self._cybox_updater = updater


    def _get_disallowed(self, root):
        """Finds all xml entities under `root` that cannot be updated.

        Note:
            This checks for both untranslatable STIX and CybOX entities.

        Args:
            root: The top-level xml node

        Returns:
            A list of untranslatable items.

        """
        disallowed = []

        for klass in self.DISALLOWED:
            found = klass.find(root)
            disallowed.extend(found)

        cybox = self._cybox_updater._get_disallowed(root)
        disallowed.extend(cybox)

        return disallowed


    def _update_versions(self, root):
        """Updates the versions of versioned nodes under `root` to align with
        STIX v1.0.1 versions.

        """
        nodes = self._get_versioned_nodes(root)
        for node in nodes:
            tag = etree.QName(node)
            name = tag.localname

            if name == "Indicator":
                node.attrib['version'] = '2.0.1'
            else:
                node.attrib['version'] = '1.0.1'


    def _update_cybox(self, root, options):
        """Updates the CybOX content found under the `root` node.

        Returns:
            An updated `root` node. This may be a new ``etree._Element``
            instance.

        """
        updated = self._cybox_updater._update(root, options)
        return updated


    def clean(self, root, options=None):
        """Removes disallowed elements from `root`.

        A copy of the removed nodes are stored on the instance-level
        `cleaned_fields` attribute. This will overwrite the `cleaned_fields`
        value with each invocation.

        Note:
            The `duplicates` parameter isn't handled. It is just kept for
            the sake of consistency across `clean()` method signatures.

        Args:
            root: The top-level XML document node.
            options(optional): A `ramrod.UpdateOptions` instance. If ``None``,
            `ramrod.DEFAULT_UPDATE_OPTIONS` will be used.

        Returns:
            The source `root` node.

        """
        removed = []
        disallowed = self._get_disallowed(root)

        for node in disallowed:
            dup = copy_xml_element(node)
            remove_xml_element(node)
            removed.append(dup)

        self.cleaned_fields = tuple(removed)
        return root


    def check_update(self, root, options=None):
        """Determines if the input document can be upgraded.

        Args:
            root (lxml.etree._Element): The top-level node of the document
                being upgraded.
            options (optional): A `ramrod.UpdateOptions` instance. If ``None``,
            `ramrod.DEFAULT_UPDATE_OPTIONS` will be used.

        Raises:
            UnknownVersionError: If the input document does not have a version.
            InvalidVersionError: If the version of the input document
                does not match the `VERSION` class-level attribute value.
            UpdateError: If the input document contains fields which cannot
                be updated.

        """
        options = options or DEFAULT_UPDATE_OPTIONS

        if options.check_versions:
            self._check_version(root)
            self._cybox_updater._check_version(root)

        disallowed  = self._get_disallowed(root)

        if disallowed:
            raise UpdateError("Found untranslatable fields in source "
                              "document.",
                              disallowed=disallowed)


    def _update(self, root, options):
        updated = self._update_cybox(root, options)
        updated = self._update_namespaces(updated)

        self._update_schemalocs(updated)

        if options.update_versions:
            self._update_versions(updated)

        if options.update_vocabularies:
            self._update_vocabs(updated)

        return updated


# Wiring namespace dictionaries
for klass in STIX_1_0_Updater.DISALLOWED:
    klass.NSMAP = STIX_1_0_Updater.NSMAP
