import copy
from lxml import etree

from ramrod import (Vocab, _DisallowedFields, UpdateError, UnknownVersionError,
                    TAG_XSI_TYPE)
from ramrod.utils import remove_xml_element
from ramrod.stix import _STIXUpdater
from ramrod.cybox import Cybox_2_0_Updater


class MotivationVocab(Vocab):
    TYPE = 'MotivationVocab-1.0.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.0.1/stix_default_vocabularies.xsd#MotivationVocab-1.0.1'
    VOCAB_NAME = 'STIX Default Motivation Vocabulary'
    TERMS = {
        "Ideological - Anti-Establisment": "Ideological - Anti-Establishment",
    }


class PlanningAndOperationalSupportVocab(Vocab):
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


class DisallowedCAPEC(_DisallowedFields):
    CTX_TYPES = {
        "CAPEC2.5InstanceType": "http://stix.mitre.org/extensions/AP#CAPEC2.5-1"
    }


class STIX_1_0_Updater(_STIXUpdater):
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
        DisallowedMAEC
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
        disallowed = []

        for klass in self.DISALLOWED:
            found = klass.find(root)
            disallowed.extend(found)

        cybox = self._cybox_updater._get_disallowed(root)
        disallowed.extend(cybox)

        return disallowed


    def check_update(self, root, check_version=True):
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
        if check_version:
            self._check_version(root)
            self._cybox_updater._check_version(root)

        disallowed  = self._get_disallowed(root)

        if disallowed:
            raise UpdateError(disallowed=disallowed)


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
            remove_xml_element(node)
            removed.append(dup)

        self.cleaned_fields = tuple(removed)


    def _update_versions(self, root):
        nodes = self._get_versioned_nodes(root)
        for node in nodes:
            tag = etree.QName(node)
            name = tag.localname

            if name == "Indicator":
                node.attrib['version'] = '2.0.1'
            else:
                node.attrib['version'] = '1.0.1'


    def _update_cybox(self, root):
        updated = self._cybox_updater.update(root)
        return updated


    def _update(self, root):
        updated = self._update_cybox(root)
        updated = self._update_namespaces(updated)
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
        except (UpdateError, UnknownVersionError):
            if force:
                self.clean(root)
                updated = self._update(root)
            else:
                raise

        return updated

# Wiring namespace dictionaries
for klass in STIX_1_0_Updater.DISALLOWED:
    klass.NSMAP = STIX_1_0_Updater.NSMAP
