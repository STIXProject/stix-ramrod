import copy
import itertools
from collections import defaultdict
from lxml import etree

from ramrod import (UpdateError, UnknownVersionError, TAG_XSI_TYPE)
from ramrod.stix import _STIXUpdater
from ramrod.cybox import Cybox_2_0_1_Updater
from ramrod.utils import (ignored, get_typed_nodes, copy_xml_element,
    remove_xml_element, remove_xml_elements, create_new_id)
from ramrod import (Vocab, UpdateError, UnknownVersionError, _DisallowedFields,
    _OptionalElements, _TranslatableField, _RenamedField)


class MotivationVocab(Vocab):
    TYPE = 'MotivationEnum-1.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.0/stix_default_vocabularies.xsd#MotivationVocab-1.1'
    VOCAB_NAME = 'STIX Default Motivation Vocabulary'
    TERMS = {
        'Policital': 'Political'
    }


class IndicatorTypeVocab(Vocab):
    TYPE = "IndicatorTypeEnum-1.1"
    VOCAB_NAME = "STIX Default Indicator Type Vocabulary"
    VOCAB_REFERENCE = "http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.0/stix_default_vocabularies.xsd#IndicatorTypeVocab-1.1"


class OptionalDataMarkingFields(_OptionalElements):
    XPATH = (
        ".//marking:Controlled_Structure | "
        ".//marking:Marking_Structure | "
    )

class DisallowedDateTime(_DisallowedFields):
    XPATH = ".//stixCommon:Date_Time"

    # Ugh. This could probably be solved with a regex but I can't find an
    # authoritative source on a xs:dateTime regex. The libxml2 2.9.1 source
    # code for dateTime validation is nuts.
    XSD = \
    """
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
        <xs:element name="test" type="xs:dateTime"/>
    </xs:schema>
    """

    XML_SCHEMA = etree.XMLSchema(etree.fromstring(XSD))

    @classmethod
    def _validate(cls, node):
        val = node.text
        xml = etree.Element("test")
        xml.text = val
        return cls.XML_SCHEMA.validate(xml)


    @classmethod
    def _interrogate(cls, nodes):
        return [x for x in nodes if not cls._validate(x)]


class STIX_1_0_1_Updater(_STIXUpdater):
    VERSION = '1.0.1'

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

    DISALLOWED_NAMESPACES = (
        'http://stix.mitre.org/extensions/AP#CAPEC2.6-1',
        'http://stix.mitre.org/extensions/Malware#MAEC4.0-1'
    )

    # STIX v1.1 NS => STIX v1.1.1 SCHEMALOC
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

    UPDATE_VOCABS = {
        'MotivationVocab-1.0.1': MotivationVocab,
        'IndicatorTypeVocab-1.0': IndicatorTypeVocab,
    }

    DISALLOWED = ()

    OPTIONAL_ELEMENTS = ()

    OPTIONAL_ATTRIBUTES = ()

    TRANSLATABLE_FIELDS = ()


    def __init__(self):
        super(STIX_1_0_1_Updater, self).__init__()
        self._init_cybox_updater()


    def _init_cybox_updater(self):
        updater_klass = Cybox_2_0_1_Updater
        updater = updater_klass()
        updater.NSMAP = dict(self.NSMAP.items() + updater_klass.NSMAP.items())
        updater.XPATH_ROOT_NODES = (
            ".//stix:Observables | "
            ".//incident:Structured_Description | "
            ".//ttp:Observable_Characterization | "
            ".//ttp:Targeted_Technical_Details | "
            ".//coa:Parameter_Observables "
        )
        updater.XPATH_VERSIONED_NODES = updater.XPATH_ROOT_NODES
        self._cybox_updater = updater


    def _translate_fields(self, root):
        for field in self.TRANSLATABLE_FIELDS:
            field.translate(root)


    def _update_optionals(self, root):
        optional_elements = self.OPTIONAL_ELEMENTS
        optional_attribs = self.OPTIONAL_ATTRIBUTES

        typed_nodes = get_typed_nodes(root)

        for optional in optional_elements:
            found = optional.find(root, typed=typed_nodes)
            remove_xml_elements(found)


        for optional in optional_attribs:
            found = optional.find(root, typed=typed_nodes)
            for node in found:
                remove_xml_elements(node, optional.ATTRIBUTES)


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
                node.attrib['version'] = '2.1'
            else:
                node.attrib['version'] = '1.1'


    def _update_cybox(self, root):
        updated = self._cybox_updater.update(root)
        return updated


    def check_update(self, root, check_versions=True):
        """Determines if the input document can be updated from CybOX 2.0.1
        to CybOX 2.1.

        A CybOX document cannot be upgraded if any of the following constructs
        are found in the document:

        * TODO: Add constructs

        CybOX 2.1 also introduces schematic enforcement of ID uniqueness. Any
        nodes with duplicate IDs are reported.

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.

        Raises:
            TODO fill out.

        """
        if check_versions:
            self._check_version(root)

        duplicates = self._get_duplicates(root)
        disallowed = self._get_disallowed(root)

        if any((disallowed, duplicates)):
            raise UpdateError("Found duplicate or untranslatable fields in "
                              "source document.",
                              disallowed=disallowed,
                              duplicates=duplicates)


    def _clean_disallowed(self, disallowed):
        removed = []

        for node in disallowed:
            dup = copy.deepcopy(node)
            remove_xml_element(node)
            removed.append(dup)

        return removed


    def _clean_duplicates(self, root, duplicates):
        """CybOX 2.1 introduced schematic enforcement of ID uniqueness, so
        CybOX 2.0.1 documents which contained duplicate IDs will need to have
        its IDs remapped to produce a schema-valid document.

        """
        self.cleaned_ids = defaultdict(list)
        for id_, nodes in duplicates.iteritems():
            for dup in nodes:
                new_id = create_new_id(id_)
                dup.attrib['id'] = new_id
                self.cleaned_ids[id_].append(new_id)


    def clean(self, root, disallowed=None, duplicates=None):
        disallowed = disallowed or self._get_disallowed(root)
        duplicates = duplicates or self._get_duplicates(root)

        self._clean_duplicates(root, duplicates)
        removed = self._clean_disallowed(disallowed)

        self.cleaned_fields = tuple(removed)
        return root


    def _update(self, root):
        updated = self._update_namespaces(root)
        self._update_schemalocs(updated)
        self._update_versions(updated)
        self._update_vocabs(updated)
        self._update_optionals(updated)
        self._translate_fields(updated)
        return updated


    def update(self, root, force=False):
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
nsmapped = itertools.chain(
    STIX_1_0_1_Updater.DISALLOWED,
    STIX_1_0_1_Updater.OPTIONAL_ELEMENTS,
    STIX_1_0_1_Updater.OPTIONAL_ATTRIBUTES,
    STIX_1_0_1_Updater.TRANSLATABLE_FIELDS,
)
for klass in nsmapped:
    klass.NSMAP = STIX_1_0_1_Updater.NSMAP