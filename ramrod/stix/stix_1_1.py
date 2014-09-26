import copy
import itertools
from collections import defaultdict
from lxml import etree

from ramrod import (Vocab, UpdateError, UnknownVersionError, _DisallowedFields,
    _OptionalElements, _TranslatableField)
from ramrod.stix import _STIXUpdater
from ramrod.cybox import Cybox_2_0_1_Updater
from ramrod.utils import (get_typed_nodes, copy_xml_element,
    remove_xml_element, remove_xml_elements, create_new_id)


class AvailabilityLossVocab(Vocab):
    TYPE = "AvailabilityLossTypeVocab-1.1.1"
    VOCAB_NAME = "STIX Default Availability Loss Type Vocabulary"
    VOCAB_REFERENCE = "http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd#AvailabilityLossTypeVocab-1.1.1"
    TERMS = {
       'Degredation': 'Degradation'
    }


class DisallowedConfidenceSource(_DisallowedFields):
    # It might be possible to translate the Source field to the new
    # Identity/Name field. I'm not sure if that's the best way to go about this.
    FIELD = "stixCommon:Source"
    XPATH = (
        ".//campaign:Confidence/{0} | "
        ".//coa:Applicability_Confidence/{0} | "
        ".//incident:Confidence/{0} | "
        ".//indicator:Confidence/{0} | "  # SightingsType and/or IndicatorType
        ".//stixCommon:Confidence_Assertion/{0} | "
        ".//stixCommon:Confidence/{0} | "  # StatementType and/or GenericRelationshipType
        ".//ta:Confidence/{0}"
    ).format(FIELD)


class DisallowedStatementSource(_DisallowedFields):
    # It might be possible to translate the Source field to the new
    # Identity/Name field. I'm not sure if that's the best way to go about this.
    FIELD = "stixCommon:Source"
    XPATH = (
        ".//campaign:Intended_Effect/{0} | "
        ".//coa:Cost/{0} | "
        ".//coa:Efficacy/{0}| "
        ".//incident:Intended_Effect/{0} | "
        ".//indicator:Likely_Impact/{0} | "
        ".//indicator:Efficacy/{0} | "
        ".//ta:Type/{0} | "
        ".//ta:Motivation/{0} | "
        ".//ta:Sophistication/{0} | "
        ".//ta:Intended_Effect/{0} | "
        ".//ta:Planning_And_Operational_Support/{0} | "
        ".//ttp:Intended_Effect/{0}"
    ).format(FIELD)


class TransCommonSource(_TranslatableField):
    FIELD = "stixCommon:Source"
    XPATH_NODE = (
        ".//campaign:Confidence/{0} | "
        ".//coa:Applicability_Confidence/{0} | "
        ".//incident:Confidence/{0} | "
        ".//indicator:Confidence/{0} | "  # SightingsType and/or IndicatorType
        ".//stixCommon:Confidence_Assertion/{0} | "
        ".//stixCommon:Confidence/{0} | "  # StatementType and/or GenericRelationshipType
        ".//ta:Confidence/{0} | "
        ".//campaign:Intended_Effect/{0} | "
        ".//coa:Cost/{0} | "
        ".//coa:Efficacy/{0}| "
        ".//incident:Intended_Effect/{0} | "
        ".//indicator:Likely_Impact/{0} | "
        ".//indicator:Efficacy/{0} | "
        ".//ta:Type/{0} | "
        ".//ta:Motivation/{0} | "
        ".//ta:Sophistication/{0} | "
        ".//ta:Intended_Effect/{0} | "
        ".//ta:Planning_And_Operational_Support/{0} | "
        ".//ttp:Intended_Effect/{0}"
    ).format(FIELD)


    @classmethod
    def _translate_fields(cls, node):
        """Translates StatementType/Source and ConfidenceType/Source fields
        from ControlledVocabularyStringType instances to InformationSourceType
        instances.

        This inserts the value under Identity/Name of the
        InformationSourceType instance.

        <ttp:Confidence>
            <stixCommon:Source>Foobar</stixCommon:Source>
        </ttp:Confidence>

        <ttp:Confidence>
            <stixCommon:Source>
                <stixCommon:Identity>
                    <stixCommon:Name>Example</stixCommon:Name>
                </stixCommon:Identity>
            </stixCommon:Source>
        </ttp:Confidence>

        Args:
            node: A ``Source`` xml element.

        Returns:
            A new ``Source`` xml element with an embedded ``Identity``
            structure.

        """

        xml = \
        """
        <stixCommon:Source xmlns:stixCommon="http://stix.mitre.org/common-1">
            <stixCommon:Identity>
                <stixCommon:Name>{0}</stixCommon:Name>
            </stixCommon:Identity>
        </stixCommon:Source>
        """.format(node.text)

        source = etree.fromstring(xml)
        return source


class TransSightingsSource(_TranslatableField):
    XPATH_NODE = (
        ".//indicator:Sighting/indicator:Source"
    )

    @classmethod
    def _translate_fields(cls, node):
        """Translates SightingType/Source fields from StructuredTextType
        instances to InformationSourceType instances.

        This inserts the value under Identity/Name of the
        InformationSourceType instance.

        <indicator:Sighting>
            <stixCommon:Source>Foobar</stixCommon:Source>
        </indicator:Sighting>

         <indicator:Sighting>
            <indicator:Source>
                <stixCommon:Identity>
                    <stixCommon:Name>Foobar</stixCommon:Name>
                </stixCommon:Identity>
            </indicator:Source>
         </indicator:Sighting>

        Args:
            node: A ``Source`` xml element.

        Returns:
            A new ``Source`` xml element with an embedded ``Identity``
            structure.

        """

        xml = \
        """
        <indicator:Source xmlns:indicator="http://stix.mitre.org/Indicator-2">
            <stixCommon:Identity xmlns:stixCommon="http://stix.mitre.org/common-1">
                <stixCommon:Name>{0}</stixCommon:Name>
            </stixCommon:Identity>
        </indicator:Source>
        """.format(node.text)

        source = etree.fromstring(xml)
        return source



class TransIndicatorRelatedCampaign(_TranslatableField):
    XPATH_NODE = ".//indicator:Related_Campaigns/indicator:Related_Campaign"
    NEW_TAG =  "{http://stix.mitre.org/Campaign-1}Campaign"

    def _translate_fields(cls, node):
        """Translates Indicator Related_Campaigns/Related_Campaign instances
        to STIX v1.1.1.

        <indicator:Related_Campaigns>
            <indicator:Related_Campaign>
                <stixCommon:Names>
                    <stixCommon:Name>Foo</stixCommon:Name>
                </stixCommon:Names>
            </indicator:Related_Campaign>
            <indicator:Related_Campaign idref='campaign-foo-1'/>
        </indicator:Related_Campaigns>

        Becomes

         <indicator:Related_Campaigns>
            <indicator:Related_Campaign>
                <stixCommon:Campaign>
                    <stixCommon:Names>
                        <stixCommon:Name>Foo</stixCommon:Name>
                    </stixCommon:Names>
                </stixCommon:Campaign>
            </indicator:Related_Campaign>
            <indicator:Related_Campaign>
                <stixCommon:Campaign idref="campaign-foo-1>
            </indicator:Related_Campaign>
        </indicator:Related_Campaigns>

        """
        dup = copy_xml_element(node, tag=cls.NEW_TAG)
        wrapper = etree.Element("{http://stix.mitre.org/Campaign-1}Related_Campaign")
        wrapper.append(dup)
        return wrapper


class OptionalGenericTestMechanismFields(_OptionalElements):
    XPATH = "./*"
    CTX_TYPES = {
        'GenericTestMechanismType': 'http://stix.mitre.org/extensions/TestMechanism#Generic-1'
    }


class STIX_1_1_Updater(_STIXUpdater):
    VERSION = '1.1'

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


    UPDATE_VOCABS = {
        'AvailabilityLossTypeVocab-1.0': AvailabilityLossVocab,
    }

    DISALLOWED = (
        #DisallowedConfidenceSource,
        #DisallowedStatementSource
    )

    OPTIONAL_ELEMENTS = (
        OptionalGenericTestMechanismFields,
    )

    TRANSLATABLE_FIELDS = (
        TransCommonSource,
        TransSightingsSource,
        TransIndicatorRelatedCampaign,
    )

    def __init__(self):
        super(STIX_1_1_Updater, self).__init__()


    def _init_cybox_updater(self):
        # This is used for updating schemalocations only
        self._cybox_updater = Cybox_2_0_1_Updater()
        pass

    def _translate_fields(self, root):
        for field in self.TRANSLATABLE_FIELDS:
            field.translate(root)


    def _update_optionals(self, root):
        optional_elements = self.OPTIONAL_ELEMENTS
        typed_nodes = get_typed_nodes(root)

        for optional in optional_elements:
            found = optional.find(root, typed=typed_nodes)
            remove_xml_elements(found)


    def _get_disallowed(self, root):
        disallowed = []

        for klass in self.DISALLOWED:
            found = klass.find(root)
            disallowed.extend(found)

        return disallowed


    def check_update(self, root, check_version=True):
        """Determines if the input document can be upgraded from STIX v1.0.1 to
        STIX v1.1.

        Args:
            root (lxml.etree._Element): The top-level node of the STIX
                document.

        Raises:
            UnknownVersionError: If the input document does not have a version.
            InvalidVersionError: If the version of the input document
                is not ``1.0.1``.
            UpdateError: If the input document contains fields which cannot
                be updated.

        """
        if check_version:
            self._check_version(root)

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
                node.attrib['version'] = '2.1.1'
            else:
                node.attrib['version'] = '1.1.1'


    def _update_cybox(self, root):
        self._cybox_updater._update_schemalocs(root)


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
        self._update_cybox(root)
        self._update_schemalocs(root)
        self._update_versions(root)
        self._update_vocabs(root)
        self._update_optionals(root)
        self._translate_fields(root)

        return root


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
    STIX_1_1_Updater.DISALLOWED,
    STIX_1_1_Updater.OPTIONAL_ELEMENTS,
    STIX_1_1_Updater.TRANSLATABLE_FIELDS,
)
for klass in nsmapped:
    klass.NSMAP = STIX_1_1_Updater.NSMAP