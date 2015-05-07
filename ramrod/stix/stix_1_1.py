# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# external
from lxml import etree

# internal
from ramrod import base, errors, utils, xmlconst
from ramrod.cybox import Cybox_2_0_1_Updater
from ramrod.options import DEFAULT_UPDATE_OPTIONS

# relative
from . import register_updater
from .base import BaseSTIXUpdater, STIXVocab


class AvailabilityLossVocab(STIXVocab):
    OLD_TYPES = ("AvailabilityLossTypeVocab-1.0",)
    NEW_TYPE = "AvailabilityLossTypeVocab-1.1.1"
    VOCAB_NAME = "STIX Default Availability Loss Type Vocabulary"
    VOCAB_REFERENCE = "http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.1/stix_default_vocabularies.xsd#AvailabilityLossTypeVocab-1.1.1"
    TERMS = {
       'Degredation': 'Degradation'
    }


class TransCommonSource(base.TranslatableField):
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

        <stixCommon:Confidence>
            <stixCommon:Source>Foobar</stixCommon:Source>
        </stixCommon:Confidence>

        <stixCommon:Confidence>
            <stixCommon:Source>
                <stixCommon:Identity>
                    <stixCommon:Name>Example</stixCommon:Name>
                </stixCommon:Identity>
            </stixCommon:Source>
        </stixCommon:Confidence>

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


class TransSightingsSource(base.TranslatableField):
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
            <indicator:Source>Foobar</indicator:Source>
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


class TransIndicatorRelatedCampaign(base.TranslatableField):
    XPATH_NODE = ".//indicator:Related_Campaigns/indicator:Related_Campaign"
    NEW_TAG =  "{http://stix.mitre.org/common-1}Campaign"

    @classmethod
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
        dup = utils.copy_xml_element(node, tag=cls.NEW_TAG)
        wrapper = etree.Element(
            "{http://stix.mitre.org/Indicator-2}Related_Campaign"
        )
        wrapper.append(dup)
        return wrapper


class OptionalGenericTestMechanismFields(base.OptionalElements):
    XPATH = xmlconst.XPATH_RELATIVE_CHILDREN
    CTX_TYPES = {
        'GenericTestMechanismType': 'http://stix.mitre.org/extensions/TestMechanism#Generic-1'
    }


@register_updater
class STIX_1_1_Updater(BaseSTIXUpdater):
    """Updates STIX v1.1 content to STIX v1.1.1.

    The following update operations are performed:

    * The ``Source`` field under instances of ``StatementType`` and
      ``ConfidenceType`` are translated from ``ControlledVocabularyStringType``
      instances to ``IdentityType`` instances. The original value becomes the
      ``Name`` field of the ``IdentityType`` instance.
    * The ``Source`` field under ``IndicatorType/Sightings/Sighting`` is
      converted into an instance of ``IdentityType`` where the original value
      becomes the value of the ``Name`` field.
    * The ``Related_Campaigns`` field under ``IndicatorType`` is converted from
      a flat list of ``RelatedCampaignType`` instances into an instance of
      ``GenericRelationshipListType``.
    * Instances of the ``GeneralTestMechanismType`` extension have empty,
      optional fields removed.
    * Instances of ``AvailabilityLossVocab-1.0`` are upgraded to
      ``AvailabilityLossVocab-1.1``

    Note:
        All fields can be translated between STIX v1.1 and STIX v1.1.1.

    """
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

    UPDATE_VOCABS = (
        AvailabilityLossVocab,
    )

    OPTIONAL_ELEMENTS = (
        OptionalGenericTestMechanismFields,
    )

    TRANSLATABLE_FIELDS = (
        TransCommonSource,
        TransSightingsSource,
        TransIndicatorRelatedCampaign,
    )

    CYBOX_UPDATER = Cybox_2_0_1_Updater

    def __init__(self):
        super(STIX_1_1_Updater, self).__init__()

    def _translate_fields(self, root):
        for field in self.TRANSLATABLE_FIELDS:
            field.translate(root)

    def _update_optionals(self, root):
        """Finds and removes empty xml elements and attributes which are
        optional in the next language release.

        Args:
            root: The top-level xml node.

        """
        optional_elements = self.OPTIONAL_ELEMENTS
        typed_nodes = utils.get_typed_nodes(root)

        for optional in optional_elements:
            found = optional.find(root, typed=typed_nodes)
            utils.remove_xml_elements(found)

    def _get_disallowed(self, root, options=None):
        """There are no untranslatable fields between STIX v1.1 and
        STIX v1.1.1.

        Note:
            This assume that `root` is schema-valid

        """
        pass

    def _get_duplicates(self, root):
        """The STIX v1.1 and v1.1.1 schemas both enforces ID uniqueness, so
        this overrides the default ``_get_duplicates()``.

        Note:
            This assumes that `root` is schema-valid.

        """
        pass

    def _update_versions(self, root):
        """Updates the versions of versioned nodes under `root` to align with
        STIX v1.1.1 versions.

        """
        nodes = self._get_versioned_nodes(root)
        for node in nodes:
            name = utils.get_localname(node)

            if name == "Indicator":
                node.attrib['version'] = '2.1.1'
            else:
                node.attrib['version'] = '1.1.1'

    def _update_cybox(self, root):
        """Updates the CybOX content found under the `root` node.

        Note:
            STIX v1.1 and STIX v1.1.1 import CybOX 2.1, so this just updates
            schemalocation attributes to point to the schemas hosted on
            http://cybox.mitre.org.

        Returns:
            An updated `root` node. This may be a new ``etree._Element``
            instance.

        """
        self._cybox_updater._update_schemalocs(root)  # noqa

    def check_update(self, root, options=None):
        """Determines if the input document can be upgraded.

        Args:
            root: The XML document. This can be a filename, a file-like object,
                an instance of ``etree._Element`` or an instance of
                ``etree._ElementTree``.
            options (optional): A ``ramrod.UpdateOptions`` instance. If
                ``None``, ``ramrod.DEFAULT_UPDATE_OPTIONS`` will be used.

        Raises:
            .UnknownVersionError: If the input document does not have a
                version.
            .InvalidVersionError: If the version of the input document
                does not match the `VERSION` class-level attribute value.
            .UpdateError: If the input document contains fields which
                cannot be updated or constructs with non-unique IDs are
                discovered.

        """
        root = utils.get_etree_root(root)
        options = options or DEFAULT_UPDATE_OPTIONS

        if options.check_versions:
            self._check_version(root)

        disallowed = self._get_disallowed(root)

        if not disallowed:
            return

        error = "Found duplicate or untranslatable fields in source document."
        raise errors.UpdateError(
            message=error,
            disallowed=disallowed
        )

    def _update(self, root, options):
        self._update_cybox(root)
        self._update_schemalocs(root)
        self._update_versions(root)
        self._translate_fields(root)

        if options.update_vocabularies:
            self._update_vocabs(root)

        if options.remove_optionals:
            self._update_optionals(root)

        return root
