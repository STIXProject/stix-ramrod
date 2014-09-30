import itertools
from collections import defaultdict
from lxml import etree

from ramrod import (_Vocab, UpdateError, UnknownVersionError,
    InvalidVersionError, _DisallowedFields, _OptionalElements,
    _TranslatableField)
from ramrod.stix import _STIXUpdater
from ramrod.cybox import Cybox_2_0_1_Updater
from ramrod.utils import (get_typed_nodes, copy_xml_element,
    remove_xml_element, remove_xml_elements, create_new_id)


class MotivationVocab(_Vocab):
    TYPE = 'MotivationVocab-1.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.0/stix_default_vocabularies.xsd#MotivationVocab-1.1'
    VOCAB_NAME = 'STIX Default Motivation Vocabulary'
    TERMS = {
        'Policital': 'Political'
    }


class IndicatorTypeVocab(_Vocab):
    TYPE = "IndicatorTypeVocab-1.1"
    VOCAB_NAME = "STIX Default Indicator Type Vocabulary"
    VOCAB_REFERENCE = "http://stix.mitre.org/XMLSchema/default_vocabularies/1.1.0/stix_default_vocabularies.xsd#IndicatorTypeVocab-1.1"


class OptionalDataMarkingFields(_OptionalElements):
    XPATH = (
        ".//marking:Controlled_Structure | "
        ".//marking:Marking_Structures"
    )


class DisallowedMAEC(_DisallowedFields):
    CTX_TYPES = {
        "MAEC4.0InstanceType": "http://stix.mitre.org/extensions/Malware#MAEC4.0-1"
    }


class DisallowedCAPEC(_DisallowedFields):
    CTX_TYPES = {
        "CAPEC2.6InstanceType": "http://stix.mitre.org/extensions/AP#CAPEC2.6-1"
    }


class DisallowedDateTime(_DisallowedFields):
    XPATH = ".//stixCommon:Date_Time"

    # Ugh. This could probably be solved with a regex but I can't find an
    # authoritative source on a xs:dateTime/ISO8601 regex. The libxml2 2.9.1
    # source code for dateTime validation is nuts.

    XSD = \
    """
    <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
        <xs:element name="test" type="xs:dateTime"/>
    </xs:schema>
    """
    XML_SCHEMA = etree.XMLSchema(etree.fromstring(XSD))

    @classmethod
    def _validate(cls, node):
        if not node.text:
            return False

        xml = etree.Element("test")
        xml.text = node.text
        return cls.XML_SCHEMA.validate(xml)


    @classmethod
    def _interrogate(cls, nodes):
        return [x for x in nodes if not cls._validate(x)]


class TransTTPExploitTargets(_TranslatableField):
    XPATH_NODE = ".//ttp:Exploit_Targets/stixCommon:Exploit_Target"

    @classmethod
    def _translate_fields(cls, node):
        """The TTP.Exploit_Targets field became a GenericRelationshipListType
        in STIX 1.1.

        <ttp:Exploit_Targets>
           <stixCommon:Exploit_Target idref='example:et-1'/>
           <stixCommon:Exploit_Target idref='example:et-2'/>
        </ttp:Exploit_Targets>

        Becomes...

        <ttp:Exploit_Targets>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target idref='example:et-1'/>
            </ttp:Exploit_Target>
            <ttp:Exploit_Target>
                <stixCommon:Exploit_Target idref='example:et-2'/>
            </ttp:Exploit_Target>
        </ttp:Exploit_Targets>

        Args:
            node: The outer ttp:Exploit_Targets node.

        """
        tag = "{http://stix.mitre.org/TTP-1}Exploit_Target"
        dup = copy_xml_element(node)
        wrapper = etree.Element(tag)
        wrapper.append(dup)

        return wrapper


class TransCommonContributors(_TranslatableField):
    XPATH_NODE = ".//stixCommon:Contributors"

    @classmethod
    def _translate_fields(cls, node):
        """This changes instances of stixCommon:ContributorsType to instances
        of stixCommon:ContributingSourcesType.

        The STIX v1.0.1 ContributorsType contains a list of `Contributor`
        elements under it which were IdentityType instances.

        The STIX v1.1 ContributingSourcesType contains a list of `Source`
        elements under it which are instances of InformationSourceType.

        Because InformationSourceType has an `Identity` child element which is
        an instance of `IdentityType`, we can perform the following
        transformation:


        <stix:Information_Source>
            <stixCommon:Contributors>
                <stixCommon:Contributor>
                    <stixCommon:Name>Example</stixCommon:Name>
                </stixCommon:Contributor>
                <stixCommon:Contributor>
                    <stixCommon:Name>Another</stixCommon:Name>
                </stixCommon:Contributor>
            </stixCommon:Contributors>
        </stix:Information_Source>

        Becomes...

        <stix:Information_Source>
            <stixCommon:Contributing_Sources>
                <stixCommon:Source>
                    <stixCommon:Identity>
                        <stixCommon:Name>Example</stixCommon:Name>
                    </stixCommon:Identity>
                </stixCommon:Source>
                <stixCommon:Source>
                    <stixCommon:Identity>
                        <stixCommon:Name>Another</stixCommon:Name>
                    </stixCommon:Identity>
                </stixCommon:Source>
            </stixCommon:Contributing_Sources>
        </stix:Information_Source>

        Args:
            node: A ``stixCommon:Contributors`` node

        """
        ns_common = "http://stix.mitre.org/common-1"
        contributing_sources_tag = "{%s}Contributing_Sources" % ns_common
        source_tag = "{%s}Source" % ns_common
        identity_tag = "{%s}Identity" % ns_common

        contributing_sources = etree.Element(contributing_sources_tag)
        for contributor in node:
            dup = copy_xml_element(contributor, tag=identity_tag)
            source = etree.Element(source_tag)
            source.append(dup)
            contributing_sources.append(source)

        return contributing_sources



class STIX_1_0_1_Updater(_STIXUpdater):
    """Updates STIX v1.0.1 content to STIX v1.1.

    The following fields and types are translated:
    * MotivationVocab-1.0.1 updated to MotivaionVocab-1.1
    * IndicatorTypeVocab-1.0 updated to IndicatorTypeVocab-1.1
    * Empty data marking fields are stripped
    * TTP/Exploit_Targets instances are updated to align with
      GenericRelationshipListType datatype.
    * Instances of stixCommon:ContributorsType are converted to instances of
      stixCommon:ContributingSourcesType

    The following fields and types cannot be translated:
    * MAEC 4.0.1 Malware extension
    * CAPEC 2.6 Attack Pattern extension
    * stixCommon:Date_Time fields that do not contain xs:dateTime values

    """
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
        'http://stix.mitre.org/extensions/AP#CAPECa2.7-1': 'http://stix.mitre.org/XMLSchema/extensions/attack_pattern/capec_2.7/1.0/capec_2.7_attack_pattern.xsd',
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

    DISALLOWED = (
        DisallowedMAEC,
        DisallowedCAPEC,
        DisallowedDateTime,
    )

    OPTIONAL_ELEMENTS = (
        OptionalDataMarkingFields,
    )

    TRANSLATABLE_FIELDS = (
        TransCommonContributors,
        TransTTPExploitTargets,
    )

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
        """Finds and removes empty xml elements and attributes which are
        optional in the next language release.

        Args:
            root: The top-level xml node.

        """
        optional_elements = self.OPTIONAL_ELEMENTS
        typed_nodes = get_typed_nodes(root)

        for optional in optional_elements:
            found = optional.find(root, typed=typed_nodes)
            remove_xml_elements(found)


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
            self._cybox_updater._check_version(root)

        disallowed  = self._get_disallowed(root)

        if disallowed:
            raise UpdateError(disallowed=disallowed)




    def _update_versions(self, root):
        """Updates the versions of versioned nodes under `root` to align with
        STIX v1.1 data type versions.

        """
        nodes = self._get_versioned_nodes(root)
        for node in nodes:
            tag = etree.QName(node)
            name = tag.localname

            if name == "Indicator":
                node.attrib['version'] = '2.1'
            else:
                node.attrib['version'] = '1.1'


    def _update_cybox(self, root):
        """Updates the CybOX content found under the `root` node.

        Returns:
            An updated `root` node. This may be a new ``etree._Element``
            instance.

        """
        updated = self._cybox_updater.update(root)
        return updated


    def check_update(self, root, check_version=True):
        """Determines if the input document can be upgraded.

        Args:
            root (lxml.etree._Element): The top-level node of the document
                being upgraded.
            check_version(boolean): If True, the version of `root` is checked.

        Raises:
            UnknownVersionError: If the input document does not have a version.
            InvalidVersionError: If the version of the input document
                does not match the `VERSION` class-level attribute value.
            UpdateError: If the input document contains fields which cannot
                be updated or constructs with non-unique IDs are discovered.

        """
        if check_version:
            self._check_version(root)
            self._cybox_updater._check_version(root)

        duplicates = self._get_duplicates(root)
        disallowed = self._get_disallowed(root)

        if any((disallowed, duplicates)):
            raise UpdateError("Found duplicate or untranslatable fields in "
                              "source document.",
                              disallowed=disallowed,
                              duplicates=duplicates)


    def _clean_disallowed(self, disallowed):
        """Removes the `disallowed` nodes from the source document.

        Args:
            disallowed: A list of nodes to remove from the source document.

        Returns:
            A list of `disallowed` node copies.

        """
        removed = []
        for node in disallowed:
            dup = copy_xml_element(node)
            remove_xml_element(node)
            removed.append(dup)

        return removed


    def _clean_duplicates(self, duplicates):
        """Assigns a unique ID to each node in `duplicates`.

        Args:
            duplicates: A list of nodes with non-unique IDs

        Returns:
            The modified `duplicates` list.

        """
        for id_, nodes in duplicates.iteritems():
            for dup in nodes:
                new_id = create_new_id(id_)
                dup.attrib['id'] = new_id

        return duplicates


    def clean(self, root, disallowed=None, duplicates=None):
        """Removes disallowed elements from `root` and remaps non-unique
        IDs to unique IDs for the sake of schema-validation.

        Note:
            This does not remap ``idref`` attributes to new ID values because
            it is impossible to determine which entity the ``idref`` was
            pointing to.

        A copy of the removed nodes are stored on the instance-level
        `cleaned_fields` attribute.

        The `cleaned_ids` instance-level dictionary will be populated with
        ids and nodes which had their ids remapped.

        Note:
            The `cleaned_fields` and `cleaned_ids` attributes will be
            overwritten with each method invocation.

        Args:
            disallowed: A list of disallowed nodes to remove from the `root`
                document. If ``None``, an attempt will be made to discover
                all untranslatable elements under the `root` node.
            duplicates: A dictionary of id => [nodes] where the key represents
                the non-unique IDs and the ``[nodes]`` value is a list of nodes
                with that ID value.

        Returns:
            The source `root` node.

        """
        disallowed = disallowed or self._get_disallowed(root)
        duplicates = duplicates or self._get_duplicates(root)

        remapped = self._clean_duplicates(duplicates)
        removed = self._clean_disallowed(disallowed)

        self.cleaned_ids = remapped
        self.cleaned_fields = tuple(removed)
        return root


    def _update(self, root):
        updated = self._update_cybox(root)
        updated = self._update_namespaces(updated)
        self._update_schemalocs(updated)
        self._update_versions(updated)
        self._update_vocabs(updated)
        self._update_optionals(updated)
        self._translate_fields(updated)

        return updated


# Wiring namespace dictionaries
nsmapped = itertools.chain(
    STIX_1_0_1_Updater.DISALLOWED,
    STIX_1_0_1_Updater.OPTIONAL_ELEMENTS,
    STIX_1_0_1_Updater.TRANSLATABLE_FIELDS,
)
for klass in nsmapped:
    klass.NSMAP = STIX_1_0_1_Updater.NSMAP