# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
from ramrod import base, errors, utils
from ramrod.options import DEFAULT_UPDATE_OPTIONS
from ramrod.cybox import Cybox_2_0_Updater

# relative
from . import register_updater
from .base import BaseSTIXUpdater, STIXVocab


class MotivationVocab(STIXVocab):
    OLD_TYPES = ('MotivationVocab-1.0',)
    NEW_TYPE = 'MotivationVocab-1.0.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.0.1/stix_default_vocabularies.xsd#MotivationVocab-1.0.1'
    VOCAB_NAME = 'STIX Default Motivation Vocabulary'
    TERMS = {
        "Ideological - Anti-Establisment": "Ideological - Anti-Establishment",
    }


class PlanningAndOperationalSupportVocab(STIXVocab):
    OLD_TYPES = ('PlanningAndOperationalSupportVocab-1.0',)
    NEW_TYPE = 'PlanningAndOperationalSupportVocab-1.0.1'
    VOCAB_REFERENCE = 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.0.1/stix_default_vocabularies.xsd#PlanningAndOperationalSupportVocab-1.0.1',
    VOCAB_NAME = 'STIX Default Planning and Operational Support Vocabulary'
    TERMS = {
        "Planning - Open-Source Intelligence (OSINT) Gethering": "Planning - Open-Source Intelligence (OSINT) Gathering",
        "Planning ": "Planning"
    }


class DisallowedMAEC(base.DisallowedFields):
    CTX_TYPES = {
        "MAEC4.0InstanceType": "http://stix.mitre.org/extensions/Malware#MAEC4.0-1"
    }


class DisallowedMalware(base.DisallowedFields):
    """A ``ttp:Malware`` field **must** contain at least one child. If all
    children are instances of the MAEC Malware Extension, they will be removed
    and leave the parent ``ttp:Malware`` instance with no children, rendering
    it schema-invalid.

    This flags the ``ttp:Malware`` field as disallowed if it contains only
    MAEC Malware Extension instances.

    """
    XPATH = ".//ttp:Malware"
    NS_MAEC_EXT = "http://stix.mitre.org/extensions/Malware#MAEC4.0-1"

    @classmethod
    def _check_maec(cls, node):
        """Returns ``True`` if every child node is an instance of the MAEC
        Malware extension.

        """
        try:
            namespaces = (utils.get_ext_namespace(x) for x in utils.iterchildren(node))
            return all(ns == cls.NS_MAEC_EXT for ns in namespaces)
        except KeyError:
            # At least one node didn't contain an xsi:type attribute
            return False

    @classmethod
    def _interrogate(cls, nodes):
        return [x for x in nodes if cls._check_maec(x)]


class DisallowedCAPEC(base.DisallowedFields):
    CTX_TYPES = {
        "CAPEC2.5InstanceType": "http://stix.mitre.org/extensions/AP#CAPEC2.5-1"
    }


class DisallowedAttackPatterns(base.DisallowedFields):
    """A ``ttp:Attack_Patterns`` field **must** contain at least one child. If
    all children are instances of the CAPEC Attack Pattern Extension, they will
    be removed and leave the parent ``ttp:Attack_Patterns`` instance with no
    children, rendering it schema-invalid.

    This flags the ``ttp:Attack_Patterns`` field as disallowed if it contains
    only CAPEC Attack Pattern Extension instances.

    """
    XPATH = ".//ttp:Attack_Patterns"
    NS_CAPEC_EXT = "http://stix.mitre.org/extensions/AP#CAPEC2.5-1"


    @classmethod
    def _check_capec(cls, node):
        """Returns ``True`` if every child node is an instance of the CAPEC
        Attack Pattern extension.

        """
        try:
            namespaces = (utils.get_ext_namespace(x) for x in utils.iterchildren(node))
            return all(ns == cls.NS_CAPEC_EXT for ns in namespaces)
        except KeyError:
            # At least one node didn't contain an xsi:type attribute
            return False

    @classmethod
    def _interrogate(cls, nodes):
        return [x for x in nodes if cls._check_capec(x)]


@register_updater
class STIX_1_0_Updater(BaseSTIXUpdater):
    """Updates STIX v1.0 content to STIX v1.0.1.

    The following fields and types are translated:

    * ``MotivationVocab-1.0`` upgraded to ``MotivationVocab-1.0.1``
    * ``PlanningAndOperationalSupportVocab-1.0`` updated to
      ``PlanningAndOperationalSupportVocab 1.0.1``

    The following fields and types **cannot** be translated:

    * MAEC 4.0 Malware extension instances
    * CAPEC 2.5 Attack Pattern extension instances
    * ``TTP:Malware`` nodes that contain only MAEC Malware_Instance
      children
    * ``TTP:Attack_Patterns`` nodes that contain only CAPEC Attack Pattern
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

    UPDATE_VOCABS = (
        MotivationVocab,
        PlanningAndOperationalSupportVocab,
    )

    CYBOX_UPDATER = Cybox_2_0_Updater

    def __init__(self):
        super(STIX_1_0_Updater, self).__init__()
        self._init_cybox_updater()

    def _init_cybox_updater(self):
        super(STIX_1_0_Updater, self)._init_cybox_updater()

        selectors = (
            "//stix:Observables | "
            "//incident:Structured_Description | "
            "//ttp:Observable_Characterization"
        )

        updater = self._cybox_updater  # noqa
        updater.XPATH_ROOT_NODES = selectors
        updater.XPATH_VERSIONED_NODES = selectors

    def _get_duplicates(self, root):
        """The STIX v1.0.1 schema does not enforce ID uniqueness, so this
        overrides the default ``_get_duplicates()`` by immediately returning.

        Note:
            This assumes that `root` is schema-valid.

        """
        pass

    def _get_disallowed(self, root, options=None):
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

        disallowed_cybox = self._cybox_updater._get_disallowed(root) # noqa

        if disallowed_cybox:
            disallowed.extend(disallowed_cybox)

        return disallowed

    def _clean_disallowed(self, disallowed, options):
        """Removes the `disallowed` nodes from the source document.

        Args:
            disallowed: A list of nodes to remove from the source document.

        Returns:
            A list of `disallowed` node copies.

        """
        removed = []
        for node in disallowed:
            dup = utils.copy_xml_element(node)
            utils.remove_xml_element(node)
            removed.append(dup)

        return removed

    def _update_versions(self, root):
        """Updates the versions of versioned nodes under `root` to align with
        STIX v1.0.1 versions.

        """
        nodes = self._get_versioned_nodes(root)
        for node in nodes:
            name = utils.get_localname(node)

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
        updated = self._cybox_updater._update(root, options)  # noqa
        return updated

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
                cannot be updated or constructs with non-unique IDs are discovered.

        """
        root = utils.get_etree_root(root)
        options = options or DEFAULT_UPDATE_OPTIONS

        if options.check_versions:
            self._check_version(root)
            self._cybox_updater._check_version(root) # noqa

        disallowed  = self._get_disallowed(root)

        if not disallowed:
            return

        raise errors.UpdateError(
            message="Found untranslatable fields in source document.",
            disallowed=disallowed
        )

    def _update(self, root, options):
        updated = self._update_cybox(root, options)
        updated = self._update_namespaces(updated)

        self._update_schemalocs(updated)
        self._update_versions(updated)

        if options.update_vocabularies:
            self._update_vocabs(updated)

        return updated
