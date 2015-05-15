# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
from ramrod import utils
from ramrod.options import DEFAULT_UPDATE_OPTIONS

# relative
from . import register_updater
from .base import BaseSTIXUpdater, STIXVocab


class DiscoveryMethodVocab(STIXVocab):
    OLD_TYPES = ("DiscoveryMethodVocab-1.0",)
    NEW_TYPE = "DiscoveryMethodVocab-2.0"
    VOCAB_NAME = "STIX Default Discovery Method Vocabulary"
    VOCAB_REFERENCE = "http://stix.mitre.org/XMLSchema/default_vocabularies/1.2.0/stix_default_vocabularies.xsd#DiscoveryMethodTypeVocab-2.0"
    TERMS = {
       'Fraud Detection': 'External - Fraud Detection'
    }


@register_updater
class STIX_1_1_1_Updater(BaseSTIXUpdater):
    """Updates STIX v1.1.1 content to STIX v1.2.

    The following update operations are performed:

    * Instances of ``DiscoveryMethodTypeVocab-1.0`` are upgraded to
      ``DiscoveryMethodTypeVocab-2.0.``
    * Component versions are updated.
    * Schemalocations are updated.

    """
    VERSION = '1.1.1'

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
        'http://data-marking.mitre.org/Marking-1': 'http://stix.mitre.org/XMLSchema/data_marking/1.2/data_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/simple/1.2/simple_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/tlp/1.2/tlp_marking.xsd',
        'http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1': 'http://stix.mitre.org/XMLSchema/extensions/marking/terms_of_use/1.0.1/terms_of_use_marking.xsd',
        'http://stix.mitre.org/Campaign-1': 'http://stix.mitre.org/XMLSchema/campaign/1.2/campaign.xsd',
        'http://stix.mitre.org/CourseOfAction-1': 'http://stix.mitre.org/XMLSchema/course_of_action/1.2/course_of_action.xsd',
        'http://stix.mitre.org/ExploitTarget-1': 'http://stix.mitre.org/XMLSchema/exploit_target/1.2/exploit_target.xsd',
        'http://stix.mitre.org/Incident-1': 'http://stix.mitre.org/XMLSchema/incident/1.2/incident.xsd',
        'http://stix.mitre.org/Indicator-2': 'http://stix.mitre.org/XMLSchema/indicator/2.2/indicator.xsd',
        'http://stix.mitre.org/TTP-1': 'http://stix.mitre.org/XMLSchema/ttp/1.2/ttp.xsd',
        'http://stix.mitre.org/ThreatActor-1': 'http://stix.mitre.org/XMLSchema/threat_actor/1.2/threat_actor.xsd',
        'http://stix.mitre.org/common-1': 'http://stix.mitre.org/XMLSchema/common/1.2/stix_common.xsd',
        'http://stix.mitre.org/default_vocabularies-1': 'http://stix.mitre.org/XMLSchema/default_vocabularies/1.2.0/stix_default_vocabularies.xsd',
        'http://stix.mitre.org/extensions/AP#CAPEC2.7-1': 'http://stix.mitre.org/XMLSchema/extensions/attack_pattern/capec_2.7/1.1/capec_2.7_attack_pattern.xsd',
        'http://stix.mitre.org/extensions/Address#CIQAddress3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/address/ciq_3.0/1.2/ciq_3.0_address.xsd',
        'http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1': 'http://stix.mitre.org/XMLSchema/extensions/identity/ciq_3.0/1.2/ciq_3.0_identity.xsd',
        'http://stix.mitre.org/extensions/Malware#MAEC4.1-1': 'http://stix.mitre.org/XMLSchema/extensions/malware/maec_4.1/1.1/maec_4.1_malware.xsd',
        'http://stix.mitre.org/extensions/StructuredCOA#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/structured_coa/generic/1.2/generic_structured_coa.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Generic-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/generic/1.2/generic_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/oval_5.10/1.2/oval_5.10_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/open_ioc_2010/1.2/open_ioc_2010_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#Snort-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/snort/1.2/snort_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/TestMechanism#YARA-1': 'http://stix.mitre.org/XMLSchema/extensions/test_mechanism/yara/1.2/yara_test_mechanism.xsd',
        'http://stix.mitre.org/extensions/Vulnerability#CVRF-1': 'http://stix.mitre.org/XMLSchema/extensions/vulnerability/cvrf_1.1/1.2/cvrf_1.1_vulnerability.xsd',
        'http://stix.mitre.org/stix-1': 'http://stix.mitre.org/XMLSchema/core/1.2/stix_core.xsd'
    }

    UPDATE_VOCABS = (
        DiscoveryMethodVocab,
    )

    def __init__(self):
        super(STIX_1_1_1_Updater, self).__init__()


    def _get_disallowed(self, root, options=None):
        """There are no untranslatable fields between STIX v1.1.1 and
        STIX v1.2.

        Note:
            This assume that `root` is schema-valid

        """
        pass

    def _get_duplicates(self, root):
        """The STIX v1.1.1 schemas enforces ID uniqueness, so
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
                node.attrib['version'] = '2.2'
            else:
                node.attrib['version'] = '1.2'

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

        """
        root = utils.get_etree_root(root)
        options = options or DEFAULT_UPDATE_OPTIONS

        if options.check_versions:
            self._check_version(root)

    def _update(self, root, options):
        self._update_schemalocs(root)
        self._update_versions(root)

        if options.update_vocabularies:
            self._update_vocabs(root)

        return root
