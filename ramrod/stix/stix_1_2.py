from . import register_updater
from .base import BaseSTIXUpdater
from ramrod import utils
from ramrod.options import DEFAULT_UPDATE_OPTIONS

@register_updater
class STIX_1_2_Updater(BaseSTIXUpdater):
    """
    This updater does nothing except update XML namespaces.
    """

    VERSION = "1.2"

    UPDATE_NS_MAP = {
        # "Core" stuff
        "http://stix.mitre.org/stix-1": "http://docs.oasis-open.org/cti/ns/stix/core-1",
        "http://stix.mitre.org/common-1": "http://docs.oasis-open.org/cti/ns/stix/common-1",
        "http://stix.mitre.org/default_vocabularies-1": "http://docs.oasis-open.org/cti/ns/stix/vocabularies-1",

        # Components
        "http://stix.mitre.org/Campaign-1": "http://docs.oasis-open.org/cti/ns/stix/campaign-1",
        "http://stix.mitre.org/CourseOfAction-1": "http://docs.oasis-open.org/cti/ns/stix/course-of-action-1",
        "http://data-marking.mitre.org/Marking-1": "http://docs.oasis-open.org/cti/ns/stix/data-marking-1",
        "http://stix.mitre.org/ExploitTarget-1": "http://docs.oasis-open.org/cti/ns/stix/exploit-target-1",
        "http://stix.mitre.org/Incident-1": "http://docs.oasis-open.org/cti/ns/stix/incident-1",
        "http://stix.mitre.org/Indicator-2": "http://docs.oasis-open.org/cti/ns/stix/indicator-1",
        "http://stix.mitre.org/Report-1": "http://docs.oasis-open.org/cti/ns/stix/report-1",
        "http://stix.mitre.org/ThreatActor-1": "http://docs.oasis-open.org/cti/ns/stix/threat-actor-1",
        "http://stix.mitre.org/TTP-1": "http://docs.oasis-open.org/cti/ns/stix/ttp-1",

        # Extensions
        "http://stix.mitre.org/extensions/Address#CIQAddress3.0-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/address/ciq-address-3.0-1",
        "http://stix.mitre.org/extensions/AP#CAPEC2.7-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/attack-pattern/capec-2.7-1",
        "http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/identity/ciq-3.0-identity-1",
        "http://stix.mitre.org/extensions/Malware#MAEC4.1-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/malware/maec-4.1-1",
        "http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/data-marking/simple-1",
        "http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/data-marking/terms-of-use-1",
        "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/data-marking/tlp-1",
        "http://stix.mitre.org/extensions/StructuredCOA#Generic-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/structured-coa/generic-1",
        "http://stix.mitre.org/extensions/TestMechanism#Generic-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/generic-1",
        "http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/openioc-2010-1",
        "http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/oval-5.10-1",
        "http://stix.mitre.org/extensions/TestMechanism#Snort-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/snort-1",
        "http://stix.mitre.org/extensions/TestMechanism#YARA-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/yara-1",
        "http://stix.mitre.org/extensions/Vulnerability#CVRF-1": "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/cvrf-1"
    }

    NSMAP = {
        "stix": "http://stix.mitre.org/stix-1"
    }

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
        root = self._update_namespaces(root)
        self._update_schemalocs(root)

        root.set("version", "1.2.1")

        return root
