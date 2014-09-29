
from distutils.version import StrictVersion
from ramrod import (_BaseUpdater, UnknownVersionError, InvalidVersionError)

class _STIXUpdater(_BaseUpdater):
    """Base class for STIX updating code. Sets default values for
    STIX-specific xpaths and namespaces.

    """
    DEFAULT_VOCAB_NAMESPACE = 'http://stix.mitre.org/default_vocabularies-1'
    XPATH_VERSIONED_NODES = (
        "//stix:STIX_Package | "
        "//indicator:Indicator[@version] | "
        "//stix:Indicator[@version] | "
        "//stixCommon:Indicator[@version] | "
        "//incident:Incident[@version] | "
        "//stix:Incident[@version] | "
        "//stixCommon:Incident[@version] | "
        "//ttp:TTP[@version] | "
        "//stix:TTP[@version] | "
        "//stixCommon:TTP[@version] | "
        "//coa:Course_Of_Action[@version] | "
        "//stix:Course_Of_Action[@version] | "
        "//stixCommon:Course_Of_Action[@version] |"
        "//ta:Threat_Actor[@version]| "
        "//stix:Threat_Actor[@version] | "
        "//stixCommon:Threat_Actor[@version] | "
        "//campaign:Campaign[@version] | "
        "//stix:Campaign[@version] | "
        "//stixCommon:Campaign[@version] | "
        "//et:Exploit_Target[@version] | "
        "//stix:Exploit_Target[@version] | "
        "//stixCommon:Exploit_Target[@version]"
    )
    XPATH_ROOT_NODES = "//stix:STIX_Package"

    def __init__(self):
        super(_STIXUpdater, self).__init__()
        self.cleaned_fields = ()
        self._init_cybox_updater()


    def _init_cybox_updater(self):
        """Returns an initialized instance of a _CyboxUpdater implementation.

        Note:
            This needs to be implemented by derived classes.

        """
        raise NotImplementedError()

    @classmethod
    def get_version(cls, package):
        """Returns the version of the `package` STIX_Package element by
        inspecting the ``version`` attribute.

        """
        return package.attrib.get('version')


    def _check_version(self, root):
        """Checks that the version of the document `root` is valid for an
        implementation of ``_BaseUpdater``.

        Note:
            The ``version`` attribute of `root` is compared against the
            ``VERSION`` class-level attribute.

        Raises:
            UnknownVersionError: If `root` does not contain a ``version``
                attribute.
            InvalidVersionError: If the ``version`` attribute value for `root`
                does not match the value of ``VERSION``.

        """
        roots = self._get_root_nodes(root)
        expected = self.VERSION

        for node in roots:
            found = self.get_version(node)

            if not found:
                raise UnknownVersionError()

            if StrictVersion(found) != StrictVersion(expected):
                raise InvalidVersionError(node, expected, found)


from .stix_1_0 import STIX_1_0_Updater
from .stix_1_0_1 import  STIX_1_0_1_Updater
from .stix_1_1 import STIX_1_1_Updater

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')

STIX_UPDATERS = {
    '1.0': STIX_1_0_Updater,
    '1.0.1': STIX_1_0_1_Updater,
    '1.1': STIX_1_1_Updater
}