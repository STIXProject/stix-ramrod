
from distutils.version import StrictVersion
from ramrod import (_BaseUpdater, UnknownVersionError, InvalidVersionError)

class _STIXUpdater(_BaseUpdater):
    def __init__(self):
        super(_STIXUpdater, self).__init__()
        self.cleaned_fields = ()


    def _init_cybox_updater(self):
        """Returns an initialized instance of a _CyboxUpdater implementation.

        Note:
            This needs to be implemented by derived classes.

        """
        raise NotImplementedError()


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
            found = node.attrib.get('version')

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