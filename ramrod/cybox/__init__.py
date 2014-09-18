from distutils.version import StrictVersion
from ramrod import (_BaseUpdater, UnknownVersionError, InvalidVersionError)

TAG_CYBOX_MAJOR  = "cybox_major_version"
TAG_CYBOX_MINOR  = "cybox_minor_version"
TAG_CYBOX_UPDATE = "cybox_update_version"

CYBOX_VERSIONS = ('2.0', '2.0.1', '2.1')


class _CyboxUpdater(_BaseUpdater):
    DEFAULT_VOCAB_NAMESPACE = 'http://cybox.mitre.org/default_vocabularies-1'

    XPATH_VERSIONED_NODES = "//cybox:Observables"
    XPATH_ROOT_NODES = "//cybox:Observables"
    XPATH_OBJECT_PROPS = "//cybox:Object/cybox:Properties"

    def __init__(self):
        super(_CyboxUpdater, self).__init__()
        self.cleaned_fields = ()

    def _get_observables_version(self, observables):
        cybox_major  = observables.attrib.get(TAG_CYBOX_MAJOR)
        cybox_minor  = observables.attrib.get(TAG_CYBOX_MINOR)
        cybox_update = observables.attrib.get(TAG_CYBOX_UPDATE)

        if not any((cybox_major, cybox_minor, cybox_update)):
            raise UnknownVersionError()

        if cybox_update:
            version = "%s.%s.%s" % (cybox_major, cybox_minor, cybox_update)
        else:
            version = "%s.%s" % (cybox_major, cybox_minor)

        return version


    def _check_version(self, root):
        """Checks the versions of the Observables instances found in the
        `root` document. This overrides the ``_BaseUpdater._check_version()``
        method.

        Note:
            The ``version`` attribute of `root` is compared against the
            ``VERSION`` class-level attribute.

        Args:
            root: The root node for the document.

        Raises:
            UnknownVersionError: If `root` does not contain a ``version``
                attribute.
            InvalidVersionError: If the ``version`` attribute value for `root`
                does not match the value of ``VERSION``.

        """
        roots = self._get_root_nodes(root)
        expected = self.VERSION

        for node in roots:
            found = self._get_observables_version(node)

            if StrictVersion(expected) != StrictVersion(found):
                raise InvalidVersionError(node, expected, found)


from .cybox_2_0 import Cybox_2_0_Updater
from .cybox_2_0_1 import Cybox_2_0_1_Updater

CYBOX_UPDATERS = {
    '2.0': Cybox_2_0_Updater,
    '2.0.1': Cybox_2_0_1_Updater
}