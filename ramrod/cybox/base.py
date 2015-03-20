# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
from ramrod import base, errors, utils

# relative
from . import common


class BaseCyboxUpdater(base.BaseUpdater):
    """Base class for CybOX updating code. Sets default values for
    CybOX-specific xpaths and namespaces.

    """
    DEFAULT_VOCAB_NAMESPACE = 'http://cybox.mitre.org/default_vocabularies-2'
    XPATH_VERSIONED_NODES = "//cybox:Observables"
    XPATH_ROOT_NODES = "//cybox:Observables"
    XPATH_OBJECT_PROPS = "//cybox:Object/cybox:Properties"

    def __init__(self):
        super(BaseCyboxUpdater, self).__init__()

    @classmethod
    def get_version(cls, observables):
        """Returns the version of the `observables` ``Observables`` node.

        Returns:
            A dotted-decimal a version string from the ``cybox_major``,
            ``cybox_minor`` and ``cybox_update`` attribute values.

        Raises:
            .UnknownVersionError: If `observables` does not contain any of the
                following attributes:

                * ``cybox_major_version``
                * ``cybox_minor_version``
                * ``cybox_update_version``
        """
        cybox_major  = observables.attrib.get(common.TAG_CYBOX_MAJOR)
        cybox_minor  = observables.attrib.get(common.TAG_CYBOX_MINOR)
        cybox_update = observables.attrib.get(common.TAG_CYBOX_UPDATE)

        if not (cybox_major and cybox_minor):
            error = "CybOX document contains no version information."
            raise errors.UnknownVersionError(error)

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
            .UnknownVersionError: If `root` does not contain a ``version``
                attribute.
            .InvalidVersionError: If the ``version`` attribute value for `root`
                does not match the value of ``VERSION``.

        """
        roots = self._get_root_nodes(root)
        expected = self.VERSION

        for node in roots:
            found = self.get_version(node)

            if utils.is_version_equal(expected, found):
                continue

            error = "Document version '{0}' does not match the expected version '{1}'."
            error = error.format(found, expected)
            raise errors.InvalidVersionError(
                message=error,
                node=node,
                expected=expected,
                found=found
            )


class CyboxVocab(base.Vocab):
    VOCAB_NAMESPACE = BaseCyboxUpdater.DEFAULT_VOCAB_NAMESPACE