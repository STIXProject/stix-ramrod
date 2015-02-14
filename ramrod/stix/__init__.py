# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
from distutils.version import StrictVersion

# internal
import ramrod.utils as utils
import ramrod.errors as errors
from ramrod import (_BaseUpdater, _Vocab, UpdateResults)

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
        self._init_cybox_updater()

    def _init_cybox_updater(self):
        """Returns an initialized instance of a _CyboxUpdater implementation.

        Note:
            This needs to be implemented by derived classes.

        """
        raise NotImplementedError()

    @classmethod
    def get_version(cls, package):
        """Returns the version of the `package` ``STIX_Package`` element by
        inspecting its ``version`` attribute.

        """
        return package.attrib.get('version')

    def _check_version(self, root):
        """Checks that the version of the document `root` is valid for an
        implementation of ``_BaseUpdater``.

        Note:
            The ``version`` attribute of `root` is compared against the
            ``VERSION`` class-level attribute.

        Raises:
            ramrod.UnknownVersionError: If `root` does not contain a ``version``
                attribute.
            ramrod.InvalidVersionError: If the ``version`` attribute value for
                `root` does not match the value of ``VERSION``.

        """
        roots = self._get_root_nodes(root)
        expected = self.VERSION

        for node in roots:
            found = self.get_version(node)

            if not found:
                error = "Unable to determine the version of the STIX document."
                raise errors.UnknownVersionError(error)

            if utils.is_version_equal(found, expected):
                return

            error = "Document version does not match the expected version."
            raise errors.InvalidVersionError(
                message=error,
                node=node,
                expected=expected,
                found=found
            )


class _STIXVocab(_Vocab):
    VOCAB_NAMESPACE = _STIXUpdater.DEFAULT_VOCAB_NAMESPACE


from .stix_1_0 import STIX_1_0_Updater
from .stix_1_0_1 import  STIX_1_0_1_Updater
from .stix_1_1 import STIX_1_1_Updater

STIX_VERSIONS = ('1.0', '1.0.1', '1.1', '1.1.1')
STIX_UPDATERS = {
    '1.0': STIX_1_0_Updater,
    '1.0.1': STIX_1_0_1_Updater,
    '1.1': STIX_1_1_Updater
}


def update(doc, from_=None, to_=None, options=None, force=False):
    """Updates a STIX document to align with a given version of the STIX
    Language schemas.

    Args:
        doc: A STIX document filename, file-like object, ``etree._Element``, or
            ``etree._ElementTree``.
        from_ (optional, string): The base version for the update process. If
            ``None``, an attempt will be made to extract the version number
            from `doc`.
        to_ (optional, string): The version to update to. If ``None``, the
            latest version of STIX is assumed.
        options (optional): A :class:`ramrod.UpdateOptions` instance. If
            ``None``, ``ramrod.DEFAULT_UPDATE_OPTIONS`` will be used.
        force (boolean): Forces the update process. This may result in content
            being removed during the update process and could result in
            schema-invalid content. **Use at your own risk!**

    Returns:
        An instance of ``ramrod.UpdateResults``.

    Raises:
        ramrod.UpdateError: If any of the following conditions are encountered:

            * The `from_` or `to_` versions are invalid.
            * An untranslatable field is encountered and `force` is ``False``.
            * A non-unique ID is encountered and `force` is ``False``.
        ramrod.InvalidVersionError: If the source document version and the
            `from_` value do not match and `force` is ``False``.
        ramrod.UnknownVersionError: If the source document does not contain
            version information and `force` is ``False``.

    """
    root = utils.get_etree_root(doc)
    from_ = from_ or _STIXUpdater.get_version(root)
    to_ = to_ or STIX_VERSIONS[-1]  # The latest version if not specified

    utils.validate_versions(from_, to_, STIX_VERSIONS)

    removed, remapped = [], {}
    idx = STIX_VERSIONS.index

    for version in STIX_VERSIONS[idx(from_):idx(to_)]:
        updater   = STIX_UPDATERS[version]
        results   = updater().update(root, options=options, force=force)
        root      = results.document.as_element()
        removed.extend(results.removed)
        remapped.update(results.remapped_ids)

    results = UpdateResults(
        document=root,
        removed=removed,
        remapped_ids=remapped
    )

    return results