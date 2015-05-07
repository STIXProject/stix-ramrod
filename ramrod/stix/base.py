# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# stdlib
import itertools

# internal
from ramrod import base, errors, utils


class BaseSTIXUpdater(base.BaseUpdater):
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

    CYBOX_UPDATER = None

    def __init__(self):
        super(BaseSTIXUpdater, self).__init__()
        self._init_cybox_updater()

    def _init_cybox_updater(self):
        """Returns an initialized instance of a _CyboxUpdater implementation.

        Note:
            This needs to be implemented by derived classes.

        """
        if not self.CYBOX_UPDATER:
            self._cybox_updater = None
            return

        updater = self.CYBOX_UPDATER()  # noqa

        updater.NSMAP = dict(
            itertools.chain(
                self.NSMAP.iteritems(),
                self.CYBOX_UPDATER.NSMAP.iteritems()
            )
        )

        self._cybox_updater = updater

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
            .UnknownVersionError: If `root` does not contain a ``version``
                attribute.
            .InvalidVersionError: If the ``version`` attribute value for
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


class STIXVocab(base.Vocab):
    VOCAB_NAMESPACE = BaseSTIXUpdater.DEFAULT_VOCAB_NAMESPACE
