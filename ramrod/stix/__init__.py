# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# stdlib
import itertools

# internal
from ramrod import utils, results

# relative
from . import common
from .base import BaseSTIXUpdater


def get_version(doc):
    """Returns the version number for input STIX document."""
    root = utils.get_etree_root(doc)
    return BaseSTIXUpdater.get_version(root)


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
        .UpdateError: If any of the following conditions are encountered:

            * The `from_` or `to_` versions are invalid.
            * An untranslatable field is encountered and `force` is ``False``.
            * A non-unique ID is encountered and `force` is ``False``.
        .InvalidVersionError: If the source document version and the
            `from_` value do not match and `force` is ``False``.
        .UnknownVersionError: If the source document does not contain
            version information and `force` is ``False``.

    """
    root = utils.get_etree_root(doc)
    versions = common.STIX_VERSIONS
    from_ = from_ or BaseSTIXUpdater.get_version(root)
    to_ = to_ or versions[-1]  # The latest version if not specified

    utils.validate_versions(from_, to_, versions)

    removed, remapped = [], {}
    idx = versions.index

    for version in versions[idx(from_):idx(to_)]:
        updater   = STIX_UPDATERS[version]
        result    = updater().update(root, options=options, force=force)
        root      = result.document.as_element()

        removed.extend(result.removed)
        remapped.update(result.remapped_ids)

    result = results.UpdateResults(
        document=root,
        removed=removed,
        remapped_ids=remapped
    )

    return result


# All known STIX versions.
STIX_VERSIONS = common.STIX_VERSIONS

# A mapping of STIX version numbers to its respective updater class.
STIX_UPDATERS = {}

def _wire_nsmaps(cls):
    # Wiring namespace dictionaries
    nsmapped = itertools.chain(
        cls.DISALLOWED,
        cls.OPTIONAL_ELEMENTS,
        cls.OPTIONAL_ATTRIBUTES,
        cls.TRANSLATABLE_FIELDS,
    )

    for klass in nsmapped:
        klass.NSMAP = cls.NSMAP

def register_updater(cls):
    """Registers a STIX updater class.

    """
    version = cls.VERSION

    if version not in STIX_VERSIONS:
        raise ValueError("Invalid STIX version found on updater: %s" % version)

    # Attach the cls NSMAP to each of the updater subcomponent classes.
    _wire_nsmaps(cls)

    # Register the updater in the global dictionary.
    STIX_UPDATERS[version] = cls

    return cls


# Registers the classes as updaters and flattens the namespaces
from .stix_1_0 import STIX_1_0_Updater  # noqa
from .stix_1_0_1 import STIX_1_0_1_Updater  # noqa
from .stix_1_1 import STIX_1_1_Updater  # noqa
from .stix_1_1_1 import STIX_1_1_1_Updater  # noqa


