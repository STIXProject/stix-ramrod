# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
import ramrod
import ramrod.utils as utils

# relative
from . import base, common
from .cybox_2_0 import Cybox_2_0_Updater
from .cybox_2_0_1 import Cybox_2_0_1_Updater

CYBOX_UPDATERS = {
    '2.0': Cybox_2_0_Updater,
    '2.0.1': Cybox_2_0_1_Updater
}

CYBOX_VERSIONS = common.CYBOX_VERSIONS


def get_version(doc):
    """Returns the version number for input CybOX document."""
    root = utils.get_etree_root(doc)
    return base.BaseCyboxUpdater.get_version(root)


def update(doc, from_=None, to_=None, options=None, force=False):
    """Updates a CybOX document to align with a given version of the CybOX
    Language.

    Args:
        doc: A CybOX document filename, file-like object, ``etree._Element``, or
            ``etree._ElementTree``.
        from_ (optional, string): The base version for the update process. If
            ``None``, an attempt will be made to extract the version number
            from `doc`.
        to_ (optional, string): The version to update to. If ``None``, the
            latest version of CybOX is assumed.
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
    versions = common.CYBOX_VERSIONS
    from_ = from_ or base.BaseCyboxUpdater.get_version(root)
    to_ = to_ or versions[-1]  # The latest version if not specified

    utils.validate_versions(from_, to_, versions)

    removed, remapped = [], {}
    idx = versions.index

    for version in versions[idx(from_):idx(to_)]:
        updater   = CYBOX_UPDATERS[version]
        results   = updater().update(root, options=options, force=force)
        root      = results.document.as_element()
        removed.extend(results.removed)
        remapped.update(results.remapped_ids)


    results = ramrod.UpdateResults(
        document=root,
        removed=removed,
        remapped_ids=remapped
    )

    return results
