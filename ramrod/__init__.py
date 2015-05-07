# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
from . import errors, utils

# Namespace flattening and backwards compatibility
from .options import UpdateOptions, DEFAULT_UPDATE_OPTIONS  # noqa
from .results import ResultDocument, UpdateResults  # noqa

from .version import __version__  # noqa


def update(doc, from_=None, to_=None, options=None, force=False):
    """Updates an input STIX or CybOX document to align with a newer version
    of the STIX/CybOX schemas.

    This will perform the following updates:

        * Update namespaces
        * Update schemalocations
        * Update construct versions (``STIX_Package``, ``Observables``, etc.)
        * Update controlled vocabularies and fix typos
        * Translate structures to new XSD data type instances where possible.
        * Remove empty instances of attributes and elements which were required
          in one version of the language and declared optional in another.

    Args:
        doc: A STIX or CybOX document filename, file-like object,
            ``etree._Element`` or ``etree._ElementTree`` object instance.
        to_ (optional, string): The expected output version of the update
            process. If not specified, the latest language version will be
            assumed.
        from_ (optional, string): The version to update from. If not specified,
            the `from_` version will be retrieved from the input document.
        options (optional): A :class:`.UpdateOptions` instance. If
            ``None``, ``ramrod.DEFAULT_UPDATE_OPTIONS`` will be used.
        force (boolean): Attempt to force the update process if the document
            contains untranslatable fields.

    Returns:
        An instance of
        :class:`.UpdateResults`.

    Raises:
        .UpdateError: If any of the following occur:

            * The input `doc` does not contain a ``STIX_Package``
              or ``Observables`` root-level node.
            * If`force` is ``False`` and an untranslatable field or
              non-unique ID is found in the input `doc`.
        .InvalidVersionError: If the input document contains a version
            attribute that is incompatible with a STIX/CybOX Updater class
            instance.
        .UnknownVersionError: If `from_` was not specified and the input
            document does not contain a version attribute.

    """
    import ramrod.cybox
    import ramrod.stix

    root = utils.get_etree_root(doc)
    name = utils.get_localname(root)
    options = options or DEFAULT_UPDATE_OPTIONS

    packages = {
        'STIX_Package': ramrod.stix,
        'Observables': ramrod.cybox,
    }

    try:
        package = packages[name]
        version_func = package.get_version
        update_func  = package.update
        from_ = from_ or version_func(root)
    except KeyError:
        error = "Document root node must be one of {0}. Found: '{1}'"
        error = error.format(packages.keys(), name)
        raise errors.UpdateError(error)

    updated = update_func(root, from_, to_, options, force)
    return updated


__all__ = [
    'update',
    'UpdateOptions',  # defined in ramrod.options
    'DEFAULT_UPDATE_OPTIONS',  # defined in ramrod.options
    'UpdateResults',  # defined in ramrod.results
    'ResultDocument'  # defined in ramrod.results
]
