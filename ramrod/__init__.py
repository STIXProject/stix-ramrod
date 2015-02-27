# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import StringIO

# external
from lxml import etree

# internal
from . import errors, utils
from .version import __version__


class UpdateResults(object):
    """Returned from :meth:`ramrod.update`, :meth:`ramrod.cybox.update`, and
    :meth:`ramrod.stix.update` methods.

    Attributes:
        document: The updated document. An instance of
            :class:`ramrod.ResultDocument`.
        removed: Untranslatable nodes that were removed from the
            document. An instance of ``tuple``.
        remapped_ids: An ``{ id: [nodes] }`` dictionary where the key is a
            non-unique ID that was discovered in the input document, and the
            nodes are all the nodes which had their ``id`` attribute
            reassigned to be unique.

    """
    def __init__(self, document, removed=None, remapped_ids=None):
        self.document = document
        self.removed = removed or ()
        self.remapped_ids = remapped_ids or {}


    @property
    def document(self):
        return self._document


    @document.setter
    def document(self, value):
        if isinstance(value, ResultDocument):
            self._document = value
        else:
            self._document = ResultDocument(value)


    def __unicode__(self):
        if not self.document:
            return u''

        return unicode(self.document)


    def __str__(self):
        if not self.document:
            return ''

        return str(self.document)


class ResultDocument(object):
    """Used to encapsulate an updated XML document. This is the type of the
    ``document`` attribute on :class:`ramrod.UpdateResults`

    Note:
        This class overrides the ``__str__`` and ``__unicode__`` methods
        and can be used with ``str()`` or ``print``.

    Args:
        document: An instance of ``etree._Element`` or ``etree._ElementTree``.

    """
    def __init__(self, document):
        allowed_types = (etree._Element, etree._ElementTree)

        if not isinstance(document, allowed_types):
            raise ValueError("Document must be one of %s" % (allowed_types,))

        try:
            self._document = document.getroottree()
        except AttributeError:
            self._document = document


    def __unicode__(self):
        return unicode(self.as_stringio().getvalue())


    def __str__(self):
        return unicode(self).encode('utf-8')


    def as_element(self):
        """Returns an ``etree._Element`` representation of the
        ``ResultDocument`` instance.

        """
        return self._document.getroot()

    def as_element_tree(self):
        """Returns an ``etree._ElementTree`` representation of the
        ``ResultDocument`` instance.

        """
        return self._document

    def as_stringio(self):
        """Returns a ``StringIO.StringIO`` representation of the
        ``ResultDocument`` instance.

        """
        buf = etree.tounicode(self._document, pretty_print=True)
        return StringIO.StringIO(buf)


class UpdateOptions(object):
    """Defines configurable options for STIX/CybOX updates.

    Attributes:
        check_versions: If ``True``, input document version information
            will be collected and checked against what the Updater class
            expects. If ``False`` no version check operations will be performed.
            Default value is ``True``.
        new_id_func: A function for setting new IDs on an ``etree._Element``
            node. The function must accept one ``etree._Element`` instance
            argument and assign it a new, unique ``id`` attribute value.
            Default value is :meth:`ramrod.utils.new_id` function.

            Example:
                >>> def my_id_func(node):
                >>>     new_id = my_generate_unique_id()
                >>>     node.attrib['id'] = new_id
                >>>
                >>> options = ramrod.UpdateOptions()
                >>> options.new_id_func = my_id_func

        update_vocabularies: If ``True``, default controlled vocabulary
            instances will be updated and typos will be fixed. If ``False``,
            no updates will be performed against controlled vocabulary
            instances. Default is ``True``.
        remove_optionals: Between revisions of language, some elements which
            were required are made optional. If ``True``, an attempt is made
            to find and remove empty instances of once required
            elements/attributes. Default is ``True``.

    """
    def __init__(self):
        self.check_versions = True
        self.new_id_func = utils.new_id
        self.update_vocabularies = True
        self.remove_optionals = True


DEFAULT_UPDATE_OPTIONS = UpdateOptions()


def update(doc, from_=None, to_=None, options=None, force=False):
    """Updates an input STIX or CybOX document to align with a newer version
    of the STIX/CybOX schemas.

    This will perform the following updates:

        * Update namespaces
        * Update schemalocations
        * Update construct versions (``STIX_Package``, ``Observables``, etc.)
        * Update controlled vocabularies and fix typos
        * Translate structures to new XSD datatype instances where possible.
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
    import ramrod.stix
    import ramrod.cybox

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
