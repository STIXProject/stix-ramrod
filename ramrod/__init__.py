import copy
from lxml import etree

__version__ = "1.0a"

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI
TAG_SCHEMALOCATION ="{%s}schemaLocation" % NS_XSI

TAG_VOCAB_REFERENCE = "vocab_reference"
TAG_VOCAB_NAME = 'vocab_name'

class UnknownVersionError(Exception):
    pass


class UpdateError(Exception):
    def __init__(self, msg, disallowed=None):
        super(UpdateError, self).__init__(msg)
        self.disallowed = disallowed

    def __str__(self):
        return super(UpdateError, self).__str__()


class InvalidVersionError(Exception):
    def __init__(self, expected=None, found=None):
        self.expected = expected
        self.found = found

    def __str__(self):
        if self.expected and self.found:
            return "Found [%s] but expected [%s]" % (self.expected, self.found)
        else:
            return ("Instance version attribute value does not match expected "
                   "version attribute value")


class _BaseUpdater(object):

    # OVERRIDE THESE IN IMPLEMENTATIONS
    VERSION = None
    DISALLOWED_NAMESPACES = ()
    NSMAP = {}
    UPDATE_NS_MAP = {}
    UPDATE_SCHEMALOC_MAP = {}

    # Controlled Vocabularies
    DEFAULT_VOCAB_NAMESPACE = None
    UPDATE_VOCABS = {}

    def __init__(self):
        pass


    def _get_ns_alias(self, root, ns):
        """Returns the XML Namespace alias defined for a namespace in a given
        instance document.

        Args:
            root (lxml.etree._Element): The instance document root node.
            ns (string): A namespace in the instance document

        Returns:
            A string namespace alias for the given ``ns`` namespace. If the
            namespace is not found in the ``root`` instance document, ``None``
            is returned.

        """
        return root.nsmap.get(ns)


    def _remove_xml_node(self, node):
        """Removes `node` from the parent of `node`."""
        parent = node.getparent()
        parent.remove(node)


    def _copy_xml_node(self, node):
        """Returns a copy of `node`."""
        return copy.deepcopy(node)


    def _remove_xml_attribute(self, node, attr):
        """Removes an attribute from `node`.

        Args:
            node (lxml.etree._Element): An _Element node.
            attr: A attribute tag to be removed.

        """
        try:
            del node.attrib[attr]
        except KeyError:
            # Attribute was not found
            pass


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
        expected = self.VERSION
        found = root.attrib.get('version')

        if not found:
            raise UnknownVersionError()

        if found != expected:
            raise InvalidVersionError(expected, found)


    def _get_ext_namespace(self, node):
        """Returns the namespace which contains the type definition for
        the `node`. The type definition is specified by the ``xsi:type``
        attribute which is formatted as ``[alias]:[type name]``.

        This method splits the ``xsi:type`` attribute value into an alias
        and a type name and performs a namespace lookup for the alias.

        Args:
            node: An instance of lxml.etree._Element which contains an
                ``xsi:type`` attribute.

        Returns:
            The namespace for the type defintion of this node.

        Raises:
            KeyError if the node does not contain an ``xsi:type`` attribute.

        """
        xsi_type = node.attrib[TAG_XSI_TYPE]
        alias, type_ = xsi_type.split(":")
        namespace = node.nsmap[alias]
        return namespace


    def _update_vocabs(self, root):
        vocabs = self.UPDATE_VOCABS
        nsmap = {"xsi":  NS_XSI}
        xpath = "//*[@xsi:type]"
        nodes = root.xpath(xpath, namespaces=nsmap)

        for node in nodes:
            xsi_type = node.attrib[TAG_XSI_TYPE]
            alias, type_ = xsi_type.split(":")

            ext_ns = self._get_ext_namespace(node)

            if ((ext_ns != self.DEFAULT_VOCAB_NAMESPACE) or
                (type_ not in vocabs)):
                continue

            attribs    = node.attrib
            vocab      = vocabs[type_]
            terms      = vocab['terms']
            new_type_  = vocab['type']
            vocab_ref  = vocab['vocab_reference']
            vocab_name = vocab['vocab_name']

            # Update the xsi:type attribute to identify the new
            # controlled vocabulary
            new_xsi_type = "%s:%s" % (alias, new_type_)
            attribs[TAG_XSI_TYPE] = new_xsi_type

            # Update the vocab_reference attribute if present
            if TAG_VOCAB_REFERENCE in attribs:
                attribs[TAG_VOCAB_REFERENCE] = vocab_ref

            # Update the vocab_name attribute if present
            if TAG_VOCAB_NAME in attribs:
                attribs[TAG_VOCAB_NAME] = vocab_name

            # Update the node value if there is a new value in the updated
            # controlled vocabulary
            value = node.text
            node.text = terms.get(value, value)


    def _remove_schemalocations(self, root):
        self._remove_xml_attribute(root, TAG_SCHEMALOCATION)


    def _clean_schemalocs(self, pairs):
        """Returns a list of ``(ns, schemaloc)`` tuples that are allowed
        for the updated document.

        """
        cleaned = []
        for ns, loc in pairs:
            if ns not in self.DISALLOWED_NAMESPACES:
                cleaned.append((ns,loc))

        return cleaned


    def _create_schemaloc_str(self, pairs):
        """Creates a valid ``xsi:schemaLocation`` string.

        Args:
            pairs: list of tuples containing (ns, schemaloc).

        Returns:
            An ``xsi:schemaLocation`` value string.

        """
        schemaloc_str = "   ".join(("%s %s" % (ns, loc)) for ns, loc in pairs)
        return schemaloc_str


    def _remap_schemalocs(self, pairs):
        remapped = []

        for ns, loc in pairs:
            if ns in self.UPDATE_SCHEMALOC_MAP:
                new_loc = self.UPDATE_SCHEMALOC_MAP[ns]
            else:
                new_loc = loc

            remapped.append((ns, new_loc))

        return remapped


    def _update_schemalocs(self, root):
        """Updates the schemalocations found on `root` to point to
        the schemalocations for the next language version.

        The new schemalocations are defined by the ``UPDATE_SCHEMALOC_MAP``
        class-level attribute.

        Args:
            root (lxml.etree._Element): The top-level xml node.

        """
        schemalocs = root.attrib.get(TAG_SCHEMALOCATION)
        if not schemalocs:
            return

        l = schemalocs.split()
        pairs = zip(l[::2], l[1::2])

        cleaned = self._clean_schemalocs(pairs)
        remapped = self._remap_schemalocs(cleaned)
        updated = self._create_schemaloc_str(remapped)

        root.attrib[TAG_SCHEMALOCATION] = updated


    def _remap_namespaces(self, root):
        """Remaps the namespaces found on the input `root` document to
        namespaces defined by the ``UPDATE_NS_MAP``. If a namespace for
        a disallowed field/type is discovered, it is removed.

        Note:
            Disallowed namespaces are defined by the ``DISALLOWED__NAMESPACES``
            class-level attribute.

        Args:
            root (lxml.etree._Element): The top-level node for this document.

        Returns:
            A dictionary of aliases to namespaces.

        """
        remapped = {}
        for alias, ns in root.nsmap.iteritems():
            if ns in self.DISALLOWED_NAMESPACES:
                continue

            remapped[alias] = self.UPDATE_NS_MAP.get(ns, ns)

        return remapped


    def _update_namespaces(self, root):
        """Updates the namespaces in the instance document to align with
        with the updated schema. This will also remove any disallowed
        namespaces if found in the instance document.

        Note:
            The lxml library does not allow you to modify the ``nsmap``
            attribute of an ``_Element`` directly. To modify the ``nsmap``,
            A copy of `root` must be made with a new initial ``nsmap``.

        Returns:
            A copy of the root document with an update ``nsmap`` attribute.

        """
        remapped = self._remap_namespaces(root)
        updated = etree.Element(root.tag, nsmap=remapped)
        updated.attrib.update(root.attrib)
        updated[:] = root[:]

        return updated


def _get_etree_root(doc):
    """Returns an instance of lxml.etree._Element for the given input.

    Args:
        doc: The input XML document. Can be an instance of
            ``lxml.etree._Element``, ``lxml.etree._ElementTree``, a file-like
            object, or a string filename.

    Returns:
        An ``lxml.etree._Element`` instance for `doc`.

    """
    if isinstance(doc, etree._Element):
        root = doc
    elif isinstance(doc, etree._ElementTree):
        root = doc.getroot()
    else:
        parser = etree.ETCompatXMLParser(huge_tree=True,
                                         remove_comments=False,
                                         strip_cdata=False)
        tree = etree.parse(doc, parser=parser)
        root = tree.getroot()

    return root


def _get_version(root):
    """Returns the ``version`` attribute of the input document `root`.

    Args:
        root (lxml.etree._Element): The top-level node for an XML document.

    Returns:
        The value of the ``version`` attribute found on `root`.

    Raises:
        UnknownVersionError: if `root` does not have a ``version`` attribute.

    """
    try:
        version = root.attrib['version']
        return version
    except KeyError:
        raise UnknownVersionError()


def _update_stix(root, from_, to_, force):
    from ramrod.stix import STIX_UPDATERS, STIX_VERSIONS

    if from_ not in STIX_VERSIONS:
        raise UpdateError("The `from_` parameter specified an unknown STIX "
                          "version: %s" % from_)

    if to_ not in STIX_VERSIONS:
        raise UpdateError("The `to_` parameter specified an unknown STIX "
                          "version: %s" % to_)

    idx_from = STIX_VERSIONS.index(from_)
    idx_to = STIX_VERSIONS.index(to_)

    updated = root
    while idx_from < idx_to:
        version = STIX_VERSIONS[idx_from]
        klass   = STIX_UPDATERS[version]
        updater = klass()
        updated = updater.update(updated, force)
        idx_from += 1

    return updated


def _update_cybox(root, from_, to_, force):
    pass


def update(doc, to_='1.1.1', force=False):
    root = _get_etree_root(doc)
    stix_version = _get_version(root)
    updated = _update_stix(root, stix_version, to_, force)
    return etree.ElementTree(updated)
