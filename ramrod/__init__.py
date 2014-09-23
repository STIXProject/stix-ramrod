import copy
from collections import defaultdict
from lxml import etree
from lxml.etree import QName
from distutils.version import StrictVersion
from ramrod.utils import ignored

__version__ = "1.0a1"

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI
TAG_SCHEMALOCATION ="{%s}schemaLocation" % NS_XSI

TAG_VOCAB_REFERENCE = "vocab_reference"
TAG_VOCAB_NAME = 'vocab_name'


class UnknownVersionError(Exception):
    pass


class UpdateError(Exception):
    def __init__(self, message=None, disallowed=None, duplicates=None):
        super(UpdateError, self).__init__(message)
        self.disallowed = disallowed
        self.duplicates = duplicates

    def __str__(self):
        s = "Update Error: %s\n%s" % (self.message, self.disallowed)
        return s


class InvalidVersionError(Exception):
    def __init__(self, node=None, expected=None, found=None):
        self.node = node
        self.expected = expected
        self.found = found

    def __str__(self):
        if all(((self.node is not None), self.expected, self.found)):
            return ("Line %s:Found '%s' but expected '%s'" %
                    (self.node.sourceline, self.found, self.expected))
        else:
            return ("Instance version attribute value does not match expected "
                   "version attribute value")


class Vocab(object):
    TYPE = None
    VOCAB_REFERENCE = None
    VOCAB_NAME = None
    TERMS = {}


class _DisallowedFields(object):
    XPATH = "."
    CTX_TYPES = {}
    NSMAP = None


    def __init__(self,):
        pass


    @classmethod
    def _interrogate(cls, nodes):
        return nodes


    @classmethod
    def _get_contexts(cls, root, typed=None):
        ctx = cls.CTX_TYPES

        if not ctx:
            return (root,)

        if not typed:
            typed = _get_typed_nodes(root)

        contexts = []
        for node in typed:
            alias, type_ = _get_type_info(node)
            ns = _get_ext_namespace(node)

            if ctx.get(type_) == ns:
                contexts.append(node)

        return contexts

    @classmethod
    def find(cls, root, typed=None):
        contexts = cls._get_contexts(root, typed)
        xpath, nsmap = cls.XPATH, cls.NSMAP

        found = []
        for ctx in contexts:
            nodes = ctx.xpath(xpath, namespaces=nsmap)
            interrogated = cls._interrogate(nodes)
            found.extend(interrogated)

        return found


class _OptionalAttributes(_DisallowedFields):
    ATTRIBUTES = ()

    def __init__(self):
        super(_OptionalAttributes, self).__init__()

    @classmethod
    def _interrogate(cls, nodes):
        contraband = []

        attrs = cls.ATTRIBUTES
        for node in nodes:
            for attr in attrs:
                val = node.attrib.get(attr)
                if not val:
                    contraband.append(node)
                    break

        return contraband


class _OptionalElements(_DisallowedFields):
    def __init__(self):
        super(_OptionalElements, self).__init__()


    @classmethod
    def _interrogate(cls, nodes):
        """Checks if any of the nodes in `nodes` are empty.

        Returns:
            A list of nodes that are empty.

        """
        contraband = []
        for node in nodes:
            if all((node.text is None, len(node) == 0), not(node.attrib)):
                contraband.append(node)

        return contraband


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
        self.XPATH_VERSIONED_NODES = "."
        self.XPATH_ROOT_NODES = "."


    def _is_leaf(self, node):
        """Returns ``True`` if the `node` has no children."""
        return (len(node) == 0)


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


    def _get_duplicates(self, root):
        """This checks `root` for nodes with duplicate IDs.

        Returns:
            A dictionary where the ID is the key and the values are lists of
            lxml._Element nodes.

        """
        id_nodes = defaultdict(list)
        roots = self._get_root_nodes(root)
        for node in roots:
            for child in node:
                if 'id' not in node.attrib:
                    continue

                id_ = child.attrib['id']
                id_nodes[id_].append(child)

        return dict((id_, nodes) for id_, nodes in id_nodes if len(nodes) > 1)


    def _remove_xml_node(self, node):
        """Removes `node` from the parent of `node`."""
        parent = node.getparent()
        parent.remove(node)


    def _remove_xml_nodes(self, nodes):
        """Removes each node found in `nodes` from the XML document."""
        for node in nodes:
            self._remove_xml_node(node)


    def _copy_xml_node(self, node):
        """Returns a copy of `node`."""
        return copy.deepcopy(node)


    def _remove_xml_attribute(self, node, attr):
        """Removes an attribute from `node`.

        Args:
            node (lxml.etree._Element): An _Element node.
            attr: A attribute tag to be removed.

        """
        with ignored(KeyError):
            del node.attrib[attr]


    def _remove_xml_attributes(self, node, attrs):
        for attr in attrs:
            self._remove_xml_attribute(node, attr)


    def _get_versioned_nodes(self, root):
        xpath = self.XPATH_VERSIONED_NODES
        namespaces = self.NSMAP
        return root.xpath(xpath, namespaces=namespaces)


    def _get_root_nodes(self, root):
        xpath = self.XPATH_ROOT_NODES
        namespaces = self.NSMAP
        return root.xpath(xpath, namespaces=namespaces)


    def _check_version(self, root):
        """Checks that the version of the document matches the expected
        version. Derived classes need to implement this method.

        """
        raise NotImplementedError()


    def _update_vocabs(self, root):
        default_vocab_ns = self.DEFAULT_VOCAB_NAMESPACE
        vocabs = self.UPDATE_VOCABS
        typed_nodes = _get_typed_nodes(root)

        for node in typed_nodes:
            alias, type_ = _get_type_info(node)
            ext_ns = _get_ext_namespace(node)

            if not all((ext_ns == default_vocab_ns, type_ in vocabs)):
                continue

            attribs    = node.attrib
            vocab      = vocabs[type_]
            terms      = vocab.TERMS
            new_type_  = vocab.TYPE
            vocab_ref  = vocab.VOCAB_REFERENCE
            vocab_name = vocab.VOCAB_NAME

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


    def _create_schemaloc_str(self, pairs):
        """Creates a valid ``xsi:schemaLocation`` string.

        Args:
            pairs: list of tuples containing (ns, schemaloc).

        Returns:
            An ``xsi:schemaLocation`` value string.

        """
        schemaloc_str = "   ".join(("%s %s" % (ns, loc)) for ns, loc in pairs)
        return schemaloc_str


    def _clean_schemalocs(self, pairs):
        """Returns a list of ``(ns, schemaloc)`` tuples that are allowed
        for the updated document.

        """
        return [(ns, loc) for ns, loc in pairs if ns not in self.DISALLOWED_NAMESPACES]


    def _remap_schemalocs(self, pairs):
        remapped = []

        for ns, loc in pairs:
            updated_ns  = self.UPDATE_NS_MAP.get(ns, ns)
            updated_loc = self.UPDATE_SCHEMALOC_MAP.get(updated_ns, loc)
            remapped.append((updated_ns, updated_loc))

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
            Disallowed namespaces are defined by the ``DISALLOWED_NAMESPACES``
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


def _get_type_info(node):
    xsi_type = node.attrib[TAG_XSI_TYPE]
    alias, type_ = xsi_type.split(':')
    return (alias, type_)


def _get_typed_nodes(root):
    nsmap = {'xsi': NS_XSI}
    xpath = ".//*[@xsi:type]"
    nodes = root.xpath(xpath, namespaces=nsmap)
    return nodes


def _get_ext_namespace(node):
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


def _get_xml_parser():
    parser = etree.ETCompatXMLParser(huge_tree=True,
                                     remove_comments=False,
                                     strip_cdata=False)

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
        parser = _get_xml_parser()
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

    if StrictVersion(from_) >= StrictVersion(to_):
        raise UpdateError("Cannot upgrade from %s to %s" % (from_, to_))

    updated = root
    idx_from = STIX_VERSIONS.index(from_)
    idx_to = STIX_VERSIONS.index(to_)
    for version in STIX_VERSIONS[idx_from:idx_to]:
        klass   = STIX_UPDATERS[version]
        updater = klass()
        updated = updater.update(updated, force)

    return updated


def _update_cybox(root, from_, to_, force):
    from ramrod.cybox import CYBOX_UPDATERS, CYBOX_VERSIONS

    if from_ not in CYBOX_VERSIONS:
        raise UpdateError("The `from_` parameter specified an unknown CybOX "
                          "version: %s" % from_)

    if to_ not in CYBOX_VERSIONS:
        raise UpdateError("The `to_` parameter specified an unknown CybOX "
                          "version: %s" % to_)

    if StrictVersion(from_) >= StrictVersion(to_):
        raise UpdateError("Cannot upgrade from %s to %s" % (from_, to_))

    updated = root
    idx_from = CYBOX_VERSIONS.index(from_)
    idx_to = CYBOX_VERSIONS.index(to_)
    for version in CYBOX_VERSIONS[idx_from:idx_to]:
        klass   = CYBOX_UPDATERS[version]
        updater = klass()
        updated = updater.update(updated, force)

    return updated


def update(doc, to_, from_=None, force=False):
    root = _get_etree_root(doc)
    name = QName(root).localname
    version = _get_version(root)

    update_methods = {
        'STIX_Package': _update_stix,
        'Observables': _update_cybox
    }

    try:
        update = update_methods[name]
    except KeyError:
        raise UpdateError("Document root node must be one of %s" % (update_methods.keys(),))

    updated = update(root, version, to_, force)
    return etree.ElementTree(updated)
