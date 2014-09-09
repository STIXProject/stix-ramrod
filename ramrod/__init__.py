import copy
from lxml import etree

__version__ = "1.0a"

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI
TAG_SCHEMALOCATION ="{%s}schemaLocation" % NS_XSI


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
    DISALLOWED_NAMESPACES = ()
    NSMAP = {}
    UPDATE_NS_MAP = {}
    UPDATE_SCHEMALOC_MAP = {}

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
        parent = node.getparent()
        parent.remove(node)


    def _copy_xml_node(self, node):
        return copy.deepcopy(node)


    def _remove_xml_attribute(self, node, attr):
        try:
            del node.attrib[attr]
        except KeyError:
            # Attribute was not found
            pass


    def _remove_schemalocations(self, root):
        self._remove_xml_attribute(root, TAG_SCHEMALOCATION)


    def _clean_schemalocs(self, pairs):
        cleaned = []
        for ns, loc in pairs:
            if ns not in self.DISALLOWED_NAMESPACES:
                cleaned.append((ns,loc))

        return cleaned


    def _create_schemaloc_str(self, pairs):
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

        Returns:
            A copy of the root document. It is impossible to update the
            ``nsmap`` member of an etree._Element[Tree] directly, so we need
            to make a copy with a modified initial nsmap.

        """
        remapped = self._remap_namespaces(root)
        updated = etree.Element(root.tag, nsmap=remapped)
        updated.attrib.update(root.attrib)
        updated[:] = root[:]

        return updated


def _get_etree_root(doc):
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
    try:
        version = root.attrib['version']
        return version
    except KeyError:
        raise UnknownVersionError()


def _update(root, from_, to_, force):
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


def update(doc, to_='1.1.1', force=False):
    root = _get_etree_root(doc)
    stix_version = _get_version(root)
    updated = _update(root, stix_version, to_, force)
    return etree.ElementTree(updated)
