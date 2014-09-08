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


def _get_etree_root(doc):
    if isinstance(doc, etree._Element):
        root = doc
    elif isinstance(doc, etree._ElementTree):
        root = doc.getroot()
    else:
        parser = etree.ETCompatXMLParser(huge_tree=True, strip_cdata=False)
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
