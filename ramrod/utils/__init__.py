import copy
from lxml import etree
from contextlib import contextmanager
from uuid import uuid4

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI


@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


def get_xml_parser():
    parser = etree.ETCompatXMLParser(huge_tree=True,
                                     remove_comments=False,
                                     strip_cdata=False)

    return parser


def get_etree_root(doc):
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
        parser = get_xml_parser()
        tree = etree.parse(doc, parser=parser)
        root = tree.getroot()

    return root


def replace_xml_element(old, new):
    parent = old.getparent()
    idx = parent.index(old)
    parent.insert(idx, new)
    parent.remove(old)


def remove_xml_element(node):
    """Removes `node` from the parent of `node`."""
    parent = node.getparent()
    parent.remove(node)


def remove_xml_elements(nodes):
    """Removes each node found in `nodes` from the XML document."""
    for node in nodes:
        remove_xml_element(node)


def copy_xml_element(node, tag=None):
    """Returns a copy of `node`."""
    dup = copy.deepcopy(node)
    dup.tag = tag if tag else dup.tag
    return dup

def remove_xml_attribute(node, attr):
    """Removes an attribute from `node`.

    Args:
        node (lxml.etree._Element): An _Element node.
        attr: A attribute tag to be removed.

    """
    with ignored(KeyError):
        del node.attrib[attr]


def remove_xml_attributes(node, attrs):
    for attr in attrs:
        remove_xml_attribute(node, attr)


def get_type_info(node):
    xsi_type = node.attrib[TAG_XSI_TYPE]
    alias, type_ = xsi_type.split(':')
    return (alias, type_)


def get_typed_nodes(root):
    nsmap = {'xsi': NS_XSI}
    xpath = ".//*[@xsi:type]"
    nodes = root.xpath(xpath, namespaces=nsmap)
    return nodes


def get_ext_namespace(node):
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


def create_new_id(orig_id):
    new_id = "%s-cleaned-%s" % (orig_id, uuid4())
    return new_id