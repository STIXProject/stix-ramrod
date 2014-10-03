import copy
from lxml import etree
from contextlib import contextmanager
from uuid import uuid4

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI


@contextmanager
def ignored(*exceptions):
    """Allows you to ignore exceptions cleanly using context managers. This
    exists in Python 3.

    """
    try:
        yield
    except exceptions:
        pass


def get_xml_parser():
    """Returns an ``etree.ETCompatXMLParser`` instance."""
    parser = etree.ETCompatXMLParser(huge_tree=True,
                                     remove_comments=False,
                                     strip_cdata=False,
                                     remove_blank_text=True)

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
    """Replaces `old` node with `new` in the document which `old` exists."""
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
    """Returns a copy of `node`. The copied node will be renamed to `tag`
    if `tag` is not ``None``."""
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
    """Removes xml attributes `attrs` from `node`."""
    for attr in attrs:
        remove_xml_attribute(node, attr)


def get_type_info(node):
    """Returns a (ns alias, typename) tuple which is generated from the
    ``xsi:type`` attribute on `node`.

    Raises:
        KeyError: If `node` does not contain an ``xsi:type`` attribute.
        ValueError: If the ``xsi:type`` attribute does not have a colon in it.

    """
    xsi_type = node.attrib[TAG_XSI_TYPE]
    alias, type_ = xsi_type.split(':')
    return (alias, type_)


def get_typed_nodes(root):
    """Finds all nodes under `root` which have an ``xsi:type`` attribute.

    Returns:
        A list of ``etree._Element`` instances.

    """
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
        KeyError: if the node does not contain an ``xsi:type`` attribute.

    """
    xsi_type = node.attrib[TAG_XSI_TYPE]
    alias, type_ = xsi_type.split(":")
    namespace = node.nsmap[alias]
    return namespace


def create_new_id(orig_id):
    """Creates a new ID from `orig_id` by appending '-cleaned-' and a UUID4
    string to the end of the `orig_id` value.

    """
    new_id = "%s-cleaned-%s" % (orig_id, uuid4())
    return new_id


def new_id(node):
    """Assigns a new, unique ID to `node` by appending '-cleaned-' and a UUID4
    string to the end of the ``id`` attribute value of the node.

    """
    orig_id = node.attrib['id']
    unique_id = create_new_id(orig_id)

    node.attrib['id'] = unique_id
    return node


def update_nsmap(root, nsmap):
    """Updates the ``nsmap`` attribute found on `root` to `nsmap`.

    The lxml API does not allow in-place modification of the ``nsmap``
    dictionary. Instead, a copy of the node must be created and initialized with
    an updated ``nsmap`` attribute.

    Returns:
        A copy of `root` with its ``nsmap`` attribute updated to include the
        values defined by the `nsmap` parameter.

    """
    new_root  = etree.Element(root.tag, nsmap=nsmap)
    new_root.attrib.update(root.attrib)
    new_root[:] = root[:]

    return new_root


