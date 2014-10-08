# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

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


def get_etree_root(doc, make_copy=False):
    """Returns an instance of lxml.etree._Element for the given input.

    Args:
        doc: The input XML document. Can be an instance of
            ``lxml.etree._Element``, ``lxml.etree._ElementTree``, a file-like
            object, or a string filename.
        make_copy: If ``True``, a ``copy.deepcopy()`` of the root node will be
            returned.

    Returns:
        An ``lxml.etree._Element`` instance for `doc`.

    """
    deepcopy = copy.deepcopy

    if isinstance(doc, etree._Element):
        root = deepcopy(doc) if make_copy else doc
    elif isinstance(doc, etree._ElementTree):
        root = deepcopy(doc.getroot()) if make_copy else doc.getroot()
    else:
        parser = get_xml_parser()
        tree = etree.parse(doc, parser=parser)
        root = tree.getroot()

    return root


def replace_xml_element(old, new):
    """Replaces `old` node with `new` in the document which `old` exists."""
    if old is new:
        return old

    parent = old.getparent()
    if parent is not None:
        idx = parent.index(old)
        parent.insert(idx, new)
        parent.remove(old)


def remove_xml_element(node):
    """Removes `node` from the parent of `node`."""
    parent = node.getparent()

    if parent is not None:
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

    Example:
        >>> e = etree.Element('test')
        >>> e.attrib['id'] = 'example:non-unique-id'
        >>> e.attrib['id']
        'example:non-unique-id'
        >>> e = new_id(e)
        >>> e.attrib['id']
        'example:non-unique-id-cleaned-92eaa185-48e2-433e-82ba-a58f692bac32'

    """
    orig_id = node.attrib['id']
    unique_id = create_new_id(orig_id)

    node.attrib['id'] = unique_id
    return node


def get_node_text(node):
    """Returns the text for a etree _Element `node`. If the node contains
    CDATA information, the text will be wrapped in an ``etree.CDATA`` instance.

    Returns:
        If the `node` contains a ``<![CDATA[]]>`` block, a ``etree.CDATA``
        instance will be returned. If the node contains children, ``None``.
        The `node` ``text`` value otherwise.

    """
    if len(node) > 0:
        return None

    if "<![CDATA[" in etree.tostring(node):
            return etree.CDATA(node.text)

    return node.text



