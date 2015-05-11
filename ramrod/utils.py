# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import copy
import contextlib
import uuid
from distutils.version import StrictVersion

# external
from lxml import etree

# relative
from . import errors, xmlconst


@contextlib.contextmanager
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
    parser = etree.ETCompatXMLParser(
        huge_tree=True,
        resolve_entities=False,
        remove_comments=False,
        strip_cdata=False,
        remove_blank_text=True
    )

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

    if isinstance(doc, etree._Element):  # noqa
        root = deepcopy(doc) if make_copy else doc
    elif isinstance(doc, etree._ElementTree):  # noqa
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
    if `tag` is not ``None``.

    """
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
    xsi_type = node.attrib[xmlconst.TAG_XSI_TYPE]
    alias, typename = xsi_type.split(':')
    return (alias, typename)


def get_typed_nodes(root):
    """Finds all nodes under `root` which have an ``xsi:type`` attribute.

    Returns:
        A list of ``etree._Element`` instances.

    """
    nsmap = {'xsi': xmlconst.NS_XSI}
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
    xsi_type = node.attrib[xmlconst.TAG_XSI_TYPE]
    alias = xsi_type.split(":")[0]
    namespace = node.nsmap[alias]
    return namespace


def create_new_id(orig_id):
    """Creates a new ID from `orig_id` by appending '-cleaned-' and a UUID4
    string to the end of the `orig_id` value.

    Returns:
        An ID string.

    """
    new_id = "%s-cleaned-%s" % (orig_id, uuid.uuid4())
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


def get_localname(node):
    """Returns the localname portion the `node` QName"""
    return etree.QName(node).localname


def get_namespace(node):
    """Returns the namespace portion of the QName for `node`."""
    return etree.QName(node).namespace


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


def get_schemaloc_pairs(node):
    """Parses the xsi:schemaLocation attribute on `node`.

    Returns:
        A list of (ns, schemaLocation) tuples for the node.

    Raises:
        KeyError: If `node` does not have an xsi:schemaLocation attribute.

    """
    schemalocs = node.attrib[xmlconst.TAG_SCHEMALOCATION]
    l = schemalocs.split()
    pairs = zip(l[::2], l[1::2])

    return pairs


def is_version_equal(x, y):
    """Attempts to determine if the `x` amd `y` version numbers are semantically
    equivalent.

    Examples:
        The version strings "2.1.0" and "2.1" represent semantically equivalent
        versions, despite not being equal strings.
    Args:
        x: A string version number. Ex: '2.1.0'
        y: A string version number. Ex: '2.1'

    """
    return StrictVersion(x) == StrictVersion(y)


def validate_version(version, allowed):
    """Raises a :class:`.InvalidVersionError` if `version` is not found in
    `allowed`.

    Args:
        version: A version string.
        allowed: An iterable collection of version strings.

    """
    if not version:
        error = "The version was `None` or could not be determined."
        raise errors.UnknownVersionError(error)

    if version not in allowed:
        error = "The version '{0}' is not valid. Must be one of '{1}'"
        error = error.format(version, allowed)
        raise errors.InvalidVersionError(error)


def validate_versions(from_, to_, allowed):
    """Raises a :class:`.InvalidVersionError` if `from_` or `to_` are not
    found in `allowed` or `from_` is greater than or equal to `to_`.

    Args:
        from_: A version string.
        to_: A version string.
        allowed: An iterable collection of version strings.

    """
    validate_version(from_, allowed)
    validate_version(to_, allowed)

    if StrictVersion(from_) >= StrictVersion(to_):
        error =  "Cannot upgrade from '{0}' to '{1}'"
        error = error.format(from_, to_)
        raise errors.InvalidVersionError(error)


def iterchildren(node):
    """Returns an iterator which yields direct child elements of `node`.

    """
    return node.iterchildren('*')


def children(node):
    """Returns an iterable collection of etree Element nodes that are direct
    children of `node`.

    """
    return list(iterchildren(node))


def iterdescendants(node):
    """Returns an iterator which yields descendant elements of `node`.

    """
    return node.iterdescendants('*')


def descendants(node):
    """Returns a list of etree Element nodes that are descendants of `node`.

    """
    return list(iterdescendants(node))


def strip_whitespace(string):
    """Returns a copy of `string` with its whitespace stripped.

    """
    if string is None:
        return None

    return "".join(string.split())
