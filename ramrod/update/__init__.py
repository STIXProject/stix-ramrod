
import copy

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{%s}type" % NS_XSI
TAG_SCHEMALOCATION ="{%s}schemaLocation" % NS_XSI

class UnknownVersionException(Exception):
    pass

class UntranslatableFieldException(Exception):
    pass

class UpdateException(Exception):
    pass

class IncorrectVersionException(Exception):
    def __init__(self, expected=None, found=None):
        self.expected = expected
        self.found = found

    def __str__(self):
        if self.expected and self.found:
            return "Found [%s] but expected [%s]" % (self.expected, self.found)
        else:
            return "Instance version attribute value does not match expected " \
                   "version attribute value"


def get_ns_alias(root, ns):
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


def remove_xml_node(node):
    parent = node.getparent()
    parent.remove(node)

def copy_xml_node(node):
    return copy.deepcopy(node)


def remove_xml_attribute(node, attr):
    try:
        del node.attrib[attr]
    except KeyError:
        # Attribute was not found
        pass
