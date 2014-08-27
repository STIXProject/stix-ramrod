

NS_XSI = "http://www.w3.org/2001/XMLSchema-instance"
TAG_XSI_TYPE = "{http://www.w3.org/2001/XMLSchema-instance}type"

class UnknownVersionException(Exception):
    pass

class UntranslatableFieldException(Exception):
    pass

class UpdateException(Exception):
    pass

class IncorrectVersionException(Exception):
    pass


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
