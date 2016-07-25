#!/usr/bin/env python

# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

"""
This script performs a function similar to stix-ramrod, but is much simpler.
It *only* handles namespace changes.  It is written in a generic way such
that it can work on any valid XML document, not just STIX documents.  It also
means this can "downgrade" just as easily as "upgrade" content (as long as it
only involves namespace changes).  stix-ramrod can only upgrade.
"""

from __future__ import print_function
import argparse
import lxml.etree as ET
import sys
from six import iteritems, itervalues, PY2

STIX_NS_1_2 = [
    # "Core" stuff
    "http://stix.mitre.org/stix-1",
    "http://stix.mitre.org/common-1",
    "http://stix.mitre.org/default_vocabularies-1",

    # Components
    "http://stix.mitre.org/Campaign-1",
    "http://stix.mitre.org/CourseOfAction-1",
    "http://data-marking.mitre.org/Marking-1",
    "http://stix.mitre.org/ExploitTarget-1",
    "http://stix.mitre.org/Incident-1",
    "http://stix.mitre.org/Indicator-2",
    "http://stix.mitre.org/Report-1",
    "http://stix.mitre.org/ThreatActor-1",
    "http://stix.mitre.org/TTP-1",

    # Extensions
    "http://stix.mitre.org/extensions/Address#CIQAddress3.0-1",
    "http://stix.mitre.org/extensions/AP#CAPEC2.7-1",
    "http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1",
    "http://stix.mitre.org/extensions/Malware#MAEC4.1-1",
    "http://data-marking.mitre.org/extensions/MarkingStructure#Simple-1",
    "http://data-marking.mitre.org/extensions/MarkingStructure#Terms_Of_Use-1",
    "http://data-marking.mitre.org/extensions/MarkingStructure#TLP-1",
    "http://stix.mitre.org/extensions/StructuredCOA#Generic-1",
    "http://stix.mitre.org/extensions/TestMechanism#Generic-1"
    "http://stix.mitre.org/extensions/TestMechanism#OpenIOC2010-1",
    "http://stix.mitre.org/extensions/TestMechanism#OVAL5.10-1",
    "http://stix.mitre.org/extensions/TestMechanism#Snort-1",
    "http://stix.mitre.org/extensions/TestMechanism#YARA-1",
    "http://stix.mitre.org/extensions/Vulnerability#CVRF-1"
]

STIX_NS_1_2_1 = [
    # "Core" stuff
    "http://docs.oasis-open.org/cti/ns/stix/core-1",
    "http://docs.oasis-open.org/cti/ns/stix/common-1",
    "http://docs.oasis-open.org/cti/ns/stix/vocabularies-1",

    # Components
    "http://docs.oasis-open.org/cti/ns/stix/campaign-1",
    "http://docs.oasis-open.org/cti/ns/stix/course-of-action-1",
    "http://docs.oasis-open.org/cti/ns/stix/data-marking-1",
    "http://docs.oasis-open.org/cti/ns/stix/exploit-target-1",
    "http://docs.oasis-open.org/cti/ns/stix/incident-1",
    "http://docs.oasis-open.org/cti/ns/stix/indicator-1",
    "http://docs.oasis-open.org/cti/ns/stix/report-1",
    "http://docs.oasis-open.org/cti/ns/stix/threat-actor-1",
    "http://docs.oasis-open.org/cti/ns/stix/ttp-1",

    # Extensions
    "http://docs.oasis-open.org/cti/ns/stix/extensions/address/ciq-address-3.0-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/attack-pattern/capec-2.7-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/identity/ciq-3.0-identity-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/malware/maec-4.1-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/data-marking/simple-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/data-marking/terms-of-use-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/data-marking/tlp-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/structured-coa/generic-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/generic-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/openioc-2010-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/oval-5.10-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/snort-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/yara-1",
    "http://docs.oasis-open.org/cti/ns/stix/extensions/test-mechanism/cvrf-1"
]


def split_braced_name(name):
    """Splits a name in the format "{foo}bar" into two pieces, "foo" and "bar",
     and returns them as a tuple.  If the name isn't in that format, it is
     returned as (None, name)."""

    if name[0] == "{":
        j = name.rfind("}")
        if j != -1:
            return name[1:j], name[j+1:]

    return None, name


def update_namespaces(elt, ns_mapping):
    """
    Replaces namespace declarations in the XML subtree rooted at elt.  This
    function tries to be smart about not replacing any elements it doesn't
    have to.  The only time replacement is necessary is when namespace
    declarations are visible which require updating.  If elt itself is
    replaced, the replacement element is returned.  Otherwise, elt itself
    is returned.  The return value is probably only useful for the original
    caller, so he can do further updates if the element has changed (e.g.
    replace the root of the containing ElementTree).


    Args:
        elt: The root of the subtree to update
        ns_mapping: a uri-to-uri namespace mapping

    Returns:
        either elt itself or an updated replacement for elt, depending on
        whether the node needed replacement.
    """

    # Pass-through comments and entities
    if isinstance(elt, ET._Comment) or isinstance(elt, ET._Entity):
        return elt

    # Wholesale replacement is only necessary when we need to modify
    # nsmap.
    need_replace_elt = False
    for ns in itervalues(elt.nsmap):
        if ns in ns_mapping:
            need_replace_elt = True
            break

    if need_replace_elt:
        # Update nsmap
        new_ns_map = {}
        for pfx, old_ns in iteritems(elt.nsmap):
            new_ns_map[pfx] = ns_mapping.get(old_ns, old_ns)

        # Must update the element and attribute names when we update nsmap,
        # because if their namespace disappears from nsmap, lxml will
        # automatically re-add it... with potentially the old wrong namespace.
        # When you subsequently fix the element/attribute names, that wrong
        # namespace decl still hangs around.

        ns, loc = split_braced_name(elt.tag)
        if ns is None:
            new_elt_name = elt.tag
        else:
            new_elt_name = "{{{}}}{}".format(ns_mapping.get(ns, ns), loc)

        new_attrib = {}
        for attr_name, attr_val in elt.items():
            ns, loc = split_braced_name(attr_name)
            if ns is None:
                new_attrib[attr_name] = attr_val
            else:
                new_attrib["{{{}}}{}".format(ns_mapping.get(ns, ns), loc)] = \
                    attr_val

        new_elt = elt.makeelement(new_elt_name, attrib=new_attrib,
                                  nsmap=new_ns_map)

        # Copy over child nodes
        new_elt[:] = elt[:]

        # Text junk
        new_elt.text = elt.text
        new_elt.tail = elt.tail

        # Replace the old node, if it isn't root.  Because this is done via
        # the parent node, the root node of the whole tree can't be replaced in
        # this way.
        if elt.getparent() is not None:
            elt.getparent().replace(elt, new_elt)

        elt = new_elt

    else:
        # Can update the element in-place!

        # Update tag name
        ns, loc = split_braced_name(elt.tag)
        if ns is not None:
            elt.tag = "{{{}}}{}".format(ns_mapping.get(ns, ns), loc)

        # Update attributes
        for attr_name, attr_val in elt.items():
            ns, loc = split_braced_name(attr_name)
            if ns is not None:
                del elt.attrib[attr_name]
                elt.set("{{{}}}{}".format(ns_mapping.get(ns, ns), loc),
                        attr_val)

    # Recurse over children
    for child in elt:
        update_namespaces(child, ns_mapping)

    return elt


_xsi_uri = "http://www.w3.org/2001/XMLSchema-instance"
_schemaloc_attr = "{{{}}}schemaLocation".format(_xsi_uri)
def update_schemalocations(tree, ns_mapping):
    """
    Check for xsi:schemaLocation attributes and update the namespaces in all
    that are found.

    Args:
        tree: the element tree to check
        ns_mapping: the desired namespaces updates

    """
    for elt in tree.iter():
        schemaloc = elt.get(_schemaloc_attr)
        if schemaloc is not None:
            # This is a simple way to modify the schemaLocation structure,
            # but throws out the user's formatting.  Dunno how important this
            # is...
            schemaloc_vals = schemaloc.split()
            for i, val in enumerate(schemaloc_vals):
                if i % 2 == 0:
                    schemaloc_vals[i] = ns_mapping.get(val, val)
            elt.set(_schemaloc_attr, " ".join(schemaloc_vals))


def special_case_version_update(tree, to_id):
    """
    Applicable only when using a predefined namespace set as the destination:
    some docs have some kind of version indicator attribute(s) on the root
    node.  Update this indicator accordingly.  If the the chosen destination
    namespace set isn't one of the predefined ones, do nothing.
    """
    root = tree.getroot()
    if to_id == "stix1.2":
        if root.get("version") is not None:
            root.set("version", "1.2")
    elif to_id == "stix1.2.1":
        if root.get("version") is not None:
            root.set("version", "1.2.1")


def get_namespace_list(id_):
    """Get a list of namespace URIs according to the given identifier.
    Some identifiers are specially recognized and result in a predefined
    list of URIs.  If the identifier is not recognized, it is treated as a
    file from which URIs are read, one per line."""

    if id_ == "stix1.2":
        ns_list = STIX_NS_1_2
    elif id_ == "stix1.2.1":
        ns_list = STIX_NS_1_2_1
    else:
        ns_list = []
        with open(id_, "r") as f:
            for line in f:
                line = line.strip()
                if len(line) == 0:
                    continue # skip blank lines
                elif line[0] == "#":
                    continue # skip comments
                else:
                    ns_list.append(line)

    return ns_list


def parse_args():
    """Sets up and parses the commandline args."""
    parser = argparse.ArgumentParser(description="""
    A simple tool to replace XML namespaces in one document with others.  The
    updated XML is written to stdout.
    """,
                                     epilog="""
    Specially recognized "from" and "to" identifiers include:
    stix1.2, stix1.2.1.  If a specially recognized identifier is used, then
    there may be an update made to version indicator attributes as well.
                                     """)

    parser.add_argument("-f", "--from", required=True, help="""
    The namespaces to change from.  This may be a file or a specially
    recognized value (see below).
    """)

    parser.add_argument("-t", "--to", required=True, help="""
    The namespaces to change to.  This may be a file or a specially recognized
    value (see below).
    """)

    parser.add_argument("-p", "--pretty", action="store_true", help="""
    Pretty-print output.
    """)

    if PY2:
        bin_stdin = sys.stdin
    else:
        bin_stdin = sys.stdin.buffer

    parser.add_argument("file", nargs="?", type=argparse.FileType("rb"),
                        default=bin_stdin, help="""
    The XML file to update.  If omitted, XML content is read from stdin.
    """)

    return parser.parse_args()


def update_from_lists(tree, from_ns, to_ns):
    """Update XML from lists of old and new namespaces."""
    ns_mapping = dict(zip(from_ns, to_ns))

    new_root = update_namespaces(tree.getroot(), ns_mapping)
    if new_root is not tree.getroot():
        tree._setroot(new_root)

    update_schemalocations(tree, ns_mapping)


def main(tree, from_id, to_id):
    """Update XML from IDs or filenames as given on the commandline."""
    from_ns = get_namespace_list(from_id)
    to_ns = get_namespace_list(to_id)

    update_from_lists(tree, from_ns, to_ns)

    special_case_version_update(tree, to_id)


if __name__ == "__main__":

    args = parse_args()

    # The parser stix-ramrod uses.
    parser = ET.ETCompatXMLParser(
        huge_tree=True,
        resolve_entities=False,
        remove_comments=False,
        strip_cdata=False,
        remove_blank_text=True
    )

    tree = ET.parse(args.file, parser)

    main(tree,
         # "from" is a python keyword... can't use the normal syntax here.
         getattr(args, "from"),
         args.to)

    output_encoding = "utf-8"

    if PY2:
        bin_stdout = sys.stdout
    else:
        bin_stdout = sys.stdout.buffer

    tree.write(bin_stdout, encoding=output_encoding, pretty_print=args.pretty,
               xml_declaration='<?xml version="1.0" encoding="{}"?>'.format(
                   output_encoding))


