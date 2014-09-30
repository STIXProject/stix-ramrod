#!/usr/bin/env python
import sys
import argparse
import ramrod

def _write_xml(tree, outfn=None):
    """Writes the XML tree to an output stream. If `outfn` is ``None``,
    sys.stdout is written to.

    Args:
        tree: An etree._ElementTree instance.

    """
    out = outfn or sys.stdout
    tree.write(out, pretty_print=True)


def _print_update_error(err):
    """Prints ramrod.UpdateError information to stdout.

    Args:
        err: A ramrod.UpdateError instance.

    """
    print "[!] %s" % (str(err))

    disallowed = err.disallowed
    duplicates = err.duplicates

    if disallowed:
        print "[!] Found the following untranslatable items:"
        for node in disallowed:
            print "  Line %s: %s" % (node.sourceline, node.tag)

    if duplicates:
        print "[!] Found items with duplicate ids:"
        for id_, nodes in duplicates.iteritems():
            print "  '%s' on lines %s" %  (id_, [x.sourceline for x in nodes])


def _write_removed(removed):
    """Prints information about xml entities that were removed during the
    update process.

    Args:
        removed: A list of etree._Element nodes.

    """
    if not removed:
        return

    print ("\n[!] The following nodes were removed from the source document "
           "during the update process:")
    
    for node in removed:
        print "    Line %s: %s" % (node.sourceline, node.tag)


def _write_remapped_ids(remapped):
    """Prints inormation about nodes that had IDs remapped to unique IDs during
    the update process.

    Args:
        remapped: A dictionary of etree nodes which have had their IDs
            remapped to unique IDs.

    """
    if not remapped:
        return

    print ("\n[!] The following ids were duplicated in the source document and "
           "remapped during the update process:")

    for orig_id, nodes in remapped.iteritems():
        print "'%s': %s" % (orig_id, [x.attrib['id'] for x in nodes])


def _get_arg_parser():
    """Returns an ArgumentParser instance for this script."""
    parser = argparse.ArgumentParser(description="STIX/CybOX Document Updater v%s"
                                    % ramrod.__version__)

    parser.add_argument("--infile", default=None, required=True,
                        help="Input STIX/CybOX document filename.")

    parser.add_argument("--outfile", default=None,
                        help="Output XML document filename. Prints to stdout "
                             "if no filename is provided.")

    parser.add_argument("--from", default=None, dest="from_",
                        metavar="VERSION IN",
                        help="The version of the input document. If not "
                             "supplied, RAMROD will try to determine the "
                             "version of the input document.")

    parser.add_argument("--to", default=None, dest="to_",
                        metavar="VERSION OUT",
                        help="Update document to this version. If no version "
                             "is supplied, the document will be updated to "
                             "the latest version.")

    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Removes untranslatable fields and attempts to "
                             "force the update process.")

    return parser


def main():
    parser = _get_arg_parser()
    args = parser.parse_args()

    try:
        updated = ramrod.update(args.infile, from_=args.from_, to_=args.to_, force=args.force)

        _write_xml(updated.document, args.outfile)
        _write_removed(updated.removed)
        _write_remapped_ids(updated.remapped_ids)
    except ramrod.UpdateError as ex:
        _print_update_error(ex)


if __name__ == "__main__":
    main()