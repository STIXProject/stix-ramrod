#!/usr/bin/env python

# Copyright (c) 2014, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
import argparse
import ramrod


def _print_error(fmt, *args):
    """Writes a message to sys.stderr.

    Example:
        >>> msg = "invalid input"
        >>> _print_error("error: %s", msg)
        error: invalid input

    Args:
        fmt: A Python format string.
        *args: Variable-length argument list for the format string.

    """
    msg = fmt % args
    sys.stderr.write("%s\n" % (msg))


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
        _print_error("[!] Found the following untranslatable items:")
        for node in disallowed:
           _print_error("  Line %s: %s", node.sourceline, node.tag)

    if duplicates:
        print "[!] Found items with duplicate ids:"
        for id_, nodes in duplicates.iteritems():
            _print_error("  '%s' on lines %s", id_, [x.sourceline for x in nodes])


def _print_invalid_version_error(err):
    print "[!] %s" % (str(err))

    node = err.node
    expected_version = err.expected
    found_version = err.found

    if node:
        _print_error("  Node: %s on line %s", node.tag, node.sourceline)
    if expected_version:
        _print_error("  Expected: '%s'", expected_version)
    if found_version:
        _print_error("  Found: '%s'", found_version)


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


def _get_options(args):
    """Builds a ramrod.UpdateOptions instance from the command line arguments.

    Args:
        args: Command line arguments parsed by `argparse` module.

    Returns:
        An instance of ramrod.UpdateOptions.

    """
    options = ramrod.UpdateOptions()
    options.remove_optionals = not(args.disable_remove_optionals)
    options.update_vocabularies = not(args.disable_vocab_update)
    options.check_versions = not(args.from_)

    return options


def _get_arg_parser():
    """Returns an ArgumentParser instance for this script."""
    parser = argparse.ArgumentParser(description="Ramrod Updater v%s: Updates "
                                                 "STIX and CybOX documents."
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

    parser.add_argument("--disable-vocab-update", action="store_true",
                        default=False,
                        help="Controlled vocabulary strings will not be "
                             "updated.")

    parser.add_argument("--disable-remove-optionals", action="store_true",
                        default=False,
                        help="Do not remove empty elements and attributes "
                             "which were required in previous language "
                             "versions but became optional in later releases.")


    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Removes untranslatable fields, remaps non-unique "
                             "IDs, and attempts to force the update process.")

    return parser


def main():
    parser = _get_arg_parser()
    args = parser.parse_args()

    try:
        options = _get_options(args)
        updated = ramrod.update(args.infile,
                                from_=args.from_,
                                to_=args.to_,
                                options=options,
                                force=args.force)

        _write_xml(updated.document, args.outfile)
        _write_removed(updated.removed)
        _write_remapped_ids(updated.remapped_ids)
    except ramrod.UpdateError as ex:
        _print_update_error(ex)
    except ramrod.InvalidVersionError as ex:
        _print_invalid_version_error(ex)


if __name__ == "__main__":
    main()