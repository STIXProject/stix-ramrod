#!/usr/bin/env python

# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# builtin
import sys
import argparse
import os.path

# internal
import ramrod
import ramrod.errors as errors

# external
from six import iteritems, PY2


EXIT_SUCCESS = 0
EXIT_FAILURE = 1

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


def _write_xml(document, outfn=None):
    """Writes the XML tree to an output stream. If `outfn` is ``None``,
    sys.stdout is written to.

    Args:
        tree: A :class:`ramrod.ResultDocument` instance.

    """
    if PY2:
        bin_stdout = sys.stdout
    else:
        bin_stdout = sys.stdout.buffer

    out = outfn or bin_stdout
    tree = document.as_element_tree()
    tree.write(out, pretty_print=True)


def _print_update_error(err):
    """Prints ramrod.errors.UpdateError information to stdout.

    Args:
        err: A ramrod.errors.UpdateError instance.

    """
    _print_error("[!] %s", str(err))

    disallowed = err.disallowed
    duplicates = err.duplicates

    if disallowed:
        _print_error("[!] Found the following untranslatable items:")
        for node in disallowed:
           _print_error("  Line %s: %s", node.sourceline, node.tag)

    if duplicates:
        print("[!] Found items with duplicate ids:")
        for id_, nodes in iteritems(duplicates):
            _print_error("  '%s' on lines %s", id_, [x.sourceline for x in nodes])


def _print_invalid_version_error(err):
    """Prints ``ramrod.InvalidVersionError`` information to stderr.

    Args:
        err: Instance of ``ramrod.errors.InvalidVersionError``.

    """
    _print_error("[!] %s", str(err))

    node = err.node
    expected_version = err.expected
    found_version = err.found

    if node:
        _print_error("  Node: %s on line %s", node.tag, node.sourceline)
    if expected_version:
        _print_error("  Expected: '%s'", expected_version)
    if found_version:
        _print_error("  Found: '%s'", found_version)


def _print_unknown_version_error(err):
    """Prints ``ramrod.UnknownVersionError`` information to stderr.

    Args:
        err: Instance of ``ramrod.errors.UnknownVersionError``.

    """
    _print_error("[!] %s", str(err))


def _write_removed(removed):
    """Prints information about xml entities that were removed during the
    update process.

    Args:
        removed: A list of etree._Element nodes.

    """
    if not removed:
        return

    print("\n[!] The following nodes were removed from the source document "
           "during the update process:")
    
    for node in removed:
        print("    Line %s: %s" % (node.sourceline, node.tag))


def _write_remapped_ids(remapped):
    """Prints inormation about nodes that had IDs remapped to unique IDs during
    the update process.

    Args:
        remapped: A dictionary of etree nodes which have had their IDs
            remapped to unique IDs.

    """
    if not remapped:
        return

    print("\n[!] The following ids were duplicated in the source document and "
           "remapped during the update process:")

    for orig_id, nodes in iteritems(remapped):
        print("'%s': %s" % (orig_id, [x.attrib['id'] for x in nodes]))


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
    desc = "Ramrod Updater v{0}: Updates STIX and CybOX documents."
    desc = desc.format(ramrod.__version__)

    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "--infile",
        default=None,
        required=True,
        help="Input STIX/CybOX document filename."
    )

    parser.add_argument(
        "--outfile",
        default=None,
        help="Output XML document filename. Prints to stdout if no filename is "
             "provided."
    )

    parser.add_argument(
        "--from",
        default=None,
        dest="from_",
        metavar="VERSION IN",
        help="The version of the input document. If not supplied, RAMROD will "
             "try to determine the version of the input document."
    )

    parser.add_argument(
        "--to",
        default=None,
        dest="to_",
        metavar="VERSION OUT",
        help="Update document to this version. If no version is supplied, the "
             "document will be updated to the latest version."
    )

    parser.add_argument(
        "--disable-vocab-update",
        action="store_true",
        default=False,
        help="Controlled vocabulary strings will not be updated."
    )

    parser.add_argument(
        "--disable-remove-optionals",
        action="store_true",
        default=False,
        help="Do not remove empty elements and attributes which were required "
             "in previous language versions but became optional in later "
             "releases."
    )

    parser.add_argument(
        "-f",
        "--force",
        action="store_true",
        default=False,
        help="Removes untranslatable fields, remaps non-unique IDs, and "
             "attempts to force the update process."
    )

    return parser


def _validate_args(args):
    """Validates the input command-line arguments.

    """
    infile = args.infile

    if os.path.exists(infile):
        return

    raise ValueError("Input file '%s' does not exist." % infile)


def main():
    parser = _get_arg_parser()
    args = parser.parse_args()

    try:
        # Validate the input commandline arguments
        _validate_args(args)

        # Build UpdateOptions from commandline arguments
        options = _get_options(args)

        # Run the update process.
        updated = ramrod.update(
            args.infile,
            from_=args.from_,
            to_=args.to_,
            options=options,
            force=args.force
        )

        # Write results
        _write_xml(updated.document, args.outfile)
        _write_removed(updated.removed)
        _write_remapped_ids(updated.remapped_ids)

    except errors.UpdateError as ex:
        _print_update_error(ex)
        sys.exit(EXIT_FAILURE)
    except errors.InvalidVersionError as ex:
        _print_invalid_version_error(ex)
        sys.exit(EXIT_FAILURE)
    except errors.UnknownVersionError as ex:
        _print_unknown_version_error(str(ex))
        sys.exit(EXIT_FAILURE)

if __name__ == "__main__":
    main()