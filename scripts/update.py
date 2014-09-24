#!/usr/bin/env python

import sys
import argparse
import ramrod

def _write_xml(tree, outfn=None):
    out = outfn or sys.stdout
    tree.write(out, pretty_print=True)


def _validate_args():
    pass


def _get_arg_parser():
    parser = argparse.ArgumentParser(description="STIX/CybOX Document Updater v%s"
                                    % ramrod.__version__)

    parser.add_argument("--infile", default=None, required=True,
                        help="Input STIX/CybOX document filename.")

    parser.add_argument("--outfile", default=None,
                        help="Output XML document filename. Prints to stdout "
                             "if no filename is provided.")

    parser.add_argument("--from", default=None, dest="from_", metavar="FROM",
                        help="The version of the input document. If not "
                             "supplied, RAMROD will try to determine the "
                             "version of the input document.")

    parser.add_argument("--to", default=None, dest="to_", metavar="TO",
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
        _validate_args()
        updated = ramrod.update(args.infile, from_=args.from_, to_=args.to_)
        _write_xml(updated, args.outfile)
    except ramrod.UpdateError as ex:
        print str(ex)

if __name__ == "__main__":
    main()