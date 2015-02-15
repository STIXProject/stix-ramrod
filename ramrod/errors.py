# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

class UnknownVersionError(Exception):
    """Raised when an input document does not contain a ``version`` attribute
    and the user has not specified a document version.

    """
    pass


class UpdateError(Exception):
    """Raised when non-translatable fields are encountered during the update
    process..

    Attributes:
        message: The error message.
        disallowed: A list of nodes found in the input document that
            cannot be translated during the update process.
        duplicates: A dictionary of nodes found in the input document
            that contain the same `id` attribute value.
    """
    def __init__(self, message=None, disallowed=None, duplicates=None):
        super(UpdateError, self).__init__(message)
        self.disallowed = disallowed
        self.duplicates = duplicates


class InvalidVersionError(Exception):
    """Raised when an input document's ``version`` attribute does not align
    with the expected version number for a given ``_BaseUpdater``
    implementation.

    Attributes:
        message: The error message.
        node: The node containing an incompatible version number.
        expected: The version that was expected.
        found: The version that was found on the `node`.

    """
    def __init__(self, message=None, node=None, expected=None, found=None):
        super(InvalidVersionError, self).__init__(message)
        self.node = node
        self.expected = expected
        self.found = found


__all__ = (
    'UnknownVersionError',
    'UpdateError',
    'InvalidVersionError'
)