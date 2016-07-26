# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# external
from lxml import etree
from six import StringIO, text_type, python_2_unicode_compatible


@python_2_unicode_compatible
class UpdateResults(object):
    """Returned from :meth:`ramrod.update`, :meth:`ramrod.cybox.update`, and
    :meth:`ramrod.stix.update` methods.

    Attributes:
        document: The updated document. An instance of
            :class:`ramrod.ResultDocument`.
        removed: Untranslatable nodes that were removed from the
            document. An instance of ``tuple``.
        remapped_ids: An ``{ id: [nodes] }`` dictionary where the key is a
            non-unique ID that was discovered in the input document, and the
            nodes are all the nodes which had their ``id`` attribute
            reassigned to be unique.

    """
    def __init__(self, document, removed=None, remapped_ids=None):
        self.document = document
        self.removed = removed or ()
        self.remapped_ids = remapped_ids or {}


    @property
    def document(self):
        return self._document


    @document.setter
    def document(self, value):
        if isinstance(value, ResultDocument):
            self._document = value
        else:
            self._document = ResultDocument(value)


    def __str__(self):
        if not self.document:
            return ''

        return text_type(self.document)


@python_2_unicode_compatible
class ResultDocument(object):
    """Used to encapsulate an updated XML document. This is the type of the
    ``document`` attribute on :class:`ramrod.UpdateResults`

    Note:
        This class overrides the ``__str__`` and ``__unicode__`` methods
        and can be used with ``str()`` or ``print``.

    Args:
        document: An instance of ``etree._Element`` or ``etree._ElementTree``.

    """
    def __init__(self, document):
        allowed_types = (etree._Element, etree._ElementTree)  # noqa

        if not isinstance(document, allowed_types):
            raise ValueError("Document must be one of %s, got %s" % (allowed_types, type(document)))

        try:
            self._document = document.getroottree()
        except AttributeError:
            self._document = document


    def __str__(self):
        return text_type(self.as_stringio().getvalue())


    def as_element(self):
        """Returns an ``etree._Element`` representation of the
        ``ResultDocument`` instance.

        """
        return self._document.getroot()

    def as_element_tree(self):
        """Returns an ``etree._ElementTree`` representation of the
        ``ResultDocument`` instance.

        """
        return self._document

    def as_stringio(self):
        """Returns a ``StringIO`` representation of the
        ``ResultDocument`` instance.

        """
        buf = etree.tounicode(self._document, pretty_print=True)
        return StringIO(buf)


__all__ = [
    'ResultDocument',
    'UpdateResults'
]
