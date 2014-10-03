CybOX v2.0.1 was a bugfix release made to CybOX v2.0. The number of changes
made to the schema were minimal.

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to CybOX 2.0 content when updating to
CybOX 2.0.1:

* The ``xsi:schemaLocation`` attribute updated to refer to CybOX 2.0.1 schemas,
  hosted at http://cybox.mitre.org/.

* The ``cybox_major_version`` attribute on ``ObservableType``
  instances set to ``2``.
* The ``cybox_minor_version`` attribute on ``ObservableType`` instances
  set to ``0``.
* The ``cybox_minor_version`` attribute added to ``ObservablesType``
  instances and set to ``1``.


Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At a minimum, controlled vocabulary updates include updates to the
``vocab_name``, ``vocab_reference``, and ``xsi:type`` attributes to refer
to new data type names and versions. Instance values may be updated if
typos were fixed in new versions.

The following updates were made to default CybOX controlled vocabularies,
defined by the ``cybox_default_vocabularies.xsd`` schema.

* ``EventTypeVocab-1.0`` updated to ``EventTypeVocab-1.0.1``

  -  Fixed typo: ``"Anomoly Events" => "Anomaly Events"``

.. include:: /_includes/note_controlled_vocabulary_updates.rst



Empty Optional Fields Removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

No existing fields were made optional in CybOX 2.0.1.
