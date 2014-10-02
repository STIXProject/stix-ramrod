CybOX v2.0.1 was a bugfix release made to CybOX v2.0. As such, the change set
is small and translation is a simple process.

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to CybOX 2.0 content when updating to
CybOX 2.0.1:

* ``xsi:schemaLocation`` attribute updated to refer to CybOX 2.0.1 schemas,
  hosted at http://cybox.mitre.org/.

* ``cybox_major_version`` attribute set to ``2``.
* ``cybox_minor_version`` attribute set to ``0``.
* ``cybox_minor_version`` attribute added to ``ObservablesType``
  instances and set to ``1``.


Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following updates were made to default CybOX controlled vocabularies,
defined by the ``cybox_default_vocabularies.xsd`` schema.

* ``EventTypeVocab-1.0`` updated to ``EventTypeVocab-1.0.1``

  -  Fixed typo: ``"Anomoly Events" => "Anomaly Events"``

Datatype and Structural Changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The update from CybOX 2.0 to 2.0.1 does not require any structures to be
translated. As a result, the **stix-ramrod** library does not perform and
field translations when updating from CybOX 2.0 to 2.0.1.


Empty Fields Removed
^^^^^^^^^^^^^^^^^^^^

No existing fields were made optional in CybOX 2.0.1.
