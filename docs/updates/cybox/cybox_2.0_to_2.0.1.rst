CybOX v2.0.1 was a bugfix release made to CybOX v2.0.1.

The sections below describe the changes **stix-ramrod** performs during an
upgrade from CybOX 2.0 to CybOX 2.0.1.

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

List Delimiters
~~~~~~~~~~~~~~~

CybOX 2.0 allows for the definition of multiple Object Property field values
through the use of reserved list delimiter, which is defined to be ``','``
(a comma). Grammatical commas were expressed as ``<![CDATA[&comma;]]>``.

CybOX 2.0.1 changed the reserved list delimiter to be ``'##comma##'``, allowing
for grammatical commas to be expressed without special syntax or ``CDATA``
wrappers.

Example CybOX 2.0 List
``````````````````````
.. code-block:: xml

    <!-- Describes two email subjects: 'Foo' and 'Bar' -->
    <EmailObj:Subject>Foo,Bar</EmailObj:Subject>

Example CybOX 2.0 Grammatical Comma
```````````````````````````````````

.. code-block:: xml

    <!-- Use of a grammatical comma -->
    <EmailObj:Subject>Et tu<![CDATA[&comma;]]> Brute?</EmailObj:Subject>


CybOX 2.0.1 changed the default list delimiter to be ``'##comma##'``, allowing
for grammatical commas to be used naturally.

Example CybOX 2.0.1 List
````````````````````````
.. code-block:: xml

    <!-- Describes two email subjects: 'Foo' and 'Bar' -->
    <EmailObj:Subject>Foo##comma##Bar</EmailObj:Subject>

Example CybOX 2.0.1 Grammatical Comma
`````````````````````````````````````

.. code-block:: xml

    <!-- Use of a grammatical comma -->
    <EmailObj:Subject>Et tu, Brute?</EmailObj:Subject>


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
