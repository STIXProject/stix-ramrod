STIX v1.2 was a minor release of the STIX language that introduced new schemas,
expanded vocabularies and introduced new capabilities for existing data types.

STIX 1.2 is **completely** backwards compatible with STIX 1.1.1, so
**stix-ramrod** makes minimal changes to STIX v1.1.1 content when upgrading to
STIX v1.2.

The sections below describe the changes **stix-ramrod** performs during an
upgrade from STIX v1.1.1 to STIX v1.2.

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to STIX v1.1 content when updating to
STIX v1.1.1:

* The ``xsi:schemaLocation`` attribute updated to refer to STIX v1.2 schemas,
  hosted at http://stix.mitre.org/.
* The ``version`` attribute  on ``STIXType`` instances set to ``1.2``.
* The ``version`` attribute on ``IncidentType`` instances set to ``1.2``.
* The ``version`` attribute on ``TTPType`` instances set to ``1.2``.
* The ``version`` attribute on ``CourseOfActionType`` instances set to
  ``1.2``.
* The ``version`` attribute on ``ThreatActorType`` instances set to ``1.2``.
* The ``version`` attribute on ``CampaignType`` instances set to ``1.2``.
* The ``version`` attribute on ``ExploitTargetType`` instances set to ``1.2``.
* The ``version`` attribute on ``IndicatorType`` instances set to ``2.2``.

Untranslatable Fields
^^^^^^^^^^^^^^^^^^^^^

No field translations are performed when upgrading from STIX v1.1.1 to
STIX v1.2.

Translated Fields
^^^^^^^^^^^^^^^^^

There are no required translations when upgrading from STIX v1.1.1 to
STIX v1.2.


Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At a minimum, controlled vocabulary updates include updates to the
``vocab_name``, ``vocab_reference``, and ``xsi:type`` attributes to refer
to new data type names and versions. Instance values may be updated if
typos were fixed in new versions.

The following updates were made to default STIX controlled vocabularies,
defined by the ``stix_default_vocabularies.xsd`` schema.

* ``DiscoveryMethodVocab-1.0`` updated to ``DiscoveryMethodVocab-2.0``.

  - Term ``'Fraud Detection'`` corrected to ``'External - Fraud Detection'``.

.. include:: /_includes/note_controlled_vocabulary_updates.rst


Empty Optional Fields Removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

No fields were changed from required to optional between STIX v1.1.1 and
STIX v1.2.