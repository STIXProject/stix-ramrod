STIX v1.0.1 was a bugfix release which came after STIX v1.0. Because it is an
bugfix release the number of changes is small.

The sections below describe the changes **stix-ramrod** performs during an
upgrade from STIX v1.0 to v1.0.1

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to STIX v1.0 content when updating to
STIX v1.0.1.

* The ``xsi:schemaLocation`` attribute updated to refer to STIX v1.0.1 schemas,
  hosted at http://stix.mitre.org/.
* The ``version`` attribute  on ``STIXType`` instances set to ``1.0.1``.
* The ``version`` attribute on ``IncidentType`` instances set to ``1.0.1``.
* The ``version`` attribute on ``TTPType`` instances set to ``1.0.1``.
* The ``version`` attribute on ``CourseOfActionType`` instances set to
  ``1.0.1``.
* The ``version`` attribute on ``ThreatActorType`` instances set to ``1.0.1``.
* The ``version`` attribute on ``CampaignType`` instances set to ``1.0.1``.
* The ``version`` attribute on ``ExploitTargetType`` instances set to ``1.0.1``.
* The ``version`` attribute on ``IndicatorType`` instances set to ``2.0.1``.
* Namespace definitions for MAEC 4.0 Malware extension removed during
  translation: ``http://stix.mitre.org/extensions/Malware#MAEC4.0-1``
* Namespace definitions for CAPEC 2.5 Attack Pattern extension removed during
  translation: ``http://stix.mitre.org/extensions/AP#CAPEC2.5-1``

.. note::

    CybOX v2.0 is tightly integrated into STIX v1.0. As such, any CybOX 2.0
    content found within a STIX v1.0 document will be updated to CybOX 2.0.1.
    See the :doc:`/updates/cybox/index` page for more details about CybOX
    content updates with **stix-ramrod**.


Untranslatable Fields
^^^^^^^^^^^^^^^^^^^^^

The following fields, data types, attributes or other structures cannot be
translated to STIX v1.0.1. Updating content which includes these fields will
require a **forced** update.

* Instances of MAEC 4.0 Malware extension ``MAEC4.0InstanceType``.
* Instances of ``ttp:Malware`` where all children are instances of MAEC
  4.0 Malware extension.
* Instances of CAPEC 2.5 Attack Pattern extension ``CAPEC2.5InstanceType``.
* Instances of ``ttp:Attack_Patterns`` where all children are instances of
  CAPEC 2.5 Attack Pattern extension.


Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At a minimum, controlled vocabulary updates include updates to the
``vocab_name``, ``vocab_reference``, and ``xsi:type`` attributes to refer
to new data type names and versions. Instance values may be updated if
typos were fixed in new versions.

The following updates were made to default CybOX controlled vocabularies,
defined by the ``cybox_default_vocabularies.xsd`` schema.

* ``MotivationVocab-1.0`` updated to ``MotivationVocab-1.0.1``.

  - Term ``'Ideological - Anti-Establisment'`` corrected to
    ``'Ideological - Anti-Establishment'``.

* ``PlanningAndOperationalSupportVocab-1.0`` updated to
  ``PlanningAndOperationalSupportVocab-1.0.1``.

  - Term ``'Planning - Open-Source Intelligence (OSINT) Gethering'``
    corrected to ``'Planning - Open-Source Intelligence (OSINT) Gathering'``
  - Term ``'Planning '`` corrected to ``'Planning'`` (trailing space removed)

.. include:: /_includes/note_controlled_vocabulary_updates.rst


Empty Optional Fields Removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are no optional fields that are removed when updating from STIX v1.0
to STIX v1.0.1.