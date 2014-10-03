STIX v1.1.1 was a bugfix release of the STIX language that fixed incorrect
data types, typos, and requirements.

The sections below describe the changes **stix-ramrod** performs during an
upgrade from STIX v1.1. to STIX v1.1.1

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to STIX v1.1 content when updating to
STIX v1.1.1

* The ``xsi:schemaLocation`` attribute updated to refer to STIX v1.1 schemas,
  hosted at http://stix.mitre.org/.
* The ``version`` attribute  on ``STIXType`` instances set to ``1.1.1``.
* The ``version`` attribute on ``IncidentType`` instances set to ``1.1.1``.
* The ``version`` attribute on ``TTPType`` instances set to ``1.1.1``.
* The ``version`` attribute on ``CourseOfActionType`` instances set to
  ``1.1.1``.
* The ``version`` attribute on ``ThreatActorType`` instances set to ``1.1.1``.
* The ``version`` attribute on ``CampaignType`` instances set to ``1.1.1``.
* The ``version`` attribute on ``ExploitTargetType`` instances set to ``1.1.1``.
* The ``version`` attribute on ``IndicatorType`` instances set to ``2.1.1``.

.. note::

   STIX v1.1 and STIX v1.1.1 are both tightly integrated with CybOX v2.1.
   Updating STIX v1.1 content to STIX v1.1.1 will result in CybOX schema
   locations in the ``xsi:schemaLocation`` attribute to be updated
   to point to the schemas hosted at http://cybox.mitre.org/. No other updates
   to CybOX content are performed.


Untranslatable Fields
^^^^^^^^^^^^^^^^^^^^^

All fields can be translated from STIX v1.1 to STIX v1.1.1.

Translated Fields
^^^^^^^^^^^^^^^^^

The following fields and data types are were changed in STIX v1.1 in a manner
that requires translation in order to maintain a schema-valid status.

stixCommon:ConfidenceType and stixCommon:StatementType
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When updating from STIX v1.0.1 to STIX v1.1, instances of
``stixCommon:ConfidenceType`` and ``stixCommon:StatementType`` must have
their ``Source`` child elements updated to be instances of
``stixCommon:InformationSourceType``.

In STIX v1.1, the ``Source`` field was of type
``stixCommon:ControlledVocabularyStringType``.

In STIX v1.1.1, the ``Source`` field was updated to be of type
``stixCommon:InformationSourceType``, a much richer data type with
many more fields.

The value of the STIX v1.1 ``Source`` field is translated into an instance of
``stixCommon:IdentityType``, where the ``Source`` value becomes the value of
the ``Name`` field under ``stixCommon:IdentityType``. The new
``stixCommon:IdentityType`` instance is assigned to the ``Identity`` field
of the ``stixCommon:InformationSourceType`` ``Source`` field.

**Example:** A STIX v1.1 ``stixCommon:ConfidenceType`` instance.

.. code-block:: xml

    <stixCommon:Confidence>
        <stixCommon:Source>Example</stixCommon:Source>
    </stixCommon:Confidence>


**Example:** A STIX v1.1.1 ``stixCommon:ConfidenceType`` instance.

.. code-block:: xml

    <stixCommon:Confidence>
        <stixCommon:Source>
            <stixCommon:Identity>
                <stixCommon:Name>Example</stixCommon:Name>
            </stixCommon:Identity>
        </stixCommon:Source>
    </stixCommon:Confidence>


indicator:SightingType
~~~~~~~~~~~~~~~~~~~~~~

When updating from STIX v1.1 to STIX v1.1.1, instances of
``indicator:SightingType`` must have their ``Source`` child element updated to
be instances of ``stixCommon:InformationSourceType``.

In STIX v1.1, the ``Source`` field was of type
``stixCommon:StructuredTextType``.

In STIX v1.1.1, the ``Source`` field was updated to be of type
``stixCommon:InformationSourceType``, a much richer data type with
many more fields.

The value of the STIX v1.1 ``Source`` field is translated into an instance of
``stixCommon:IdentityType``, where the ``Source`` value becomes the value of
the ``Name`` field under ``stixCommon:IdentityType``. The new
``stixCommon:IdentityType`` instance is assigned to the ``Identity`` field
of the ``stixCommon:InformationSourceType`` ``Source`` field.

**Example:** A STIX v1.1 ``indicator:SightingType`` instance.

.. code-block:: xml

    <indicator:Sighting>
        <indicator:Source>Example</indicator:Source>
    </indicator:Sighting>


**Example:** A STIX v1.1.1 ``indicator:SightingType`` instance.

.. code-block:: xml

    <indicator:Sighting>
        <indicator:Source>
            <stixCommon:Identity>
                <stixCommon:Name>Foobar</stixCommon:Name>
            </stixCommon:Identity>
        </indicator:Source>
    </indicator:Sighting>


stixCommon:CampaignReferenceType
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When updating from STIX v1.1 to STIX v1.1.1, instances of
``stixCommon:CampaignReferenceType`` must be updated.

In STIX v1.1, the ``stixCommon:CampaignReferenceType`` contained a child
``Names`` element, which was of type ``stixCommon:NamesType``.

In STIX v1.1.1, the ``stixCommon:CampaignReferenceType`` was updated to
extend the ``stixCommon:GenericRelationshipType`` and introduced a new
``Campaign`` element layer as a result.

**Example:** A STIX v1.1 ``stixCommon:CampaignReferenceType`` instance.

.. code-block:: xml

    <indicator:Related_Campaigns>
        <indicator:Related_Campaign>
            <stixCommon:Names>
                <stixCommon:Name>Example</stixCommon:Name>
            </stixCommon:Names>
        </indicator:Related_Campaign>
        <indicator:Related_Campaign idref='campaign-foo-1'/>
    </indicator:Related_Campaigns>

**Example:** A STIX v1.1.1 ``stixCommon:CampaignReferenceType`` instance.

.. code-block:: xml

    <indicator:Related_Campaigns>
        <indicator:Related_Campaign>
            <stixCommon:Campaign>
                <stixCommon:Names>
                    <stixCommon:Name>Example</stixCommon:Name>
                </stixCommon:Names>
            </stixCommon:Campaign>
        </indicator:Related_Campaign>
        <indicator:Related_Campaign>
            <stixCommon:Campaign idref="campaign-foo-1>
        </indicator:Related_Campaign>
    </indicator:Related_Campaigns>


Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At a minimum, controlled vocabulary updates include updates to the
``vocab_name``, ``vocab_reference``, and ``xsi:type`` attributes to refer
to new data type names and versions. Instance values may be updated if
typos were fixed in new versions.

The following updates were made to default STIX controlled vocabularies,
defined by the ``stix_default_vocabularies.xsd`` schema.

* ``AvailabilityLossVocab-1.0` updated to ``AvailabilityLossVocab-1.1.1``.

  - Term ``'Degredation'`` corrected to ``'Degradation'``.

.. include:: /_includes/note_controlled_vocabulary_updates.rst


Empty Optional Fields Removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following elements were required in STIX v1.1 but became optional in
STIX v1.1.1. Empty instances of these fields will be stripped during the update
process.

* All child nodes of the Generic Test Mechanism extension instance,
  ``GenericTestMechanismType``.

.. include:: /_includes/note_remove_empty_optionals_updates.rst