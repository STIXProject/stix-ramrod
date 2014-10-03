STIX v1.1 was a minor release which came after STIX v1.0.1. STIX v1.1 introduced
a number of new fields, data types, and extensions for capturing and
characterizing cyber threat intelligence data.

The sections below describe the changes **stix-ramrod** performs during an
upgrade from STIX v1.0.1 to v1.1

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to STIX v1.0.1 content when updating to
STIX v1.1

* The ``xsi:schemaLocation`` attribute updated to refer to STIX v1.1 schemas,
  hosted at http://stix.mitre.org/.
* The ``version`` attribute  on ``STIXType`` instances set to ``1.1``.
* The ``version`` attribute on ``IncidentType`` instances set to ``1.1``.
* The ``version`` attribute on ``TTPType`` instances set to ``1.1``.
* The ``version`` attribute on ``CourseOfActionType`` instances set to ``1.1``.
* The ``version`` attribute on ``ThreatActorType`` instances set to ``1.1``.
* The ``version`` attribute on ``CampaignType`` instances set to ``1.1``.
* The ``version`` attribute on ``ExploitTargetType`` instances set to ``1.1``.
* The ``version`` attribute on ``IndicatorType`` instances set to ``2.1``.
* Namespace definitions for MAEC 4.0.1 Malware extension removed during
  translation: ``http://stix.mitre.org/extensions/Malware#MAEC4.0-1``
* Namespace definitions for CAPEC 2.6.1 Attack Pattern extension removed during
  translation: ``http://stix.mitre.org/extensions/AP#CAPEC2.6-1``

.. note::

    CybOX v2.0.1 is tightly integrated into STIX v1.0.1. As such, any CybOX
    2.0.1 content found within a STIX v1.0.1 document will be updated to CybOX
    2.1. See the :doc:`/updates/cybox/index` page for more details about CybOX
    content updates with **stix-ramrod**.

Untranslatable Fields
^^^^^^^^^^^^^^^^^^^^^

The following fields, data types, attributes or other structures cannot be
translated to STIX v1.1. Updating content which includes these fields will
require a **forced** update.

* Instances of MAEC 4.0.1 Malware extension ``MAEC4.0InstanceType``.
* Instances of CAPEC 2.6.1 Attack Pattern extension ``CAPEC2.6InstanceType``.
* Instances of ``ttp:Malware`` where all children are instances of MAEC
  4.0.1 Malware extension.
* Instances of ``ttp:Attack_Patterns`` where all children are instances of
  CAPEC 2.6.1 Attack Pattern extension.
* Instances of ``stixCommon:Date_Time`` that do not have valid ``xs:dateTime``
  values.

Translated Fields
^^^^^^^^^^^^^^^^^

The following fields and data types are were changed in STIX v1.1 in a manner
that requires translation in order to maintain a schema-valid status.

stixCommon:Contributors
~~~~~~~~~~~~~~~~~~~~~~~

When updating from STIX v1.0.1 to STIX v1.1, instances of
``stixCommon:ContributorsType`` must be translated to instances of
``stixCommon:ContributingSourceType``.

The STIX v1.0.1 ContributorsType contains a list of ``Contributor``
elements under it which were IdentityType instances.

The STIX v1.1 ContributingSourcesType contains a list of ``Source``
elements under it which are instances of InformationSourceType.

Because InformationSourceType has an ``Identity`` child element which is
an instance of ``IdentityType``, we can perform the following transformation:

**Example:** A STIX v1.0.1 ``ContributorsType`` instance.

.. code-block:: xml

    <stix:Information_Source>
        <stixCommon:Contributors>
            <stixCommon:Contributor>
                <stixCommon:Name>Example</stixCommon:Name>
            </stixCommon:Contributor>
            <stixCommon:Contributor>
                <stixCommon:Name>Another</stixCommon:Name>
            </stixCommon:Contributor>
        </stixCommon:Contributors>
    </stix:Information_Source>


**Example:** A STIX v1.1 ``ContributingSourceType`` instance.

.. code-block:: xml

    <stix:Information_Source>
        <stixCommon:Contributing_Sources>
            <stixCommon:Source>
                <stixCommon:Identity>
                    <stixCommon:Name>Example</stixCommon:Name>
                </stixCommon:Identity>
            </stixCommon:Source>
            <stixCommon:Source>
                <stixCommon:Identity>
                    <stixCommon:Name>Another</stixCommon:Name>
                </stixCommon:Identity>
            </stixCommon:Source>
        </stixCommon:Contributing_Sources>
    </stix:Information_Source>


ttp:Exploit_Targets
~~~~~~~~~~~~~~~~~~~

When updating from STIX v1.0.1 to STIX v1.1, instances of
``stixCommon:ExploitTargetsType`` change from a flat list of
``stixCommon:ExploitTargetBaseType`` instances to an extension of
``stixCommon:GenericRelationshipListType``.


**Example:** A STIX v1.0.1 ``ttp:Exploit_Targets`` instance.

.. code-block:: xml

    <ttp:Exploit_Targets>
       <stixCommon:Exploit_Target idref='example:et-1'/>
       <stixCommon:Exploit_Target idref='example:et-2'/>
    </ttp:Exploit_Targets>

**Example:** A STIX v1.1 ``ttp:Exploit_Targets`` instance.

.. code-block:: xml

    <ttp:Exploit_Targets>
        <ttp:Exploit_Target>
            <stixCommon:Exploit_Target idref='example:et-1'/>
        </ttp:Exploit_Target>
        <ttp:Exploit_Target>
            <stixCommon:Exploit_Target idref='example:et-2'/>
        </ttp:Exploit_Target>
    </ttp:Exploit_Targets>


Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At a minimum, controlled vocabulary updates include updates to the
``vocab_name``, ``vocab_reference``, and ``xsi:type`` attributes to refer
to new data type names and versions. Instance values may be updated if
typos were fixed in new versions.

The following updates were made to default STIX controlled vocabularies,
defined by the ``stix_default_vocabularies.xsd`` schema.

* ``MotivationVocab-1.0.1`` updated to ``MotivationVocab-1.1``.

  - Term ``'Policital'`` corrected to ``'Political'``.

* ``IndicatorTypeVocab-1.0`` updated to ``IndicatorTypeVocab-1.1``.

.. include:: /_includes/note_controlled_vocabulary_updates.rst


Empty Optional Fields Removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following elements were required in STIX v1.0.1 but became optional in
STIX v1.1. Empty instances of these fields will be stripped during the update
process.

* ``marking:Controlled_Structure``
* ``marking:Marking_Structure``

.. include:: /_includes/note_remove_empty_optionals_updates.rst