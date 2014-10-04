CybOX v2.1 was a minor release made to CybOX v2.0.1 and included many bug fixes,
some of which resulted in backwards incompatibilities with previous versions of
CybOX. On top of bug fixes, CybOX 2.1 introduced new controlled vocabularies
and terms, CybOX Objects, data types and backwards-compatible structural
enhancements.

The sections below describe the changes **stix-ramrod** performs during an
upgrade from CybOX 2.0.1 to CybOX 2.1.

General Updates
^^^^^^^^^^^^^^^

The following general changes are made to CybOX 2.0.1 content when updating to
CybOX 2.1.

* The ``xsi:schemaLocation`` attribute updated to refer to CybOX 2.1 schemas,
  hosted at http://cybox.mitre.org/.
* The ``cybox_major_version`` attribute on ``ObservableType`` instances
  set to ``2``.
* The ``cybox_minor_version`` attribute on ``ObservableType`` instances
  set to ``1``.
* The ``cybox_update_version`` attribute removed from ``ObservablesType``
  instances.

Untranslatable Fields
^^^^^^^^^^^^^^^^^^^^^

The following fields, data types, attributes or other structures cannot be
translated to CybOX v2.1. Updating content which includes these fields will
require a **forced** update.

* ``HTTPSessionObj:X_Forwarded_Proto`` element instances.
* ``Type`` elements instances found in ``WinExecutableFileObj:PESectionType``.
* ``WinMailslotObj:Handle`` element instances when it contains more than one
  child ``Handle`` element.
* ``WinTaskObj:Task_Trigger`` element instances.


Object Updates
^^^^^^^^^^^^^^

The following changes are made to CybOX Objects.

HTTP Session Object
~~~~~~~~~~~~~~~~~~~

* ``HTTPSessionObj:DNT`` element data type changed from ``URIObj:URIObjectType``
  to ``cyboxCommon:StringObjectPropertyType``.
* ``HTTPSessionObj:Vary`` element data type changed from
  ``URIObj:URIObjectType`` to ``cyboxCommon:StringObjectPropertyType``.
* ``HTTPSessionObj:Refresh`` updated from
  ``cyboxCommon:IntegerObjectPropertyType`` to
  ``cyboxCommon:StringObjectPropertyType``

Network Packet Object
~~~~~~~~~~~~~~~~~~~~~

* ``PacketObj:Protol_Addr_Size`` renamed to ``PacketObj:Proto_Addr_Size``
* ``PacketObj:Excapsulating_Security_Payload`` renamed to
  ``PacketObj:Encapsulating_Security_Payload``
* ``PacketObj:Authenication_Data`` renamed to
  ``PacketObj:Authentication_Data``


Windows Driver Object
~~~~~~~~~~~~~~~~~~~~~

* The version of the ``Win_Driver_Object.xsd`` schema, which defines the Windows
  Driver Object was upgraded to ``3.0``.
* The namespace for the Windows Driver Object was changed from
  ``http://cybox.mitre.org/objects#WinDriverObject-2`` to
  ``'http://cybox.mitre.org/objects#WinDriverObject-3``.


Windows Mailslot Object
~~~~~~~~~~~~~~~~~~~~~~~
* The top-level ``WinMailslotObj:Handle`` container is removed, causing
  ``Handle`` child to take it its place. This can only be done if there
  is one ``Handle`` child. If more than one child ``Handle`` element is
  present, the top-level ``WinMailslotObj:Handle`` container is considered
  untranslatable.

  **Example CybOX 2.0.1 WinMailslotObj:Handle**

  .. code-block:: xml

    <cybox:Object>
        <cybox:Properties xsi:type="WinMailslotObj:WindowsMailslotObjectType">
            <WinMailslotObj:Handle>
                <WinHandleObj:Handle>
                    <WinHandleObj:Name>Test</WinHandleObj:Name>
                </WinHandleObj:Handle>
            </WinMailslotObj:Handle>
        </cybox:Properties>
    </cybox:Object>

  **Example CybOX 2.1 WinMailslotObj:Handle**

  .. code-block:: xml

    <cybox:Object>
        <cybox:Properties xsi:type="WinMailslotObj:WindowsMailslotObjectType">
            <WinHandleObj:Handle>
                <WinHandleObj:Name>Test</WinHandleObj:Name>
            </WinHandleObj:Handle>
        </cybox:Properties>
    </cybox:Object>

  **Example Untranslatable CybOX 2.0.1 WinMailslotObj:Handle**

  .. code-block:: xml

    <cybox:Object>
        <cybox:Properties xsi:type="WinMailslotObj:WindowsMailslotObjectType">
            <WinMailslotObj:Handle>
                <WinHandleObj:Handle>
                    <WinHandleObj:Name>One Child</WinHandleObj:Name>
                </WinHandleObj:Handle>
                <WinHandleObj:Handle>
                    <WinHandleObj:Name>Cannot translate! Two Handle children present.</WinHandleObj:Name>
                </WinHandleObj:Handle>
            </WinMailslotObj:Handle>
        </cybox:Properties>
    </cybox:Object>

Controlled Vocabulary Updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At a minimum, controlled vocabulary updates include updates to the
``vocab_name``, ``vocab_reference``, and ``xsi:type`` attributes to refer
to new data type names and versions. Instance values may be updated if
typos were fixed in new versions.

The following updates were made to default CybOX controlled vocabularies,
defined by the ``cybox_default_vocabularies.xsd`` schema.

* ``ToolTypeVocab-1.0`` updated to ``ToolTypeVocab-1.1``.

  - Term ``'A/V'`` changed to ``'AV'``.

* ``ObjectRelationshipVocab-1.0`` updated to ``ObjectRelationshipVocab-1.1``.
* ``ActionNameVocab-1.0`` updated to ``ActionNameVocab-1.1``.

.. include:: /_includes/note_controlled_vocabulary_updates.rst


Empty Optional Fields Removed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following elements were required in CybOX 2.0.1 but became optional in
CybOX 2.1. Empty instances of these fields will be stripped during the update
process.

* ``DiskPartitionObj:Partition_ID``
* ``DNSCacheObj:DNS_Entry``
* ``DNSQueryObj:QName``
* ``FileObj:Depth``
* ``HTTPSessionObj:Message_Body``, ``HTTPSessionObj:Domain_Name``
* ``PacketObj:Address_Mask``, ``PacketObj:Address_Mask_Reply``,
  ``PacketObj:Address_Mask_Request``, ``PacketObj:Destination_Unreachable``,
  ``PacketObj:Echo_Reply``, ``PacketObj:Echo_Request``,
  ``PacketObj:Error_Msg``, ``PacketObj:Frag_Reassembly_Time_Exceeded``,
  ``PacketObj:Host_Redirect``, ``PacketObj:IP_Addr_Prefix``,
  ``PacketObj:IPv6_Addr``, ``PacketObj:Info_Msg``,
  ``PacketObj:Network_Redirect``,
  ``PacketObj:Outbound_Packet_Forward_Success``,
  ``PacketObj:Outbound_Packet_no_Route``, ``PacketObj:Receive_Timestamp``,
  ``PacketObj:Redirect_Message``, ``PacketObj:Source_Quench``,
  ``PacketObj:TTL_Exceeded_In_Transit``, ``PacketObj:Time_Exceeded``,
  ``PacketObj:Timestamp``, ``PacketObj:Timestamp_Reply``,
  ``PacketObj:Timestamp_Request``, ``PacketObj:ToS_Host_Redirect``,
  ``PacketObj:ToS_Network_Redirect``, ``PacketObj:Traceroute``,
  ``PacketObj:Transmit_Timestamp``
* ``SystemObj:IP_Address``
* ``URIObj:Value``
* ``WinComputerAccountObj:Delegation``, ``WinComputerAccountObj:Bitmask``,
  ``WinComputerAccountObj:Service``
* ``WinFileObj:Size_In_Bytes``
* ``WinNetworkShareObj:Netname``
* ``WinPrefetchObj:VolumeItem``, ``WinPrefetchObj:DeviceItem``

.. include:: /_includes/note_remove_empty_optionals_updates.rst