import itertools
from ramrod import (_Vocab, UpdateError, _DisallowedFields, _OptionalElements,
    _TranslatableField, _RenamedField)
from ramrod.utils import (ignored, get_typed_nodes, copy_xml_element,
    remove_xml_element, remove_xml_elements, remove_xml_attributes,
    create_new_id, replace_xml_element)
from ramrod.cybox import (_CyboxUpdater, TAG_CYBOX_MAJOR, TAG_CYBOX_MINOR,
    TAG_CYBOX_UPDATE)


class ObjectRelationshipVocab(_Vocab):
    TYPE = 'ObjectRelationshipVocab-1.1'
    VOCAB_REFERENCE = 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd#ObjectRelationshipVocab-1.1',
    VOCAB_NAME = 'CybOX Default Object-Object Relationships'


class ToolTypeVocab(_Vocab):
    TYPE = 'ToolTypeVocab-1.1'
    VOCAB_REFERENCE = 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd#ToolTypeVocab-1.1'
    VOCAB_NAME = 'CybOX Default Tool Types'
    TERMS = {
        'A/V': 'AV'
    }


class ActionNameVocab(_Vocab):
    TYPE = 'ActionNameVocab-1.1'
    VOCAB_REFERENCE = 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd#DefinedActionNameVocab-1.1'
    VOCAB_NAME = 'CybOX Default Action Names'


class DisallowedTaskTrigger(_DisallowedFields):
    XPATH = ".//WinTaskObj:Task_Trigger"


class DisallowedWindowsMailslotHandle(_DisallowedFields):
    XPATH = ".//WinMailslotObj:Handle[WinHandleObj:Handle]"

    @classmethod
    def _interrogate(cls, nodes):
        """Checks if any of the nodes in `nodes` contains more than one child
        element.

        In CybOX 2.0.1, the ``Handle`` element defined within the
        ``WindowsMailslotObjectType`` contained a list of
        ``WindowsHandleObjectType`` instances. CybOX 2.1 changed the top-level
        ``Handle`` element to be a single instance of
        ``WindowsHandleObjectType``.

        Content translation from CybOX 2.0.1 to CybOX 2.1 is only possible if
        the 2.0.1 content contains only one child.

        Returns:
            A list of nodes that contain more than one ``Handle`` child.

        """
        contraband = []
        for node in nodes:
            if len(node) > 1:
                contraband.append(node)

        return contraband


class DisallowedWinExecutableFile(_DisallowedFields):
    """Removes the ``Type`` element from instances of PESectionType, defined
    in the WindowsExecutableFileObject schema.

    The ``Type`` field does not exist in ``PESectionType`` of the
    ``WindowsExecutableFileObject`` v2.1.

    """
    # This could potentially become something that is translated into
    # another field rather than a disallowed field.
    XPATH = ".//{0}:Section/{0}:Type".format('WinExecutableFileObj')


class DisallowedHTTPSession(_DisallowedFields):
    XPATH = ".//HTTPSessionObj:X_Forwarded_Proto"


class OptionalCommonFields(_OptionalElements):
    XPATH = ".//cyboxCommon:Tool_Configuration"


class OptionalDNSCacheFields(_OptionalElements):
    XPATH = ".//DNSCacheObj:DNS_Entry"


class OptionalDNSQueryFields(_OptionalElements):
    XPATH = ".//DNSQueryObj:QName"


class OptionalDiskPartitionFields(_OptionalElements):
    XPATH = ".//DiskPartitionObj:Partition_ID"


class OptionalFileFields(_OptionalElements):
    XPATH = ".//FileObj:Depth"


class OptionalHTTPSessionFields(_OptionalElements):
    XPATH = (
        ".//HTTPSessionObj:Message_Body | "
        ".//HTTPSessionObj:Domain_Name"
    )


class OptionalLinkPackageFields(_OptionalElements):
    XPATH = ".//LinuxPackageObj:Name"


class OptionalNetworkPacketFields(_OptionalElements):
    ELEMENTS = (
        'Error_Msg', 'Info_Msg', 'Traceroute', 'Destination_Unreachable',
        'Source_Quench', 'Redirect_Message', 'Time_Exceeded', 'Echo_Reply',
        'Echo_Request', 'Timestamp_Request', 'Timestamp_Reply', 'Address_Mask',
        'Outbound_Packet_Forward_Success', 'Outbound_Packet_no_Route',
        'Network_Redirect', 'Host_Redirect', 'ToS_Host_Redirect',
        'ToS_Network_Redirect', 'TTL_Exceeded_In_Transit',
        'Frag_Reassembly_Time_Exceeded', 'Timestamp', 'Receive_Timestamp',
        'Transmit_Timestamp', 'Address_Mask_Request', 'Address_Mask_Reply',
        'IPv6_Addr', 'IP_Addr_Prefix',
    )
    XPATH = " | ".join(".//PacketObj:%s" % x for x in ELEMENTS)


class OptionalProductFields(_OptionalElements):
    XPATH = (
        ".//ProductObj:Product | "
        ".//ProductObj:Vendor"
    )


class OptionalSystemFields(_OptionalElements):
    XPATH = ".//SystemObj:IP_Address"


class OptionalURIFields(_OptionalElements):
    XPATH = ".//URIObj:Value"


class OptionalWinComputerAccountFields(_OptionalElements):
    XPATH = (
        ".//WinComputerAccountObj:Delegation | "
        ".//WinComputerAccountObj:Bitmask | "
        ".//WinComputerAccountObj:Service"
    )


class OptionalWinFileFields(_OptionalElements):
    XPATH = ".//WinFileObj:Size_In_Bytes"


class OptionalWinNetworkShareFields(_OptionalElements):
    XPATH = ".//WinNetworkShareObj:Netname"


class OptionalWinPrefetchFields(_OptionalElements):
    XPATH =(
        ".//WinPrefetchObj:VolumeItem | "
        ".//WinPrefetchObj:DeviceItem"
    )


class TransHTTPSessionDNT(_TranslatableField):
    XPATH_NODE = ".//HTTPSessionObj:DNT"
    XPATH_VALUE = "./URIObj:Value"
    COPY_ATTRIBUTES = True # TODO: make sure this correct


class TransHTTPSessionVary(_TranslatableField):
    XPATH_NODE = ".//HTTPSessionObj:Vary"
    XPATH_VALUE = "./URIObj:Value"
    COPY_ATTRIBUTES = True # TODO: make sure this correct


class TransHTTPSessionXRequestedFor(_RenamedField):
    XPATH_NODE = ".//HTTPSessionObj:X_Requested_For"
    NEW_TAG = "{http://cybox.mitre.org/objects#HTTPSessionObject-2}X_Forwarded_For"


class TransHTTPSessionRefresh(_TranslatableField):
    XPATH_NODE = ".//HTTPSessionObj:Refresh"
    COPY_ATTRIBUTES = True # TODO: make sure this correct
    OVERRIDE_ATTRIBUTES = {
        'datatype': 'string'
    }

class TransNetPacketProtoAddrSize(_RenamedField):
    XPATH_NODE = ".//PacketObj:Protol_Addr_Size"
    NEW_TAG = "{http://cybox.mitre.org/objects#PacketObject-2}Proto_Addr_Size"


class TransNetPacketEncapsulatingSecurityPayload(_RenamedField):
    XPATH_NODE = ".//PacketObj:Excapulating_Security_Payload"
    NEW_TAG = "{http://cybox.mitre.org/objects#PacketObject-2}Encapsulating_Security_Payload"


class TransNetPacketAuthenticationData(_RenamedField):
    XPATH_NODE = ".//PacketObj:Authenication_Data"
    NEW_TAG = "{http://cybox.mitre.org/objects#PacketObject-2}Authentication_Data"


class TransWinMailslotHandle(_TranslatableField):
    XPATH_NODE = ".//WinMailslotObj:Handle/WinHandleObj:Handle"
    NEW_TAG = "{http://cybox.mitre.org/objects#WinMailslotObject-2}Handle"

    @classmethod
    def _replace(cls, node):
        parent = node.getparent()
        dup = copy_xml_element(node, tag=cls.NEW_TAG)
        replace_xml_element(parent, dup)

    @classmethod
    def translate(cls, root):
        nodes = cls._find(root)
        for node in nodes:
            cls._replace(node)


class Cybox_2_0_1_Updater(_CyboxUpdater):
    """Updates CybOX v2.0.1 content to CybOX v2.1.

    The following fields are translated:
    * ToolTypeVocab-1.0 updated to ToolTypeVocab-1.1
    * ObjectRelationshipVocab-1.0 updated to ObjectRelationshipVocab-1.1
    * ActionNameVocab-1.0 updated to ActionNameVocab-1.1
    * Empty instances of cyboxCommon:Tool_Configuration are removed
    * Empty instances of DNSCacheObj:DNS_Entry are removed
    * Empty instances of DNSQueryObj:QName are removed
    * Empty instances of DiskPartitionObj:Partition_ID are removed
    * Empty instances of FileObj:Depth are removed
    * Empty instances of HTTPSessionObj:Message_Body and Domain_Name are removed
    * Many empty instance od elements under PacketeObj (see
      `OptionalNetworkPacketFields` class)
    * Empty instances of SystemObj:IP_Address are removed
    * Empty instances of URIObj:Value are removed
    * Empty instances of WinComputerAccountObj:Delegation, Bitmask, and Service
      are removed.
    * Empty instances of WinNetworkShareObj:Netname are removed
    * Empty instances of WinFileObj:Size_In_Bytes are removed
    * Empty instances of WinPrefetchObj:VolumeItem and DeviceItem are removed
    * HTTPSessionObj:DNT updated from URIObjectType to StringObjectPropertyType
    * HTTPSessionObj:Vary updated from URIObjectType to StringObjectPropertyType
    * HTTPSessionObj:Refresh updated from IntegerObjectPropertyType
      to StringObjectPropertyType
    * PacketObj:Protol_Addr_Size renamed to Proto_Addr_Size
    * PacketObj:Excapsulating_Security_Payload renamed to
      Encapsulating_Security_Payload
    * PacketObj:Authenication_Data renamed to Authentication_Data
    * WinMailslotObj:Handle container element removed and child bubbled up when
      only one child is defined.

    The following fields cannot be translated:
    * WinTaskObj:Task_Trigger instances.
    * WinMailslotObj:Handle when more than one child is defined.
    * WinExecutableFileObj:PESectionType/Type instances.
    * HTTPSession:X_Forwarded_Proto instances.

    """
    VERSION = '2.0.1'

    NSMAP = {
        'APIObj': 'http://cybox.mitre.org/objects#APIObject-2',
        'AccountObj': 'http://cybox.mitre.org/objects#AccountObject-2',
        'AddressObj': 'http://cybox.mitre.org/objects#AddressObject-2',
        'ArtifactObj': 'http://cybox.mitre.org/objects#ArtifactObject-2',
        'CodeObj': 'http://cybox.mitre.org/objects#CodeObject-2',
        'CustomObj': 'http://cybox.mitre.org/objects#CustomObject-1',
        'DNSCacheObj': 'http://cybox.mitre.org/objects#DNSCacheObject-2',
        'DNSQueryObj': 'http://cybox.mitre.org/objects#DNSQueryObject-2',
        'DNSRecordObj': 'http://cybox.mitre.org/objects#DNSRecordObject-2',
        'DeviceObj': 'http://cybox.mitre.org/objects#DeviceObject-2',
        'DiskObj': 'http://cybox.mitre.org/objects#DiskObject-2',
        'DiskPartitionObj': 'http://cybox.mitre.org/objects#DiskPartitionObject-2',
        'EmailMessageObj': 'http://cybox.mitre.org/objects#EmailMessageObject-2',
        'FileObj': 'http://cybox.mitre.org/objects#FileObject-2',
        'GUIDialogBoxObj': 'http://cybox.mitre.org/objects#GUIDialogboxObject-2',
        'GUIObj': 'http://cybox.mitre.org/objects#GUIObject-2',
        'GUIWindowObj': 'http://cybox.mitre.org/objects#GUIWindowObject-2',
        'HTTPSessionObj': 'http://cybox.mitre.org/objects#HTTPSessionObject-2',
        'LibraryObj': 'http://cybox.mitre.org/objects#LibraryObject-2',
        'LinkObj': 'http://cybox.mitre.org/objects#LinkObject-1',
        'LinuxPackageObj': 'http://cybox.mitre.org/objects#LinuxPackageObject-2',
        'MemoryObj': 'http://cybox.mitre.org/objects#MemoryObject-2',
        'MutexObj': 'http://cybox.mitre.org/objects#MutexObject-2',
        'NetFlowObj': 'http://cybox.mitre.org/objects#NetworkFlowObject-2',
        'NetworkConnectionObj': 'http://cybox.mitre.org/objects#NetworkConnectionObject-2',
        'NetworkRouteEntryObj': 'http://cybox.mitre.org/objects#NetworkRouteEntryObject-2',
        'NetworkRouteObj': 'http://cybox.mitre.org/objects#NetworkRouteObject-2',
        'NetworkSocketObj': 'http://cybox.mitre.org/objects#NetworkSocketObject-2',
        'NetworkSubnetObj': 'http://cybox.mitre.org/objects#NetworkSubnetObject-2',
        'PDFFileObj': 'http://cybox.mitre.org/objects#PDFFileObject-1',
        'PacketObj': 'http://cybox.mitre.org/objects#PacketObject-2',
        'PipeObj': 'http://cybox.mitre.org/objects#PipeObject-2',
        'PortObj': 'http://cybox.mitre.org/objects#PortObject-2',
        'ProcessObj': 'http://cybox.mitre.org/objects#ProcessObject-2',
        'ProductObj': 'http://cybox.mitre.org/objects#ProductObject-2',
        'SemaphoreObj': 'http://cybox.mitre.org/objects#SemaphoreObject-2',
        'SocketAddressObj': 'http://cybox.mitre.org/objects#SocketAddressObject-1',
        'SystemObj': 'http://cybox.mitre.org/objects#SystemObject-2',
        'URIObj': 'http://cybox.mitre.org/objects#URIObject-2',
        'UnixFileObj': 'http://cybox.mitre.org/objects#UnixFileObject-2',
        'UnixNetworkRouteEntryObj': 'http://cybox.mitre.org/objects#UnixNetworkRouteEntryObject-2',
        'UnixPipeObj': 'http://cybox.mitre.org/objects#UnixPipeObject-2',
        'UnixProcessObj': 'http://cybox.mitre.org/objects#UnixProcessObject-2',
        'UnixUserAccountObj': 'http://cybox.mitre.org/objects#UnixUserAccountObject-2',
        'UnixVolumeObj': 'http://cybox.mitre.org/objects#UnixVolumeObject-2',
        'UserAccountObj': 'http://cybox.mitre.org/objects#UserAccountObject-2',
        'UserSessionObj': 'http://cybox.mitre.org/objects#UserSessionObject-2',
        'VolumeObj': 'http://cybox.mitre.org/objects#VolumeObject-2',
        'WhoisObj': 'http://cybox.mitre.org/objects#WhoisObject-2',
        'WinComputerAccountObj': 'http://cybox.mitre.org/objects#WinComputerAccountObject-2',
        'WinCriticalSectionObj': 'http://cybox.mitre.org/objects#WinCriticalSectionObject-2',
        'WinDriverObj': 'http://cybox.mitre.org/objects#WinDriverObject-2',
        'WinEventLogObj': 'http://cybox.mitre.org/objects#WinEventLogObject-2',
        'WinEventObj': 'http://cybox.mitre.org/objects#WinEventObject-2',
        'WinExecutableFileObj': 'http://cybox.mitre.org/objects#WinExecutableFileObject-2',
        'WinFileObj': 'http://cybox.mitre.org/objects#WinFileObject-2',
        'WinHandleObj': 'http://cybox.mitre.org/objects#WinHandleObject-2',
        'WinKernelHookObj': 'http://cybox.mitre.org/objects#WinKernelHookObject-2',
        'WinKernelObj': 'http://cybox.mitre.org/objects#WinKernelObject-2',
        'WinMailslotObj': 'http://cybox.mitre.org/objects#WinMailslotObject-2',
        'WinMemoryPageRegionObj': 'http://cybox.mitre.org/objects#WinMemoryPageRegionObject-2',
        'WinMutexObj': 'http://cybox.mitre.org/objects#WinMutexObject-2',
        'WinNetworkRouteEntryObj': 'http://cybox.mitre.org/objects#WinNetworkRouteEntryObject-2',
        'WinNetworkShareObj': 'http://cybox.mitre.org/objects#WinNetworkShareObject-2',
        'WinPipeObj': 'http://cybox.mitre.org/objects#WinPipeObject-2',
        'WinPrefetchObj': 'http://cybox.mitre.org/objects#WinPrefetchObject-2',
        'WinProcessObj': 'http://cybox.mitre.org/objects#WinProcessObject-2',
        'WinRegistryKeyObj': 'http://cybox.mitre.org/objects#WinRegistryKeyObject-2',
        'WinSemaphoreObj': 'http://cybox.mitre.org/objects#WinSemaphoreObject-2',
        'WinServiceObj': 'http://cybox.mitre.org/objects#WinServiceObject-2',
        'WinSystemObj': 'http://cybox.mitre.org/objects#WinSystemObject-2',
        'WinSystemRestoreObj': 'http://cybox.mitre.org/objects#WinSystemRestoreObject-2',
        'WinTaskObj': 'http://cybox.mitre.org/objects#WinTaskObject-2',
        'WinThreadObj': 'http://cybox.mitre.org/objects#WinThreadObject-2',
        'WinUserAccountObj': 'http://cybox.mitre.org/objects#WinUserAccountObject-2',
        'WinVolumeObj': 'http://cybox.mitre.org/objects#WinVolumeObject-2',
        'WinWaitableTimerObj': 'http://cybox.mitre.org/objects#WinWaitableTimerObject-2',
        'X509CertificateObj': 'http://cybox.mitre.org/objects#X509CertificateObject-2',
        'cybox': 'http://cybox.mitre.org/cybox-2',
        'cyboxCommon': 'http://cybox.mitre.org/common-2',
        'cyboxVocabs': 'http://cybox.mitre.org/default_vocabularies-2',
        'cybox-cpe': 'http://cybox.mitre.org/extensions/platform#CPE2.3-1',
    }

    DISALLOWED = (
        DisallowedHTTPSession,
        DisallowedTaskTrigger,
        DisallowedWinExecutableFile,
        DisallowedWindowsMailslotHandle
    )

    OPTIONAL_ELEMENTS = (
        OptionalCommonFields,
        OptionalDiskPartitionFields,
        OptionalDNSCacheFields,
        OptionalDNSQueryFields,
        OptionalFileFields,
        OptionalHTTPSessionFields,
        OptionalLinkPackageFields,
        OptionalNetworkPacketFields,
        OptionalProductFields,
        OptionalSystemFields,
        OptionalURIFields,
        OptionalWinComputerAccountFields,
        OptionalWinFileFields,
        OptionalWinNetworkShareFields,
        OptionalWinPrefetchFields,
    )

    OPTIONAL_ATTRIBUTES = ()

    TRANSLATABLE_FIELDS = (
        TransHTTPSessionDNT,
        TransHTTPSessionVary,
        TransHTTPSessionRefresh,
        TransHTTPSessionXRequestedFor,
        TransNetPacketAuthenticationData,
        TransNetPacketEncapsulatingSecurityPayload,
        TransNetPacketProtoAddrSize,
        TransWinMailslotHandle
    )

    UPDATE_NS_MAP = {
        'http://cybox.mitre.org/objects#WinDriverObject-2': 'http://cybox.mitre.org/objects#WinDriverObject-3',
    }

    # Cybox 2.1 NS => CybOX 2.1 Schemalocations
    UPDATE_SCHEMALOC_MAP = {
        'http://cybox.mitre.org/common-2': 'http://cybox.mitre.org/XMLSchema/common/2.1/cybox_common.xsd',
        'http://cybox.mitre.org/cybox-2': 'http://cybox.mitre.org/XMLSchema/core/2.1/cybox_core.xsd',
        'http://cybox.mitre.org/default_vocabularies-2': 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.1/cybox_default_vocabularies.xsd',
        'http://cybox.mitre.org/extensions/Address#CIQAddress3.0-1': 'http://cybox.mitre.org/XMLSchema/extensions/location/ciq_address_3.0/1.0/ciq_address_3.0.xsd',
        'http://cybox.mitre.org/extensions/platform#CPE2.3-1': 'http://cybox.mitre.org/XMLSchema/extensions/platform/cpe2.3/1.1/cpe2.3.xsd',
        'http://cybox.mitre.org/objects#APIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/API/2.1/API_Object.xsd',
        'http://cybox.mitre.org/objects#ARPCacheObject-1': 'http://cybox.mitre.org/XMLSchema/objects/ARP_Cache/1.0/ARP_Cache_Object.xsd',
        'http://cybox.mitre.org/objects#ASObject-1': 'http://cybox.mitre.org/XMLSchema/objects/AS/1.0/AS_Object.xsd',
        'http://cybox.mitre.org/objects#AccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Account/2.1/Account_Object.xsd',
        'http://cybox.mitre.org/objects#AddressObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Address/2.1/Address_Object.xsd',
        'http://cybox.mitre.org/objects#ArchiveFileObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Archive_File/1.0/Archive_File_Object.xsd',
        'http://cybox.mitre.org/objects#ArtifactObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Artifact/2.1/Artifact_Object.xsd',
        'http://cybox.mitre.org/objects#CodeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Code/2.1/Code_Object.xsd',
        'http://cybox.mitre.org/objects#CustomObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Custom/1.1/Custom_Object.xsd',
        'http://cybox.mitre.org/objects#DNSCacheObject-2': 'http://cybox.mitre.org/XMLSchema/objects/DNS_Cache/2.1/DNS_Cache_Object.xsd',
        'http://cybox.mitre.org/objects#DNSQueryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/DNS_Query/2.1/DNS_Query_Object.xsd',
        'http://cybox.mitre.org/objects#DNSRecordObject-2': 'http://cybox.mitre.org/XMLSchema/objects/DNS_Record/2.1/DNS_Record_Object.xsd',
        'http://cybox.mitre.org/objects#DeviceObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Device/2.1/Device_Object.xsd',
        'http://cybox.mitre.org/objects#DiskObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Disk/2.1/Disk_Object.xsd',
        'http://cybox.mitre.org/objects#DiskPartitionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Disk_Partition/2.1/Disk_Partition_Object.xsd',
        'http://cybox.mitre.org/objects#DomainNameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Domain_Name/1.0/Domain_Name_Object.xsd',
        'http://cybox.mitre.org/objects#EmailMessageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.1/Email_Message_Object.xsd',
        'http://cybox.mitre.org/objects#FileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/File/2.1/File_Object.xsd',
        'http://cybox.mitre.org/objects#GUIDialogboxObject-2': 'http://cybox.mitre.org/XMLSchema/objects/GUI_Dialogbox/2.1/GUI_Dialogbox_Object.xsd',
        'http://cybox.mitre.org/objects#GUIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/GUI/2.1/GUI_Object.xsd',
        'http://cybox.mitre.org/objects#GUIWindowObject-2': 'http://cybox.mitre.org/XMLSchema/objects/GUI_Window/2.1/GUI_Window_Object.xsd',
        'http://cybox.mitre.org/objects#HTTPSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/HTTP_Session/2.1/HTTP_Session_Object.xsd',
        'http://cybox.mitre.org/objects#HostnameObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Hostname/1.0/Hostname_Object.xsd',
        'http://cybox.mitre.org/objects#ImageFileObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Image_File/1.0/Image_File_Object.xsd',
        'http://cybox.mitre.org/objects#LibraryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Library/2.1/Library_Object.xsd',
        'http://cybox.mitre.org/objects#LinkObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Link/1.1/Link_Object.xsd',
        'http://cybox.mitre.org/objects#LinuxPackageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Linux_Package/2.1/Linux_Package_Object.xsd',
        'http://cybox.mitre.org/objects#MemoryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Memory/2.1/Memory_Object.xsd',
        'http://cybox.mitre.org/objects#MutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Mutex/2.1/Mutex_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkConnectionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Connection/2.1/Network_Connection_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkFlowObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Flow/2.1/Network_Flow_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkRouteEntryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Route_Entry/2.1/Network_Route_Entry_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkRouteObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Route/2.1/Network_Route_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkSocketObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Socket/2.1/Network_Socket_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkSubnetObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Subnet/2.1/Network_Subnet_Object.xsd',
        'http://cybox.mitre.org/objects#PDFFileObject-1': 'http://cybox.mitre.org/XMLSchema/objects/PDF_File/1.1/PDF_File_Object.xsd',
        'http://cybox.mitre.org/objects#PacketObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Packet/2.1/Network_Packet_Object.xsd',
        'http://cybox.mitre.org/objects#PipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Pipe/2.1/Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#PortObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Port/2.1/Port_Object.xsd',
        'http://cybox.mitre.org/objects#ProcessObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Process/2.1/Process_Object.xsd',
        'http://cybox.mitre.org/objects#ProductObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Product/2.1/Product_Object.xsd',
        'http://cybox.mitre.org/objects#SMSMessageObject-1': 'http://cybox.mitre.org/XMLSchema/objects/SMS_Message/1.0/SMS_Message_Object.xsd',
        'http://cybox.mitre.org/objects#SemaphoreObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Semaphore/2.1/Semaphore_Object.xsd',
        'http://cybox.mitre.org/objects#SocketAddressObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Socket_Address/1.1/Socket_Address_Object.xsd',
        'http://cybox.mitre.org/objects#SystemObject-2': 'http://cybox.mitre.org/XMLSchema/objects/System/2.1/System_Object.xsd',
        'http://cybox.mitre.org/objects#URIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/URI/2.1/URI_Object.xsd',
        'http://cybox.mitre.org/objects#URLHistoryObject-1': 'http://cybox.mitre.org/XMLSchema/objects/URL_History/1.0/URL_History_Object.xsd',
        'http://cybox.mitre.org/objects#UnixFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_File/2.1/Unix_File_Object.xsd',
        'http://cybox.mitre.org/objects#UnixNetworkRouteEntryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Network_Route_Entry/2.1/Unix_Network_Route_Entry_Object.xsd',
        'http://cybox.mitre.org/objects#UnixPipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Pipe/2.1/Unix_Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#UnixProcessObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Process/2.1/Unix_Process_Object.xsd',
        'http://cybox.mitre.org/objects#UnixUserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_User_Account/2.1/Unix_User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#UnixVolumeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Volume/2.1/Unix_Volume_Object.xsd',
        'http://cybox.mitre.org/objects#UserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/User_Account/2.1/User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#UserSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/User_Session/2.1/User_Session_Object.xsd',
        'http://cybox.mitre.org/objects#VolumeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Volume/2.1/Volume_Object.xsd',
        'http://cybox.mitre.org/objects#WhoisObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Whois/2.1/Whois_Object.xsd',
        'http://cybox.mitre.org/objects#WinComputerAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Computer_Account/2.1/Win_Computer_Account_Object.xsd',
        'http://cybox.mitre.org/objects#WinCriticalSectionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Critical_Section/2.1/Win_Critical_Section_Object.xsd',
        'http://cybox.mitre.org/objects#WinDriverObject-3': 'http://cybox.mitre.org/XMLSchema/objects/Win_Driver/3.0/Win_Driver_Object.xsd',
        'http://cybox.mitre.org/objects#WinEventLogObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Event_Log/2.1/Win_Event_Log_Object.xsd',
        'http://cybox.mitre.org/objects#WinEventObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Event/2.1/Win_Event_Object.xsd',
        'http://cybox.mitre.org/objects#WinExecutableFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/2.1/Win_Executable_File_Object.xsd',
        'http://cybox.mitre.org/objects#WinFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_File/2.1/Win_File_Object.xsd',
        'http://cybox.mitre.org/objects#WinFilemappingObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Win_Filemapping/1.0/Win_Filemapping_Object.xsd',
        'http://cybox.mitre.org/objects#WinHandleObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Handle/2.1/Win_Handle_Object.xsd',
        'http://cybox.mitre.org/objects#WinHookObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Win_Hook/1.0/Win_Hook_Object.xsd',
        'http://cybox.mitre.org/objects#WinKernelHookObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Kernel_Hook/2.1/Win_Kernel_Hook_Object.xsd',
        'http://cybox.mitre.org/objects#WinKernelObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Kernel/2.1/Win_Kernel_Object.xsd',
        'http://cybox.mitre.org/objects#WinMailslotObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Mailslot/2.1/Win_Mailslot_Object.xsd',
        'http://cybox.mitre.org/objects#WinMemoryPageRegionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Memory_Page_Region/2.1/Win_Memory_Page_Region_Object.xsd',
        'http://cybox.mitre.org/objects#WinMutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Mutex/2.1/Win_Mutex_Object.xsd',
        'http://cybox.mitre.org/objects#WinNetworkRouteEntryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Network_Route_Entry/2.1/Win_Network_Route_Entry_Object.xsd',
        'http://cybox.mitre.org/objects#WinNetworkShareObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Network_Share/2.1/Win_Network_Share_Object.xsd',
        'http://cybox.mitre.org/objects#WinPipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Pipe/2.1/Win_Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#WinPrefetchObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Prefetch/2.1/Win_Prefetch_Object.xsd',
        'http://cybox.mitre.org/objects#WinProcessObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Process/2.1/Win_Process_Object.xsd',
        'http://cybox.mitre.org/objects#WinRegistryKeyObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.1/Win_Registry_Key_Object.xsd',
        'http://cybox.mitre.org/objects#WinSemaphoreObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Semaphore/2.1/Win_Semaphore_Object.xsd',
        'http://cybox.mitre.org/objects#WinServiceObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Service/2.1/Win_Service_Object.xsd',
        'http://cybox.mitre.org/objects#WinSystemObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_System/2.1/Win_System_Object.xsd',
        'http://cybox.mitre.org/objects#WinSystemRestoreObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_System_Restore/2.1/Win_System_Restore_Object.xsd',
        'http://cybox.mitre.org/objects#WinTaskObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Task/2.1/Win_Task_Object.xsd',
        'http://cybox.mitre.org/objects#WinThreadObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Thread/2.1/Win_Thread_Object.xsd',
        'http://cybox.mitre.org/objects#WinUserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_User_Account/2.1/Win_User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#WinVolumeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Volume/2.1/Win_Volume_Object.xsd',
        'http://cybox.mitre.org/objects#WinWaitableTimerObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Waitable_Timer/2.1/Win_Waitable_Timer_Object.xsd',
        'http://cybox.mitre.org/objects#X509CertificateObject-2': 'http://cybox.mitre.org/XMLSchema/objects/X509_Certificate/2.1/X509_Certificate_Object.xsd',
    }


    UPDATE_VOCABS = {
        'ObjectRelationshipVocab-1.0': ObjectRelationshipVocab,
        'ToolTypeVocab-1.0': ToolTypeVocab,
        'ActionNameVocab-1.0': ActionNameVocab
    }


    def __init__(self):
        super(Cybox_2_0_1_Updater, self).__init__()


    def _update_versions(self, root):
        """Updates the version of Observables instances under `root` to
        ``2.1``.

        """
        nodes = self._get_versioned_nodes(root)

        for node in nodes:
            attribs = node.attrib
            attribs[TAG_CYBOX_MAJOR]  = '2'
            attribs[TAG_CYBOX_MINOR]  = '1'

            with ignored(KeyError):
                del attribs[TAG_CYBOX_UPDATE]


    def _translate_fields(self, root):
        """Translates fields which have changed in structure or data type.

        """
        for field in self.TRANSLATABLE_FIELDS:
            field.translate(root)


    def _update_optionals(self, root):
        """Finds and removes empty xml elements and attributes which are
        optional in the next language release.

        Args:
            root: The top-level xml node.

        """
        optional_elements = self.OPTIONAL_ELEMENTS
        optional_attribs = self.OPTIONAL_ATTRIBUTES

        typed_nodes = get_typed_nodes(root)

        for optional in optional_elements:
            found = optional.find(root, typed=typed_nodes)
            remove_xml_elements(found)


        for optional in optional_attribs:
            found = optional.find(root, typed=typed_nodes)
            for node in found:
                remove_xml_attributes(node, optional.ATTRIBUTES)


    def _get_disallowed(self, root):
        """Finds all xml entities under `root` that cannot be updated.

        Args:
            root: The top-level xml node

        Returns:
            A list of untranslatable items.

        """
        disallowed = []

        for klass in self.DISALLOWED:
            found = klass.find(root)
            disallowed.extend(found)

        return disallowed


    def check_update(self, root, check_version=True):
        """Determines if the input document can be upgraded.

        Args:
            root (lxml.etree._Element): The top-level node of the document
                being upgraded.
            check_version(boolean): If True, the version of `root` is checked.

        Raises:
            UnknownVersionError: If the input document does not have a version.
            InvalidVersionError: If the version of the input document
                does not match the `VERSION` class-level attribute value.
            UpdateError: If the input document contains fields which cannot
                be updated or constructs with non-unique IDs are discovered.

        """
        if check_version:
            self._check_version(root)

        duplicates = self._get_duplicates(root)
        disallowed = self._get_disallowed(root)

        if any((disallowed, duplicates)):
            raise UpdateError("Found duplicate or untranslatable fields in "
                              "source document.",
                              disallowed=disallowed,
                              duplicates=duplicates)


    def _clean_disallowed(self, disallowed):
        """Removes the `disallowed` nodes from the source document.

        Args:
            disallowed: A list of nodes to remove from the source document.

        Returns:
            A list of `disallowed` node copies.

        """
        removed = []
        for node in disallowed:
            dup = copy_xml_element(node)
            remove_xml_element(node)
            removed.append(dup)

        return removed


    def _clean_duplicates(self, duplicates):
        """Assigns a unique ID to each node in `duplicates`.

        Args:
            duplicates: A list of nodes with non-unique IDs

        Returns:
            The modified `duplicates` list.

        """
        for id_, nodes in duplicates.iteritems():
            for node in nodes:
                new_id = create_new_id(id_)
                node.attrib['id'] = new_id

        return duplicates

    def clean(self, root, disallowed=None, duplicates=None):
        """Removes disallowed elements from `root` and remaps non-unique
        IDs to unique IDs for the sake of schema-validation.

        Note:
            This does not remap ``idref`` attributes to new ID values because
            it is impossible to determine which entity the ``idref`` was
            pointing to.

        A copy of the removed nodes are stored on the instance-level
        `cleaned_fields` attribute.

        The `cleaned_ids` instance-level dictionary will be populated with
        ids and nodes which had their ids remapped.

        Note:
            The `cleaned_fields` and `cleanded_ids` attributes will be
            overwritten with each method invocation.

        Args:
            disallowed: A list of disallowed nodes to remove from the `root`
                document. If ``None``, an attempt will be made to discover
                all untranslatable elements under the `root` node.
            duplicates: A dictionary of id => [nodes] where the key represents
                the non-unique IDs and the ``[nodes]`` value is a list of nodes
                with that ID value.

        Returns:
            The source `root` node.

        """
        disallowed = disallowed or self._get_disallowed(root)
        duplicates = duplicates or self._get_duplicates(root)

        remapped = self._clean_duplicates(duplicates)
        removed = self._clean_disallowed(disallowed)

        self.cleaned_ids = remapped
        self.cleaned_fields = tuple(removed)

        return root


    def _update(self, root):
        updated = self._update_namespaces(root)
        self._update_schemalocs(updated)
        self._update_versions(updated)
        self._update_vocabs(updated)
        self._update_optionals(updated)
        self._translate_fields(updated)
        return updated



# Wiring namespace dictionaries
nsmapped = itertools.chain(
    Cybox_2_0_1_Updater.DISALLOWED,
    Cybox_2_0_1_Updater.OPTIONAL_ELEMENTS,
    Cybox_2_0_1_Updater.OPTIONAL_ATTRIBUTES,
    Cybox_2_0_1_Updater.TRANSLATABLE_FIELDS
)
for klass in nsmapped:
    klass.NSMAP = Cybox_2_0_1_Updater.NSMAP
