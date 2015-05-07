# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# internal
from ramrod import utils, xmlconst
from ramrod.options import DEFAULT_UPDATE_OPTIONS

# relative
from . import common
from . import register_updater
from .base import CyboxVocab, BaseCyboxUpdater


class EventTypeVocab(CyboxVocab):
    OLD_TYPES = ('EventTypeVocab-1.0',)
    NEW_TYPE = 'EventTypeVocab-1.0.1'
    VOCAB_REFERENCE = 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.0.1/cybox_default_vocabularies.xsd#EventTypeVocab-1.0.1'
    VOCAB_NAME = 'CybOX Default Event Types'
    TERMS = {
        "Anomoly Events": "Anomaly Events"
    }


@register_updater
class Cybox_2_0_Updater(BaseCyboxUpdater):
    """Updates CybOX v2.0 content to CybOX v2.0.1.

    The following fields are translated:

    * ``EventTypeVocab-1.0`` updated to ``EventTypeVocab-1.0.1``

    Note:
        All fields can be translated from CybOX v2.0 to CybOX v2.0.1

    """
    VERSION = '2.0'

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

    # CybOX 2.0 NS => CybOX 2.0.1 SCHEMALOC
    UPDATE_SCHEMALOC_MAP = {
        'http://cybox.mitre.org/common-2': 'http://cybox.mitre.org/XMLSchema/common/2.0.1/cybox_common.xsd',
        'http://cybox.mitre.org/cybox-2': 'http://cybox.mitre.org/XMLSchema/core/2.0.1/cybox_core.xsd',
        'http://cybox.mitre.org/default_vocabularies-2': 'http://cybox.mitre.org/XMLSchema/default_vocabularies/2.0.1/cybox_default_vocabularies.xsd',
        'http://cybox.mitre.org/extensions/platform#CPE2.3-1': 'http://cybox.mitre.org/XMLSchema/extensions/platform/cpe2.3/1.0.1/cpe2.3.xsd',
        'http://cybox.mitre.org/objects#APIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/API/2.0.1/API_Object.xsd',
        'http://cybox.mitre.org/objects#AccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Account/2.0.1/Account_Object.xsd',
        'http://cybox.mitre.org/objects#AddressObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Address/2.0.1/Address_Object.xsd',
        'http://cybox.mitre.org/objects#ArtifactObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Artifact/2.0.1/Artifact_Object.xsd',
        'http://cybox.mitre.org/objects#CodeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Code/2.0.1/Code_Object.xsd',
        'http://cybox.mitre.org/objects#CustomObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Custom/1.0.1/Custom_Object.xsd',
        'http://cybox.mitre.org/objects#DNSCacheObject-2': 'http://cybox.mitre.org/XMLSchema/objects/DNS_Cache/2.0.1/DNS_Cache_Object.xsd',
        'http://cybox.mitre.org/objects#DNSQueryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/DNS_Query/2.0.1/DNS_Query_Object.xsd',
        'http://cybox.mitre.org/objects#DNSRecordObject-2': 'http://cybox.mitre.org/XMLSchema/objects/DNS_Record/2.0.1/DNS_Record_Object.xsd',
        'http://cybox.mitre.org/objects#DeviceObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Device/2.0.1/Device_Object.xsd',
        'http://cybox.mitre.org/objects#DiskObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Disk/2.0.1/Disk_Object.xsd',
        'http://cybox.mitre.org/objects#DiskPartitionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Disk_Partition/2.0.1/Disk_Partition_Object.xsd',
        'http://cybox.mitre.org/objects#EmailMessageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Email_Message/2.0.1/Email_Message_Object.xsd',
        'http://cybox.mitre.org/objects#FileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/File/2.0.1/File_Object.xsd',
        'http://cybox.mitre.org/objects#GUIDialogboxObject-2': 'http://cybox.mitre.org/XMLSchema/objects/GUI_Dialogbox/2.0.1/GUI_Dialogbox_Object.xsd',
        'http://cybox.mitre.org/objects#GUIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/GUI/2.0.1/GUI_Object.xsd',
        'http://cybox.mitre.org/objects#GUIWindowObject-2': 'http://cybox.mitre.org/XMLSchema/objects/GUI_Window/2.0.1/GUI_Window_Object.xsd',
        'http://cybox.mitre.org/objects#HTTPSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/HTTP_Session/2.0.1/HTTP_Session_Object.xsd',
        'http://cybox.mitre.org/objects#LibraryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Library/2.0.1/Library_Object.xsd',
        'http://cybox.mitre.org/objects#LinkObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Link/1.0.1/Link_Object.xsd',
        'http://cybox.mitre.org/objects#LinuxPackageObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Linux_Package/2.0.1/Linux_Package_Object.xsd',
        'http://cybox.mitre.org/objects#MemoryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Memory/2.0.1/Memory_Object.xsd',
        'http://cybox.mitre.org/objects#MutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Mutex/2.0.1/Mutex_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkConnectionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Connection/2.0.1/Network_Connection_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkFlowObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Flow/2.0.1/Network_Flow_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkRouteEntryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Route_Entry/2.0.1/Network_Route_Entry_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkRouteObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Route/2.0.1/Network_Route_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkSocketObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Socket/2.0.1/Network_Socket_Object.xsd',
        'http://cybox.mitre.org/objects#NetworkSubnetObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Subnet/2.0.1/Network_Subnet_Object.xsd',
        'http://cybox.mitre.org/objects#PDFFileObject-1': 'http://cybox.mitre.org/XMLSchema/objects/PDF_File/1.0.1/PDF_File_Object.xsd',
        'http://cybox.mitre.org/objects#PacketObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Network_Packet/2.0.1/Network_Packet_Object.xsd',
        'http://cybox.mitre.org/objects#PipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Pipe/2.0.1/Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#PortObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Port/2.0.1/Port_Object.xsd',
        'http://cybox.mitre.org/objects#ProcessObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Process/2.0.1/Process_Object.xsd',
        'http://cybox.mitre.org/objects#ProductObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Product/2.0.1/Product_Object.xsd',
        'http://cybox.mitre.org/objects#SemaphoreObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Semaphore/2.0.1/Semaphore_Object.xsd',
        'http://cybox.mitre.org/objects#SocketAddressObject-1': 'http://cybox.mitre.org/XMLSchema/objects/Socket_Address/1.0.1/Socket_Address_Object.xsd',
        'http://cybox.mitre.org/objects#SystemObject-2': 'http://cybox.mitre.org/XMLSchema/objects/System/2.0.1/System_Object.xsd',
        'http://cybox.mitre.org/objects#URIObject-2': 'http://cybox.mitre.org/XMLSchema/objects/URI/2.0.1/URI_Object.xsd',
        'http://cybox.mitre.org/objects#UnixFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_File/2.0.1/Unix_File_Object.xsd',
        'http://cybox.mitre.org/objects#UnixNetworkRouteEntryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Network_Route_Entry/2.0.1/Unix_Network_Route_Entry_Object.xsd',
        'http://cybox.mitre.org/objects#UnixPipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Pipe/2.0.1/Unix_Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#UnixProcessObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Process/2.0.1/Unix_Process_Object.xsd',
        'http://cybox.mitre.org/objects#UnixUserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_User_Account/2.0.1/Unix_User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#UnixVolumeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Unix_Volume/2.0.1/Unix_Volume_Object.xsd',
        'http://cybox.mitre.org/objects#UserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/User_Account/2.0.1/User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#UserSessionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/User_Session/2.0.1/User_Session_Object.xsd',
        'http://cybox.mitre.org/objects#VolumeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Volume/2.0.1/Volume_Object.xsd',
        'http://cybox.mitre.org/objects#WhoisObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Whois/2.0.1/Whois_Object.xsd',
        'http://cybox.mitre.org/objects#WinComputerAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Computer_Account/2.0.1/Win_Computer_Account_Object.xsd',
        'http://cybox.mitre.org/objects#WinCriticalSectionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Critical_Section/2.0.1/Win_Critical_Section_Object.xsd',
        'http://cybox.mitre.org/objects#WinDriverObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Driver/2.0.1/Win_Driver_Object.xsd',
        'http://cybox.mitre.org/objects#WinEventLogObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Event_Log/2.0.1/Win_Event_Log_Object.xsd',
        'http://cybox.mitre.org/objects#WinEventObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Event/2.0.1/Win_Event_Object.xsd',
        'http://cybox.mitre.org/objects#WinExecutableFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Executable_File/2.0.1/Win_Executable_File_Object.xsd',
        'http://cybox.mitre.org/objects#WinFileObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_File/2.0.1/Win_File_Object.xsd',
        'http://cybox.mitre.org/objects#WinHandleObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Handle/2.0.1/Win_Handle_Object.xsd',
        'http://cybox.mitre.org/objects#WinKernelHookObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Kernel_Hook/2.0.1/Win_Kernel_Hook_Object.xsd',
        'http://cybox.mitre.org/objects#WinKernelObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Kernel/2.0.1/Win_Kernel_Object.xsd',
        'http://cybox.mitre.org/objects#WinMailslotObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Mailslot/2.0.1/Win_Mailslot_Object.xsd',
        'http://cybox.mitre.org/objects#WinMemoryPageRegionObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Memory_Page_Region/2.0.1/Win_Memory_Page_Region_Object.xsd',
        'http://cybox.mitre.org/objects#WinMutexObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Mutex/2.0.1/Win_Mutex_Object.xsd',
        'http://cybox.mitre.org/objects#WinNetworkRouteEntryObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Network_Route_Entry/2.0.1/Win_Network_Route_Entry_Object.xsd',
        'http://cybox.mitre.org/objects#WinNetworkShareObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Network_Share/2.0.1/Win_Network_Share_Object.xsd',
        'http://cybox.mitre.org/objects#WinPipeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Pipe/2.0.1/Win_Pipe_Object.xsd',
        'http://cybox.mitre.org/objects#WinPrefetchObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Prefetch/2.0.1/Win_Prefetch_Object.xsd',
        'http://cybox.mitre.org/objects#WinProcessObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Process/2.0.1/Win_Process_Object.xsd',
        'http://cybox.mitre.org/objects#WinRegistryKeyObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Registry_Key/2.0.1/Win_Registry_Key_Object.xsd',
        'http://cybox.mitre.org/objects#WinSemaphoreObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Semaphore/2.0.1/Win_Semaphore_Object.xsd',
        'http://cybox.mitre.org/objects#WinServiceObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Service/2.0.1/Win_Service_Object.xsd',
        'http://cybox.mitre.org/objects#WinSystemObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_System/2.0.1/Win_System_Object.xsd',
        'http://cybox.mitre.org/objects#WinSystemRestoreObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_System_Restore/2.0.1/Win_System_Restore_Object.xsd',
        'http://cybox.mitre.org/objects#WinTaskObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Task/2.0.1/Win_Task_Object.xsd',
        'http://cybox.mitre.org/objects#WinThreadObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Thread/2.0.1/Win_Thread_Object.xsd',
        'http://cybox.mitre.org/objects#WinUserAccountObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_User_Account/2.0.1/Win_User_Account_Object.xsd',
        'http://cybox.mitre.org/objects#WinVolumeObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Volume/2.0.1/Win_Volume_Object.xsd',
        'http://cybox.mitre.org/objects#WinWaitableTimerObject-2': 'http://cybox.mitre.org/XMLSchema/objects/Win_Waitable_Timer/2.0.1/Win_Waitable_Timer_Object.xsd',
        'http://cybox.mitre.org/objects#X509CertificateObject-2': 'http://cybox.mitre.org/XMLSchema/objects/X509_Certificate/2.0.1/X509_Certificate_Object.xsd',
    }

    UPDATE_VOCABS = (
        EventTypeVocab,
    )

    def __init__(self):
        super(Cybox_2_0_Updater, self).__init__()

    def _update_versions(self, root):
        """Updates the version of Observables instances under `root` to
        ``2.0.1``.

        """
        nodes = self._get_versioned_nodes(root)

        for node in nodes:
            attribs = node.attrib
            attribs[common.TAG_CYBOX_MAJOR]  = '2'
            attribs[common.TAG_CYBOX_MINOR]  = '0'
            attribs[common.TAG_CYBOX_UPDATE] = '1'

    def _update_lists(self, root):
        """Replaces CybOX v2.0 list delimiters with CybOX v2.0.1 list
        delimiters.

        CybOX v2.0 allows lists of Object Property values to be defined by
        expressing a ``,`` delimited string. Because ``,`` is reserved, actual
        commas should be recorded as ``<![CDATA[&comma;]]>``.

        CybOX v2.0.1 uses ``##comma##`` as a list delimiter, allowing commas
        to be processed without CybOX Language semantics.

        TODO: Should this check for @apply_condition and only modify field
            values if found?

        """
        props = root.xpath(self.XPATH_OBJECT_PROPS, namespaces=self.NSMAP)

        for prop in props:
            for child in prop.findall(xmlconst.XPATH_RELATIVE_DESCENDANTS):
                if not child.text:
                    continue

                text = child.text
                text = text.replace(",", "##comma##")
                text = text.replace("&comma;", ",")
                child.text = text

    def _get_disallowed(self, root, options=None):
        """There are no untranslatable fields between CybOX 2.0 and
        CybOX v2.0.1..

        """
        pass

    def _get_duplicates(self, root):
        """There is no need to remap non-unique IDs between CybOX 2.0 and
        CybOX 2.0.1 instance documents because CybOX 2.0.1 does not enforce
        ID uniqueness in schema.

        Note:
            This assumes that `root` is schema-valid.

        """
        pass

    def check_update(self, root, options=None):
        """Determines if the input document can be upgraded.

        Args:
            root: The XML document. This can be a filename, a file-like object,
                an instance of ``etree._Element`` or an instance of
                ``etree._ElementTree``.
            options (optional): A ``ramrod.UpdateOptions`` instance. If
                ``None``, ``ramrod.DEFAULT_UPDATE_OPTIONS`` will be used.

        Raises:
            .UnknownVersionError: If the input document does not have a
                version.
            .InvalidVersionError: If the version of the input document
                does not match the `VERSION` class-level attribute value.
            .UpdateError: If the input document contains fields which
                cannot be updated or constructs with non-unique IDs are discovered.

        """
        root = utils.get_etree_root(root)
        options = options or DEFAULT_UPDATE_OPTIONS

        if options.check_versions:
            self._check_version(root)

    def _update(self, root, options):
        self._update_schemalocs(root)
        self._update_versions(root)
        self._update_lists(root)

        if options.update_vocabularies:
            self._update_vocabs(root)

        return root
