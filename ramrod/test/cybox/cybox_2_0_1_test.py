# Copyright (c) 2015, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import unittest
from StringIO import StringIO

import ramrod
import ramrod.cybox
import ramrod.cybox.cybox_2_0_1
import ramrod.utils as utils

from ramrod.test import (_BaseOptional, _BaseTrans, _BaseDisallowed, _BaseVocab)

OBSERVBALE_TEMPLATE = \
"""
<cybox:Observables xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:APIObj="http://cybox.mitre.org/objects#APIObject-2"
    xmlns:AccountObj="http://cybox.mitre.org/objects#AccountObject-2"
    xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
    xmlns:ArtifactObj="http://cybox.mitre.org/objects#ArtifactObject-2"
    xmlns:CodeObj="http://cybox.mitre.org/objects#CodeObject-2"
    xmlns:CustomObj="http://cybox.mitre.org/objects#CustomObject-1"
    xmlns:DNSCacheObj="http://cybox.mitre.org/objects#DNSCacheObject-2"
    xmlns:DNSQueryObj="http://cybox.mitre.org/objects#DNSQueryObject-2"
    xmlns:DNSRecordObj="http://cybox.mitre.org/objects#DNSRecordObject-2"
    xmlns:DeviceObj="http://cybox.mitre.org/objects#DeviceObject-2"
    xmlns:DiskObj="http://cybox.mitre.org/objects#DiskObject-2"
    xmlns:DiskPartitionObj="http://cybox.mitre.org/objects#DiskPartitionObject-2"
    xmlns:EmailMessageObj="http://cybox.mitre.org/objects#EmailMessageObject-2"
    xmlns:FileObj="http://cybox.mitre.org/objects#FileObject-2"
    xmlns:GUIDialogBoxObj="http://cybox.mitre.org/objects#GUIDialogboxObject-2"
    xmlns:GUIObj="http://cybox.mitre.org/objects#GUIObject-2"
    xmlns:GUIWindowObj="http://cybox.mitre.org/objects#GUIWindowObject-2"
    xmlns:HTTPSessionObj="http://cybox.mitre.org/objects#HTTPSessionObject-2"
    xmlns:LibraryObj="http://cybox.mitre.org/objects#LibraryObject-2"
    xmlns:LinkObj="http://cybox.mitre.org/objects#LinkObject-1"
    xmlns:LinuxPackageObj="http://cybox.mitre.org/objects#LinuxPackageObject-2"
    xmlns:MemoryObj="http://cybox.mitre.org/objects#MemoryObject-2"
    xmlns:MutexObj="http://cybox.mitre.org/objects#MutexObject-2"
    xmlns:NetFlowObj="http://cybox.mitre.org/objects#NetworkFlowObject-2"
    xmlns:NetworkConnectionObj="http://cybox.mitre.org/objects#NetworkConnectionObject-2"
    xmlns:NetworkRouteEntryObj="http://cybox.mitre.org/objects#NetworkRouteEntryObject-2"
    xmlns:NetworkRouteObj="http://cybox.mitre.org/objects#NetworkRouteObject-2"
    xmlns:NetworkSocketObj="http://cybox.mitre.org/objects#NetworkSocketObject-2"
    xmlns:NetworkSubnetObj="http://cybox.mitre.org/objects#NetworkSubnetObject-2"
    xmlns:PDFFileObj="http://cybox.mitre.org/objects#PDFFileObject-1"
    xmlns:PacketObj="http://cybox.mitre.org/objects#PacketObject-2"
    xmlns:PipeObj="http://cybox.mitre.org/objects#PipeObject-2"
    xmlns:PortObj="http://cybox.mitre.org/objects#PortObject-2"
    xmlns:ProcessObj="http://cybox.mitre.org/objects#ProcessObject-2"
    xmlns:ProductObj="http://cybox.mitre.org/objects#ProductObject-2"
    xmlns:SemaphoreObj="http://cybox.mitre.org/objects#SemaphoreObject-2"
    xmlns:SocketAddressObj="http://cybox.mitre.org/objects#SocketAddressObject-1"
    xmlns:SystemObj="http://cybox.mitre.org/objects#SystemObject-2"
    xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
    xmlns:UnixFileObj="http://cybox.mitre.org/objects#UnixFileObject-2"
    xmlns:UnixNetworkRouteEntryObj="http://cybox.mitre.org/objects#UnixNetworkRouteEntryObject-2"
    xmlns:UnixPipeObj="http://cybox.mitre.org/objects#UnixPipeObject-2"
    xmlns:UnixProcessObj="http://cybox.mitre.org/objects#UnixProcessObject-2"
    xmlns:UnixUserAccountObj="http://cybox.mitre.org/objects#UnixUserAccountObject-2"
    xmlns:UnixVolumeObj="http://cybox.mitre.org/objects#UnixVolumeObject-2"
    xmlns:UserAccountObj="http://cybox.mitre.org/objects#UserAccountObject-2"
    xmlns:UserSessionObj="http://cybox.mitre.org/objects#UserSessionObject-2"
    xmlns:VolumeObj="http://cybox.mitre.org/objects#VolumeObject-2"
    xmlns:WhoisObj="http://cybox.mitre.org/objects#WhoisObject-2"
    xmlns:WinComputerAccountObj="http://cybox.mitre.org/objects#WinComputerAccountObject-2"
    xmlns:WinCriticalSectionObj="http://cybox.mitre.org/objects#WinCriticalSectionObject-2"
    xmlns:WinDriverObj="http://cybox.mitre.org/objects#WinDriverObject-2"
    xmlns:WinEventLogObj="http://cybox.mitre.org/objects#WinEventLogObject-2"
    xmlns:WinEventObj="http://cybox.mitre.org/objects#WinEventObject-2"
    xmlns:WinExecutableFileObj="http://cybox.mitre.org/objects#WinExecutableFileObject-2"
    xmlns:WinFileObj="http://cybox.mitre.org/objects#WinFileObject-2"
    xmlns:WinHandleObj="http://cybox.mitre.org/objects#WinHandleObject-2"
    xmlns:WinKernelHookObj="http://cybox.mitre.org/objects#WinKernelHookObject-2"
    xmlns:WinKernelObj="http://cybox.mitre.org/objects#WinKernelObject-2"
    xmlns:WinMailslotObj="http://cybox.mitre.org/objects#WinMailslotObject-2"
    xmlns:WinMemoryPageRegionObj="http://cybox.mitre.org/objects#WinMemoryPageRegionObject-2"
    xmlns:WinMutexObj="http://cybox.mitre.org/objects#WinMutexObject-2"
    xmlns:WinNetworkRouteEntryObj="http://cybox.mitre.org/objects#WinNetworkRouteEntryObject-2"
    xmlns:WinNetworkShareObj="http://cybox.mitre.org/objects#WinNetworkShareObject-2"
    xmlns:WinPipeObj="http://cybox.mitre.org/objects#WinPipeObject-2"
    xmlns:WinPrefetchObj="http://cybox.mitre.org/objects#WinPrefetchObject-2"
    xmlns:WinProcessObj="http://cybox.mitre.org/objects#WinProcessObject-2"
    xmlns:WinRegistryKeyObj="http://cybox.mitre.org/objects#WinRegistryKeyObject-2"
    xmlns:WinSemaphoreObj="http://cybox.mitre.org/objects#WinSemaphoreObject-2"
    xmlns:WinServiceObj="http://cybox.mitre.org/objects#WinServiceObject-2"
    xmlns:WinSystemObj="http://cybox.mitre.org/objects#WinSystemObject-2"
    xmlns:WinSystemRestoreObj="http://cybox.mitre.org/objects#WinSystemRestoreObject-2"
    xmlns:WinTaskObj="http://cybox.mitre.org/objects#WinTaskObject-2"
    xmlns:WinThreadObj="http://cybox.mitre.org/objects#WinThreadObject-2"
    xmlns:WinUserAccountObj="http://cybox.mitre.org/objects#WinUserAccountObject-2"
    xmlns:WinVolumeObj="http://cybox.mitre.org/objects#WinVolumeObject-2"
    xmlns:WinWaitableTimerObj="http://cybox.mitre.org/objects#WinWaitableTimerObject-2"
    xmlns:X509CertificateObj="http://cybox.mitre.org/objects#X509CertificateObject-2"
    xmlns:cybox="http://cybox.mitre.org/cybox-2"
    xmlns:cybox-cpe="http://cybox.mitre.org/extensions/platform#CPE2.3-1"
    xmlns:cyboxCommon="http://cybox.mitre.org/common-2"
    xmlns:cyboxVocabs="http://cybox.mitre.org/default_vocabularies-2"
    xmlns:example="http://example.com/"
    cybox_major_version="2" cybox_minor_version="0" cybox_update_version="1">
    %s
</cybox:Observables>
"""

UPDATER_MOD = ramrod.cybox.cybox_2_0_1
UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater

class Cybox_2_0_1_Test(unittest.TestCase):
    XML_VERSIONS = \
    """
     <cybox:Observables
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xmlns:cybox="http://cybox.mitre.org/cybox-2"
        id="example:1" cybox_major_version="2" cybox_minor_version="0" cybox_update_version="1">
    </cybox:Observables>
    """

    @classmethod
    def setUpClass(cls):
        cls._versions = StringIO(cls.XML_VERSIONS)

    def test_get_version(self):
        root = utils.get_etree_root(self._versions)
        version = UPDATER.get_version(root)
        self.assertEqual(version, UPDATER.VERSION)

    def test_update_version(self):
        valid_versions = ramrod.cybox.CYBOX_VERSIONS
        idx = valid_versions.index
        version_to = valid_versions[idx(UPDATER.VERSION)+1:]

        for version in version_to:
            updated = ramrod.update(self._versions, to_=version)
            updated_root = updated.document.as_element()
            updated_version = UPDATER.get_version(updated_root)
            self.assertEqual(version, updated_version)


class OptionalURIFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalURIFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable id="example:foo-1">
        <cybox:Object id="example:foo-1">
            <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                <cyboxCommon:Custom_Properties>
                    <cyboxCommon:Property name="Test" condition="Equals">TEST</cyboxCommon:Property>
                </cyboxCommon:Custom_Properties>
                <URIObj:Value></URIObj:Value>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
     <cybox:Observable id="example:foo-2">
        <cybox:Object id="example:foo-2">
            <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                <cyboxCommon:Custom_Properties>
                    <cyboxCommon:Property name="Test" condition="Equals">TEST</cyboxCommon:Property>
                </cyboxCommon:Custom_Properties>
                <URIObj:Value></URIObj:Value>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)

class OptionalDNSCacheFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalDNSCacheFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test Optional DNS_Entry Removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="DNSCacheObj:DNSCacheObjectType">
                <DNSCacheObj:DNS_Cache_Entry>
                    <DNSCacheObj:DNS_Entry/>
                    <DNSCacheObj:TTL>1</DNSCacheObj:TTL>
                </DNSCacheObj:DNS_Cache_Entry>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Description>Test Optional DNS_Entry Removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="DNSCacheObj:DNSCacheObjectType">
                <DNSCacheObj:DNS_Cache_Entry>
                    <DNSCacheObj:DNS_Entry/>
                    <DNSCacheObj:TTL>1</DNSCacheObj:TTL>
                </DNSCacheObj:DNS_Cache_Entry>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionaFileFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalFileFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test optional Depth element removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:Packer_List>
                    <FileObj:Packer>
                        <FileObj:EP_Jump_Codes>
                            <FileObj:Depth/>
                            <FileObj:Opcodes>Test</FileObj:Opcodes>
                        </FileObj:EP_Jump_Codes>
                    </FileObj:Packer>
                </FileObj:Packer_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Description>Test optional Depth element removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:Packer_List>
                    <FileObj:Packer>
                        <FileObj:EP_Jump_Codes>
                            <FileObj:Depth/>
                            <FileObj:Opcodes>Test</FileObj:Opcodes>
                        </FileObj:EP_Jump_Codes>
                    </FileObj:Packer>
                </FileObj:Packer_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalDNSQueryFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalDNSQueryFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test Optional QName removal. This includes an optional URIObj:Value field removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="DNSQueryObj:DNSQueryObjectType">
                <DNSQueryObj:Question>
                    <DNSQueryObj:QName>
                        <URIObj:Value/>
                    </DNSQueryObj:QName>
                </DNSQueryObj:Question>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Description>Test Optional QName removal. This includes an optional URIObj:Value field removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="DNSQueryObj:DNSQueryObjectType">
                <DNSQueryObj:Question>
                    <DNSQueryObj:QName>
                        <URIObj:Value/>
                    </DNSQueryObj:QName>
                </DNSQueryObj:Question>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalDiskPartitionFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalDiskPartitionFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test Optional Partition_ID Removal</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="DiskPartitionObj:DiskPartitionObjectType">
                <DiskPartitionObj:Partition_ID></DiskPartitionObj:Partition_ID>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Description>Test Optional Partition_ID Removal</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="DiskPartitionObj:DiskPartitionObjectType">
                <DiskPartitionObj:Partition_ID/>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalHTTPSessionFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalHTTPSessionFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Description>Test HTTP Session Object translations</cybox:Description>
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Client_Request>
                        <HTTPSessionObj:HTTP_Message_Body>
                            <HTTPSessionObj:Length>1024</HTTPSessionObj:Length>
                            <!--Message_Body is not optional in CybOX 2.0.1 and will be removed in the update process-->
                            <HTTPSessionObj:Message_Body/>
                        </HTTPSessionObj:HTTP_Message_Body>
                    </HTTPSessionObj:HTTP_Client_Request>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Description>Test HTTP Session Object translations</cybox:Description>
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Client_Request>
                       <HTTPSessionObj:HTTP_Request_Header>
                                <HTTPSessionObj:Parsed_Header>
                                    <HTTPSessionObj:Host>
                                        <!-- Test removal of optional Domain Name. URIObj:Value will be removed too -->
                                        <HTTPSessionObj:Domain_Name>
                                            <URIObj:Value></URIObj:Value>
                                        </HTTPSessionObj:Domain_Name>
                                    </HTTPSessionObj:Host>
                                </HTTPSessionObj:Parsed_Header>
                            </HTTPSessionObj:HTTP_Request_Header>
                    </HTTPSessionObj:HTTP_Client_Request>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalLinuxPackageFieldsTest(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalLinkPackageFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Object>
            <cybox:Properties xsi:type="LinuxPackageObj:LinuxPackageObjectType">
                <LinuxPackageObj:Name/>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable><cybox:Observable>
        <cybox:Object>
            <cybox:Properties xsi:type="LinuxPackageObj:LinuxPackageObjectType">
                <LinuxPackageObj:Name/>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalNetworkPacketFieldsTest(_BaseOptional):
    # TODO: Make this complete. There are a lot of other elements!
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalNetworkPacketFields
    OPTIONAL_COUNT = 4  # Info_Msg x 2, Echo_Request, Echo_Reply
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test removal of optional Network Packet Object fields.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="PacketObj:NetworkPacketObjectType">
                <PacketObj:Internet_Layer>
                    <PacketObj:ICMPv4>
                        <PacketObj:Info_Msg>
                            <PacketObj:Echo_Reply/>
                        </PacketObj:Info_Msg>
                    </PacketObj:ICMPv4>
                </PacketObj:Internet_Layer>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Description>Test removal of optional Network Packet Object fields.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="PacketObj:NetworkPacketObjectType">
                <PacketObj:Internet_Layer>
                    <PacketObj:ICMPv4>
                        <PacketObj:Info_Msg>
                            <PacketObj:Echo_Request/>
                        </PacketObj:Info_Msg>
                    </PacketObj:ICMPv4>
                </PacketObj:Internet_Layer>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalSystemFields(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalSystemFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Tests SystemObj IP_Address removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="SystemObj:SystemObjectType">
                <SystemObj:Network_Interface_List>
                    <SystemObj:Network_Interface>
                        <SystemObj:IP_List>
                            <SystemObj:IP_Info>
                                <SystemObj:IP_Address/>
                                <SystemObj:Subnet_Mask/>
                            </SystemObj:IP_Info>
                        </SystemObj:IP_List>
                    </SystemObj:Network_Interface>
                </SystemObj:Network_Interface_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
     <cybox:Observable>
        <cybox:Description>Tests SystemObj IP_Address removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="SystemObj:SystemObjectType">
                <SystemObj:Network_Interface_List>
                    <SystemObj:Network_Interface>
                        <SystemObj:IP_List>
                            <SystemObj:IP_Info>
                                <SystemObj:IP_Address/>
                                <SystemObj:Subnet_Mask/>
                            </SystemObj:IP_Info>
                        </SystemObj:IP_List>
                    </SystemObj:Network_Interface>
                </SystemObj:Network_Interface_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)

class OptionalWinComputerAccountFields(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalWinComputerAccountFields
    OPTIONAL_COUNT = 6
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test Optional WinComputerAccountObj element removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinComputerAccountObj:WindowsComputerAccountObjectType">
                <WinComputerAccountObj:Kerberos>
                    <WinComputerAccountObj:Delegation>
                        <WinComputerAccountObj:Bitmask/>
                        <WinComputerAccountObj:Service/>
                    </WinComputerAccountObj:Delegation>
                    <WinComputerAccountObj:Ticket>1</WinComputerAccountObj:Ticket>
                </WinComputerAccountObj:Kerberos>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
        <cybox:Observable>
        <cybox:Description>Test Optional WinComputerAccountObj element removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinComputerAccountObj:WindowsComputerAccountObjectType">
                <WinComputerAccountObj:Kerberos>
                    <WinComputerAccountObj:Delegation>
                        <WinComputerAccountObj:Bitmask/>
                        <WinComputerAccountObj:Service/>
                    </WinComputerAccountObj:Delegation>
                    <WinComputerAccountObj:Ticket>1</WinComputerAccountObj:Ticket>
                </WinComputerAccountObj:Kerberos>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)

class OptionalWinFileFields(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalWinFileFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
     <cybox:Observable>
        <cybox:Description>Test WinFileObject Size_In_Bytes element removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinFileObj:WindowsFileObjectType">
                <WinFileObj:Security_ID>TEST</WinFileObj:Security_ID>
                <WinFileObj:Stream_List>
                    <WinFileObj:Stream>
                        <cyboxCommon:Hash/>
                        <WinFileObj:Name>Test</WinFileObj:Name>
                        <WinFileObj:Size_In_Bytes/>
                    </WinFileObj:Stream>
                </WinFileObj:Stream_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
     <cybox:Observable>
        <cybox:Description>Test WinFileObject Size_In_Bytes element removal.</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinFileObj:WindowsFileObjectType">
                <WinFileObj:Security_ID>TEST</WinFileObj:Security_ID>
                <WinFileObj:Stream_List>
                    <WinFileObj:Stream>
                        <cyboxCommon:Hash/>
                        <WinFileObj:Name>Test</WinFileObj:Name>
                        <WinFileObj:Size_In_Bytes/>
                    </WinFileObj:Stream>
                </WinFileObj:Stream_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)

class OptionalWinNetworkShareFields(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalWinNetworkShareFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test optional WinNetworkShareObj Netname element removal</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinNetworkShareObj:WindowsNetworkShareObjectType">
                <WinNetworkShareObj:Current_Uses>0</WinNetworkShareObj:Current_Uses>
                <WinNetworkShareObj:Netname/>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Description>Test optional WinNetworkShareObj Netname element removal</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinNetworkShareObj:WindowsNetworkShareObjectType">
                <WinNetworkShareObj:Current_Uses>0</WinNetworkShareObj:Current_Uses>
                <WinNetworkShareObj:Netname/>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class OptionalWinPrefetchFields(_BaseOptional):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    OPTIONAL_KLASS = UPDATER_MOD.OptionalWinPrefetchFields
    OPTIONAL_COUNT = 2
    OBSERVABLES = \
    """
    <cybox:Observable>
        <cybox:Description>Test optional WinPrefetchObj element removal</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="WinPrefetchObj:WindowsPrefetchObjectType">
                <WinPrefetchObj:Application_File_Name>Test</WinPrefetchObj:Application_File_Name>
                <WinPrefetchObj:Volume>
                    <WinPrefetchObj:VolumeItem/>
                    <WinPrefetchObj:VolumeItem>
                        <VolumeObj:Name>Not Empty</VolumeObj:Name>
                    </WinPrefetchObj:VolumeItem>
                    <WinPrefetchObj:DeviceItem/>
                    <WinPrefetchObj:DeviceItem>
                        <DeviceObj:Description>Not Empty</DeviceObj:Description>
                    </WinPrefetchObj:DeviceItem>
                </WinPrefetchObj:Volume>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML_OPTIONALS = OBSERVBALE_TEMPLATE % (OBSERVABLES)


class TransHTTPSessionDNT(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransHTTPSessionDNT
    TRANS_XPATH = ".//HTTPSessionObj:DNT"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Client_Request>
                        <HTTPSessionObj:HTTP_Request_Header>
                            <HTTPSessionObj:Parsed_Header>
                                <HTTPSessionObj:DNT>
                                    <URIObj:Value>%s</URIObj:Value>
                                </HTTPSessionObj:DNT>
                            </HTTPSessionObj:Parsed_Header>
                        </HTTPSessionObj:HTTP_Request_Header>
                    </HTTPSessionObj:HTTP_Client_Request>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)

    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)


class TransHTTPSessionVary(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransHTTPSessionVary
    TRANS_XPATH = ".//HTTPSessionObj:Vary"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Server_Response>
                        <HTTPSessionObj:HTTP_Response_Header>
                            <HTTPSessionObj:Parsed_Header>
                                <HTTPSessionObj:Vary>
                                    <URIObj:Value>%s</URIObj:Value>
                                </HTTPSessionObj:Vary>
                            </HTTPSessionObj:Parsed_Header>
                        </HTTPSessionObj:HTTP_Response_Header>
                    </HTTPSessionObj:HTTP_Server_Response>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)

    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)


class TransHTTPSessionXRequestedFor(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransHTTPSessionXRequestedFor
    TRANS_XPATH = ".//HTTPSessionObj:X_Forwarded_For"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Server_Response>
                        <HTTPSessionObj:HTTP_Response_Header>
                            <HTTPSessionObj:Parsed_Header>
                               <HTTPSessionObj:X_Requested_For>%s</HTTPSessionObj:X_Requested_For>
                            </HTTPSessionObj:Parsed_Header>
                        </HTTPSessionObj:HTTP_Response_Header>
                    </HTTPSessionObj:HTTP_Server_Response>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)

    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)


class TransHTTPSessionRefresh(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransHTTPSessionRefresh
    TRANS_XPATH = ".//HTTPSessionObj:Refresh"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Server_Response>
                        <HTTPSessionObj:HTTP_Response_Header>
                            <HTTPSessionObj:Parsed_Header>
                                <HTTPSessionObj:Refresh datatype="int">%s</HTTPSessionObj:Refresh>
                            </HTTPSessionObj:Parsed_Header>
                        </HTTPSessionObj:HTTP_Response_Header>
                    </HTTPSessionObj:HTTP_Server_Response>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)

    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)

    def test_attrib_value(self):
        root = utils.get_etree_root(self.xml)
        self.TRANS_KLASS.translate(root)

        updated_nodes = root.xpath(self.TRANS_XPATH,
                                namespaces=self.UPDATER.NSMAP)

        for node in updated_nodes:
            self.assertEqual(node.attrib['datatype'], 'string')


class TransNetPacketProtoAddrSize(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransNetPacketProtoAddrSize
    TRANS_XPATH = ".//HTTPSessionObj:Proto_Addr_Size"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable>
        <cybox:Description>Test Network Packet Object translations</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="PacketObj:NetworkPacketObjectType">
                <PacketObj:Link_Layer>
                    <PacketObj:Logical_Protocols>
                        <PacketObj:ARP_RARP>
                            <PacketObj:Protol_Addr_Size>%s</PacketObj:Protol_Addr_Size>
                        </PacketObj:ARP_RARP>
                    </PacketObj:Logical_Protocols>
                </PacketObj:Link_Layer>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)
    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)


class TransNetPacketEncapsulatingSecurityPayload(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransNetPacketEncapsulatingSecurityPayload
    TRANS_XPATH = ".//PacketObj:Encapsulating_Security_Payload"
    TRANS_VALUE = None
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable>
        <cybox:Description>Test Network Packet Object translations</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="PacketObj:NetworkPacketObjectType">
                <PacketObj:Internet_Layer>
                    <PacketObj:IPv6>
                        <PacketObj:Ext_Headers>
                            <!-- This should get renamed to Encapsulating_Security_Payload -->
                            <PacketObj:Excapsulating_Security_Payload>
                                <PacketObj:Sequence_Number>1</PacketObj:Sequence_Number>
                            </PacketObj:Excapsulating_Security_Payload>
                        </PacketObj:Ext_Headers>
                    </PacketObj:IPv6>
                </PacketObj:Internet_Layer>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)



class TransNetPacketAuthenticationData(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransNetPacketAuthenticationData
    TRANS_XPATH = ".//PacketObj:Authentication_Data"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable>
        <cybox:Description>Test Network Packet Object translations</cybox:Description>
        <cybox:Object>
            <cybox:Properties xsi:type="PacketObj:NetworkPacketObjectType">
                <PacketObj:Internet_Layer>
                    <PacketObj:IPv6>
                        <PacketObj:Ext_Headers>
                            <!-- This should get renamed to Encapsulating_Security_Payload -->
                            <PacketObj:Excapsulating_Security_Payload>
                                <PacketObj:Sequence_Number>1</PacketObj:Sequence_Number>
                                <!-- This should get renamed to Authentication_Data -->
                                <PacketObj:Authenication_Data>%s</PacketObj:Authenication_Data>
                            </PacketObj:Excapsulating_Security_Payload>
                        </PacketObj:Ext_Headers>
                    </PacketObj:IPv6>
                </PacketObj:Internet_Layer>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)
    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)


class TransWinMailslotHandle(_BaseTrans):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    TRANS_KLASS = UPDATER_MOD.TransWinMailslotHandle
    TRANS_XPATH = ".//WinMailslotObj:Handle/WinMailslotObj:Name"
    TRANS_VALUE = _BaseTrans.TRANS_VALUE
    TRANS_COUNT = 1
    TRANS_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b8">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d0">
            <cybox:Properties xsi:type="WinMailslotObj:WindowsMailslotObjectType">
                <WinMailslotObj:Handle>
                    <WinHandleObj:Handle>
                        <WinHandleObj:Name>%s</WinHandleObj:Name>
                    </WinHandleObj:Handle>
                </WinMailslotObj:Handle>
                <WinMailslotObj:Name>TEST NAME</WinMailslotObj:Name>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """ % (TRANS_VALUE)
    XML = OBSERVBALE_TEMPLATE % (TRANS_XML)


class DisallowedTaskTriggerType(_BaseDisallowed):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedTaskTriggerType
    DISALLOWED_COUNT = 2
    DISALLOWED_XML = \
    """
    <cybox:Observable>
        <cybox:Object>
            <cybox:Properties xsi:type="WinTaskObj:WindowsTaskObjectType">
                <WinTaskObj:Trigger_List>
                    <WinTaskObj:Trigger>
                        <WinTaskObj:Trigger_Type/>
                    </WinTaskObj:Trigger>
                </WinTaskObj:Trigger_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    <cybox:Observable>
        <cybox:Object>
            <cybox:Properties xsi:type="WinTaskObj:WindowsTaskObjectType">
                <WinTaskObj:Trigger_List>
                    <WinTaskObj:Trigger>
                        <WinTaskObj:Trigger_Type/>
                    </WinTaskObj:Trigger>
                </WinTaskObj:Trigger_List>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (DISALLOWED_XML)


class DisallowedWinExecutableFile(_BaseDisallowed):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedWinExecutableFile
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <cybox:Observable>
        <cybox:Object>
            <cybox:Properties xsi:type="WinExecutableFileObj:WindowsExecutableFileObjectType">
                <FileObj:File_Name>Hax.exe</FileObj:File_Name>
                <WinExecutableFileObj:Sections>
                    <WinExecutableFileObj:Section>
                        <WinExecutableFileObj:Entropy>
                            <WinExecutableFileObj:Value>1.0</WinExecutableFileObj:Value>
                        </WinExecutableFileObj:Entropy>
                        <WinExecutableFileObj:Type>THIS REQUIRES FORCED UPDATES</WinExecutableFileObj:Type>
                    </WinExecutableFileObj:Section>
                </WinExecutableFileObj:Sections>
                <WinExecutableFileObj:Type>Invalid</WinExecutableFileObj:Type>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (DISALLOWED_XML)


class DisallowedHTTPSession(_BaseDisallowed):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedHTTPSession
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b9">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d3">
            <cybox:Properties xsi:type="HTTPSessionObj:HTTPSessionObjectType">
                <HTTPSessionObj:HTTP_Request_Response>
                    <HTTPSessionObj:HTTP_Server_Response>
                        <HTTPSessionObj:HTTP_Response_Header>
                            <HTTPSessionObj:Parsed_Header>
                                <HTTPSessionObj:X_Forwarded_Proto/>
                            </HTTPSessionObj:Parsed_Header>
                        </HTTPSessionObj:HTTP_Response_Header>
                    </HTTPSessionObj:HTTP_Server_Response>
                </HTTPSessionObj:HTTP_Request_Response>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (DISALLOWED_XML)


class DisallowedWinMailslot(_BaseDisallowed):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    DISALLOWED_KLASS = UPDATER_MOD.DisallowedWindowsMailslotHandle
    DISALLOWED_COUNT = 1
    DISALLOWED_XML = \
    """
    <cybox:Observable id="example:Observable-1c9af310-0d5a-4c44-bdd7-aea3d99f13b8">
        <cybox:Object id="example:Object-26be6630-b2df-4bf9-8750-3f45ca9e19d0">
            <cybox:Properties xsi:type="WinMailslotObj:WindowsMailslotObjectType">
                <WinMailslotObj:Handle>
                    <WinHandleObj:Handle>
                        <WinHandleObj:Name>Test</WinHandleObj:Name>
                    </WinHandleObj:Handle>
                    <WinHandleObj:Handle>
                        <WinHandleObj:Name>Test</WinHandleObj:Name>
                    </WinHandleObj:Handle>
                </WinMailslotObj:Handle>
                <WinMailslotObj:Name>TEST NAME</WinMailslotObj:Name>
            </cybox:Properties>
        </cybox:Object>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (DISALLOWED_XML)


class ObjectRelationshipVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    VOCAB_KLASS = UPDATER_MOD.ObjectRelationshipVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <cybox:Observable>
        <cybox:Object>
            <cybox:Related_Objects>
                <cybox:Related_Object>
                    <cybox:Relationship xsi:type="cyboxVocabs:ObjectRelationshipVocab-1.0">Allocated</cybox:Relationship>
                </cybox:Related_Object>
            </cybox:Related_Objects>
        </cybox:Object>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (VOCAB_XML)


class ToolTypeVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    VOCAB_KLASS = UPDATER_MOD.ToolTypeVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <cybox:Observable>
        <cybox:Observable_Source>
            <cyboxCommon:Tool_Type xsi:type="cyboxVocabs:ToolTypeVocab-1.0">A/V</cyboxCommon:Tool_Type>
        </cybox:Observable_Source>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (VOCAB_XML)


class ActionNameVocab(_BaseVocab):
    UPDATER = UPDATER_MOD.Cybox_2_0_1_Updater
    VOCAB_KLASS = UPDATER_MOD.ActionNameVocab
    VOCAB_COUNT = 1
    VOCAB_XML = \
    """
    <cybox:Observable>
        <cybox:Event>
            <cybox:Actions>
                <cybox:Action>
                    <cybox:Name xsi:type="cyboxVocabs:ActionNameVocab-1.0">Accept Socket Connection</cybox:Name>
                </cybox:Action>
            </cybox:Actions>
        </cybox:Event>
    </cybox:Observable>
    """
    XML = OBSERVBALE_TEMPLATE % (VOCAB_XML)

if __name__ == "__main__":
    unittest.main()
