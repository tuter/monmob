#/usr/bin/env python

# Copyright (c) 2012, Andres Blanco and Matias Eissler
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. All advertising materials mentioning features or use of this software
#    must display the following acknowledgement:
#    This product includes software developed by the authors.
# 4. Neither the name of the authors nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import struct
import helpers

DOT11_FRAME_CONTROL_SIZE = 2

DOT11_MANAGEMENT_FRAME_FIELDS_SIZE = 24
DOT11_DATA_FRAME_FIELDS_SIZE = 24
DOT11_PROBE_REQUEST_FRAME_FIELDS_SIZE = 24
DOT11_BEACON_FRAME_FIELDS_SIZE = 36

FCS_SIZE = 4

IE_SSID = "SSID"
IE_SUPPORTED_RATES = "Supported Rates"
IE_DS_PARAMETER_SET = "DS Parameter Set"
IE_RSN = "RSN"
IE_WPA = "WPA"
IE_EXTENDED_SUPPORTED_RATES = "Extended Supported Rates"
IE_VENDOR_SPECIFIC = "Vendor Specific"

# OUI
OUI_SIZE = 3
OUI_RSN = '\x00\x0F\xAC'
OUI_MS = '\x00\x50\xF2'

# Frame Control Capabilities
CAP_ESS = int('0000000000000001', 2)
CAP_IBSS = int('0000000000000010', 2)
CAP_CF_POLL = int('0000000000000100', 2)
CAP_CF_POLL_REQ = int('0000000000001000', 2)
CAP_PRIVACY = int('0000000000010000', 2)
CAP_SHORT_PREAMBLE = int('0000000000100000', 2)
CAP_PBCC = int('0000000001000000', 2)
CAP_CH_AGILITY = int('0000000010000000', 2)
CAP_SHORT_SLOT_TIME = int('0000010000000000', 2)
CAP_DSSS_OFDM = int('0010000000000000', 2)

TYPE_MANAGEMENT = 0
TYPE_CONTROL = 1
TYPE_DATA = 2

SUBTYPE_MANAGEMENT_ASSOCIATION_REQ = 0
SUBTYPE_MANAGEMENT_ASSOCIATION_RES = 1
SUBTYPE_MANAGEMENT_REASSOCIATION_REQ = 2
SUBTYPE_MANAGEMENT_REASSOCIATION_RES = 3
SUBTYPE_MANAGEMENT_PROBE_REQ = 4
SUBTYPE_MANAGEMENT_PROBE_RES = 5
SUBTYPE_MANAGEMENT_BEACON = 8
SUBTYPE_MANAGEMENT_ATIM = 9
SUBTYPE_MANAGEMENT_DISASSOCIATION = 10
SUBTYPE_MANAGEMENT_AUTHENTICATION = 11
SUBTYPE_MANAGEMENT_DEAUTHENTICATION = 12
SUBTYPE_MANAGEMENT_ACTION = 13


frame_type = {0: "Management",
              1: "Control",
              2: "Data"}

management_subtype = {0: "Association Request",
                      1: "Association Response",
                      2: "Reassociation Request",
                      3: "Reassociation Response",
                      4: "Probe Request",
                      5: "Probe Response",
                      8: "Beacon",
                      9: "Announcement Traffic Indication Message",
                     10: "Disassociation",
                     11: "Authentication",
                     12: "Deauthentication",
                     13: "Action"}

control_subtype = {8: "Block Acknowledgment Request",
                   9: "Block Acknowledgment",
                  10: "Power Save-Poll",
                  11: "RTS",
                  12: "CTS",
                  13: "ACK",
                  14: "Contention-Free-End",
                  15: "CF-End+CF-ACK"}

data_subtype = {0: "Data",
                1: "Data+CF-ACK",
                2: "Data+CF-Poll",
                3: "Data+CF-ACK+CF-Poll",
                4: "Null Data",
                5: "CF-ACK",
                6: "CF-Poll",
                7: "CF-ACK+CF-Poll",
                8: "QoS Data",
                9: "QoS Data + CF-ACK",
               10: "QoS Data + CF-Poll",
               11: "QoS Data + CF-ACK + CF-Poll",
               12: "QoS Null Data",
               13: "QoS CF-ACK",
               14: "QoS CF-Poll",
               15: "QoS CF-ACK + CF-Poll"}

frame_control_flags = {"ToDS": 1,
                       "FromDS": 2,
                       "MoreFrag": 4,
                       "Retry": 8,
                       "PowerManagement": 16,
                       "More Data": 32,
                       "Protected": 64,
                       "Order": 128}

information_elements_id = {0x00: IE_SSID,
                           0x01: IE_SUPPORTED_RATES,
                           0x03: IE_DS_PARAMETER_SET,
                           0x30: IE_RSN,
                           0x32: IE_EXTENDED_SUPPORTED_RATES,
                           0xdd: IE_VENDOR_SPECIFIC}

rsn_cipher_suite_id = {0: "Same as Group Cipher Suite",
                       1: "WEP-40",
                       2: "TKIP",
                       4: "CCMP",
                       5: "WEP-104"}

rsn_authentication_suite_id = {1: "PMK", 2: "PSK"}


class InvalidInformationElement(Exception):
    pass


class FrameControl(object):
    def __init__(self, data):
        if len(data) < DOT11_FRAME_CONTROL_SIZE:
            raise IndexError("Frame to short")
        self._frameControl = data[:DOT11_FRAME_CONTROL_SIZE]
        self._protocol = 0
        self._type = 0
        self._subtype = 0
        self._toDs = False
        self._fromDs = False
        self._moreFrag = False
        self._retry = False
        self._powerManagement = False
        self._moreData = False
        self._protectedFrame = False
        self._order = False
        self._processFrame()

    def _processFlags(self, flags):
        '''Process Frame Control Flags.'''
        if (flags & frame_control_flags["ToDS"]) > 0:
            self._toDs = True
        if (flags & frame_control_flags["FromDS"]) > 0:
            self._fromDs = True
        if (flags & frame_control_flags["MoreFrag"]) > 0:
            self._moreFrag = True
        if (flags & frame_control_flags["Retry"]) > 0:
            self._retry = True
        if (flags & frame_control_flags["PowerManagement"]) > 0:
            self._powerManagement = True
        if (flags & frame_control_flags["More Data"]) > 0:
            self._moreData = True
        if (flags & frame_control_flags["Protected"]) > 0:
            self._protectedFrame = True
        if (flags & frame_control_flags["Order"]) > 0:
            self._order = True

    def _processFrame(self):
        '''Process Frame Control.'''
        frameControl = struct.unpack("H", self._frameControl)[0]
        self._protocol = frameControl & 0x0003
        self._type = (frameControl & 0x000C) >> 2
        self._subtype = (frameControl & 0x00F0) >> 4
        flags = (frameControl & 0xFF00) >> 8
        self._processFlags(flags)

    def getProtocol(self):
        '''Return frame control protocol.'''
        return self._protocol

    def getType(self):
        '''Return frame control type.'''
        return self._type

    def getSubtype(self):
        '''Return frame control subtype.'''
        return self._subtype

    def getToDs(self):
        '''Return frame control to DS.'''
        return self._toDs

    def getFromDs(self):
        '''Return frame control from DS.'''
        return self._fromDs

    def getMoreFrag(self):
        '''Return frame control more frag.'''
        return self._moreFrag

    def getRetry(self):
        '''Return frame control retry.'''
        return self._retry

    def getPowerManagement(self):
        '''Return frame control power management flag.'''
        return self._powerManagement

    def getMoreData(self):
        '''Return frame control more data flag.'''
        return self._moreData

    def getProtectedFrame(self):
        '''Return frame control protected flag.'''
        return self._protectedFrame

    def getOrder(self):
        '''Return frame control order flag.'''
        return self._order


class ManagementFrame(object):
    def __init__(self, data):
        self._frame_size = len(data)
        # Essential fields on the data frame
        # Field ----------- Size
        # frame control --- 2 B
        # duration -------- 2 B
        # destination ----- 6 B
        # source ---------- 6 B
        # bssid ----------- 6 B
        # sequence ctrl --- 2 B
        if self._frame_size < DOT11_DATA_FRAME_FIELDS_SIZE:
            raise IndexError("Frame to short.")
        index = 0

        self._fc = FrameControl(data)
        index += 2

        self._duration = data[index:index + 2]
        index += 2

        # Addresses
        self._destination = helpers.bytes_to_mac_address(data[index:index + 6])
        index += 6
        self._source = helpers.bytes_to_mac_address(data[index:index + 6])
        index += 6
        self._bssid = helpers.bytes_to_mac_address(data[index:index + 6])
        index += 6

        seqctrl = struct.unpack("H", data[index:index + 2])[0]
        self._fragment = (seqctrl & 0x000F)
        self._sequence = (seqctrl & 0xFFF0) >> 4

    def getBssid(self):
        '''Return the bssid of the data frame.'''
        return self._bssid

    def getSourceAddress(self):
        '''Return the source address of the data frame.'''
        return self._source

    def getDestinationAddress(self):
        '''Return the destination address of the data frame.'''
        return self._destination


class DataFrame(object):
    def __init__(self, data):
        self._frame_size = len(data)
        # Essential fields on the data frame
        # Field ----------- Size
        # frame control --- 2 B
        # duration -------- 2 B
        # address1 -------- 6 B
        # address2 -------- 6 B
        # address3 -------- 6 B
        # sequence ctrl --- 2 B
        # address4 -------- 6 B (optional)
        if self._frame_size < DOT11_DATA_FRAME_FIELDS_SIZE:
            raise IndexError("Frame to short.")
        index = 0

        self._fc = FrameControl(data)
        index += 2

        self._duration = data[index:index + 2]
        index += 2

        self._ibss = False
        self._infrastructure = False
        self._wds = False

        # Addresses
        self._address1 = helpers.bytes_to_mac_address(data[index:index + 6])
        index += 6
        self._address2 = helpers.bytes_to_mac_address(data[index:index + 6])
        index += 6
        self._address3 = helpers.bytes_to_mac_address(data[index:index + 6])
        index += 6

        to_ds = self._fc.getToDs()
        from_ds = self._fc.getFromDs()

        # IBSS
        if not to_ds and not from_ds:
            self._ibss = True
            self._destination = self._address1
            self._source = self._address2
            self._bssid = self._address3

        # Infrastructure
        if (to_ds and not from_ds) or (not to_ds and from_ds):
            self._infrastructure = True
            if (to_ds and not from_ds):
                self._bssid = self._address1
                self._source = self._address2
                self._destination = self._address3
            else:
                self._destination = self._address1
                self._bssid = self._address2
                self._source = self._address3

        # WDS
        if to_ds and from_ds:
            self._address4 = helpers.bytes_to_mac_address(data[index:index + 6])
            index += 6
            self._wds = True
            self._bssid = self._address1
            self._destination = self._address3
            self._source = self._address4

        seqctrl = struct.unpack("H", data[index:index + 2])[0]
        self._fragment = (seqctrl & 0x000F)
        self._sequence = (seqctrl & 0xFFF0) >> 4

    def isIbss(self):
        '''Returns True if frame is from a IBSS network.'''
        return self._ibss

    def isInfrastructure(self):
        '''Returns True if frame is from a Infrastructure network.'''
        return self._infrastructure

    def isWds(self):
        '''Returns True if frame is from a WDS network.'''
        return self._wds

    def getBssid(self):
        '''Return the bssid of the data frame.'''
        return self._bssid

    def getSourceAddress(self):
        '''Return the source address of the data frame.'''
        return self._source

    def getDestinationAddress(self):
        '''Return the destination address of the data frame.'''
        return self._destination


class ProbeRequest(object):
    def __init__(self, data):
        self._frame_size = len(data)
        # Essential fields on the beacon frame
        # Field ----------- Size
        # frame control --- 2 B
        # duration -------- 2 B
        # destination ----- 6 B
        # source ---------- 6 B
        # bssid ----------- 6 B
        # sequence ctrl --- 2 B
        if self._frame_size < DOT11_PROBE_REQUEST_FRAME_FIELDS_SIZE:
            raise IndexError("Frame to short.")
        self._management_frame = ManagementFrame(data)
        self._raw_ies = {}
        self._ies = {}
        self._process(data)

    def _process(self, data):
        '''Process Probe Request frame fields.'''
        self._frameControl = FrameControl(data[:2])
        if self._frameControl.getType() != TYPE_MANAGEMENT:
            raise Exception("Invalid Frame Type.")
        if self._frameControl.getSubtype() != SUBTYPE_MANAGEMENT_PROBE_REQ:
            raise Exception("Invalid Frame Subtype.")
        self._duration = struct.unpack("H", data[2:4])[0]
        self._destination = helpers.bytes_to_mac_address(data[4:10])
        self._source = helpers.bytes_to_mac_address(data[10:16])
        self._bssid = helpers.bytes_to_mac_address(data[16:22])
        # Process sequence control field
        seqctrl = struct.unpack("H", data[22:24])[0]
        self._fragment = (seqctrl & 0x000F)
        self._sequence = (seqctrl & 0xFFF0) >> 4
        if self._frame_size > DOT11_PROBE_REQUEST_FRAME_FIELDS_SIZE + FCS_SIZE:
            # To get the offset of the information elements we need to go
            # to the end offset of the essential fields of the beacon frame
            # up to the end of the frame substracting the 4 bytes of the FCS.
            ie_data = data[DOT11_BEACON_FRAME_FIELDS_SIZE:-4]
            self._processInformationElements(ie_data)

    def _processInformationElements(self, data):
        '''Process Information Elements.'''
        index = 0
        # ie header -> 2 bytes
        # ie id -> 1 byte
        # ie len -> 1 byte
        ie_header_size = 2
        data_length = len(data)
        while(data_length):
            if data_length < ie_header_size:
                break
            ie_id = struct.unpack("B", data[index])[0]
            ie_len = struct.unpack("B", data[index + 1])[0]
            if (data_length - ie_header_size) < ie_len:
                break
            begin = index + ie_header_size
            end = begin + ie_len
            ie_data = data[begin:end]
            self._raw_ies[ie_id] = ie_data
            ie_item = InformationElementHelper(ie_id, ie_data)
            self._ies[ie_item.getName()] = ie_item.getData()
            data_length -= (ie_len + ie_header_size)
            index += (ie_len + ie_header_size)

    def getSource(self):
        '''Returns Probe Request Source field.'''
        return self._management_frame.getSourceAddress()


class ProbeResponse(object):
    def __init__(self):
        pass


class Beacon(object):
    def __init__(self, data):
        self._frame_size = len(data)
        # Essential fields on the beacon frame
        # Field ----------- Size
        # frame control --- 2 B
        # duration -------- 2 B
        # destination ----- 6 B
        # source ---------- 6 B
        # bssid ----------- 6 B
        # sequence ctrl --- 2 B
        # timestamp ------- 8 B
        # beacon interval - 2 B
        # capabilities ---- 2 B
        if self._frame_size < DOT11_BEACON_FRAME_FIELDS_SIZE:
            raise IndexError("Frame to short.")
        self._duration = 0
        self._destination = ""
        self._source = ""
        self._bssid = ""
        self._fragment = 0
        self._sequence = 0
        self._timestamp = 0
        self._interval = 0
        self._capabilities = 0
        self._raw_ies = {}
        self._ies = {}
        self._process(data)

    def _process(self, data):
        '''Process Beacon frame fields.'''
        self._frameControl = FrameControl(data[:2])
        if self._frameControl.getType() != TYPE_MANAGEMENT:
            raise Exception("Invalid Frame Type.")
        if self._frameControl.getSubtype() != SUBTYPE_MANAGEMENT_BEACON:
            raise Exception("Invalid Frame Subtype.")
        self._duration = struct.unpack("H", data[2:4])[0]
        self._destination = helpers.bytes_to_mac_address(data[4:10])
        self._source = helpers.bytes_to_mac_address(data[10:16])
        self._bssid = helpers.bytes_to_mac_address(data[16:22])
        # Process sequence control field
        seqctrl = struct.unpack("H", data[22:24])[0]
        self._fragment = (seqctrl & 0x000F)
        self._sequence = (seqctrl & 0xFFF0) >> 4
        self._timestamp = struct.unpack("Q", data[24:32])[0]
        self._interval = struct.unpack("H", data[32:34])[0]
        self._capabilities = struct.unpack("H", data[34:36])[0]
        if self._frame_size > DOT11_BEACON_FRAME_FIELDS_SIZE + FCS_SIZE:
            # To get the offset of the information elements we need to go
            # to the end offset of the essential fields of the beacon frame
            # up to the end of the frame substracting the 4 bytes of the FCS.
            ie_data = data[DOT11_BEACON_FRAME_FIELDS_SIZE:-4]
            self._processInformationElements(ie_data)

    def _processInformationElements(self, data):
        '''Process Information Elements.'''
        index = 0
        # ie header -> 2 bytes
        # ie id -> 1 byte
        # ie len -> 1 byte
        ie_header_size = 2
        data_length = len(data)
        while(data_length):
            if data_length < ie_header_size:
                break
            ie_id = struct.unpack("B", data[index])[0]
            ie_len = struct.unpack("B", data[index + 1])[0]
            if (data_length - ie_header_size) < ie_len:
                break
            begin = index + ie_header_size
            end = begin + ie_len
            ie_data = data[begin:end]
            self._raw_ies[ie_id] = ie_data
            ie_item = InformationElementHelper(ie_id, ie_data)
            self._ies[ie_item.getName()] = ie_item.getData()
            data_length -= (ie_len + ie_header_size)
            index += (ie_len + ie_header_size)

    def getDuration(self):
        '''Returns Beacon Duration field.'''
        return self._duration

    def getDestination(self):
        '''Returns Beacon Destination field.'''
        return self._destination

    def getSource(self):
        '''Returns Beacon Source field.'''
        return self._source

    def getBssid(self):
        '''Returns Beacon BSSID field.'''
        return self._bssid

    def getFragment(self):
        '''Returns Beacon fragment field.'''
        return self._fragment

    def getSequence(self):
        '''Returns Beacon sequence field.'''
        return self._sequence

    def getTimestamp(self):
        '''Returns Beacon timestamp field.'''
        return self._timestamp

    def getInterval(self):
        '''Returns Beacon interval field.'''
        return self._interval

    def getCapabilities(self):
        '''Returns Beacon capabilities field.'''
        return self._capabilities

    def getRawInformationElements(self):
        '''Returns dictionary with Beacon information elements.'''
        return self._raw_ies

    def getInformationElements(self):
        '''Returns dictionary with Beacon information elements.'''
        return self._ies


class InformationElementHelper(object):
    def __init__(self, ie_id, ie_data):
        self._ie_id = ie_id
        self._ie_data = ie_data
        self._name = ''
        self._data = ie_data
        self._process()

    def _process_ssid(self, data):
        '''Process SSID information element data.'''
        return data

    def _process_supported_rates(self, data):
        '''Process Supported Rates information element data.'''
        result = []
        for rate in data:
            rate = (ord(rate) & 0x7F) / 2
            result.append("%d" % rate)
        return ', '.join(result)

    def _process_ds_parameter_set(self, data):
        '''Process DS parameter set information element data.'''
        data_length = len(data)
        if data_length != 1:
            raise InvalidInformationElement
        return ord(data[0])

    def _process_rsn_wpa(self, data, rsn=True):
        '''Process RSN or WPA information element data.'''
        i = 0
        result = {}
        data_length = len(data)
        # type - WPA or WPA2 (RSN)
        if rsn:
            result['type'] = "WPA2"
        else:
            result['type'] = "WPA"
        # version - 2 bytes
        if data_length < 2:
            raise InvalidInformationElement
        version = struct.unpack('H', data[i:i + 2])[0]
        result['version'] = version
        i += 2
        # multicast cipher suite - 4 bytes
        if data_length - i < 4:
            raise InvalidInformationElement
        multicast_ptr = data[i:i + OUI_SIZE]
        if (multicast_ptr != OUI_RSN) and (multicast_ptr != OUI_MS):
            raise InvalidInformationElement
        i += OUI_SIZE
        result['multicast'] = rsn_cipher_suite_id[ord(data[i])]
        i += 1
        # unicast cipher suite count - 2 bytes
        if data_length - i < 2:
            raise InvalidInformationElement
        unicast_cipher_suite_count = struct.unpack('H', data[i:i + 2])[0]
        i += 2
        if unicast_cipher_suite_count * 4 > data_length - i:
            raise InvalidInformationElement
        # unicast cipher suite - 4 bytes
        unicast_cipher_suite_list = []
        for cipher_suite in range(unicast_cipher_suite_count):
            if data_length - i < OUI_SIZE + 1:
                raise InvalidInformationElement
            unicast_suite = data[i:i + OUI_SIZE]
            if (unicast_suite != OUI_RSN) and (unicast_suite != OUI_MS):
                continue
            i += OUI_SIZE
            unicast_cipher_suite_list.append(rsn_cipher_suite_id[ord(data[i])])
            i += 1
        result['unicast cipher suites'] = unicast_cipher_suite_list
        # authentication suite count - 2 bytes
        if data_length - i < 2:
            raise InvalidInformationElement
        auth_suite_count = struct.unpack('H', data[i:i + 2])[0]
        i += 2
        if auth_suite_count * 4 > data_length - i:
            raise InvalidInformationElement
        # unicast cipher suite - 4 bytes * unicast cipher suite count
        auth_suite_list = []
        for auth_suite in range(auth_suite_count):
            if data_length - i < OUI_SIZE + 1:
                raise InvalidInformationElement
            auth_suite = data[i:i + OUI_SIZE]
            if (auth_suite != OUI_RSN) and (auth_suite != OUI_MS):
                continue
            i += OUI_SIZE
            auth_suite_list.append(rsn_authentication_suite_id[ord(data[i])])
            i += 1
        result['authentication suites'] = auth_suite_list
        # Ignore RSN capabilities for now
        return result

    def _process_rsn(self, data):
        '''Process RSN information element data.'''
        return self._process_rsn_wpa(data)

    def _process_vendor_specific(self, data):
        '''Process Vendor Specific information element data.'''
        i = 0
        result = {}
        data_length = len(data)
        # vendor oui
        if data_length < OUI_SIZE:
            raise InvalidInformationElement
        vendor_oui = data[i:i + OUI_SIZE]
        i += OUI_SIZE
        result['vendor oui'] = vendor_oui
        if data_length - i < 1:
            result['data'] = data[i:]
        else:
            data_id = struct.unpack("B", data[i:i + 1])[0]
            i += 1
            # WPA IE
            if vendor_oui == OUI_MS and data_id == 1:
                self._name = IE_WPA
                return self._process_rsn_wpa(data[i:], rsn=False)
            result['data'] = data[i:]
        return result

    def _process(self):
        '''Process information element data.'''
        if self._ie_id in information_elements_id.keys():
            self._name = information_elements_id[self._ie_id]
            if self._name == IE_SSID:
                self._data = self._process_ssid(self._data)
            elif self._name == IE_SUPPORTED_RATES:
                self._data = self._process_supported_rates(self._data)
            elif self._name == IE_DS_PARAMETER_SET:
                self._data = self._process_ds_parameter_set(self._data)
            elif self._name == IE_RSN:
                self._data = self._process_rsn(self._data)
            elif self._name == IE_EXTENDED_SUPPORTED_RATES:
                self._data = self._process_supported_rates(self._data)
            elif self._name == IE_VENDOR_SPECIFIC:
                self._data = self._process_vendor_specific(self._data)
        else:
            self._name = "Unknown"
            self._data = "%r" % self._data

    def getName(self):
        '''Returns information element name.'''
        return self._name

    def getData(self):
        '''Returns a string with the processed
           information element value.'''
        return self._data
