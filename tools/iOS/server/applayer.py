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

import dot11
from helpers import get_vendor_from_oui


class Station(object):

    def __init__(self, mac_address):
        self._mac_address = mac_address
        self._vendor = get_vendor_from_oui(mac_address[:8])
        self._conneted = False
        self._probes = []
        self._sentDataFrames = 0

    def getMacAddress(self):
        '''Returns the Station MAC address.'''
        return self._mac_address

    def getVendor(self):
        '''Returns the Station vendor based on the MAC address.'''
        return self._vendor

    def isConnected(self):
        '''Returns the Station connected state.'''
        return self._conneted

    def getProbes(self):
        '''Returns a list with the SSID of the networks the Station is probbing
           for.'''
        return self._probes

    def incrementDataFrameStatistics(self):
        self._sentDataFrames += 1

    def toDict(self):
        return {'addr': self._mac_address,
                'vendor': self._vendor,
                'sentDataFrames': self._sentDataFrames}


class Network(object):

    MGMT_FRAMES_COUNT = "Management frames count"
    DATA_FRAMES_COUNT = "Data frames count"

    def __init__(self, beacon):
        if not isinstance(beacon, dot11.Beacon):
            raise TypeError("Network constructor is expecting Beacon class.")

        self._processBeacon(beacon)

        self._statistics = {Network.MGMT_FRAMES_COUNT: 0,
                            Network.DATA_FRAMES_COUNT: 0}

        self._stations = {}

    def _processBeacon(self, beacon):
        self._bssid = beacon.getBssid()

        ies = beacon.getInformationElements()

        if dot11.IE_SSID in ies:
            self._cloacked = False
            self._ssid = ies[dot11.IE_SSID]
        else:
            self._cloacked = True
            self._ssid = ""

        if dot11.IE_RSN in ies:
            self._security = "WPA2"
        elif dot11.IE_WPA in ies:
            self._security = "WPA"
        elif beacon.getCapabilities() & dot11.CAP_PRIVACY:
            self._security = "WEP"
        else:
            self._security = "OPEN"

        self._vendor = get_vendor_from_oui(self._bssid[:8])

        if dot11.IE_DS_PARAMETER_SET in ies:
            self._channel = ies[dot11.IE_DS_PARAMETER_SET]
        else:
            self._channel = 0

    def getBssid(self):
        '''Returns the Network BSSID'''
        return self._bssid

    def getSsid(self):
        '''Returns the Network SSID.'''
        return self._ssid

    def getVendor(self):
        '''Returns the Network vendor based on the BSSID.'''
        return self._vendor

    def getChannel(self):
        '''Returns the Network channel.'''
        return self._channel

    def isCloacked(self):
        '''Returns True in case the Network is not broadcasting the SSID on the
           beacon frames.'''
        return self._cloacked

    def getSecurity(self):
        '''Returns the network security.'''
        return self._security

    def getStatistics(self):
        '''Returns Network statistics dictionary.'''
        return self._statistics

    def incrementManagementFrameStatistics(self):
        '''Increments the Management frame statistics of the Network.'''
        self._statistics[Network.MGMT_FRAMES_COUNT] += 1

    def incrementControlFrameStatistics(self):
        '''Increments the Control frame statistics of the Network.'''
        self._statistics[Network.CTRL_FRAMES_COUNT] += 1

    def incrementDataFrameStatistics(self):
        '''Increments the Data frame statistics of the Network.'''
        self._statistics[Network.DATA_FRAMES_COUNT] += 1

    def addStation(self, station):
        '''Add Station object to the list of the connected stations.'''
        addr = station.getMacAddress()
        if not addr in self._stations:
            self._stations[addr] = station

    def getStations(self):
        '''Returns a list with the Stations that have exchange Data frames
           with the Network.'''
        return self._stations
