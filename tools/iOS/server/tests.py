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

# Command Line tool for testing or something...

import sys
import phy
import dot11
import libpcap
import helpers
import applayer

# PCAP
DEVICE = "en0"  # iOS devices only
PROMISC = 1
SNAPLEN = 65535
TIMEOUT_MS = 100
BPF_FILTER = "ether host 88:88:88:88:88:88"

# Header Sizes
WLC_PHY_HEADER_SIZE = 36
ETHERNET_HEADER_SIZE = 14

# Global things :S
debug = False
networks = {}


def processPackets(packet):
    if debug:
        print "pcap length: %d" % packet.getLength()

    if packet.getLength() < WLC_PHY_HEADER_SIZE + ETHERNET_HEADER_SIZE:
        return None
    phy_hdr_begin = ETHERNET_HEADER_SIZE
    phy_hdr_end = phy_hdr_begin + WLC_PHY_HEADER_SIZE
    phy_header = packet.getData()[phy_hdr_begin:phy_hdr_end]
    phy_hdr = phy.Bcm4329PhyHeader(phy_header)

    if debug:
        phy_channel = phy_hdr.getChannel()
        print "phy length: %d" % phy_hdr.getFrameSize()
        print "phy channel: %d %04X" % (phy_channel, phy_channel)
        print "phy rssi: %d" % (phy_hdr.getRssi())
        print "phy valid FCS: %d" % (phy_hdr.hasValidFCS())

    if not phy_hdr.hasValidFCS():
        print "Invalid FCS!"
        # return None

    fc = dot11.FrameControl(packet.getData()[phy_hdr_end:])
    fc_protocol = fc.getProtocol()
    fc_type = fc.getType()
    fc_subtype = fc.getSubtype()
    fc_to_ds = fc.getToDs()
    fc_from_ds = fc.getFromDs()
    fc_protected = fc.getProtectedFrame()

    if debug:
        print "proto: %d" % fc_protocol
        print "type: %d - subtype: %d" % (fc_type, fc_subtype)
        print "toDS: %r - fromDS: %r" % (fc_to_ds, fc_from_ds)
        print "protectedFrame: %r" % fc_protected

    if fc_type == 0 and fc_subtype == 8:  # Type Management Subtype Beacon
        try:
            beacon_frame = dot11.Beacon(packet.getData()[phy_hdr_end:])
            bssid = beacon_frame.getBssid()
            if debug:
                print "Beacon"
                print "Duration: %d" % beacon_frame.getDuration()
                print "Destination: %s" % beacon_frame.getDestination()
                print "Source: %s" % beacon_frame.getSource()
                print "BSSID: %s" % bssid
                print "Fragment: %s" % beacon_frame.getFragment()
                print "Sequence: %s" % beacon_frame.getSequence()
                print "Information Elements"
                for item in beacon_frame.getRawInformationElements().items():
                    print item
                for item in beacon_frame.getInformationElements().items():
                    print item[0]
                    print item[1]

            if not (bssid in networks):
                    nt = applayer.Network(beacon_frame)
                    networks[bssid] = nt
                    ssid = nt.getSsid()
                    ch = nt.getChannel()
                    security = nt.getSecurity()
                    vendor = nt.getVendor()
                    print "%s - %s - %d - %s - %s" % (bssid,
                                                      ssid,
                                                      ch,
                                                      security,
                                                      vendor)
        # except dot11.InvalidInformationElement:
            # pass
        except Exception, e:
            print "Exception: %s" % e.__class__
            print "phy valid FCS: %d" % phy_hdr.hasValidFCS()
            print "phy raw data"
            print phy_header.encode('hex')
            print "802.11 raw data"
            print packet.getData()[phy_hdr_end:].encode('hex')
            raise Exception
    elif fc_type == 0 and fc_subtype == 4:  # Type Management Subtype Probe Req
        probe_req = dot11.ProbeRequest(packet.getData()[phy_hdr_end:])
        print "-" * 40
        print probe_req.getSource()
        print probe_req._ies
        print "-" * 40
    elif fc_type == 2:  # Type data
        data_frame = dot11.DataFrame(packet.getData()[phy_hdr_end:])
        bssid = data_frame.getBssid()
        station_address = data_frame.getSourceAddress()
        if helpers.is_mac_address_multicast(station_address):
            return
        if bssid in networks:
            nt = networks[bssid]
            stations = nt.getStations()
            station_address = data_frame.getSourceAddress()
            station = applayer.Station(station_address)
            if not (station_address in stations):
                nt.addStation(station)
                print "Station %s connected to %s %s" % (station_address,
                                                         nt.getBssid(),
                                                         nt.getSsid())
        # Show not encrypted frames
        # if not fc_protected:
        #     print repr(packet.getData()[phy_hdr_end:])


def forever():
    try:
        handle = libpcap.pcap_open_live(DEVICE, SNAPLEN, PROMISC, TIMEOUT_MS)
        if handle:
            bpf = libpcap.bpf_program()
            libpcap.pcap_compile(handle, BPF_FILTER, bpf)
            libpcap.pcap_setfilter(handle, bpf)
            while(1):
                pkt_hdr, pkt_data = libpcap.pcap_next(handle)
                packet = libpcap.Packet(pkt_hdr, pkt_data)
                processPackets(packet)
    except KeyboardInterrupt:
        print "Trap Ctrl+C."
        print "Exiting..."
        sys.exit(0)

if __name__ == "__main__":
    if "debug" in sys.argv:
        debug = True

    forever()
