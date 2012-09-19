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


import socket
import libpcap
import plistlib
import struct
import time
import select
import ioctl
import phy
import dot11
import applayer

# Server Commands
class ServerCommand(object):
    def getData(self):
        ''' Returns a dictionary with command parameters '''
        raise NotImplementedError()

    def getSerialized(self):
        ''' Returns a string plist representing the command '''
        plist = plistlib.Plist()
        plist['command'] = self.CMD_ID
        
        cmd_values = self.getData()
        plist.update(cmd_values)
        ret =  plistlib.writePlistToString(plist)
        if isinstance(self,NetworkDetailCmd):
            pass  #print ret
        return ret 

        

class NetworkUpdateCmd(ServerCommand): # Network update.
    ''' Command send to UI when a beacon is recieved '''
    CMD_ID = 0
    def __init__(self, network, phy_hdr):
        super(NetworkUpdateCmd, self).__init__()
        self.network = network
        self.phy_hdr = phy_hdr

    def getData(self):
        return {'ssid': repr(self.network.getSsid())[1:-1],
                'bssid': self.network.getBssid(),
                'protection': self.network.getSecurity(), # 'WEP',
                'channel': self.phy_hdr.getChannel(),  
                'rssi': self.phy_hdr.getRssi(),
                'vendor': self.network.getVendor()}


class NetworkDetailCmd(ServerCommand):
    CMD_ID = 1
    def __init__(self, network):
        super(NetworkDetailCmd, self).__init__()
        self.network = network

    def getData(self):
        stations = self.network.getStations()
        clients = [stations[k].toDict() for k in stations]
        return {'clients': clients}


# Client Commands
class ClientCommand(object):
    def __init__(self, server):
        self.server = server

    def action(self):
        raise NotImplementedError()

    @classmethod
    def fromStream(cls, stream, server):
        size = stream.recv(4, socket.MSG_WAITALL)
        size = struct.unpack("<L", size)[0]
        rawCmd = stream.recv(size, socket.MSG_WAITALL)
        cmd = plistlib.readPlistFromString(rawCmd)
        return cls.fromDict(cmd, server)

    @classmethod
    def fromDict(cls, d, server):
        cmd_id = d['command']
        child = [c for c in cls.__subclasses__() if c.CMD_ID == cmd_id][0]
        return child(d, server)
        

class SetChannelCmd(ClientCommand):
    CMD_ID = 0
    def __init__(self, cmd, server):
        super(SetChannelCmd, self).__init__(server)
        self.channel = cmd['channel']

    def action(self):
        ioctl.set_channel(self.channel)
        while ioctl.get_channel()[0] != self.channel:
            ioctl.set_channel(self.channel)

class SetNetworkCmd(ClientCommand):
    CMD_ID = 1
    def __init__(self, cmd, server):
        super(SetNetworkCmd, self).__init__(server)
        self.bssid = cmd['bssid']

    def action(self):
        network = self.server.networks[self.bssid]
        newMode = NetworkDetailMode(self.server.networks, network)
        self.server.setMode(newMode)


class UnsetNetworkCmd(ClientCommand):
    CMD_ID = 2
    def __init__(self, cmd, server):
        super(UnsetNetworkCmd, self).__init__(server)

    def action(self):
        newMode = PassiveScanMode(self.server.networks)
        self.server.setMode(newMode)


class OperationMode(object):
    def __init__(self, networks):
        self.networks = networks

    def onFrame(self, phy_hdr, raw_frame):
        frame = None
        try: 
            fc = dot11.FrameControl(raw_frame)
            if fc.getType() == 0 and fc.getSubtype() == 8:
                frame = dot11.Beacon(raw_frame)
                bssid = frame.getBssid()

                if not bssid in self.networks:
                    net = applayer.Network(frame)
                    self.networks[bssid] = net

            elif fc.getType() == 2:
                frame = dot11.Data(raw_frame)
                bssid = frame.getBssid()
                if bssid in self.networks:
                    net = self.networks[bssid]
                    stations = net.getStations()
                    src = frame.getSourceAddress()
                    if not src in stations:
                        net.addStation(applayer.Station(src))
                    else:
                        s = stations[src]
                        s.incrementDataFrameStatistics()

            return self.cmdFromFrame(frame, phy_hdr)

        except Exception, e:
            print repr(e)

    def cmdFromFrame(self, frame, phy_hdr):
        raise NotImplementedError()
    

class PassiveScanMode(OperationMode):
    def __init__(self, networks):
        super(PassiveScanMode, self).__init__(networks)
        self.notificationTimes = {}

    def cmdFromFrame(self, frame, phy_hdr):
        ret = None
        if isinstance(frame, dot11.Beacon):
            bssid = frame.getBssid()
            t0 = time.time()
            notify = False
            if not bssid in self.notificationTimes:
                self.notificationTimes[bssid] = t0
                notify = True
            elif t0 - self.notificationTimes[bssid] > 1:
                self.notificationTimes[bssid] = t0
                notify = True

            if notify:
                ret = NetworkUpdateCmd(self.networks[bssid], phy_hdr)
            
        return ret

class NetworkDetailMode(OperationMode):
    def __init__(self, networks, network):
        super(NetworkDetailMode, self).__init__(networks)
        self.network = network
        self.justStarted = True

    def cmdFromFrame(self, frame, phy_hdr):
        ret = None
        if isinstance(frame, dot11.Data):
            if frame.getBssid() == self.network.getBssid() or self.justStarted:
                self.justStarted = False
                ret = NetworkDetailCmd(self.network)

        return ret


class Server:
    snaplen = 0xffff
    promisc = 1
    to_ms   = 1000
    pcap_filter = "ether host 88:88:88:88:88:88"
    ethernet_header_size = 14
    wlc_phy_header_size = 36

    def __init__(self, port):
        self.port = port
        self.networks = {}
        self.mode = PassiveScanMode(self.networks)

    def setMode(self, mode):
        self.mode = mode

    def setupConnection(self):
        s = socket.socket()
        s.bind(('127.0.0.1', self.port))
        s.listen(1)
        self.sock = s.accept()[0]
        s.close()

    def setupCard(self):
        if ioctl.get_intvar('mpc'):
            ioctl.set_intvar('mpc', 0)

    def setupPcap(self):
        device = libpcap.pcap_findalldevs()[0]
        self.pcap = libpcap.pcap_open_live(device, self.snaplen, self.promisc, self.to_ms)
        bpf = libpcap.bpf_program()
        libpcap.pcap_compile(self.pcap, self.pcap_filter, bpf)
        libpcap.pcap_setfilter(self.pcap, bpf)

    def getFrame(self):
        pkt_hdr, pkt_data = libpcap.pcap_next(self.pcap)
        packet = libpcap.Packet(pkt_hdr, pkt_data)
        raw_packet = packet.getData()
        frame_index = self.ethernet_header_size + self.wlc_phy_header_size
        if len(raw_packet) < frame_index:
            return None, None

        raw_phy_header = raw_packet[self.ethernet_header_size:frame_index]
        phy_hdr = phy.Bcm4329PhyHeader(raw_phy_header)
        raw_frame = raw_packet[frame_index:]

        return phy_hdr, raw_frame

    def processCommands(self):
        socks = [self.sock]
        cmdPending = len(select.select(socks, [], [], 0)[0]) > 0

        if cmdPending:
            cmd = ClientCommand.fromStream(self.sock, self)
            cmd.action()

    def _run(self):
        self.setupConnection()
        self.setupCard()
        self.setupPcap()

        while True:
            self.processCommands()
            phy_hdr, raw_frame = self.getFrame()
            if not raw_frame is None:
                cmd = self.mode.onFrame(phy_hdr, raw_frame)
                if not cmd is None:
                    try:
                        cmd_str = cmd.getSerialized()
                        self.sock.send(struct.pack("<L", len(cmd_str)) + cmd_str)
                    except Exception, e:
                        print e

    def run(self):
        try:
            self._run()
        finally:
            if hasattr(self, 'sock'):
                self.sock.close()


if __name__ == "__main__":
    s = Server(61000)
    s.run()

