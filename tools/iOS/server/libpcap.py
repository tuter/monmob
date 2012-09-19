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

import ctypes
import helpers

libpcap_filename = "libpcap.dylib"
_libpcap_lib = ctypes.cdll.LoadLibrary(libpcap_filename)

if helpers.is_lib_installed_on_system(libpcap_filename):
    _libpcap_lib = ctypes.cdll.LoadLibrary(libpcap_filename)
else:
    print "Error: unable to load \"%s\" library." % libpcap_filename

PCAP_NETMASK_UNKNOWN = 0xffffffff


class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_ushort),
                ("sa_data", ctypes.c_char * 14)]


class pcap_addr(ctypes.Structure):
    pass

pcap_addr._fields_ = [('next', ctypes.POINTER(pcap_addr)),
                      ('addr', ctypes.POINTER(sockaddr)),
                      ('netmask', ctypes.POINTER(sockaddr)),
                      ('broadaddr', ctypes.POINTER(sockaddr)),
                      ('dstaddr', ctypes.POINTER(sockaddr))]


class pcap_if(ctypes.Structure):
    pass

pcap_if._fields_ = [('next', ctypes.POINTER(pcap_if)),
                    ('name', ctypes.c_char_p),
                    ('description', ctypes.c_char_p),
                    ('addresses', ctypes.POINTER(pcap_addr)),
                    ('flags', ctypes.c_uint)]


class timeval(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long),
                ('tv_usec', ctypes.c_long)]


class pcap_pkthdr(ctypes.Structure):
    _fields_ = [('ts', timeval),
                ('caplen', ctypes.c_uint),
                ('len', ctypes.c_uint)]


class bpf_insn(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort),
                ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte),
                ('k', ctypes.c_ulong)]


class bpf_program(ctypes.Structure):
    _fields_ = [('bf_len', ctypes.c_int),
                ('bpf_insn', ctypes.POINTER(bpf_insn))]


def pcap_lookupdev():
    '''Return the first valid device in the system.'''
    # char* pcap_lookupdev(char *errbuf)
    errbuf = ctypes.create_string_buffer(256)
    pcap_lookupdev = _libpcap_lib.pcap_lookupdev
    pcap_lookupdev.restype = ctypes.c_char_p
    return pcap_lookupdev(errbuf)


def pcap_findalldevs():
    '''Construct a list of network devices that can be
       opened with pcap_open_live().'''
    # int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
    pcap_findalldevs = _libpcap_lib.pcap_findalldevs
    pcap_findalldevs.restype = ctypes.c_int
    pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(pcap_if)),
                                 ctypes.c_char_p]
    errbuf = ctypes.create_string_buffer(256)
    alldevs = ctypes.POINTER(pcap_if)()
    result = pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    if result == 0:
        devices = []
        device = alldevs.contents
        while(device):
            devices.append(device.name)
            if device.next:
                device = device.next.contents
            else:
                device = False
        # free to avoid leaking every time we call findalldevs
        pcap_freealldevs(alldevs)
    else:
        raise Exception(errbuf)
    return devices


def pcap_freealldevs(alldevs):
    '''Free an interface list returned by pcap_findalldevs().'''
    # void pcap_freealldevs(pcap_if_t *alldevsp)
    pcap_freealldevs = _libpcap_lib.pcap_freealldevs
    pcap_freealldevs.restype = None
    pcap_freealldevs.argtypes = [ctypes.POINTER(pcap_if)]
    pcap_freealldevs(alldevs)


def pcap_open_live(device, snaplen, promisc, to_ms):
    '''Open a live capture from the network.'''
    # pcap_t* pcap_open_live(const char* device, int snaplen,
    #                        int promisc, int to_ms, char* ebuf)
    pcap_open_live = _libpcap_lib.pcap_open_live
    pcap_open_live.restype = ctypes.POINTER(ctypes.c_void_p)
    pcap_open_live.argtypes = [ctypes.c_char_p,
                               ctypes.c_int,
                               ctypes.c_int,
                               ctypes.c_int,
                               ctypes.c_char_p]
    errbuf = ctypes.create_string_buffer(256)
    handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf)
    if not handle:
        print "Error opening device %s." % device
        return None
    return handle


def pcap_next(handle):
    '''Return the next available packet in a dictionary.'''
    # u_char* pcap_next(pcap_t* p, struct pcap_pkthdr* h)
    pcap_next = _libpcap_lib.pcap_next
    pcap_next.restype = ctypes.POINTER(ctypes.c_char)
    pcap_next.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                          ctypes.POINTER(pcap_pkthdr)]
    pkthdr = pcap_pkthdr()
    pktdata = pcap_next(handle, ctypes.byref(pkthdr))
    return pkthdr, pktdata[:pkthdr.len]


def pcap_compile(handle, filter, bpf):
    '''Compile a packet filter, converting an high level filtering
       expression in a program that can be interpreted by the kernel-level
       filtering engine.'''
    # int pcap_compile(pcap_t *p, struct bpf_program *fp,
    #                  char *str, int optimize, bpf_u_int32 netmask)
    pcap_compile = _libpcap_lib.pcap_compile
    pcap_compile.restype = ctypes.c_int
    pcap_compile.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                             ctypes.POINTER(bpf_program),
                             ctypes.c_char_p,
                             ctypes.c_int,
                             ctypes.c_uint]
    result = pcap_compile(handle,
                          ctypes.byref(bpf),
                          filter,
                          1,
                          PCAP_NETMASK_UNKNOWN)
    return result


def pcap_setfilter(handle, bpf):
    '''Associate a filter to a capture.'''
    # int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
    pcap_setfilter = _libpcap_lib.pcap_setfilter
    pcap_setfilter.restype = ctypes.c_int
    pcap_setfilter.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                               ctypes.POINTER(bpf_program)]
    result = pcap_setfilter(handle, bpf)
    return result


def pcap_close(handle):
    '''Close the files associated with p and deallocates resources.'''
    # void pcap_close(pcap_t* p)
    pcap_close = _libpcap_lib.pcap_close
    pcap_close.restype = None
    pcap_close.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    pcap_close(handle)


class Packet(object):
    '''Simple wrapper for the pcap structure.'''
    def __init__(self, header, data):
        self._length = header.len
        self._data = data

    def getData(self):
        return self._data

    def getLength(self):
        return self._length

if __name__ == "__main__":
    print "Testcases for libpcap module"

    # Test pcap_lookupdev function
    device = pcap_lookupdev()
    print "pcap_lookupdev() -> %r" % device

    # Test pcap_findalldevs function
    devices = pcap_findalldevs()
    print "pcap_findalldevs() -> %r" % devices

    # Test pcap_open_live function
    device = devices[0]
    snaplen = 65535
    promisc = 1
    to_ms = 10000
    print "pcap_open_live(%s, %s, %s, %s)" % (device, snaplen, promisc, to_ms)
    handle = pcap_open_live(device, snaplen, promisc, to_ms)
    print "pcap_open_live(...) -> %r" % handle
    if handle:
        bpf = bpf_program()
        result = pcap_compile(handle, "icmp", bpf)
        print "pcap_compile -> %r" % result

        result = pcap_setfilter(handle, bpf)
        print "pcap_setfilter -> %r" % result

        # Test pcap_next function
        pkt_hdr, pkt_data = pcap_next(handle)
        print "Length: %r" % pkt_hdr.len
        print "Capture Length: %r" % pkt_hdr.caplen
        print "Timestamp in Seconds: %r" % pkt_hdr.ts.tv_sec
        print "Timestamp in Microseconds: %r" % pkt_hdr.ts.tv_usec
        data = ""
        for index in range(pkt_hdr.len):
            data += chr(pkt_data[index])
        print "Data:"
        print repr(data)

    # Test pcap_close function
    pcap_close(handle)
