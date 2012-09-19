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
import socket
import struct

# Apple ioctl codes
SIOCGA80211 = 0xC02069C9
SIOCSA80211 = 0x802069C8
APPLE80211_IOC_CARD_SPECIFIC = 0xFFFFFFFF

# broadcom wl_ioctl codes
WLC_MAGIC = 0
WLC_GET_VERSION = 1
WLC_GET_CHANNEL = 29
WLC_SET_CHANNEL = 30
WLC_GET_RADIO = 37
WLC_SET_RADIO = 38
WLC_GET_VAR = 262
WLC_SET_VAR = 263


class apple80211req(ctypes.Structure):
    _fields_ = [("ifname", ctypes.c_char * 16),
                ("req_type", ctypes.c_int),
                ("req_val", ctypes.c_int),
                ("req_len", ctypes.c_uint),
                ("req_data", ctypes.c_void_p)]


def wl_ioctl(cmd, buff=''):
    req = apple80211req()
    req.ifname = "en0\0"
    req.req_type = APPLE80211_IOC_CARD_SPECIFIC
    req.req_val = cmd

    if len(buff) != 0:
        # TODO: create_string agrega '\0'.
        buff = ctypes.create_string_buffer(buff)
        req.req_data = ctypes.cast(buff, ctypes.c_void_p)
        req.req_len = len(buff) - 1
    else:
        buff = ctypes.create_string_buffer(4)
        req.req_data = ctypes.cast(buff, ctypes.c_void_p)
        req.req_len = 4

    libSystem = ctypes.cdll.LoadLibrary("/usr/lib/libSystem.B.dylib")
    s = socket.socket()
    if libSystem.ioctl(s.fileno(), SIOCSA80211, ctypes.byref(req)) != 0:
        libSystem.__error.restype = ctypes.POINTER(ctypes.c_int)
        libSystem.strerror.restype = ctypes.c_char_p
        errno = libSystem.__error().contents.value
        raise Exception("ioctl error: %s" % libSystem.strerror(errno))

    s.close()
    return ''.join(x for x in buff)


def test_ioctl():
    return (struct.unpack("<L", wl_ioctl(WLC_MAGIC))[0] == 0x14e46c77 and
            struct.unpack("<L", wl_ioctl(WLC_GET_VERSION))[0] == 1)


def inject(frame):
    buff = struct.pack("<L", len(frame)) + frame
    wl_ioctl(0xfafa, buff)


def get_channel():
    """ returns (current, target, scan) channels """
    chan = wl_ioctl(WLC_GET_CHANNEL, '\x00' * 12)
    # TODO: arreglar el bug de arriba y sacar el [:-1]
    return struct.unpack("<LLL", chan[:-1])


def set_channel(number):
    wl_ioctl(WLC_SET_CHANNEL, struct.pack("<L", number))


def get_radio():
    return struct.unpack("<L", wl_ioctl(WLC_GET_RADIO))[0]


def set_radio(status):
    mask = 7
    status = struct.pack("<l", (mask << 16) | status)
    wl_ioctl(WLC_SET_RADIO, status)


def get_intvar(var):
    return struct.unpack("<L", wl_ioctl(WLC_GET_VAR, var + '\0')[:4])[0]


def set_intvar(var, val):
    wl_ioctl(WLC_SET_VAR, var + '\0' + struct.pack("<L", val))


# inject beacon on channel 8
if __name__ == "__main__":
    if not test_ioctl():
        raise Exception("test failed")

    # beacon frame.
    ssid = 'ipad injected'
    frame = (
        "80000000"
        "ffffffff"
        "ffffe0cb"
        "4e52a3cb"
        "e0cb4e52"
        "a3cbf072"
        "8b91606e"
        "a4010000"
        "64002104"
        "00").decode('hex') + struct.pack('b', len(ssid)) + ssid + (
        "0108"
        "82848b96"
        "2430486c"
        "03010605"
        "04000100"
        "002a0100"
        "2f010032"
        "040c1218"
        "60dd0600"
        "10180200"
        "00").decode('hex')

    channel = 8
    set_channel(channel)

    # 0 is ON
    radio = 0
    if get_intvar('mpc'):
        print 'disabling mpc'
        # y mpc queda desabilitado para siempre
        # habria que volver a prenderlo alguna vez.
        set_intvar('mpc', 0)

    while True:
        cur_channel = get_channel()[0]
        if cur_channel != channel:
            print "channel changed to", cur_channel
            set_channel(channel)

        cur_radio = get_radio()
        if cur_radio != radio:
            print "radio changed to", cur_radio
            set_radio(radio)

        inject(frame)
