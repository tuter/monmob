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

import os
import re
from oui import oui_db


def is_lib_installed_on_system(lib_name):
    '''Returns True if lib_name exists on the system.'''
    lib_paths = ["/usr/lib/"]
    for path in lib_paths:
        lib_path = os.path.join(path, lib_name)
        if os.path.exists(lib_path):
            if os.path.isfile(lib_path):
                return True
    return False


def bytes_to_mac_address(bytes):
    '''Returns a mac address string from a bytes string.
       Input -> '\x00\x01\x02\x03\x04\x05'
       Output -> '00:01:02:03:04:05'
    '''
    if len(bytes) != 6:
        raise IndexError("String to short. MAC address must be 6 bytes long.")
    result = []
    for byte in bytes:
        result.append(byte.encode('hex'))
    return ':'.join(result)


def get_vendor_from_oui(oui):
    '''Returns the vendor name from an OUI.'''
    oui_regex = "([0-9a-fA-F][0-9a-fA-F][:-]){2}[0-9a-fA-F][0-9a-fA-F]"
    match = re.match(oui_regex, oui)
    if not match:
        raise Exception("Invalid OUI.")
    oui = oui.replace(":", "-").upper()
    if oui in oui_db:
        return oui_db[oui]
    return None


def is_mac_address_multicast(mac_address):
    '''Returns True if mac address is multicast.'''
    first_byte = int(mac_address.split(":")[0], 16)
    if first_byte & 0x01:
        return True
    return False


if __name__ == "__main__":
    print "Testcases for helpers functions"
    # Test is_lib_installed_on_system function
    # result = is_lib_installed_on_system("libpcap.1.0.0.dylib")
    # if not result:
    #    print "Error: is_lib_installed_on_system() -> %r" % result
    # Test bytes_to_mac_address function
    result = bytes_to_mac_address("\x00\x01\x02\x03\x04\x05")
    if result != "00:01:02:03:04:05":
        print "Error: bytes_to_mac_address() -> %r" % result
    print "OK: bytes_to_mac_address() -> %r" % result
    # Test get_vendor_from_oui function
    result = get_vendor_from_oui("00:00:00")
    if result != "XEROX CORPORATION":
        print "Error: get_vendor_from_oui() -> %r" % result
    print "OK: get_vendor_from_oui() -> %r" % result
    # Test is_mac_address_multicast
    result = is_mac_address_multicast("00:11:22:33:44:55")
    if result != False:
        print "Error: is_mac_address_multicast() -> %r" % result
    result = is_mac_address_multicast("33:33:00:00:00:00")
    if result != True:
        print "Error: is_mac_address_multicast() -> %r" % result
    result = is_mac_address_multicast("01:00:5e:00:00:00")
    if result != True:
        print "Error: is_mac_address_multicast() -> %r" % result
    print "OK: is_mac_address_multicast() -> %r" % result
