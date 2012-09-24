#!/usr/bin/python
from __future__ import with_statement

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
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


import sys
import shutil
import os

from struct import pack
from zlib import crc32
from hashlib import sha1

def getSignature(firmware_data):
    start = firmware_data[:-2].rfind('\x00') + 1
    ret = firmware_data[start:]
    if not 'Version' in ret or not 'Date' in ret:
        raise Exception("Invalid signature")
    return ret

def getToken(signature, token, end_char):
    start = signature.find(token) + len(token)
    end = signature.find(end_char, start)
    return signature[start:end]

def getChipset(signature):
    return getToken(signature, '', '/')

def getVersion(signature):
    return getToken(signature, "Version: ", ' ')

def getDate(signature):
    return getToken(signature, "Date: ", '\x00')

def readDiff(fname):
    changes = []

    with open(fname, "r") as f:
        for line in f:
            if ':' in line:
                offset, diff = line.split(':')
                before, after = diff.lstrip().split(' ')
                after = after.rstrip()

                offset = int(offset, 16)
                before = int(before, 16)
                after  = int(after , 16)

                changes.append( (offset, before, after) )

    return changes


    

def patch(orig_fname, diff_fname, dest_fname, crc_offset):
#    crcoffset = 0x044E80        # Iphone 3Gs - 5.0.1
    crcoffset = 0x0409A9 - 4    # Ipad   1   - 5.0.1
#    crcoffset = 0x042170 - 4    # Galaxy tab - ??

    # read original firmare.
    origdata = ''
    with open(orig_fname, "rb") as f:
        origdata = f.read()
        if pack("<l", crc32(origdata[:crc_offset]))[:4] != origdata[crc_offset:crc_offset+4]:
            raise Exception("checksum mismatch!")
        print "checksum ok!"

    # read list of changes to do.
    
    changes = readDiff(diff_fname)
   
    # apply changes.
    newdata = origdata[:]
    for offset, before, after in changes:
        if origdata[offset] != chr(before):
            raise Exception("data mismatch at %x expecting %x found %x" % (offset, before, origdata[offset]))
        newdata = newdata[:offset] + chr(after) + newdata[offset+1:]
    
    # fix checksum
    newchecksum = pack("<l", crc32(newdata[:crc_offset]))[:4]
    newdata = newdata[:crc_offset] + newchecksum + newdata[crc_offset+4:]
    
    # write new file
    with open(dest_fname, "wb") as f:
        f.write(newdata)

def backup(fname):
    shutil.copy(fname, fname + '-backup')

def check_file(fname, msg):
    if not os.path.exists(fname):
        print ("Error: %s" % msg)
        sys.exit(1)


if __name__ == "__main__":
    crc_offsets = {
        "79232dc60d97b01b5c986269172f485de23f5142": 0x0409A9 - 4  # Ipad   1   - 5.0.1
    }

    if len(sys.argv) != 2:
        print "Usage: bcm_patcher firmware_file\n"
        sys.exit(1)

    firmware_data = ''
    firmware_fname = sys.argv[1]
    check_file(firmware_fname, 'firmware file not found')
    backup(firmware_fname)

    with open(firmware_fname, 'rb') as f:
        firmware_data = f.read()
    
    signature = getSignature(firmware_data)
    print 'Identifying firmware...'
    print '\tChipset:', getChipset(signature)
    print '\tVersion:', getVersion(signature)
    print '\tDate:', getDate(signature)

    hash_str = sha1(firmware_data).hexdigest()
    diff_fname = hash_str + '.diff'
    check_file(diff_fname, 'diff file not found (unsupported firmware?)')
   
    crcoffset = crc_offsets[hash_str]
    patch(firmware_fname, diff_fname, firmware_fname, crcoffset)

