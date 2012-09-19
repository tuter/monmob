#!/usr/bin/python

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

import os
import sys
import struct

SCRIPT_NAME = "monitor_mode_magic_pcap"

PCAP_GLOBAL_HDR_SIZE = 24
PCAP_FRAME_HDR_SIZE = 16

PCAP_MAGIC = '\xd4\xc3\xb2\xa1'
PCAP_MAJOR = 2
PCAP_MINOR = 4

MAX_FRAME_SIZE = 1500

DATALINK_802_11 = 105

datalink_dict = {
                      1 : "Ethernet",
                    105 : "802.11",
                    127 : "802.11 + Radiotap",
                }

def check_input_file(filename):
    if not os.path.exists(filename):
        print "Error: input file '%s' doesn't exists." % filename
        return False
    if not os.path.isfile(filename):
        print "Error: input file '%s' is not a file." % filename
        return False
    return True

def check_output_file(filename):
    if os.path.exists(filename):
        print "Error: output file '%s' exists." % filename
        return False
    return True

def parse_pcap_file(input_filename, output_filename, piped):
    mode = ''
    if piped:
        mode = '+'

    fdi = open(input_filename, "rb" + mode)
    fdo = open(output_filename, "wb" + mode)
    
    magic = fdi.read(4)
    if magic != PCAP_MAGIC:
        print "Error: Invalid pcap magic."
    
    # Write to output file
    fdo.write(magic)
    
    raw_major = fdi.read(2)
    raw_minor = fdi.read(2)
    major = struct.unpack("H", raw_major)[0]
    minor = struct.unpack("H", raw_minor)[0]
    if major != PCAP_MAJOR or minor != PCAP_MINOR:
        print "Error: Invalid pcap version."
    
    # Write to output file
    fdo.write(raw_major)
    fdo.write(raw_minor)
    
    # Write to output file | thiszone & thisfigs
    # fdo.write("\x00\x00\x00\x00\x00\x00\x00\x00")
    fdo.write(fdi.read(8)) # skip 
    
    raw_snaplen = fdi.read(4)
    raw_datalink = fdi.read(4)
    snaplen = struct.unpack("I", raw_snaplen)[0]
    datalink_id = struct.unpack("I", raw_datalink)[0]
    
    if snaplen < MAX_FRAME_SIZE:
        msg = "Warning: snaplen is lower than %d. " % MAX_FRAME_SIZE
        msg += "Frame data could be missing on the capture."
        print msg
    
    # Write to output file
    fdo.write(raw_snaplen)
    new_datalink = struct.pack("I", DATALINK_802_11)
    fdo.write(new_datalink)
    
    print "Filename -- %s" % input_filename
    print "Snaplen --- %d" % snaplen
    print "Datalink -- %s [%d]" % (datalink_dict[datalink_id], datalink_id)

    # To Remove PHY and fake ether headers
    skip_bytes = 36 + 14
 
    frame_number = 0
    raw_timestamp_seconds = fdi.read(4)
    while raw_timestamp_seconds:
        timestamp_seconds           = struct.unpack("I", raw_timestamp_seconds)[0]
        raw_timestamp_microseconds  = fdi.read(4)
        timestamp_microseconds      = struct.unpack("I", raw_timestamp_microseconds)[0]
        frame_len_in_file           = struct.unpack("I", fdi.read(4))[0]
        raw_frame_len_in_capture    = fdi.read(4)
        frame_len_in_capture        = struct.unpack("I", raw_frame_len_in_capture)[0]
        
        raw_frame_data = fdi.read(frame_len_in_file)
        frame_data = raw_frame_data[skip_bytes:-4]

        # Remove FCS
        # frame_data = frame_data[:-4]
 
        new_len_in_file = len(frame_data)
        raw_new_len_in_file = struct.pack("I", new_len_in_file)
        # Not interested on knowing the size on the capture
        raw_new_len_in_capture = raw_new_len_in_file
        
        # Write to output file (only frames with fafa ether type).
        if raw_frame_data[12:14] == '\xfa\xfa':
            frame_number += 1
            fdo.write(raw_timestamp_seconds)
            fdo.write(raw_timestamp_microseconds)
            fdo.write(raw_new_len_in_file)
            fdo.write(raw_new_len_in_capture)
            fdo.write(frame_data)

        raw_timestamp_seconds = fdi.read(4)
    
    print "Wrote %d frames to file '%s'." % (frame_number, output_file)
    fdo.close()
    fdi.close()

if __name__ == "__main__":
    if not len(sys.argv) in (3,4) or (len(sys.argv) == 4 and sys.argv[3] != '-pipe'):
        print "Usage"
        print "\t%s <pcap input file> <pcap output file> [-pipe]" % SCRIPT_NAME
        sys.exit(-1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    piped = False
    if len(sys.argv) == 4:
        piped = True
    
    if not piped and not check_input_file(input_file):
        sys.exit(-1)
    
    if not piped and not check_output_file(output_file):
        sys.exit(-1)
    
    parse_pcap_file(input_file, output_file, piped)

