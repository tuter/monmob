#!/usr/bin/python
from __future__ import with_statement

import sys
from struct import pack, unpack
from zlib import crc32, adler32

def extract(trxfname, dstfname):
    firmdata = ''
    with open(trxfname, "rb") as f:
        firmdata = f.read()

    if firmdata[:4] != 'HDR0':
        raise Exception("Unrecognized trx file")

    size = unpack("<l", firmdata[4:8])[0]
    if size != len(firmdata):
        raise Exception("Incosistent sizes: trx file says %d file is: %d" % (size, len(firmdata)))

    headercrc = firmdata[8:12]
    calcedcrc = crc32(firmdata[12:])

    if calcedcrc < 0: # crc32 should be unsigned...
        calcedcrc = (calcedcrc + 1) * (-1)

    if pack("<l", calcedcrc) != headercrc:
        raise Exception("Checksum mismatch!")
    else:
        print "checksum ok"

    with open(dstfname, "wb") as f:
        f.write(firmdata[0x1c:])

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "usage: trxunpack trxfile destfile"
        sys.exit(1)

    extract(*sys.argv[1:])
