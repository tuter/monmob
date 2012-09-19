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

BCM_4329_PHY_HDR_SIZE = 36

RXS_FCSERR = (1 << 0)
RXS_PHYRXST_VALID = (1 << 8)
PRXS1_nphy_PWR0_MASK = 0xFF


class Bcm4329PhyHeader(object):
    '''Broadcom 4329 PHY header class.

       Physical Header Specs

       u16 RxFrameSize; /* Actual byte length of the frame data received */
       u16 PAD;
       u16 PhyRxStatus_0; /* PhyRxStatus 15:0 */
       u16 PhyRxStatus_1; /* PhyRxStatus 31:16 */
       u16 PhyRxStatus_2; /* PhyRxStatus 47:32 */
       u16 PhyRxStatus_3; /* PhyRxStatus 63:48 */
       u16 PhyRxStatus_4; /* PhyRxStatus 79:64 */
       u16 PhyRxStatus_5; /* PhyRxStatus 95:80 */
       u16 RxStatus1; /* MAC Rx Status */
       u16 RxStatus2; /* extended MAC Rx status */
       u16 RxTSFTime; /* RxTSFTime time of first MAC symbol+M_PHY_PLCPRX_DLY */
       u16 RxChan; /* gain code, channel radio code, and phy type */
       u32 tsf_l; /* TSF_L reading */
       s8 rssi; /* computed instanteneous rssi in BMAC */
       s8 rxpwr0; /* obsoleted, place holder for legacy ROM. use rxpwr[] */
       s8 rxpwr1; /* obsoleted, place holder for legacy ROM. use rxpwr[] */
       s8 do_rssi_ma; /* do per-pkt sampling for per-antenna ma in HIGH */
       s8 rxpwr[WL_RSSI_ANT_MAX]; /* rssi for supported antennas */
    '''

    def __init__(self, data):
        if len(data) < BCM_4329_PHY_HDR_SIZE:
            raise IndexError("Phy Header size too small.")
        self._phy_header = data
        self._frame_size = 0
        self._processHeader()

    def _processHeader(self):
        '''Process Broadcom PHY header.'''
        self._frame_size = struct.unpack("H", self._phy_header[0:2])[0]
        self._phyRxStatus_0 = struct.unpack("H", self._phy_header[4:6])[0]
        self._phyRxStatus_1 = struct.unpack("H", self._phy_header[6:8])[0]
        self._phyRxStatus_2 = struct.unpack("H", self._phy_header[8:10])[0]
        self._phyRxStatus_3 = struct.unpack("H", self._phy_header[10:12])[0]
        self._phyRxStatus_4 = struct.unpack("H", self._phy_header[12:14])[0]
        self._phyRxStatus_5 = struct.unpack("H", self._phy_header[14:16])[0]
        self._rxStatus1 = struct.unpack("H", self._phy_header[16:18])[0]
        self._rxStatus2 = struct.unpack("H", self._phy_header[18:20])[0]
        self._rxTSFTime = struct.unpack("H", self._phy_header[20:22])[0]
        self._rxChan = struct.unpack("H", self._phy_header[22:24])[0]
        self._tsf_l = struct.unpack("I", self._phy_header[24:28])[0]
        self._rssi = struct.unpack("B", self._phy_header[28:29])[0]
        self._rxpwr0 = struct.unpack("B", self._phy_header[29:30])[0]
        self._rxpwr1 = struct.unpack("B", self._phy_header[30:31])[0]
        self._do_rssi_ma = struct.unpack("B", self._phy_header[31:32])[0]
        self._rxpwr = struct.unpack("I", self._phy_header[32:36])

    def getFrameSize(self):
        '''Return the actual byte length of the frame data received.'''
        return self._frame_size

    def getChannel(self):
        '''Return the channel for received frame.'''
        # LDRB.W  R2, [R8,#0x17]
        # LDRB.W  R3, [R8,#0x16]
        # ORR.W   R3, R3, R2,LSL#8
        # UBFX.W  R4, R3, #3, #8
        return (self._rxChan >> 3) & 0x00FF

    def getRssi(self):
        '''Return the rssi for received frame.'''
        phyrxst_valid = self._rxStatus2 & 0xFF00
        if phyrxst_valid == 256:
            rssi = self._phyRxStatus_1 & PRXS1_nphy_PWR0_MASK
            if rssi > 127:
                rssi -= 0x100
            return rssi
        return None

    def hasValidFCS(self):
        '''Returns True if the FCS is valid.'''
        return not (self._rxStatus1 & RXS_FCSERR)

if __name__ == "__main__":
    test_header = "\x5b\x00\x00\x00\x00\x60\xa9\x53\x23\x78\x40\x85" \
                  "\x00\x00\x00\x00\x00\x00\x06\x01\x2d\x36\x36\x00" \
                  "\x00\x00\x00\x00\x00\x00\x0a\x04\xa8\x02\x3c\x01"
    phy_header = Bcm4329PhyHeader(test_header)
    if phy_header.getFrameSize() != 91:
        print "Error: frame size incorrect."
    if phy_header.getChannel() != 6:
        print "Error: channel incorrect."
    if phy_header.getRssi() != -87:
        print "Error: rssi incorrect."
