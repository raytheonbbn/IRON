// IRON: iron_headers 
/*
 * Distribution A
 *
 * Approved for Public Release, Distribution Unlimited
 *
 * EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
 * DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
 * Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
 *
 * This material is based upon work supported by the Defense Advanced
 * Research Projects Agency under Contracts No. HR0011-15-C-0097 and
 * HR0011-17-C-0050. Any opinions, findings and conclusions or
 * recommendations expressed in this material are those of the author(s)
 * and do not necessarily reflect the views of the Defense Advanced
 * Research Project Agency.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/* IRON: end */

#ifndef IRON_UDP_PROXY_FEC_DEFS_H
#define IRON_UDP_PROXY_FEC_DEFS_

/// The FEC Gateway server port.
#define  FEC_GW_SERVER_PORT       3144

/// The maximum size of the command response packets
/// that are received from the FEC Gateway.
#define  FEC_MAX_PKT_SIZE         1400

// Define the FEC code rate range, packet ID mask value and chunk ID mask
// value.
// Note that this value must fit within the size of slotID in the FEC Control
// Trailer structure below.

#define MAX_FEC_RATE   32
#define FEC_PKTID_MASK 0x3f
#define FEC_CHUNK_MASK 0x1f

#define FECSTATE_OKAY         0
#define FECSTATE_OUTOFBOUNDS -1
#define FECSTATE_CLOCKFAIL   -2

#define FEC_ORIGINAL 0
#define FEC_REPAIR   1

#define FEC_MAX_AGE  10

// Note: the rollover and mask values are intrinsicallly
// tied to the size of the groupID bitfield below

#define FEC_GROUPID_MASK     0xffffff
#define FEC_GROUPID_ROLLOVER 0x1000000

#endif // IRON_UDP_PROXY_FEC_DEFS_
