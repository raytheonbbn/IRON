//============================================================================
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
//
// This code is derived in part from the stablebits libquic code available at:
// https://github.com/stablebits/libquic.
//
// The stablebits code was forked from the devsisters libquic code available
// at:  https://github.com/devsisters/libquic
//
// The devsisters code was extracted from Google Chromium's QUIC
// implementation available at:
// https://chromium.googlesource.com/chromium/src.git/+/master/net/quic/
//
// The original source code file markings are preserved below.

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#ifndef IRON_SLIQ_PRIVATE_DEFS_H
#define IRON_SLIQ_PRIVATE_DEFS_H

#include "sliq_private_types.h"
#include "sliq_types.h"

#include <cstdlib>


/// Packet sequence number (PktSeqNumber) comparators.
#define SEQ_GT(a,b)   ((int32_t)((a)-(b)) > 0)
#define SEQ_LT(a,b)   ((int32_t)((a)-(b)) < 0)
#define SEQ_GEQ(a,b)  ((int32_t)((a)-(b)) >= 0)
#define SEQ_LEQ(a,b)  ((int32_t)((a)-(b)) <= 0)

/// Packet count (PktCount) comparators.
#define CNT_GT(a,b)   ((int32_t)((a)-(b)) > 0)
#define CNT_LT(a,b)   ((int32_t)((a)-(b)) < 0)
#define CNT_GEQ(a,b)  ((int32_t)((a)-(b)) >= 0)
#define CNT_LEQ(a,b)  ((int32_t)((a)-(b)) <= 0)

/// Packet timestamp (PktTimestamp) comparators.
#define TS_GT(a,b)   ((int32_t)((a)-(b)) > 0)
#define TS_LT(a,b)   ((int32_t)((a)-(b)) < 0)
#define TS_GEQ(a,b)  ((int32_t)((a)-(b)) >= 0)
#define TS_LEQ(a,b)  ((int32_t)((a)-(b)) <= 0)

namespace sliq
{

  // ================ SLIQ Stream IDs ================

  /// The minimum stream ID value.
  const StreamId  kMinStreamId = 1;

  /// The maximum stream ID value.
  const StreamId  kMaxStreamId = 32;

  // ================ SLIQ Stream Priority ================

  /// The highest priority for a stream.
  const Priority  kHighestPriority = 0;

  /// The lowest priority for a stream.
  const Priority  kLowestPriority = 7;

  /// The number of priority values.
  const Priority  kNumPriorities = 8;

  // ================ SLIQ Sequence Number ================

  /// The initial sequence number range, from zero to this value.
  const PktSeqNumber  kInitSeqNumRange = 1000000000;

  /// The maximum sequence number.
  const PktSeqNumber  kMaxSeqNum = UINT32_MAX;

  // ================ SLIQ RTTs ================

  /// The minimum allowable computed RTT in microseconds.
  const uint32_t  kMinRttUsec = 20;

  /// The minimum allowable computed RTT in seconds.
  const double  kMinRttSec = (0.000001 * static_cast<double>(kMinRttUsec));

  /// The maximum allowable computed RTT in microseconds.
  const uint32_t  kMaxRttUsec = 4000000;

  // ================ SLIQ Packets ================

  // The maximum packet size of any SLIQ packet, based on Ethernet's MTU,
  // minus the IP and UDP headers.  IPv4 has a 20 byte header, and UPD adds an
  // additional 8 bytes.  This is a total overhead of 28 bytes.  Ethernet's
  // MTU is 1500 bytes.  Thus, 1500 - 28 = 1472.
  const size_t  kMaxPacketSize = 1472;

  // ================ SLIQ Data Headers ================

  // The base size of the data header, in bytes.
  const size_t  kDataHdrBaseSize = 20;

  // The size of the move forward sequence number field in the data header, in
  // bytes.
  const size_t  kDataHdrMoveFwdSize = 4;

  // The size of the FEC fields in the data header, in bytes.
  const size_t  kDataHdrFecSize = 4;

  // The size of the encoded packet length field in the data header, in bytes.
  const size_t  kDataHdrEncPktLenSize = 2;

  // The size of the each time-to-go (TTG) field in the data header, in bytes.
  const size_t  kDataHdrTtgSize = 2;

  /// The maximum number of time-to-go (TTG) values that may be contained in a
  /// single data header.
  const size_t  kMaxTtgs = 16;

  // ================ SLIQ ACK Headers ================

  // The base size of the ACK header, in bytes.
  const size_t  kAckHdrBaseSize = 16;

  // The size of each observed time entry in the ACK header, in bytes.
  const size_t  kAckHdrObsTimeSize = 8;

  // The size of each ACK block offset entry in the ACK header, in bytes.
  const size_t  kAckHdrAckBlockOffsetSize = 2;

  /// The maximum number of observed packet times that may be contained in a
  /// single ACK header.
  const size_t  kMaxObsTimes = 7;

  /// The maximum number of ACK block offsets that may be contained in a
  /// single ACK header.
  const size_t  kMaxAckBlockOffsets = 31;

  /// The target number of ACK block offsets to be included in each ACK
  /// header.  Increasing this parameter improves resilience to ACK packet
  /// loss at the expense of larger ACK headers.  Must not be greater than
  /// kMaxAckBlockOffsets.
  const size_t  kTargetAckBlockOffsets = 10;

  /// The number of recently received and regenerated data packets to keep
  /// track of when generating ACK block offsets.  There is no benefit to
  /// making this larger than kMaxAckBlockOffsets.
  const size_t  kAckHistorySize = 24;

  /// The number of data packets that must be received before sending an ACK
  /// packet, unless the ACK timer expires before this count is reached.
  const size_t  kAckAfterDataPktCnt = 2;

  /// The number of ACKs that must be sent upon receipt of data for any stream
  /// after all missing data is received for a stream.
  const size_t  kPostRecoveryAckCnt = 3;

  /// The ACK timer duration in microseconds.  Must be less than 500000
  /// microseconds (500 milliseconds).
  const suseconds_t  kAckTimerUsec = 40000;

  // ================ SLIQ CC Synchronization Headers ================

  // The size of the congestion control synchronization header, in bytes.
  const size_t  kCcSyncHdrSize = 8;

  // ================ SLIQ Received Packet Count Headers ================

  // The size of the received packet count header, in bytes.
  const size_t  kRcvdPktCntHdrSize = 12;

  // The number of data packet receptions necessary to trigger a received
  // packet count header transmission.  If the header cannot be
  // opportunistically added within twice this number of packets, then a
  // received packet count header will be sent by itself in a packet.
  const size_t  kRcvdPktCntIntPkts = 32;

  // ================ SLIQ CC Packet Train Headers ================

  // The size of the congestion control packet train header, in bytes.
  const size_t  kCcPktTrainHdrSize = 16;

  // ================ SLIQ Stream Flow Control ================

  /// The fixed stream flow control send window size in packets.  This is
  /// limited to 2^15 (32,768) by the ACK header ACK block offset size, which
  /// is 15 bits.
  const WindowSize  kFlowCtrlWindowPkts = 32768;

  // ================ SLIQ Connection Congestion Control ================

  /// The maximum congestion control window size in packets.
  const size_t  kMaxCongCtrlWindowPkts = 32768;

  // ================ SLIQ Retransmissions ================

  /// The maximum retransmission count.
  const RetransCount  kMaxRexmitCount = 255;

  /// The maximum retransmission wait time in seconds.
  const time_t  kMaxRexmitWaitTimeSec = 64;

  // ================ SLIQ Reliability ================

  /// The default semi-reliable packet delivery retransmission limit.
  const RexmitLimit  kDefaultDeliveryRexmitLimit = 2;

  // ================ SLIQ Forward Error Correction ================

  /// The maximum FEC block length (source + encoded) in packets.  Set based
  /// on the capabilities of the VdmFec class.  Cannot be greater than 32 due
  /// to the FecGroupPktBitVec type.
  const size_t  kMaxFecBlockLengthPkts = 31;

  /// The maximum target packet receive probability.
  const double  kMaxTgtPktRcvProb = 0.999;

  /// The maximum target packet delivery rounds.  This constant is used for
  /// sizing the FEC lookup tables using the kNumRounds constant in the FEC
  /// definitions header file.
  const size_t  kMaxTgtPktDelRnds = 7;

  /// The maximum packet delivery round value supported.
  const FecRound  kMaxRnd = 255;

  // ================ SLIQ Sockets ================

  /// The maximum number of packets that will be read for each recvmmsg()
  /// system call.
  const size_t  kNumPktsPerRecvMmsgCall = 16;

} // namespace sliq

#endif // IRON_SLIQ_PRIVATE_DEFS_H
