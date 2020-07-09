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

/// The header types for encapsulating CAT and SLIQ headers.  Determined by
/// the first byte in the buffer.
enum HeaderType
{
  // SLIQ connection establishment, reset, and close headers.  Cannot be
  // concatenated.
  CONNECTION_HANDSHAKE_HEADER = 0,
  RESET_CONNECTION_HEADER     = 1,
  CLOSE_CONNECTION_HEADER     = 2,

  // SLIQ stream creation and reset headers.  Cannot be concatenated.
  CREATE_STREAM_HEADER        = 3,
  RESET_STREAM_HEADER         = 4,

  // SLIQ data transfer headers.  Can be concatenated, but any data header
  // must be last.
  DATA_HEADER                 = 32,
  ACK_HEADER                  = 33,
  CC_SYNC_HEADER              = 34,
  RCVD_PKT_CNT_HEADER         = 35,

  // SLIQ specialized stand-alone headers.  Cannot be concatenated.
  CC_PKT_TRAIN_HEADER         = 40,

  // CAT packet object metadata headers.  Must follow all SLIQ headers.
  CAT_PKT_DST_VEC_HEADER      = 52,
  CAT_PKT_ID_HEADER           = 53,
  CAT_PKT_HISTORY_HEADER      = 54,
  CAT_PKT_LATENCY_HEADER      = 55,

  UNKNOWN_HEADER              = 255
};


//  ================ SLIQ Connection Handshake Headers ================
// The size of the base connection handshake header, in bytes.
const size_t  kConnHandshakeHdrBaseSize = 16;

// The size of the connection handshake CC algorithm fields, in bytes.
const size_t  kConnHandshakeHdrCcAlgSize = 8;

/// The SLIQ connection handshake header (partial).
///
/// \verbatim
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |  # of CC Alg  |          Message Tag          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct connHndshkFrontend
{
  uint8_t   type;
  uint8_t   num_cc_algs;
  uint16_t  message_tag;
} __attribute__((packed));


//  ================ SLIQ Connection Reset Headers ================
// The size of the connection reset header, in bytes.
const size_t  kConnResetHdrSize = 4;


//  ================ SLIQ Connection Close Headers ================
// The size of the connection close header, in bytes.
const size_t  kConnCloseHdrSize = 4;


//  ================ SLIQ Create Stream Headers ================
// The size of the connection reset header, in bytes.
const size_t  kCreateStreamHdrSize = 20;


//  ================ SLIQ Reset Stream Headers ================
// The size of the connection reset header, in bytes.
const size_t  kResetStreamHdrSize = 8;


// ================ SLIQ Data Headers ================

// The size of the base data header, in bytes.
const size_t  kDataHdrBaseSize = 20;

// The size of the data header move forward field, in bytes.
const size_t  kDataHdrMoveFwdSize = 4;

// The size of the data header FEC fields, in bytes.
const size_t  kDataHdrFecSize = 4;

// The size of the data header encoded packet size field, in bytes.
const size_t  kDataHdrEncPktLenSize = 2;

// The size of the data header time-to-go field, in bytes.
const size_t  kDataHdrTimeToGoSize = 2;

/// The SLIQ Data header (partial).
///
/// \verbatim
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |U|L|E|M| U |P|F|   Stream ID   | Number of TTG |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct dataFrontend
{
  uint8_t  type;
  uint8_t  flags;
  uint8_t  stream_id;
  uint8_t  num_ttg;
} __attribute__((packed));


// ================ SLIQ ACK Headers ================

// The base size of the ACK header, in bytes.
const size_t  kAckHdrBaseSize = 16;

// The size of each observed time entry in the ACK header, in bytes.
const size_t  kAckHdrObsTimeSize = 8;

// The size of each ACK block offset entry in the ACK header, in bytes.
const size_t  kAckHdrAckBlockOffsetSize = 2;

/// The SLIQ ACK header (partial).
///
/// \verbatim
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |Flags (Unused) |   Stream ID   | #OPT|   #ABO  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct ackFrontend
{
  uint8_t  type;
  uint8_t  flags;
  uint8_t  stream_id;
  uint8_t  num_opt_abo;
} __attribute__((packed));


// ================ SLIQ Congestion Control Synchronization Headers ==========

// The size of the CC sync header, in bytes.
const size_t  kCcSyncHdrSize = 8;


// ================ SLIQ Received Packet Count Headers ================

// The size of the received packet count header, in bytes.
const size_t  kRcvdPktCntHdrSize = 12;


//  ================ SLIQ Congestion Control Packet Train Headers ============
// The size of the connection reset header, in bytes.
const size_t  kCcPktTrainHdrSize = 16;


// ================ CAT Packet Destination Vector Headers ================

// The size of the packet destination vector header, in bytes.
const size_t  kCatPktDstVecHdrSize = 4;


// ================ CAT Packet Identifier Headers ================

// The size of the packet ID header, in bytes.
const size_t  kCatPktIdHdrSize = 4;


// ================ CAT Packet History Headers ================

// The size of the packet history header, in bytes.
const size_t  kCatPktHistoryHdrSize = 12;


// ================ CAT Packet Latency Headers ================

// The size of the packet latency header, in bytes.
const size_t  kCatPktLatencyHdrSize = 8;


#endif // IRON_SLIQ_PRIVATE_DEFS_H
