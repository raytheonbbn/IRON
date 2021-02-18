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
//============================================================================

#ifndef IRON_SLIQ_PACKET_DEFS_H
#define IRON_SLIQ_PACKET_DEFS_H

/// The header types for encapsulating BPF, CAT and SLIQ headers.  Determined
/// by the first byte in the buffer.
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

  // BPF Queue Length Advertisement Message (QLAM) packets.
  QLAM_PACKET                 = 16,

  // BPF Link State Advertisement (LSA) packets.
  LSA_PACKET                  = 19,

  // BPF Zombie packets.
  ZOMBIE_PACKET               = 21,

  // SLIQ data transfer headers.  Can be concatenated, but any data header
  // must be last.
  DATA_HEADER                 = 32,
  ACK_HEADER                  = 33,
  CC_SYNC_HEADER              = 34,
  RCVD_PKT_CNT_HEADER         = 35,
  CONN_MEAS_HEADER            = 36,

  // SLIQ specialized stand-alone headers.  Cannot be concatenated.
  CC_PKT_TRAIN_HEADER         = 40,

  // CAT headers and CAT packet object metadata headers.  Must follow all SLIQ
  // headers.
  CAT_CAP_EST_HEADER          = 48,
  CAT_PKT_DEST_LIST_HEADER    = 52,
  CAT_PKT_ID_HEADER           = 53,
  CAT_PKT_HISTORY_HEADER      = 54,
  CAT_PKT_LATENCY_HEADER      = 55,

  // IPv4 packets.  Value of 0x4 in most significant 4-bits of first byte.
  IPV4_PACKET                 = 64,

  // For use in sizing the opt_log array.
  OPT_LOG_SIZE                = 65,

  UNKNOWN_HEADER              = 255
};


//  ================ SLIQ Connection Handshake Headers ================
const size_t kConnHndshkHdrBaseSize     = 12;
const size_t kConnHndshkHdrCcAlgSize    = 8;
const size_t kConnHndshkHdrClientIdSize = 4;

struct ConnHndshkHdrBase
{
  uint8_t   type;
  uint8_t   num_cc;
  uint16_t  tag;
  uint32_t  ts;
  uint32_t  echo_ts;
} __attribute__((packed));

struct ConnHndshkHdrCcAlg
{
  uint8_t   cc_type;
  uint8_t   cc_flags;
  uint16_t  cc_unused;
  uint32_t  cc_params;
} __attribute__((packed));

struct ConnHndshkHdrClientId
{
  uint32_t  client_id;
} __attribute__((packed));


//  ================ SLIQ Reset Connection Headers ================
const size_t kResetConnHdrSize = 4;

struct ResetConnHdr
{
  uint8_t   type;
  uint8_t   flags;
  uint16_t  error;
} __attribute__((packed));


//  ================ SLIQ Close Connection Headers ================
const size_t kCloseConnHdrSize = 4;

struct CloseConnHdr
{
  uint8_t   type;
  uint8_t   flags;
  uint16_t  reason;
} __attribute__((packed));


//  ================ SLIQ Create Stream Headers ================
const size_t kCreateStreamHdrSize = 20;

struct CreateStreamHdr
{
  uint8_t   type;
  uint8_t   flags;
  uint8_t   stream;
  uint8_t   priority;
  uint32_t  init_win_size;
  uint32_t  init_seq;
  uint8_t   del_rel;
  uint8_t   rexmit_limit;
  uint16_t  tgt_del;
  uint16_t  tgt_rcv;
  uint16_t  unused;
} __attribute__((packed));


//  ================ SLIQ Reset Stream Headers ================
const size_t kResetStreamHdrSize = 8;

struct ResetStreamHdr
{
  uint8_t   type;
  uint8_t   flags;
  uint8_t   stream;
  uint8_t   error;
  uint32_t  final_seq;
} __attribute__((packed));


// ================ SLIQ Data Headers ================
const size_t kDataHdrBaseSize  = 20;
const size_t kDataHdrMvFwdSize = 4;
const size_t kDataHdrFecSize   = 4;
const size_t kDataHdrEPLenSize = 2;
const size_t kDataHdrTTGSize   = 2;

struct DataHdrBase
{
  uint8_t   type;
  uint8_t   flags;
  uint8_t   stream;
  uint8_t   num_ttg;
  uint8_t   cc_id;
  uint8_t   rexmit;
  uint16_t  pld_len;
  uint32_t  seq;
  uint32_t  ts;
  uint32_t  ts_delta;
} __attribute__((packed));

struct DataHdrMvFwd
{
  uint32_t  seq;
} __attribute__((packed));

struct DataHdrFec
{
  uint8_t   type_idx;
  uint8_t   src_rnd;
  uint16_t  grp;
} __attribute__((packed));

struct DataHdrEPLen
{
  uint16_t  epl;
} __attribute__((packed));

struct DataHdrTTG
{
  uint16_t  ttg;
} __attribute__((packed));


// ================ SLIQ ACK Headers ================
const size_t kAckHdrBaseSize  = 16;
const size_t kAckHdrTimeSize  = 8;
const size_t kAckHdrBlockSize = 2;

struct AckHdrBase
{
  uint8_t   type;
  uint8_t   flags;
  uint8_t   stream;
  uint8_t   num_opt_abo;
  uint32_t  ne_seq;
  uint32_t  ts;
  uint32_t  ts_delta;
} __attribute__((packed));

struct AckHdrTime
{
  uint32_t  tm_seq;
  uint32_t  tm_ts;
} __attribute__((packed));

struct AckHdrBlock
{
  uint16_t  type_offset;
} __attribute__((packed));


// ================ SLIQ Congestion Control Synchronization Headers ==========
const size_t kCcSyncHdrSize = 8;

struct CcSyncHdr
{
  uint8_t   type;
  uint8_t   cc_id;
  uint16_t  seq_num;
  uint32_t  params;
} __attribute__((packed));


// ================ SLIQ Received Packet Count Headers ================
const size_t kRcvdPktCntHdrSize = 12;

struct RcvdPktCntHdr
{
  uint8_t   type;
  uint8_t   flags;
  uint8_t   stream;
  uint8_t   rexmit;
  uint32_t  seq;
  uint32_t  cnt;
} __attribute__((packed));


// ================ SLIQ Connection Measurement Headers ================
const size_t kConnMeasHdrBaseSize      = 4;
const size_t kConnMeasHdrMaxRtlOwdSize = 4;

struct ConnMeasHdrBase
{
  uint8_t   type;
  uint8_t   flags;
  uint16_t  seq;
} __attribute__((packed));

struct ConnMeasHdrMaxRtlOwd
{
  uint32_t  owd;
} __attribute__((packed));


// ================ SLIQ Congestion Control Packet Train Headers ==========
const size_t kCcPktTrainHdrSize = 16;

struct CcPktTrainHdr
{
  uint8_t   type;
  uint8_t   cc_id;
  uint8_t   pt_type;
  uint8_t   pt_seq;
  uint32_t  pt_irt;
  uint32_t  pt_ts;
  uint32_t  pt_ts_delta;
} __attribute__((packed));


// ================ CAT Capacity Estimate Headers ================
const size_t kCatCapEstHdrSize = 4;

struct CatCapEstHdr
{
  uint8_t   type;
  uint8_t   est_ho;
  uint16_t  est_lo;
} __attribute__((packed));


// ================ CAT Packet Destination List Headers ================
const size_t kPktDestListHdrSize = 4;

struct PktDestListHdr
{
  uint8_t   type;
  uint8_t   dest_ho;
  uint16_t  dest_lo;
} __attribute__((packed));


// ================ CAT Packet Identification Headers ================
const size_t kPktIdHdrSize = 4;

struct PktIdHdr
{
  uint8_t   type;
  uint8_t   bin_pkt_ho;
  uint16_t  pkt_lo;
} __attribute__((packed));


// ================ CAT Packet History Headers ================
const size_t kPktHistoryHdrSize   = 12;
const size_t kPktHistoryNumBinIds = 11;

struct PktHistoryHdr
{
  uint8_t   type;
  uint8_t   bin_id[kPktHistoryNumBinIds];
} __attribute__((packed));


// ================ CAT Packet Latency Headers ================
const size_t kPktLatencyHdrSize = 8;

struct PktLatencyHdr
{
  uint8_t   type;
  uint8_t   flags;
  uint16_t  origin_ts;
  uint32_t  ttg;
} __attribute__((packed));


#endif // IRON_SLIQ_PACKET_DEFS_H
