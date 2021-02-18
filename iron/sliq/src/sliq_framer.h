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

#ifndef IRON_SLIQ_FRAMER_H
#define IRON_SLIQ_FRAMER_H

#include "sliq_app.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_types.h"

#include "ipv4_endpoint.h"
#include "packet.h"
#include "packet_pool.h"


namespace sliq
{
  class Connection;
  class RecvPacketManager;

  /// The connection close codes.
  enum ConnCloseCode
  {
    SLIQ_CONN_NORMAL_CLOSE = 0,

    SLIQ_CONN_FLOW_CTRL_SENT_TOO_MUCH_DATA = 1,

    SLIQ_CONN_LAST_CLOSE
  };

  /// The connection error codes.
  enum ConnErrorCode
  {
    SLIQ_CONN_NO_ERROR = 0,

    SLIQ_CONN_RECV_CLOSE_ERROR   = 1,
    SLIQ_CONN_SOCKET_WRITE_ERROR = 2,
    SLIQ_CONN_INTERNAL_ERROR     = 3,

    SLIQ_CONN_LAST_ERROR
  };

  /// The stream error codes.
  enum StreamErrorCode
  {
    SLIQ_STREAM_NO_ERROR = 0,

    SLIQ_STREAM_SOCKET_PARTIAL_WRITE_ERROR = 1,
    SLIQ_STREAM_SOCKET_WRITE_ERROR         = 2,
    SLIQ_STREAM_FLOW_CONTROL_ERROR         = 3,
    SLIQ_STREAM_TRANSMIT_QUEUE_ERROR       = 4,

    SLIQ_STREAM_LAST_ERROR
  };

  /// The FEC packet types.  Either a Source Data Packet, or an Encoded Data
  /// Packet.
  enum FecPktType
  {
    FEC_SRC_PKT = 0,
    FEC_ENC_PKT = 1
  };

  /// The ACK block offset types.  Either a single packet ACK block offset, or
  /// a multiple packet ACK block offset.
  enum AckBlkType
  {
    ACK_BLK_SINGLE = 0,
    ACK_BLK_MULTI  = 1
  };

  /// The header types for SLIQ packets.  Determined by the first byte in the
  /// buffer.
  ///
  /// All SLIQ header type values are one byte long, and are within the
  /// following two hexadecimal ranges:
  ///
  ///   Range 0x00-0x0f (decimal 0-15)
  ///   Range 0x20-0x2f (decimal 32-47)
  ///
  /// This leaves the following ranges for other components:
  ///
  ///   Range 0x10-0x1f (decimal 16-31) for BPF packets.
  ///   Range 0x30-0x3f (decimal 48-63) for CAT packets and headers.
  ///   Range 0x40-0x4f (decimal 64-79) for IPv4 headers.
  ///
  /// WARNING: Any changes to these header types must not conflict with the
  /// PacketType definition in iron/common/include/packet.h and the
  /// CatHeaderType definition in iron/bpf/src/path_controller.h.
  enum HeaderType
  {
    // Connection establishment, reset, and close headers.  Cannot be
    // concatenated.
    CONNECTION_HANDSHAKE_HEADER = 0,   // 0x00
    RESET_CONNECTION_HEADER     = 1,   // 0x01
    CLOSE_CONNECTION_HEADER     = 2,   // 0x02

    // Stream creation and reset headers.  Cannot be concatenated.
    CREATE_STREAM_HEADER        = 3,   // 0x03
    RESET_STREAM_HEADER         = 4,   // 0x04

    // Data transfer headers.  Can be concatenated, but any data header must
    // be last.
    DATA_HEADER                 = 32,  // 0x20
    ACK_HEADER                  = 33,  // 0x21
    CC_SYNC_HEADER              = 34,  // 0x22
    RCVD_PKT_CNT_HEADER         = 35,  // 0x23
    CONN_MEAS_HEADER            = 36,  // 0x24

    // Specialized stand-alone headers.  Cannot be concatenated.
    CC_PKT_TRAIN_HEADER         = 40,  // 0x28

    // Special header type value for an unknown header.
    UNKNOWN_HEADER              = 255
  };

  /// The SLIQ connection handshake header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |  # of CC Alg  |          Message Tag          |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                       Packet Timestamp                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                        Echo Timestamp                         |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// | CC Alg Type #1|   Unused  |D|P|             Unused            |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                     CC Alg Parameters #1                      |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// ~                                                               ~
  /// ~                                                               ~
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// | CC Alg Type #N|   Unused  |D|P|             Unused            |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                     CC Alg Parameters #N                      |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                       Unique Client ID                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x00)
  ///   Number of Congestion Control Algorithms (1 byte)
  ///   Message Tag (2 bytes, char string) ("CH", "SH", "CC", or "RJ")
  ///   Packet Timestamp in Microseconds (4 bytes)
  ///   Echo Timestamp in Microseconds (4 bytes)
  ///   Series of Congestion Control Algorithms:
  ///     Congestion Control Algorithm Type (1 byte)
  ///     Flags (1 byte) (uuuuuudp)
  ///       uuuuuu - Unused (6 bits)
  ///       d      - Deterministic, Copa Beta 1 Only (1 bit)
  ///       p      - Pacing, Cubic/Reno Only (1 bit)
  ///     Unused (2 bytes)
  ///     Congestion Control Parameters (4 bytes)
  ///   Unique Client Identifier (4 bytes)
  /// \endverbatim
  ///
  /// Length = 16 bytes + (num_cc_alg * 8 bytes).
  ///
  /// This header uses specialized reliability and retransmission rules.
  struct ConnHndshkHeader
  {
    ConnHndshkHeader();
    ConnHndshkHeader(uint8_t num_alg, MsgTag tag, PktTimestamp ts,
                     PktTimestamp echo_ts, ClientId id, CongCtrl* alg);
    virtual ~ConnHndshkHeader() {}
    size_t ConvertToCongCtrl(CongCtrl* alg, size_t max_alg);

    uint8_t       num_cc_algs;
    MsgTag        message_tag;
    PktTimestamp  timestamp;
    PktTimestamp  echo_timestamp;
    ClientId      client_id;

    struct
    {
      CongCtrlAlg  congestion_control_alg;
      bool         deterministic_flag;
      bool         pacing_flag;
      uint32_t     congestion_control_params;
    } cc_alg[SliqApp::kMaxCcAlgPerConn];
  };

  /// The SLIQ reset connection header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |Flags (Unused) |          Error Code           |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x01)
  ///   Flags (1 byte) (uuuuuuuu)
  ///     uuuuuuuu - Unused (8 bits)
  ///   Error Code (2 bytes)
  /// \endverbatim
  ///
  /// Length = 4 bytes.
  ///
  /// This header is best effort.
  struct ResetConnHeader
  {
    ResetConnHeader();
    ResetConnHeader(ConnErrorCode error);
    virtual ~ResetConnHeader() {}

    ConnErrorCode  error_code;
  };

  /// The SLIQ close connection header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |   Unused    |A|          Reason Code          |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x02)
  ///   Flags (1 byte) (uuuuuuua)
  ///     uuuuuuu - Unused (7 bits)
  ///     a       - ACK (1 bit)
  ///   Reason Code (2 bytes)
  /// \endverbatim
  ///
  /// Length = 4 bytes.
  ///
  /// This header uses specialized reliability and retransmission rules.
  struct CloseConnHeader
  {
    CloseConnHeader();
    CloseConnHeader(bool ack, ConnCloseCode reason);
    virtual ~CloseConnHeader() {}

    bool           ack_flag;
    ConnCloseCode  reason_code;
  };

  /// The SLIQ create stream header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |  Unused   |T|A|   Stream ID   |   Priority    |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                      Initial Window Size                      |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                Initial Packet Sequence Number                 |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |  Del  |  Rel  | Rexmit Limit  | FEC Target Delivery Rnds/Time |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |FEC Target Pkt Recv Probability|            Unused             |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x03)
  ///   Flags (1 byte) (uuuuuuta)
  ///     uuuuuu - Unused (6 bits)
  ///     t      - Delivery Time, ARQ+FEC Mode Only (1 bit)
  ///     a      - ACK (1 bit)
  ///   Stream ID (1 byte)
  ///   Priority (1 byte)
  ///   Initial Window Size in Packets (4 bytes)
  ///   Initial Packet Sequence Number (4 bytes)
  ///   Delivery Mode (4 bits)
  ///   Reliability Mode (4 bits)
  ///   Semi-Reliable Packet Retransmission Limit (1 byte)
  ///   FEC Target Delivery Rounds or Time in Milliseconds (2 bytes)
  ///     Rounds if (Delivery Time == 0), time if (Delivery Time == 1)
  ///   FEC Target Packet Receive Probability Times 10000, 1-9990 (2 bytes)
  ///   Unused (2 bytes)
  /// \endverbatim
  ///
  /// Length = 20 bytes.
  ///
  /// This header uses specialized reliability and retransmission rules.
  struct CreateStreamHeader
  {
    CreateStreamHeader();
    CreateStreamHeader(bool tm, bool ack, StreamId sid, Priority prio,
                       WindowSize win_size, PktSeqNumber seq_num,
                       DeliveryMode del_mode, ReliabilityMode rel_mode,
                       RexmitLimit limit, RexmitRounds del_rnds,
                       double del_time, double recv_p);
    virtual ~CreateStreamHeader() {}
    void GetReliability(Reliability& rel);

    bool             del_time_flag;
    bool             ack_flag;
    StreamId         stream_id;
    Priority         priority;
    WindowSize       initial_win_size_pkts;
    PktSeqNumber     initial_seq_num;
    DeliveryMode     delivery_mode;
    ReliabilityMode  reliability_mode;
    RexmitLimit      rexmit_limit;
    RexmitRounds     fec_target_pkt_del_rounds;
    double           fec_target_pkt_del_time_sec;
    double           fec_target_pkt_recv_prob;
  };

  /// The SLIQ reset stream header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |Flags (Unused) |   Stream ID   |  Error Code   |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                 Final Packet Sequence Number                  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x04)
  ///   Flags (1 byte) (uuuuuuuu)
  ///     uuuuuuuu - Unused (8 bits)
  ///   Stream ID (1 byte)
  ///   Error Code (1 byte)
  ///   Final Packet Sequence Number (4 bytes)
  /// \endverbatim
  ///
  /// Length = 8 bytes.
  ///
  /// This header is best effort.
  struct ResetStreamHeader
  {
    ResetStreamHeader();
    ResetStreamHeader(StreamId sid, StreamErrorCode error,
                      PktSeqNumber seq_num);
    virtual ~ResetStreamHeader() {}

    StreamId         stream_id;
    StreamErrorCode  error_code;
    PktSeqNumber     final_seq_num;
  };

  /// The SLIQ data header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |U|L|E|M| U |P|F|   Stream ID   | Number of TTG |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     CC ID     | Rexmit Count  |    Payload Length in Bytes    |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                    Packet Sequence Number                     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                       Packet Timestamp                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                    Packet Timestamp Delta                     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |             Move Forward Packet Sequence Number*              |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |T|U|  Index*   |NumSrc*|Round* |           Group ID*           |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |    Encoded Packet Length*     |        Time-To-Go #1*         |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |        Time-To-Go #2*         |        Time-To-Go #3*         |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// ~                                                               ~
  /// ~                                                               ~
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |        Time-To-Go #N*         |            Payload            |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
  /// |                                                               |
  /// ~                                                               ~
  /// ~                                                               ~
  /// |                                                               |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  /// Optional fields are denoted with (*).  The "T" and "U" fields in the FEC
  /// fields are also optional.
  ///
  ///   Header Type (1 byte) (0x20)
  ///   Flags (1 byte) (ulemuupf)
  ///     u  - Unused (1 bit)
  ///     l  - Encoded Packet Length Present (1 bit)
  ///     e  - Forward Error Correction (FEC) Fields Present (1 bit)
  ///     m  - Move Forward Present (1 bit)
  ///     uu - Unused (2 bits)
  ///     p  - Persist (1 bit)
  ///     f  - FIN (1 bit)
  ///   Stream ID (1 byte)
  ///   Number of Time-To-Go Values (1 byte)
  ///   Congestion Control Identifier (1 byte)
  ///   Retransmission Count (1 byte)
  ///   Payload Length in Bytes (2 bytes)
  ///   Packet Sequence Number (4 bytes)
  ///   Packet Timestamp in Microseconds (4 bytes)
  ///   Packet Timestamp Delta in Microseconds (4 bytes)
  ///
  ///   Present if (Move Forward Present == 1):
  ///     Move Forward Packet Sequence Number (4 bytes)
  ///
  ///   Present if (FEC Fields Present == 1):
  ///     FEC Packet Type (1 bit)
  ///       0 = Original Packet (aka Source Data Packet)
  ///       1 = FEC Packet (aka Encoded Data Packet)
  ///     Unused (1 bit)
  ///     Group Index within the FEC Group, 0-63 (6 bits)
  ///     Number of FEC Source Packets in FEC Group, 0-15 (4 bits)
  ///       Must be 0 if (FEC Packet Type == 0)
  ///     Round Number in FEC Group, 0-15 (4 bits)
  ///     FEC Group Identifier (2 bytes)
  ///
  ///   Present if (Encoded Packet Length Present == 1):
  ///     Encoded Packet Length (2 bytes)
  ///
  ///   Series of Time-To-Go (TTG) Values:
  ///     Time-To-Go (2 bytes)
  ///       If the MSB is 0, then the remaining 15 bits contain a time-to-go
  ///         value in the range (0.0 seconds <= TTG <= 1.0 seconds):
  ///           time_to_go = (15_bit_value / 32767.0) seconds
  ///       If the MSB is 1, then the remaining 15 bits contain a time-to-go
  ///         value in the range (1.0 seconds < TTG <= 33.767 seconds):
  ///           time_to_go = (1.0 + (15_bit_value / 1000.0)) seconds
  ///
  ///   Payload (variable)
  /// \endverbatim
  ///
  /// Length = 20 bytes + (m_bit * 4 bytes) + (e_bit * 4 bytes) +
  ///          (l_bit * 2 bytes) + (num_ttg * 2 bytes) + payload_len_bytes.
  ///
  /// This header, plus any payload, is reliable via the ACK header and/or
  /// FEC.
  ///
  /// This header may be concatenated with ACK, Congestion Control
  /// Synchronization, Received Packet Count, and Connection Measurement
  /// headers into a single UDP packet, but only one Data header may be
  /// included and the Data header (plus any payload) must come last.
  struct DataHeader
  {
    DataHeader();
    DataHeader(bool epl, bool fec, bool move_fwd, bool persist, bool fin,
               StreamId sid, TtgCount ttgs, CcId id, RetransCount rx_cnt,
               PktSeqNumber seq_num, PktTimestamp ts, PktTimestamp ts_delta,
               PktSeqNumber mf_seq_num, FecPktType fec_type, FecSize fec_idx,
               FecSize fec_src, FecRound fec_rnd, FecGroupId fec_grp,
               FecEncPktLen enc_pkt_len);
    virtual ~DataHeader() {}

    bool              enc_pkt_len_flag;
    bool              fec_flag;
    bool              move_fwd_flag;
    bool              persist_flag;
    bool              fin_flag;
    StreamId          stream_id;
    TtgCount          num_ttg;
    CcId              cc_id;
    RetransCount      retransmission_count;
    PktSeqNumber      sequence_number;
    PktTimestamp      timestamp;
    PktTimestamp      timestamp_delta;
    PktSeqNumber      move_fwd_seq_num;
    FecPktType        fec_pkt_type;
    FecSize           fec_group_index;
    FecSize           fec_num_src;
    FecRound          fec_round;
    FecGroupId        fec_group_id;
    FecEncPktLen      encoded_pkt_length;
    double            ttg[kMaxTtgs];

    size_t         payload_offset;
    size_t         payload_length;
    iron::Packet*  payload;
  };

  /// The SLIQ ACK header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |Flags (Unused) |   Stream ID   | #OPT|   #ABO  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |             Next Expected Packet Sequence Number              |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                       Packet Timestamp                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                    Packet Timestamp Delta                     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |              Observed Packet Sequence Number #1               |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                 Observed Packet Timestamp #1                  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |              Observed Packet Sequence Number #2               |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                 Observed Packet Timestamp #2                  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// ~                                                               ~
  /// ~                                                               ~
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |              Observed Packet Sequence Number #N               |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                 Observed Packet Timestamp #N                  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |T|     ACK Block Offset #1     |T|     ACK Block Offset #2     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// ~                                                               ~
  /// ~                                                               ~
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |T|     ACK Block Offset #N     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  /// Each ACK Block Offset is a 1-bit type and a 15-bit unsigned integer
  /// offset from the Next Expected Sequence Number contained in the ACK
  /// header.  An ACK Block may consist of a single packet being ACKed (one
  /// ACK Block Offset of Type 0 for the packet) or multiple packets being
  /// ACKed (two sequential ACK Block Offsets of Type 1, the first for the
  /// first packet in the block, the second for the last packet in the block).
  /// If all packets have been received, then the Next Expected Sequence
  /// Number is set to the largest observed packet sequence number plus one,
  /// and no ACK Block Offsets are included.  If there are missing packets,
  /// then the Next Expected Sequence Number is set to the first missing
  /// packet, the first ACK Block must include the ACK for the latest packet
  /// received, and one of the ACK Blocks must include the largest observed
  /// packet sequence number.
  ///
  ///   Header Type (1 byte) (0x21)
  ///   Flags (1 byte) (uuuuuuuu)
  ///     uuuuuuuu - Unused (8 bits)
  ///   Stream ID (1 byte)
  ///   Number of Observed Packet Times (3 bits)
  ///   Number of ACK Block Offsets (5 bits)
  ///   Next Expected Packet Sequence Number (4 bytes)
  ///   Packet Timestamp in Microseconds (4 bytes)
  ///   Packet Timestamp Delta in Microseconds (4 bytes)
  ///
  ///   Series of Observed Packet Times:
  ///     Observed Packet Sequence Number (4 bytes)
  ///     Observed Packet Timestamp in Microseconds (4 bytes)
  ///
  ///   Series of ACK Block Offsets:
  ///     Type (1 bit)
  ///       0 = Single Packet ACK Block
  ///       1 = ACK Block Start/End (Two Sequential ACK Block Offsets)
  ///     Offset From Next Expected Sequence Number (15 bits)
  /// \endverbatim
  ///
  /// Length = 16 bytes + (num_times * 8 bytes) + (num_blocks * 2 bytes).
  ///
  /// This header is best effort.
  ///
  /// This header may be concatenated with Data, Congestion Control
  /// Synchronization, Received Packet Count, and Connection Measurement
  /// headers into a single UDP packet.
  struct AckHeader
  {
    AckHeader();
    AckHeader(StreamId sid, PktSeqNumber ne_seq, PktTimestamp ts,
              PktTimestamp ts_delta);
    virtual ~AckHeader() {}

    StreamId      stream_id;
    uint8_t       num_observed_times;
    uint8_t       num_ack_block_offsets;
    PktSeqNumber  next_expected_seq_num;
    PktTimestamp  timestamp;
    PktTimestamp  timestamp_delta;

    struct
    {
      PktSeqNumber  seq_num;
      PktTimestamp  timestamp;
    } observed_time[kMaxObsTimes];

    struct
    {
      AckBlkType  type;
      uint16_t    offset;
    } ack_block_offset[kMaxAckBlockOffsets];
  };

  /// The SLIQ congestion control synchronization header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |     CC ID     |        Sequence Number        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                        CC Parameter(s)                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x22)
  ///   Congestion Control Identifier (1 byte)
  ///   Sequence Number (2 bytes)
  ///   Congestion Control Parameter(s) (4 bytes)
  /// \endverbatim
  ///
  /// Length = 8 bytes.
  ///
  /// This header is best effort.
  ///
  /// This header may be concatenated with Data, ACK, Received Packet Count,
  /// and Connection Measurement headers into a single UDP packet.
  struct CcSyncHeader
  {
    CcSyncHeader();
    CcSyncHeader(CcId id, uint16_t sn, uint32_t params);
    virtual ~CcSyncHeader() {}

    CcId      cc_id;
    uint16_t  seq_num;
    uint32_t  cc_params;
  };

  /// The SLIQ received packet count header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |Flags (Unused) |   Stream ID   | Rexmit Count  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                    Packet Sequence Number                     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |             Connection Received Data Packet Count             |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x23)
  ///   Flags (1 byte) (uuuuuuuu)
  ///     uuuuuuuu - Unused (8 bits)
  ///   Last Received Data Packet Stream ID (1 byte)
  ///   Last Received Data Packet Retransmission Count (1 byte)
  ///   Last Received Data Packet Sequence Number (4 bytes)
  ///   Connection Received Data Packet Count (4 bytes)
  /// \endverbatim
  ///
  /// Length = 12 bytes.
  ///
  /// This header is best effort.
  ///
  /// This header may be concatenated with Data, ACK, Congestion Control
  /// Synchronization, and Connection Measurement headers into a single UDP
  /// packet.
  struct RcvdPktCntHeader
  {
    RcvdPktCntHeader();
    RcvdPktCntHeader(StreamId sid, RetransCount rexmit_cnt,
                     PktSeqNumber seq_num, PktCount cnt);
    virtual ~RcvdPktCntHeader() {}

    StreamId      stream_id;
    RetransCount  retransmission_count;
    PktSeqNumber  sequence_number;
    PktCount      rcvd_data_pkt_count;
  };

  /// The SLIQ connection measurement header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |O|   Unused    |        Sequence Number        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |            Maximum Remote-To-Local One-Way Delay*             |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  /// Optional fields are denoted with (*).  Optional fields that are present
  /// must appear in the order listed above.
  ///
  ///   Header Type (1 byte) (0x24)
  ///   Flags (1 byte) (ouuuuuuu)
  ///     o       - Maximum Remote-To-Local One-Way Delay Present (1 bit)
  ///     uuuuuuu - Unused (7 bits)
  ///   Sequence Number (2 bytes)
  ///
  ///   Present if (Maximum Remote-To-Local One-Way Delay Present == 1):
  ///     Maximum Remote-To-Local One-Way Delay in Microseconds (4 bytes)
  /// \endverbatim
  ///
  /// Length = 4 bytes + (o_bit * 4 bytes).
  ///
  /// This header is best effort.
  ///
  /// This header may be concatenated with Data, ACK, Congestion Control
  /// Synchronization, and Received Packet Count headers into a single UDP
  /// packet.
  struct ConnMeasHeader
  {
    ConnMeasHeader();
    ConnMeasHeader(bool owd, uint16_t sn, uint32_t max_owd);
    virtual ~ConnMeasHeader() {}

    bool      owd_flag;
    uint16_t  sequence_number;
    uint32_t  max_rmt_to_loc_owd;
  };

  /// The SLIQ congestion control packet train header.
  ///
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |     Type      |     CC ID     |  PT Pkt Type  |   PT Seq Num  |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                Packet Pair Inter-Receive Time                 |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                       Packet Timestamp                        |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                    Packet Timestamp Delta                     |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |                            Payload                            |
  /// ~                                                               ~
  /// ~                                                               ~
  /// |                                                               |
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ///
  ///   Header Type (1 byte) (0x28)
  ///   Congestion Control Identifier (1 byte)
  ///   Packet Train Packet Type (1 byte)
  ///   Packet Train Sequence Number (1 byte)
  ///   Packet Pair Inter-Receive Time in Microseconds (4 bytes)
  ///   Packet Timestamp in Microseconds (4 bytes)
  ///   Packet Timestamp Delta in Microseconds (4 bytes)
  ///   Payload (variable)
  /// \endverbatim
  ///
  /// Length = 16 bytes + payload.
  ///
  /// This header is best effort.
  struct CcPktTrainHeader
  {
    CcPktTrainHeader();
    CcPktTrainHeader(CcId id, uint8_t type, uint8_t seq, uint32_t irt,
                     PktTimestamp ts, PktTimestamp ts_delta);
    virtual ~CcPktTrainHeader() {}

    CcId          cc_id;
    uint8_t       pt_pkt_type;
    uint8_t       pt_seq_num;
    uint32_t      pt_inter_recv_time;
    PktTimestamp  pt_timestamp;
    PktTimestamp  pt_timestamp_delta;
  };

  /// The SLIQ packet framer.  This class is responsible for generating and
  /// parsing all of the SLIQ headers.
  class Framer
  {

   public:

    /// \brief Constructor.
    explicit Framer(iron::PacketPool& packet_pool);

    /// \brief Destructor.
    virtual ~Framer();

    /// \brief Generate a SLIQ packet with a connection handshake header.
    ///
    /// \param  input  The header input data.
    ///
    /// \return  The generated packet if successful, or NULL if an error
    ///          occurs during packet generation.
    iron::Packet* GenerateConnHndshk(const ConnHndshkHeader& input);

    /// \brief Generate a SLIQ packet with a reset connection header.
    ///
    /// \param  input  The header input data.
    ///
    /// \return  The generated packet if successful, or NULL if an error
    ///          occurs during packet generation.
    iron::Packet* GenerateResetConn(const ResetConnHeader& input);

    /// \brief Generate a SLIQ packet with a close connection header.
    ///
    /// \param  input  The header input data.
    ///
    /// \return  The generated packet if successful, or NULL if an error
    ///          occurs during packet generation.
    iron::Packet* GenerateCloseConn(const CloseConnHeader& input);

    /// \brief Generate a SLIQ packet with a create stream header.
    ///
    /// \param  input  The header input data.
    ///
    /// \return  The generated packet if successful, or NULL if an error
    ///          occurs during packet generation.
    iron::Packet* GenerateCreateStream(const CreateStreamHeader& input);

    /// \brief Generate a SLIQ packet with a reset stream header.
    ///
    /// \param  input  The header input data.
    ///
    /// \return  The generated packet if successful, or NULL if an error
    ///          occurs during packet generation.
    iron::Packet* GenerateResetStream(const ResetStreamHeader& input);

    /// \brief Append a SLIQ data header.
    ///
    /// \param  packet          A reference to a pointer to the packet where
    ///                         the data header will be appended.  If NULL,
    ///                         then a packet will be generated and placed in
    ///                         this pointer.
    /// \param  input           The header input data.
    /// \param  payload_length  The length of the payload data in bytes to set
    ///                         in the data header.
    ///
    /// \return  True on success, or false otherwise.
    bool AppendDataHeader(iron::Packet*& packet, const DataHeader& input,
                          size_t payload_length);

    /// \brief Append a SLIQ ACK header.
    ///
    /// \param  packet  A reference to a pointer to the packet where the ACK
    ///                 header will be appended.  If NULL, then a packet will
    ///                 be generated and placed in this pointer.
    /// \param  input   The header input data.
    ///
    /// \return  True on success, or false otherwise.
    bool AppendAckHeader(iron::Packet*& packet, const AckHeader& input);

    /// \brief Append a SLIQ congestion control synchronization header.
    ///
    /// \param  packet  A reference to a pointer to the packet where the CC
    ///                 sync header will be appended.  If NULL, then a packet
    ///                 will be generated and placed in this pointer.
    /// \param  input   The header input data.
    ///
    /// \return  True on success, or false otherwise.
    bool AppendCcSyncHeader(iron::Packet*& packet, const CcSyncHeader& input);

    /// \brief Append a SLIQ received packet count header.
    ///
    /// \param  packet  A reference to a pointer to the packet where the
    ///                 received packet count header will be appended.  If
    ///                 NULL, then a packet will be generated and placed in
    ///                 this pointer.
    /// \param  input   The header input data.
    ///
    /// \return  True on success, or false otherwise.
    bool AppendRcvdPktCntHeader(iron::Packet*& packet,
                                const RcvdPktCntHeader& input);

    /// \brief Append a SLIQ connection measurement header.
    ///
    /// \param  packet  A reference to a pointer to the packet where the
    ///                 received packet count header will be appended.  If
    ///                 NULL, then a packet will be generated and placed in
    ///                 this pointer.
    /// \param  input   The header input data.
    ///
    /// \return  True on success, or false otherwise.
    bool AppendConnMeasHeader(iron::Packet*& packet,
                              const ConnMeasHeader& input);

    /// \brief Generate a SLIQ packet with a congestion control packet train
    /// header followed by a payload of the specified length.
    ///
    /// \param  input           The header input data.
    /// \param  payload_length  The length of the payload data.
    ///
    /// \return  The generated packet if successful, or NULL if an error
    ///          occurs during packet generation.
    iron::Packet* GenerateCcPktTrain(const CcPktTrainHeader& input,
                                     size_t payload_length);

    /// \brief Determine the type of SLIQ header at a given packet offset.
    ///
    /// \param  packet  The packet.
    /// \param  offset  The byte offset into the packet where the SLIQ header
    ///                 begins.
    ///
    /// \return  The type of SLIQ header.
    HeaderType GetHeaderType(const iron::Packet* packet, size_t offset);

    /// \brief Parse a SLIQ connection handshake header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ
    ///                 connection handshake header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseConnHndshkHeader(const iron::Packet* packet, size_t& offset,
                               ConnHndshkHeader& output);

    /// \brief Parse a SLIQ reset connection header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ reset
    ///                 connection header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseResetConnHeader(const iron::Packet* packet, size_t& offset,
                              ResetConnHeader& output);

    /// \brief Parse a SLIQ close connection header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ close
    ///                 connection header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseCloseConnHeader(const iron::Packet* packet, size_t& offset,
                              CloseConnHeader& output);

    /// \brief Parse a SLIQ create stream header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ create
    ///                 stream header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseCreateStreamHeader(const iron::Packet* packet, size_t& offset,
                                 CreateStreamHeader& output);

    /// \brief Parse a SLIQ reset stream header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ reset
    ///                 stream header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseResetStreamHeader(const iron::Packet* packet, size_t& offset,
                                ResetStreamHeader& output);

    /// \brief Parse a SLIQ data header and its payload.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ data
    ///                 header begins.
    /// \param  output  The parsed header, including the payload.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseDataHeader(iron::Packet* packet, size_t& offset,
                         DataHeader& output);

    /// \brief Parse a SLIQ ACK header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ ACK
    ///                 header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseAckHeader(const iron::Packet* packet, size_t& offset,
                        AckHeader& output);

    /// \brief Parse a SLIQ congestion control synchronization header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ CC sync
    ///                 header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseCcSyncHeader(const iron::Packet* packet, size_t& offset,
                           CcSyncHeader& output);

    /// \brief Parse a received packet count header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the received
    ///                 packet count header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseRcvdPktCntHeader(const iron::Packet* packet, size_t& offset,
                               RcvdPktCntHeader& output);

    /// \brief Parse a received connection measurement header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the received
    ///                 connection measurement header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseConnMeasHeader(const iron::Packet* packet, size_t& offset,
                             ConnMeasHeader& output);

    /// \brief Parse a SLIQ congestion control packet train header.
    ///
    /// \param  packet  The packet that is being parsed.
    /// \param  offset  The byte offset into the packet where the SLIQ
    ///                 congestion control packet train header begins.
    /// \param  output  The parsed header.
    ///
    /// \return  True if the header is parsed successfully, or false
    ///          otherwise.
    bool ParseCcPktTrainHeader(const iron::Packet* packet, size_t& offset,
                               CcPktTrainHeader& output);

    /// \brief Determine the size of the SLIQ data header if it were to be
    /// generated, not including the payload.
    ///
    /// \param  hdr  A reference to the data header.
    ///
    /// \return  The size of the generated data header in bytes.
    inline static size_t ComputeDataHeaderSize(DataHeader& hdr)
    {
      return(kDataHdrBaseSize +
             (hdr.move_fwd_flag ? kDataHdrMoveFwdSize : 0) +
             (hdr.fec_flag ? kDataHdrFecSize : 0) +
             (hdr.enc_pkt_len_flag ? kDataHdrEncPktLenSize : 0) +
             (hdr.num_ttg * kDataHdrTtgSize));
    }

    /// \brief Determine the size of the SLIQ ACK header if it were to be
    /// generated.
    ///
    /// \param  input  The header input data.
    ///
    /// \return  The size of the generated ACK header in bytes.
    inline static size_t ComputeAckHeaderSize(const AckHeader& input)
    {
      return(kAckHdrBaseSize +
             ((input.num_observed_times & 0x07) * kAckHdrObsTimeSize) +
             ((input.num_ack_block_offsets & 0x1f) *
              kAckHdrAckBlockOffsetSize));
    }

   private:

    /// \brief Copy constructor.
    Framer(const Framer& other);

    /// \brief Copy operator.
    Framer& operator=(const Framer& other);

    /// \brief Write a uint8_t value to a SLIQ packet.
    ///
    /// \param  value   The value to be written to the packet.
    /// \param  packet  The packet into which the value will be placed.
    ///
    /// \return  True if successful, or false otherwise.
    bool WriteUint8(uint8_t value, iron::Packet* packet);

    /// \brief Write a uint16_t value to a SLIQ packet.
    ///
    /// The value is written to the packet in network byte order.
    ///
    /// \param  value   The value to be written to the packet in host byte
    ///                 order.
    /// \param  packet  The packet into which the value will be placed.
    ///
    /// \return  True if successful, or false otherwise.
    bool WriteUint16(uint16_t value, iron::Packet* packet);

    /// \brief Write 24 bits of a uint32_t value to a SLIQ packet.
    ///
    /// The value is written to the packet in network byte order.
    ///
    /// \param  value   The value to be written to the packet in host byte
    ///                 order.
    /// \param  packet  The packet into which the value will be placed.
    ///
    /// \return  True if successful, or false otherwise.
    bool WriteUint24(uint32_t value, iron::Packet* packet);

    /// \brief Write a uint32_t value to a SLIQ packet.
    ///
    /// The value is written to the packet in network byte order.
    ///
    /// \param  value   The value to be written to the packet in host byte
    ///                 order.
    /// \param  packet  The packet into which the value will be placed.
    ///
    /// \return  True if successful, or false otherwise.
    bool WriteUint32(uint32_t value, iron::Packet* packet);

    /// \brief Write a int32_t value to a SLIQ packet.
    ///
    /// The value is written to the packet in network byte order.
    ///
    /// \param  value   The value to be written to the packet in host byte
    ///                 order.
    /// \param  packet  The packet into which the value will be placed.
    ///
    /// \return  True if successful, or false otherwise.
    bool WriteInt32(int32_t value, iron::Packet* packet);

    /// \brief Read a uint8_t value from a SLIQ packet.
    ///
    /// \param  packet  The packet from which the value will be read.
    /// \param  offset  The offset into the packet buffer from which to start
    ///                 the read.
    /// \param  result  The resulting value.
    ///
    /// \return  True if successful, or false otherwise.
    bool ReadUint8(const iron::Packet* packet, size_t& offset,
                   uint8_t& result);

    /// \brief Read a uint16_t value from a SLIQ packet.
    ///
    /// The field within the packet must be in network byte order.
    ///
    /// \param  packet  The packet from which the value will be read.
    /// \param  offset  The offset into the packet buffer from which to start
    ///                 the read.
    /// \param  result  The resulting value in host byte order.
    ///
    /// \return  True if successful, or false otherwise.
    bool ReadUint16(const iron::Packet* packet, size_t& offset,
                    uint16_t& result);

    /// \brief Read 24 bits of a uint32_t value from a SLIQ packet.
    ///
    /// The field within the packet must be in network byte order.
    ///
    /// \param  packet  The packet from which the value will be read.
    /// \param  offset  The offset into the packet buffer from which to start
    ///                 the read.
    /// \param  result  The resulting value in host byte order.
    ///
    /// \return  True if successful, or false otherwise.
    bool ReadUint24(const iron::Packet* packet, size_t& offset,
                    uint32_t& result);

    /// \brief Read a uint32_t value from a SLIQ packet.
    ///
    /// The field within the packet must be in network byte order.
    ///
    /// \param  packet  The packet from which the value will be read.
    /// \param  offset  The offset into the packet buffer from which to start
    ///                 the read.
    /// \param  result  The resulting value in host byte order.
    ///
    /// \return  True if successful, or false otherwise.
    bool ReadUint32(const iron::Packet* packet, size_t& offset,
                    uint32_t& result);

    /// \brief Read an int32_t value from a SLIQ packet.
    ///
    /// The field within the packet must be in network byte order.
    ///
    /// \param  packet  The packet from which the value will be read.
    /// \param  offset  The offset into the packet buffer from which to start
    ///                 the read.
    /// \param  result  The resulting value in host byte order.
    ///
    /// \return  True if successful, or false otherwise.
    bool ReadInt32(const iron::Packet* packet, size_t& offset,
                   int32_t& result);

    /// Pool containing packets to use.
    iron::PacketPool&  packet_pool_;

  }; // end class Framer

} // namespace sliq

#endif // IRON_SLIQ_FRAMER_H
