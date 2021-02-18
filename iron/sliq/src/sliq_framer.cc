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

#include "sliq_framer.h"

#include "log.h"
#include "iron_constants.h"
#include "packet.h"
#include "packet_pool.h"
#include "unused.h"

#include <cstring>
#include <inttypes.h>


using ::sliq::AckHeader;
using ::sliq::CcPktTrainHeader;
using ::sliq::CcSyncHeader;
using ::sliq::CloseConnHeader;
using ::sliq::ConnHndshkHeader;
using ::sliq::ConnMeasHeader;
using ::sliq::CreateStreamHeader;
using ::sliq::DataHeader;
using ::sliq::Framer;
using ::sliq::HeaderType;
using ::sliq::RcvdPktCntHeader;
using ::sliq::ResetConnHeader;
using ::sliq::ResetStreamHeader;
using ::iron::Packet;
using ::iron::PacketPool;


namespace
{
  // The class name for logging.
  const char*  UNUSED(kClassName) = "Framer";
}


//============================================================================
Framer::Framer(PacketPool& packet_pool)
  : packet_pool_(packet_pool)
{
}

//============================================================================
Framer::~Framer()
{
}

//============================================================================
Packet* Framer::GenerateConnHndshk(const ConnHndshkHeader& input)
{
  // Get a packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return NULL;
  }

  // Do not exceed the input array size.
  uint8_t  cnt = ((input.num_cc_algs > SliqApp::kMaxCcAlgPerConn) ?
                  SliqApp::kMaxCcAlgPerConn : input.num_cc_algs);

  // Build the header.
  if ((!WriteUint8(CONNECTION_HANDSHAKE_HEADER, packet)) ||
      (!WriteUint8(cnt, packet)) ||
      (!WriteUint16(input.message_tag, packet)) ||
      (!WriteUint32(input.timestamp, packet)) ||
      (!WriteUint32(input.echo_timestamp, packet)))
  {
    LogE(kClassName, __func__, "Error generating connection handshake "
         "header.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  // Append all of the congestion control algorithm settings.
  for (uint8_t i = 0; i < cnt; ++i)
  {
    // Generate the flags field.
    uint8_t  flags = ((input.cc_alg[i].deterministic_flag ? 0x02 : 0x00) |
                      (input.cc_alg[i].pacing_flag ? 0x01 : 0x00));

    if ((!WriteUint8(static_cast<uint8_t>(
                       input.cc_alg[i].congestion_control_alg), packet)) ||
        (!WriteUint8(flags, packet)) ||
        (!WriteUint16(0, packet)) ||
        (!WriteUint32(input.cc_alg[i].congestion_control_params, packet)))
    {
      LogE(kClassName, __func__, "Error generating connection handshake "
           "CC params.\n");
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
      return NULL;
    }
  }

  // Append the unique client ID.
  if (!WriteUint32(input.client_id, packet))
  {
    LogE(kClassName, __func__, "Error generating connection handshake client "
         "ID.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  return packet;
}

//============================================================================
Packet* Framer::GenerateResetConn(const ResetConnHeader& input)
{
  // Get a packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return NULL;
  }

  // Generate the flags field.
  uint8_t  flags = 0;

  // Build the header.
  if ((!WriteUint8(RESET_CONNECTION_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint16(input.error_code, packet)))
  {
    LogE(kClassName, __func__, "Error generating reset connection header.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  return packet;
}

//============================================================================
Packet* Framer::GenerateCloseConn(const CloseConnHeader& input)
{
  // Get a packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return NULL;
  }

  // Generate the flags field.
  uint8_t  flags = (input.ack_flag ? 0x01 : 0x00);

  // Build the header.
  if ((!WriteUint8(CLOSE_CONNECTION_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint16(input.reason_code, packet)))
  {
    LogE(kClassName, __func__, "Error generating close connection header.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  return packet;
}

//============================================================================
Packet* Framer::GenerateCreateStream(const CreateStreamHeader& input)
{
  // Get a packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return NULL;
  }

  // Generate the necessary fields.
  uint8_t   flags   = ((input.del_time_flag ? 0x02 : 0x00) |
                       (input.ack_flag ? 0x01 : 0x00));
  uint8_t   del_rel = (((static_cast<uint8_t>(input.delivery_mode) & 0x0f)
                        << 4) |
                       (static_cast<uint8_t>(input.reliability_mode) & 0x0f));
  uint16_t  tgt_del = 0;
  uint16_t  tgt_rcv = 0;

  if (input.reliability_mode == SEMI_RELIABLE_ARQ_FEC)
  {
    if (input.del_time_flag)
    {
      tgt_del = (static_cast<uint16_t>((input.fec_target_pkt_del_time_sec *
                                        1000.0) + 0.5));
    }
    else
    {
      tgt_del = input.fec_target_pkt_del_rounds;
    }

    tgt_rcv = (static_cast<uint16_t>((input.fec_target_pkt_recv_prob *
                                      10000.0) + 0.5));
  }

  // Build the header.
  if ((!WriteUint8(CREATE_STREAM_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint8(input.stream_id, packet)) ||
      (!WriteUint8(input.priority, packet)) ||
      (!WriteUint32(input.initial_win_size_pkts, packet)) ||
      (!WriteUint32(input.initial_seq_num, packet)) ||
      (!WriteUint8(del_rel, packet)) ||
      (!WriteUint8(input.rexmit_limit, packet)) ||
      (!WriteUint16(tgt_del, packet)) ||
      (!WriteUint16(tgt_rcv, packet)) ||
      (!WriteUint16(0, packet)))
  {
    LogE(kClassName, __func__, "Error generating create stream header.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  return packet;
}

//============================================================================
Packet* Framer::GenerateResetStream(const ResetStreamHeader& input)
{
  // Get a packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return NULL;
  }

  // Generate the flags field.
  uint8_t  flags = 0;

  // Build the header.
  if ((!WriteUint8(RESET_STREAM_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint8(input.stream_id, packet)) ||
      (!WriteUint8(input.error_code, packet)) ||
      (!WriteUint32(input.final_seq_num, packet)))
  {
    LogE(kClassName, __func__, "Error generating reset stream header.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  return packet;
}

//============================================================================
bool Framer::AppendDataHeader(Packet*& packet, const DataHeader& input,
                              size_t payload_length)
{
  // Verify the number of time-to-go (TTG) values first.
  if (input.num_ttg > kMaxTtgs)
  {
    LogE(kClassName, __func__, "Error, invalid number of TTGs %" PRITtgCount
         ".\n", input.num_ttg);
    return false;
  }

  if (packet == NULL)
  {
    packet = packet_pool_.Get();

    if (packet == NULL)
    {
      LogE(kClassName, __func__, "Error getting packet from pool.\n");
      return false;
    }
  }

  // Generate the flags field.
  uint8_t  flags = ((input.enc_pkt_len_flag ? 0x40 : 0x00) |
                    (input.fec_flag ? 0x20 : 0x00) |
                    (input.move_fwd_flag ? 0x10 : 0x00) |
                    (input.persist_flag ? 0x02 : 0x00) |
                    (input.fin_flag ? 0x01 : 0x00));

  // Build the header.
  if ((!WriteUint8(DATA_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint8(input.stream_id, packet)) ||
      (!WriteUint8(input.num_ttg, packet)) ||
      (!WriteUint8(input.cc_id, packet)) ||
      (!WriteUint8(input.retransmission_count, packet)) ||
      (!WriteUint16(payload_length, packet)) ||
      (!WriteUint32(input.sequence_number, packet)) ||
      (!WriteUint32(input.timestamp, packet)) ||
      (!WriteUint32(input.timestamp_delta, packet)))
  {
    LogE(kClassName, __func__, "Error generating data header common "
         "fields.\n");
    return false;
  }

  // Append the move forward packet sequence number field if needed.
  if (input.move_fwd_flag)
  {
    if (!WriteUint32(input.move_fwd_seq_num, packet))
    {
      LogE(kClassName, __func__, "Error appending move forward sequence "
           "number.\n");
      return false;
    }
  }

  // Append the FEC fields if needed.
  if (input.fec_flag)
  {
    uint16_t  tmp =
      (((static_cast<uint16_t>(input.fec_pkt_type) & 0x01) << 15) |
       ((static_cast<uint16_t>(input.fec_group_index) & 0x3f) << 8) |
       ((static_cast<uint16_t>(input.fec_num_src) & 0x0f) << 4) |
       (static_cast<uint16_t>(input.fec_round) & 0x0f));

    if ((!WriteUint16(tmp, packet)) ||
        (!WriteUint16(input.fec_group_id, packet)))
    {
      LogE(kClassName, __func__, "Error appending FEC fields.\n");
      return false;
    }
  }

  // Append the encoded packet length field if needed.
  if (input.enc_pkt_len_flag)
  {
    if (!WriteUint16(input.encoded_pkt_length, packet))
    {
      LogE(kClassName, __func__, "Error appending encoded packet length "
           "field.\n");
      return false;
    }
  }

  // Append the time-to-go (TTG) fields if needed.
  if (input.num_ttg > 0)
  {
    TtgTime  ttg = 0;

    for (TtgCount i = 0; i < input.num_ttg; ++i)
    {
      double  ttg_sec = input.ttg[i];

      if (ttg_sec <= 1.0)
      {
        if (ttg_sec < 0.0)
        {
          ttg_sec = 0.0;
        }

        ttg = (static_cast<TtgTime>((ttg_sec * 32767.0) + 0.5));
      }
      else
      {
        if (ttg_sec > 33.767)
        {
          ttg_sec = 33.767;
        }

        ttg = (static_cast<TtgTime>(((ttg_sec - 1.0) * 1000.0) + 0.5) |
               static_cast<TtgTime>(0x8000));
      }

      if (!WriteUint16(ttg, packet))
      {
        LogE(kClassName, __func__, "Error appending time-to-go.\n");
        return false;
      }
    }
  }

  return true;
}

//============================================================================
bool Framer::AppendAckHeader(Packet*& packet, const AckHeader& input)
{
  if (packet == NULL)
  {
    packet = packet_pool_.Get();

    if (packet == NULL)
    {
      LogE(kClassName, __func__, "Error getting packet from pool.\n");
      return false;
    }
  }

  // Generate the flags and number of observed times/ACK block offsets fields.
  uint8_t  flags     = 0;
  uint8_t  num_field = (((input.num_observed_times & 0x07) << 5) |
                        (input.num_ack_block_offsets & 0x1f));

  // Build the common fields for the header.
  if ((!WriteUint8(ACK_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint8(input.stream_id, packet)) ||
      (!WriteUint8(num_field, packet)) ||
      (!WriteUint32(input.next_expected_seq_num, packet)) ||
      (!WriteUint32(input.timestamp, packet)) ||
      (!WriteUint32(input.timestamp_delta, packet)))
  {
    LogE(kClassName, __func__, "Error generating ack header common "
         "fields.\n");
    return false;
  }

  // Append all of the observed packet times.
  for (uint8_t i = 0; i < (input.num_observed_times & 0x07); ++i)
  {
    if ((!WriteUint32(input.observed_time[i].seq_num, packet)) ||
        (!WriteUint32(input.observed_time[i].timestamp, packet)))
    {
      LogE(kClassName, __func__, "Error appending observed time.\n");
      return false;
    }
  }

  // Append all of the ACK block offsets.
  for (uint8_t j = 0; j < (input.num_ack_block_offsets & 0x1f); ++j)
  {
    uint16_t  tmp = (((static_cast<uint16_t>(input.ack_block_offset[j].type) &
                       0x0001) << 15) |
                     (input.ack_block_offset[j].offset & 0x7fff));

    if (!WriteUint16(tmp, packet))
    {
      LogE(kClassName, __func__, "Error appending ACK block offset.\n");
      return false;
    }
  }

  return true;
}

//============================================================================
bool Framer::AppendCcSyncHeader(Packet*& packet, const CcSyncHeader& input)
{
  if (packet == NULL)
  {
    packet = packet_pool_.Get();

    if (packet == NULL)
    {
      LogE(kClassName, __func__, "Error getting packet from pool.\n");
      return false;
    }
  }

  // Build the header.
  if ((!WriteUint8(CC_SYNC_HEADER, packet)) ||
      (!WriteUint8(input.cc_id, packet)) ||
      (!WriteUint16(input.seq_num, packet)) ||
      (!WriteUint32(input.cc_params, packet)))
  {
    LogE(kClassName, __func__, "Error generating cc sync header.\n");
    return false;
  }

  return true;
}

//============================================================================
bool Framer::AppendRcvdPktCntHeader(Packet*& packet,
                                    const RcvdPktCntHeader& input)
{
  if (packet == NULL)
  {
    packet = packet_pool_.Get();

    if (packet == NULL)
    {
      LogE(kClassName, __func__, "Error getting packet from pool.\n");
      return false;
    }
  }

  // Build the header.
  uint8_t  flags = 0;

  if ((!WriteUint8(RCVD_PKT_CNT_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint8(input.stream_id, packet)) ||
      (!WriteUint8(input.retransmission_count, packet)) ||
      (!WriteUint32(input.sequence_number, packet)) ||
      (!WriteUint32(input.rcvd_data_pkt_count, packet)))
  {
    LogE(kClassName, __func__, "Error generating received packet count "
         "header.\n");
    return false;
  }

  return true;
}

//============================================================================
bool Framer::AppendConnMeasHeader(Packet*& packet,
                                  const ConnMeasHeader& input)
{
  if (packet == NULL)
  {
    packet = packet_pool_.Get();

    if (packet == NULL)
    {
      LogE(kClassName, __func__, "Error getting packet from pool.\n");
      return false;
    }
  }

  // Generate the flags field.
  uint8_t  flags = (input.owd_flag ? 0x80 : 0x00);

  // Build the header.
  if ((!WriteUint8(CONN_MEAS_HEADER, packet)) ||
      (!WriteUint8(flags, packet)) ||
      (!WriteUint16(input.sequence_number, packet)))
  {
    LogE(kClassName, __func__, "Error generating connection measurement "
         "header common fields.\n");
    return false;
  }

  // Append the maximum remote-to-local one-way delay field if needed.
  if (input.owd_flag)
  {
    if (!WriteUint32(input.max_rmt_to_loc_owd, packet))
    {
      LogE(kClassName, __func__, "Error appending maximum remote to local "
           "one-way delay.\n");
      return false;
    }
  }

  return true;
}

//============================================================================
Packet* Framer::GenerateCcPktTrain(const CcPktTrainHeader& input,
                                   size_t payload_length)
{
  // Get a packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return NULL;
  }

  // Build the header.
  if ((!WriteUint8(CC_PKT_TRAIN_HEADER, packet)) ||
      (!WriteUint8(input.cc_id, packet)) ||
      (!WriteUint8(input.pt_pkt_type, packet)) ||
      (!WriteUint8(input.pt_seq_num, packet)) ||
      (!WriteUint32(input.pt_inter_recv_time, packet)) ||
      (!WriteUint32(input.pt_timestamp, packet)) ||
      (!WriteUint32(input.pt_timestamp_delta, packet)))
  {
    LogE(kClassName, __func__, "Error generating CC packet train header.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return NULL;
  }

  // Add the specified payload after the header.
  if (payload_length > 0)
  {
    size_t  packet_len = packet->GetLengthInBytes();

    if (((packet_len + payload_length) > packet->GetMaxLengthInBytes()) ||
        (!packet->SetLengthInBytes(packet_len + payload_length)))
    {
      LogE(kClassName, __func__, "Error adding %zu byte payload after CC "
           "packet train header.\n", payload_length);
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
      return NULL;
    }
  }

  return packet;
}

//============================================================================
HeaderType Framer::GetHeaderType(const Packet* packet, size_t offset)
{
  // Read the header type byte from the packet to determine the header type.
  size_t   local_offset = offset;
  uint8_t  type_byte    = 0;

  if (!ReadUint8(packet, local_offset, type_byte))
  {
    LogE(kClassName, __func__, "Unable to read type byte from header.\n");
    return UNKNOWN_HEADER;
  }

  // Test the most likely success case first for efficiency.
  if (((type_byte >= DATA_HEADER) && (type_byte <= CONN_MEAS_HEADER)) ||
      ((type_byte >= CONNECTION_HANDSHAKE_HEADER) &&
       (type_byte <= RESET_STREAM_HEADER)) ||
      (type_byte == CC_PKT_TRAIN_HEADER))
  {
    return static_cast<HeaderType>(type_byte);
  }

  LogE(kClassName, __func__, "Invalid header type %" PRIu8 ".\n", type_byte);
  return UNKNOWN_HEADER;
}

//============================================================================
bool Framer::ParseConnHndshkHeader(const Packet* packet, size_t& offset,
                                   ConnHndshkHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  if ((!ReadUint8(packet, offset, output.num_cc_algs)) ||
      (!ReadUint16(packet, offset, output.message_tag)) ||
      (!ReadUint32(packet, offset, output.timestamp)) ||
      (!ReadUint32(packet, offset, output.echo_timestamp)))
  {
    LogE(kClassName, __func__, "Error parsing connection handshake "
         "header.\n");
    return false;
  }

  // Parse all of the congestion control algorithm settings.
  uint8_t   alg_type = 0;
  uint8_t   flags    = 0;
  uint32_t  params   = 0;

  for (uint8_t i = 0; i < output.num_cc_algs; ++i)
  {
    if ((!ReadUint8(packet, offset, alg_type)) ||
        (!ReadUint8(packet, offset, flags)))
    {
      LogE(kClassName, __func__, "Error parsing connection handshake "
           "CC type and flags.\n");
      return false;
    }

    // Skip the unused 2 bytes in the middle.
    offset += 2;

    if (!ReadUint32(packet, offset, params))
    {
      LogE(kClassName, __func__, "Error parsing connection handshake "
           "CC param.\n");
      return false;
    }

    if (i < SliqApp::kMaxCcAlgPerConn)
    {
      output.cc_alg[i].congestion_control_alg =
        static_cast<CongCtrlAlg>(alg_type);
      output.cc_alg[i].deterministic_flag        = ((flags & 0x02) != 0);
      output.cc_alg[i].pacing_flag               = ((flags & 0x01) != 0);
      output.cc_alg[i].congestion_control_params = params;
    }
  }

  // Do not exceed the output array size.
  if (output.num_cc_algs > SliqApp::kMaxCcAlgPerConn)
  {
    output.num_cc_algs = SliqApp::kMaxCcAlgPerConn;
  }

  // Parse the unique client ID, if present.
  if (!ReadUint32(packet, offset, output.client_id))
  {
    output.client_id = 0;
  }

  return true;
}

//============================================================================
bool Framer::ParseResetConnHeader(const Packet* packet, size_t& offset,
                                  ResetConnHeader& output)
{
  // Skip the packet type byte and the flags byte.
  offset += 2;

  // Parse the header.
  uint16_t  code = 0;

  if (!ReadUint16(packet, offset, code))
  {
    LogE(kClassName, __func__, "Error parsing reset connection header.\n");
    return false;
  }

  output.error_code = static_cast<ConnErrorCode>(code);

  return true;
}

//============================================================================
bool Framer::ParseCloseConnHeader(const Packet* packet, size_t& offset,
                                  CloseConnHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  uint8_t   flags = 0;
  uint16_t  code  = 0;

  if ((!ReadUint8(packet, offset, flags)) ||
      (!ReadUint16(packet, offset, code)))
  {
    LogE(kClassName, __func__, "Error parsing close connection header.\n");
    return false;
  }

  output.ack_flag    = ((flags & 0x01) != 0);
  output.reason_code = static_cast<ConnCloseCode>(code);

  return true;
}

//============================================================================
bool Framer::ParseCreateStreamHeader(const Packet* packet,
                                     size_t& offset,
                                     CreateStreamHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  uint8_t   flags   = 0;
  uint8_t   del_rel = 0;
  uint16_t  tgt_del = 0;
  uint16_t  tgt_rcv = 0;

  if ((!ReadUint8(packet, offset, flags)) ||
      (!ReadUint8(packet, offset, output.stream_id)) ||
      (!ReadUint8(packet, offset, output.priority)) ||
      (!ReadUint32(packet, offset, output.initial_win_size_pkts)) ||
      (!ReadUint32(packet, offset, output.initial_seq_num)) ||
      (!ReadUint8(packet, offset, del_rel)) ||
      (!ReadUint8(packet, offset, output.rexmit_limit)) ||
      (!ReadUint16(packet, offset, tgt_del)) ||
      (!ReadUint16(packet, offset, tgt_rcv)))
  {
    LogE(kClassName, __func__, "Error parsing create stream header.\n");
    return false;
  }

  // Skip the unused 2 bytes at the end.
  offset += 2;

  output.del_time_flag    = ((flags & 0x02) != 0);
  output.ack_flag         = ((flags & 0x01) != 0);
  output.delivery_mode    = static_cast<DeliveryMode>((del_rel >> 4) & 0x0f);
  output.reliability_mode = static_cast<ReliabilityMode>(del_rel & 0x0f);

  if (output.del_time_flag)
  {
    output.fec_target_pkt_del_rounds   = 0;
    output.fec_target_pkt_del_time_sec = (static_cast<double>(tgt_del) *
                                          0.001);
  }
  else
  {
    output.fec_target_pkt_del_rounds   = static_cast<RexmitRounds>(tgt_del);
    output.fec_target_pkt_del_time_sec = 0.0;
  }

  output.fec_target_pkt_recv_prob = (static_cast<double>(tgt_rcv) * 0.0001);

  return true;
}

//============================================================================
bool Framer::ParseResetStreamHeader(const Packet* packet, size_t& offset,
                                    ResetStreamHeader& output)
{
  // Skip the packet type byte and the flags byte.
  offset += 2;

  // Parse the header.
  uint8_t  code = 0;

  if ((!ReadUint8(packet, offset, output.stream_id)) ||
      (!ReadUint8(packet, offset, code)) ||
      (!ReadUint32(packet, offset, output.final_seq_num)))
  {
    LogE(kClassName, __func__, "Error parsing reset stream header.\n");
    return false;
  }

  output.error_code = static_cast<StreamErrorCode>(code);

  return true;
}

//============================================================================
bool Framer::ParseDataHeader(Packet* packet, size_t& offset,
                             DataHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  uint8_t   flags   = 0;
  uint16_t  pld_len = 0;

  if ((!ReadUint8(packet, offset, flags)) ||
      (!ReadUint8(packet, offset, output.stream_id)) ||
      (!ReadUint8(packet, offset, output.num_ttg)) ||
      (!ReadUint8(packet, offset, output.cc_id)) ||
      (!ReadUint8(packet, offset, output.retransmission_count)) ||
      (!ReadUint16(packet, offset, pld_len)) ||
      (!ReadUint32(packet, offset, output.sequence_number)) ||
      (!ReadUint32(packet, offset, output.timestamp)) ||
      (!ReadUint32(packet, offset, output.timestamp_delta)))
  {
    LogE(kClassName, __func__, "Error parsing data header.\n");
    return false;
  }

  output.enc_pkt_len_flag = ((flags & 0x40) != 0);
  output.fec_flag         = ((flags & 0x20) != 0);
  output.move_fwd_flag    = ((flags & 0x10) != 0);
  output.persist_flag     = ((flags & 0x02) != 0);
  output.fin_flag         = ((flags & 0x01) != 0);

  // Validate the congestion control identifier.
  if (output.cc_id >= SliqApp::kMaxCcAlgPerConn)
  {
    LogE(kClassName, __func__, "Error, invalid cc_id %" PRICcId ".\n",
         output.cc_id);
    return false;
  }

  // Parse the optional move forward packet sequence number if needed.
  if (output.move_fwd_flag)
  {
    if (!ReadUint32(packet, offset, output.move_fwd_seq_num))
    {
      LogE(kClassName, __func__, "Error parsing move forward sequence "
           "number.\n");
      return false;
    }
  }

  // Parse the optional FEC fields if needed.
  if (output.fec_flag)
  {
    uint16_t  tmp = 0;

    if ((!ReadUint16(packet, offset, tmp)) ||
        (!ReadUint16(packet, offset, output.fec_group_id)))
    {
      LogE(kClassName, __func__, "Error parsing FEC fields.\n");
      return false;
    }

    output.fec_pkt_type    = static_cast<FecPktType>((tmp >> 15) & 0x01);
    output.fec_group_index = static_cast<FecSize>((tmp >> 8) & 0x3f);
    output.fec_num_src     = static_cast<FecSize>((tmp >> 4) & 0x0f);
    output.fec_round       = static_cast<FecRound>(tmp & 0x0f);
  }

  // Parse the encoded packet length field if needed.
  if (output.enc_pkt_len_flag)
  {
    if (!ReadUint16(packet, offset, output.encoded_pkt_length))
    {
      LogE(kClassName, __func__, "Error parsing encoded packet length "
           "field.\n");
      return false;
    }
  }

  // Parse the packet time-to-go (TTG) fields if needed.
  if (output.num_ttg > 0)
  {
    TtgTime  ttg     = 0;
    double   ttg_sec = 0.0;

    for (TtgCount i = 0; i < output.num_ttg; ++i)
    {
      if (!ReadUint16(packet, offset, ttg))
      {
        LogE(kClassName, __func__, "Error parsing time-to-go.\n");
        return false;
      }

      if (i < kMaxTtgs)
      {
        if ((ttg & 0x8000) != 0)
        {
          ttg_sec = (1.0 + (static_cast<double>(ttg & 0x7fff) / 1000.0));
        }
        else
        {
          ttg_sec = (static_cast<double>(ttg) / 32767.0);
        }

        output.ttg[i] = ttg_sec;
      }
    }

    if (output.num_ttg > kMaxTtgs)
    {
      LogE(kClassName, __func__, "Error parsing %" PRITtgCount " TTGs.\n",
           output.num_ttg);
      output.num_ttg = kMaxTtgs;
    }
  }

  // Add information about the data header and payload.
  output.payload_offset = offset;
  output.payload_length = (packet->GetLengthInBytes() - offset);
  output.payload        = packet;

  if (pld_len != output.payload_length)
  {
    if (pld_len < output.payload_length)
    {
      LogE(kClassName, __func__, "Error, extra payload bytes in buffer (%"
           PRIu16 " < %zu).\n", pld_len, output.payload_length);
      output.payload_length = pld_len;
    }
    else
    {
      LogE(kClassName, __func__, "Error, missing payload bytes in buffer (%"
           PRIu16 " > %zu).\n", pld_len, output.payload_length);
    }
  }

  // Skip to the end of the packet payload.
  offset = packet->GetLengthInBytes();

  return true;
}

//============================================================================
bool Framer::ParseAckHeader(const Packet* packet, size_t& offset,
                            AckHeader& output)
{
  // Skip the packet type byte and the flags byte.
  offset += 2;

  // Parse the header.
  uint8_t  num_field;

  if ((!ReadUint8(packet, offset, output.stream_id)) ||
      (!ReadUint8(packet, offset, num_field)) ||
      (!ReadUint32(packet, offset, output.next_expected_seq_num)) ||
      (!ReadUint32(packet, offset, output.timestamp)) ||
      (!ReadUint32(packet, offset, output.timestamp_delta)))
  {
    LogE(kClassName, __func__, "Error parsing ACK header.\n");
    return false;
  }

  output.num_observed_times    = ((num_field >> 5) & 0x07);
  output.num_ack_block_offsets = (num_field & 0x1f);

  // Parse all of the observed packet times.
  for (uint8_t i = 0; i < output.num_observed_times; ++i)
  {
    if ((!ReadUint32(packet, offset, output.observed_time[i].seq_num)) ||
        (!ReadUint32(packet, offset, output.observed_time[i].timestamp)))
    {
      LogE(kClassName, __func__, "Error parsing observed time.\n");
      return false;
    }
  }

  // Parse all of the ACK blocks.
  for (uint8_t j = 0; j < output.num_ack_block_offsets; ++j)
  {
    uint16_t  tmp;

    if (!ReadUint16(packet, offset, tmp))
    {
      LogE(kClassName, __func__, "Error parsing ACK block offset.\n");
      return false;
    }

    output.ack_block_offset[j].type   = static_cast<AckBlkType>((tmp >> 15) &
                                                                0x0001);
    output.ack_block_offset[j].offset = (tmp & 0x7fff);
  }

  return true;
}

//============================================================================
bool Framer::ParseCcSyncHeader(const Packet* packet, size_t& offset,
                               CcSyncHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  if ((!ReadUint8(packet, offset, output.cc_id)) ||
      (!ReadUint16(packet, offset, output.seq_num)) ||
      (!ReadUint32(packet, offset, output.cc_params)))
  {
    LogE(kClassName, __func__, "Error parsing CC sync header.\n");
    return false;
  }

  return true;
}

//============================================================================
bool Framer::ParseRcvdPktCntHeader(const Packet* packet, size_t& offset,
                                   RcvdPktCntHeader& output)
{
  // Skip the packet type byte and the flags byte.
  offset += 2;

  // Parse the header.
  if ((!ReadUint8(packet, offset, output.stream_id)) ||
      (!ReadUint8(packet, offset, output.retransmission_count)) ||
      (!ReadUint32(packet, offset, output.sequence_number)) ||
      (!ReadUint32(packet, offset, output.rcvd_data_pkt_count)))
  {
    LogE(kClassName, __func__, "Error parsing received packet count "
         "header.\n");
    return false;
  }

  return true;
}

//============================================================================
bool Framer::ParseConnMeasHeader(const Packet* packet, size_t& offset,
                                 ConnMeasHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  uint8_t  flags   = 0;

  if ((!ReadUint8(packet, offset, flags)) ||
      (!ReadUint16(packet, offset, output.sequence_number)))
  {
    LogE(kClassName, __func__, "Error parsing connection measurement common "
         "fields.\n");
    return false;
  }

  output.owd_flag = ((flags & 0x80) != 0);

  // Parse the optional maximum remote-to-local one-way delay field if needed.
  if (output.owd_flag)
  {
    if (!ReadUint32(packet, offset, output.max_rmt_to_loc_owd))
    {
      LogE(kClassName, __func__, "Error parsing maximum remote-to-local "
           "one-way delay.\n");
      return false;
    }
  }

  return true;
}

//============================================================================
bool Framer::ParseCcPktTrainHeader(const Packet* packet, size_t& offset,
                                   CcPktTrainHeader& output)
{
  // Skip the packet type byte.
  offset += 1;

  // Parse the header.
  if ((!ReadUint8(packet, offset, output.cc_id)) ||
      (!ReadUint8(packet, offset, output.pt_pkt_type)) ||
      (!ReadUint8(packet, offset, output.pt_seq_num)) ||
      (!ReadUint32(packet, offset, output.pt_inter_recv_time)) ||
      (!ReadUint32(packet, offset, output.pt_timestamp)) ||
      (!ReadUint32(packet, offset, output.pt_timestamp_delta)))
  {
    LogE(kClassName, __func__, "Error parsing CC packet train header.\n");
    return false;
  }

  return true;
}

//============================================================================
bool Framer::WriteUint8(uint8_t value, Packet* packet)
{
  size_t  packet_len = packet->GetLengthInBytes();

  if ((packet_len + sizeof(uint8_t)) > packet->GetMaxLengthInBytes())
  {
    return false;
  }

  ::memcpy(reinterpret_cast<void*>(packet->GetBuffer(packet_len)),
           &value, sizeof(uint8_t));

  return packet->SetLengthInBytes(packet_len + sizeof(uint8_t));
}

//============================================================================
bool Framer::WriteUint16(uint16_t value, Packet* packet)
{
  size_t    packet_len = packet->GetLengthInBytes();
  uint16_t  value_nbo  = htons(value);

  if ((packet_len + sizeof(value_nbo)) > packet->GetMaxLengthInBytes())
  {
    return false;
  }

  ::memcpy(reinterpret_cast<void*>(packet->GetBuffer(packet_len)),
           &value_nbo, sizeof(value_nbo));

  return packet->SetLengthInBytes(packet_len + sizeof(value_nbo));
}

//============================================================================
bool Framer::WriteUint24(uint32_t value, Packet* packet)
{
  size_t    packet_len = packet->GetLengthInBytes();
  uint32_t  value_nbo  = htonl(value & 0xffffff);

  if ((packet_len + 3) > packet->GetMaxLengthInBytes())
  {
    return false;
  }

  ::memcpy(reinterpret_cast<void*>(packet->GetBuffer(packet_len)),
           (reinterpret_cast<uint8_t*>(&value_nbo) + 1), 3);

  return packet->SetLengthInBytes(packet_len + 3);
}

//============================================================================
bool Framer::WriteUint32(uint32_t value, Packet* packet)
{
  size_t    packet_len = packet->GetLengthInBytes();
  uint32_t  value_nbo  = htonl(value);

  if ((packet_len + sizeof(value_nbo)) > packet->GetMaxLengthInBytes())
  {
    return false;
  }

  ::memcpy(reinterpret_cast<void*>(packet->GetBuffer(packet_len)),
           &value_nbo, sizeof(value_nbo));

  return packet->SetLengthInBytes(packet_len + sizeof(value_nbo));
}

//============================================================================
bool Framer::WriteInt32(int32_t value, Packet* packet)
{
  size_t    packet_len = packet->GetLengthInBytes();
  uint32_t  value_nbo  = htonl(static_cast<uint32_t>(value));

  if ((packet_len + sizeof(value_nbo)) > packet->GetMaxLengthInBytes())
  {
    return false;
  }

  ::memcpy(reinterpret_cast<void*>(packet->GetBuffer(packet_len)),
           &value_nbo, sizeof(value_nbo));

  return packet->SetLengthInBytes(packet_len + sizeof(value_nbo));
}

//============================================================================
bool Framer::ReadUint8(const Packet* packet, size_t& offset, uint8_t& result)
{
  if ((offset + sizeof(uint8_t)) > packet->GetLengthInBytes())
  {
    return false;
  }

  ::memcpy(&result, packet->GetBuffer(offset), sizeof(uint8_t));

  offset += sizeof(uint8_t);

  return true;
}

//============================================================================
bool Framer::ReadUint16(const Packet* packet, size_t& offset,
                        uint16_t& result)
{
  uint16_t  result_nbo = 0;

  if ((offset + sizeof(result_nbo)) > packet->GetLengthInBytes())
  {
    return false;
  }

  ::memcpy(&result_nbo, packet->GetBuffer(offset), sizeof(result_nbo));

  result  = ntohs(result_nbo);
  offset += sizeof(result_nbo);

  return true;
}

//============================================================================
bool Framer::ReadUint24(const Packet* packet, size_t& offset,
                        uint32_t& result)
{
  uint32_t  result_nbo = 0;

  if ((offset + 3) > packet->GetLengthInBytes())
  {
    return false;
  }

  ::memcpy((reinterpret_cast<uint8_t*>(&result_nbo) + 1),
           packet->GetBuffer(offset), 3);

  result  = (ntohl(result_nbo) & 0xffffff);
  offset += 3;

  return true;
}

//============================================================================
bool Framer::ReadUint32(const Packet* packet, size_t& offset,
                        uint32_t& result)
{
  uint32_t  result_nbo = 0;

  if ((offset + sizeof(result_nbo)) > packet->GetLengthInBytes())
  {
    return false;
  }

  ::memcpy(&result_nbo, packet->GetBuffer(offset), sizeof(result_nbo));

  result  = ntohl(result_nbo);
  offset += sizeof(result_nbo);

  return true;
}

//============================================================================
bool Framer::ReadInt32(const Packet* packet, size_t& offset,
                       int32_t& result)
{
  int32_t  result_nbo = 0;

  if ((offset + sizeof(result_nbo)) > packet->GetLengthInBytes())
  {
    return false;
  }

  ::memcpy(&result_nbo, packet->GetBuffer(offset), sizeof(result_nbo));

  result  = static_cast<int32_t>(ntohl(result_nbo));
  offset += sizeof(result_nbo);

  return true;
}

//============================================================================
ConnHndshkHeader::ConnHndshkHeader()
    : num_cc_algs(0), message_tag(0), timestamp(0), echo_timestamp(0),
      client_id(0), cc_alg()
{}

//============================================================================
ConnHndshkHeader::ConnHndshkHeader(uint8_t num_alg, MsgTag tag,
                                   PktTimestamp ts, PktTimestamp echo_ts,
                                   ClientId id, CongCtrl* alg)
    : num_cc_algs(num_alg), message_tag(tag), timestamp(ts),
      echo_timestamp(echo_ts), client_id(id), cc_alg()
{
  if (alg == NULL)
  {
    num_cc_algs = 0;
    return;
  }

  if (num_alg > SliqApp::kMaxCcAlgPerConn)
  {
    num_cc_algs = SliqApp::kMaxCcAlgPerConn;
  }

  for (uint8_t i = 0; i < num_cc_algs; ++i)
  {
    cc_alg[i].congestion_control_alg = alg[i].algorithm;
    cc_alg[i].deterministic_flag     = alg[i].deterministic_copa;
    cc_alg[i].pacing_flag            = alg[i].cubic_reno_pacing;

    if (alg[i].algorithm == COPA1_CONST_DELTA_CC)
    {
      cc_alg[i].congestion_control_params =
        static_cast<uint32_t>((alg[i].copa_delta * 1000.0) + 0.5);
    }
    else if (alg[i].algorithm == COPA_CC)
    {
      cc_alg[i].congestion_control_params =
        static_cast<uint32_t>((alg[i].copa_anti_jitter * 1000000.0) + 0.5);
    }
    else if (alg[i].algorithm == FIXED_RATE_TEST_CC)
    {
      cc_alg[i].congestion_control_params =
        static_cast<uint32_t>(alg[i].fixed_send_rate);
    }
    else
    {
      cc_alg[i].congestion_control_params = 0;
    }
  }
}

//============================================================================
size_t ConnHndshkHeader::ConvertToCongCtrl(CongCtrl* alg, size_t max_alg)
{
  size_t  rv = 0;

  if (alg != NULL)
  {
    rv = ((num_cc_algs < max_alg) ? num_cc_algs : max_alg);
    rv = ((rv > SliqApp::kMaxCcAlgPerConn) ? SliqApp::kMaxCcAlgPerConn : rv);

    for (size_t i = 0; i < rv; ++i)
    {
      alg[i].algorithm          = cc_alg[i].congestion_control_alg;
      alg[i].deterministic_copa = cc_alg[i].deterministic_flag;
      alg[i].cubic_reno_pacing  = cc_alg[i].pacing_flag;

      if (alg[i].algorithm == COPA1_CONST_DELTA_CC)
      {
        alg[i].copa_delta       =
          (static_cast<double>(cc_alg[i].congestion_control_params) * 0.001);
        alg[i].copa_anti_jitter = 0.0;
        alg[i].fixed_send_rate  = 0;
      }
      else if (alg[i].algorithm == COPA_CC)
      {
        alg[i].copa_delta       = 0.0;
        alg[i].copa_anti_jitter =
          (static_cast<double>(cc_alg[i].congestion_control_params) *
           0.000001);
        alg[i].fixed_send_rate   = 0;
      }
      else if (alg[i].algorithm == FIXED_RATE_TEST_CC)
      {
        alg[i].copa_delta       = 0.0;
        alg[i].copa_anti_jitter = 0.0;
        alg[i].fixed_send_rate  = cc_alg[i].congestion_control_params;
      }
      else
      {
        alg[i].copa_delta       = 0.0;
        alg[i].copa_anti_jitter = 0.0;
        alg[i].fixed_send_rate  = 0;
      }
    }
  }

  return rv;
}

//============================================================================
ResetConnHeader::ResetConnHeader()
    : error_code(SLIQ_CONN_NO_ERROR)
{}

//============================================================================
ResetConnHeader::ResetConnHeader(ConnErrorCode error)
    : error_code(error)
{}

//============================================================================
CloseConnHeader::CloseConnHeader()
    : ack_flag(false), reason_code(SLIQ_CONN_NORMAL_CLOSE)
{}

//============================================================================
CloseConnHeader::CloseConnHeader(bool ack, ConnCloseCode reason)
    : ack_flag(ack), reason_code(reason)
{}

//============================================================================
CreateStreamHeader::CreateStreamHeader()
    : del_time_flag(false), ack_flag(false), stream_id(0),
      priority(kLowestPriority), initial_win_size_pkts(kFlowCtrlWindowPkts),
      initial_seq_num(0), delivery_mode(ORDERED_DELIVERY),
      reliability_mode(RELIABLE_ARQ),
      rexmit_limit(kDefaultDeliveryRexmitLimit), fec_target_pkt_del_rounds(0),
      fec_target_pkt_del_time_sec(0.0), fec_target_pkt_recv_prob(0.0)
{}

//============================================================================
CreateStreamHeader::CreateStreamHeader(
  bool tm, bool ack, StreamId sid, Priority prio, WindowSize win_size,
  PktSeqNumber seq_num, DeliveryMode del_mode, ReliabilityMode rel_mode,
  RexmitLimit limit, RexmitRounds del_rnds, double del_time, double recv_p)
    : del_time_flag(tm), ack_flag(ack), stream_id(sid), priority(prio),
      initial_win_size_pkts(win_size), initial_seq_num(seq_num),
      delivery_mode(del_mode), reliability_mode(rel_mode),
      rexmit_limit(limit), fec_target_pkt_del_rounds(del_rnds),
      fec_target_pkt_del_time_sec(del_time), fec_target_pkt_recv_prob(recv_p)
{}

//============================================================================
void CreateStreamHeader::GetReliability(Reliability& rel)
{
  rel.mode = reliability_mode;

  if ((reliability_mode == SEMI_RELIABLE_ARQ) ||
      (reliability_mode == SEMI_RELIABLE_ARQ_FEC))
  {
    rel.rexmit_limit = rexmit_limit;
  }
  else
  {
    rel.rexmit_limit = 0;
  }

  if (reliability_mode == SEMI_RELIABLE_ARQ_FEC)
  {
    rel.fec_target_pkt_recv_prob = fec_target_pkt_recv_prob;
    rel.fec_del_time_flag        = del_time_flag;

    if (del_time_flag)
    {
      rel.fec_target_pkt_del_rounds   = 0;
      rel.fec_target_pkt_del_time_sec = fec_target_pkt_del_time_sec;
    }
    else
    {
      rel.fec_target_pkt_del_rounds   = fec_target_pkt_del_rounds;
      rel.fec_target_pkt_del_time_sec = 0.0;
    }
  }
  else
  {
    rel.fec_target_pkt_recv_prob    = 0.0;
    rel.fec_del_time_flag           = false;
    rel.fec_target_pkt_del_rounds   = 0;
    rel.fec_target_pkt_del_time_sec = 0.0;
  }
}

//============================================================================
ResetStreamHeader::ResetStreamHeader()
    : stream_id(0), error_code(SLIQ_STREAM_NO_ERROR), final_seq_num(0)
{}

//============================================================================
ResetStreamHeader::ResetStreamHeader(StreamId sid, StreamErrorCode error,
                                     PktSeqNumber seq_num)
    : stream_id(sid), error_code(error), final_seq_num(seq_num)
{}

//============================================================================
DataHeader::DataHeader()
    : enc_pkt_len_flag(false), fec_flag(false), move_fwd_flag(false),
      persist_flag(false), fin_flag(false), stream_id(0),
      num_ttg(0), cc_id(0), retransmission_count(0), sequence_number(0),
      timestamp(0), timestamp_delta(0), move_fwd_seq_num(0),
      fec_pkt_type(FEC_SRC_PKT), fec_group_index(0), fec_num_src(0),
      fec_round(0), fec_group_id(0), encoded_pkt_length(0), ttg(),
      payload_offset(0), payload_length(0), payload(NULL)
{}

//============================================================================
DataHeader::DataHeader(bool epl, bool fec, bool move_fwd, bool persist,
                       bool fin, StreamId sid, TtgCount ttgs, CcId id,
                       RetransCount rx_cnt, PktSeqNumber seq_num,
                       PktTimestamp ts, PktTimestamp ts_delta,
                       PktSeqNumber mf_seq_num, FecPktType fec_type,
                       FecSize fec_idx, FecSize fec_src, FecRound fec_rnd,
                       FecGroupId fec_grp, FecEncPktLen enc_pkt_len)
    : enc_pkt_len_flag(epl), fec_flag(fec), move_fwd_flag(move_fwd),
      persist_flag(persist), fin_flag(fin), stream_id(sid),
      num_ttg(ttgs), cc_id(id), retransmission_count(rx_cnt),
      sequence_number(seq_num), timestamp(ts), timestamp_delta(ts_delta),
      move_fwd_seq_num(mf_seq_num), fec_pkt_type(fec_type),
      fec_group_index(fec_idx), fec_num_src(fec_src), fec_round(fec_rnd),
      fec_group_id(fec_grp), encoded_pkt_length(enc_pkt_len),
      ttg(), payload_offset(0), payload_length(0), payload(NULL)
{}

//============================================================================
AckHeader::AckHeader()
    : stream_id(0), num_observed_times(0), num_ack_block_offsets(0),
      next_expected_seq_num(0), timestamp(0), timestamp_delta(0),
      observed_time(), ack_block_offset()
{}

//============================================================================
AckHeader::AckHeader(StreamId sid, PktSeqNumber ne_seq, PktTimestamp ts,
                     PktTimestamp ts_delta)
    : stream_id(sid), num_observed_times(0), num_ack_block_offsets(0),
      next_expected_seq_num(ne_seq), timestamp(ts), timestamp_delta(ts_delta),
      observed_time(), ack_block_offset()
{}

//============================================================================
CcSyncHeader::CcSyncHeader()
    : cc_id(0), seq_num(0), cc_params(0)
{}

//============================================================================
CcSyncHeader::CcSyncHeader(CcId id, uint16_t sn, uint32_t params)
    : cc_id(id), seq_num(sn), cc_params(params)
{}

//============================================================================
RcvdPktCntHeader::RcvdPktCntHeader()
    : stream_id(0), retransmission_count(0), sequence_number(0),
      rcvd_data_pkt_count(0)
{}

//============================================================================
RcvdPktCntHeader::RcvdPktCntHeader(StreamId sid, RetransCount rexmit_cnt,
                                   PktSeqNumber seq_num, PktCount cnt)
    : stream_id(sid), retransmission_count(rexmit_cnt),
      sequence_number(seq_num), rcvd_data_pkt_count(cnt)
{}

//============================================================================
ConnMeasHeader::ConnMeasHeader()
    : owd_flag(false), sequence_number(0), max_rmt_to_loc_owd(0)
{}

//============================================================================
ConnMeasHeader::ConnMeasHeader(bool owd, uint16_t sn, uint32_t max_owd)
    : owd_flag(owd), sequence_number(sn), max_rmt_to_loc_owd(max_owd)
{}

//============================================================================
CcPktTrainHeader::CcPktTrainHeader()
    : cc_id(0), pt_pkt_type(0), pt_seq_num(0), pt_inter_recv_time(0),
      pt_timestamp(0), pt_timestamp_delta(0)
{}

//============================================================================
CcPktTrainHeader::CcPktTrainHeader(CcId id, uint8_t type, uint8_t seq,
                                   uint32_t irt, PktTimestamp ts,
                                   PktTimestamp ts_delta)
    : cc_id(id), pt_pkt_type(type), pt_seq_num(seq), pt_inter_recv_time(irt),
      pt_timestamp(ts), pt_timestamp_delta(ts_delta)
{}
