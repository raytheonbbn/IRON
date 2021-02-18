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

#include "sliq_received_packet_manager.h"

#include "sliq_connection.h"

#include "log.h"
#include "packet_pool.h"
#include "unused.h"

#include <cstring>
#include <inttypes.h>


using ::sliq::FecSize;
using ::sliq::PktSeqNumber;
using ::sliq::RcvdPktManager;
using ::sliq::VdmFec;
using ::sliq::WindowSize;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*         UNUSED(kClassName) = "RcvdPktManager";

  /// Received packet information flag for forward error correction (FEC).
  const uint8_t       kFec               = 0x01;

  /// Received packet information flag for the data packet FIN flag.
  const uint8_t       kFin               = 0x02;

  /// Received packet information flag for data packets that have been
  /// received.
  const uint8_t       kReceived          = 0x04;

  /// Received packet information flag for data packets that have been
  /// regenerated using FEC.
  const uint8_t       kRegenerated       = 0x08;

  /// Received packet information flag for data packets that have been
  /// delivered to the application.
  const uint8_t       kDelivered         = 0x10;

  /// The number of FEC groups supported for storing FEC information.  The
  /// worst case occurs when there is only one packet in each FEC group.
  const WindowSize    kFecGroupInfoSize  = sliq::kFlowCtrlWindowPkts;

  /// The SLIQ latency-sensitive data packet overhead to use in the raw
  /// goodput statistics.  Includes the Ethernet header size (14 bytes), IPv4
  /// header size (20 bytes), UDP header size (8 bytes), and the base SLIQ
  /// data header size for latency-sensitive packets with no FEC information
  /// (22 bytes).
  const size_t        kRawGpHdrSizeBytes = 64;
}


// Macros for received packet information.
#define IS_FEC(info)          (((info).flags_ & kFec) != 0)
#define IS_FIN(info)          (((info).flags_ & kFin) != 0)
#define IS_RECEIVED(info)     (((info).flags_ & kReceived) != 0)
#define IS_REGENERATED(info)  (((info).flags_ & kRegenerated) != 0)
#define IS_DELIVERED(info)    (((info).flags_ & kDelivered) != 0)

#define SET_FEC(info)          (info).flags_ |= kFec
#define SET_FIN(info)          (info).flags_ |= kFin
#define SET_RECEIVED(info)     (info).flags_ |= kReceived
#define SET_REGENERATED(info)  (info).flags_ |= kRegenerated
#define SET_DELIVERED(info)    (info).flags_ |= kDelivered


/// The RcvdPktInfo's static member to the packet pool.
PacketPool*  RcvdPktManager::RcvdPktInfo::packet_pool_ = NULL;


//============================================================================
RcvdPktManager::RcvdPktManager(Connection& conn, PacketPool& packet_pool,
                               EndptId conn_id, StreamId stream_id)
    : conn_(conn),
      packet_pool_(packet_pool),
      conn_id_(conn_id),
      stream_id_(stream_id),
      rel_(),
      del_mode_(ORDERED_DELIVERY),
      rcv_wnd_(kFlowCtrlWindowPkts),
      rcv_min_(0),
      rcv_nxt_(0),
      rcv_max_(0),
      rcv_max_fin_flag_(false),
      ack_blk_(),
      vdm_info_(),
      obs_times_(),
      rct_rcvs_(),
      stats_pkts_(),
      fec_grp_info_(NULL),
      fec_src_pkts_(NULL),
      rcvd_pkts_(NULL)
{
}

//============================================================================
RcvdPktManager::~RcvdPktManager()
{
  // Log the packet receive and regeneration statistics.
  LogI(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       " rcvd pkt counts: tgt_app %zu tgt_tot %zu norm %zu norm_rx %zu "
       "fec_src %zu fec_src_rx %zu fec_src_rg %zu fec_enc %zu fec_enc_rx %zu"
       "\n", conn_id_, stream_id_, stats_pkts_.target_app_rcvd_,
       stats_pkts_.target_tot_rcvd_, stats_pkts_.norm_rcvd_,
       stats_pkts_.norm_rx_rcvd_, stats_pkts_.fec_src_rcvd_,
       stats_pkts_.fec_src_rx_rcvd_, stats_pkts_.fec_src_regen_,
       stats_pkts_.fec_enc_rcvd_, stats_pkts_.fec_enc_rx_rcvd_);

  // Log the FEC packet statistics.
  if ((stats_pkts_.fec_total_src_rcvd_ + stats_pkts_.fec_total_ext_rcvd_) > 0)
  {
    LogI(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         " results: tot_src %zu tot_ext %zu efficiency %f\n",
         conn_id_, stream_id_, stats_pkts_.fec_total_src_rcvd_,
         stats_pkts_.fec_total_ext_rcvd_,
         (static_cast<double>(stats_pkts_.fec_total_src_rcvd_) /
          static_cast<double>(stats_pkts_.fec_total_src_rcvd_ +
                              stats_pkts_.fec_total_ext_rcvd_)));
  }

  // Log the raw goodput statistics.
  if ((stats_pkts_.raw_goodput_bytes_ > 0) &&
      (stats_pkts_.end_time_ > stats_pkts_.start_time_))
  {
    Time    dur    = (stats_pkts_.end_time_ - stats_pkts_.start_time_);
    double  raw_gp = (static_cast<double>(stats_pkts_.raw_goodput_bytes_) *
                      8.0 / dur.ToDouble());

    LogI(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         " raw goodput: %0.6f Mbps\n", conn_id_, stream_id_,
         (raw_gp / 1000000.0));
  }

  // Delete the arrays of FEC group and received packet information.
  if (fec_grp_info_ != NULL)
  {
    delete [] fec_grp_info_;
    fec_grp_info_ = NULL;
  }

  if (fec_src_pkts_ != NULL)
  {
    delete [] fec_src_pkts_;
    fec_src_pkts_ = NULL;
  }

  if (rcvd_pkts_ != NULL)
  {
    delete [] rcvd_pkts_;
    rcvd_pkts_ = NULL;
  }
}

//============================================================================
bool RcvdPktManager::Initialize(
  const Reliability& rel, DeliveryMode del_mode, PktSeqNumber init_seq_num)
{
  // Prevent multiple initializations.
  if (rcvd_pkts_ != NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, already initialized.\n", conn_id_, stream_id_);
    return false;
  }

  // Initialize the FEC encoder.
  if (rel.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    if (!rel.fec_del_time_flag)
    {
      // Check that the target number of rounds is within limits.
      if ((rel.fec_target_pkt_del_rounds < 1) ||
          (rel.fec_target_pkt_del_rounds > kMaxTgtPktDelRnds))
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC target number of rounds %" PRIRexmitRounds
             " exceeds limits of 1 to %zu.\n", conn_id_, stream_id_,
             rel.fec_target_pkt_del_rounds, kMaxTgtPktDelRnds);
        return false;
      }
    }

    VdmFec::Initialize();
  }

  // Set the packet pool for the RcvdPktInfo objects to use.
  RcvdPktInfo::SetPacketPool(&packet_pool_);

  // Allocate the arrays of FEC information.
  if (rel.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    fec_grp_info_ = new (std::nothrow) FecGroupInfo[kFecGroupInfoSize];
    fec_src_pkts_ = new (std::nothrow) RcvdPktInfo[kMaxFecGroupLengthPkts];

    if ((fec_grp_info_ == NULL) || (fec_src_pkts_ == NULL))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error allocating FEC arrays.\n", conn_id_, stream_id_);
      return false;
    }

    // Invalidate the first entry in the FEC group array.  The others are
    // already invalid, as the FEC group IDs are initialized to zero.
    fec_grp_info_[0].fec_grp_id_ = 1;
  }

  // Allocate the circular array of received packet information.
  rcvd_pkts_ = new (std::nothrow) RcvdPktInfo[kFlowCtrlWindowPkts];

  if (rcvd_pkts_ == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error allocating received packet array.\n", conn_id_, stream_id_);
    return false;
  }

  // Store the settings.
  rel_      = rel;
  del_mode_ = del_mode;
  rcv_wnd_  = kFlowCtrlWindowPkts;
  rcv_min_  = init_seq_num;
  rcv_nxt_  = init_seq_num;
  rcv_max_  = (init_seq_num - 1);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Initialize receive packet manager: rel_mode %d rexmit_limit %"
       PRIRexmitLimit " del_time %d tgt_rnds %" PRIFecRound " tgt_time %f "
       "tgt_prob %f del_mode %d rcv_wnd_ %" PRIWindowSize " rcv_min_ %"
       PRIPktSeqNumber " rcv_nxt_ %" PRIPktSeqNumber " rcv_max_ %"
       PRIPktSeqNumber ".\n", conn_id_, stream_id_, rel_.mode,
       rel_.rexmit_limit, static_cast<int>(rel_.fec_del_time_flag),
       rel_.fec_target_pkt_del_rounds, rel_.fec_target_pkt_del_time_sec,
       rel_.fec_target_pkt_recv_prob, del_mode_, rcv_wnd_, rcv_min_, rcv_nxt_,
       rcv_max_);
#endif

  return true;
}

//============================================================================
bool RcvdPktManager::IsGoodDataPacket(DataHeader& pkt)
{
  // The manager must have been initialized.
  if (rcvd_pkts_ == NULL)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, not initialized.\n", conn_id_, stream_id_);
  }

  // If the packet is not to the right of rcv_max_, then look closer.
  if (SEQ_LEQ(pkt.sequence_number, rcv_max_))
  {
    RcvdPktInfo&  pkt_info = rcvd_pkts_[(pkt.sequence_number %
                                         kFlowCtrlWindowPkts)];

    // Check if this is a duplicate packet.
    if ((pkt.sequence_number == pkt_info.seq_num_) &&
        (IS_RECEIVED(pkt_info)) &&
        (pkt.retransmission_count <= pkt_info.rexmit_cnt_))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, duplicate packet seq %" PRIPktSeqNumber " detected (%"
           PRIRetransCount " <= %" PRIRetransCount ").\n", conn_id_,
           stream_id_, pkt_info.seq_num_, pkt.retransmission_count,
           pkt_info.rexmit_cnt_);
      return false;
    }
  }

  return true;
}

//============================================================================
bool RcvdPktManager::AddPkt(DataHeader& pkt, const Time& rcv_time)
{
  bool  ack_now = false;

  // Update the packet receive statistics.
  stats_pkts_.Update(rel_, pkt);

  // Make sure that the current window has not already moved beyond this
  // packet.
  if (SEQ_LT(pkt.sequence_number, rcv_min_))
  {
#ifdef SLIQ_DEBUG
    if (pkt.fec_flag)
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Redundant packet, received seq %" PRIPktSeqNumber " grp %"
           PRIFecGroupId " idx %" PRIFecSize " precedes the current window."
           "\n", conn_id_, stream_id_, pkt.sequence_number, pkt.fec_group_id,
           pkt.fec_group_index);
    }
    else
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Redundant packet, received seq %" PRIPktSeqNumber " precedes "
           "the current window.\n", conn_id_, stream_id_,
           pkt.sequence_number);
    }
#endif

    // Report the packet's timestamp in the next ACK packet to be sent.
    obs_times_.StoreObsTime(pkt.sequence_number, pkt.timestamp, rcv_time);

    // Record the packet's sequence number as a recently received data packet.
    rct_rcvs_.RecordSeqNum(pkt.sequence_number);

    // Release the packet.
    packet_pool_.Recycle(pkt.payload);
    pkt.payload = NULL;

    // Update the packet receive statistics for this redundant FEC packet.
    if ((pkt.fec_flag) && (rel_.mode == SEMI_RELIABLE_ARQ_FEC) &&
        (pkt.fec_round > 0) &&
        (((rel_.fec_del_time_flag) && (pkt.fec_round < kOutOfRounds)) ||
         ((!rel_.fec_del_time_flag) &&
          (pkt.fec_round <= rel_.fec_target_pkt_del_rounds))))
    {
      // This value may be decremented if FEC encoded packets are used to
      // regenerate FEC source packets.
      ++stats_pkts_.fec_total_ext_rcvd_;
    }

    // Attempt to update the flags and retransmission count for the packet.
    // This can help detect duplicate data packets so that they can be
    // ignored.
    RcvdPktInfo&  old_rpi = rcvd_pkts_[(pkt.sequence_number %
                                        kFlowCtrlWindowPkts)];

    if ((pkt.sequence_number == old_rpi.seq_num_) &&
        (pkt.retransmission_count > old_rpi.rexmit_cnt_))
    {
      SET_RECEIVED(old_rpi);
      old_rpi.rexmit_cnt_ = pkt.retransmission_count;
    }

    // This packet is out of order, so send an ACK packet immediately.
    return true;
  }

  // Make sure that there will be room for this packet in the circular receive
  // window.
  if (SEQ_GT(pkt.sequence_number, rcv_max_) &&
      (((pkt.sequence_number - rcv_min_) + 1) > kFlowCtrlWindowPkts))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Dropping seq %" PRIPktSeqNumber ", circular array size %"
         PRIPktSeqNumber " would exceed max %" PRIWindowSize ".\n", conn_id_,
         stream_id_, pkt.sequence_number,
         ((pkt.sequence_number - rcv_min_) + 1), kFlowCtrlWindowPkts);

    // Release the packet.
    packet_pool_.Recycle(pkt.payload);
    pkt.payload = NULL;

    // The sender should not overrun the receive window, so send an ACK packet
    // immediately in order to hopefully correct the situation.
    return true;
  }

  // Report the packet's timestamp in the next ACK packet to be sent.
  obs_times_.StoreObsTime(pkt.sequence_number, pkt.timestamp, rcv_time);

  // Record the packet's sequence number as a recently received data packet.
  rct_rcvs_.RecordSeqNum(pkt.sequence_number);

  // Get access to the packet information for the received packet.
  RcvdPktInfo&  pkt_info = rcvd_pkts_[(pkt.sequence_number %
                                       kFlowCtrlWindowPkts)];

  // Check if this packet is beyond the current window.
  if (SEQ_GT(pkt.sequence_number, rcv_max_))
  {
    // Check that a FIN has not already been received.
    if (rcv_max_fin_flag_)
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Received seq %" PRIPktSeqNumber " that is greater than FIN seq "
           "%" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
           pkt.sequence_number, rcv_max_);
    }

    // Add "holes" for the missing packets.
    size_t  num_holes_to_add = (pkt.sequence_number - rcv_max_ - 1);

    if (num_holes_to_add > 0)
    {
      // This packet is out of order, so send an ACK packet immediately.
      ack_now = true;
    }

    for (PktSeqNumber seq_num = (rcv_max_ + 1);
         SEQ_LT(seq_num, pkt.sequence_number); ++seq_num)
    {
      RcvdPktInfo&  rpi = rcvd_pkts_[(seq_num % kFlowCtrlWindowPkts)];

      rpi.Clear();

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Adding hole for seq %" PRIPktSeqNumber ".\n", conn_id_,
           stream_id_, seq_num);
#endif
    }

    // Now add the packet.
    StorePkt(pkt, pkt_info);

    // Update the upper edge of the window.
    rcv_max_          = pkt.sequence_number;
    rcv_max_fin_flag_ = pkt.fin_flag;
  }
  else
  {
    // This packet is within the current window.  Check if the packet has
    // already been received and/or regenerated.
    if ((!IS_RECEIVED(pkt_info)) && (!IS_REGENERATED(pkt_info)))
    {
      // The packet has not been received or regenerated yet.  Add the packet.
      StorePkt(pkt, pkt_info);

      // This packet is out of order, so send an ACK packet immediately.
      ack_now = true;
    }
    else
    {
      // The packet has already been received or regenerated.  Mark the packet
      // as being received, update the retransmission count, then recycle the
      // packet.
      SET_RECEIVED(pkt_info);

      if (pkt.retransmission_count > pkt_info.rexmit_cnt_)
      {
        pkt_info.rexmit_cnt_ = pkt.retransmission_count;
      }

      packet_pool_.Recycle(pkt.payload);
      pkt.payload = NULL;

#ifdef SLIQ_DEBUG
      if (pkt.fec_flag)
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Redundant packet, received seq %" PRIPktSeqNumber " grp %"
             PRIFecGroupId " idx %" PRIFecSize " already present.\n",
             conn_id_, stream_id_, pkt.sequence_number, pkt.fec_group_id,
             pkt.fec_group_index);
      }
      else
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Redundant packet, received seq %" PRIPktSeqNumber " already "
             "present.\n", conn_id_, stream_id_, pkt.sequence_number);
      }
#endif

      // Update the packet receive statistics for this redundant FEC packet.
      if ((pkt.fec_flag) && (rel_.mode == SEMI_RELIABLE_ARQ_FEC) &&
          (pkt.fec_round > 0) &&
          (((rel_.fec_del_time_flag) && (pkt.fec_round < kOutOfRounds)) ||
           ((!rel_.fec_del_time_flag) &&
            (pkt.fec_round <= rel_.fec_target_pkt_del_rounds))))
      {
        // This value may be decremented if FEC encoded packets are used to
        // regenerate FEC source packets.
        ++stats_pkts_.fec_total_ext_rcvd_;
      }

      // Since we have not added a new packet to the window, there is nothing
      // left to do but return.  This packet is out of order, so send an ACK
      // packet immediately.
      return true;
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Adding packet, seq %" PRIPktSeqNumber " fec %d fin %d rcv_time %s."
       "\n", conn_id_, stream_id_, pkt.sequence_number,
       static_cast<int>(pkt.fec_flag), static_cast<int>(pkt.fin_flag),
       rcv_time.ToString().c_str());
#endif

  // If the packet just added to the window is an FEC packet and FEC packets
  // are expected, then update the packet receive statistics for this new FEC
  // packet and attempt to regenerate packets within the same FEC group.
  if ((pkt.fec_flag) && (rel_.mode == SEMI_RELIABLE_ARQ_FEC))
  {
    if ((pkt.fec_round > 0) &&
        (((rel_.fec_del_time_flag) && (pkt.fec_round < kOutOfRounds)) ||
         ((!rel_.fec_del_time_flag) &&
          (pkt.fec_round <= rel_.fec_target_pkt_del_rounds))))
    {
      if (pkt.fec_pkt_type == FEC_SRC_PKT)
      {
        ++stats_pkts_.fec_total_src_rcvd_;
      }
      else
      {
        // This value may be decremented if FEC encoded packets are used to
        // regenerate FEC source packets.
        ++stats_pkts_.fec_total_ext_rcvd_;
      }
    }

    RegeneratePkts(pkt, rcv_time);
  }

  // Now that the received packet has been added to the window and any FEC
  // packets have been regenerated into the window, update the next expected
  // sequence number.
  UpdateNextExpected(false);

  // If there are any packets missing or if this packet has the FIN flag set,
  // then send an ACK packet immediately.
  if ((SEQ_GT(rcv_max_, rcv_nxt_)) || (pkt.fin_flag))
  {
    ack_now = true;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated receive window, rcv_min_ %" PRIPktSeqNumber " rcv_nxt_ %"
       PRIPktSeqNumber " rcv_max_ %" PRIPktSeqNumber ".\n", conn_id_,
       stream_id_, rcv_min_, rcv_nxt_, rcv_max_);
#endif

  return ack_now;
}

//============================================================================
bool RcvdPktManager::GetNextAppPkt(Packet*& pkt, size_t& payload_offset,
                                   size_t& payload_len, bool& fin_flag)
{
  // Check if there is no possible way of delivering a packet.
  if ((rcvd_pkts_ == NULL) || (SEQ_GT(rcv_min_, rcv_max_)))
  {
    return false;
  }

  PktSeqNumber  del_seq_num = rcv_min_;

  // First, find a candidate for delivery to the application.  Ordered
  // delivery will always use a sequence number of rcv_min_, which was set
  // above.
  if (del_mode_ == UNORDERED_DELIVERY)
  {
    // Unordered packet delivery to the application.  Loop over the receive
    // window to find a packet to deliver.
    for (del_seq_num = rcv_min_;
         SEQ_LEQ(del_seq_num, rcv_max_); ++del_seq_num)
    {
      RcvdPktInfo&  rpi = rcvd_pkts_[(del_seq_num % kFlowCtrlWindowPkts)];

      // Be careful not to deliver FEC encoded packets.
      if ((rpi.packet_ != NULL) &&
          (IS_RECEIVED(rpi) || IS_REGENERATED(rpi)) &&
          ((!IS_FEC(rpi)) || (rpi.fec_pkt_type_ == FEC_SRC_PKT)) &&
          (!IS_DELIVERED(rpi)))
      {
        break;
      }
    }

    if (SEQ_GT(del_seq_num, rcv_max_))
    {
      // Attempt to move the left edge of the window to the right.
      MoveWindowRight();

      return false;
    }
  }

  // Get the candidate for delivery using the sequence number identified
  // above.
  RcvdPktInfo&  pkt_info = rcvd_pkts_[(del_seq_num % kFlowCtrlWindowPkts)];

  // Determine if the candidate for delivery meets the criteria for delivery.
  if ((pkt_info.packet_ == NULL) || IS_DELIVERED(pkt_info))
  {
    // Attempt to move the left edge of the window to the right.
    MoveWindowRight();

    return false;
  }

  // Mark that the packet was received on time (i.e., not "late").
  pkt_info.packet_->set_recv_late(false);

  // Update the packet receive counts and the packet's received "late" flag.
  if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    if ((pkt_info.fec_round_ > 0) &&
        (((rel_.fec_del_time_flag) && (pkt_info.fec_round_ < kOutOfRounds)) ||
         ((!rel_.fec_del_time_flag) &&
          (pkt_info.fec_round_ <= rel_.fec_target_pkt_del_rounds))))
    {
      if (pkt_info.payload_len_ > 0)
      {
        ++stats_pkts_.target_app_rcvd_;
      }
    }
    else
    {
      pkt_info.packet_->set_recv_late(true);
    }
  }

  // Update the raw goodput statistics.
  if (pkt_info.payload_len_ > 0)
  {
    Time  now = Time::Now();

    if (stats_pkts_.raw_goodput_bytes_ == 0)
    {
      stats_pkts_.start_time_ = now;
    }

    stats_pkts_.raw_goodput_bytes_ += (kRawGpHdrSizeBytes +
                                       pkt_info.payload_len_);
    stats_pkts_.end_time_           = now;
  }

  // Deliver this packet to the application.
  if (IS_FEC(pkt_info) && (pkt_info.fec_pkt_type_ == FEC_SRC_PKT))
  {
    // The packet must be cloned in order to keep a copy for FEC decoding.
    //
    // NOTE:  This code makes a deep copy of all FEC source data packets.  It
    // would be more efficient to do a shallow copy (a simple reference count
    // increment) of the packet.  However, the packet might be modified by one
    // of the proxies while SLIQ is still holding onto it for FEC decoding,
    // and any changes to the packet will corrupt the decoding.
    pkt = packet_pool_.Clone(pkt_info.packet_, true,
                             iron::PACKET_COPY_TIMESTAMP);

    if (pkt == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error cloning packet.\n", conn_id_, stream_id_);
    }

    // Update the FEC group delivered packet count.
    FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                             kFecGroupInfoSize)];

    if (grp_info.fec_grp_id_ == pkt_info.fec_grp_id_)
    {
      ++(grp_info.delivered_cnt_);
    }
  }
  else
  {
    // Simply hand off the packet since SLIQ no longer needs it.
    pkt              = pkt_info.packet_;
    pkt_info.packet_ = NULL;
  }

  payload_offset = pkt_info.payload_offset_;
  payload_len    = pkt_info.payload_len_;
  fin_flag       = IS_FIN(pkt_info);

  SET_DELIVERED(pkt_info);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Deliver seq %" PRIPktSeqNumber " to app.\n", conn_id_, stream_id_,
       del_seq_num);
#endif

  // Attempt to move the left edge of the window to the right.
  MoveWindowRight();

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated receive window, rcv_min_ %" PRIPktSeqNumber " rcv_nxt_ %"
       PRIPktSeqNumber " rcv_max_ %" PRIPktSeqNumber ".\n", conn_id_,
       stream_id_, rcv_min_, rcv_nxt_, rcv_max_);
#endif

  return true;
}

//============================================================================
bool RcvdPktManager::MoveForward(PktSeqNumber ne_seq_num)
{
  // Note that this method is called only if the reliability mode is not
  // RELIABLE_ARQ.
  if (rcvd_pkts_ == NULL)
  {
    return false;
  }

  // Check if the specified next expected sequence number is greater than
  // rcv_min_.  If this is not the case, then there is nothing to do here.
  if (SEQ_GT(ne_seq_num, rcv_min_))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Moving forward to seq %" PRIPktSeqNumber ", rcv_min_ %"
         PRIPktSeqNumber " rcv_nxt_ %" PRIPktSeqNumber " rcv_max_ %"
         PRIPktSeqNumber ".\n", conn_id_, stream_id_, ne_seq_num, rcv_min_,
         rcv_nxt_, rcv_max_);
#endif

    // First, update rcv_min_.  Move the window forward until the new next
    // expected sequence number is reached, then attempt to move it forward as
    // far as possible.  Stop if the receive window becomes empty.
    while (SEQ_LEQ(rcv_min_, rcv_max_))
    {
      RcvdPktInfo&  rpi = rcvd_pkts_[(rcv_min_ % kFlowCtrlWindowPkts)];

      // Once ne_seq_num is reached, then rcv_min_ is moved to the right only
      // if the packet has been delivered or if the packet is an FEC encoded
      // packet.
      if (SEQ_GEQ(rcv_min_, ne_seq_num))
      {
        bool  drop = ((IS_RECEIVED(rpi) || IS_REGENERATED(rpi)) &&
                      (IS_DELIVERED(rpi) ||
                       (IS_FEC(rpi) && (rpi.fec_pkt_type_ == FEC_ENC_PKT))));

        if (!drop)
        {
          break;
        }
      }

#ifdef SLIQ_DEBUG
      if (IS_DELIVERED(rpi))
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Pkt seq %" PRIPktSeqNumber " already delivered, being "
             "dropped.\n", conn_id_, stream_id_, rcv_min_);
      }
      else
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Pkt seq %" PRIPktSeqNumber " being dropped.\n", conn_id_,
             stream_id_, rcv_min_);
      }
#endif

      // If this is an FEC source data packet, then add it to the FEC source
      // data packet array.
      if (IS_FEC(rpi) && (rpi.fec_pkt_type_ == FEC_SRC_PKT))
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Storing FEC SRC pkt seq %" PRIPktSeqNumber " for grp %"
             PRIFecGroupId " idx %" PRIFecSize ".\n", conn_id_, stream_id_,
             rcv_min_, rpi.fec_grp_id_, rpi.fec_grp_idx_);
#endif

        fec_src_pkts_[rpi.fec_grp_idx_].MoveFecInfo(rpi);
      }

      // Drop the element.
      if (rpi.packet_ != NULL)
      {
        packet_pool_.Recycle(rpi.packet_);
        rpi.packet_ = NULL;
      }

      ++rcv_min_;
    }

    // If the receive window is now empty and the new next expected sequence
    // was not reached, then simply adjust rcv_min_.
    if (SEQ_GT(rcv_min_, rcv_max_) && SEQ_LT(rcv_min_, ne_seq_num))
    {
      rcv_min_ = ne_seq_num;
    }

    // Next, update rcv_nxt_ as needed.
    if (SEQ_LT(rcv_nxt_, rcv_min_))
    {
      UpdateNextExpected(true);
    }

    // Finally, update rcv_max_ as needed.
    if (SEQ_LT(rcv_max_, (rcv_min_ - 1)))
    {
      rcv_max_ = (rcv_min_ - 1);
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Moved forward to seq %" PRIPktSeqNumber ", rcv_min_ %"
         PRIPktSeqNumber " rcv_nxt_ %" PRIPktSeqNumber " rcv_max_ %"
         PRIPktSeqNumber ".\n", conn_id_, stream_id_, ne_seq_num, rcv_min_,
         rcv_nxt_, rcv_max_);
#endif

    // An ACK should be sent when rcv_min_ is updated, since the advertised
    // window size might change.
    return true;
  }

  return false;
}

//============================================================================
size_t RcvdPktManager::PrepareNextAckHdr()
{
  size_t  len = kAckHdrBaseSize;

  if (rcvd_pkts_ == NULL)
  {
    return len;
  }

  // Add the length of any observed times.
  len += (obs_times_.cnt_ * kAckHdrObsTimeSize);

  // If this stream is currently in semi-reliable ARQ+FEC mode and there are
  // no new observed times, then attempt to add the latest observed time.
  if ((rel_.mode == SEMI_RELIABLE_ARQ_FEC) && (obs_times_.cnt_ == 0) &&
      obs_times_.has_latest_)
  {
    len += kAckHdrObsTimeSize;
  }

  // Add the length of any ACK block offsets.  If there are no missing data
  // packets, then there are no ACK block offsets.
  ack_blk_.Clear();

  if (SEQ_GT(rcv_max_, rcv_nxt_))
  {
    // Build the ACK blocks necessary for the ACK header.  The ACK blocks must
    // include the most recently received data packet and largest observed
    // data packet.  This is done as follows:
    // - As data packets are received, their sequence numbers are recorded in
    //   an ordered, circular list.
    // - Working from newest to oldest sequence number in the circular list:
    //     > Walk window forward and backward from the next most recent
    //       sequence number to generate an ACK block that does not repeat an
    //       existing ACK block.
    //     > If this is the second time through the loop, then walk the window
    //       forward and backward from the largest observed sequence number to
    //       generate an ACK block that does not repeat an existing ACK block.
    PktSeqNumber  seq_num = 0;

    for (size_t i = 0; i < kAckHistorySize; ++i)
    {
      // After the most recently received data packet has been processed (when
      // i = 0), generate an ACK block for the largest observed sequence
      // number (rcv_max_).
      if (i == 1)
      {
        GenerateAckBlock(rcv_max_);
      }

      // Attempt to get the next most recently received data packet sequence
      // number and generate an ACK block for it.
      if (!rct_rcvs_.GetSeqNum(i, seq_num))
      {
        break;
      }

      GenerateAckBlock(seq_num);

      // If the target number of ACK block offsets has been reached, then
      // stop.
      if (ack_blk_.hdr_cnt_ >= kTargetAckBlockOffsets)
      {
        break;
      }
    }

    // Add the length of the resulting ACK block offsets.
    len += (ack_blk_.hdr_cnt_ * kAckHdrAckBlockOffsetSize);
  }

  return len;
}

//============================================================================
bool RcvdPktManager::BuildNextAckHdr(AckHeader& ack_hdr, const Time& now)
{
  if (rcvd_pkts_ == NULL)
  {
    return false;
  }

  // This is a check just to warn if the element at the left edge of the
  // receive window still has a packet that has not been delivered to the
  // application.
  if (SEQ_LEQ(rcv_min_, rcv_max_))
  {
    RcvdPktInfo&  rpi = rcvd_pkts_[(rcv_min_ % kFlowCtrlWindowPkts)];

    if ((rpi.packet_ != NULL) && (IS_RECEIVED(rpi) || IS_REGENERATED(rpi)) &&
        ((!IS_FEC(rpi)) || (rpi.fec_pkt_type_ == FEC_SRC_PKT)) &&
        (!IS_DELIVERED(rpi)))
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Warning, packet at rcv_min_ %" PRIPktSeqNumber " is here but "
           "not delivered.\n", conn_id_, stream_id_, rcv_min_);
    }
  }

  // Populate the ACK header.
  ack_hdr.stream_id             = stream_id_;
  ack_hdr.num_observed_times    = 0;
  ack_hdr.num_ack_block_offsets = 0;
  ack_hdr.next_expected_seq_num = rcv_nxt_;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": ACK header: ne_seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
       ack_hdr.next_expected_seq_num);
#endif

  // Add any observed times to the ACK header.
  obs_times_.AddObsTimesToAckHdr(ack_hdr, now);

  // If this stream is currently in semi-reliable ARQ+FEC mode and there are
  // no new observed times, then attempt to add the latest observed time.
  // This is necessary in order to end the FEC group rounds quickly in the
  // presence of data and ACK packet loss.
  if ((rel_.mode == SEMI_RELIABLE_ARQ_FEC) &&
      (ack_hdr.num_observed_times == 0))
  {
    obs_times_.AddLatestObsTimeToAckHdr(ack_hdr, now);
  }

  // Add the ACK block offsets prepared in PrepareNextAckHdr() to the ACK
  // header.
  if (ack_blk_.cnt_ > 0)
  {
    ack_blk_.AddAckBlocksToAckHdr(ack_hdr, rcv_nxt_);
  }

  return true;
}

//============================================================================
bool RcvdPktManager::IsDataMissing() const
{
  // Note that if data packets are missing, then rcv_max_ will be greater
  // than rcv_nxt_.
  return (SEQ_GT(rcv_max_, rcv_nxt_));
}

//============================================================================
bool RcvdPktManager::IsAllDataAndFinConsumed() const
{
  // For best effort streams, once the FIN is received, all of the data is
  // considered consumed.
  if (rel_.mode == BEST_EFFORT)
  {
    return rcv_max_fin_flag_;
  }

  // Note that if all of the data packets have been delivered to the
  // application, then rcv_max_ will be one less than rcv_nxt_.
  return ((SEQ_LT(rcv_max_, rcv_nxt_)) && rcv_max_fin_flag_);
}

//============================================================================
void RcvdPktManager::UpdateNextExpected(bool reset_to_min)
{
  if (reset_to_min)
  {
    rcv_nxt_ = rcv_min_;
  }

  // Move rcv_nxt_ forward through the receive window until a packet that
  // has not been received or regenerated is found.
  while (SEQ_LEQ(rcv_nxt_, rcv_max_))
  {
    RcvdPktInfo&  rpi = rcvd_pkts_[(rcv_nxt_ % kFlowCtrlWindowPkts)];

    if (IS_RECEIVED(rpi) || IS_REGENERATED(rpi))
    {
      ++rcv_nxt_;
    }
    else
    {
      break;
    }
  }
}

//============================================================================
void RcvdPktManager::MoveWindowRight()
{
  // Move the left edge of the window up to the next packet that either has
  // not been delivered or has not been given up on yet.
  while (SEQ_LEQ(rcv_min_, rcv_max_))
  {
    RcvdPktInfo&  rpi = rcvd_pkts_[(rcv_min_ % kFlowCtrlWindowPkts)];

    // Decide if the left edge of the window can be moved right or not.
    // Delivered packets and FEC encoded packets can be dropped.
    if ((IS_RECEIVED(rpi) || IS_REGENERATED(rpi)) &&
        (IS_DELIVERED(rpi) || (IS_FEC(rpi) &&
                               (rpi.fec_pkt_type_ == FEC_ENC_PKT))))
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Moving right beyond pkt seq %" PRIPktSeqNumber ".\n", conn_id_,
           stream_id_, rcv_min_);
#endif

      // If this is an FEC source data packet, then add it to the FEC source
      // data packet array.
      if (IS_FEC(rpi) && (rpi.fec_pkt_type_ == FEC_SRC_PKT))
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Storing FEC SRC pkt seq %" PRIPktSeqNumber " for grp %"
             PRIFecGroupId " idx %" PRIFecSize ".\n", conn_id_, stream_id_,
             rcv_min_, rpi.fec_grp_id_, rpi.fec_grp_idx_);
#endif

        fec_src_pkts_[rpi.fec_grp_idx_].MoveFecInfo(rpi);
      }

      if (rpi.packet_ != NULL)
      {
        packet_pool_.Recycle(rpi.packet_);
        rpi.packet_ = NULL;
      }

      ++rcv_min_;
    }
    else
    {
      break;
    }
  }

  // If we have moved the window right over an undelivered packet, update
  // rcv_nxt_ as needed.
  if (SEQ_LT(rcv_nxt_, rcv_min_))
  {
    UpdateNextExpected(true);
  }
}

//============================================================================
void RcvdPktManager::GenerateAckBlock(PktSeqNumber seq_num)
{
  // Make sure that the packet is still within the window.
  if (SEQ_LT(seq_num, rcv_nxt_))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "  Packet seq %" PRIPktSeqNumber " no longer "
         "in window.\n", seq_num);
#endif

    return;
  }

  // Check if the packet is already covered by an ACK block.
  if ((ack_blk_.cnt_ > 0) && ack_blk_.IsAlreadyInAckBlock(seq_num))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "  Packet seq %" PRIPktSeqNumber " already "
         "covered by an ACK block.\n", seq_num);
#endif

    return;
  }

  // The packet is not already covered by an ACK block.  Walk the window
  // backward and forward from the specified sequence number to generate the
  // ACK block.
  PktSeqNumber  ack_lo = seq_num;
  PktSeqNumber  ack_hi = seq_num;

  for (PktSeqNumber sn = (seq_num - 1); SEQ_GEQ(sn, rcv_nxt_); --sn)
  {
    RcvdPktInfo&  rpi = rcvd_pkts_[(sn % kFlowCtrlWindowPkts)];

    if ((!IS_RECEIVED(rpi)) && (!IS_REGENERATED(rpi)))
    {
      break;
    }

    ack_lo = sn;
  }

  for (PktSeqNumber sn = (seq_num + 1); SEQ_LEQ(sn, rcv_max_); ++sn)
  {
    RcvdPktInfo&  rpi = rcvd_pkts_[(sn % kFlowCtrlWindowPkts)];

    if ((!IS_RECEIVED(rpi)) && (!IS_REGENERATED(rpi)))
    {
      break;
    }

    ack_hi = sn;
  }

  ack_blk_.AddAckBlock(ack_lo, ack_hi);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "  Packet seq %" PRIPktSeqNumber " ACK block %"
       PRIPktSeqNumber "-%" PRIPktSeqNumber ".\n", seq_num, ack_lo, ack_hi);
#endif
}

//============================================================================
void RcvdPktManager::StorePkt(DataHeader& pkt, RcvdPktInfo& pkt_info)
{
  // Release any existing Packet object in the RcvdPktInfo.
  if (pkt_info.packet_ != NULL)
  {
    // There might be an FEC regenerated packet, which is OK.  Otherwise, this
    // is unexpected.
    if (!IS_REGENERATED(pkt_info))
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Warning, seq %" PRIPktSeqNumber " was not received but has a "
           "pkt.\n", conn_id_, stream_id_, pkt.sequence_number);
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    }

    packet_pool_.Recycle(pkt_info.packet_);
    pkt_info.packet_ = NULL;
  }

  // If needed, get the packet's time-to-go (TTG) from the data header, update
  // it for the current one-way delay (OWD) estimate, and store it in the
  // payload Packet object.
  if (((!pkt.fec_flag) || (pkt.fec_pkt_type == FEC_SRC_PKT)) &&
      (pkt.payload != NULL) && (pkt.num_ttg == 1))
  {
    Time    rcv_time(pkt.payload->recv_time());
    double  owd_est_sec = conn_.GetRtlOwdEst(pkt.timestamp, rcv_time);
    double  new_ttg_sec = (pkt.ttg[0] - owd_est_sec);

    if (new_ttg_sec < 0.0)
    {
      new_ttg_sec = 0.0;
    }

    Time  nttg(new_ttg_sec);

    pkt.payload->set_track_ttg(true);
    pkt.payload->SetTimeToGo(nttg, true);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Latency-sensitive pkt seq %" PRIPktSeqNumber " rcv_ttg %f "
         "owd_est %f new_ttg %f\n", conn_id_, stream_id_, pkt.sequence_number,
         pkt.ttg[0], owd_est_sec, new_ttg_sec);
#endif

#ifdef TTG_TRACKING
    // Log the amount that the TTG was reduced by.
    // Format:  PLT_OWD <seq_num> <ttg_delta> <final_ttg>
    LogC(kClassName, __func__, "Conn %" PRIEndptId ": PLT_OWD %"
         PRIPktSeqNumber " %f %f\n", conn_id_, pkt.sequence_number,
         owd_est_sec, new_ttg_sec);
#endif // TTG_TRACKING
  }

  // Store the packet's information.
  pkt_info.packet_         = pkt.payload;
  pkt_info.seq_num_        = pkt.sequence_number;
  pkt_info.payload_offset_ = pkt.payload_offset;
  pkt_info.payload_len_    = pkt.payload_length;
  pkt_info.rexmit_cnt_     = pkt.retransmission_count;
  pkt_info.flags_          = 0;

  if (pkt.fec_flag)
  {
    SET_FEC(pkt_info);

    pkt_info.fec_pkt_type_    = static_cast<uint8_t>(pkt.fec_pkt_type);
    pkt_info.fec_grp_id_      = pkt.fec_group_id;
    pkt_info.fec_enc_pkt_len_ = pkt.encoded_pkt_length;
    pkt_info.fec_grp_idx_     = pkt.fec_group_index;
    pkt_info.fec_num_src_     = pkt.fec_num_src;
    pkt_info.fec_round_       = pkt.fec_round;

    if ((pkt.fec_pkt_type == FEC_ENC_PKT) && (!pkt.enc_pkt_len_flag))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Warning, seq %" PRIPktSeqNumber " is FEC ENC pkt with no "
           "encoded packet length.\n", conn_id_, stream_id_,
           pkt.sequence_number);
    }

    if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
    {
      // Update the FEC group information.
      FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                               kFecGroupInfoSize)];

      if (grp_info.fec_grp_id_ != pkt_info.fec_grp_id_)
      {
        // This is a new FEC group information entry.
        grp_info.fec_grp_id_    = pkt_info.fec_grp_id_;
        grp_info.delivered_cnt_ = 0;
        grp_info.ttg_cnt_       = 0;

        if (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)
        {
          grp_info.fec_num_src_       = 0;
          grp_info.fec_src_rcvd_cnt_  = 1;
          grp_info.fec_enc_rcvd_cnt_  = 0;
          grp_info.start_src_seq_num_ = pkt.sequence_number;
          grp_info.start_enc_seq_num_ = 0;
        }
        else
        {
          grp_info.fec_num_src_       = pkt_info.fec_num_src_;
          grp_info.fec_src_rcvd_cnt_  = 0;
          grp_info.fec_enc_rcvd_cnt_  = 1;
          grp_info.start_src_seq_num_ = 0;
          grp_info.start_enc_seq_num_ = pkt.sequence_number;
        }
      }
      else
      {
        // This is an existing FEC group information entry.
        if (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)
        {
          ++(grp_info.fec_src_rcvd_cnt_);

          if ((grp_info.fec_src_rcvd_cnt_ == 1) ||
              (SEQ_LT(pkt.sequence_number, grp_info.start_src_seq_num_)))
          {
            grp_info.start_src_seq_num_ = pkt.sequence_number;
          }
        }
        else
        {
          if (grp_info.fec_num_src_ == 0)
          {
            grp_info.fec_num_src_ = pkt_info.fec_num_src_;
          }

          // The number of FEC source packets must match.
          if (pkt_info.fec_num_src_ != grp_info.fec_num_src_)
          {
            LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
                 PRIStreamId ": Error, num_src mismatch (%" PRIFecSize
                 " != %" PRIFecSize ").\n", conn_id_, stream_id_,
                 pkt_info.fec_num_src_, grp_info.fec_num_src_);
            if (pkt_info.fec_num_src_ > grp_info.fec_num_src_)
            {
              grp_info.fec_num_src_ = pkt_info.fec_num_src_;
            }
          }

          ++(grp_info.fec_enc_rcvd_cnt_);

          if ((grp_info.fec_enc_rcvd_cnt_ == 1) ||
              (SEQ_LT(pkt.sequence_number, grp_info.start_enc_seq_num_)))
          {
            grp_info.start_enc_seq_num_ = pkt.sequence_number;
          }
        }
      }

      // Store the FEC encoded packet's TTG values if there are enough of them
      // for all of the FEC source packets in the group.
      if ((pkt_info.fec_pkt_type_ == FEC_ENC_PKT) &&
          (pkt.num_ttg >= pkt_info.fec_num_src_))
      {
        grp_info.ttg_cnt_ = pkt.num_ttg;

        if (grp_info.ttg_cnt_ > kMaxTtgs)
        {
          grp_info.ttg_cnt_ = kMaxTtgs;
        }

        for (TtgCount i = 0; i < grp_info.ttg_cnt_; ++i)
        {
          grp_info.ttg_[i] = pkt.ttg[i];
        }
      }

#ifdef SLIQ_DEBUG
      if (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Received FEC src pkt: seq %" PRIPktSeqNumber " rx %"
             PRIRetransCount " grp %" PRIFecGroupId " idx %" PRIFecSize
             " rnd %" PRIFecRound " rcvd_src %" PRIFecSize " rcvd_enc %"
             PRIFecSize " ttg_cnt %" PRITtgCount ".\n", conn_id_, stream_id_,
             pkt.sequence_number, pkt.retransmission_count, pkt.fec_group_id,
             pkt.fec_group_index, pkt.fec_round, grp_info.fec_src_rcvd_cnt_,
             grp_info.fec_enc_rcvd_cnt_, grp_info.ttg_cnt_);
        if (pkt.num_ttg > 0)
        {
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ":   ttg %" PRITtgCount " %f\n", conn_id_,
               stream_id_, pkt.num_ttg, pkt.ttg[0]);
        }
      }
      else
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Received FEC enc pkt: seq %" PRIPktSeqNumber " rx %"
             PRIRetransCount " grp %" PRIFecGroupId " idx %" PRIFecSize
             " num_src %" PRIFecSize " rnd %" PRIFecRound " rcvd_src %"
             PRIFecSize " rcvd_enc %" PRIFecSize " ttg_cnt %" PRITtgCount
             ".\n", conn_id_, stream_id_, pkt.sequence_number,
             pkt.retransmission_count, pkt.fec_group_id, pkt.fec_group_index,
             pkt.fec_num_src, pkt.fec_round, grp_info.fec_src_rcvd_cnt_,
             grp_info.fec_enc_rcvd_cnt_, grp_info.ttg_cnt_);
        if (pkt.num_ttg > 0)
        {
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ":   ttg %" PRITtgCount " %f %f %f %f %f %f %f %f "
               "%f %f\n", conn_id_, stream_id_, pkt.num_ttg, pkt.ttg[0],
               pkt.ttg[1], pkt.ttg[2], pkt.ttg[3], pkt.ttg[4], pkt.ttg[5],
               pkt.ttg[6], pkt.ttg[7], pkt.ttg[8], pkt.ttg[9]);
        }
      }
#endif
    }
  }

  if (pkt.fin_flag)
  {
    SET_FIN(pkt_info);
  }

  SET_RECEIVED(pkt_info);

  // The packet is now owned by the packet information object.
  pkt.payload = NULL;
}

//============================================================================
void RcvdPktManager::RegeneratePkts(DataHeader& fec_pkt, const Time& rcv_time)
{
  FecGroupId     grp_id   = fec_pkt.fec_group_id;
  FecGroupInfo&  grp_info = fec_grp_info_[(grp_id % kFecGroupInfoSize)];

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Examining FEC pkts in grp %" PRIFecGroupId " due to idx %"
       PRIFecSize " seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
       grp_id, fec_pkt.fec_group_index, fec_pkt.sequence_number);
#endif

  // Make sure that there is FEC group information for the packet.
  if (grp_info.fec_grp_id_ != grp_id)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": No FEC group info found for grp %" PRIFecGroupId ".\n", conn_id_,
         stream_id_, grp_id);
    return;
  }

  // If no FEC encoded data packets have been received for the FEC group or
  // the number of FEC source data packets for the FEC group is not known,
  // then regeneration cannot be done yet.
  if ((grp_info.fec_enc_rcvd_cnt_ == 0) || (grp_info.fec_num_src_ == 0))
  {
    return;
  }

  // If we have all of the FEC source data packets, or if we do not have the
  // correct total number of FEC source and encoded data packets, then
  // regeneration is not needed.
  if ((grp_info.fec_src_rcvd_cnt_ == grp_info.fec_num_src_) ||
      ((grp_info.fec_src_rcvd_cnt_ + grp_info.fec_enc_rcvd_cnt_) !=
       grp_info.fec_num_src_))
  {
    return;
  }

  int           in_idx  = 0;
  FecSize       src_cnt = 0;
  PktSeqNumber  seq_num = 0;
  RetransCount  max_rnd = 0;

  // Clear the VDM decoder information.
  memset(&vdm_info_, 0, sizeof(vdm_info_));

  // Look for which FEC source packets have been received.
  for (seq_num = grp_info.start_src_seq_num_;
       ((grp_info.fec_src_rcvd_cnt_ > 0) &&
        (src_cnt < grp_info.fec_src_rcvd_cnt_) &&
        SEQ_LEQ(seq_num, rcv_max_)); ++seq_num)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Considering seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
         seq_num);
#endif

    FecSize  src_idx = 0;
    bool     in_wnd  = SEQ_GEQ(seq_num, rcv_min_);

    // If the packet is not in the current window, then search for it in the
    // FEC source packet array.
    if (!in_wnd)
    {
      bool  pkt_found = false;

      for (src_idx = 0; src_idx < grp_info.fec_num_src_; ++src_idx)
      {
        if ((fec_src_pkts_[src_idx].seq_num_ == seq_num) &&
            (fec_src_pkts_[src_idx].fec_grp_id_ == grp_id) &&
            (fec_src_pkts_[src_idx].packet_ != NULL))
        {
#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Found FEC SRC seq %" PRIPktSeqNumber " grp %"
               PRIFecGroupId " at index %" PRIFecSize " outside of window."
               "\n", conn_id_, stream_id_, seq_num, grp_id, src_idx);
#endif

          pkt_found = true;
          break;
        }
      }

      if (!pkt_found)
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Could not find FEC SRC seq %" PRIPktSeqNumber " grp %"
             PRIFecGroupId " outside of window.\n", conn_id_, stream_id_,
             seq_num, grp_id);
#endif

        continue;
      }
    }

    RcvdPktInfo&  pkt_info = (in_wnd ?
                              rcvd_pkts_[(seq_num % kFlowCtrlWindowPkts)] :
                              fec_src_pkts_[(src_idx %
                                             kMaxFecGroupLengthPkts)]);

    // If any packet has been regenerated in this FEC group, then the
    // regeneration work is already done.
    if (IS_REGENERATED(pkt_info) && (pkt_info.fec_grp_id_ == grp_id))
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Found regenerated pkt seq %" PRIPktSeqNumber ", stopping.\n",
           conn_id_, stream_id_, seq_num);
#endif
      return;
    }

    // Only consider received FEC source packets.
    if (IS_RECEIVED(pkt_info) && IS_FEC(pkt_info) &&
        (pkt_info.fec_pkt_type_ == FEC_SRC_PKT))
    {
      // If this FEC source packet is from another FEC group, then stop.
      if (pkt_info.fec_grp_id_ != grp_id)
      {
        break;
      }

      // The FEC source data packet must still be available.
      if (pkt_info.packet_ == NULL)
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, NULL packet pointer for received FEC SRC data packet."
             "\n", conn_id_, stream_id_);
      }

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Found received FEC SRC pkt seq %" PRIPktSeqNumber " idx %"
           PRIFecSize ".\n", conn_id_, stream_id_, seq_num,
           pkt_info.fec_grp_idx_);
#endif

      // This is a received FEC source data packet for the FEC group we are
      // looking for.
      uint8_t*  pkt_ptr    =
        pkt_info.packet_->GetBuffer(pkt_info.payload_offset_);
      size_t    packet_len = static_cast<size_t>(pkt_info.payload_len_);
      uint16_t  pkt_len    = static_cast<uint16_t>(packet_len);

      // Update the maximum FEC group round found so far.
      if (pkt_info.fec_round_ == 0)
      {
        max_rnd = kOutOfRounds;
      }
      else
      {
        if (pkt_info.fec_round_ > max_rnd)
        {
          max_rnd = pkt_info.fec_round_;
        }
      }

      // Copy the packet's sequence number to the end of the payload if
      // needed.  This is only used for decoding the sequence number of
      // regenerated FEC source data packets when in FEC mode in order to
      // position them correctly within the received packet window.
      if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
      {
        uint32_t  seq_num_nbo = htonl(seq_num);

        if ((pkt_info.payload_offset_ + packet_len + sizeof(seq_num_nbo)) >
            pkt_info.packet_->GetMaxLengthInBytes())
        {
          LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Error, FEC SRC data packet %" PRIPktSeqNumber
               " is too big to add sequence number.\n", conn_id_, stream_id_,
               seq_num);
          return;
        }

        ::memcpy(reinterpret_cast<void*>(
                   pkt_info.packet_->GetBuffer(pkt_info.payload_offset_ +
                                               packet_len)),
                 &seq_num_nbo, sizeof(seq_num_nbo));

        pkt_len += static_cast<uint16_t>(sizeof(seq_num_nbo));
      }

      vdm_info_.num_src_pkt_                         = (in_idx + 1);
      vdm_info_.in_pkt_data_[in_idx]                 = pkt_ptr;
      vdm_info_.in_pkt_size_[in_idx]                 = pkt_len;
      vdm_info_.in_enc_pkt_size_[in_idx]             = pkt_len;
      vdm_info_.in_pkt_index_[in_idx]                = pkt_info.fec_grp_idx_;
      vdm_info_.out_pkt_data_[pkt_info.fec_grp_idx_] = pkt_ptr;
      ++in_idx;
      ++src_cnt;
    }
  }

  // Verify the number of FEC source data packets found.
  if (src_cnt != grp_info.fec_src_rcvd_cnt_)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Warning, only found %" PRIFecSize " of %" PRIFecSize " FEC SRC "
         "pkts for grp %" PRIFecGroupId ".\n", conn_id_, stream_id_, src_cnt,
         grp_info.fec_src_rcvd_cnt_, grp_id);
    return;
  }

  // Make sure that the starting FEC encoded data packet is still present in
  // the window.  If this is not the case, then regeneration of missing
  // packets is impossible.
  if (SEQ_LT(grp_info.start_enc_seq_num_, rcv_min_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Start of FEC ENC group (%" PRIPktSeqNumber ") < rcv_min_ (%"
         PRIPktSeqNumber ") in grp %" PRIFecGroupId ".\n", conn_id_,
         stream_id_, grp_info.start_enc_seq_num_, rcv_min_, grp_id);
    return;
  }

  FecSize  enc_cnt = 0;

  // Look for which FEC encoded packets have been received.
  for (seq_num = grp_info.start_enc_seq_num_;
       ((enc_cnt < grp_info.fec_enc_rcvd_cnt_) && SEQ_LEQ(seq_num, rcv_max_));
       ++seq_num)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Considering seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
         seq_num);
#endif

    RcvdPktInfo&  pkt_info = rcvd_pkts_[(seq_num % kFlowCtrlWindowPkts)];

    // Only consider received FEC encoded data packets for this group.
    if (IS_RECEIVED(pkt_info) && IS_FEC(pkt_info) &&
        (pkt_info.fec_pkt_type_ == FEC_ENC_PKT) &&
        (pkt_info.fec_grp_id_ == grp_id))
    {
      // The FEC encoded data packet must still be available.
      if (pkt_info.packet_ == NULL)
      {
        // If this is the FIN packet, then there may not be any payload.
        // Regenerating FEC source data packets can be skipped in this case.
        if (IS_FIN(pkt_info))
        {
          return;
        }

        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, NULL packet pointer for received FEC ENC data packet."
             "\n", conn_id_, stream_id_);
        return;
      }

      // The FEC encoded data packet index must not exceed the index limit.
      if (pkt_info.fec_grp_idx_ >= kMaxFecGroupLengthPkts)
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Invalid index %" PRIFecSize ".\n", conn_id_, stream_id_,
             pkt_info.fec_grp_idx_);
        return;
      }

      // The number of FEC source data packets values must match.
      if (pkt_info.fec_num_src_ != grp_info.fec_num_src_)
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, num_src mismatch (%" PRIFecSize " != %" PRIFecSize
             ").\n", conn_id_, stream_id_, pkt_info.fec_num_src_,
             grp_info.fec_num_src_);
        return;
      }

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Found received FEC ENC pkt seq %" PRIPktSeqNumber " idx %"
           PRIFecSize " num_src %" PRIFecSize ".\n",
           conn_id_, stream_id_, seq_num, pkt_info.fec_grp_idx_,
           pkt_info.fec_num_src_);
#endif

      // This is a received FEC encoded data packet for the FEC group we are
      // looking for.
      uint8_t*  pkt_ptr = pkt_info.packet_->GetBuffer(
        pkt_info.payload_offset_);
      uint16_t  pkt_len = static_cast<uint16_t>(pkt_info.payload_len_);

      // Update the maximum FEC group round found so far.
      if (pkt_info.fec_round_ == 0)
      {
        max_rnd = kOutOfRounds;
      }
      else
      {
        if (pkt_info.fec_round_ > max_rnd)
        {
          max_rnd = pkt_info.fec_round_;
        }
      }

      vdm_info_.num_src_pkt_             = (in_idx + 1);
      vdm_info_.in_pkt_data_[in_idx]     = pkt_ptr;
      vdm_info_.in_pkt_size_[in_idx]     = pkt_len;
      vdm_info_.in_enc_pkt_size_[in_idx] = pkt_info.fec_enc_pkt_len_;
      vdm_info_.in_pkt_index_[in_idx]    = pkt_info.fec_grp_idx_;
      ++in_idx;
      ++enc_cnt;
    }
  }

  // Verify the number of FEC encoded data packets found.
  if (enc_cnt != grp_info.fec_enc_rcvd_cnt_)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, only found %" PRIFecSize " of %" PRIFecSize " FEC ENC "
         "pkts.\n", conn_id_, stream_id_, enc_cnt,
         grp_info.fec_enc_rcvd_cnt_);
  }

  // Verify the number of FEC source and encoded data packets found.
  if (vdm_info_.num_src_pkt_ != static_cast<int>(grp_info.fec_num_src_))
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, only found %d of %" PRIFecSize " FEC pkts.\n", conn_id_,
         stream_id_, vdm_info_.num_src_pkt_, grp_info.fec_num_src_);
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Results src %" PRIFecSize " enc %" PRIFecSize " num_src %"
       PRIFecSize ".\n", conn_id_, stream_id_, src_cnt, enc_cnt,
       grp_info.fec_num_src_);
#endif

  // Set the output packet information for the FEC source data packets that
  // will be regenerated.
  int  out_idx = 0;

  for (out_idx = 0; out_idx < grp_info.fec_num_src_; ++out_idx)
  {
    if (vdm_info_.out_pkt_data_[out_idx] == NULL)
    {
      vdm_info_.out_pkt_[out_idx] = packet_pool_.Get();

      if (vdm_info_.out_pkt_[out_idx] == NULL)
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error getting packet from pool.\n", conn_id_, stream_id_);
      }

      vdm_info_.out_pkt_data_[out_idx] =
        vdm_info_.out_pkt_[out_idx]->GetBuffer(0);
    }
  }

  // Decode the packets.
  if (VdmFec::DecodePackets(vdm_info_.num_src_pkt_, vdm_info_.in_pkt_data_,
                            vdm_info_.in_pkt_size_,
                            vdm_info_.in_enc_pkt_size_,
                            vdm_info_.in_pkt_index_, vdm_info_.out_pkt_data_,
                            vdm_info_.out_pkt_size_) != 0)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error decoding FEC packets for grp %" PRIFecGroupId ".\n",
         conn_id_, stream_id_, grp_id);

    // Release the allocated Packet objects that were to be used to hold the
    // decoding data packets.
    for (out_idx = 0; out_idx < grp_info.fec_num_src_; ++out_idx)
    {
      if (vdm_info_.out_pkt_[out_idx] != NULL)
      {
        packet_pool_.Recycle(vdm_info_.out_pkt_[out_idx]);
        vdm_info_.out_pkt_[out_idx] = NULL;
      }
    }

    return;
  }

  // Compute the time-to-go (TTG) correction, if any.  This is necessary if
  // the last packet received in the group is an FEC source packet, it has a
  // TTG, and a TTG vector was received for the group previously in an FEC
  // encoded packet.
  double  ttg_corr = 0.0;

  if ((fec_pkt.fec_pkt_type == FEC_SRC_PKT) &&
      (fec_pkt.num_ttg == 1) && (grp_info.ttg_cnt_ >= grp_info.fec_num_src_))
  {
    ttg_corr = (grp_info.ttg_[fec_pkt.fec_group_index] - fec_pkt.ttg[0]);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Packet TTG correction (%f - %f) = %f\n", conn_id_, stream_id_,
         static_cast<double>(grp_info.ttg_[fec_pkt.fec_group_index]),
         fec_pkt.ttg[0], ttg_corr);
#endif
  }

  // Store the regenerated FEC source data packets while updating their sizes.

  // The position of the FEC source data packets can vary.  Use the decoded
  // sequence numbers in the regenerated FEC source data packets to position
  // them correctly.
  for (out_idx = 0; out_idx < grp_info.fec_num_src_; ++out_idx)
  {
    if (vdm_info_.out_pkt_[out_idx] != NULL)
    {
      // This is a missing FEC source data packet.  Get the sequence number.
      Packet*   pkt         = vdm_info_.out_pkt_[out_idx];
      uint16_t  pkt_len     = vdm_info_.out_pkt_size_[out_idx];
      uint32_t  seq_num_nbo = 0;

      if (pkt_len < sizeof(seq_num_nbo))
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC SRC pkt for grp %" PRIFecGroupId " too small for "
             "sequence number.\n", conn_id_, stream_id_, grp_id);
      }

      pkt_len -= sizeof(seq_num_nbo);
      ::memcpy(&seq_num_nbo, reinterpret_cast<void*>(pkt->GetBuffer(pkt_len)),
               sizeof(seq_num_nbo));
      seq_num = ntohl(seq_num_nbo);

      // Make sure that the regenerated FEC source data packet is still
      // within the window.
      if (SEQ_LT(seq_num, rcv_min_))
      {
        LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Warning, no place for FEC SRC pkt seq %" PRIPktSeqNumber
             " in grp %" PRIFecGroupId " idx %d.\n", conn_id_, stream_id_,
             seq_num, grp_id, out_idx);
      }
      else
      {
        RcvdPktInfo&  pkt_info = rcvd_pkts_[(seq_num % kFlowCtrlWindowPkts)];

        if (IS_RECEIVED(pkt_info))
        {
          LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Error, FEC SRC pkt seq %" PRIPktSeqNumber
               " in grp %" PRIFecGroupId " idx %d already received.\n",
               conn_id_, stream_id_, seq_num, grp_id, out_idx);
        }

        if (pkt_info.packet_ != NULL)
        {
          packet_pool_.Recycle(pkt_info.packet_);
        }

        pkt_info.packet_            = pkt;
        vdm_info_.out_pkt_[out_idx] = NULL;

        pkt_info.seq_num_ = seq_num;
        pkt_info.flags_   = 0;

        SET_FEC(pkt_info);

        pkt_info.fec_pkt_type_    = static_cast<uint8_t>(FEC_SRC_PKT);
        pkt_info.fec_grp_id_      = grp_id;
        pkt_info.fec_enc_pkt_len_ = 0;
        pkt_info.fec_grp_idx_     = static_cast<FecSize>(out_idx);
        pkt_info.fec_num_src_     = grp_info.fec_num_src_;
        pkt_info.fec_round_       = max_rnd;

        SET_REGENERATED(pkt_info);

        pkt_info.packet_->SetLengthInBytes(pkt_len);
        pkt_info.packet_->set_recv_time(rcv_time);
        pkt_info.payload_offset_ = 0;
        pkt_info.payload_len_    = pkt_len;
        pkt_info.rexmit_cnt_     = 0;

        // Determine the TTG for the regenerated FEC source packet, if
        // possible.
        double  new_ttg_sec = 0.0;

        if (grp_info.ttg_cnt_ >= grp_info.fec_num_src_)
        {
          double  owd_est_sec = conn_.GetRtlOwdEst(0, rcv_time);

          new_ttg_sec = (grp_info.ttg_[out_idx] - owd_est_sec - ttg_corr);

          if (new_ttg_sec < 0.0)
          {
            new_ttg_sec = 0.0;
          }

          Time  nttg(new_ttg_sec);

          pkt_info.packet_->set_track_ttg(true);
          pkt_info.packet_->SetTimeToGo(nttg, true);

#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Latency-sensitive pkt seq %" PRIPktSeqNumber
               " enc_ttg %f owd_est %f ttg_corr %f new_ttg %f.\n", conn_id_,
               stream_id_, seq_num,
               static_cast<double>(grp_info.ttg_[out_idx]), owd_est_sec,
               ttg_corr, new_ttg_sec);
#endif

#ifdef TTG_TRACKING
          // Log the amount that the TTG was reduced by.
          // Format:  PLT_OWD <seq_num> <ttg_delta> <final_ttg>
          LogC(kClassName, __func__, "Conn %" PRIEndptId ": PLT_OWD %"
               PRIPktSeqNumber " %f %f\n", conn_id_, seq_num, owd_est_sec,
               new_ttg_sec);
#endif // TTG_TRACKING
        }

        // Record the packet's sequence number as a recently regenerated
        // data packet.
        rct_rcvs_.RecordSeqNum(seq_num);

        // Update the packet regeneration statistics.
        ++stats_pkts_.fec_src_regen_;

#ifdef SLIQ_DEBUG
        if (pkt_info.packet_->track_ttg())
        {
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Regenerated grp %" PRIFecGroupId " idx %d seq %"
               PRIPktSeqNumber " len %" PRIu16 " ttg %f.\n", conn_id_,
               stream_id_, grp_id, out_idx, seq_num, pkt_len, new_ttg_sec);
        }
        else
        {
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Regenerated grp %" PRIFecGroupId " idx %d seq %"
               PRIPktSeqNumber " len %" PRIu16 ".\n", conn_id_, stream_id_,
               grp_id, out_idx, seq_num, pkt_len);
        }
#endif
      }
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Completed grp %" PRIFecGroupId " via regeneration.\n", conn_id_,
       stream_id_, grp_id);
#endif

  // Update the packet receive statistics for the regenerated FEC source
  // packets.
  if (((rel_.fec_del_time_flag) && (max_rnd < kOutOfRounds)) ||
      ((!rel_.fec_del_time_flag) &&
       (max_rnd <= rel_.fec_target_pkt_del_rounds)))
  {
    // Increment the number of FEC source packets received, and decrement the
    // number of "extra" FEC encoded packets used to do the regeneration.
    stats_pkts_.fec_total_src_rcvd_ += static_cast<size_t>(enc_cnt);
    stats_pkts_.fec_total_ext_rcvd_ -= static_cast<size_t>(enc_cnt);
  }

  // Release any allocated Packet objects that were not transferred to
  // received packet information entries.
  for (out_idx = 0; out_idx < grp_info.fec_num_src_; ++out_idx)
  {
    if (vdm_info_.out_pkt_[out_idx] != NULL)
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Warning, FEC SRC Packet object for grp %" PRIFecGroupId " idx "
           "%d not used.\n", conn_id_, stream_id_, grp_id, out_idx);

      packet_pool_.Recycle(vdm_info_.out_pkt_[out_idx]);
      vdm_info_.out_pkt_[out_idx] = NULL;
    }
  }
}

//============================================================================
RcvdPktManager::RcvdPktInfo::RcvdPktInfo()
    : packet_(NULL), seq_num_(0), payload_offset_(0), payload_len_(0),
      rexmit_cnt_(0), flags_(0), fec_pkt_type_(0), fec_grp_id_(0),
      fec_enc_pkt_len_(0), fec_grp_idx_(0), fec_num_src_(0), fec_round_(0)
{
}

//============================================================================
RcvdPktManager::RcvdPktInfo::~RcvdPktInfo()
{
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }
}

//============================================================================
void RcvdPktManager::RcvdPktInfo::Clear()
{
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }

  seq_num_         = 0;
  payload_offset_  = 0;
  payload_len_     = 0;
  rexmit_cnt_      = 0;
  flags_           = 0;
  fec_pkt_type_    = 0;
  fec_grp_id_      = 0;
  fec_enc_pkt_len_ = 0;
  fec_grp_idx_     = 0;
  fec_num_src_     = 0;
  fec_round_       = 0;
}

//============================================================================
void RcvdPktManager::RcvdPktInfo::MoveFecInfo(RcvdPktInfo& rpi)
{
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }

  packet_     = rpi.packet_;
  rpi.packet_ = NULL;

  seq_num_         = rpi.seq_num_;
  payload_offset_  = rpi.payload_offset_;
  payload_len_     = rpi.payload_len_;
  rexmit_cnt_      = rpi.rexmit_cnt_;
  flags_           = rpi.flags_;
  fec_pkt_type_    = rpi.fec_pkt_type_;
  fec_grp_id_      = rpi.fec_grp_id_;
  fec_enc_pkt_len_ = rpi.fec_enc_pkt_len_;
  fec_grp_idx_     = rpi.fec_grp_idx_;
  fec_num_src_     = rpi.fec_num_src_;
  fec_round_       = rpi.fec_round_;
}

//============================================================================
RcvdPktManager::RctRcvInfo::RctRcvInfo()
    : cnt_(0), offset_(0), seq_num_()
{
}

//============================================================================
RcvdPktManager::RctRcvInfo::~RctRcvInfo()
{
}

//============================================================================
void RcvdPktManager::RctRcvInfo::RecordSeqNum(PktSeqNumber seq_num)
{
  offset_           = ((offset_ + 1) % kAckHistorySize);
  seq_num_[offset_] = seq_num;

  if (cnt_ < kAckHistorySize)
  {
    ++cnt_;
  }
}

//============================================================================
bool RcvdPktManager::RctRcvInfo::GetSeqNum(size_t i, PktSeqNumber& seq_num)
{
  bool  rv = (i < cnt_);

  if (rv)
  {
    seq_num = seq_num_[((offset_ + kAckHistorySize - i) % kAckHistorySize)];
  }

  return rv;
}

//============================================================================
RcvdPktManager::AckBlkInfo::AckBlkInfo()
    : cnt_(0), hdr_cnt_(0), ack_blk_()
{
}

//============================================================================
RcvdPktManager::AckBlkInfo::~AckBlkInfo()
{
}

//============================================================================
bool RcvdPktManager::AckBlkInfo::IsAlreadyInAckBlock(PktSeqNumber seq_num)
{
  // Check for the sequence number in an ACK block.
  for (size_t i = 0; i < cnt_; ++i)
  {
    if (SEQ_GEQ(seq_num, ack_blk_[i][0]) && SEQ_LEQ(seq_num, ack_blk_[i][1]))
    {
      return true;
    }
  }

  return false;
}

//============================================================================
void RcvdPktManager::AckBlkInfo::AddAckBlock(PktSeqNumber ack_lo,
                                             PktSeqNumber ack_hi)
{
  if (cnt_ >= kMaxAckBlockOffsets)
  {
    LogW(kClassName, __func__, "Warning, too many ACK blocks for array.\n");
    return;
  }

  // Add the ACK block.
  ack_blk_[cnt_][0] = ack_lo;
  ack_blk_[cnt_][1] = ack_hi;
  ++cnt_;

  // Update the ACK block offset count for the ACK header.
  hdr_cnt_ += ((ack_lo == ack_hi) ? 1 : 2);
}

//============================================================================
void RcvdPktManager::AckBlkInfo::AddAckBlocksToAckHdr(AckHeader& ack_hdr,
                                                      PktSeqNumber rcv_nxt)
{
  if (cnt_ > 0)
  {
    // Add the ACK blocks, converting sequence numbers to 15-bit offsets.
    size_t  hdr_idx = 0;

    for (size_t i = 0; i < cnt_; ++i)
    {
      if (ack_blk_[i][0] == ack_blk_[i][1])
      {
        // Single ACK.
        if (SEQ_LT(ack_blk_[i][0], rcv_nxt))
        {
          LogF(kClassName, __func__, "Invalid single ACK seq %"
               PRIPktSeqNumber ", rcv_nxt %" PRIPktSeqNumber ".\n",
               ack_blk_[i][0], rcv_nxt);
        }

        if (hdr_idx >= kMaxAckBlockOffsets)
        {
          break;
        }

        ack_hdr.ack_block_offset[hdr_idx].type   = ACK_BLK_SINGLE;
        ack_hdr.ack_block_offset[hdr_idx].offset =
          static_cast<uint16_t>(ack_blk_[i][0] - rcv_nxt);
        ++hdr_idx;

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "  ACK block offset %zu SINGLE seq %"
             PRIPktSeqNumber " offset %" PRIPktSeqNumber ".\n", (hdr_idx - 1),
             ack_blk_[i][0], (ack_blk_[i][0] - rcv_nxt));
#endif
      }
      else
      {
        // Multiple ACKs.
        if ((SEQ_LT(ack_blk_[i][0], rcv_nxt)) ||
            (SEQ_LT(ack_blk_[i][1], rcv_nxt)) ||
            (SEQ_GT(ack_blk_[i][0], ack_blk_[i][1])))
        {
          LogF(kClassName, __func__, "Invalid multi ACK seq %" PRIPktSeqNumber
               "-%" PRIPktSeqNumber ", rcv_nxt %" PRIPktSeqNumber ".\n",
               ack_blk_[i][0], ack_blk_[i][1], rcv_nxt);
        }

        if (hdr_idx >= (kMaxAckBlockOffsets - 1))
        {
          break;
        }

        ack_hdr.ack_block_offset[hdr_idx].type   = ACK_BLK_MULTI;
        ack_hdr.ack_block_offset[hdr_idx].offset =
          static_cast<uint16_t>(ack_blk_[i][0] - rcv_nxt);
        ++hdr_idx;

        ack_hdr.ack_block_offset[hdr_idx].type   = ACK_BLK_MULTI;
        ack_hdr.ack_block_offset[hdr_idx].offset =
          static_cast<uint16_t>(ack_blk_[i][1] - rcv_nxt);
        ++hdr_idx;

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "  ACK block offset %zu MULTI seq %"
             PRIPktSeqNumber " offset %" PRIPktSeqNumber ".\n", (hdr_idx - 2),
             ack_blk_[i][0], (ack_blk_[i][0] - rcv_nxt));
        LogD(kClassName, __func__, "  ACK block offset %zu MULTI seq %"
             PRIPktSeqNumber " offset %" PRIPktSeqNumber ".\n", (hdr_idx - 1),
             ack_blk_[i][1], (ack_blk_[i][1] - rcv_nxt));
#endif
      }
    }

    ack_hdr.num_ack_block_offsets = static_cast<uint8_t>(hdr_idx);
  }
  else
  {
    ack_hdr.num_ack_block_offsets = 0;
  }
}

//============================================================================
RcvdPktManager::PktObsTime::PktObsTime()
    : seq_num_(0), timestamp_(0), rcv_time_()
{
}

//============================================================================
RcvdPktManager::PktObsTime::~PktObsTime()
{
}

//============================================================================
RcvdPktManager::ObsTimeInfo::ObsTimeInfo()
    : cnt_(0), obs_time_(), has_latest_(false), latest_obs_time_()
{
}

//============================================================================
RcvdPktManager::ObsTimeInfo::~ObsTimeInfo()
{
}

//============================================================================
void RcvdPktManager::ObsTimeInfo::StoreObsTime(
  PktSeqNumber seq_num, PktTimestamp send_ts, const Time& rcv_time)
{
  if (cnt_ < kMaxObsTimes)
  {
    obs_time_[cnt_].seq_num_   = seq_num;
    obs_time_[cnt_].timestamp_ = send_ts;
    obs_time_[cnt_].rcv_time_  = rcv_time;

    ++cnt_;
  }
  else
  {
    LogW(kClassName, __func__, "Warning, too many observed times for "
         "array.\n");
  }

  latest_obs_time_.seq_num_   = seq_num;
  latest_obs_time_.timestamp_ = send_ts;
  latest_obs_time_.rcv_time_  = rcv_time;

  has_latest_ = true;
}

//============================================================================
void RcvdPktManager::ObsTimeInfo::AddObsTimesToAckHdr(AckHeader& ack_hdr,
                                                      const Time& now)
{
  if (cnt_ > 0)
  {
    // Add the observed packet timestamps, adjusting for the hold time.
    for (size_t i = 0; i < cnt_; ++i)
    {
      Time  delta_time = (now - obs_time_[i].rcv_time_);

      ack_hdr.observed_time[i].seq_num   = obs_time_[i].seq_num_;
      ack_hdr.observed_time[i].timestamp =
        (obs_time_[i].timestamp_ +
         static_cast<PktTimestamp>(delta_time.GetTimeInUsec()));

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "  Observed time %zu seq %" PRIPktSeqNumber
           " ts %" PRIPktTimestamp ".\n", i, ack_hdr.observed_time[i].seq_num,
           ack_hdr.observed_time[i].timestamp);
#endif
    }

    ack_hdr.num_observed_times = static_cast<uint8_t>(cnt_);
    cnt_                       = 0;
  }
  else
  {
    ack_hdr.num_observed_times = 0;
  }
}

//============================================================================
void RcvdPktManager::ObsTimeInfo::AddLatestObsTimeToAckHdr(AckHeader& ack_hdr,
                                                           const Time& now)
{
  if (has_latest_)
  {
    Time  delta_time = (now - latest_obs_time_.rcv_time_);

    ack_hdr.observed_time[0].seq_num   = latest_obs_time_.seq_num_;
    ack_hdr.observed_time[0].timestamp =
      (latest_obs_time_.timestamp_ +
       static_cast<PktTimestamp>(delta_time.GetTimeInUsec()));

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "  Latest observed time seq %" PRIPktSeqNumber
         " ts %" PRIPktTimestamp ".\n", ack_hdr.observed_time[0].seq_num,
         ack_hdr.observed_time[0].timestamp);
#endif

    ack_hdr.num_observed_times = 1;
  }
}

//============================================================================
RcvdPktManager::FecGroupInfo::FecGroupInfo()
    : fec_grp_id_(0), fec_num_src_(0), fec_src_rcvd_cnt_(0),
      fec_enc_rcvd_cnt_(0), delivered_cnt_(0), ttg_cnt_(0),
      start_src_seq_num_(0), start_enc_seq_num_(0), ttg_()
{
}

//============================================================================
RcvdPktManager::FecGroupInfo::~FecGroupInfo()
{
}

//============================================================================
RcvdPktManager::VdmDecodeInfo::VdmDecodeInfo()
    : num_src_pkt_(0), in_pkt_data_(), in_pkt_size_(), in_enc_pkt_size_(),
      in_pkt_index_(), out_pkt_(), out_pkt_data_(), out_pkt_size_()
{
}

//============================================================================
RcvdPktManager::VdmDecodeInfo::~VdmDecodeInfo()
{
}

//============================================================================
RcvdPktManager::PktCounts::PktCounts()
    : target_app_rcvd_(0), target_tot_rcvd_(0), norm_rcvd_(0),
      norm_rx_rcvd_(0), fec_src_rcvd_(0), fec_src_rx_rcvd_(0),
      fec_src_regen_(0), fec_enc_rcvd_(0), fec_enc_rx_rcvd_(0),
      fec_total_src_rcvd_(0), fec_total_ext_rcvd_(0), raw_goodput_bytes_(0),
      start_time_(), end_time_()
{
}

//============================================================================
RcvdPktManager::PktCounts::~PktCounts()
{
}

//============================================================================
void RcvdPktManager::PktCounts::Update(const Reliability& rel,
                                       const DataHeader& pkt)
{
  // Update the target packet counts.
  if ((rel.mode == SEMI_RELIABLE_ARQ_FEC) && (pkt.fec_flag) &&
      (pkt.fec_round > 0) &&
      (((rel.fec_del_time_flag) && (pkt.fec_round < kOutOfRounds)) ||
       ((!rel.fec_del_time_flag) &&
        (pkt.fec_round <= rel.fec_target_pkt_del_rounds))))
  {
    ++target_tot_rcvd_;
  }

  // Update the general packet counts.
  if (pkt.fec_flag)
  {
    // FEC packet.
    if (pkt.fec_pkt_type == FEC_SRC_PKT)
    {
      // FEC source packet.
      if (pkt.retransmission_count == 0)
      {
        ++fec_src_rcvd_;
      }
      else
      {
        ++fec_src_rx_rcvd_;
      }
    }
    else
    {
      // FEC encoded packet.
      if (pkt.retransmission_count == 0)
      {
        ++fec_enc_rcvd_;
      }
      else
      {
        ++fec_enc_rx_rcvd_;
      }
    }
  }
  else
  {
    // Non-FEC packet.
    if (pkt.retransmission_count == 0)
    {
      ++norm_rcvd_;
    }
    else
    {
      ++norm_rx_rcvd_;
    }
  }
}
