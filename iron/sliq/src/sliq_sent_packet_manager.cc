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

#include "sliq_sent_packet_manager.h"

#include "sliq_app.h"
#include "sliq_connection.h"
#include "sliq_cc_copa.h"
#include "sliq_cc_interface.h"
#include "sliq_fec_defs.h"

#include "packet_pool.h"
#include "unused.h"

#include <inttypes.h>
#include <math.h>


using ::sliq::FecRound;
using ::sliq::FecSize;
using ::sliq::PktSeqNumber;
using ::sliq::PktTimestamp;
using ::sliq::RetransCount;
using ::sliq::SentPktManager;
using ::sliq::VdmFec;
using ::sliq::WindowSize;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*         UNUSED(kClassName)  = "SentPktManager";

  /// Sent packet information flag for forward error correction (FEC).
  const uint8_t       kFec                = 0x01;

  /// Sent packet information flag for the data packet FIN flag.
  const uint8_t       kFin                = 0x02;

  /// Sent packet information flag for data packets that are blocked.
  const uint8_t       kBlocked            = 0x04;

  /// Sent packet information flag for data packets that have been ACKed.
  const uint8_t       kAcked              = 0x08;

  /// Sent packet information flag for data packets considered lost.
  const uint8_t       kLost               = 0x10;

  /// Sent packet information flag for fast retransmit candidate reporting.
  const uint8_t       kCand               = 0x20;

  /// FEC group flag for pure ARQ mode.
  const uint8_t       kFecPureArq         = 0x01;

  /// FEC group flag for latency sensitive traffic.
  const uint8_t       kFecLatSens         = 0x02;

  /// FEC group flag for forcing the end of the group.
  const uint8_t       kFecForceEnd        = 0x04;

  /// The distance between a packet and the current largest observed packet to
  /// consider a packet lost, and for a fast retransmission to take place.
  /// This is an adaptation of the TCP 3 duplicate ACKs rule (RFC 5681,
  /// section 3.2).
  const int           kFastRexmitDist     = 3;

  /// The size of each set of triangle tables in the FEC lookup table in
  /// number of elements.  These tables are stored as efficiently as possible.
  /// The sizes of the tables add up as follows as k goes from 1 to 10:
  /// 1+3+6+10+15+21+28+36+45+55 = 220.
  const size_t        kFecTriTableSize    = 220;

  /// The size of each 4D FEC lookup table in number of elements.  The
  /// dimensions are [p][k][sr][cr], where p is the PER, k is the number of
  /// source packets per group, sr is the number of source packets received,
  /// and cr is the number of coded packets received.  Note that [k][sr][cr]
  /// is a series of triangle tables that are stored as efficiently as
  /// possible.
  const size_t        kFecTableSize       = (kNumPers * kFecTriTableSize);

  /// The minimum target number of rounds (N).
  const FecRound      kMinN               = 1;

  /// The maximum target number of rounds (N).
  const FecRound      kMaxN               = kNumRounds;

  /// The minimum number of FEC source packets in an FEC group (k).
  const FecSize       kMinK               = 1;

  /// The maximum number of FEC source packets in an FEC group (k).
  const FecSize       kMaxK               = kNumSrcPkts;

  /// The number of consecutive FEC groups sent without an early ACK being
  /// received for the number of FEC source packets to be increased.
  const FecSize       kFecAckAfterGrpCnt  = 16;

  /// The number of FEC groups required for storing FEC information.
  const WindowSize    kFecGroupSize       = ((sliq::kFlowCtrlWindowPkts /
                                              kMinK) + 1);

  /// The size, in packets, of the queue for original FEC encoded data
  /// packets (unsent FEC encoded packets generated in round 1).
  const WindowSize    kOrigFecEncQSize    = sliq::kMaxFecGroupLengthPkts;

  /// The size, in packets, of the queue for additional FEC encoded data
  /// packets (unsent FEC encoded packets generated in round 2+).
  const WindowSize    kAddlFecEncQSize    = (sliq::kFlowCtrlWindowPkts / 2);

  /// The amount of time, in microseconds, to add to FEC end of round
  /// timestamps in order to account for timing variations.  This prevents
  /// early FEC packet retransmissions and avoids received packet count lookup
  /// misses.
  const PktTimestamp  kFecEorTsDelta      = 4000;

  /// The alpha factor for tracking the amount of time allowed for sending the
  /// FEC source packets in each group using an EWMA estimator.
  const double        kDurAlpha           = 0.25;

  /// The packet overhead due to IP (20 bytes) and UDP (8 bytes), in bytes.
  const size_t        kPktOverheadBytes   = 28;
}


// Macros for sent packet information.
#define IS_FEC(info)      (((info).flags_ & kFec) != 0)
#define IS_FIN(info)      (((info).flags_ & kFin) != 0)
#define IS_BLOCKED(info)  (((info).flags_ & kBlocked) != 0)
#define IS_ACKED(info)    (((info).flags_ & kAcked) != 0)
#define IS_LOST(info)     (((info).flags_ & kLost) != 0)
#define IS_CAND(info)     (((info).flags_ & kCand) != 0)

#define SET_FEC(info)      (info).flags_ |= kFec
#define SET_FIN(info)      (info).flags_ |= kFin
#define SET_BLOCKED(info)  (info).flags_ |= kBlocked
#define SET_ACKED(info)    (info).flags_ |= kAcked
#define SET_LOST(info)     (info).flags_ |= kLost
#define SET_CAND(info)     (info).flags_ |= kCand

#define CLEAR_BLOCKED(info)  (info).flags_ &= ~kBlocked
#define CLEAR_LOST(info)     (info).flags_ &= ~kLost
#define CLEAR_CAND(info)     (info).flags_ &= ~kCand


// Macros for FEC group information.
#define IS_PURE_ARQ(info)   (((info).fec_flags_ & kFecPureArq) != 0)
#define IS_LAT_SENS(info)   (((info).fec_flags_ & kFecLatSens) != 0)
#define IS_FORCE_END(info)  (((info).fec_flags_ & kFecForceEnd) != 0)

#define SET_PURE_ARQ(info)   (info).fec_flags_ |= kFecPureArq
#define SET_LAT_SENS(info)   (info).fec_flags_ |= kFecLatSens
#define SET_FORCE_END(info)  (info).fec_flags_ |= kFecForceEnd

#define CLEAR_PURE_ARQ(info)  (info).fec_flags_ &= ~kFecPureArq


/// The SentPktInfo's static member to the packet pool.
PacketPool*  SentPktManager::SentPktInfo::packet_pool_ = NULL;


//============================================================================
SentPktManager::SentPktManager(Connection& conn, Stream& stream,
                               RttManager& rtt_mgr, PacketPool& packet_pool,
                               CcAlgs& cc_algs, EndptId conn_id,
                               StreamId stream_id)
    : conn_(conn),
      stream_(stream),
      rtt_mgr_(rtt_mgr),
      packet_pool_(packet_pool),
      cc_algs_(cc_algs),
      conn_id_(conn_id),
      stream_id_(stream_id),
      fin_sent_(false),
      rel_(),
      snd_fec_(0),
      snd_una_(0),
      snd_nxt_(0),
      rcv_ack_nxt_exp_(0),
      rcv_ack_lrg_obs_(0),
      last_lo_conn_seq_(0),
      stats_pkts_(),
      stats_bytes_in_flight_(0),
      stats_fec_src_dur_sec_(1.0),
      stats_pkt_ist_(-1.0),
      fec_per_(0.0),
      fec_per_idx_(0),
      fec_epsilon_idx_(0),
      fec_target_rounds_(0),
      fec_grp_idx_(0),
      fec_grp_id_(0),
      fec_total_pkts_(0),
      fec_dss_next_num_src_(kMaxK),
      fec_dss_ack_after_grp_cnt_(0),
      fec_midgame_tables_(),
      fec_endgame_tables_(),
      fec_grp_info_(NULL),
      fec_eor_cnt_(0),
      fec_eor_idx_(0),
      fec_eor_(NULL),
      fec_enc_orig_(),
      fec_enc_addl_(),
      fec_enc_tmp_seq_num_(0),
      vdm_info_(),
      cc_cnt_adj_(),
      cc_una_pkt_(),
      sent_pkts_(NULL)
{
  // Set all of the FEC lookup table pointers to NULL.
  for (size_t i = 0; i < kNumLookupTables; ++i)
  {
    fec_midgame_tables_[i] = NULL;
    fec_endgame_tables_[i] = NULL;
  }
}

//============================================================================
SentPktManager::~SentPktManager()
{
  // Log the packet transmission statistics.
  LogI(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       " sent pkt counts: norm %zu norm_rx %zu fec_src %zu fec_src_rx %zu "
       "fec_enc %zu fec_enc_rx %zu\n", conn_id_, stream_id_,
       stats_pkts_.norm_sent_, stats_pkts_.norm_rx_sent_,
       stats_pkts_.fec_src_sent_, stats_pkts_.fec_src_rx_sent_,
       stats_pkts_.fec_enc_sent_, stats_pkts_.fec_enc_rx_sent_);

  LogI(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       " sent fec grp counts: pure_fec %zu coded_arq %zu pure_arq %zu ( "
       "pure_arq_1 %zu pure_arq_2+ %zu )\n", conn_id_, stream_id_,
       stats_pkts_.fec_grp_pure_fec_, stats_pkts_.fec_grp_coded_arq_,
       (stats_pkts_.fec_grp_pure_arq_1_ + stats_pkts_.fec_grp_pure_arq_2p_),
       stats_pkts_.fec_grp_pure_arq_1_, stats_pkts_.fec_grp_pure_arq_2p_);

  // Delete the arrays of information.
  for (size_t i = 0; i < kNumLookupTables; ++i)
  {
    if (fec_midgame_tables_[i] != NULL)
    {
      delete [] fec_midgame_tables_[i];
      fec_midgame_tables_[i] = NULL;
    }

    if (fec_endgame_tables_[i] != NULL)
    {
      delete [] fec_endgame_tables_[i];
      fec_endgame_tables_[i] = NULL;
    }
  }

  if (fec_grp_info_ != NULL)
  {
    delete [] fec_grp_info_;
    fec_grp_info_ = NULL;
  }

  if (fec_eor_ != NULL)
  {
    delete [] fec_eor_;
    fec_eor_ = NULL;
  }

  if (sent_pkts_ != NULL)
  {
    delete [] sent_pkts_;
    sent_pkts_ = NULL;
  }
}

//============================================================================
bool SentPktManager::Initialize(const Reliability& rel,
                                PktSeqNumber init_seq_num)
{
  // Prevent multiple initializations.
  if (sent_pkts_ != NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Error, already "
         "initialized.\n", conn_id_);
    return false;
  }

  // Store the reliability settings.
  rel_ = rel;

  // Initialize the FEC state.
  if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    if (rel_.fec_del_time_flag)
    {
      // Set the target number of rounds to one for now.  It will be set to
      // the correct value whenever UpdateFecTableParams() is called.
      fec_target_rounds_ = 1;
    }
    else
    {
      // Note that the target number of rounds is limited due to the size of
      // the FEC lookup table parameter arrays.  Avoid exceeding the limits.
      if ((rel_.fec_target_pkt_del_rounds < 1) ||
          (rel_.fec_target_pkt_del_rounds > kNumRounds))
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC target number of rounds %" PRIRexmitRounds
             " exceeds limits of 1 to %zu.\n", conn_id_, stream_id_,
             rel_.fec_target_pkt_del_rounds, kNumRounds);
        return false;
      }

      // Store the target number of rounds.  This value will not change.
      fec_target_rounds_ = rel_.fec_target_pkt_del_rounds;
    }

    // Initialize the FEC encoder.
    VdmFec::Initialize();
  }

  // Set the packet pool for the SentPktInfo objects to use.
  SentPktInfo::SetPacketPool(&packet_pool_);

  // Allocate the FEC lookup tables and arrays.
  if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    if (!CreateFecTables())
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error creating FEC lookup tables.\n", conn_id_, stream_id_);
      return false;
    }

    fec_grp_info_ = new (std::nothrow) FecGroupInfo[kFecGroupSize];

    if (fec_grp_info_ == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error allocating FEC group array.\n", conn_id_, stream_id_);
      return false;
    }

    fec_eor_ = new (std::nothrow) FecEndOfRndInfo[kFecGroupSize];

    if (fec_eor_ == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error allocating FEC round array.\n", conn_id_, stream_id_);
      return false;
    }

    if ((!fec_enc_orig_.Init(kOrigFecEncQSize)) ||
        (!fec_enc_addl_.Init(kAddlFecEncQSize)))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error initializing FEC encoded packet queues.\n", conn_id_,
           stream_id_);
      return false;
    }
  }

  // Allocate the circular array of sent packet information.
  sent_pkts_ = new (std::nothrow) SentPktInfo[kFlowCtrlWindowPkts];

  if (sent_pkts_ == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error allocating sent packet array.\n", conn_id_, stream_id_);
    return false;
  }

  // Initialize the FEC source packet sending duration to the current smoothed
  // RTT.
  stats_fec_src_dur_sec_ = rtt_mgr_.smoothed_rtt().ToDouble();

  // Adjust the stored retransmission limit to zero if the reliability mode
  // does not use it.
  rel_.rexmit_limit = (((rel_.mode == SEMI_RELIABLE_ARQ) ||
                        (rel_.mode == SEMI_RELIABLE_ARQ_FEC)) ?
                       rel.rexmit_limit : 0);

  // Store the other settings.
  snd_fec_         = init_seq_num;
  snd_una_         = init_seq_num;
  snd_nxt_         = init_seq_num;
  rcv_ack_nxt_exp_ = init_seq_num;
  rcv_ack_lrg_obs_ = (init_seq_num - 1);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Initialize sent packet manager: rel_mode %d rexmit_limit %"
       PRIRexmitLimit " del_time %d tgt_rnds %" PRIFecRound " tgt_time %f "
       "tgt_prob %f snd_wnd %" PRIWindowSize " snd_fec %" PRIPktSeqNumber
       " snd_una %" PRIPktSeqNumber " snd_nxt %" PRIPktSeqNumber
       " rcv_ack_nxt_exp %" PRIPktSeqNumber " rcv_ack_lrg_obs %"
       PRIPktSeqNumber "\n", conn_id_, stream_id_, rel_.mode,
       rel_.rexmit_limit, static_cast<int>(rel_.fec_del_time_flag),
       fec_target_rounds_, rel_.fec_target_pkt_del_time_sec,
       rel_.fec_target_pkt_recv_prob, kFlowCtrlWindowPkts, snd_fec_, snd_una_,
       snd_nxt_, rcv_ack_nxt_exp_, rcv_ack_lrg_obs_);
#endif

  return true;
}

//============================================================================
bool SentPktManager::PrepareNextPkt(Packet* pkt, CcId cc_id, bool fin,
                                    const Time& now, DataHeader& hdr,
                                    bool& new_grp)
{
  new_grp = false;

  // The manager must have been initialized.
  if (sent_pkts_ == NULL)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Not initialized.\n", conn_id_, stream_id_);
  }

  // Make sure that there is window space available for sending a packet.
  if (!CanSend())
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, cannot send a packet now, snd_fec_ %" PRIPktSeqNumber
         " snd_nxt_ %" PRIPktSeqNumber " rcv_ack_nxt_exp_ %" PRIPktSeqNumber
         " snd_wnd_ %" PRIWindowSize ".\n", conn_id_, stream_id_, snd_fec_,
         snd_nxt_, rcv_ack_nxt_exp_, kFlowCtrlWindowPkts);
    return false;
  }

  // There should be no original FEC encoded data packets (unsent FEC encoded
  // packets generated in round 1) waiting to be sent.
  if (fec_enc_orig_.GetCount() > 0)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Warning, %" PRIWindowSize " FEC encoded packets waiting to be "
         "sent.\n", conn_id_, stream_id_, fec_enc_orig_.GetCount());
  }

  // Initialize the packet header.
  hdr.enc_pkt_len_flag     = false;
  hdr.fec_flag             = ((!fin) && (rel_.mode == SEMI_RELIABLE_ARQ_FEC));
  hdr.move_fwd_flag        = false;
  hdr.persist_flag         = false;
  hdr.fin_flag             = fin;
  hdr.stream_id            = stream_id_;
  hdr.num_ttg              = 0;
  hdr.cc_id                = cc_id;
  hdr.retransmission_count = 0;
  hdr.sequence_number      = snd_nxt_;
  hdr.timestamp            = 0;
  hdr.timestamp_delta      = 0;
  hdr.move_fwd_seq_num     = 0;

  if (hdr.fec_flag)
  {
    new_grp = (fec_grp_idx_ == 0);

    hdr.fec_pkt_type       = FEC_SRC_PKT;
    hdr.fec_group_index    = fec_grp_idx_;
    hdr.fec_num_src        = 0;
    hdr.fec_round          = 1;
    hdr.fec_group_id       = fec_grp_id_;
    hdr.encoded_pkt_length = 0;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Next seq %" PRIPktSeqNumber " FEC SRC grp %" PRIFecGroupId
         " idx %" PRIFecSize "\n", conn_id_, stream_id_, hdr.sequence_number,
         hdr.fec_group_id, hdr.fec_group_index);
#endif

    ++fec_grp_idx_;
  }
#ifdef SLIQ_DEBUG
  else
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Next seq %" PRIPktSeqNumber "\n", conn_id_, stream_id_,
         hdr.sequence_number);
  }
#endif

  // Add any TTGs to the packet.
  AddPktTtgs(now, pkt, hdr);

  // Set the FIN sent flag before AddSentPkt() is called.
  if (fin)
  {
    fin_sent_ = true;
  }

  return true;
}

//============================================================================
void SentPktManager::AddSentPkt(
  DataHeader& hdr, Packet* pkt, size_t bytes_sent, PktSeqNumber conn_seq,
  PktCount sent_pkt_cnt, const Time& xmit_time, const Time& queueing_delay,
  bool blocked, bool& grp_end)
{
  PktSeqNumber  seq_num = hdr.sequence_number;
  CcId          cc_id   = hdr.cc_id;
  bool          fin     = hdr.fin_flag;

  grp_end = false;

  // This packet's sequence number should be snd_nxt_.
  if (seq_num != snd_nxt_)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Sent seq %" PRIPktSeqNumber " is not equal to next seq %"
         PRIPktSeqNumber ".\n", conn_id_, stream_id_, seq_num, snd_nxt_);
    return;
  }

  // There should be no original FEC encoded data packets (unsent FEC encoded
  // packets generated in round 1) waiting to be sent.
  if (fec_enc_orig_.GetCount() > 0)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Warning, %" PRIWindowSize " FEC encoded packets waiting to be "
         "sent.\n", conn_id_, stream_id_, fec_enc_orig_.GetCount());
  }

  // Verify that the circular array size will not be exceeded.
  if ((seq_num - snd_fec_) >= kFlowCtrlWindowPkts)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Circular array size %" PRIPktSeqNumber " would exceed max %"
         PRIWindowSize ".\n", conn_id_, stream_id_,
         ((seq_num - snd_fec_) + 1), kFlowCtrlWindowPkts);
    return;
  }

  // Determine if this is a latency-sensitive packet or not.
  bool lat_sens = ((pkt != NULL) && (pkt->track_ttg()));

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Adding packet, seq %" PRIPktSeqNumber " conn_seq %" PRIPktSeqNumber
       " cnt %" PRIPktCount " fec %d fin %d cc_id %" PRICcId " xmit_time %s "
       "q_delay %s lat_sens %d blocked %d bytes %zu.\n", conn_id_, stream_id_,
       seq_num, conn_seq, sent_pkt_cnt, static_cast<int>(hdr.fec_flag),
       static_cast<int>(fin), cc_id, xmit_time.ToString().c_str(),
       queueing_delay.ToString().c_str(), static_cast<int>(lat_sens),
       static_cast<int>(blocked), bytes_sent);
#endif

  // Get the packet length, not including any headers.
  size_t  pkt_len = ((pkt != NULL) ? (pkt->GetMetadataHeaderLengthInBytes() +
                                      pkt->GetLengthInBytes()) : 0);

  // Update congestion control.
  CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[cc_id].cc_alg;

  if (cc_alg == NULL)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": NULL congestion control object for cc_id %" PRICcId ".\n",
         conn_id_, stream_id_, cc_id);
    return;
  }

  float         cc_val     = 0.0;
  PktSeqNumber  cc_seq_num = cc_alg->OnPacketSent(stream_id_, xmit_time,
                                                  seq_num, pkt_len,
                                                  bytes_sent, cc_val);

  // The packet has not been ACKed yet, is not considered lost yet, and has
  // not been retransmitted yet.  Update the counts appropriately.
  stats_bytes_in_flight_ += static_cast<ssize_t>(pkt_len);
  cc_alg->UpdateCounts(1, static_cast<ssize_t>(pkt_len),
                       static_cast<ssize_t>(pkt_len));

  // Add the packet to the send window.
  SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

  if (pkt_info.packet_ != NULL)
  {
    packet_pool_.Recycle(pkt_info.packet_);
    pkt_info.packet_ = NULL;
  }

  if ((blocked) || (fin) || (rel_.mode != BEST_EFFORT))
  {
    pkt_info.packet_ = pkt;
  }
  else if (pkt != NULL)
  {
    packet_pool_.Recycle(pkt);
  }

  pkt_info.seq_num_           = seq_num;
  pkt_info.conn_seq_num_      = conn_seq;
  pkt_info.cc_seq_num_        = cc_seq_num;
  pkt_info.cc_val_            = cc_val;
  pkt_info.q_delay_usec_      =
    static_cast<uint32_t>(queueing_delay.GetTimeInUsec());
  pkt_info.rtt_usec_          = 0;
  pkt_info.xmit_time_         = xmit_time.ToTval();
  pkt_info.last_xmit_time_    = xmit_time.ToTval();
  pkt_info.pkt_len_           = static_cast<uint16_t>(pkt_len);
  pkt_info.bytes_sent_        = static_cast<uint16_t>(bytes_sent);
  pkt_info.rexmit_limit_      = rel_.rexmit_limit;
  pkt_info.rexmit_cnt_        = 0;
  pkt_info.cc_id_             = cc_id;
  pkt_info.flags_             = 0;
  pkt_info.sent_pkt_cnt_      = sent_pkt_cnt;
  pkt_info.prev_sent_pkt_cnt_ = 0;

  if (hdr.fec_flag)
  {
    SET_FEC(pkt_info);
    pkt_info.fec_grp_id_      = hdr.fec_group_id;
    pkt_info.fec_enc_pkt_len_ = hdr.encoded_pkt_length;
    pkt_info.fec_grp_idx_     = hdr.fec_group_index;
    pkt_info.fec_num_src_     = hdr.fec_num_src;
    pkt_info.fec_round_       = hdr.fec_round;
    pkt_info.fec_pkt_type_    = static_cast<uint8_t>(hdr.fec_pkt_type);
    pkt_info.fec_ts_          = hdr.timestamp;
    ++stats_pkts_.fec_src_sent_;
  }
  else
  {
    ++stats_pkts_.norm_sent_;
  }

  if (fin)
  {
    SET_FIN(pkt_info);
  }

  if (blocked)
  {
    SET_BLOCKED(pkt_info);
  }

  // Update the next sequence number.
  ++snd_nxt_;

  // Update the FEC state as needed.
  if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    FecGroupInfo&  grp_info = fec_grp_info_[(fec_grp_id_ % kFecGroupSize)];

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Sent FEC src pkt: seq %" PRIPktSeqNumber " rx %" PRIRetransCount
         " grp %" PRIFecGroupId " idx %" PRIFecSize " rnd %" PRIFecRound
         ".\n", conn_id_, stream_id_, seq_num, hdr.retransmission_count,
         hdr.fec_group_id, hdr.fec_group_index, hdr.fec_round);
#endif

    if (hdr.fec_group_index == 0)
    {
      // Initialize the new FEC group information.
      grp_info.fec_grp_id_          = fec_grp_id_;
      grp_info.fec_num_src_         = 1;
      grp_info.fec_num_enc_         = 0;
      grp_info.fec_src_ack_cnt_     = 0;
      grp_info.fec_enc_ack_cnt_     = 0;
      grp_info.fec_round_           = 0;
      grp_info.fec_max_rounds_      = 0;
      grp_info.fec_gen_enc_round_   = 0;
      grp_info.fec_src_to_send_icr_ = 0;
      grp_info.fec_enc_to_send_icr_ = 0;
      grp_info.fec_src_sent_icr_    = 0;
      grp_info.fec_enc_sent_icr_    = 0;
      grp_info.fec_rexmit_limit_    = rel_.rexmit_limit;
      grp_info.fec_flags_           = 0;
      grp_info.start_src_seq_num_   = seq_num;
      grp_info.end_src_seq_num_     = seq_num;
      grp_info.start_enc_seq_num_   = seq_num;
      grp_info.end_enc_seq_num_     = seq_num;

      if (lat_sens)
      {
        SET_LAT_SENS(grp_info);
      }

      // Update the FEC lookup table parameters for the new FEC group.  This
      // includes the PER, the target number of rounds (N), and the number of
      // source packets per group (k).  It also determines if pure ARQ can be
      // used or not.
      bool  fec_pure_arq_flag = UpdateFecTableParams();

      // Set the number of FEC source packets in the group, the maximum number
      // of rounds to be used, and if pure ARQ should be used for the group.
      // This must be done after the UpdateFecTableParams() call, but before
      // the PrepareNextFecRound() call.
      grp_info.fec_num_src_    = (fec_pure_arq_flag ?
                                  1 : fec_dss_next_num_src_);
      grp_info.fec_max_rounds_ = fec_target_rounds_;

      if (fec_pure_arq_flag)
      {
        SET_PURE_ARQ(grp_info);
      }

      // Make sure that the retransmission limit for the FEC group allows for
      // the scheduled number of rounds.  Note that N rounds includes (N-1)
      // retransmissions.
      if ((grp_info.fec_max_rounds_ > 1) &&
          ((grp_info.fec_rexmit_limit_ + 1) < grp_info.fec_max_rounds_))
      {
        grp_info.fec_rexmit_limit_ = (grp_info.fec_max_rounds_ - 1);
        pkt_info.rexmit_limit_     = grp_info.fec_rexmit_limit_;
      }

      // Prepare what packets should be sent in the first round using the FEC
      // lookup tables.  This will set the current round to 1.
      PrepareNextFecRound(grp_info);

      // We must be able to send all of the FEC source packets in the group in
      // the first round, or there is an error.
      if (grp_info.fec_src_to_send_icr_ != grp_info.fec_num_src_)
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC lookup table reports to send only %"
             PRIFecSize " FEC source packets in round 1.\n", conn_id_,
             stream_id_, grp_info.fec_src_to_send_icr_);
        grp_info.fec_src_to_send_icr_ = grp_info.fec_num_src_;
      }

      // Store the number of source and encoded packets in the current group.
      fec_total_pkts_ = (grp_info.fec_num_src_ + grp_info.fec_num_enc_);
    }
    else
    {
      // The FEC group information entry should still be for the current FEC
      // group being sent.
      if (grp_info.fec_grp_id_ != fec_grp_id_)
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC group info for current grp %" PRIFecGroupId " not "
             "found, entry set to %" PRIFecGroupId ".\n", conn_id_,
             stream_id_, fec_grp_id_, grp_info.fec_grp_id_);
      }

      // Set the FEC source packet's retransmission limit to that for the FEC
      // group.
      pkt_info.rexmit_limit_ = grp_info.fec_rexmit_limit_;

      // Update the last FEC source packet sequence number in the FEC group.
      grp_info.end_src_seq_num_ = seq_num;

      // Update the latency-sensitive data setting for the FEC group.  If at
      // least one source packet in the group is latency-sensitive, then all
      // source packets in the group must be treated as latency-sensitive.
      if (lat_sens)
      {
        SET_LAT_SENS(grp_info);
      }
    }

    // Update the source packet sent count for the FEC group's current round.
    ++grp_info.fec_src_sent_icr_;

    // Check if this is the last FEC source packet to be sent in the FEC
    // group.
    if (hdr.fec_group_index == (grp_info.fec_num_src_ - 1))
    {
      grp_end = true;

      // Now that we have all of the FEC source packets for the group,
      // generate any required FEC encoded packets.  Note that any FEC encoded
      // packets needed later are generated in PrepareNextFecRound().
      if (grp_info.fec_num_enc_ > 0)
      {
        if (!GenerateFecEncodedPkts(
              grp_info.start_src_seq_num_, grp_info.end_src_seq_num_,
              grp_info.fec_grp_id_, kMaxFecGroupLengthPkts,
              grp_info.fec_num_src_, 0, grp_info.fec_num_enc_, fec_enc_orig_,
              false))
        {
          LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Cannot continue without generation of FEC "
               "encoded packets.\n", conn_id_, stream_id_);
        }

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Generated %" PRIFecSize " FEC encoded packets for grp %"
             PRIFecGroupId " in round %" PRIFecRound ".\n", conn_id_,
             stream_id_, grp_info.fec_num_enc_, grp_info.fec_grp_id_,
             grp_info.fec_round_);
#endif

        // Record the round when the FEC encoded packets were first generated.
        grp_info.fec_gen_enc_round_ = grp_info.fec_round_;
      }
      else
      {
        // There are no FEC encoded packets for the FEC group, so all of the
        // packets for the FEC group have been sent.  Watch the
        // returned ACK packet timestamps for the end of the round.
        RecordEndOfFecRound(xmit_time, grp_info, hdr.timestamp);
      }

      // Move to the next FEC group.
      StartNextFecGroup();
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated send window, snd_fec_ %" PRIPktSeqNumber " snd_una_ %"
       PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber " fec_enc_orig_cnt_ %"
       PRIWindowSize ".\n", conn_id_, stream_id_, snd_fec_, snd_una_,
       snd_nxt_, fec_enc_orig_.GetCount());
#endif
}

//============================================================================
bool SentPktManager::GetBlockedPkt(DataHeader& hdr, Packet*& pkt)
{
  // Search for blocked packets.
  for (PktSeqNumber seq = snd_una_; SEQ_LT(seq, snd_nxt_); ++seq)
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq % kFlowCtrlWindowPkts)];

    if (IS_BLOCKED(pkt_info))
    {
      pkt = pkt_info.packet_;

      hdr.enc_pkt_len_flag     = false;
      hdr.fec_flag             = IS_FEC(pkt_info);
      hdr.move_fwd_flag        = false;
      hdr.persist_flag         = false;
      hdr.fin_flag             = IS_FIN(pkt_info);
      hdr.stream_id            = stream_id_;
      hdr.num_ttg              = 0;
      hdr.cc_id                = pkt_info.cc_id_;
      hdr.retransmission_count = pkt_info.rexmit_cnt_;
      hdr.sequence_number      = seq;
      hdr.timestamp            = 0;
      hdr.timestamp_delta      = 0;
      hdr.move_fwd_seq_num     = 0;

      if (hdr.fec_flag)
      {
        hdr.fec_pkt_type    = static_cast<FecPktType>(pkt_info.fec_pkt_type_);
        hdr.fec_group_index = pkt_info.fec_grp_idx_;
        hdr.fec_num_src     = pkt_info.fec_num_src_;
        hdr.fec_round       = pkt_info.fec_round_;
        hdr.fec_group_id    = pkt_info.fec_grp_id_;

        if (hdr.fec_pkt_type == FEC_ENC_PKT)
        {
          hdr.enc_pkt_len_flag   = true;
          hdr.encoded_pkt_length = pkt_info.fec_enc_pkt_len_;
        }
      }

      // Add any TTGs to the packet.
      Time  now = Time::Now();

      AddPktTtgs(now, pkt, hdr);

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Found blocked pkt, seq %" PRIPktSeqNumber " cc_id %" PRICcId
           " fin %d fec %d\n", conn_id_, stream_id_, hdr.sequence_number,
           hdr.cc_id, static_cast<int>(hdr.fin_flag),
           static_cast<int>(hdr.fec_flag));
#endif

      return true;
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": No blocked pkts.\n", conn_id_, stream_id_);
#endif

  return false;
}

//============================================================================
void SentPktManager::SetPktUnblocked(DataHeader& hdr, size_t bytes_sent,
                                     PktCount sent_pkt_cnt,
                                     const Time& xmit_time)
{
  PktSeqNumber  seq_num = hdr.sequence_number;

  if (SEQ_GEQ(seq_num, snd_una_) && SEQ_LT(seq_num, snd_nxt_))
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

    pkt_info.xmit_time_         = xmit_time.ToTval();
    pkt_info.last_xmit_time_    = xmit_time.ToTval();
    pkt_info.bytes_sent_        = static_cast<uint16_t>(bytes_sent);
    pkt_info.sent_pkt_cnt_      = sent_pkt_cnt;
    pkt_info.prev_sent_pkt_cnt_ = 0;

    if (hdr.fec_flag)
    {
      pkt_info.fec_ts_ = hdr.timestamp;
    }

    CLEAR_BLOCKED(pkt_info);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Pkt seq %" PRIPktSeqNumber " cnt %" PRIPktCount " now "
         "unblocked.\n", conn_id_, stream_id_, seq_num, sent_pkt_cnt);
#endif

    return;
  }

  LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Warning, pkt seq %" PRIPktSeqNumber " out of range [%"
       PRIPktSeqNumber "..%" PRIPktSeqNumber "].\n", conn_id_, stream_id_,
       seq_num, snd_una_, (snd_nxt_ - 1));
}

//============================================================================
bool SentPktManager::GetRexmitPktSeqNum(const Time& now, bool lowest,
                                        PktSeqNumber& seq_num, CcId& cc_id)
{
  Time  rexmit_time = rtt_mgr_.GetRexmitTime();
  int   cnt         = 0;

  // Search for either the lowest or highest unACKed packet that is allowed to
  // be retransmitted in the current send window.  Does not include additional
  // FEC encoded packets (unsent FEC encoded packets generated in round 2+).
  for (PktSeqNumber seq = snd_una_; SEQ_LT(seq, snd_nxt_); ++seq)
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq % kFlowCtrlWindowPkts)];

    if (!IS_ACKED(pkt_info))
    {
      if (AllowRexmitBasic(pkt_info, now, rexmit_time))
      {
        seq_num = seq;
        cc_id   = pkt_info.cc_id_;
        if (lowest)
        {
          return true;
        }
        ++cnt;
      }
    }
  }

  return (cnt > 0);
}

//============================================================================
bool SentPktManager::GetRexmitPktLen(PktSeqNumber seq_num, bool addl,
                                     size_t& data_len, CcId& cc_id)
{
  bool        allow      = false;
  bool        is_fec_enc = false;
  FecGroupId  grp_id     = 0;

  if (addl)
  {
    // This is an additional FEC encoded packet (an unsent FEC encoded packet
    // generated in round 2+).  Even though it has not been sent yet, it is
    // treated as a retransmission because it was generated after the first
    // round was over, which is when retransmissions normally occur.  Thus,
    // this additional FEC encoded packet is akin to a repair packet, and is
    // sent using the same methods as for retransmission packets.

    // For additional FEC encoded packets, congestion control is handled as
    // follows:
    //
    // 1. The stream calls this method and gets an invalid cc_id returned.
    // 2. The stream then checks all of the CC algorithms for permission to
    //    send the packet using the CC algorithm CanSend() methods.
    // 3. If no CC algorithm grants permission, then the packet is not sent
    //    and this processing stops.
    // 4. If a CC algorithm grants permission, then the packet has a cc_id.
    // 5. The stream calls into GetRexmitPkt() to get the packet to send,
    //    specifying the cc_id.
    // 6. After the packet is sent, the stream calls into SentRexmitPkt(),
    //    which will call into the CC algorithm OnPacketSent() method to
    //    assign the cc_seq_num.

    // First, clean up the additional queue.
    CleanUpAddlFecEncQueue(seq_num);

    // Check that there is at least one packet in the additional FEC encoded
    // packet queue.
    if (fec_enc_addl_.GetCount() > 0)
    {
      // Verify that this packet is at the head of the additional FEC encoded
      // packet queue and so should be next to go.
      SentPktInfo&  fe_pkt_info = fec_enc_addl_.GetHead();

      if (seq_num == fe_pkt_info.seq_num_)
      {
        data_len = fe_pkt_info.pkt_len_;
        cc_id    = SliqApp::kMaxCcAlgPerConn; // Invalid value.

        // The retransmission packet was found and is an FEC encoded packet.
        allow      = true;
        is_fec_enc = true;
        grp_id     = fe_pkt_info.fec_grp_id_;
      }
    }
  }
  else
  {
    // This is a packet retransmission.  Check that seq_num is in the current
    // send window and that the packet has not been ACKed.
    if ((SEQ_GEQ(seq_num, snd_una_)) && (SEQ_LT(seq_num, snd_nxt_)))
    {
      SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

      if (!IS_ACKED(pkt_info))
      {
        data_len = pkt_info.pkt_len_;
        cc_id    = pkt_info.cc_id_;

        // The retransmission packet was found.
        allow = true;

        // Determine if it is an FEC encoded packet or not.
        if (IS_FEC(pkt_info) && (pkt_info.fec_pkt_type_ == FEC_ENC_PKT))
        {
          is_fec_enc = true;
          grp_id     = pkt_info.fec_grp_id_;
        }
      }
    }
  }

  // If allow is true and this is an FEC encoded data packet, then make sure
  // that the FEC group still needs the packet to be resent.
  if (allow && is_fec_enc)
  {
    FecGroupInfo&  grp_info = fec_grp_info_[(grp_id % kFecGroupSize)];

    if (grp_info.fec_grp_id_ == grp_id)
    {
      // Check if all of the FEC source data packets for the group have been
      // ACKed.  If so, then do not bother resending the FEC encoded data
      // packet.
      if (grp_info.fec_src_ack_cnt_ >= grp_info.fec_num_src_)
      {
        allow = false;
      }
    }
    else
    {
      // There is no FEC group information.  Do not bother resending the FEC
      // encoded data packet.
      allow = false;
    }
  }

  return allow;
}

//============================================================================
bool SentPktManager::GetRexmitPkt(const Time& now, PktSeqNumber seq_num,
                                  bool addl, bool rto_outage, CcId cc_id,
                                  DataHeader& hdr, Packet*& pkt)
{
  if (addl)
  {
    // This is an additional FEC encoded packet (an unsent FEC encoded packet
    // generated in round 2+).  First, clean up the additional queue.
    CleanUpAddlFecEncQueue(seq_num);

    // Make sure that there is window space available and an original FEC
    // encoded data packet (an unsent FEC encoded packet generated in round 1)
    // waiting to be sent.
    if ((!CanSend()) || (fec_enc_addl_.GetCount() == 0))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Cannot send an addl FEC encoded packet now, snd_fec_ %"
           PRIPktSeqNumber " snd_una_ %" PRIPktSeqNumber " snd_nxt_ %"
           PRIPktSeqNumber " snd_wnd_ %" PRIWindowSize " fec_enc_addl_cnt_ "
           "%" PRIWindowSize ".\n", conn_id_, stream_id_, snd_fec_, snd_una_,
           snd_nxt_, kFlowCtrlWindowPkts, fec_enc_addl_.GetCount());
      return false;
    }

    // Check that seq_num is the head packet in the additional FEC encoded
    // packet queue.
    SentPktInfo&  fe_pkt_info = fec_enc_addl_.GetHead();

    if (seq_num != fe_pkt_info.seq_num_)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Addl FEC encoded packet sequence number mismatch, %"
           PRIPktSeqNumber " != " PRIPktSeqNumber ".\n", conn_id_, stream_id_,
           seq_num, fe_pkt_info.seq_num_);
      return false;
    }

    // Get the FEC encoded packet ready for transmission.
    if (!GetFecEncPkt(now, cc_id, fec_enc_addl_, hdr, pkt))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error preparing addl FEC encoded packet for transmission.\n",
           conn_id_, stream_id_);
      return false;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Next seq %" PRIPktSeqNumber " addl FEC ENC grp %" PRIFecGroupId
         " idx %" PRIFecSize "\n", conn_id_, stream_id_, hdr.sequence_number,
         hdr.fec_group_id, hdr.fec_group_index);
#endif

    return true;
  }

  // This is a packet retransmission.  Check that seq_num is in the current
  // send window.
  if ((SEQ_LT(seq_num, snd_una_)) || (SEQ_GEQ(seq_num, snd_nxt_)))
  {
    return false;
  }

  SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

  // Make sure that the packet has not been ACKed.
  if (IS_ACKED(pkt_info))
  {
    return false;
  }

  // Increment the retransmission count in a local variable, making sure that
  // it does not overflow back to zero.  The pkt_info rexmit_cnt_ member will
  // be updated later when UpdateRexmitPkt() is called.
  RetransCount  rexmit_cnt = ((pkt_info.rexmit_cnt_ < kMaxRexmitCount) ?
                              (pkt_info.rexmit_cnt_ + 1) :
                              pkt_info.rexmit_cnt_);

  pkt = pkt_info.packet_;

  hdr.enc_pkt_len_flag     = false;
  hdr.fec_flag             = IS_FEC(pkt_info);
  hdr.move_fwd_flag        = false;
  hdr.persist_flag         = false;
  hdr.fin_flag             = IS_FIN(pkt_info);
  hdr.stream_id            = stream_id_;
  hdr.num_ttg              = 0;
  hdr.cc_id                = pkt_info.cc_id_;
  hdr.retransmission_count = rexmit_cnt;
  hdr.sequence_number      = seq_num;
  hdr.timestamp            = 0;
  hdr.timestamp_delta      = 0;
  hdr.move_fwd_seq_num     = 0;

  if (hdr.fec_flag)
  {
    hdr.fec_pkt_type    = static_cast<FecPktType>(pkt_info.fec_pkt_type_);
    hdr.fec_group_index = pkt_info.fec_grp_idx_;
    hdr.fec_num_src     = pkt_info.fec_num_src_;
    hdr.fec_round       = (rto_outage ? 0 :
                           GetRexmitFecRound(pkt_info.fec_grp_id_));
    hdr.fec_group_id    = pkt_info.fec_grp_id_;

    // FEC encoded packets require the encoded packet length.
    if (hdr.fec_pkt_type == FEC_ENC_PKT)
    {
      hdr.enc_pkt_len_flag   = true;
      hdr.encoded_pkt_length = pkt_info.fec_enc_pkt_len_;
    }
  }

  // Add any TTGs to the packet.
  AddPktTtgs(now, pkt, hdr);

  return true;
}

//============================================================================
void SentPktManager::SentRexmitPkt(
  DataHeader& hdr, size_t bytes_sent, PktSeqNumber conn_seq,
  PktCount sent_pkt_cnt, CcId rexmit_cc_id, bool addl, bool rto_outage,
  const Time& now)
{
  if (addl)
  {
    // This is an additional FEC encoded packet (an unsent FEC encoded packet
    // generated in round 2+).  Move the packet information from the queue to
    // the send window.
    MoveFecEncPkt(fec_enc_addl_, hdr, bytes_sent, conn_seq, sent_pkt_cnt,
                  now);

    return;
  }

  // This is a packet retransmission (a normal, FEC source, or FEC encoded
  // packet that has already been sent at least once).  Check that seq_num is
  // in the current send window.
  PktSeqNumber  seq_num = hdr.sequence_number;

  if ((SEQ_GEQ(seq_num, snd_una_)) && (SEQ_LT(seq_num, snd_nxt_)))
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

    // Access the congestion control algorithm that is allowing the
    // retransmission.
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[rexmit_cc_id].cc_alg;

    if (cc_alg == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": NULL congestion control object for cc_id %" PRICcId ".\n",
           conn_id_, stream_id_, rexmit_cc_id);
      return;
    }

#ifdef SLIQ_DEBUG
    if (hdr.fec_flag)
    {
      if (hdr.fec_pkt_type == FEC_SRC_PKT)
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Resent FEC src pkt: rto %d seq %" PRIPktSeqNumber " rx %"
             PRIRetransCount " grp %" PRIFecGroupId " idx %" PRIFecSize
             " rnd %" PRIFecRound " num_ttg %" PRITtgCount " ttg %f.\n",
             conn_id_, stream_id_, (rto_outage ? 1 : 0), seq_num,
             hdr.retransmission_count, hdr.fec_group_id, hdr.fec_group_index,
             hdr.fec_round, hdr.num_ttg, hdr.ttg[0]);
      }
      else
      {
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Resent FEC enc pkt: rto %d seq %" PRIPktSeqNumber " rx %"
             PRIRetransCount " grp %" PRIFecGroupId " idx %" PRIFecSize
             " rnd %" PRIFecRound " num_ttg %" PRITtgCount " ttg %f %f %f %f "
             "%f %f %f %f %f %f.\n", conn_id_, stream_id_,
             (rto_outage ? 1 : 0), seq_num, hdr.retransmission_count,
             hdr.fec_group_id, hdr.fec_group_index, hdr.fec_round,
             hdr.num_ttg, hdr.ttg[0], hdr.ttg[1], hdr.ttg[2], hdr.ttg[3],
             hdr.ttg[4], hdr.ttg[5], hdr.ttg[6], hdr.ttg[7], hdr.ttg[8],
             hdr.ttg[9]);
      }
    }
    else
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Resent pkt: rto %d seq %" PRIPktSeqNumber " rx %"
           PRIRetransCount " num_ttg %" PRITtgCount " ttg %f.\n", conn_id_,
           stream_id_, (rto_outage ? 1 : 0), seq_num,
           hdr.retransmission_count, hdr.num_ttg, hdr.ttg[0]);
    }
#endif

    // Increment the retransmission count, making sure that it does not
    // overflow back to zero.
    if (pkt_info.rexmit_cnt_ < kMaxRexmitCount)
    {
      ++pkt_info.rexmit_cnt_;
    }

    // Update the sent packet count.
    pkt_info.prev_sent_pkt_cnt_ = pkt_info.sent_pkt_cnt_;
    pkt_info.sent_pkt_cnt_      = sent_pkt_cnt;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Update rexmit pkt seq %" PRIPktSeqNumber " cnt %" PRIPktCount
         ".\n", conn_id_, stream_id_, seq_num, sent_pkt_cnt);
#endif

    // Update the last transmission time.
    pkt_info.last_xmit_time_ = now.ToTval();

    // If this retransmission was not due to an RTO or the end of an outage,
    // then clear the candidate flag now that the packet has been
    // retransmitted.
    if (!rto_outage)
    {
      CLEAR_CAND(pkt_info);
    }

    // Update the number of bytes sent for the packet.
    pkt_info.bytes_sent_ = bytes_sent;

    // If this retransmission was not due to an RTO or the end of an outage,
    // then update the FEC group round number.
    if ((!rto_outage) && (hdr.fec_flag) && (hdr.fec_round > 0))
    {
      pkt_info.fec_round_ = hdr.fec_round;
    }

    // Update the stored FEC packet timestamp and packet statistics.
    if (hdr.fec_flag)
    {
      pkt_info.fec_ts_ = hdr.timestamp;

      if (hdr.fec_pkt_type == FEC_SRC_PKT)
      {
        ++stats_pkts_.fec_src_rx_sent_;
      }
      else
      {
        ++stats_pkts_.fec_enc_rx_sent_;
      }
    }
    else
    {
      ++stats_pkts_.norm_rx_sent_;
    }

    // If this retransmission was not due to an RTO or the end of an outage,
    // then update the congestion control algorithm that is allowing the
    // retransmission.
    if (!rto_outage)
    {
      cc_alg->OnPacketResent(stream_id_, now, seq_num, pkt_info.cc_seq_num_,
                             pkt_info.pkt_len_, bytes_sent, rto_outage,
                             (pkt_info.cc_id_ == rexmit_cc_id),
                             pkt_info.cc_val_);
    }

    // The packet is still unACKed.  If this is the first retransmission, then
    // update the pipe count in the associated congestion control algorithm.
    if (pkt_info.rexmit_cnt_ == 1)
    {
      cc_alg = cc_algs_.cc_alg[pkt_info.cc_id_].cc_alg;

      if (cc_alg == NULL)
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": NULL congestion control object for cc_id %" PRICcId ".\n",
             conn_id_, stream_id_, pkt_info.cc_id_);
      }
      else
      {
        cc_alg->UpdateCounts(0, 0, static_cast<ssize_t>(pkt_info.pkt_len_));
      }
    }

    // Update the FEC group state.
    if ((!rto_outage) && (rel_.mode == SEMI_RELIABLE_ARQ_FEC) &&
        IS_FEC(pkt_info))
    {
      FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                               kFecGroupSize)];

      if (grp_info.fec_grp_id_ == pkt_info.fec_grp_id_)
      {
        // This group should not be in round 1, since no retransmissions
        // should occur in round 1.
        if (grp_info.fec_round_ == 1)
        {
          LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Warning, FEC grp %" PRIFecGroupId " rexmit in "
               "round 1.\n", conn_id_, stream_id_, grp_info.fec_grp_id_);
        }

        // Update the packet sent count for the FEC group's current round.
        if (grp_info.fec_round_ <= grp_info.fec_max_rounds_)
        {
          if (hdr.fec_pkt_type == FEC_SRC_PKT)
          {
            ++grp_info.fec_src_sent_icr_;
          }
          else
          {
            ++grp_info.fec_enc_sent_icr_;
          }

#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Updated grp %" PRIFecGroupId " counts: "
               " src_to_send %" PRIFecSize " enc_to_send %" PRIFecSize
               " src_sent %" PRIFecSize " enc_sent %" PRIFecSize ".\n",
               conn_id_, stream_id_, grp_info.fec_grp_id_,
               grp_info.fec_src_to_send_icr_, grp_info.fec_enc_to_send_icr_,
               grp_info.fec_src_sent_icr_, grp_info.fec_enc_sent_icr_);
#endif

          // Check if all of the transmissions are complete for the FEC group
          // in the current round.  If so, then set up watching the returned
          // ACK packet timestamps for the end of the round.
          if ((grp_info.fec_src_sent_icr_ >= grp_info.fec_src_to_send_icr_) &&
              (grp_info.fec_enc_sent_icr_ >= grp_info.fec_enc_to_send_icr_))
          {
            RecordEndOfFecRound(now, grp_info, hdr.timestamp);
          }
        }
      }
    }
  }
}

//============================================================================
WindowSize SentPktManager::OrigFecEncPktsToBeSent()
{
  // First, clean up the original FEC encoded packet queue.  This is for
  // unsent FEC encoded packets generated in round 1.
  CleanUpOrigFecEncQueue();

  // Return the current original FEC encoded packet queue size.
  return fec_enc_orig_.GetCount();
}

//============================================================================
size_t SentPktManager::GetNextOrigFecEncPktLen()
{
  size_t  data_len = 0;

  // Access the next FEC encoded data packet (an unsent FEC encoded packet
  // generated in round 1) waiting in the original FEC encoded data packet
  // queue.
  while (fec_enc_orig_.GetCount() > 0)
  {
    SentPktInfo&  fe_pkt_info = fec_enc_orig_.GetHead();

    // Make sure that the packet is an FEC encoded data packet.
    if (IS_FEC(fe_pkt_info) && (fe_pkt_info.fec_pkt_type_ == FEC_ENC_PKT))
    {
      data_len = ((fe_pkt_info.packet_ != NULL) ?
                  fe_pkt_info.packet_->GetLengthInBytes() : 0);
      break;
    }

    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": FEC encoded packet missing.\n", conn_id_, stream_id_);

    fec_enc_orig_.RemoveFromHead();
  }

  return data_len;
}

//============================================================================
bool SentPktManager::GetNextOrigFecEncPkt(const Time& now, CcId cc_id,
                                          DataHeader& hdr, Packet*& pkt)
{
  // Make sure that there is window space available and an original FEC
  // encoded data packet (an unsent FEC encoded packet generated in round 1)
  // waiting to be sent.
  if ((!CanSend()) || (fec_enc_orig_.GetCount() == 0))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Cannot send an original FEC encoded packet now, snd_fec_ %"
         PRIPktSeqNumber " snd_una_ %" PRIPktSeqNumber " snd_nxt_ %"
         PRIPktSeqNumber " snd_wnd_ %" PRIWindowSize " fec_enc_orig_cnt_ %"
         PRIWindowSize ".\n", conn_id_, stream_id_, snd_fec_, snd_una_,
         snd_nxt_, kFlowCtrlWindowPkts, fec_enc_orig_.GetCount());
    return false;
  }

  // Get the FEC encoded packet ready for transmission.
  if (!GetFecEncPkt(now, cc_id, fec_enc_orig_, hdr, pkt))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error preparing original FEC encoded packet for transmission.\n",
         conn_id_, stream_id_);
    return false;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Next seq %" PRIPktSeqNumber " orig FEC ENC grp %" PRIFecGroupId
       " idx %" PRIFecSize "\n", conn_id_, stream_id_, hdr.sequence_number,
       hdr.fec_group_id, hdr.fec_group_index);
#endif

  return true;
}

//============================================================================
void SentPktManager::SentOrigFecEncPkt(DataHeader& hdr, size_t bytes_sent,
                                       PktSeqNumber conn_seq,
                                       PktCount sent_pkt_cnt,
                                       const Time& xmit_time)
{
  MoveFecEncPkt(fec_enc_orig_, hdr, bytes_sent, conn_seq, sent_pkt_cnt,
                xmit_time);
}

//============================================================================
void SentPktManager::ForceFecGroupToEnd()
{
  // First, check if a new FEC group has been started.  This is done by
  // checking if at least one FEC source data packet has been sent in the
  // current FEC group, which increments the next FEC group index to a
  // non-zero value.  If not, then return.
  if (fec_grp_idx_ == 0)
  {
    return;
  }

  // Find the current FEC group info.
  FecGroupInfo&  grp_info = fec_grp_info_[(fec_grp_id_ % kFecGroupSize)];

  // Make sure that the current FEC group is still in round 1.
  if (grp_info.fec_round_ != 1)
  {
    return;
  }

  // Mark the group as being forced to end.
  SET_FORCE_END(grp_info);

  // Update the number of source and encoded packets in the current group.
  // The number of source packets will be however many have already been sent.
  grp_info.fec_num_src_ = grp_info.fec_src_sent_icr_;

  // Determine the total number of packets to be sent.
  int32_t  num_src       = grp_info.fec_num_src_;
  int32_t  total_to_send = 0;

  if (IS_PURE_ARQ(grp_info))
  {
    // Pure ARQ is in use.  Do not send any FEC encoded packets.
    total_to_send = num_src;
  }
  else
  {
    // Use the correct FEC lookup table to determine the total number of
    // packets to be sent.
    size_t  idx = TableOffset(fec_per_idx_, grp_info.fec_num_src_, 0, 0);

    if ((grp_info.fec_max_rounds_ >= kNumLookupTables) ||
        (fec_midgame_tables_[grp_info.fec_max_rounds_] == NULL) ||
        (fec_endgame_tables_[grp_info.fec_max_rounds_] == NULL))
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, missing FEC lookup tables for n %" PRIFecRound ".\n",
           conn_id_, stream_id_, grp_info.fec_max_rounds_);
    }

    if (grp_info.fec_round_ < grp_info.fec_max_rounds_)
    {
      // Not in the last round yet.  Use the midgame table.
      total_to_send = fec_midgame_tables_[grp_info.fec_max_rounds_][idx];
    }
    else
    {
      // In the last round now.  Use the endgame table.
      total_to_send = fec_endgame_tables_[grp_info.fec_max_rounds_][idx];
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Force end of FEC grp %" PRIFecGroupId " %sgame[%" PRIFecRound
         "][%zu][%" PRId32 "][0][0] = %" PRId32 "\n", conn_id_, stream_id_,
         grp_info.fec_grp_id_,
         ((grp_info.fec_round_ < grp_info.fec_max_rounds_) ? "mid" : "end"),
         grp_info.fec_round_, fec_per_idx_, num_src, total_to_send);
#endif
  }

  int32_t  num_enc = (total_to_send - num_src);

  grp_info.fec_num_enc_ = num_enc;

  grp_info.fec_src_to_send_icr_ = num_src;
  grp_info.fec_enc_to_send_icr_ = num_enc;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Force end of FEC grp %" PRIFecGroupId " src %" PRId32 " enc %"
       PRId32 "\n", conn_id_, stream_id_, grp_info.fec_grp_id_, num_src,
       num_enc);
#endif

  // Now that we have all of the FEC source packets for the group, generate
  // any required FEC encoded packets.  Note that any FEC encoded packets
  // needed later are generated in PrepareNextFecRound().
  if (grp_info.fec_num_enc_ > 0)
  {
    if (!GenerateFecEncodedPkts(
          grp_info.start_src_seq_num_, grp_info.end_src_seq_num_,
          grp_info.fec_grp_id_, kMaxFecGroupLengthPkts,
          grp_info.fec_num_src_, 0, grp_info.fec_num_enc_, fec_enc_orig_,
          false))
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Cannot continue without generation of FEC encoded packets.\n",
           conn_id_, stream_id_);
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Generated %" PRIFecSize " FEC encoded packets for grp %"
         PRIFecGroupId ".\n", conn_id_, stream_id_, grp_info.fec_num_enc_,
         grp_info.fec_grp_id_);
#endif

    // Record the round when the FEC encoded packets were first generated.
    grp_info.fec_gen_enc_round_ = grp_info.fec_round_;
  }
  else
  {
    // There are no FEC encoded packets for the FEC group, so all of the
    // packets for the FEC group have been sent.  Watch the returned ACK
    // packet timestamps for the end of the round.
    Time          now = Time::Now();
    PktTimestamp  ts  = conn_.GetCurrentLocalTimestamp();

    RecordEndOfFecRound(now, grp_info, ts);
  }

  // Move to the next FEC group.
  StartNextFecGroup();
}

//============================================================================
bool SentPktManager::GetSentPktCnt(
  PktSeqNumber seq_num, RetransCount rexmit_cnt, PktCount& sent_pkt_cnt) const
{
  // Look up the sent packet information for the data packet.
  SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

  if (pkt_info.seq_num_ == seq_num)
  {
    if (pkt_info.rexmit_cnt_ == rexmit_cnt)
    {
      // Return the sent data packet count from when the data packet was sent
      // most recently.
      sent_pkt_cnt = pkt_info.sent_pkt_cnt_;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Found seq %" PRIPktSeqNumber " rexmit_cnt %" PRIRetransCount
           ", current cnt %" PRIPktCount ".\n", conn_id_, stream_id_, seq_num,
           rexmit_cnt, sent_pkt_cnt);
#endif

      return true;
    }

    if ((pkt_info.rexmit_cnt_ > 0) &&
        (pkt_info.rexmit_cnt_ < kMaxRexmitCount) &&
        ((pkt_info.rexmit_cnt_ - 1) == rexmit_cnt))
    {
      // Return the previous sent data packet count from when the data packet
      // was sent the previous time.
      sent_pkt_cnt = pkt_info.prev_sent_pkt_cnt_;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Found seq %" PRIPktSeqNumber " rexmit_cnt %" PRIRetransCount
           ", previous cnt %" PRIPktCount ".\n", conn_id_, stream_id_,
           seq_num, rexmit_cnt, sent_pkt_cnt);
#endif

      return true;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Mismatch seq %" PRIPktSeqNumber " rexmit_cnt (%" PRIRetransCount
         "!= %" PRIRetransCount ").\n", conn_id_, stream_id_, seq_num,
         pkt_info.rexmit_cnt_, rexmit_cnt);
#endif
  }
#ifdef SLIQ_DEBUG
  else
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Cannot find seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
         seq_num);
  }
#endif

  return false;
}

//============================================================================
bool SentPktManager::IsGoodAckPacket(const AckHeader& ack_hdr)
{
  // Make sure that the next expected sequence number is not going backward.
  if (SEQ_LT(ack_hdr.next_expected_seq_num, rcv_ack_nxt_exp_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, ACK next expected seq %" PRIPktSeqNumber " less than "
         "current next expected seq %" PRIPktSeqNumber ".\n", conn_id_,
         stream_id_, ack_hdr.next_expected_seq_num, rcv_ack_nxt_exp_);
    return false;
  }

  // Make sure that the largest observed sequence number is not greater than
  // the largest sequence number sent.
  PktSeqNumber  lo_seq_num = GetLrgObsSeqNum(ack_hdr);

  if (SEQ_GEQ(lo_seq_num, snd_nxt_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, ACK largest observed seq %" PRIPktSeqNumber " greater "
         "than max sent seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
         lo_seq_num, (snd_nxt_ - 1));
    return false;
  }

  return true;
}

//============================================================================
bool SentPktManager::ProcessAck(const AckHeader& ack_hdr,
                                const Time& rcv_time, const Time& now,
                                bool& new_data_acked,
                                PktSeqNumber& lo_conn_seq)
{
  // Initialize the new data ACKed flag.
  new_data_acked = false;

  // Get the next expected and largest observed sequence numbers from the ACK
  // header.
  PktSeqNumber  seq_num    = 0;
  PktSeqNumber  ne_seq_num = ack_hdr.next_expected_seq_num;
  PktSeqNumber  lo_seq_num = GetLrgObsSeqNum(ack_hdr);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Processing ACK, num_obs %" PRIu8 " num_blk %" PRIu8 " nxt_exp %"
       PRIPktSeqNumber " lrg_obs %" PRIPktSeqNumber ", snd_wnd_ %"
       PRIWindowSize " snd_fec_ %" PRIPktSeqNumber " snd_una_ %"
       PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber " fec_enc_orig_cnt_ %"
       PRIWindowSize " fec_enc_addl_cnt_ %" PRIWindowSize " bif %zd.\n",
       conn_id_, stream_id_, ack_hdr.num_observed_times,
       ack_hdr.num_ack_block_offsets, ne_seq_num, lo_seq_num,
       kFlowCtrlWindowPkts, snd_fec_, snd_una_, snd_nxt_,
       fec_enc_orig_.GetCount(), fec_enc_addl_.GetCount(),
       stats_bytes_in_flight_);
#endif

  // Update the current next expected and largest observed sequence numbers.
  if (SEQ_GT(ne_seq_num, rcv_ack_nxt_exp_))
  {
    rcv_ack_nxt_exp_ = ne_seq_num;
  }

  if (SEQ_GT(lo_seq_num, rcv_ack_lrg_obs_))
  {
    rcv_ack_lrg_obs_ = lo_seq_num;
  }

  // Return the largest observed connection sequence number.
  if (SEQ_LT(rcv_ack_lrg_obs_, snd_una_) ||
      SEQ_GEQ(rcv_ack_lrg_obs_, snd_nxt_))
  {
    lo_conn_seq = last_lo_conn_seq_;
  }
  else
  {
    lo_conn_seq       = sent_pkts_[(rcv_ack_lrg_obs_ %
                                    kFlowCtrlWindowPkts)].conn_seq_num_;
    last_lo_conn_seq_ = lo_conn_seq;
  }

  // Compute the RTTs from the information in the ACK packet.
  for (uint8_t i = 0; i < ack_hdr.num_observed_times; ++i)
  {
    seq_num = ack_hdr.observed_time[i].seq_num;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": ACK obs_time[%" PRIu8 "]: seq %" PRIPktSeqNumber " ts %"
         PRIPktTimestamp ".\n", conn_id_, stream_id_, i, seq_num,
         ack_hdr.observed_time[i].timestamp);
#endif

    // Compute the RTT.
    PktTimestamp  rcv_ts   = (static_cast<PktTimestamp>(
                                rcv_time.GetTimeInUsec()) +
                              conn_.GetLocalTimestampCorrection());
    PktTimestamp  rtt_usec = (rcv_ts - ack_hdr.observed_time[i].timestamp);

    // The RTT must not be equal to zero or be negative.  Use a minimum
    // allowable RTT to allow components that track a minimum observed RTT to
    // function properly.
    if (rtt_usec < kMinRttUsec)
    {
      rtt_usec = kMinRttUsec;
    }

    if (rtt_usec > kMaxRttUsec)
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Warning, invalid computed RTT %" PRIPktTimestamp " usec for "
           "seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_, rtt_usec,
           seq_num);
      continue;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Computed RTT %" PRIPktTimestamp " usec for seq %" PRIPktSeqNumber
         ".\n", conn_id_, stream_id_, rtt_usec, seq_num);
#endif

    // Update the RTT manager.
    Time  rtt = Time::FromUsec(rtt_usec);

    rtt_mgr_.UpdateRtt(now, conn_id_, rtt);

    // Store the RTT for the packet, and notify the congestion control
    // algorithm of the RTT update.
    if ((SEQ_LT(seq_num, snd_nxt_)) &&
        ((snd_nxt_ - seq_num) < kFlowCtrlWindowPkts))
    {
      SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

      // Store the RTT for the packet.
      pkt_info.rtt_usec_ = rtt_usec;

      // Look up the congestion control algorithm using the CC ID from when
      // the packet was sent.
      CcAlg&              cc_info = cc_algs_.cc_alg[pkt_info.cc_id_];
      CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

      if ((pkt_info.cc_id_ >= SliqApp::kMaxCcAlgPerConn) || (cc_alg == NULL))
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": NULL congestion control object for cc_id %" PRICcId ".\n",
             conn_id_, stream_id_, pkt_info.cc_id_);
      }
      else
      {
        if (!cc_info.in_ack_proc)
        {
          cc_alg->OnAckPktProcessingStart(now);
          cc_info.in_ack_proc = true;
        }

        cc_alg->OnRttUpdate(stream_id_, now, ack_hdr.timestamp, rcv_ts,
                            seq_num, pkt_info.cc_seq_num_, rtt,
                            pkt_info.pkt_len_, pkt_info.cc_val_);
      }
    }
    else
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Warning, RTT for seq %" PRIPktSeqNumber " outside window, "
           "can't look up CC seq.\n", conn_id_, stream_id_, seq_num);
    }
  }

  // Now that the RTT manager has been updated, get the current retransmit
  // time for use below.
  Time     rexmit_time = rtt_mgr_.GetFastRexmitTime();
  ssize_t  new_bif     = stats_bytes_in_flight_;

  // Reset the congestion control count adjustments before processing the ACK
  // information.
  ResetCcCntAdjInfo();

  // Process all of the ACKs in the ACK header.
  // - All packets from snd_una_ up to ne_seq_num must be ACKed.
  // - Packets from ne_seq_num to lo_seq_num in the ACK blocks must be ACKed.
  for (seq_num = snd_una_; SEQ_LT(seq_num, ne_seq_num); ++seq_num)
  {
    MarkPktAcked(seq_num, ack_hdr, now, new_data_acked, new_bif);
  }

  bool          multi_block   = false;
  PktSeqNumber  start_seq_num = 0;

  for (uint8_t i = 0; i < ack_hdr.num_ack_block_offsets; ++i)
  {
    seq_num = (ne_seq_num + static_cast<PktSeqNumber>(
                 ack_hdr.ack_block_offset[i].offset));

    switch (ack_hdr.ack_block_offset[i].type)
    {
      case ACK_BLK_SINGLE:
        MarkPktAcked(seq_num, ack_hdr, now, new_data_acked, new_bif);
        multi_block = false;
        break;

      case ACK_BLK_MULTI:
        if (!multi_block)
        {
          start_seq_num = seq_num;
          multi_block   = true;
        }
        else
        {
          for (PktSeqNumber sn = start_seq_num; SEQ_LEQ(sn, seq_num); ++sn)
          {
            MarkPktAcked(sn, ack_hdr, now, new_data_acked, new_bif);
          }
          multi_block = false;
        }
        break;
    }
  }

  // Walk the window forward up to the last packet that might be considered
  // lost.
  for (seq_num = snd_fec_; SEQ_LEQ(seq_num, (lo_seq_num - kFastRexmitDist));
       ++seq_num)
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

    // If the packet has not been ACKed, then attempt to consider it lost.
    if (!IS_ACKED(pkt_info))
    {
      MaybeMarkPktLost(seq_num, pkt_info, now, rexmit_time);
    }
  }

  // The bytes in flight should never be less than 0.
  if (new_bif < 0)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Negative bytes in flight.\n", conn_id_, stream_id_);
  }

  // Update the counts.  This has to happen after the OnPacketLost() and
  // OnPacketAcked() calls, which are above.
  //
  //   pif_adj  - starts at 0, subtract one for each ACKed packet.
  //   bif_adj  - starts at 0, subtract packet size for each ACKed packet.
  //   pipe_adj - starts at 0, subtract packet size for each packet that was
  //              not lost and is now either ACKed or considered lost,
  //              subtract packet size again if packet was retransmitted.
  ReportCcCntAdjToCc();

  stats_bytes_in_flight_ = new_bif;

  // Move snd_una_ up to the next expected sequence number in the received ACK
  // packet.  These packets have either been ACKed or are FEC packets that the
  // receiver has given up on (based on move forward packets).
  PktSeqNumber  old_snd_una = snd_una_;
  bool          using_fec   = (rel_.mode == SEMI_RELIABLE_ARQ_FEC);

  while (SEQ_LT(snd_una_, ne_seq_num))
  {
    SentPktInfo&  pkt_info = sent_pkts_[(snd_una_  % kFlowCtrlWindowPkts)];

    if ((!using_fec) && (pkt_info.packet_ != NULL))
    {
      packet_pool_.Recycle(pkt_info.packet_);
      pkt_info.packet_ = NULL;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Packet seq %" PRIPktSeqNumber " is no longer needed.\n", conn_id_,
         stream_id_, snd_una_);
#endif

    ++snd_una_;
  }

  // Now that snd_una_ is updated, update snd_fec_.
  if (using_fec)
  {
    UpdateSndFec(false);
  }
  else
  {
    snd_fec_ = snd_una_;
  }

  // Semi-reliable or best effort modes can now drop any stale or lost
  // packets.  This might move snd_una_ and/or snd_fec_ forward.
  if (rel_.mode != RELIABLE_ARQ)
  {
    DropPackets(now, false);
  }

  // Update the oldest unacknowledged packet for the stream with congestion
  // control, if required.
  if ((cc_algs_.use_una_pkt_reporting) && (old_snd_una != snd_una_))
  {
    ReportUnaToCc();
  }

  // Determine the end of FEC group rounds using the observed sequence number
  // timestamps.
  if ((rel_.mode == SEMI_RELIABLE_ARQ_FEC) &&
      (ack_hdr.num_observed_times > 0))
  {
    for (uint8_t i = 0; i < ack_hdr.num_observed_times; ++i)
    {
      ProcessEndOfFecRounds(ack_hdr.observed_time[i].seq_num,
                            ack_hdr.observed_time[i].timestamp);
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated snd_wnd_ %" PRIWindowSize " snd_fec_ %" PRIPktSeqNumber
       " snd_una_ %" PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber
       " rcv_ack_nxt_exp_ %" PRIPktSeqNumber " rcv_ack_lrg_obs_ %"
       PRIPktSeqNumber " fec_enc_orig_cnt_ %" PRIWindowSize
       " fec_enc_addl_cnt_ %" PRIWindowSize " bif %zd.\n", conn_id_,
       stream_id_, kFlowCtrlWindowPkts, snd_fec_, snd_una_, snd_nxt_,
       rcv_ack_nxt_exp_, rcv_ack_lrg_obs_, fec_enc_orig_.GetCount(),
       fec_enc_addl_.GetCount(), stats_bytes_in_flight_);
#endif

  return true;
}

//============================================================================
void SentPktManager::ProcessImplicitAck(const Time& now,
                                        PktSeqNumber lo_conn_seq)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Processing implicit ACK, lrg_obs_conn_seq %" PRIPktSeqNumber
       ", snd_wnd_ %" PRIWindowSize " snd_fec_ %" PRIPktSeqNumber
       " snd_una_ %" PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber
       " fec_enc_orig_cnt_ %" PRIWindowSize " fec_enc_addl_cnt_ %"
       PRIWindowSize " bif %zd.\n", conn_id_, stream_id_, lo_conn_seq,
       kFlowCtrlWindowPkts, snd_fec_, snd_una_, snd_nxt_,
       fec_enc_orig_.GetCount(), fec_enc_addl_.GetCount(),
       stats_bytes_in_flight_);
#endif

  // Get the current retransmit time for use below.
  Time  rexmit_time = rtt_mgr_.GetFastRexmitTime();

  // Reset the congestion control count adjustments before processing the
  // implicit ACK information.
  ResetCcCntAdjInfo();

  // Loop over all of the elements in the send window while processing the
  // implicit ACK information.
  for (PktSeqNumber seq = snd_fec_; SEQ_LT(seq, snd_nxt_); ++seq)
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq % kFlowCtrlWindowPkts)];

    // If the packet has not been ACKed yet, it has been too long since the
    // packet was sent, and the largest observed connection sequence number
    // has moved forward enough, then check if this packet should be
    // considered lost.
    if ((!IS_ACKED(pkt_info)) &&
        (now >= (Time(pkt_info.last_xmit_time_) + rexmit_time)) &&
        SEQ_LEQ((pkt_info.conn_seq_num_ + kFastRexmitDist), lo_conn_seq))
    {
      MaybeMarkPktLost(seq, pkt_info, now, rexmit_time);
    }
  }

  // Update the counts.  This has to happen after the OnPacketLost() calls,
  // which are above.
  //
  //   pipe_adj - starts at 0, subtract packet size for each packet that was
  //              not lost and is now considered lost.
  ReportCcCntAdjToCc();

  // Semi-reliable or best effort modes can now drop any stale or lost
  // packets.  This might move snd_una_ and/or snd_fec_ forward.
  if (rel_.mode != RELIABLE_ARQ)
  {
    PktSeqNumber  old_snd_una = snd_una_;

    DropPackets(now, false);

    // Update the oldest unacknowledged packet for the stream with congestion
    // control, if required.
    if ((cc_algs_.use_una_pkt_reporting) && (old_snd_una != snd_una_))
    {
      ReportUnaToCc();
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated snd_wnd_ %" PRIWindowSize " snd_fec_ %" PRIPktSeqNumber
       " snd_una_ %" PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber
       " rcv_ack_nxt_exp_ %" PRIPktSeqNumber " rcv_ack_lrg_obs_ %"
       PRIPktSeqNumber " fec_enc_orig_cnt_ %" PRIWindowSize
       " fec_enc_addl_cnt_ %" PRIWindowSize " bif %zd.\n", conn_id_,
       stream_id_, kFlowCtrlWindowPkts, snd_fec_, snd_una_, snd_nxt_,
       rcv_ack_nxt_exp_, rcv_ack_lrg_obs_, fec_enc_orig_.GetCount(),
       fec_enc_addl_.GetCount(), stats_bytes_in_flight_);
#endif
}

//============================================================================
bool SentPktManager::ForceUnackedPacketsLost(const Time& now)
{
  // Get the current retransmit time for use below.
  Time  rexmit_time = rtt_mgr_.GetFastRexmitTime();

  // Reset the congestion control count adjustments before updating the packet
  // information.
  ResetCcCntAdjInfo();

  // Loop over all of the elements in the send window, looking for unACKed
  // packets that are not considered lost yet.
  for (PktSeqNumber seq = snd_una_; SEQ_LT(seq, snd_nxt_); ++seq)
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq % kFlowCtrlWindowPkts)];

    if ((!IS_ACKED(pkt_info)) && (!IS_LOST(pkt_info)))
    {
      MaybeMarkPktLost(seq, pkt_info, now, rexmit_time, true);
    }
  }

  // Update the counts.
  //
  //   pif_adj  - starts at 0, subtract one for each ACKed packet.
  //   bif_adj  - starts at 0, subtract packet size for each ACKed packet.
  //   pipe_adj - starts at 0, subtract packet size for each packet that was
  //              not lost and is now either ACKed or considered lost,
  //              subtract packet size again if packet was retransmitted.
  ReportCcCntAdjToCc();

  // Semi-reliable or best effort modes can now drop any stale or lost
  // packets.  This might move snd_una_ and/or snd_fec_ forward.
  if (rel_.mode != RELIABLE_ARQ)
  {
    PktSeqNumber  old_snd_una = snd_una_;

    DropPackets(now, false);

    // Update the oldest unacknowledged packet for the stream with congestion
    // control, if required.
    if ((cc_algs_.use_una_pkt_reporting) && (old_snd_una != snd_una_))
    {
      ReportUnaToCc();
    }
  }

  return true;
}

//============================================================================
void SentPktManager::LeaveOutage()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Leaving outage.\n", conn_id_, stream_id_);
#endif

  if (rel_.mode != RELIABLE_ARQ)
  {
    // Get the current time.
    Time  now = Time::Now();

    // Reset the FEC group.
    if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
    {
      StartNextFecGroup();
      UpdateSndFec(true);
      EmptyFecEncodedPktQueues();
      fec_eor_cnt_ = 0;
    }

    // Semi-reliable or best effort modes can now drop any stale or lost
    // packets using special rules.  This might move snd_una_ and/or snd_fec_
    // forward.
    DropPackets(now, true);
  }

  // Update the oldest unacknowledged packet for the stream with congestion
  // control, if required.
  if (cc_algs_.use_una_pkt_reporting)
  {
    ReportUnaToCc();
  }
}

//============================================================================
void SentPktManager::GetMoveForward(DataHeader& hdr)
{
  switch (rel_.mode)
  {
    case BEST_EFFORT:
    case SEMI_RELIABLE_ARQ:
      // Have the receiver at least be up to snd_una_.
      hdr.move_fwd_flag    = SEQ_LT(rcv_ack_nxt_exp_, snd_una_);
      hdr.move_fwd_seq_num = snd_una_;
      break;

    case SEMI_RELIABLE_ARQ_FEC:
      if (fin_sent_)
      {
        // This is brutal, but force the receiver to give up on any missing
        // packets when the FIN is sent.  Since retransmissions may not be
        // sent for certain packets (such as FEC packets that may not be
        // resent due to FEC group rounds no longer being advanced), it is
        // possible that the receiver will get hung up waiting for a packet
        // that will never be resent and will not process the FIN in order to
        // close the stream.
        hdr.move_fwd_flag    = true;
        hdr.move_fwd_seq_num = snd_nxt_;
      }
      else
      {
        // Have the receiver at least be up to snd_fec_.
        hdr.move_fwd_flag    = SEQ_LT(rcv_ack_nxt_exp_, snd_fec_);
        hdr.move_fwd_seq_num = snd_fec_;
      }
      break;

    case RELIABLE_ARQ:
    default:
      // Move forwards are never sent.
      hdr.move_fwd_flag = false;
  }
}

//============================================================================
double SentPktManager::GetFecSrcPktsDurSec()
{
  double  rv = stats_fec_src_dur_sec_;

  if (stats_pkt_ist_ > 0.0)
  {
    // When computing the duration limit using the current packet inter-send
    // time estimate, use (pkts) instead of (pkts - 1) and then add 20% in
    // order to avoid ending FEC groups too soon.
    FecSize  pkts = ((fec_total_pkts_ > 1) ? fec_total_pkts_ : 2);
    double   lim  = (1.2 * (stats_pkt_ist_ * static_cast<double>(pkts)));

    if (rv > lim)
    {
      rv = lim;
    }
  }

  return rv;
}

//============================================================================
PktSeqNumber SentPktManager::GetLrgObsSeqNum(const AckHeader& ack_hdr)
{
  // Figure out the largest observed sequence number from the ACK header.
  PktSeqNumber  ne_seq = ack_hdr.next_expected_seq_num;

  if (ack_hdr.num_ack_block_offsets == 0)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": All ACKed up, lo_seq %" PRIPktSeqNumber ".\n", conn_id_,
         stream_id_, (ne_seq - 1));
#endif

    // The receiver is all ACKed up.  The largest observed sequence number is
    // one less than the next expected sequence number.
    return (ne_seq - 1);
  }

  // The receiver is not all ACKed up.  The largest observed sequence number
  // must be in one of the included ACK blocks.  Find the maximum ACK block
  // offset.  The offset types can simply be ignored here.
  uint16_t  max_offset = ack_hdr.ack_block_offset[0].offset;

  for (uint8_t i = 1; i < ack_hdr.num_ack_block_offsets; ++i)
  {
    uint16_t  offset = ack_hdr.ack_block_offset[i].offset;

    if (offset > max_offset)
    {
      max_offset = offset;
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Found lo_seq %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
       (ne_seq + static_cast<PktSeqNumber>(max_offset)));
#endif

  // Convert the maximum ACK block offset found to a sequence number.
  return (ne_seq + max_offset);
}

//============================================================================
void SentPktManager::MarkPktAcked(
  PktSeqNumber seq_num, const AckHeader& ack_hdr, const Time& now,
  bool& new_data_acked, ssize_t& new_bif)
{
  SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

  // Do not re-ACK a packet. Packets before snd_una_ have already been ACKed.
  if (SEQ_LT(seq_num, snd_una_) || IS_ACKED(pkt_info))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Pkt seq %" PRIPktSeqNumber " is already ACKed.\n", conn_id_,
         stream_id_, seq_num);
#endif

    return;
  }

  // Update congestion control.
  CcAlg&              cc_info = cc_algs_.cc_alg[pkt_info.cc_id_];
  CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

  if (cc_alg == NULL)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": NULL congestion control object for cc_id %" PRICcId ".\n",
         conn_id_, stream_id_, pkt_info.cc_id_);
  }

  if (!cc_info.in_ack_proc)
  {
    cc_alg->OnAckPktProcessingStart(now);
    cc_info.in_ack_proc = true;
  }

  cc_alg->OnPacketAcked(stream_id_, now, seq_num, pkt_info.cc_seq_num_,
                        ack_hdr.next_expected_seq_num, pkt_info.pkt_len_);

  // The unACKed packet is about to be marked as ACKed.  Update the counts.
  cc_cnt_adj_[pkt_info.cc_id_].updated_  = true;
  cc_cnt_adj_[pkt_info.cc_id_].pif_adj_ -= 1;
  cc_cnt_adj_[pkt_info.cc_id_].bif_adj_ -=
    static_cast<ssize_t>(pkt_info.pkt_len_);
  new_bif                               -=
    static_cast<ssize_t>(pkt_info.pkt_len_);
  if (!IS_LOST(pkt_info))
  {
    cc_cnt_adj_[pkt_info.cc_id_].pipe_adj_ -=
      static_cast<ssize_t>(pkt_info.pkt_len_);
  }
  if (pkt_info.rexmit_cnt_ > 0)
  {
    cc_cnt_adj_[pkt_info.cc_id_].pipe_adj_ -=
      static_cast<ssize_t>(pkt_info.pkt_len_);
  }

  // Update the capacity estimate.  Be careful to only report application
  // payload bytes in the ACKed packet.
  uint16_t  app_payload_len =
    (((!IS_FEC(pkt_info)) || (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)) ?
     pkt_info.pkt_len_ : 0);

  conn_.UpdateCapacityEstimate(now, pkt_info.cc_id_, app_payload_len,
                               pkt_info.bytes_sent_);

  // Pass the RTT measurement and packet delivery delay (PDD) estimate to the
  // connection.  These will be passed to the application when it is safe to
  // do so.
  if (((!IS_FEC(pkt_info)) || (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)) &&
      (pkt_info.rtt_usec_ > 0))
  {
    // Compute the PDD.  This is the time from when the packet was received
    // from the application until the packet was delivered to the peer.
    // Estimate the one-way delay to the peer as one half of the RTT.
    //
    //   PDD = (now - orig_xmit_time) + q_delay - (0.5 * rtt)
    uint32_t  pdd = ((now - Time(pkt_info.xmit_time_)).GetTimeInUsec() +
                     pkt_info.q_delay_usec_ - ((pkt_info.rtt_usec_ + 1) / 2));

    conn_.PktAcked(stream_id_, pkt_info.rtt_usec_, pdd);
  }

  // Update the FEC group state.  This must be done before the pkt_info flags
  // are modified.
  if ((rel_.mode == SEMI_RELIABLE_ARQ_FEC) && IS_FEC(pkt_info))
  {
    RecordFecGroupPktAck(now, pkt_info);
  }

  // Mark the packet as ACKed.  It is also no longer considered lost.
  SET_ACKED(pkt_info);
  CLEAR_LOST(pkt_info);

  // Update the new data ACKed flag.
  new_data_acked = true;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Pkt seq %" PRIPktSeqNumber " is now ACKed.\n", conn_id_, stream_id_,
       seq_num);
#endif
}

//============================================================================
void SentPktManager::MaybeMarkPktLost(
  PktSeqNumber seq_num, SentPktInfo& pkt_info, const Time& now,
  const Time& rexmit_time, bool force_lost)
{
  // Update congestion control if needed.
  bool  consider_lost = force_lost;

  if ((!force_lost) && (!IS_LOST(pkt_info)))
  {
    CcAlg&              cc_info = cc_algs_.cc_alg[pkt_info.cc_id_];
    CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

    if (cc_alg == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": NULL congestion control object for cc_id %" PRICcId ".\n",
           conn_id_, stream_id_, pkt_info.cc_id_);
    }
    else
    {
      if (!cc_info.in_ack_proc)
      {
        cc_alg->OnAckPktProcessingStart(now);
        cc_info.in_ack_proc = true;
      }

      consider_lost = cc_alg->OnPacketLost(stream_id_, now, seq_num,
                                           pkt_info.cc_seq_num_,
                                           pkt_info.pkt_len_);
    }
  }

  // Retransmit if needed.  Requires either of the following to be true:
  // - congestion control determined that the packet is now lost, or
  // - the packet is already considered lost, it has not been reported as a
  //   fast retransmit candidate since the last transmission, and it has been
  //   too long since the last retransmission.
  if (consider_lost ||
      (IS_LOST(pkt_info) && (!IS_CAND(pkt_info)) &&
       (now >= (Time(pkt_info.last_xmit_time_) + rexmit_time))))
  {
    if (AllowRexmit(pkt_info))
    {
      if (stream_.AddFastRexmitPkt(seq_num))
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Add pkt seq %" PRIPktSeqNumber " to fast rexmit candidate "
             "list.\n", conn_id_, stream_id_, seq_num);
#endif

        SET_CAND(pkt_info);
      }
    }
  }

  // Update the lost flag.  This is only done if congestion control was
  // updated and returned true.
  if (!IS_LOST(pkt_info) && consider_lost)
  {
    // The unACKed packet is about to be marked as Lost.  Update the counts.
    cc_cnt_adj_[pkt_info.cc_id_].updated_   = true;
    cc_cnt_adj_[pkt_info.cc_id_].pipe_adj_ -=
      static_cast<ssize_t>(pkt_info.pkt_len_);

    // Mark the packet as lost.
    SET_LOST(pkt_info);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": pkt seq %" PRIPktSeqNumber " is now lost.\n", conn_id_,
         stream_id_, seq_num);
#endif
  }
#ifdef SLIQ_DEBUG
  else
  {
    if (IS_LOST(pkt_info))
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": pkt seq %" PRIPktSeqNumber " already marked as lost.\n",
           conn_id_, stream_id_, seq_num);
    }
    else
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": pkt seq %" PRIPktSeqNumber " not yet lost.\n", conn_id_,
           stream_id_, seq_num);
    }
  }
#endif
}

//============================================================================
bool SentPktManager::AllowRexmitBasic(const SentPktInfo& pkt_info,
                                      const Time& now,
                                      const Time& rexmit_time)
{
  // If the packet has the FIN flag set, then it must be able to be
  // retransmitted.
  if (IS_FIN(pkt_info))
  {
    return true;
  }

  switch (rel_.mode)
  {
    case BEST_EFFORT:
      // Do not retransmit.
      return false;

    case SEMI_RELIABLE_ARQ:
      // Retransmit if allowed and not stale.
      return ((pkt_info.rexmit_limit_ > 0) &&
              ((pkt_info.rexmit_cnt_ < pkt_info.rexmit_limit_) ||
               (now < (Time(pkt_info.last_xmit_time_) + rexmit_time))));

    case SEMI_RELIABLE_ARQ_FEC:
    {
      // Retransmit if allowed and not stale.
      bool allow = ((pkt_info.rexmit_limit_ > 0) &&
                    ((pkt_info.rexmit_cnt_ < pkt_info.rexmit_limit_) ||
                     (now < (Time(pkt_info.last_xmit_time_) + rexmit_time))));

      // If allow is true and this is an FEC encoded data packet, then make
      // sure that the FEC group still needs the packet to be resent.
      if (allow && IS_FEC(pkt_info) &&
          (pkt_info.fec_pkt_type_ == FEC_ENC_PKT))
      {
        FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                                 kFecGroupSize)];

        if (grp_info.fec_grp_id_ == pkt_info.fec_grp_id_)
        {
          // Check if all of the FEC source data packets for the group have
          // been ACKed.  If so, then do not bother resending the FEC encoded
          // data packet.
          if (grp_info.fec_src_ack_cnt_ >= grp_info.fec_num_src_)
          {
            allow = false;
          }
        }
        else
        {
          // There is no FEC group information.  Do not bother resending the
          // FEC encoded data packet.
          allow = false;
        }
      }

      return allow;
    }

    case RELIABLE_ARQ:
    default:
      // Retransmit.
      return true;
  }
}

//============================================================================
bool SentPktManager::AllowRexmit(SentPktInfo& pkt_info)
{
  // If the packet has the FIN flag set, then it must be able to be
  // retransmitted.
  if (IS_FIN(pkt_info))
  {
    return true;
  }

  switch (rel_.mode)
  {
    case BEST_EFFORT:
      // Do not retransmit.
      return false;

    case SEMI_RELIABLE_ARQ:
      // Retransmit if allowed.
      return ((pkt_info.rexmit_limit_ > 0) &&
              (pkt_info.rexmit_cnt_ < pkt_info.rexmit_limit_));

    case SEMI_RELIABLE_ARQ_FEC:
    {
      // Check the packet's retransmission limit first.
      bool  allow = ((pkt_info.rexmit_limit_ > 0) &&
                     (pkt_info.rexmit_cnt_ < pkt_info.rexmit_limit_));

      // If allowed is true, then check the FEC group for permission.
      if (IS_FEC(pkt_info) && allow)
      {
        FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                                 kFecGroupSize)];

        if (grp_info.fec_grp_id_ == pkt_info.fec_grp_id_)
        {
          // Only allow the retransmission here if the FEC group is out of
          // rounds, all of the FEC source packets have not been ACKed yet,
          // and this is an FEC source packet.
          allow = ((grp_info.fec_round_ > grp_info.fec_max_rounds_) &&
                   (grp_info.fec_src_ack_cnt_ < grp_info.fec_num_src_) &&
                   (pkt_info.fec_pkt_type_ == FEC_SRC_PKT));
        }
        else
        {
          LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Error, FEC group info for grp %" PRIFecGroupId
               " not available.\n", conn_id_, stream_id_,
               pkt_info.fec_grp_id_);
        }
      }

      return allow;
    }

    case RELIABLE_ARQ:
    default:
      // Retransmit.
      return true;
  }
}

//============================================================================
bool SentPktManager::GetFecEncPkt(const Time& now, CcId cc_id,
                                  SentPktQueue& fec_enc_q, DataHeader& hdr,
                                  Packet*& pkt)
{
  // Get the next FEC encoded data packet waiting in the queue.
  SentPktInfo&  fe_pkt_info = fec_enc_q.GetHead();

  // Make sure that the packet is an FEC encoded data packet.
  if ((!IS_FEC(fe_pkt_info)) || (fe_pkt_info.fec_pkt_type_ != FEC_ENC_PKT))
  {
    return false;
  }

  // Set the Packet object pointer.
  pkt = fe_pkt_info.packet_;

  // Populate the data header.
  hdr.enc_pkt_len_flag     = true;
  hdr.fec_flag             = true;
  hdr.move_fwd_flag        = false;
  hdr.persist_flag         = false;
  hdr.fin_flag             = false;
  hdr.stream_id            = stream_id_;
  hdr.num_ttg              = 0;
  hdr.cc_id                = cc_id;
  hdr.retransmission_count = 0;
  hdr.sequence_number      = snd_nxt_;
  hdr.timestamp            = 0;
  hdr.timestamp_delta      = 0;
  hdr.move_fwd_seq_num     = 0;

  hdr.fec_pkt_type       = FEC_ENC_PKT;
  hdr.fec_group_index    = fe_pkt_info.fec_grp_idx_;
  hdr.fec_num_src        = fe_pkt_info.fec_num_src_;
  hdr.fec_round          = GetRexmitFecRound(fe_pkt_info.fec_grp_id_);
  hdr.fec_group_id       = fe_pkt_info.fec_grp_id_;
  hdr.encoded_pkt_length = fe_pkt_info.fec_enc_pkt_len_;

  // Add any TTGs to the packet.
  AddPktTtgs(now, pkt, hdr);

  return true;
}

//============================================================================
void SentPktManager::MoveFecEncPkt(
  SentPktQueue& fec_enc_q, DataHeader& hdr, size_t bytes_sent,
  PktSeqNumber conn_seq, PktCount sent_pkt_cnt, const Time& xmit_time)
{
  PktSeqNumber  seq_num = hdr.sequence_number;
  CcId          cc_id   = hdr.cc_id;
  FecGroupId    fec_grp = hdr.fec_group_id;

  // This packet's sequence number should be snd_nxt_.
  if (seq_num != snd_nxt_)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Sent FEC encoded packet seq %" PRIPktSeqNumber " != snd_nxt_ %"
         PRIPktSeqNumber ".\n", conn_id_, stream_id_, seq_num, snd_nxt_);
    fec_enc_q.RemoveFromHead();
    return;
  }

  // There should be an FEC encoded data packet in the queue.
  if (fec_enc_q.GetCount() == 0)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": There are no FEC encoded packets in the queue.\n", conn_id_,
         stream_id_);
    return;
  }

  // Verify that the circular array size will not be exceeded.
  if ((seq_num - snd_fec_) >= kFlowCtrlWindowPkts)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Circular array size %" PRIPktSeqNumber " would exceed max %"
         PRIWindowSize ".\n", conn_id_, stream_id_,
         ((seq_num - snd_fec_) + 1), kFlowCtrlWindowPkts);
    fec_enc_q.RemoveFromHead();
    return;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Adding FEC packet, seq %" PRIPktSeqNumber " conn_seq %"
       PRIPktSeqNumber " cnt %" PRIPktCount " fec %d fin %d cc_id %" PRICcId
       " xmit_time %s bytes %zu.\n", conn_id_, stream_id_, seq_num,
       conn_seq, sent_pkt_cnt, static_cast<int>(hdr.fec_flag),
       static_cast<int>(hdr.fin_flag), cc_id, xmit_time.ToString().c_str(),
       bytes_sent);
#endif

  // Access the FEC encoded data packet queue element.
  SentPktInfo&  fe_pkt_info = fec_enc_q.GetHead();

  // Get the packet length, not including any headers.
  size_t  pkt_len = ((fe_pkt_info.packet_ != NULL) ?
                     fe_pkt_info.packet_->GetLengthInBytes() : 0);

  // Update congestion control.
  CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[cc_id].cc_alg;

  if (cc_alg == NULL)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": NULL congestion control object for cc_id %" PRICcId ".\n",
         conn_id_, stream_id_, cc_id);
    fec_enc_q.RemoveFromHead();
    return;
  }

  float         cc_val     = 0.0;
  PktSeqNumber  cc_seq_num = cc_alg->OnPacketSent(stream_id_, xmit_time,
                                                  seq_num, pkt_len,
                                                  bytes_sent, cc_val);

  // The packet has not been ACKed yet, is not considered lost yet, and has
  // not been retransmitted yet.  Update the counts appropriately.
  stats_bytes_in_flight_ += static_cast<ssize_t>(pkt_len);
  cc_alg->UpdateCounts(1, static_cast<ssize_t>(pkt_len),
                       static_cast<ssize_t>(pkt_len));

  // Access the send window element.
  SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

  // Move the FEC information from the FEC encoded data packet queue element
  // into the send window element.
  pkt_info.MoveFecInfo(fe_pkt_info);

  pkt_info.seq_num_           = seq_num;
  pkt_info.conn_seq_num_      = conn_seq;
  pkt_info.cc_seq_num_        = cc_seq_num;
  pkt_info.cc_val_            = cc_val;
  pkt_info.q_delay_usec_      = 0;
  pkt_info.rtt_usec_          = 0;
  pkt_info.xmit_time_         = xmit_time.ToTval();
  pkt_info.last_xmit_time_    = xmit_time.ToTval();
  pkt_info.pkt_len_           = static_cast<uint16_t>(pkt_len);
  pkt_info.bytes_sent_        = static_cast<uint16_t>(bytes_sent);
  pkt_info.rexmit_limit_      = rel_.rexmit_limit;
  pkt_info.rexmit_cnt_        = 0;
  pkt_info.cc_id_             = cc_id;
  pkt_info.sent_pkt_cnt_      = sent_pkt_cnt;
  pkt_info.prev_sent_pkt_cnt_ = 0;
  pkt_info.fec_ts_            = hdr.timestamp;

  // Update the packet send statistics.
  ++stats_pkts_.fec_enc_sent_;

  // Update the FEC group state.
  FecGroupInfo&  grp_info = fec_grp_info_[(fec_grp % kFecGroupSize)];

  if (grp_info.fec_grp_id_ == fec_grp)
  {
    // Set the FEC encoded packet's retransmission limit to that for the FEC
    // group.
    pkt_info.rexmit_limit_ = grp_info.fec_rexmit_limit_;

    // Update the encoded packet sent count for the FEC group's current round.
    ++grp_info.fec_enc_sent_icr_;

    // Update the FEC encoded packet sequence numbers in the FEC group.
    if (pkt_info.fec_grp_idx_ == grp_info.fec_num_src_)
    {
      grp_info.start_enc_seq_num_ = seq_num;
    }
    grp_info.end_enc_seq_num_ = seq_num;

    // Check if all of the transmissions are complete for the FEC group in the
    // current round.  If so, then set up watching the returned ACK packet
    // timestamps for the end of the round.
    if ((grp_info.fec_src_sent_icr_ >= grp_info.fec_src_to_send_icr_) &&
        (grp_info.fec_enc_sent_icr_ >= grp_info.fec_enc_to_send_icr_))
    {
      RecordEndOfFecRound(xmit_time, grp_info, hdr.timestamp);
    }
  }

  // Remove the FEC encoded packet information from the queue.
  fec_enc_q.RemoveFromHead();

  // Update the next sequence number.
  ++snd_nxt_;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Sent FEC enc pkt: seq %" PRIPktSeqNumber " rx %" PRIRetransCount
       " grp %" PRIFecGroupId " idx %" PRIFecSize " rnd %" PRIFecRound
       " num_ttg %" PRITtgCount " ttg %f %f %f %f %f %f %f %f %f %f.\n",
       conn_id_, stream_id_, seq_num, hdr.retransmission_count, fec_grp,
       hdr.fec_group_index, hdr.fec_round, hdr.num_ttg, hdr.ttg[0],
       hdr.ttg[1], hdr.ttg[2], hdr.ttg[3], hdr.ttg[4], hdr.ttg[5], hdr.ttg[6],
       hdr.ttg[7], hdr.ttg[8], hdr.ttg[9]);
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated send window, snd_fec_ %" PRIPktSeqNumber " snd_una_ %"
       PRIPktSeqNumber " snd_nxt_ %" PRIPktSeqNumber " fec_enc_orig_cnt_ %"
       PRIWindowSize ".\n", conn_id_, stream_id_, snd_fec_, snd_una_,
       snd_nxt_, fec_enc_orig_.GetCount());
#endif
}

//============================================================================
void SentPktManager::CleanUpOrigFecEncQueue()
{
  // Remove original FEC encoded data packets (unsent FEC encoded packets
  // generated in round 1) from the head of the original queue for various
  // reasons.
  while (fec_enc_orig_.GetCount() > 0)
  {
    SentPktInfo&   fe_pkt_info = fec_enc_orig_.GetHead();
    FecGroupInfo&  grp_info    = fec_grp_info_[(fe_pkt_info.fec_grp_id_ %
                                                kFecGroupSize)];

    // Eliminate non-FEC encoded packets.  This should not happen.
    if (IS_FEC(fe_pkt_info) && (fe_pkt_info.fec_pkt_type_ == FEC_ENC_PKT))
    {
      // Check if the FEC group information is still usable.
      if (grp_info.fec_grp_id_ == fe_pkt_info.fec_grp_id_)
      {
        // Check if all of the FEC source data packets in the FEC group have
        // been delivered.
        if ((grp_info.fec_round_ <= grp_info.fec_max_rounds_) &&
            (grp_info.fec_src_ack_cnt_ < grp_info.fec_num_src_))
        {
          // There are still FEC source data packets to be delivered, so
          // this FEC encoded data packet is still needed.
          return;
        }
        else
        {
#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": FEC encoded pkt idx %" PRIFecSize " not "
               "needed for completed grp %" PRIFecGroupId ".\n", conn_id_,
               stream_id_, fe_pkt_info.fec_grp_idx_, fe_pkt_info.fec_grp_id_);
#endif
        }
      }
      else
      {
        // It is unclear if this FEC data packet is really needed or not.
        // Log a warning and assume that it is still needed.
        LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Warning, missing FEC group info for grp %" PRIFecGroupId
             ", keep FEC encoded pkt idx %" PRIFecSize ".\n", conn_id_,
             stream_id_, fe_pkt_info.fec_grp_id_, fe_pkt_info.fec_grp_idx_);
        return;
      }
    }
    else
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, removing non-FEC encoded pkt grp %" PRIFecGroupId
           " idx %" PRIFecSize ".\n", conn_id_, stream_id_,
           fe_pkt_info.fec_grp_id_, fe_pkt_info.fec_grp_idx_);
    }

    // It is not necessary to send this FEC encoded data packet.  Update the
    // number of FEC encoded data packets sent in this FEC group (pretend that
    // it actually was sent) before recycling it.
    if ((grp_info.fec_grp_id_ == fe_pkt_info.fec_grp_id_) &&
        (grp_info.fec_round_ <= grp_info.fec_max_rounds_))
    {
      ++grp_info.fec_enc_sent_icr_;
    }

    fec_enc_orig_.RemoveFromHead();
  }
}

//============================================================================
void SentPktManager::CleanUpAddlFecEncQueue(PktSeqNumber seq_num)
{
  // Remove additional FEC encoded data packets (unsent FEC encoded packets
  // generated in round 2+) from the head of the additional queue for various
  // reasons.
  while (fec_enc_addl_.GetCount() > 0)
  {
    SentPktInfo&   fe_pkt_info = fec_enc_addl_.GetHead();
    FecGroupInfo&  grp_info    = fec_grp_info_[(fe_pkt_info.fec_grp_id_ %
                                                kFecGroupSize)];

    // Eliminate non-FEC encoded packets.  This should not happen.
    if (IS_FEC(fe_pkt_info) && (fe_pkt_info.fec_pkt_type_ == FEC_ENC_PKT))
    {
      // Eliminate additional FEC encoded packets with sequence numbers less
      // than seq_num.  This should not happen.
      if (SEQ_GEQ(fe_pkt_info.seq_num_, seq_num))
      {
        // Check if the FEC group information is still usable.
        if (grp_info.fec_grp_id_ == fe_pkt_info.fec_grp_id_)
        {
          // Check if all of the FEC source data packets in the FEC group have
          // been delivered.
          if ((grp_info.fec_round_ <= grp_info.fec_max_rounds_) &&
              (grp_info.fec_src_ack_cnt_ < grp_info.fec_num_src_))
          {
            // There are still FEC source data packets to be delivered, so
            // this FEC encoded data packet is still needed.
            return;
          }
          else
          {
#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
                 PRIStreamId ": FEC encoded pkt seq %" PRIPktSeqNumber " not "
                 "needed for completed grp %" PRIFecGroupId ".\n", conn_id_,
                 stream_id_, fe_pkt_info.seq_num_, fe_pkt_info.fec_grp_id_);
#endif
          }
        }
        else
        {
          // It is unclear if this FEC data packet is really needed or not.
          // Log a warning and assume that it is still needed.
          LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Warning, missing FEC group info for grp %"
               PRIFecGroupId ", keep FEC encoded pkt seq %" PRIPktSeqNumber
               ".\n", conn_id_, stream_id_, fe_pkt_info.fec_grp_id_,
               fe_pkt_info.seq_num_);
          return;
        }
      }
      else
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, removing stuck FEC encoded pkt seq %" PRIPktSeqNumber
             " when getting seq %" PRIPktSeqNumber ".\n", conn_id_,
             stream_id_, fe_pkt_info.seq_num_, seq_num);
      }
    }
    else
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, removing non-FEC encoded pkt seq %" PRIPktSeqNumber
           ".\n", conn_id_, stream_id_, fe_pkt_info.seq_num_);
    }

    // It is not necessary to send this FEC encoded data packet.  Update the
    // number of FEC encoded data packets sent in this FEC group (pretend that
    // it actually was sent) before recycling it.
    if ((grp_info.fec_grp_id_ == fe_pkt_info.fec_grp_id_) &&
        (grp_info.fec_round_ <= grp_info.fec_max_rounds_))
    {
      ++grp_info.fec_enc_sent_icr_;
    }

    fec_enc_addl_.RemoveFromHead();
  }
}

//============================================================================
void SentPktManager::EmptyFecEncodedPktQueues()
{
  while (fec_enc_orig_.GetCount() > 0)
  {
    fec_enc_orig_.RemoveFromHead();
  }

  while (fec_enc_addl_.GetCount() > 0)
  {
    fec_enc_addl_.RemoveFromHead();
  }
}

//============================================================================
void SentPktManager::DropPackets(const Time& now, bool leaving_outage)
{
  Time     rexmit_time = rtt_mgr_.GetRexmitTime();
  ssize_t  new_bif     = stats_bytes_in_flight_;

  // Reset the congestion control count adjustments before dropping packets.
  ResetCcCntAdjInfo();

  while (SEQ_LT(snd_una_, snd_nxt_))
  {
    SentPktInfo&  pkt_info = sent_pkts_[(snd_una_ % kFlowCtrlWindowPkts)];
    bool          drop_pkt = false;
    bool          is_acked = IS_ACKED(pkt_info);

    // Decide if this packet should be dropped or not.  Leaving an outage is a
    // special case.
    if (leaving_outage)
    {
      if (rel_.mode == SEMI_RELIABLE_ARQ)
      {
        // Drop any packets that have exceeded an estimated retransmission
        // time limit.  Packets with the FIN flag set can't be skipped.
        drop_pkt = ((now > (Time(pkt_info.xmit_time_) +
                            rexmit_time.Multiply(pkt_info.rexmit_limit_ + 1)))
                    && (!IS_FIN(pkt_info)));
      }
      else
      {
        // Drop all packets.  Packets with the FIN flag set can't be skipped.
        drop_pkt = (!IS_FIN(pkt_info));
      }
    }
    else
    {
      if (rel_.mode == SEMI_RELIABLE_ARQ)
      {
        // Drop any packets that have exceeded the standard delivery
        // retransmission limit.  Packets with the FIN flag set can't be
        // skipped.
        drop_pkt = ((pkt_info.rexmit_cnt_ >= pkt_info.rexmit_limit_) &&
                    (now > (Time(pkt_info.last_xmit_time_) + rexmit_time)) &&
                    (!IS_FIN(pkt_info)));
      }
      else if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
      {
        if (IS_FEC(pkt_info) && (pkt_info.fec_pkt_type_ == FEC_ENC_PKT))
        {
          // Drop all FEC encoded packets that are considered ACKed or lost.
          // This keeps FEC encoded packets around long enough for their
          // reception/loss status to update congestion control algorithms.
          // Packets with the FIN flag set can't be skipped.
          drop_pkt = ((IS_ACKED(pkt_info) || IS_LOST(pkt_info)) &&
                      (!IS_FIN(pkt_info)));
        }
        else
        {
          // Drop any non-FEC or FEC source packets that have exceeded the
          // standard delivery retransmission limit.  Packets with the FIN
          // flag set can't be skipped.
          drop_pkt = ((pkt_info.rexmit_cnt_ >= pkt_info.rexmit_limit_) &&
                      (now > (Time(pkt_info.last_xmit_time_) +
                              rexmit_time)) &&
                      (!IS_FIN(pkt_info)));
        }
      }
      else
      {
        // Drop any packets that are considered lost.  Packets with the FIN
        // flag set can't be skipped.
        drop_pkt = ((IS_LOST(pkt_info)) && (!IS_FIN(pkt_info)));
      }
    }

    // If the packet is either to be dropped or is ACKed, then the packet will
    // be dropped.  Otherwise, stop the search.
    if ((!drop_pkt) && (!is_acked))
    {
      break;
    }

    // Update the counts.
    if (!is_acked)
    {
      cc_cnt_adj_[pkt_info.cc_id_].updated_  = true;
      cc_cnt_adj_[pkt_info.cc_id_].pif_adj_ -= 1;
      cc_cnt_adj_[pkt_info.cc_id_].bif_adj_ -=
        static_cast<ssize_t>(pkt_info.pkt_len_);
      new_bif                             -=
        static_cast<ssize_t>(pkt_info.pkt_len_);
      if (!IS_LOST(pkt_info))
      {
        cc_cnt_adj_[pkt_info.cc_id_].pipe_adj_ -=
          static_cast<ssize_t>(pkt_info.pkt_len_);
      }
      if (pkt_info.rexmit_cnt_ > 0)
      {
        cc_cnt_adj_[pkt_info.cc_id_].pipe_adj_ -=
          static_cast<ssize_t>(pkt_info.pkt_len_);
      }
    }

#ifdef SLIQ_DEBUG
    if (!is_acked)
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Pkt seq %" PRIPktSeqNumber " being dropped.\n", conn_id_,
           stream_id_, snd_una_);
    }
    else
    {
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Pkt seq %" PRIPktSeqNumber " already ACKed, being dropped.\n",
           conn_id_, stream_id_, snd_una_);
    }
#endif

    // Drop the packet.
    if ((pkt_info.packet_ != NULL) &&
        ((!IS_FEC(pkt_info)) || (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)));
    {
      // Pass the packet drop information to the connection.  This will be
      // passed to the application.
      conn_.DropCallback(stream_id_, pkt_info.packet_);
    }

    if ((rel_.mode != SEMI_RELIABLE_ARQ_FEC) && (pkt_info.packet_ != NULL))
    {
      packet_pool_.Recycle(pkt_info.packet_);
      pkt_info.packet_ = NULL;
    }

    ++snd_una_;
  }

  // Update snd_fec_.
  if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    UpdateSndFec(leaving_outage);
  }
  else
  {
    snd_fec_ = snd_una_;
  }

  // The bytes in flight should never be less than 0.
  if (new_bif < 0)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Negative bytes in flight.\n", conn_id_, stream_id_);
  }

  // Update the counts.
  ReportCcCntAdjToCc();
  stats_bytes_in_flight_ = new_bif;
}

//============================================================================
void SentPktManager::ResetCcCntAdjInfo()
{
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    cc_cnt_adj_[i].updated_  = false;
    cc_cnt_adj_[i].pif_adj_  = 0;
    cc_cnt_adj_[i].bif_adj_  = 0;
    cc_cnt_adj_[i].pipe_adj_ = 0;
  }
}

//============================================================================
void SentPktManager::ReportCcCntAdjToCc()
{
  // Report only the updated count adjustments to the congestion control
  // algorithms.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    if (cc_cnt_adj_[i].updated_)
    {
      CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

      if (cc_alg == NULL)
      {
        LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": NULL congestion control object for cc_id %zu.\n", conn_id_,
             stream_id_, i);
      }
      else
      {
        cc_alg->UpdateCounts(cc_cnt_adj_[i].pif_adj_, cc_cnt_adj_[i].bif_adj_,
                             cc_cnt_adj_[i].pipe_adj_);
      }
    }
  }
}

//============================================================================
void SentPktManager::ReportUnaToCc()
{
  size_t  cnt = 0;

  // Reset the array of congestion control unacknowledged packet information.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    if (cc_algs_.cc_alg[i].use_una_pkt_reporting)
    {
      // To be reported.
      cc_una_pkt_[i].has_una_ = false;
    }
    else
    {
      // Not to be reported, so act like it has been found so it can be
      // skipped.
      cc_una_pkt_[i].has_una_ = true;
      ++cnt;
    }
  }

  // Walk the current window, from snd_una_ to snd_nxt_, noting the oldest
  // unacknowledged packet for each congestion control algorithm.  Stop early
  // if one has been found for each congestion control algorithm that needs
  // it.
  for (PktSeqNumber seq = snd_una_;
       (SEQ_LT(seq, snd_nxt_) && (cnt < cc_algs_.num_cc_alg)); ++seq)
  {
    SentPktInfo&   pkt_info = sent_pkts_[(seq % kFlowCtrlWindowPkts)];
    CcUnaPktInfo&  una_info = cc_una_pkt_[pkt_info.cc_id_];

    if ((!una_info.has_una_) && (!IS_ACKED(pkt_info)))
    {
      una_info.has_una_        = true;
      una_info.una_cc_seq_num_ = pkt_info.cc_seq_num_;
      ++cnt;
    }
  }

  // Report any updates to the congestion control algorithms.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CcUnaPktInfo&  una_info = cc_una_pkt_[i];

    // Check if a report is necessary.
    if (cc_algs_.cc_alg[i].use_una_pkt_reporting)
    {
      //             New false    New true
      //            +-----------+-----------------------+
      // Prev false | No report | Report                |
      //            +-----------+-----------------------+
      // Prev true  | Report    | Report if seq changed |
      //            +-----------+-----------------------+
      if (((una_info.has_una_) &&
           ((!una_info.prev_has_una_) ||
            (una_info.una_cc_seq_num_ != una_info.prev_una_cc_seq_num_))) ||
          ((!una_info.has_una_) && (una_info.prev_has_una_)))
      {
        CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

        if (cc_alg == NULL)
        {
          LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": NULL congestion control object for cc_id "
               "%zu.\n", conn_id_, stream_id_, i);
        }
        else
        {
          cc_alg->ReportUnaPkt(stream_id_, una_info.has_una_,
                               una_info.una_cc_seq_num_);
        }

        // Store the reported values.
        una_info.prev_has_una_        = una_info.has_una_;
        una_info.prev_una_cc_seq_num_ = una_info.una_cc_seq_num_;
      }
    }
  }
}

//============================================================================
void SentPktManager::AddPktTtgs(const Time& now, Packet* pkt, DataHeader& hdr)
{
  if (pkt == NULL)
  {
    // FIN packets may not have any payload Packet object.  They do not get
    // any TTG either, so do not log an error if this is a FIN packet.
    if (!hdr.fin_flag)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, missing Packet object for pkt seq %" PRIPktSeqNumber
           ".\n", conn_id_, stream_id_, hdr.sequence_number);
    }

    return;
  }

  double  orig_ttg  = 0.0;
  double  hold_time = 0.0;

  // Clear the number of TTGs in this packet.
  hdr.num_ttg = 0;

  // Check if this is a non-FEC packet.
  if (!hdr.fec_flag)
  {
    // If this is a latency-sensitive packet, then compute the packet's
    // current time-to-go (TTG) values.
    if (pkt->track_ttg())
    {
      orig_ttg  = pkt->GetTimeToGo().ToDouble();
      hold_time = (Time::Now() - pkt->recv_time()).ToDouble();

      hdr.num_ttg = 1;
      hdr.ttg[0]  = (orig_ttg - hold_time);

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Latency-sensitive seq %" PRIPktSeqNumber " old_ttg %f "
           "hold_time %f new_ttg %f\n", conn_id_, stream_id_,
           hdr.sequence_number, orig_ttg, hold_time, hdr.ttg[0]);
#endif
    }

    return;
  }

  // This is an FEC packet.  Look up the FEC group information.
  bool           is_ls    = false;
  FecGroupInfo&  grp_info = fec_grp_info_[(hdr.fec_group_id %
                                           kFecGroupSize)];

  // Only add TTGs for groups with latency-sensitive FEC source packets.  Note
  // that the first FEC source packet in each group will not have any FEC
  // group information yet.
  if (grp_info.fec_grp_id_ == hdr.fec_group_id)
  {
    is_ls = IS_LAT_SENS(grp_info);
  }
  else
  {
    is_ls = pkt->track_ttg();
  }

  if (!is_ls)
  {
    return;
  }

  // If this is an FEC source packet, then add its adjusted TTG value.
  if (hdr.fec_pkt_type == FEC_SRC_PKT)
  {
    orig_ttg  = pkt->GetTimeToGo().ToDouble();
    hold_time = (now - pkt->recv_time()).ToDouble();

    hdr.num_ttg = 1;
    hdr.ttg[0]  = (orig_ttg - hold_time);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Latency-sensitive FEC src seq %" PRIPktSeqNumber " old_ttg %f "
         "hold_time %f new_ttg %f\n", conn_id_, stream_id_,
         hdr.sequence_number, orig_ttg, hold_time, hdr.ttg[0]);
#endif

    return;
  }

  // From this point on, the FEC group information is required.
  if (grp_info.fec_grp_id_ != hdr.fec_group_id)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, FEC grp %" PRIFecGroupId " info not available for FEC pkt "
         "%" PRIPktSeqNumber " rexmit.\n", conn_id_, stream_id_,
         hdr.fec_group_id, hdr.sequence_number);
    return;
  }

  // This is an FEC encoded packet.  Add adjusted TTG values for all FEC
  // source packets in the group.
  for (PktSeqNumber seq_num = grp_info.start_src_seq_num_;
       (SEQ_LEQ(seq_num, grp_info.end_src_seq_num_) &&
        SEQ_LT(seq_num, snd_nxt_)); ++seq_num)
  {
    SentPktInfo&  spi = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

    if (IS_FEC(spi) && (spi.fec_grp_id_ == grp_info.fec_grp_id_) &&
        (spi.fec_pkt_type_ == FEC_SRC_PKT))
    {
      if (hdr.num_ttg >= kMaxTtgs)
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, too many packet TTGs for FEC grp %" PRIFecGroupId
             ".\n", conn_id_, stream_id_, hdr.fec_group_id);
        break;
      }

      Packet*  src_pkt = spi.packet_;

      if (src_pkt == NULL)
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC grp %" PRIFecGroupId " src pkt seq %"
             PRIPktSeqNumber " has no Packet object.\n", conn_id_, stream_id_,
             hdr.fec_group_id, seq_num);
        hdr.num_ttg = 0;
        break;
      }

      orig_ttg  = src_pkt->GetTimeToGo().ToDouble();
      hold_time = (now - src_pkt->recv_time()).ToDouble();

      hdr.ttg[hdr.num_ttg] = (orig_ttg - hold_time);
      ++hdr.num_ttg;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Latency-sensitive FEC src idx %" PRITtgCount " seq %"
           PRIPktSeqNumber " old_ttg %f hold_time %f new_ttg %f\n", conn_id_,
           stream_id_, (hdr.num_ttg - 1), seq_num, orig_ttg, hold_time,
           hdr.ttg[(hdr.num_ttg - 1)]);
#endif
    }
  }

  if (hdr.num_ttg != grp_info.fec_num_src_)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, not all src pkts found for FEC grp %" PRIFecGroupId ".\n",
         conn_id_, stream_id_, hdr.fec_group_id);
  }
}

//============================================================================
void SentPktManager::UpdateSndFec(bool force_fwd)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Start snd_fec_ %" PRIPktSeqNumber " snd_una_ %" PRIPktSeqNumber
       " delta %" PRIPktSeqNumber "\n", conn_id_, stream_id_, snd_fec_,
       snd_una_, (snd_una_ - snd_fec_));
#endif

  // Check the packet at snd_fec_ to see if the packet is still needed for
  // FEC.  If not, then move snd_fec_ forward.  Stop when either an FEC packet
  // is still needed or snd_una_ is reached.
  while (SEQ_LT(snd_fec_, snd_una_))
  {
    SentPktInfo&  pkt_info = sent_pkts_[(snd_fec_ % kFlowCtrlWindowPkts)];

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Check if snd_fec_ %" PRIPktSeqNumber " is needed.\n", conn_id_,
         stream_id_, snd_fec_);
#endif

    // When not forcing snd_fec_ forward, only FEC source data packets need to
    // be checked.
    if ((!force_fwd) && IS_FEC(pkt_info) &&
        (pkt_info.fec_pkt_type_ == FEC_SRC_PKT))
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Packet %" PRIPktSeqNumber " is FEC source packet.\n", conn_id_,
           stream_id_, snd_fec_);
#endif

      FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                               kFecGroupSize)];

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Packet %" PRIPktSeqNumber " is FEC packet for grp %"
           PRIFecGroupId " (grp %" PRIFecGroupId " in group info).\n",
           conn_id_, stream_id_, snd_fec_, pkt_info.fec_grp_id_,
           grp_info.fec_grp_id_);
#endif

      // If the FEC group information is still valid for the FEC data packet,
      // then check the FEC group further.  Otherwise, the FEC data packet is
      // no longer needed.
      if (grp_info.fec_grp_id_ == pkt_info.fec_grp_id_)
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
             PRIStreamId ": Check grp %" PRIFecGroupId " : src_ack %"
             PRIFecSize " k %" PRIFecSize " rexmit_cnt %" PRIRetransCount
             " rexmit_limit %" PRIRetransCount ".\n", conn_id_, stream_id_,
             grp_info.fec_grp_id_, grp_info.fec_src_ack_cnt_,
             grp_info.fec_num_src_, pkt_info.rexmit_cnt_,
             pkt_info.rexmit_limit_);
#endif

        // If the FEC group round is still within the target number of rounds
        // and not all of the FEC source data packets in the FEC group are
        // ACKed yet, then the FEC source data packet is still needed to
        // possibly generate FEC encoded data packets.  Note that it does not
        // matter if the FEC source data packet is ACKed or not.
        if ((grp_info.fec_round_ <= grp_info.fec_max_rounds_) &&
            (grp_info.fec_src_ack_cnt_ < grp_info.fec_num_src_))
        {
#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Packet %" PRIPktSeqNumber " still needed by "
               "FEC grp %" PRIFecGroupId " for now.\n", conn_id_, stream_id_,
               snd_fec_, grp_info.fec_grp_id_);
#endif

          break;
        }
      }
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Packet %" PRIPktSeqNumber " is no longer needed for FEC.\n",
         conn_id_, stream_id_, snd_fec_);
#endif

    // The packet at snd_fec_ is no longer needed.
    if (pkt_info.packet_ != NULL)
    {
      packet_pool_.Recycle(pkt_info.packet_);
      pkt_info.packet_ = NULL;
    }

    ++snd_fec_;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated snd_fec_ %" PRIPktSeqNumber " snd_una_ %" PRIPktSeqNumber
       " delta %" PRIPktSeqNumber "\n", conn_id_, stream_id_, snd_fec_,
       snd_una_, (snd_una_ - snd_fec_));
#endif
}

//============================================================================
void SentPktManager::RecordFecGroupPktAck(const Time& now,
                                          SentPktInfo& pkt_info)
{
  FecGroupInfo&  grp_info = fec_grp_info_[(pkt_info.fec_grp_id_ %
                                           kFecGroupSize)];

  if (grp_info.fec_grp_id_ != pkt_info.fec_grp_id_)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, FEC group info for grp %" PRIFecGroupId " not "
         "available.\n", conn_id_, stream_id_, pkt_info.fec_grp_id_);
    return;
  }

  // Check if this ACK is the first ACK received for the current group that is
  // not using pure ARQ and is still sending its source and encoded packets in
  // round 1.
  if ((!IS_PURE_ARQ(grp_info)) && (grp_info.fec_round_ == 1) &&
      ((grp_info.fec_src_sent_icr_ + grp_info.fec_enc_sent_icr_) <
       (grp_info.fec_num_src_ + grp_info.fec_num_enc_)) &&
      (grp_info.fec_src_ack_cnt_ == 0) && (grp_info.fec_enc_ack_cnt_ == 0))
  {
    // Compute the amount of time allowed for sending the source packets.
    SentPktInfo&  spi = sent_pkts_[(grp_info.start_src_seq_num_ %
                                    kFlowCtrlWindowPkts)];

    if ((spi.seq_num_ == grp_info.start_src_seq_num_) && IS_FEC(spi) &&
        (spi.fec_grp_id_ == grp_info.fec_grp_id_) &&
        (spi.fec_pkt_type_ == FEC_SRC_PKT))
    {
      double  ack_delta_sec = (now - Time(spi.xmit_time_)).ToDouble();
      double  src_delta_sec =
        (ack_delta_sec * static_cast<double>(grp_info.fec_num_src_) /
         static_cast<double>(grp_info.fec_num_src_ + grp_info.fec_num_enc_));

      if (src_delta_sec <= stats_fec_src_dur_sec_)
      {
        stats_fec_src_dur_sec_ = src_delta_sec;
      }
      else
      {
        stats_fec_src_dur_sec_ =
          ((kDurAlpha * src_delta_sec) +
           ((1.0 - kDurAlpha) * stats_fec_src_dur_sec_));
      }
    }

    // Update the dynamic source size state.
    if (fec_dss_next_num_src_ >= grp_info.fec_num_src_)
    {
      if (fec_dss_next_num_src_ > kMinK)
      {
        fec_dss_next_num_src_ -= 1;
      }

      fec_dss_ack_after_grp_cnt_ = 0;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Early ACK for grp %" PRIFecGroupId ", next_num_src %" PRIFecSize
           ".\n", conn_id_, stream_id_, grp_info.fec_grp_id_,
           fec_dss_next_num_src_);
#endif
    }
  }

  // Update the FEC group's packet counts based on the ACK.
  bool  updated_sent_icr = false;

  if (pkt_info.fec_pkt_type_ == FEC_SRC_PKT)
  {
    grp_info.fec_src_ack_cnt_ += 1;

    // If this packet is a fast retransmit candidate, then look closely at it
    // to see if it is being ACKed before it can be retransmitted.  If so,
    // then update the source packet sent count for the FEC group's current
    // round since it will not actually be sent.
    if (IS_CAND(pkt_info) && (grp_info.fec_round_ > 1) &&
        (grp_info.fec_round_ <= grp_info.fec_max_rounds_))
    {
      ++grp_info.fec_src_sent_icr_;
      updated_sent_icr = true;
    }
  }
  else
  {
    grp_info.fec_enc_ack_cnt_ += 1;

    // If this packet is a fast retransmit candidate, then look closely at it
    // to see if it is being ACKed before it can be retransmitted.  If so,
    // then update the source packet sent count for the FEC group's current
    // round since it will not actually be sent.
    if (IS_CAND(pkt_info) && (grp_info.fec_gen_enc_round_ > 0) &&
        (grp_info.fec_round_ > grp_info.fec_gen_enc_round_) &&
        (grp_info.fec_round_ <= grp_info.fec_max_rounds_))
    {
      ++grp_info.fec_enc_sent_icr_;
      updated_sent_icr = true;
    }
  }

  // If the number of packets sent in the current round was updated, then
  // check if all of the transmissions are complete for the FEC group in the
  // current round.  If so, then set up watching the returned ACK packet
  // timestamps for the end of the round.
  if (updated_sent_icr &&
      (grp_info.fec_src_sent_icr_ >= grp_info.fec_src_to_send_icr_) &&
      (grp_info.fec_enc_sent_icr_ >= grp_info.fec_enc_to_send_icr_))
  {
    PktTimestamp  ts = conn_.GetCurrentLocalTimestamp();

    RecordEndOfFecRound(now, grp_info, ts);
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Updated grp %" PRIFecGroupId " counts: src_ack %" PRIFecSize
       " enc_ack %" PRIFecSize " src_to_send %" PRIFecSize " enc_to_send %"
       PRIFecSize " src_sent %" PRIFecSize " enc_sent %" PRIFecSize ".\n",
       conn_id_, stream_id_, grp_info.fec_grp_id_, grp_info.fec_src_ack_cnt_,
       grp_info.fec_enc_ack_cnt_, grp_info.fec_src_to_send_icr_,
       grp_info.fec_enc_to_send_icr_, grp_info.fec_src_sent_icr_,
       grp_info.fec_enc_sent_icr_);
#endif
}

//============================================================================
bool SentPktManager::GenerateFecEncodedPkts(
  PktSeqNumber start_src_seq_num, PktSeqNumber end_src_seq_num,
  FecGroupId grp_id, FecSize n, FecSize k, FecSize enc_offset,
  FecSize enc_cnt, SentPktQueue& fec_enc_q, bool addl_flag)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Generate FEC encoded packets, start_src_seq %" PRIPktSeqNumber
       " end_src_seq %" PRIPktSeqNumber " grp %" PRIFecGroupId " coding (%"
       PRIFecSize ",%" PRIFecSize ") enc_offset %" PRIFecSize
       " enc_count %" PRIFecSize ".\n", conn_id_, stream_id_,
       start_src_seq_num, end_src_seq_num, grp_id, n, k, enc_offset, enc_cnt);
#endif

  // Validate the starting sequence number.
  if (SEQ_LT(start_src_seq_num, snd_fec_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, FEC grp %" PRIFecGroupId " start seq %" PRIPktSeqNumber
         " less than snd_fec_ %" PRIPktSeqNumber ".\n", conn_id_, stream_id_,
         grp_id, start_src_seq_num, snd_fec_);
    return false;
  }

  // Validate the encoded data packet offset and length.
  if ((enc_cnt == 0) || ((enc_offset + enc_cnt) > (n - k)))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, invalid offset %" PRIFecSize " count %" PRIFecSize
         " for (%" PRIFecSize ",%" PRIFecSize ") coding.\n", conn_id_,
         stream_id_, enc_offset, enc_cnt, n, k);
    return false;
  }

  // Check that the generated FEC encoded data packets will fit in the
  // specified FEC encoded data packet queue.
  if ((fec_enc_q.GetCount() + enc_cnt) > fec_enc_q.GetMaxSize())
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, %" PRIFecSize " FEC encoded packets will not fit in "
         "queue with %" PRIWindowSize " of %" PRIWindowSize " already "
         "used.\n", conn_id_, stream_id_, enc_cnt, fec_enc_q.GetCount(),
         fec_enc_q.GetMaxSize());
    return false;
  }

  // Clear the VDM encoder information.
  memset(&vdm_info_, 0, sizeof(vdm_info_));

  // Set the number of source and encoded data packets.  The number of encoded
  // data packets must be the total possible number, not enc_cnt.
  vdm_info_.num_src_pkt_ = k;
  vdm_info_.num_enc_pkt_ = (n - k);

  int           i       = 0;
  uint16_t      enc_len = 0;
  PktSeqNumber  seq_num = 0;

  // Prepare the FEC source data packet information.
  for (i = 0, seq_num = start_src_seq_num;
       ((i < vdm_info_.num_src_pkt_) && SEQ_LEQ(seq_num, end_src_seq_num) &&
        SEQ_LT(seq_num, snd_nxt_)); ++seq_num)
  {
    SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

    // If this is the FIN packet, then generation of FEC encoded data packets
    // can be skipped.
    if (IS_FIN(pkt_info))
    {
      return true;
    }

    // Check the FEC group ID.
    if (!IS_FEC(pkt_info) || (pkt_info.fec_grp_id_ != grp_id))
    {
      continue;
    }

    // Check the packet pointer.
    if (pkt_info.packet_ == NULL)
    {
      // Note that FIN packets may not have any payload, but a FIN check was
      // already done above, so this is not a FIN packet.
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, FEC source data packet seq %" PRIPktSeqNumber " for "
           "grp %" PRIFecGroupId " has NULL packet.\n", conn_id_, stream_id_,
           seq_num, grp_id);
      return false;
    }

    // Get the packet's length.
    size_t    mdata_len = pkt_info.packet_->GetMetadataHeaderLengthInBytes();
    size_t    data_len  = pkt_info.packet_->GetLengthInBytes();
    uint16_t  pkt_len   = static_cast<uint16_t>(mdata_len + data_len);

    // Copy the packet's sequence number to the end of the payload.  This is
    // used for encoding the sequence number into the FEC encoded data packets
    // since the position of the regenerated FEC source data packets will not
    // be known at the receiver.  It is not actually sent in the FEC source
    // data packet over the network.
    uint32_t  seq_num_nbo = htonl(seq_num);

    if ((data_len + sizeof(seq_num_nbo)) >
        pkt_info.packet_->GetMaxLengthInBytes())
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, FEC source data packet seq %" PRIPktSeqNumber " is too "
           "big to add sequence number.\n", conn_id_, stream_id_, seq_num);
      return false;
    }

    ::memcpy(reinterpret_cast<void*>(
               pkt_info.packet_->GetBuffer(data_len)),
             &seq_num_nbo, sizeof(seq_num_nbo));

    pkt_len += static_cast<uint16_t>(sizeof(seq_num_nbo));

    // Set the FEC source packet data and size.
    vdm_info_.src_pkt_data_[i] = pkt_info.packet_->GetMetadataHeaderBuffer();
    vdm_info_.src_pkt_size_[i] = pkt_len;

    if (pkt_len > enc_len)
    {
      enc_len = pkt_len;
    }

    // Move to the next FEC source packet index.
    ++i;
  }

  // Verify that all K FEC source data packets were found.
  if (i != vdm_info_.num_src_pkt_)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, only %d of %d FEC source data packets for grp %"
         PRIFecGroupId " were found.\n", conn_id_, stream_id_, i,
         vdm_info_.num_src_pkt_, grp_id);
    return false;
  }

  // Make sure encoded data packets are always an even number of bytes in
  // length.  This is required for the Vandermonde encoding to work right.
  if (enc_len & 0x1)
  {
    ++enc_len;
  }

  // Prepare the FEC encoded data packet information.
  FecSize     grp_idx     = (k + enc_offset);
  FecSize     enc_idx     = enc_offset;
  WindowSize  start_q_idx = fec_enc_q.GetCount();
  WindowSize  q_idx       = start_q_idx;

  for (i = 0; i < enc_cnt; ++i, ++grp_idx, ++enc_idx)
  {
    // Add a new entry at the tail of the queue, then get the new tail entry
    // to use.
    if (!fec_enc_q.AddToTail())
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error adding element to tail of FEC encoded packet queue.\n",
           conn_id_, stream_id_);
    }

    SentPktInfo&  fe_pkt_info = fec_enc_q.GetTail();

    // Get a new Packet object to use for the FEC encoded packet and set its
    // length.
    if (fe_pkt_info.packet_ != NULL)
    {
      packet_pool_.Recycle(fe_pkt_info.packet_);
    }

    fe_pkt_info.packet_ = packet_pool_.Get();

    if (fe_pkt_info.packet_ == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error getting packet from pool.\n", conn_id_, stream_id_);
    }

    fe_pkt_info.packet_->SetLengthInBytes(enc_len);

    // If these are additional FEC encoded packets (unsent FEC encoded packets
    // generated in round 2+), then add a temporary sequence number to the
    // packets in order to reference them in the stream's list of additional
    // and retransmission packets to be sent.
    if (addl_flag)
    {
      fe_pkt_info.seq_num_ = fec_enc_tmp_seq_num_;
      ++fec_enc_tmp_seq_num_;
    }

    // Initialize the FEC information for the FEC encoded packet.
    fe_pkt_info.pkt_len_      = enc_len;
    fe_pkt_info.bytes_sent_   = 0;
    fe_pkt_info.flags_        = 0;
    SET_FEC(fe_pkt_info);
    fe_pkt_info.fec_grp_id_   = grp_id;
    fe_pkt_info.fec_grp_idx_  = grp_idx;
    fe_pkt_info.fec_num_src_  = k;
    fe_pkt_info.fec_round_    = 0;
    fe_pkt_info.fec_pkt_type_ = static_cast<uint8_t>(FEC_ENC_PKT);
    fe_pkt_info.fec_ts_       = 0;

    vdm_info_.enc_pkt_data_[enc_idx] = fe_pkt_info.packet_->GetBuffer();
  }

  // Encode the packets.
  VdmFec::EncodePackets(vdm_info_.num_src_pkt_, vdm_info_.src_pkt_data_,
                        vdm_info_.src_pkt_size_, vdm_info_.num_enc_pkt_,
                        vdm_info_.enc_pkt_data_, vdm_info_.enc_pkt_size_);

  // Store the encoded data packet lengths for the generated FEC encoded data
  // packets.
  for (i = 0, enc_idx = enc_offset, q_idx = start_q_idx; i < enc_cnt;
       ++i, ++enc_idx, ++q_idx)
  {
    SentPktInfo&  fe_pkt_info = fec_enc_q.Get(q_idx);

    fe_pkt_info.fec_enc_pkt_len_ = vdm_info_.enc_pkt_size_[enc_idx];

    // If these are additional FEC encoded packets (unsent FEC encoded packets
    // generated in round 2+), then add the additional FEC encoded data
    // packet's temporary sequence number (assigned above) to the stream's
    // list of additional and retransmission packets to be sent.
    if (addl_flag)
    {
      if (stream_.AddAddlFecEncPkt(fe_pkt_info.seq_num_))
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Add FEC enc pkt seq %" PRIPktSeqNumber " to addl candidate "
             "list.\n", conn_id_, stream_id_, fe_pkt_info.seq_num_);
#endif
      }
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Generated FEC encoded packet len %" PRIu16 " for grp %"
         PRIFecGroupId " idx %d (cnt %" PRIWindowSize ").\n", conn_id_,
         stream_id_, fe_pkt_info.pkt_len_, grp_id,
         static_cast<int>(k + enc_offset + i), fec_enc_q.GetCount());
#endif
  }

  return true;
}

//============================================================================
FecRound SentPktManager::GetRexmitFecRound(FecGroupId grp_id)
{
  // Look up the FEC group information.
  FecGroupInfo&  grp_info = fec_grp_info_[(grp_id % kFecGroupSize)];

  if (grp_info.fec_grp_id_ != grp_id)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, FEC grp %" PRIFecGroupId " info not available for FEC pkt "
         "rexmit.\n", conn_id_, stream_id_, grp_id);

    return 0;
  }

  return grp_info.fec_round_;
}

//============================================================================
bool SentPktManager::PrepareNextFecRound(FecGroupInfo& grp_info)
{
  // Move to the next round.
  ++grp_info.fec_round_;

  // Reset the sent packet counts for the new round.
  grp_info.fec_src_sent_icr_ = 0;
  grp_info.fec_enc_sent_icr_ = 0;

  // Handle the case when there are no more rounds.
  if (grp_info.fec_round_ > grp_info.fec_max_rounds_)
  {
    // There are no more rounds, so set the round number to the special "out
    // of rounds" value.
    grp_info.fec_round_           = kOutOfRounds;
    grp_info.fec_src_to_send_icr_ = 0;
    grp_info.fec_enc_to_send_icr_ = 0;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": FEC grp %" PRIFecGroupId " out of rounds (%" PRIFecRound " > %"
         PRIFecRound ").\n", conn_id_, stream_id_, grp_info.fec_grp_id_,
         grp_info.fec_round_, grp_info.fec_max_rounds_);
#endif

    return false;
  }

  // Create local variables for the current group status.
  int32_t  num_src  = grp_info.fec_num_src_;
  int32_t  num_enc  = grp_info.fec_num_enc_;
  int32_t  src_rcvd = grp_info.fec_src_ack_cnt_;
  int32_t  enc_rcvd = grp_info.fec_enc_ack_cnt_;
  int32_t  src_lost = ((src_rcvd <= num_src) ? (num_src - src_rcvd) : 0);
  int32_t  enc_lost = ((enc_rcvd <= num_enc) ? (num_enc - enc_rcvd) : 0);

  // Determine the total number of packets to be sent.
  int32_t  total_to_send = 0;

  if (IS_PURE_ARQ(grp_info))
  {
    // Pure ARQ is in use.  Only send the necessary FEC source packets.
    total_to_send = src_lost;
  }
  else
  {
    // Use the correct FEC lookup table to determine the total number of
    // packets to be sent.
    size_t  idx = TableOffset(fec_per_idx_, grp_info.fec_num_src_,
                              grp_info.fec_src_ack_cnt_,
                              grp_info.fec_enc_ack_cnt_);

    if ((grp_info.fec_max_rounds_ >= kNumLookupTables) ||
        (fec_midgame_tables_[grp_info.fec_max_rounds_] == NULL) ||
        (fec_endgame_tables_[grp_info.fec_max_rounds_] == NULL))
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, missing FEC lookup tables for n %" PRIFecRound ".\n",
           conn_id_, stream_id_, grp_info.fec_max_rounds_);
    }

    if (grp_info.fec_round_ < grp_info.fec_max_rounds_)
    {
      // Not in the last round yet.  Use the midgame table.
      total_to_send = fec_midgame_tables_[grp_info.fec_max_rounds_][idx];
    }
    else
    {
      // In the last round now.  Use the endgame table.
      total_to_send = fec_endgame_tables_[grp_info.fec_max_rounds_][idx];
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": FEC grp %" PRIFecGroupId " round %" PRIFecRound " %sgame[%"
         PRIFecRound "][%zu][%" PRId32 "][%" PRId32 "][%" PRId32 "] = %"
         PRId32 "\n", conn_id_, stream_id_, grp_info.fec_grp_id_,
         grp_info.fec_round_,
         ((grp_info.fec_round_ < grp_info.fec_max_rounds_) ? "mid" : "end"),
         grp_info.fec_round_, fec_per_idx_, num_src, src_rcvd, enc_rcvd,
         total_to_send);
#endif
  }

  // Divide the total number of packets to send into the number of source and
  // encoded packets to generate/send/resend.
  int32_t  enc_to_gen = 0;
  int32_t  enc_to_rx  = 0;

  if (total_to_send <= src_lost)
  {
    grp_info.fec_src_to_send_icr_ = total_to_send;
    grp_info.fec_enc_to_send_icr_ = 0;
  }
  else
  {
    int32_t  enc_to_send = (total_to_send - src_lost);

    if (enc_to_send <= enc_lost)
    {
      enc_to_rx = enc_to_send;
    }
    else
    {
      enc_to_gen = (enc_to_send - enc_lost);
      enc_to_rx  = enc_lost;

      if ((num_src + num_enc + enc_to_gen) >
          static_cast<int32_t>(kMaxFecGroupLengthPkts))
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC grp %" PRIFecGroupId " cannot generate %" PRId32
             " enc pkts, will only generate %" PRId32 " enc pkts.\n",
             conn_id_, stream_id_, static_cast<int32_t>(num_enc + enc_to_gen),
             grp_info.fec_grp_id_, static_cast<int32_t>(kMaxFecGroupLengthPkts
                                                        - num_src));

        enc_to_gen  = static_cast<int32_t>(kMaxFecGroupLengthPkts - num_src -
                                           num_enc);
        enc_to_send = (enc_to_rx + enc_to_gen);
      }
    }

    grp_info.fec_src_to_send_icr_ = src_lost;
    grp_info.fec_enc_to_send_icr_ = enc_to_send;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": FEC grp %" PRIFecGroupId " round %" PRIFecRound " sending src %"
       PRIFecSize " enc %" PRIFecSize " (gen %" PRId32 " rx %" PRId32 ")\n",
       conn_id_, stream_id_, grp_info.fec_grp_id_, grp_info.fec_round_,
       grp_info.fec_src_to_send_icr_, grp_info.fec_enc_to_send_icr_,
       enc_to_gen, enc_to_rx);
#endif

  // Generate the necessary fast retransmit candidates for the new round.  FEC
  // source packets are only retransmitted starting in round 2.  FEC encoded
  // packets are only retransmitted starting in the round after the round in
  // which they were generated.
  bool  src_frc = ((grp_info.fec_src_to_send_icr_ > 0) &&
                   (grp_info.fec_round_ > 1));
  bool  enc_frc = ((enc_to_rx > 0) && (grp_info.fec_gen_enc_round_ > 0) &&
                   (grp_info.fec_round_ > grp_info.fec_gen_enc_round_));

  // Validate the needed starting sequence numbers.
  if (((src_frc) && (SEQ_LT(grp_info.start_src_seq_num_, snd_fec_))) ||
      ((enc_frc) && (SEQ_LT(grp_info.start_enc_seq_num_, snd_fec_))))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, FEC grp %" PRIFecGroupId " src seq %" PRIPktSeqNumber
         " or FEC enc seq %" PRIPktSeqNumber " less than snd_fec_ %"
         PRIPktSeqNumber ", ending rounds.\n", conn_id_, stream_id_,
         grp_info.fec_grp_id_, grp_info.start_src_seq_num_,
         grp_info.start_enc_seq_num_, snd_fec_);

    // End all rounds.  Set the round number to the special "out of rounds"
    // value.
    grp_info.fec_round_           = kOutOfRounds;
    grp_info.fec_src_to_send_icr_ = 0;
    grp_info.fec_enc_to_send_icr_ = 0;

    return false;
  }

  PktSeqNumber  seq_num  = 0;
  FecSize       cand_cnt = 0;

  // Generate all of the FEC source packet fast retransmit candidates.
  if (src_frc)
  {
    for (seq_num = grp_info.start_src_seq_num_, cand_cnt = 0;
         (SEQ_LEQ(seq_num, grp_info.end_src_seq_num_) &&
          SEQ_LT(seq_num, snd_nxt_) &&
          (cand_cnt < grp_info.fec_src_to_send_icr_)); ++seq_num)
    {
      SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

      if (IS_FEC(pkt_info) &&
          (pkt_info.fec_grp_id_ == grp_info.fec_grp_id_) &&
          (pkt_info.fec_pkt_type_ == FEC_SRC_PKT) && (!IS_ACKED(pkt_info)))
      {
        if (!IS_CAND(pkt_info))
        {
          if (stream_.AddFastRexmitPkt(seq_num))
          {
#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
                 PRIStreamId ": Add FEC src pkt seq %" PRIPktSeqNumber " to "
                 "fast rexmit candidate list.\n", conn_id_, stream_id_,
                 seq_num);
#endif

            SET_CAND(pkt_info);
            ++cand_cnt;
          }
        }
        else
        {
          LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Error, FEC grp %" PRIFecGroupId " src seq %"
               PRIPktSeqNumber " is already a rexmit candidate.\n", conn_id_,
               stream_id_, grp_info.fec_grp_id_, seq_num);
        }
      }
    }

    if (cand_cnt < grp_info.fec_src_to_send_icr_)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, FEC grp %" PRIFecGroupId " only generated %" PRIFecSize
           " out of %" PRIFecSize " FEC src rexmits.\n", conn_id_,
           stream_id_, grp_info.fec_grp_id_, cand_cnt,
           grp_info.fec_src_to_send_icr_);
      grp_info.fec_src_to_send_icr_ = cand_cnt;
    }
  }

  // Generate all of the FEC encoded packet fast retransmit candidates.
  if (enc_frc)
  {
    for (seq_num = grp_info.start_enc_seq_num_, cand_cnt = 0;
         (SEQ_LEQ(seq_num, grp_info.end_enc_seq_num_) &&
          SEQ_LT(seq_num, snd_nxt_) &&
          (cand_cnt < static_cast<FecSize>(enc_to_rx))); ++seq_num)
    {
      SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

      if (IS_FEC(pkt_info) &&
          (pkt_info.fec_grp_id_ == grp_info.fec_grp_id_) &&
          (pkt_info.fec_pkt_type_ == FEC_ENC_PKT) && (!IS_ACKED(pkt_info)))
      {
        if (!IS_CAND(pkt_info))
        {
          if (stream_.AddFastRexmitPkt(seq_num))
          {
#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
                 PRIStreamId ": Add FEC enc pkt seq %" PRIPktSeqNumber " to "
                 "fast rexmit candidate list.\n", conn_id_, stream_id_,
                 seq_num);
#endif

            SET_CAND(pkt_info);
            ++cand_cnt;
          }
        }
        else
        {
          LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Error, FEC grp %" PRIFecGroupId " enc seq %"
               PRIPktSeqNumber " is already a rexmit candidate.\n", conn_id_,
               stream_id_, grp_info.fec_grp_id_, seq_num);
        }
      }
    }

    if (cand_cnt < static_cast<FecSize>(enc_to_rx))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, FEC grp %" PRIFecGroupId " only generated %" PRIFecSize
           " out of %" PRId32 " FEC enc rexmits.\n", conn_id_,
           stream_id_, grp_info.fec_grp_id_, cand_cnt, enc_to_rx);
      grp_info.fec_enc_to_send_icr_ -= (static_cast<FecSize>(enc_to_rx) -
                                        cand_cnt);
    }
  }

  // Generate any needed FEC encoded packets now.
  if (grp_info.fec_round_ == 1)
  {
    // In round 1, simply record the number of FEC encoded packets to generate
    // later in AddSentPkt().
    grp_info.fec_num_enc_ = static_cast<FecSize>(enc_to_gen);
  }
  else if (enc_to_gen > 0)
  {
    if (!GenerateFecEncodedPkts(
          grp_info.start_src_seq_num_, grp_info.end_src_seq_num_,
          grp_info.fec_grp_id_, kMaxFecGroupLengthPkts, grp_info.fec_num_src_,
          grp_info.fec_num_enc_, enc_to_gen, fec_enc_addl_, true))
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Cannot continue without generation of FEC encoded packets.\n",
           conn_id_, stream_id_);
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Generated %" PRId32 " FEC encoded packets for grp %" PRIFecGroupId
         " in round %" PRIFecRound ".\n", conn_id_, stream_id_, enc_to_gen,
         grp_info.fec_grp_id_, grp_info.fec_round_);
#endif

    // Update the total number of FEC encoded packets generated thus far, and
    // record the round when the FEC encoded packets were first generated.
    grp_info.fec_num_enc_ += static_cast<FecSize>(enc_to_gen);

    if (grp_info.fec_gen_enc_round_ == 0)
    {
      grp_info.fec_gen_enc_round_ = grp_info.fec_round_;
    }
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": FEC grp %" PRIFecGroupId " starting round %" PRIFecRound " with "
       "src %" PRIFecSize " enc %" PRIFecSize ": src_ack %" PRIFecSize
       " enc_ack %" PRIFecSize " src_to_send %" PRIFecSize " enc_to_send %"
       PRIFecSize ".\n", conn_id_, stream_id_, grp_info.fec_grp_id_,
       grp_info.fec_round_, grp_info.fec_num_src_, grp_info.fec_num_enc_,
       grp_info.fec_src_ack_cnt_, grp_info.fec_enc_ack_cnt_,
       grp_info.fec_src_to_send_icr_, grp_info.fec_enc_to_send_icr_);
#endif

  return true;
}

//============================================================================
void SentPktManager::RecordEndOfFecRound(const Time& now,
                                         FecGroupInfo& grp_info,
                                         PktTimestamp ts)
{
  // Make sure that the circular array size is not exceeded.
  if (fec_eor_cnt_ >= kFecGroupSize)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Out of FEC end of round entries, cannot continue.\n", conn_id_,
         stream_id_);
  }

  // Add an entry at the tail of the list for the group's end of round
  // information.
  WindowSize        idx      = ((fec_eor_idx_ + fec_eor_cnt_) %
                                kFecGroupSize);
  FecEndOfRndInfo&  rnd_info = fec_eor_[idx];

  rnd_info.pkt_ts_       = ts;
  rnd_info.obs_pkt_bvec_ = 0;
  rnd_info.fec_grp_id_   = grp_info.fec_grp_id_;

  ++fec_eor_cnt_;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Added end of round info: grp %" PRIFecGroupId " ts %"
       PRIPktTimestamp "\n", conn_id_, stream_id_, grp_info.fec_grp_id_, ts);
#endif

  // Check if no ACKs have been received for the current group that is done
  // sending its source and encoded packets in round 1.
  if ((!IS_PURE_ARQ(grp_info)) && (grp_info.fec_round_ == 1) &&
      (grp_info.fec_src_ack_cnt_ == 0) && (grp_info.fec_enc_ack_cnt_ == 0))
  {
    // Update the dynamic source size state.
    fec_dss_ack_after_grp_cnt_ += 1;

    if (fec_dss_ack_after_grp_cnt_ >= kFecAckAfterGrpCnt)
    {
      if (fec_dss_next_num_src_ < kMaxK)
      {
        fec_dss_next_num_src_ += 1;
      }

      fec_dss_ack_after_grp_cnt_ = 0;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": No ACK for grp %" PRIFecGroupId ", next_num_src %" PRIFecSize
         ".\n", conn_id_, stream_id_, grp_info.fec_grp_id_,
         fec_dss_next_num_src_);
#endif

    // Update the packet inter-send time.
    FecSize  pkts = (grp_info.fec_num_src_ + grp_info.fec_num_enc_);

    if ((pkts > 1) && (!IS_FORCE_END(grp_info)))
    {
      SentPktInfo&  spi = sent_pkts_[(grp_info.start_src_seq_num_ %
                                      kFlowCtrlWindowPkts)];

      if ((spi.seq_num_ == grp_info.start_src_seq_num_) && IS_FEC(spi) &&
          (spi.fec_grp_id_ == grp_info.fec_grp_id_) &&
          (spi.fec_pkt_type_ == FEC_SRC_PKT))
      {
        double  tot = (now - Time(spi.xmit_time_)).ToDouble();
        double  ips = (tot / static_cast<double>(pkts - 1));

        if (stats_pkt_ist_ < 0.0)
        {
          stats_pkt_ist_ = ips;
        }
        else
        {
          stats_pkt_ist_ = ((0.05 * ips) + (0.95 * stats_pkt_ist_));
        }
      }
    }
  }
}

//============================================================================
void SentPktManager::ProcessEndOfFecRounds(PktSeqNumber seq_num,
                                           PktTimestamp obs_ts)
{
  bool  good_snd_ts = true;

  // Get the necessary information for the observed packet and its group.
  SentPktInfo&  pkt_info = sent_pkts_[(seq_num % kFlowCtrlWindowPkts)];

  // Check the packet information entry.
  if ((pkt_info.seq_num_ != seq_num) || (!IS_FEC(pkt_info)))
  {
    good_snd_ts = false;
  }

  FecGroupId    grp_id  = pkt_info.fec_grp_id_;
  FecSize       grp_idx = pkt_info.fec_grp_idx_;
  PktTimestamp  snd_ts  = pkt_info.fec_ts_;

  // The send timestamp must be less than or equal to the observed packet
  // timestamp, or else this observed timestamp does not match the last
  // transmission of this packet and the send timestamp is not usable here.
  if (good_snd_ts && TS_GT(snd_ts, obs_ts))
  {
    good_snd_ts = false;
  }

  // Loop over the end of round entries starting at the head of the list.
  while (fec_eor_cnt_ > 0)
  {
    FecEndOfRndInfo&  rnd_info = fec_eor_[fec_eor_idx_];

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Checking grp %" PRIFecGroupId " idx %" PRIFecSize " seq %"
         PRIPktSeqNumber " snd_ts %" PRIPktTimestamp " obs_ts %"
         PRIPktTimestamp " against end-of-round grp %" PRIFecGroupId " bvec %"
         PRIFecGroupBitVec " ts %" PRIPktTimestamp ".\n", conn_id_,
         stream_id_, grp_id, grp_idx, seq_num, snd_ts, obs_ts,
         rnd_info.fec_grp_id_, rnd_info.obs_pkt_bvec_, rnd_info.pkt_ts_);
#endif

    // See if the appropriate timestamp is later than the recorded end of
    // round timestamp.  If so, then the end of round has been reached.
    bool  eor_reached = false;

    if ((grp_id == rnd_info.fec_grp_id_) &&
        ((rnd_info.obs_pkt_bvec_ &
          (static_cast<FecGroupBitVec>(1) << grp_idx)) != 0))
    {
      // The observed packet timestamp is from a duplicate ACK.  Compare the
      // received timestamp with an adjusted end of round timestamp (to
      // account for receiver processing time).
      eor_reached = TS_GEQ(obs_ts, (rnd_info.pkt_ts_ + kFecEorTsDelta));
    }
    else
    {
      // The observed packet timestamp is not from a duplicate ACK.  If the
      // send timestamp is usable here, then compare the sent timestamp with
      // the recorded end of round timestamp.
      if (good_snd_ts)
      {
        eor_reached = TS_GEQ(snd_ts, rnd_info.pkt_ts_);
      }
    }

    // If this is the matching group and this packet was sent in this round
    // (i.e. the send timestamp is good), then set a bit for the received
    // observed packet in the group's bit vector.
    if (good_snd_ts && (grp_id == rnd_info.fec_grp_id_))
    {
      rnd_info.obs_pkt_bvec_ |= (static_cast<FecGroupBitVec>(1) << grp_idx);
    }

    if (eor_reached)
    {
      // This is the end of a round for the FEC group.
      FecGroupInfo&  grp_info = fec_grp_info_[(rnd_info.fec_grp_id_ %
                                               kFecGroupSize)];

      if (grp_info.fec_grp_id_ == rnd_info.fec_grp_id_)
      {
        // If enough of the FEC source and encoded packets in the FEC group
        // have been ACKed, then processing for the FEC group is over.
        if ((grp_info.fec_src_ack_cnt_ + grp_info.fec_enc_ack_cnt_) >=
            grp_info.fec_num_src_)
        {
          // Set the round number to the special "out of rounds" value.
          grp_info.fec_round_ = kOutOfRounds;

#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": FEC grp %" PRIFecGroupId " done.\n", conn_id_,
               stream_id_, rnd_info.fec_grp_id_);
#endif
        }
        else
        {
          // Prepare what packets should be sent in the next round using the
          // FEC lookup tables, if another round is allowed.  This will
          // increment the current round.
          if (PrepareNextFecRound(grp_info))
          {
#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
                 PRIStreamId ": FEC grp %" PRIFecGroupId " starting round %"
                 PRIFecRound ".\n", conn_id_, stream_id_,
                 grp_info.fec_grp_id_, grp_info.fec_round_);
#endif
          }
          else
          {
            // The FEC group is out of rounds.  Allow retransmissions up to
            // the retransmission limit to at least get the FEC source packets
            // delivered late if possible.  No changes are needed to enable
            // this to happen.

#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
                 PRIStreamId ": FEC grp %" PRIFecGroupId " out of rounds.\n",
                 conn_id_, stream_id_, grp_info.fec_grp_id_);
#endif
          }
        }
      }
      else
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error, FEC group info for grp %" PRIFecGroupId " not "
             "available.\n", conn_id_, stream_id_, rnd_info.fec_grp_id_);
      }

      // Remove the entry from the head of the list.
      fec_eor_idx_ = ((fec_eor_idx_ + 1) % kFecGroupSize);
      --fec_eor_cnt_;
    }
    else
    {
      // Since the entries are in chronological order, as soon as the
      // specified timestamp is not late enough, the search is complete.
      break;
    }
  }
}

//============================================================================
void SentPktManager::StartNextFecGroup()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": End of FEC grp %" PRIFecGroupId " start of FEC grp %" PRIFecGroupId
       " \n", conn_id_, stream_id_, fec_grp_id_, (fec_grp_id_ + 1));
#endif

  // Move to the next FEC group.
  fec_grp_idx_ = 0;
  ++fec_grp_id_;
}

//============================================================================
bool SentPktManager::CreateFecTables()
{
  // Allocate only the necessary FEC lookup tables.
  FecRound  min_n = (rel_.fec_del_time_flag ? kMinN : fec_target_rounds_);
  FecRound  max_n = (rel_.fec_del_time_flag ? kMaxN : fec_target_rounds_);

  for (FecRound n = min_n; n <= max_n; ++n)
  {
    if (!AllocateFecTables(n))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error allocating FEC lookup tables at N=%" PRIFecRound ".\n",
           conn_id_, stream_id_, n);
      return false;
    }
  }

  // Get the value of Epsilon to use in the tables.
  fec_epsilon_idx_ = 0;

  for (ssize_t i = (kNumEps - 1); i >= 0; --i)
  {
    if (rel_.fec_target_pkt_recv_prob <= (1.0 - kEpsilon[i]))
    {
      fec_epsilon_idx_ = i;
      break;
    }
  }

  double  eps = kEpsilon[fec_epsilon_idx_];

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId ": "
       "Map epsilon from %f to %f (index %zu) for use in lookup tables.\n",
       conn_id_, stream_id_, (1.0 - rel_.fec_target_pkt_recv_prob), eps,
       fec_epsilon_idx_);
#endif

  // Set the lookup tables.  Loop over all target number of rounds (N) values.
  for (FecRound n = kMinN; n <= kMaxN; ++n)
  {
    // Only populate the tables if they are allocated.
    if ((fec_midgame_tables_[n] == NULL) || (fec_endgame_tables_[n] == NULL))
    {
      continue;
    }

    // Loop over all PER (p) values.
    for (size_t per_idx = 0; per_idx < kNumPers; ++per_idx)
    {
      double  per = kPerVals[per_idx];

      // Determine how many rounds would be needed for pure ARQ.  Given that
      // per can be a maximum of 0.5 and eps can be a minimum of 0.001,
      // arq_cutover cannot be larger than 10.
      FecRound  arq_cutover = 1;
      double    test_p_loss = per;

      while (test_p_loss > eps)
      {
        test_p_loss *= per;
        ++arq_cutover;
      }

      if (n >= arq_cutover)
      {
        // Use pure ARQ.
        for (FecSize k = kMinK; k <= kMaxK; ++k)
        {
          for (FecSize sr = 0; sr < k; ++sr)
          {
            for (FecSize cr = 0; cr < (k - sr); ++cr)
            {
              size_t  idx = TableOffset(per_idx, k, sr, cr);

              fec_midgame_tables_[n][idx] = (uint8_t)(k - sr);
              fec_endgame_tables_[n][idx] = (uint8_t)(k - sr);
            }
          }
        }
      }
      else
      {
        for (FecSize k = kMinK; k <= kMaxK; ++k)
        {
          // Lookup the midgame probability of packet receive given the
          // current values.
          double  midgame_p_recv =
            kMidgameParms[k - 1][per_idx][n - 1][fec_epsilon_idx_];

          // A midgame_p_recv value of 0.0 signals that we should use an
          // ARQ-like midgame lookup table.
          if (midgame_p_recv < 0.001)
          {
            for (FecSize sr = 0; sr < k; ++sr)
            {
              for (FecSize cr = 0; cr < (k - sr); ++cr)
              {
                size_t  idx = TableOffset(per_idx, k, sr, cr);

                fec_midgame_tables_[n][idx] = (k - sr);
              }
            }
          }
          else
          {
            for (FecSize sr = 0; sr < k; ++sr)
            {
              for (FecSize cr = 0; cr < (k - sr); ++cr)
              {
                size_t  idx = TableOffset(per_idx, k, sr, cr);

                CalculateConditionalSimpleFecDofToSend(
                  kMaxFecGroupLengthPkts, per, midgame_p_recv, k, sr, cr,
                  fec_midgame_tables_[n][idx]);
              }
            }
          }

          // Lookup the endgame probability of packet receive given the
          // current values.
          double  endgame_p_recv =
            kEndgameParms[k - 1][per_idx][n - 1][fec_epsilon_idx_];

          for (FecSize sr = 0; sr < k; ++sr)
          {
            for (FecSize cr = 0; cr < (k - sr); ++cr)
            {
              size_t  idx = TableOffset(per_idx, k, sr, cr);

              CalculateConditionalSystematicFecDofToSend(
                kMaxFecGroupLengthPkts, per, endgame_p_recv, k, sr, cr,
                fec_endgame_tables_[n][idx]);
            }
          }
        } // end k loop
      } // end if pure ARQ
    } // end per_idx loop
  } // end n loop

  return true;
}

//============================================================================
bool SentPktManager::AllocateFecTables(FecRound n)
{
  // Allocate the midgame and endgame FEC lookup tables for the specified
  // target number of rounds.
  fec_midgame_tables_[n] = new (std::nothrow) uint8_t[kFecTableSize];
  fec_endgame_tables_[n] = new (std::nothrow) uint8_t[kFecTableSize];

  if ((fec_midgame_tables_[n] == NULL) || (fec_endgame_tables_[n] == NULL))
  {
    return false;
  }

  memset(fec_midgame_tables_[n], 0, (kFecTableSize * sizeof(uint8_t)));
  memset(fec_endgame_tables_[n], 0, (kFecTableSize * sizeof(uint8_t)));

  return true;
}

//============================================================================
bool SentPktManager::UpdateFecTableParams()
{
  // Get the latest PER estimate (p) for the connection and map it into a PER
  // index for the FEC lookup tables.  These are stored in fec_per_ and
  // fec_per_idx_.
  double  new_per = conn_.StatsGetLocalPer();

  if (new_per != fec_per_)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Old PER %f new PER %f sRTT %f\n", conn_id_, stream_id_, fec_per_,
         new_per, rtt_mgr_.smoothed_rtt().ToDouble());
#endif

    fec_per_     = new_per;
    fec_per_idx_ = (kNumPers - 1);

    for (size_t i = 0; i < kNumPers; ++i)
    {
      if (kPerVals[i] >= new_per)
      {
        fec_per_idx_ = i;
        break;
      }
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Map PER from %f to %f (index %zu) for use in lookup tables.\n",
         conn_id_, stream_id_, new_per, kPerVals[fec_per_idx_], fec_per_idx_);
#endif
  }

  // If the target number of rounds (N) is fixed, then fec_target_rounds_ is
  // already set correctly and there is nothing else to do here.  The number
  // of source packets per group (k) will be completely controlled by
  // fec_dss_next_num_src_ in this case.  The use of Pure ARQ depends on the
  // FEC lookup table results, and is not guaranteed.
  if (!rel_.fec_del_time_flag)
  {
    return false;
  }

  // The target number of rounds (N) is controlled by the specified packet
  // delivery time limit and the current RTT and OWD estimates.  Find the
  // target number of rounds that will meet the specified packet delivery time
  // limit.  There are three different scenarios that must be tested in order
  // to find N.

  // First, check if pure ARQ can be used with just a single round.  This is a
  // very easy test.  Use the exact target packet receive probability and the
  // exact PER estimate.
  if ((fec_per_ <= 0.000001) ||
      ((1.0 - fec_per_) >= rel_.fec_target_pkt_recv_prob))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Pure ARQ will work, set N to 1, k to 1.\n", conn_id_, stream_id_);
#endif

    // Update the target number of rounds (N) to one, and the number of source
    // packets per group (k) to 1 using the returned pure ARQ flag.
    fec_target_rounds_         = 1;
    fec_dss_ack_after_grp_cnt_ = 0;

    ++stats_pkts_.fec_grp_pure_arq_1_;

    return true;
  }

  // Second, determine how many rounds would be needed if pure ARQ is used.
  // This requires a loop.  Again, use the exact target packet receive
  // probability and the exact PER estimate.  Limit arq_cutover to the maximum
  // supported number of rounds for each FEC group (determined by the size of
  // the 4-bit round field in the Data Header, and the round value 15 reserved
  // for the "out of rounds" value).
  bool    valid_result = true;
  size_t  arq_cutover  = 1;
  double  test_eps     = (1.0 - rel_.fec_target_pkt_recv_prob);
  double  test_p_loss  = fec_per_;

  while (test_p_loss > test_eps)
  {
    test_p_loss *= fec_per_;
    ++arq_cutover;

    if (arq_cutover >= kOutOfRounds)
    {
      valid_result = false;
      break;
    }
  }

  // Get the maximum RTT estimate and the maximum local-to-remote one-way
  // delay estimate.  These will be needed to make packet delivery time
  // estimates.
  double  max_rtt_sec     = rtt_mgr_.maximum_rtt().ToDouble();
  double  max_ltr_owd_sec = conn_.GetMaxLtrOwdEst().ToDouble();

  if (max_ltr_owd_sec <= 0.0)
  {
    LogA(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Max OWD not available, using %f\n", conn_id_, stream_id_,
         (0.5 * max_rtt_sec));
    max_ltr_owd_sec = (0.5 * max_rtt_sec);
  }

  // Only continue checking the pure ARQ case if the ARQ cutover value is
  // valid.
  if (valid_result)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": ARQ cutover occurs at %zu rounds.\n", conn_id_, stream_id_,
         arq_cutover);
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Pure ARQ test, target %f arq_cutover %zu rtt %f owd %f.\n",
         conn_id_, stream_id_, rel_.fec_target_pkt_del_time_sec, arq_cutover,
         max_rtt_sec, max_ltr_owd_sec);
#endif

    // Pure ARQ can be used if there should be enough time to meet the packet
    // delivery deadline time.
    if (rel_.fec_target_pkt_del_time_sec >
        (((static_cast<double>(arq_cutover) - 1.0) * max_rtt_sec) +
         max_ltr_owd_sec))
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Pure ARQ will work, update N from %" PRIFecRound " to %zu, k "
           "to 1.\n", conn_id_, stream_id_, fec_target_rounds_, arq_cutover);
#endif

      // Update the target number of rounds (N) to the pure ARQ cutover number
      // of rounds, and the number of source packets per group (k) to 1 using
      // the returned pure ARQ flag.
      fec_target_rounds_         = arq_cutover;
      fec_dss_ack_after_grp_cnt_ = 0;

      ++stats_pkts_.fec_grp_pure_arq_2p_;

      return true;
    }
  }

  // Third, check if pure FEC (N=1) or coded ARQ (N>1) can be used.  The test
  // requires the maximum packet serialization time, which is computed using
  // the maximum packet size and the current connection send rate estimate.
  double  max_pst_sec   = 0.0;
  double  send_rate_bps = conn_.StatsGetSendRate();

  if (send_rate_bps > 0.0)
  {
    max_pst_sec = ((static_cast<double>(kPktOverheadBytes + kMaxPacketSize) *
                    8.0) / send_rate_bps);
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Pure FEC/Coded ARQ test, target %f rtt %f owd %f PER %f rate %f "
       "pst %f.\n", conn_id_, stream_id_, rel_.fec_target_pkt_del_time_sec,
       max_rtt_sec, max_ltr_owd_sec, kPerVals[fec_per_idx_], send_rate_bps,
       max_pst_sec);
#endif

  // Find the target number of rounds (N) and number of source packets per
  // group (k) that maximizes efficiency while keeping the total worst case
  // delay within the packet delivery time limit.
  FecRound  opt_n   = 0;
  FecSize   opt_k   = 0;
  uint8_t   opt_eff = 0;

  for (FecRound n = kMinN; n <= kMaxN; ++n)
  {
    // Make sure the needed tables have been allocated.
    if ((fec_midgame_tables_[n] == NULL) ||
        (fec_endgame_tables_[n] == NULL))
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, missing FEC lookup tables for n %" PRIFecRound ".\n",
           conn_id_, stream_id_, n);
      continue;
    }

    for (FecSize k = kMinK; k <= kMaxK; ++k)
    {
      // Compute the total worst-case delay.
      size_t  idx        = TableOffset(fec_per_idx_, k, 0, 0);
      double  mg_max_dof = fec_midgame_tables_[n][idx];
      double  eg_max_dof = fec_endgame_tables_[n][idx];
      double  twc_delay  =
        (((n - 1) * (((mg_max_dof + 1.0) * max_pst_sec) + max_rtt_sec)) +
         ((eg_max_dof * max_pst_sec) + max_ltr_owd_sec));

      if (twc_delay <= rel_.fec_target_pkt_del_time_sec)
      {
        uint8_t  eff =
          kEfficiency[fec_epsilon_idx_][fec_per_idx_][n - 1][k - 1];

        if (eff > opt_eff)
        {
          opt_n   = n;
          opt_k   = k;
          opt_eff = eff;

#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %"
               PRIStreamId ": Pure FEC/Coded ARQ candidate, eps=%f (idx %zu) "
               "per=%f (idx %zu) N=%" PRIFecRound " k=%" PRIFecSize " eff=%"
               PRIu8 " (%f) twcd %f target %f\n", conn_id_, stream_id_,
               kEpsilon[fec_epsilon_idx_], fec_epsilon_idx_,
               kPerVals[fec_per_idx_], fec_per_idx_, n, k, eff,
               (static_cast<double>(eff) / 255.0), twc_delay,
               rel_.fec_target_pkt_del_time_sec);
#endif
        }
      }
    }
  }

  // If there were no candidates found, then pure FEC (N=1) must be used with
  // one source packets per group (k=1).
  if (opt_n == 0)
  {
    opt_n = 1;
    opt_k = 1;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": No candidates found, using pure FEC (N=1 k=1).\n", conn_id_,
         stream_id_);
#endif
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": %s will work, update N from %" PRIFecRound " to %" PRIFecRound
       ", k from %" PRIFecSize " to %" PRIFecSize " (%s).\n", conn_id_,
       stream_id_, ((opt_n == 1) ? "Pure FEC" : "Coded ARQ"),
       fec_target_rounds_, opt_n, fec_dss_next_num_src_, opt_k,
       ((opt_k <= fec_dss_next_num_src_) ? "yes" : "no"));
#endif

  if (opt_n == 1)
  {
    ++stats_pkts_.fec_grp_pure_fec_;
  }
  else
  {
    ++stats_pkts_.fec_grp_coded_arq_;
  }

  // Update the target number of rounds (N).
  fec_target_rounds_ = opt_n;

  // Update the number of source packets per group (k).  Make sure that the
  // fec_dss_next_num_src_ value does not go up.
  if (opt_k <= fec_dss_next_num_src_)
  {
    fec_dss_next_num_src_      = opt_k;
    fec_dss_ack_after_grp_cnt_ = 0;
  }

  return false;
}

//============================================================================
size_t SentPktManager::TableOffset(size_t per_idx, FecSize k, FecSize sr,
                                   FecSize cr)
{
  static size_t  k_offset[11] = { 0, 0, 1, 4, 10, 20, 35, 56, 84, 120, 165 };
  static size_t  sr_corr[10]  = { 0, 0, 1, 3, 6, 10, 15, 21, 28, 36 };

  // Validate the parameters.
  if ((per_idx >= kNumPers) || (k < kMinK) || (k > kMaxK) || (sr >= k) ||
      (cr >= k) || ((sr + cr) >= k))
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Invalid FEC table index, per_idx=%zu k=%" PRIFecSize " sr=%"
         PRIFecSize " cr=%" PRIFecSize ".\n", conn_id_, stream_id_, per_idx,
         k, sr, cr);
    return 0;
  }

  // Compute the offset into the array of elements.
  size_t  offset = ((per_idx * kFecTriTableSize) + k_offset[k] +
                    (static_cast<size_t>(sr) * static_cast<size_t>(k)) -
                    sr_corr[sr] + static_cast<size_t>(cr));

  if (offset >= kFecTableSize)
  {
    LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Invalid result, table[%zu][%" PRIFecSize "][%" PRIFecSize "][%"
         PRIFecSize "] offset=%zu.\n", conn_id_, stream_id_, per_idx, k, sr,
         cr, offset);
    return 0;
  }

  return offset;
}

//============================================================================
double SentPktManager::CalculateConditionalSimpleFecDofToSend(
  int max_grp_len, double per, double tgt_p_recv, int num_src, int src_rcvd,
  int enc_rcvd, uint8_t& dof_to_send)
{
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  if (dof_needed < 1)
  {
    dof_to_send = 0;
    return 1.0;
  }

  // Success probability given an FEC configuration.
  double  ps = 0.0;

  if (tgt_p_recv >= kMaxTgtPktRcvProb)
  {
    tgt_p_recv = kMaxTgtPktRcvProb;
  }

  // Start at a test value for dof_to_send of 0.
  int  dts = 0;

  for (dts = 1; dts < (max_grp_len - src_rcvd); ++dts)
  {
    ps = ComputeConditionalSimpleFecPs(num_src, src_rcvd, enc_rcvd, dts, per);

    if (ps >= tgt_p_recv)
    {
      break;
    }
  }

  dof_to_send = dts;

#ifdef SLIQ_DEBUG
  if (ps < tgt_p_recv)
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Cannot achieve target receive probability with given "
         "constraints.\n", conn_id_, stream_id_);
  }
#endif

  return ps;
}

//============================================================================
double SentPktManager::CalculateConditionalSystematicFecDofToSend(
  int max_grp_len, double per, double tgt_p_recv, int num_src, int src_rcvd,
  int enc_rcvd, uint8_t& dof_to_send)
{
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  if (dof_needed < 1)
  {
    dof_to_send = 0;
    return 1.0;
  }

  if (tgt_p_recv >= kMaxTgtPktRcvProb)
  {
    tgt_p_recv = kMaxTgtPktRcvProb;
  }

  // Success probability given an FEC receive configuration.
  double  ps = 0.0;

  // Start at a test value for dof_to_send of 1.
  int  dts = 0;

  for (dts = 1; dts < max_grp_len; ++dts)
  {
    ps = ComputeConditionalSystematicFecPs(num_src, src_rcvd, enc_rcvd, dts,
                                           per);

    if (ps >= tgt_p_recv)
    {
      break;
    }
  }

  if (dts < dof_needed)
  {
    dof_to_send = dof_needed;
  }
  else
  {
    dof_to_send = dts;
  }

#ifdef SLIQ_DEBUG
  if (ps < tgt_p_recv)
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Cannot achieve target receive probability with given "
         "constraints.\n", conn_id_, stream_id_);
  }
#endif

  return ps;
}

//============================================================================
double SentPktManager::ComputeConditionalSimpleFecPs(
  int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per)
{
  double  sum = 0.0;

  // Compute the degrees of freedom needed to completely decode.
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  // This loop computes the probability that we receive at least num_src
  // packets out of the (src_rcvd + enc_rcvd) we have, and the dof_to_send we
  // send, then weights this contribution by num_src.
  for (int i = dof_needed; i <= dof_to_send; ++i)
  {
    sum += (Combination(dof_to_send, i) * pow(per, (dof_to_send - i)) *
            pow((1.0 - per), i));
  }

  return sum;
}

//============================================================================
double SentPktManager::ComputeConditionalSystematicFecPs(
  int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per)
{
  double  sum = 0.0;

  // Compute the degrees of freedom needed to completely decode.
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  // We are modeling a systematic code here, where we may have usable source
  // packets even if we don't receive enough total packets to decode the FEC.

  // Consider two cases:
  //   1st case: we receive >= num_src total pkts and can decode (normal FEC)
  //   2nd case: we receive  < num_src total pkts, some of which are src pkts
  //
  // We compute the expected number of usable source packets received across
  // the two cases, then divide by the number of source packets to get the
  // probability of successfully receiving a source packet.
  //
  // This first loop computes the probability that we receive at least num_src
  // packets out of the (src_rcvd + enc_rcvd) we have, and the dof_to_send we
  // send, then weights this contribution by num_src.
  for (int i = dof_needed; i <= dof_to_send; ++i)
  {
    sum += (static_cast<double>(num_src) * Combination(dof_to_send, i) *
            pow(per, (dof_to_send - i)) * pow((1.0 - per), i));
  }

  // src_to_send is the number of original/source packets we send out of the
  // dof_to_send specified.  We always send source packets ahead of repair
  // packets, since they can be used even when we don't receive enough total
  // packets to decode -- so we make as many of the dof_to_send packets source
  // packets as possible.
  int  src_to_send = (num_src - src_rcvd);

  if (src_to_send > dof_to_send)
  {
    src_to_send = dof_to_send;
  }

  // enc_to_send is the number of repair packets we send, if any, out of the
  // total dof_to_send.
  int  enc_to_send = 0;

  if ((dof_to_send - src_to_send) > 0)
  {
    enc_to_send = (dof_to_send - src_to_send);
  }

  // This second loop sums over the probability that we receive exactly i
  // source packets and less than num_src total packets given the (src_rcvd +
  // enc_rcvd) = dof_to_send we have to send, summing for i between 0 and the
  // minimum of src_to_send-1 and dof_needed-1.  We then weight this by the
  // number of source packets received = (i + src_rcvd).
  int  upper_bound = ((src_to_send < dof_needed) ? src_to_send : dof_needed);

  for (int i = 0; i < upper_bound; ++i)
  {
    // This inner loop computes the probability of receiving no more than
    // (dof_needed - i - 1) repair packets out of the dof_to_send we send.
    // Note that we cannot receive more repair packets than we send, so limit
    // appropriately.
    double  inner_prob = 1.0;

    if (enc_to_send > 0)
    {
      inner_prob = 0.0;

      int  j_i = enc_to_send;

      if (j_i > (dof_needed - i - 1))
      {
        j_i = (dof_needed - i - 1);
      }

      for (int j = 0; j <= j_i; ++j)
      {
        inner_prob += (Combination(enc_to_send, j) *
                       pow(per, (enc_to_send - j)) * pow((1.0 - per), j));
      }
    }

    // The right side of this expression computes the probability that exactly
    // i source packets are received out of the src_to_send we send and
    // insufficient repair packets are received to reconstruct more.
    //
    // This is then weighted by i to compute the expected number of source
    // packets received in this situation.
    sum += (static_cast<double>(i + src_rcvd) * Combination(src_to_send, i) *
            pow(per, (src_to_send - i)) * pow((1.0 - per), i) * inner_prob);
  }

  // Finally we divide by the number of source packets sent to determine the
  // expected number of source packets received.
  sum /= static_cast<double>(num_src);

  return sum;
}

//============================================================================
double SentPktManager::Combination(int n, int k)
{
  double  cnk = 1.0;

  if ((k * 2) > n)
  {
    k = (n - k);
  }

  for (int i = 1; i <= k; n--, i++)
  {
    cnk = (cnk * (static_cast<double>(n) / static_cast<double>(i)));
  }

  return cnk;
}

//============================================================================
SentPktManager::CcCntAdjInfo::CcCntAdjInfo()
    : updated_(false), pif_adj_(0), bif_adj_(0), pipe_adj_(0)
{
}

//============================================================================
SentPktManager::CcCntAdjInfo::~CcCntAdjInfo()
{
}

//============================================================================
SentPktManager::CcUnaPktInfo::CcUnaPktInfo()
    : has_una_(false), una_cc_seq_num_(0), prev_has_una_(false),
      prev_una_cc_seq_num_(0)
{
}

//============================================================================
SentPktManager::CcUnaPktInfo::~CcUnaPktInfo()
{
}

//============================================================================
SentPktManager::SentPktInfo::SentPktInfo()
    : packet_(NULL), seq_num_(0), conn_seq_num_(0), cc_seq_num_(0),
      cc_val_(0.0), q_delay_usec_(0), rtt_usec_(0), xmit_time_(),
      last_xmit_time_(), pkt_len_(0), bytes_sent_(0), rexmit_limit_(0),
      rexmit_cnt_(0), cc_id_(0), flags_(0), sent_pkt_cnt_(0),
      prev_sent_pkt_cnt_(0), fec_grp_id_(0), fec_enc_pkt_len_(0),
      fec_grp_idx_(0), fec_num_src_(0), fec_round_(0), fec_pkt_type_(0),
      fec_ts_(0)
{
}

//============================================================================
SentPktManager::SentPktInfo::~SentPktInfo()
{
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }
}

//============================================================================
void SentPktManager::SentPktInfo::Clear()
{
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }
}

//============================================================================
void SentPktManager::SentPktInfo::MoveFecInfo(SentPktInfo& spi)
{
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }

  packet_          = spi.packet_;
  spi.packet_      = NULL;
  pkt_len_         = spi.pkt_len_;
  flags_           = spi.flags_;
  fec_grp_id_      = spi.fec_grp_id_;
  fec_enc_pkt_len_ = spi.fec_enc_pkt_len_;
  fec_grp_idx_     = spi.fec_grp_idx_;
  fec_num_src_     = spi.fec_num_src_;
  fec_round_       = spi.fec_round_;
  fec_pkt_type_    = spi.fec_pkt_type_;
  fec_ts_          = spi.fec_ts_;
}

//============================================================================
SentPktManager::SentPktQueue::SentPktQueue()
    : size_(0), cnt_(0), head_(0), buf_(NULL)
{
}

//============================================================================
SentPktManager::SentPktQueue::~SentPktQueue()
{
  if (buf_ != NULL)
  {
    delete [] buf_;
    buf_ = NULL;
  }
}

//============================================================================
bool SentPktManager::SentPktQueue::Init(WindowSize max_size)
{
  if ((buf_ == NULL) && (max_size > 1))
  {
    buf_ = new (std::nothrow) SentPktInfo[max_size];

    if (buf_ != NULL)
    {
      size_ = max_size;
      cnt_  = 0;
      head_ = 0;

      return true;
    }
  }

  return false;
}

//============================================================================
bool SentPktManager::SentPktQueue::AddToTail()
{
  if (cnt_ < size_)
  {
    ++cnt_;

    return true;
  }

  return false;
}

//============================================================================
bool SentPktManager::SentPktQueue::RemoveFromHead()
{
  if (cnt_ > 0)
  {
    buf_[head_].Clear();
    head_ = ((head_ + 1) % size_);
    --cnt_;

    return true;
  }

  return false;
}

//============================================================================
SentPktManager::FecGroupInfo::FecGroupInfo()
    : fec_grp_id_(0), fec_num_src_(0), fec_num_enc_(0), fec_src_ack_cnt_(0),
      fec_enc_ack_cnt_(0), fec_round_(0), fec_max_rounds_(0),
      fec_gen_enc_round_(0), fec_src_to_send_icr_(0), fec_enc_to_send_icr_(0),
      fec_src_sent_icr_(0), fec_enc_sent_icr_(0), fec_rexmit_limit_(0),
      fec_flags_(0), start_src_seq_num_(0), end_src_seq_num_(0),
      start_enc_seq_num_(0), end_enc_seq_num_(0)
{
}

//============================================================================
SentPktManager::FecGroupInfo::~FecGroupInfo()
{
}

//============================================================================
SentPktManager::FecEndOfRndInfo::FecEndOfRndInfo()
    : pkt_ts_(0), obs_pkt_bvec_(0), fec_grp_id_(0)
{
}

//============================================================================
SentPktManager::FecEndOfRndInfo::~FecEndOfRndInfo()
{
}

//============================================================================
SentPktManager::VdmEncodeInfo::VdmEncodeInfo()
    : num_src_pkt_(0), num_enc_pkt_(0), src_pkt_data_(), src_pkt_size_(),
      enc_pkt_data_(), enc_pkt_size_()
{
}

//============================================================================
SentPktManager::VdmEncodeInfo::~VdmEncodeInfo()
{
}

//============================================================================
SentPktManager::PktCounts::PktCounts()
    : norm_sent_(0), norm_rx_sent_(0), fec_src_sent_(0), fec_src_rx_sent_(0),
      fec_enc_sent_(0), fec_enc_rx_sent_(0), fec_grp_pure_fec_(0),
      fec_grp_coded_arq_(0), fec_grp_pure_arq_1_(0), fec_grp_pure_arq_2p_(0)
{
}

//============================================================================
SentPktManager::PktCounts::~PktCounts()
{
}
