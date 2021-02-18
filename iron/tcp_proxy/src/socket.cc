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

#include "socket.h"
#include "clock.h"
#include "cong_ctrl_none.h"
#include "cong_ctrl_vj.h"
#include "iron_constants.h"
#include "list.h"
#include "log.h"
#include "log_utility.h"
#include "packet_pool.h"
#include "string_utils.h"
#include "tcp_proxy.h"
#include "unused.h"

#include <inttypes.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

using ::iron::CallbackNoArg;
using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::LogUtility;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PktMemIndex;
using ::iron::QueueDepths;
using ::iron::StringUtils;
using ::iron::Time;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "Socket";

  /// The default initial rtt, in microseconds.
  const uint32_t  kDefaultInitialRtt = 0;

  /// The default initial rtt variance, in microseconds
  const uint32_t  kDefaultInitialRttVar = 125000;

  /// The default initial rto, in microseconds
  const uint32_t  kDefaultInitialRto = 6000000;

  /// The default MTU in bytes.
  //
  // We set the default MTU to be 1280 (desired MSS) + 40 bytes (TCP and IP
  // header lengths). The 1280 byte desired MSS and a window scale of 8
  // ensures that the advertised window is a multiple of the MSS. NOTE: if we
  // ever need to reduce this MTU we will also need to adjust the window
  // scaling.
  const uint32_t  kDefaultMTU = 1320; //1200;

  /// The default ACK behavior.
  const uint32_t  kDefaultAckFreq = 2;

  /// The default ACK delay, in microseconds.
  const uint32_t  kDefaultAckDelayUs = 200000;

  /// 1 sec minimum RTO, per RFC 6298.
  const uint32_t  kMinRtoUs = 1000000;

  /// 64 sec maximum RTO, per RFC 6298.
  const uint32_t  kMaxRtoUs = 60000000;

  /// Maximum retransmissions during a connection.
  const uint32_t  kTimeout = 1000000;

  /// Maximum retransmissions for opens.
  const uint32_t  kLongTimeout = 32;

  /// 2 MSL, in seconds.
  const uint32_t  k2MslTimeout = 10;

  /// KeepAlive timer.
  const uint32_t  kKaTimeout = 15 * 60;

  /// The maximum Persist timer shift.
  const uint8_t   kMaxPersistShift = 7;

  /// The Persist timeouts.
  const int kPersistTimeouts[kMaxPersistShift] = {0, 5, 6, 12, 24, 48, 96};

  /// The default buffer sizes.
  const uint32_t  kDefaultBufferSize = 1000000;

  /// The burst interval multiplier.
  const uint8_t   kBurstIntervalMultiplier = 1;

  /// The number of SYN retransmissions before server is declared
  /// unreachable.
  const uint8_t   kMaxSeamlessHandoffSynRexmits = 2;
}

//============================================================================
Socket::Socket(TcpProxy& tcp_proxy, iron::PacketPool& packet_pool,
               iron::BinMap& bin_map,
               PktInfoPool& pkt_info_pool, TcpProxyConfig& proxy_config,
               SocketMgr& socket_mgr)
    : proxy_config_(proxy_config),
      tcp_proxy_(tcp_proxy),
      packet_pool_(packet_pool),
      bin_map_(bin_map),
      socket_mgr_(socket_mgr),
      pkt_info_pool_(pkt_info_pool),
      bin_idx_(iron::kInvalidBinIndex),
      flow_tag_(0),
      cfg_if_id_(LAN),
      my_port_(0),
      his_port_(0),
      sock_flags_(0),
      is_active_(false),
      orig_syn_pkt_info_(NULL),
      do_seamless_handoff_(false),
      seamless_handoff_endpoint_(),
      client_configured_server_endpoint_(),
      is_tunneled_(false),
      tunnel_hdrs_(),
      adaptive_buffers_(proxy_config_.adaptive_buffers()),
      send_buf_(NULL),
      out_seq_buf_(NULL),
      peer_(NULL),
      peer_send_buf_max_bytes_(kDefaultBufferSize),
      gw_flags_(0),
      flow_utility_fn_(NULL),
      tos_(0),
      desired_dscp_(-1),
      state_(0),
      prev_state_(0),
      capabilities_(0),
      initial_seq_num_(0),
      initial_seq_num_rec_(0),
      rel_seq_num_urg_ptr_(0),
      ack_num_(0),
      seq_num_(0),
      syn_seq_num_(0),
      syn_seq_num_set_(false),
      fin_seq_num_(0),
      fin_seq_num_set_(false),
      snd_una_(0),
      seq_sent_(0),
      snd_max_(0),
      high_seq_(0),
      high_cong_seq_(0),
      pkts_ack_in_epoch_(0),
      funct_flags_(0),
      snd_wnd_(0),
      last_ack_(0),
      last_uwe_(0),
      last_uwe_in_(0),
      ph_(),
      timeout_(kLongTimeout),
      persist_shift_(0),
      flags_(TH_SYN),
      ack_delay_(0),
      ack_freq_(kDefaultAckFreq),
      t_maxseg_(0),
      max_data_(0),
      remote_mss_offer_(0),
      my_mss_offer_(0),
      snd_awnd_(0),
      snd_cwnd_(0),
      snd_prev_cwnd_(0),
      snd_ssthresh_(0),
      mtu_(kDefaultMTU),
      t_dupacks_(0),
      unacked_segs_(0),
      last_adv_wnd_(kDefaultBufferSize),
      total_sent_(0),
      is_carrying_data_(false),
      flow_svc_id_(0),
      requested_s_scale_(0),
      request_r_scale_(0),
      snd_scale_(0),
      rcv_scale_(0),
      ts_recent_(0),
      ts_recent_age_(0),
      ts_ecr_recent_(0),
      plug_send_size_(0),
      plug_send_seq_(0),
      sack_plug_cache_(),
      rtt_cur_(0),
      initial_rtt_(kDefaultInitialRtt),
      initial_rtt_var_(kDefaultInitialRttVar),
      initial_rto_(kDefaultInitialRto),
      t_srtt_(0),
      t_rttvar_(0),
      t_rxtcur_(0),
      t_rxtshift_(0),
      t_rxtmaxshift_(12),
      t_rtt(false),
      t_rtseq(0),
      rtseq_ts_val_(),
      ack_delay_us_(kDefaultAckDelayUs),
      min_rto_us_(kMinRtoUs),
      max_rto_us_(kMaxRtoUs),
      rto_failed_(0),
      ka_timeout_(kKaTimeout),
      next_admission_time_(Time::Now()),
      min_burst_usec_(0, iron::kDefaultBpfMinBurstUsec),
      last_send_rate_(kMinSendRate),
      delayed_ack_time_(),
      keep_alive_time_(),
      persist_time_(),
      rto_time_(),
      time_wait_time_(),
      flow_is_idle_(true),
      flow_ctrl_blocked_(false),
      flow_ctrl_blocked_seq_num_(0),
      flow_ctrl_blocked_data_len_(0),
      stats_src_endpt_(),
      stats_dst_endpt_(),
      sent_pkt_cnt_(0),
      sent_bytes_cnt_(0),
      cumulative_sent_pkt_cnt_(0),
      cumulative_sent_bytes_cnt_(0),
      rcvd_pkt_cnt_(0),
      rcvd_bytes_cnt_(0),
      cumulative_rcvd_pkt_cnt_(0),
      cumulative_rcvd_bytes_cnt_(0),
      cumulative_utility_(0.0),
      utility_(0.0),
      utility_sample_cnt_(0),
      ave_utility_(0.0),
      cumulative_pkt_delay_ms_(0),
      pkt_delay_sample_cnt_(0),
      ave_pkt_delay_ms_(0),
      last_report_time_(),
      next_(NULL),
      prev_(NULL)
{
  LogD(kClassName, __func__, "Creating new Socket...\n");

  rtseq_ts_val_.SetInfinite();
  delayed_ack_time_.SetInfinite();
  keep_alive_time_.SetInfinite();
  persist_time_.SetInfinite();
  rto_time_.SetInfinite();
  time_wait_time_.SetInfinite();

  memset(&my_addr_, 0, sizeof(my_addr_));
  memset(&his_addr_, 0, sizeof(his_addr_));

  // Initialize the IP header template. Set the fields that won't change. The
  // other fields will be set when received packets are processed.
  memset(&t_template_, 0, sizeof(t_template_));
  t_template_.ihl      = sizeof(struct iphdr) >> 2;
  t_template_.version  = 4;
  t_template_.tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  t_template_.ttl      = 96;
  t_template_.protocol = IPPROTO_TCP;

  memset(&ph_, 0, sizeof(ph_));

  // Initialize buffers.
  send_buf_    = new SendBuffer(pkt_info_pool_, kDefaultBufferSize,
                                adaptive_buffers_, this);
  out_seq_buf_ = new OutSeqBuffer(pkt_info_pool_, kDefaultBufferSize, this);

  peer_send_buf_max_bytes_ = kDefaultBufferSize;

  ph_.mbz      = 0;
  ph_.protocol = IPPROTO_TCP;

  // Default to running with Timestamps.
  capabilities_ |= CAP_TIMESTAMP;
  sock_flags_   |= TF_REQ_TSTMP;

  // By default, we won't enable SACK. We do this because we want the
  // advertised window on the LAN-facing socket to be a multiple of the
  // MSS. Enabling SACK makes this more difficult. Additionally, we shouldn't
  // observe any loss on the LAN-facing socket. The WAN-facing socket will
  // have SACK enabled as controlled by the kDefaultWanIfSack constant in
  // tcp_proxy_config.cc.
  //
  // capabilities_ |= CAP_SACK;
  // sock_flags_   |= TF_REQ_SACK;

  capabilities_ |= CAP_CONGEST;

  // Say we'll scale our windows.
  sock_flags_      |= TF_REQ_SCALE;

  // For now, we set the advertised window scaling to be the mimimum of 8 and
  // TCP_MAX_WINSHIFT. This is because with an MTU of 1332 bytes we will be
  // ensured to advertise a window that is a multiple of the MSS.
  request_r_scale_  = 8 < TCP_MAX_WINSHIFT ? 8 : TCP_MAX_WINSHIFT;

  // while ((request_r_scale_ < TCP_MAX_WINSHIFT) &&
  //        ((TCP_MAXWIN << request_r_scale_) < (int)peer_send_buf_max_bytes_))
  // {
  //   request_r_scale_++;
  // }

  // Create the Congestion Control Algorithms.
  for (int i = 0; i < MAX_CC_ALG_CNT; i++)
  {
    cc_algs_[i] = NULL;
  }

  cc_algs_[NO_CONGESTION_CONTROL] = new NoCongCtrlAlg(this);
  cc_algs_[VJ_CONGESTION_CONTROL] = new VJCongCtrlAlg(this);

  // The default Congestion Control Alogirthm is VJ.
  cc_algs_[VJ_CONGESTION_CONTROL]->Select();

  // Initialize the utility function of the parent class
  flow_utility_fn_ = NULL;

  // Initialize the SCAK plug cache.
  memset(&sack_plug_cache_, 0, sizeof(OutSeqBuffer::PlugInfo) * 4);
}

//============================================================================
Socket::~Socket()
{
  state_ = TCP_CLOSE;

  // Cancel the timers.
  CancelAllScheduledEvents();

  // Clean up the timer callback object pools.
  CallbackNoArg<Socket>::EmptyPool();

  // Free the buffers.
  if (send_buf_ != NULL)
  {
    delete send_buf_;
    send_buf_ = NULL;
  }

  if (out_seq_buf_ != NULL)
  {
    delete out_seq_buf_;
    out_seq_buf_ = NULL;
  }

  if (peer_ && (peer_->peer_) && (peer_->peer_ == this))
  {
    peer_->peer_ = NULL;
  }

  // Destroy the Congestion Control Algorithms.
  for (int i = 0; i < MAX_CC_ALG_CNT; i++)
  {
    if (cc_algs_[i] != NULL)
    {
      delete cc_algs_[i];
    }
  }

  // Delete the Utility Function.
  if (flow_utility_fn_ != NULL)
  {
    delete flow_utility_fn_;
    flow_utility_fn_ = NULL;
  }

  // Report that this socket is being deleted
  LogD(kClassName, __func__, "%s, deleting socket.\n", flow_id_str_);
}

//============================================================================
int Socket::ProcessPkt(PktInfo* pkt_info, const struct tcphdr* tcp_hdr,
                       const struct iphdr* ip_hdr)
{
  volatile uint32_t  window_hbo = ntohs(tcp_hdr->th_win);
  volatile uint32_t  ack_hbo    = ntohl(tcp_hdr->th_ack);
  volatile uint32_t  seq_hbo    = ntohl(tcp_hdr->th_seq);

  int       ts_present;
  int16_t   option_len;
  uint16_t  tcp_hdr_flags;
  uint32_t  ts_val;
  uint32_t  ts_ecr;

  // Onetime check on the pkt_info.
  if (pkt_info->pkt == NULL)
  {
    LogW(kClassName, __func__, "%s, method called with invalid pkt_info.\n",
         flow_id_str_);
    pkt_info_pool_.Recycle(pkt_info);
  }

  tcp_hdr_flags = tcp_hdr->th_flags;

  // General approach in this method: If the pkt_info is not enqueued, or
  // otherwise saved as in this statement below
  //
  //      orig_syn_pkt_info_ = pkt_info;
  //
  // then the pkt_info must be recycled. When the pkt_info is passed to a
  // lower level method, that method takes care of recycling. Otherwise the
  // pkt_info must be recycled in this method.

  if (tcp_hdr_flags & TH_RST)
  {
    LogD(kClassName, __func__, "%s, received a reset.\n", flow_id_str_);

    if (state_ == TCP_CLOSE)
    {
      // Need to recycle the packet
      pkt_info_pool_.Recycle(pkt_info);

      return -1;
    }

    prev_state_ = state_;
    state_      = TCP_CLOSE;

    CancelScheduledEvent(rto_time_);

    if (peer_ && (peer_->peer_->peer_ == peer_))
    {
      // Take the appropriate action to the received TCP RST in the peer
      // socket. If the TCP RST is received on the WAN-facing socket, the
      // socket is configured to do seamless handoffs, and the peer is in a
      // LISTEN state, then do a "silent abort", which will find another
      // available server to try. Otherwise, simply perform a normal abort.
      if ((cfg_if_id_ == WAN) && do_seamless_handoff_ &&
          (peer_->state() == TCP_LISTEN))
      {
        peer_->SilentAbort();
      }
      else
      {
        peer_->SendPkt(pkt_info);

        // if (tcp_proxy_.SimpleSendPkt(cfg_if_id_ == WAN ? LAN : WAN, pkt_info)
        //     < 0)
        // {
        //   LogW(kClassName, __func__, "%s, unable to send any bytes.\n",
        //        flow_id_str_);
        //   TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        // }
        socket_mgr_.MarkSocketForRemoval(peer_);
      }
    }
    else
    {
      // Need to recycle the packet
      pkt_info_pool_.Recycle(pkt_info);
    }

    socket_mgr_.MarkSocketForRemoval(this);

    return -1;
  }

  if ((tcp_hdr_flags & TH_SYN) == 0)
  {
    snd_awnd_ = window_hbo << snd_scale_;
  }
  else
  {
    snd_awnd_ = window_hbo;
  }

  snd_wnd_    = MIN(snd_cwnd_, snd_awnd_ + snd_una_ - snd_max_);
  ts_present  = 0;
  option_len  = (tcp_hdr->th_off << 2) - sizeof(struct tcphdr);

  if ((pkt_info->data_len) && (!peer_))
  {
    t_template_.daddr = ip_hdr->saddr;
    t_template_.saddr = ip_hdr->daddr;

    Reset(tcp_hdr);
  }

  bool  pkt_changed_snd_buf = false;
  if (option_len && (state_ != TCP_LISTEN))
  {
    DoOptions(option_len, tcp_hdr, &ts_present, &ts_val, &ts_ecr,
              pkt_changed_snd_buf);
  }

  uint32_t  tp_now = Clock::ValueRough();

  if ((sock_flags_ & TF_REQ_TSTMP) && (sock_flags_ & TF_RCVD_TSTMP))
  {
    // Revert to Braden code.
    //
    // Since there are multiple paths through the network, don't ignore "late"
    // packets.
    //
    // if (ts_present && SEQ_GEQ(ts_val, ts_recent_) &&
    //     SEQ_LEQ(seq_hbo, last_ack_))
    if (ts_present && SEQ_LEQ(seq_hbo, last_ack_))
    {
      ts_recent_     = ts_val;
      ts_recent_age_ = tp_now;
    }

    if (ts_present && ts_ecr)
    {
      // Only update the delay stats and RTT if this packet contains new information.
      if ((SEQ_GEQ(ack_hbo, snd_una_)
           ||
           (((seq_hbo == last_ack_) && (pkt_info->data_len == 0)) ||
            SEQ_GT(seq_hbo, last_ack_)))
          ||
          pkt_changed_snd_buf)
      {
        // Collect packet delay statistics.
        cumulative_pkt_delay_ms_ += (tp_now - ts_val) / 1000;
        pkt_delay_sample_cnt_++;
        if ((cfg_if_id_ == WAN) &&
            (((tp_now - ts_val) / 1000) > 5000))
        {
          LogD(kClassName, __func__, "%s: pkt ts is %" PRIu32 ", "
               "now is %" PRIu32 ".\n", flow_id_str_, ts_val, tp_now);
          LogD(kClassName, __func__, "%s: pkt delay is %" PRIu32 ", "
               "cumulative_pkt_delay_ms_ is %" PRIu32 ", pkt_delay_sample_cnt is "
               "%" PRIu16 ".\n", flow_id_str_, ((tp_now - ts_val) / 1000),
               cumulative_pkt_delay_ms_, pkt_delay_sample_cnt_);
          LogD(kClassName, __func__, "%s: ack num is %" PRIu32 ", "
               "snd una is %" PRIu32 ", seq num is %" PRIu32 ", last ack is %"
               PRIu32 ".\n", flow_id_str_, ack_hbo, snd_una_, seq_hbo,
               last_ack_);
        }

        if (SEQ_GT(tp_now, ts_ecr))
        {
          UpdateRttEstimate((uint32_t)(tp_now - ts_ecr));
          ts_ecr_recent_ = ts_ecr;
        }
        else
        {
          LogW(kClassName, __func__, "now is less than ts_ecr\n");
        }
      }
    }
  }
  else
  {
    if (t_rtt)
    {
      if (SEQ_LT(t_rtseq, ack_hbo))
      {
        Time  now = Time::Now();
        UpdateRttEstimate(
          static_cast<uint32_t>((now - rtseq_ts_val_).GetTimeInUsec()));
        t_rtt = false;
      }
    }
  }

  flags_ = TH_ACK;

  if (tos_ != ip_hdr->tos)
  {
    tos_ = ip_hdr->tos;
  }

  t_template_.tos = ip_hdr->tos;
  tos_            = ip_hdr->tos;

  if (peer_)
  {
    peer_->t_template().tos = ip_hdr->tos;
  }

  int  rv = 1;
  switch (state_)
  {
    case TCP_LISTEN:
      // Save the received PktInfo, which contains the SYN. We will process it
      // when we receive the SYN/ACK on the active socket (our peer).
      if (tcp_hdr->th_flags & TH_SYN)
      {
        if (orig_syn_pkt_info_ != NULL)
        {
          pkt_info_pool_.Recycle(pkt_info);
        }
        else
        {
          orig_syn_pkt_info_ = pkt_info;
        }
      }
      // Packet recycling not needed here
      break;

    case TCP_SYN_SENT:
      rv = ProcessPktSynSentState(tcp_hdr);
      // Need to recycle the packet.
      pkt_info_pool_.Recycle(pkt_info);
      break;

    case TCP_SYN_RECV:
      rv = ProcessPktSynRecState(pkt_info, tcp_hdr, ip_hdr);
      // Packet recycling handled in above method.
      break;

    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
      rv = ProcessPktEstablishedState(pkt_info, tcp_hdr);
      // Packet recycling handled in above method.
      break;

    case TCP_FIN_WAIT1:
      rv = ProcessPktFinWait1State(pkt_info, tcp_hdr);
      // Packet recycling handled in above method.
      break;

    case TCP_FIN_WAIT2:
      ProcessPktFinWait2State(pkt_info, tcp_hdr);
      // Packet recycling handled in above method.
      break;

    case TCP_CLOSING:
      ProcessPktClosingState(pkt_info, tcp_hdr);
      // Packet recycling handled in above method.
      break;

    case TCP_LAST_ACK:
      rv = ProcessPktLastAckState(pkt_info, tcp_hdr);
      // Need to recycle the packet.
      pkt_info_pool_.Recycle(pkt_info);
      break;

    case TCP_TIME_WAIT:
      ProcessPktTimeWaitState(tcp_hdr, ip_hdr);
      // Need to recycle the packet.
      pkt_info_pool_.Recycle(pkt_info);
      break;
  }

  return rv;
}

//============================================================================
PktInfo* Socket::BuildHdr(PktInfo* pkt_info, int push, bool use_seq_sent)
{
  volatile uint16_t  opt_len;

  size_t     tcp_hdr_len;
  uint8_t    opt[kMaxTcpOptLen];
  uint32_t*  options_start;

  if (pkt_info)
  {
    use_seq_sent = false;
  }

  if (!pkt_info)
  {
    pkt_info = pkt_info_pool_.Get();
  }

  if (push)
  {
    flags_ |= TH_PUSH;
  }
  else
  {
    flags_ &= ~TH_PUSH;
  }

  pkt_info->pkt->SetLengthInBytes(kMaxTcpOptLen);
  pkt_info->pkt->RemoveBytesFromBeginning(kMaxTcpOptLen);

  // First, add the IP header information. We don't yet know the total length
  // of the Packet so we'll defer setting that until the Packet is ready to be
  // sent.
  struct iphdr*  ip_hdr = reinterpret_cast<struct iphdr*>
    (pkt_info->pkt->GetBuffer());
  t_template_.check = 0;
  t_template_.id++;
  memcpy(ip_hdr, (void*)&(t_template_), sizeof(t_template_));

  // Next, add the TCP header information.
  struct tcphdr*  tcp_hdr = reinterpret_cast<struct tcphdr*>
    (pkt_info->pkt->GetBuffer(sizeof(t_template_)));

  options_start = reinterpret_cast<uint32_t*>
    (reinterpret_cast<uint8_t*>(tcp_hdr) + sizeof(t_template_));

  // End of basic TCP header.

  // Start the tp length calculation with the tp header size.
  tcp_hdr_len = sizeof(struct tcphdr);

  tcp_hdr->th_sport = my_port_;
  tcp_hdr->th_dport = his_port_;
  tcp_hdr->th_urp   = 0;

  if (funct_flags_ & FUNCT_REL_SEQ_NUM_URG_PTR)
  {
    uint32_t  x;

    x = rel_seq_num_urg_ptr_ - (seq_num_ - initial_seq_num_);

    if (x < TCP_MAXWIN)
    {
      flags_          |= TH_URG;
      tcp_hdr->th_urp  = htons(x);
    }
  }

  // If use_seq_sent is set to true and this call had no data associated
  // with it (i.e., pkt_info was NULL) then set the sequence number to
  // seq_sent_ rather than seq_num_ -- basically supporting SYN and FIN
  // sequence number rules.
  if (use_seq_sent)
  {
    tcp_hdr->th_seq   = htonl(seq_sent_);
    pkt_info->seq_num = seq_sent_;
  }
  else
  {
    tcp_hdr->th_seq   = htonl(seq_num_);
    pkt_info->seq_num = seq_num_;
  }

  tcp_hdr->th_x2    = 0;         // Clear reserved bits.
  tcp_hdr->th_flags = flags_;
  tcp_hdr->th_off   = 0x5;       // 4-bit header len
  tcp_hdr->th_sum   = 0;

  opt_len = GetOptions(opt, kMaxTcpOptLen);

  // Copy the options into the TCP header.
  memcpy(options_start, &opt[0], opt_len);

  tcp_hdr_len += opt_len;

  tcp_hdr->th_off = (tcp_hdr_len >> 2);

  // tcp_data_len = pkt_info->data_len;

  seq_num_ += pkt_info->data_len;
  if (flags_ & (TH_SYN | TH_FIN))
  {
    seq_num_++;
  }

  // Set the length of the Packet as constructed so far (contains IP and TCP
  // headers and options.
  pkt_info->pkt->SetLengthInBytes(sizeof(t_template_) + tcp_hdr_len);

  return pkt_info;
}

//============================================================================
uint32_t Socket::Send(PktInfo* arg_pkt_info, bool force)
{
  volatile uint32_t  seq_num_hbo;

  int       took_while  = 0;
  int       test_val    = 0;
  int       max_to_send = 0;
  uint32_t  bytes_sent  = 0;

  Time  now = Time::Now();

  // Update the flow service id.
  flow_svc_id_++;

  // Basic mechanism:
  //
  //    Walk the Pending Retransmission Queue and
  //    transmit any elements where either
  //        - The Rexmit Time is clear    or
  //        - The Rexmit Time is < tpNow
  //    (both are handled by the test (tpNow >= Rexmit_Time)
  //
  //    Following emission of retransmissions, we then
  //    send any new data available.

  // The max_to_send local variable, which is used to "throttle"
  // transmissions, is only used on LAN-facing sockets (WAN-facing sockets are
  // governed by Admission Control). For now, limit the number of concurrent
  // transmissions to 30 packets each time that the socket is serviced.
  //
  // max_to_send = (mtu_ << 1);
  max_to_send = mtu_ * 30;

  LogD(kClassName, __func__, "%s, starting big while loop.\n", flow_id_str_);

  PktInfo* pkt_info  = NULL;

  // Make sure we don't allow for an indefinite amount of catch up time.
  Time  low_adm_time =
    now.Subtract(min_burst_usec_.Multiply(kBurstIntervalMultiplier));
  if (next_admission_time_ < low_adm_time)
  {
    next_admission_time_ = low_adm_time;
  }

  while (true)
  {
    // We exit the loop if the force flag is true.
    if (force)
    {
      LogD(kClassName, __func__, "%s, exiting loop, force is true.\n",
           flow_id_str_);
      break;
    }

    // On the WAN side interface there is no congestion control. Instead, we
    // check with admission control to see if a packet can be admitted.
    if ((cfg_if_id_ == WAN) && (!CanAdmitPacket(now)))
    {
      LogD(kClassName, __func__, "%s, exiting loop, admission control "
           "blocked.\n", flow_id_str_);

      if (next_admission_time_ <
          now.Subtract(min_burst_usec_.Multiply(kBurstIntervalMultiplier)))
      {
        flow_is_idle_ = true;
      }

      break;
    }

    // Test if there is anything in the send buffer that should be
    // sent. This could be a retransmission or new data.
    if ((pkt_info = send_buf_->GetNextTransmission(now, last_uwe_in_,
                                                   cfg_if_id_)) == NULL)
    {
      if ((cfg_if_id_ == WAN) && (is_carrying_data_))
      {
        LogD(kClassName, __func__, "%s, exiting loop, nothing in send buffer "
             "to send via WAN. Usable window: %" PRIu32 " uwe: %" PRIu32
             ", bytes held in OOSeq buffer: %" PRIu32 ".\n", flow_id_str_,
             send_buf_->GetUsableWindow(), send_buf_->uwe(),
             peer_->out_seq_buf_->size_bytes());
      }
      break;
    }

    // Test if we have exceeded the maximum burst limit on LAN side
    // interface.
    /*
    if ((cfg_if_id_ == LAN) && (gwFairnessCntr >= PROXY_MAX_BURST))
    {
      LogW(kClassName, __func__, "Exiting loop, fairness count exceeds "
           "PROXY_MAX_BURST.\n");
      break;
    }
    */

    // Test if we are flow control blocked on either the LAN side or the WAN
    // side interfaces.
    if (SEQ_GT(pkt_info->seq_num + pkt_info->data_len, last_uwe_in_) &&
        (pkt_info->data_len != 0))
    {
      LogD(kClassName, __func__, "%s, exiting loop, flow control blocked: "
           "last_uwe_in_=%" PRIu32 " ptk_info->seq_num + pkt_info->data_len=%"
           PRIu32 "\n", flow_id_str_, last_uwe_in_,
           (pkt_info->seq_num + pkt_info->data_len));

      flow_ctrl_blocked_          = true;
      flow_ctrl_blocked_seq_num_  = pkt_info->seq_num;
      flow_ctrl_blocked_data_len_ = pkt_info->data_len;

      break;
    }

    // Ensure that we have not already sent this packet during this service
    // interval.
    if ((!pkt_info->rexmit_time.IsInfinite()) &&
        (!SEQ_LT(pkt_info->last_flow_svc_id, flow_svc_id_)))
    {
      LogD(kClassName, __func__, "%s, pkt with seq num (%" PRIu32 ") has "
           "already been transmitted during the current flow service "
           "interval.\n", flow_id_str_, pkt_info->seq_num);
      break;
    }

    test_val = pkt_info->pkt->GetLengthInBytes();

    // Test if we are congestion control blocked on the LAN side interface.
    /*
    if ((cfg_if_id_ == LAN) && (capabilities_ & CAP_CONGEST) &&
        (static_cast<int>(snd_cwnd_) <
         static_cast<int>(pkt_info->data_len)))
    {
      LogW(kClassName, __func__, "tag: %" PRId32 " Exiting loop, "
           "congestion control blocked: snd_cwnd_=%" PRIu32
           " pkt_info->data_len=%" PRIu32 ".\n", -(int32_t)flow_tag(),
           snd_cwnd_, pkt_info->data_len);
      break;
    }
    */

    // Test if we have exceeded the maximum bytes to send limit.
    if ((cfg_if_id_ == LAN) && (max_to_send < test_val))
    {
      LogD(kClassName, __func__, "%s, exiting loop, max to send limit "
           "exceeded: max_to_send=%d test_val=%d.\n", flow_id_str_,
           max_to_send, test_val);
      break;
    }

    LogD(kClassName, __func__, "%s, inside big while loop...\n",
         flow_id_str_);

    took_while = 1;

    if (is_tunneled_ && pkt_info->has_been_encapsulated)
    {
      // Remove the tunnel headers for packets that have been
      // encapsulated. This generally ocurs because packets that are
      // transmitted remain in the send buffer until ACKed (and therefore may
      // be retransmitted). If a packet is retransmitted and the encapsulating
      // headers have already been prepended, we need to strip them off before
      // proceeding.
      pkt_info->pkt->RemoveBytesFromBeginning(iron::kVxlanTunnelHdrLen);
    }

    struct tcphdr*  tcp_hdr = pkt_info->pkt->GetTcpHdr();

    seq_num_hbo = ntohl(tcp_hdr->th_seq);

    LogD(kClassName, __func__, "%s, seq (%" PRIu32 ") in TCP hdr.\n",
         flow_id_str_, seq_num_hbo);

    // During a congestion epoch, remember the highest sequence number sent.
    // Later we won't credit our snd_cwnd for the acks from these packets.
    //
    // The rationale here is this: On entering a congestion epoch, we cut
    // our transmission rate (since snd_cwnd will generally go negative, so
    // we have to wait until 1/2 a window of dupacks come in before we sent
    // anything) and then start remembering the highest sequence number sent
    // during the epoch. On leaving the epoch, we're going to give ourselves
    // a full snd_cwnd of credit and NOT credit for acks from packets sent
    // during the epoch.
    if ((funct_flags_ & FUNCT_HIGH_SEQ) &&
        SEQ_GT(seq_num_hbo + pkt_info->data_len, high_cong_seq_))
    {
      high_cong_seq_ = seq_num_hbo + pkt_info->data_len;
      funct_flags_   = funct_flags_ | FUNCT_HIGH_CONGESTION_SEQ;
    }

    // Check for flow control
    if (SEQ_LEQ((seq_num_hbo + pkt_info->data_len), last_uwe_in_) ||
        (pkt_info->data_len == 0))
    {
      if ((pkt_info->data_len == 0) && SEQ_GT(seq_num_hbo, last_uwe_in_))
      {
        uint8_t flags = pkt_info->pkt->GetTcpHdr()->th_flags;

        if (!(flags & (TH_SYN | TH_FIN)))
        {
          LogW(kClassName, __func__, "%s, zero length packet w/o SYN or FIN "
               "has seq num of %" PRIu32 " relative to last_uwe_in_ of %"
               PRIu32 ": flags are %" PRIu8 "\n", flow_id_str_, seq_num_hbo,
               last_uwe_in_, flags);
        }
      }

      if ((bytes_sent = SendPkt(pkt_info)) == 0)
      {
        break;
      }

      if (is_tunneled_ && pkt_info->has_been_encapsulated)
      {
        // If we get here, the VXLAN tunnel headers were prepended to the
        // packet that was transmitted. The modification makes the pointer to
        // the TCP header invalid, so we adjust it here. We should investigate
        // better solutions for this.
        tcp_hdr = reinterpret_cast<tcphdr*>(
          reinterpret_cast<uint8_t*>(tcp_hdr) + iron::kVxlanTunnelHdrLen);
      }

      max_to_send -= bytes_sent;

      if (!pkt_info->rexmit_time.IsInfinite() && (bytes_sent > 0))
      {
        LogD(kClassName, __func__, "%s, retransmitted seq num %" PRIu32
             " rexmit time %s, now %s.\n", flow_id_str_, seq_num_hbo,
             pkt_info->rexmit_time.ToString().c_str(),
             Time::Now().ToString().c_str());
      }
    }
    else
    {
      LogD(kClassName, __func__, "%s, can't send packet with seq num %"
           PRIu32 ". Outside of flow control window %" PRIu32 "\n",
           flow_id_str_, seq_num_hbo, last_uwe_in_);

      flow_ctrl_blocked_          = true;
      flow_ctrl_blocked_seq_num_  = pkt_info->seq_num;
      flow_ctrl_blocked_data_len_ = pkt_info->data_len;
    }

    if (SEQ_GT((seq_num_hbo + pkt_info->data_len), seq_sent_))
    {
      seq_sent_ = seq_num_hbo + pkt_info->data_len;
    }

    // Update snd_max_ if seq_sent_ moves ahead.
    if (SEQ_GT(seq_sent_, snd_max_))
    {
      snd_max_ = seq_sent_;
    }

    last_ack_ = ack_num_;
    last_uwe_ = peer_->send_buf_->uwe();

    if (tcp_hdr->th_flags & TH_SYN)
    {
      if (!syn_seq_num_set_)
      {
	syn_seq_num_     = pkt_info->seq_num + pkt_info->data_len;
	syn_seq_num_set_ = true;
	seq_sent_        = syn_seq_num_ + 1;
	snd_max_         = seq_sent_;
      }
    }

    if (tcp_hdr->th_flags & TH_FIN)
    {
      if (!fin_seq_num_set_)
      {
	fin_seq_num_     = pkt_info->seq_num + pkt_info->data_len;
	fin_seq_num_set_ = true;
	seq_sent_        = fin_seq_num_ + 1;
	snd_max_         = seq_sent_;
      }

      switch (state_)
      {
        case TCP_ESTABLISHED:
          if ((tcp_hdr->th_flags & TH_ACK) && peer_->fin_seq_num_set_ &&
              (ntohl(tcp_hdr->th_ack) == (peer_->fin_seq_num_ + 1)))
          {
            // We are sending a FIN and an ACK for the FIN that we originally
            // sent via our peer. Transition to state TCP_LAST_ACK.
            prev_state_ = state_;
            state_      = TCP_LAST_ACK;

            LogD(kClassName, __func__, "%s, transitioning from state "
                 "TCP_ESTABLISHED to TCP_LAST_ACK.\n", flow_id_str_);
          }
          else
          {
            // We are sending a FIN. Transition to state TCP_FIN_WAIT1.
            prev_state_ = state_;
            state_      = TCP_FIN_WAIT1;

            LogD(kClassName, __func__, "%s, transitioning from state "
                 "TCP_ESTABLISHED to TCP_FIN_WAIT1.\n", flow_id_str_);
          }

          break;

        case TCP_CLOSE_WAIT:
          // Current state is TCP_CLOSE_WAIT and we sending a FIN, so
          // transition to state TCP_LAST_ACK.
          prev_state_ = state_;
          state_      = TCP_LAST_ACK;

          LogD(kClassName, __func__, "%s, transitioning from state "
               "TCP_CLOSE_WAIT to TCP_LAST_ACK.\n", flow_id_str_);

          break;

        default:
          break;
      }
    }

    if (bytes_sent != 0)
    {
      // Notify the send packet buffer that the packet retrieved for
      // transmission was successfully transmitted.
      send_buf_->RecordPktXmitSuccess(pkt_info);

      // We set the rexmit_time if we have a hole.
      if (!pkt_info->rexmit_time.IsInfinite())
      {
        // Force no backoff on hole rexmits.
        int  rx_shift_value = 0;

        // Set the rexmit_time
        uint32_t  rexmit_delta;
        if (t_srtt_)
        {
          rexmit_delta =
            MAX(min_burst_usec_.Add(0.000005).GetTimeInUsec(),
                (MIN(max_rto_us_,
                     (((MAX(0, t_srtt_) >> TCP_RTT_SHIFT) + t_rttvar_) <<
                      rx_shift_value))));
        }
        else
        {
          rexmit_delta =
            MAX(min_burst_usec_.Add(0.000005).GetTimeInUsec(),
                (MIN(max_rto_us_,
                     (MAX(0, initial_rto_) << rx_shift_value))));
        }
        pkt_info->rexmit_time = now + Time::FromUsec(rexmit_delta);
        send_buf_->MoveToEndOfRexmitList(pkt_info);

        LogD(kClassName, __func__, "%s, resetting rexmit time for seq %" PRIu32
             " to %s, now is %s.\n", flow_id_str_, pkt_info->seq_num,
             pkt_info->rexmit_time.ToString().c_str(),
             now.ToString().c_str());

        pkt_info->last_flow_svc_id = flow_svc_id_;
      }
    }

    // If the Rexmit timer isn't already running, set it.
    if (rto_time_.IsInfinite() || rto_failed_ == 1)
    {
      rto_failed_ = 0;

      int64_t  rto_delta = 0;
      // If we have a notion of srtt, set the retransmission timer
      // appropriately. If not, then set the retransmission timer to the
      // initial value in the rt_route structure.
      if (t_srtt_)
      {
        // When we use the rttvar in calculating the rxtcur, we need to make
        // sure the var is at least 0.5 seconds. Rational is the following.
        // with implementation of TCP, the unit of variance is 1/4 of a tick
        // and a tick is 0.5 seconds. The smallest value of the variable is
        // 0.125 seconds. Therefore when you multiply it by 4, the minimum
        // value of the variance term is 500000 microseconds.  - PDF
        rto_delta = ((t_srtt_ >> TCP_RTT_SHIFT) +
                     MAX(MIN_RTTVAR, ((t_rttvar_ >> TCP_RTTVAR_SHIFT) << 2)));
      }
      else
      {
        rto_delta = initial_rto_;
      }

      rto_delta = MAX(min_rto_us_, rto_delta) << t_rxtshift_; // Scale the rtt
      rto_delta = MIN(rto_delta, max_rto_us_);
      Time  duration = Time::FromUsec(rto_delta);
      ScheduleRtoEvent(duration);
    }
  } // Big while loop termination

  if (!(took_while) && (pkt_info) &&
      (SEQ_LT(last_uwe_in_, pkt_info->seq_num + pkt_info->data_len)))
  {
    if (persist_time_.IsInfinite() && rto_time_.IsInfinite())
    {
      if (last_uwe_in_ == pkt_info->seq_num)
      {
        LogE(kClassName, __func__, "%s, would not have transitioned to "
             "persist state...\n", flow_id_str_);
      }

      // Transition into persist state.
      persist_shift_++;
      if (persist_shift_ == kMaxPersistShift)
      {
        persist_shift_ = kMaxPersistShift - 1;
      }

      int64_t  usec = kPersistTimeouts[persist_shift_] * 1000 * 1000;
      Time  duration = Time::FromUsec(usec);
      SchedulePersistEvent(duration);

      CancelScheduledEvent(rto_time_);

      timeout_ = kLongTimeout;
    }
  }

  if ((arg_pkt_info) && !(took_while))
  {
    if (is_tunneled_ && arg_pkt_info->has_been_encapsulated)
    {
      // Remove the tunnel headers for packets that have been
      // encapsulated. This generally ocurs because packets that are
      // transmitted remain in the send buffer until ACKed (and therefore may
      // be retransmitted). If a packet is retransmitted and the encapsulating
      // headers have already been prepended, we need to strip them off before
      // proceeding.
      arg_pkt_info->pkt->RemoveBytesFromBeginning(iron::kVxlanTunnelHdrLen);
    }

    struct tcphdr*  tcp_hdr = arg_pkt_info->pkt->GetTcpHdr();

    uint32_t arg_seq_num_hbo = ntohl(tcp_hdr->th_seq);
    uint8_t  arg_flags       = tcp_hdr->th_flags;

    if (capabilities_ & CAP_TIMESTAMP)
    {
      if ((sock_flags_ & (TF_RCVD_TSTMP | TF_REQ_TSTMP)) ==
          (TF_RCVD_TSTMP | TF_REQ_TSTMP))
      {
        last_ack_ = ack_num_;
        last_uwe_ = peer_->send_buf_->uwe();
      }
    }

    if (SEQ_LEQ((arg_seq_num_hbo + arg_pkt_info->data_len), last_uwe_in_)
        || (arg_pkt_info->data_len == 0))
    {
      if (arg_pkt_info->data_len == 0)
      {
        if ((!(arg_flags & (TH_SYN | TH_FIN))) &&
            SEQ_GT(ntohl(tcp_hdr->th_seq), last_uwe_in_))
        {
          LogW(kClassName, __func__, "%s, zero length packet w/o SYN or FIN "
               "has seq num of %" PRIu32 " relative to last_uwe_in_ of %"
               PRIu32 ": flags are %" PRIu8 "\n", flow_id_str_,
               arg_seq_num_hbo, last_uwe_in_, arg_flags);
        }
      }

      if ((cfg_if_id_ == LAN) ||
          (force) ||
          ((cfg_if_id_ == WAN) && (CanAdmitPacket(now))))
      {
        if ((bytes_sent = SendPkt(arg_pkt_info)) <
            arg_pkt_info->pkt->GetLengthInBytes())
        {
          LogW(kClassName, __func__, "%s, SendPkt failure, sent %" PRIu32
               " bytes.\n", flow_id_str_, bytes_sent);
        }

        if (is_tunneled_ && arg_pkt_info->has_been_encapsulated)
        {
          // If we get here, the VXLAN tunnel headers were prepended to the
          // packet that was transmitted. The modification makes the pointer to
          // the TCP header invalid, so we adjust it here. We should investigate
          // better solutions for this.
          tcp_hdr = reinterpret_cast<tcphdr*>(
            reinterpret_cast<uint8_t*>(tcp_hdr) + iron::kVxlanTunnelHdrLen);
        }

        if (force)
        {
          LogD(kClassName, __func__, "%s, force transmission for seq num %"
               PRIu32 ".\n", flow_id_str_, ntohl(tcp_hdr->th_seq));
        }

        if (!arg_pkt_info->rexmit_time.IsInfinite() && (bytes_sent > 0))
        {
          LogD(kClassName, __func__, "%s, retransmitted hole with seq num %"
               PRIu32 ")\n", flow_id_str_, ntohl(tcp_hdr->th_seq));
        }
      }
    }
    else
    {
      LogD(kClassName, __func__, "%s, arg_pkt_info flow controlled: seq num: "
           "%" PRIu32 " data length: %" PRIu32 " last_uwe_in_: %" PRIu32
            ".\n", flow_id_str_, ntohl(tcp_hdr->th_seq),
           arg_pkt_info->data_len, last_uwe_in_);
    }

    max_to_send -= bytes_sent;

    if (bytes_sent != 0)
    {
      // Notify the send packet buffer that the packet provided for
      // transmission was successfully transmitted.
      send_buf_->RecordPktXmitSuccess(arg_pkt_info);

      Time  now = Time::Now();

      if (force)
      {
        if (!arg_pkt_info->rexmit_time.IsInfinite())
        {
          uint32_t  rexmit_delta;
          if (t_srtt_)
          {
            rexmit_delta =
              MAX(min_burst_usec_.Add(0.000005).GetTimeInUsec(),
                  MIN(max_rto_us_,
                      (MAX(0, t_srtt_) >> TCP_RTT_SHIFT)));
          }
          else
          {
            rexmit_delta =
              MAX(min_burst_usec_.Add(0.000005).GetTimeInUsec(),
                  MIN(max_rto_us_, MAX(0, (initial_rto_))));
          }
          arg_pkt_info->rexmit_time = now + Time::FromUsec(rexmit_delta);
          send_buf_->MoveToEndOfRexmitList(arg_pkt_info);

          arg_pkt_info->last_flow_svc_id = flow_svc_id_;
        }

        LogD(kClassName, __func__, "%s, setting rexmit time for seq %" PRIu32
             " to %s, now is %s.\n", flow_id_str_, arg_pkt_info->seq_num,
             arg_pkt_info->rexmit_time.ToString().c_str(),
             now.ToString().c_str());
      }
      else
      {
        arg_pkt_info->rexmit_time.SetInfinite();
      }
    }
  }

  return bytes_sent;
}

//============================================================================
void Socket::BuildAndSendAck()
{
  if (sock_flags_ & (SOCK_ACKNOW | SOCK_CANACK))
  {
    flags_ = TH_ACK;

    PktInfo*  pkt_info;
    if (!(pkt_info = BuildHdr(NULL, 0, true)))
    {
      LogW(kClassName, __func__, "%s, error building packet.\n",
           flow_id_str_);
    }
    else
    {
      if ((Send(pkt_info, false)) > 0)
      {
        sock_flags_  &= ~(SOCK_ACKNOW | SOCK_CANACK | SOCK_DELACK);
        unacked_segs_ = 0;
        last_ack_     = ack_num_;
        CancelDelayedAckEvent();
        last_uwe_     = peer_->send_buf_->uwe();
        ack_delay_    = 0;
      }
      pkt_info_pool_.Recycle(pkt_info);
    }
  }
}

//============================================================================
void Socket::SvcEvents(Time& now)
{
  LogD(kClassName, __func__, "%s, servicing events.\n", flow_id_str_);

  // Update the scheduled admission event time.
  UpdateScheduledAdmissionEvent(now);

  // Service all events that have expired.
  //
  // If the socket is a LAN side socket or a WAN side socket and either the
  // flow is idle or the next admission event has expired, service the socket.
  if ((cfg_if_id_ == LAN) ||
      ((cfg_if_id_ == WAN) &&
       (flow_is_idle_ ||
        (next_admission_time_ <=
         (now + min_burst_usec_.Multiply(kBurstIntervalMultiplier))))))
  {
    bool  send_called = false;

    if (sock_flags_ & (SOCK_ACKNOW | SOCK_CANACK))
    {
      flags_ = TH_ACK;

      PktInfo*  pkt_info;
      if (!(pkt_info = BuildHdr(NULL, 0, true)))
      {
        LogW(kClassName, __func__, "%s, error building packet.\n",
             flow_id_str_);
      }
      else
      {
        if ((Send(pkt_info, false)) > 0)
        {
          send_called   = true;
          sock_flags_  &= ~(SOCK_ACKNOW | SOCK_CANACK | SOCK_DELACK);
          unacked_segs_ = 0;
          last_ack_     = ack_num_;
          CancelDelayedAckEvent();
          last_uwe_     = peer_->send_buf_->uwe();
          ack_delay_    = 0;
        }
        pkt_info_pool_.Recycle(pkt_info);
      }
    }

    if (!send_called)
    {
      if (send_buf_->snd_una() || send_buf_->snd_nxt())
      {
        Send(NULL, false);
      }
    }

    if (flags_ & TH_FIN)
    {
      Send(NULL, false);
    }
  }

  if (delayed_ack_time_ < now)
  {
    DelayedAckTimeout();
  }

  if (keep_alive_time_ < now)
  {
    KeepAliveTimeout();
  }

  if (persist_time_ < now)
  {
    PersistTimeout();
  }

  if (rto_time_ < now)
  {
    RtoTimeout();
  }

  if (time_wait_time_ < now)
  {
    TimeWaitTimeout();
  }
}

//============================================================================
void Socket::CancelDelayedAckEvent()
{
  CancelScheduledEvent(delayed_ack_time_);
}

//==========================================================================
bool Socket::Connect()
{
  prev_state_ = TCP_CLOSE;
  state_      = TCP_SYN_SENT;

  ph_.src.s_addr = t_template_.saddr;
  ph_.dst.s_addr = t_template_.daddr;

  // Set the maximum segment size.
  SetMss(0);

  int64_t  rto_delta = initial_rto_;
  t_rxtcur_          = rto_delta;
  rto_delta          = MIN(rto_delta, max_rto_us_);

  // Intentionally don't clamp against RTOMAX_ here. If you set the initial
  // RTO specifically very large, so be it.
  if (rto_time_.IsInfinite())
  {
    Time  duration = Time::FromUsec(rto_delta);
    ScheduleRtoEvent(duration);
  }

  PktInfo*  pkt_info = NULL;
  if ((pkt_info = BuildHdr(NULL, 0, true)))
  {
    if (!send_buf_->Enqueue(pkt_info))
    {
      return false;
    }

    // XXX Check return value here.
    Send(NULL, false);

    return true;
  }
  else
  {
    return false;
  }

  return true;
}

//============================================================================
bool Socket::Close()
{
  switch (state_)
  {
    case TCP_LISTEN:
    case TCP_NASCENT:
    case TCP_SYN_SENT:
      return true;
      break;

    case TCP_CLOSE_WAIT:
    case TCP_ESTABLISHED:
    case TCP_SYN_RECV:
    {
      Flush();
      return true;
    }
  }

  gw_flags_ |= PROXY_SEND_FIN;

  return false;
}

//============================================================================
int Socket::Abort()
{
  if ((state_ != TCP_CLOSE) && (state_ != TCP_TIME_WAIT))
  {
    flags_    = TH_RST | TH_ACK;
    last_ack_ = ack_num_;
    if (peer_)
    {
      last_uwe_ = peer_->send_buf_->uwe();
    }
    else
    {
      last_uwe_ = ack_num_ + peer_send_buf_max_bytes_;
    }

    // Create a Packet before calling SimpleSendPkt.
    PktInfo*  pkt_info = NULL;
    if ((pkt_info = BuildHdr(NULL, 0, false)))
    {
      struct tcphdr*  tcp_hdr = pkt_info->pkt->GetTcpHdr();
      tcp_hdr->th_flags       = flags_;

      if (orig_syn_pkt_info_ != NULL)
      {
        // We are aborting a connection that was never fully established.
        LogD(kClassName, __func__, "%s, aborting connection that was never "
             "fully established.\n", flow_id_str_);

        struct tcphdr*  orig_syn_tcp_hdr =
          orig_syn_pkt_info_->pkt->GetTcpHdr();

        tcp_hdr->seq = htonl(0);
        ack_num_     = ntohl(orig_syn_tcp_hdr->seq) + 1;
      }

      tcp_hdr->ack_seq = htonl(ack_num_);

      if (tcp_proxy_.SimpleSendPkt(cfg_if_id_, pkt_info) < 0)
      {
        LogW(kClassName, __func__, "%s, unable to send any bytes.\n",
             flow_id_str_);
        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      }

      LogD(kClassName, __func__, "%s, sending reset.\n", flow_id_str_);
    }
  }

  prev_state_ = 0;
  state_      = TCP_CLOSE;

  CancelScheduledEvent(rto_time_);
  CancelScheduledEvent(time_wait_time_);

  socket_mgr_.MarkSocketForRemoval(this);

  return 0;
}

//============================================================================
void Socket::ConfigureUtilityFn(string utility_def, QueueDepths& queue_depths)
{
  size_t  type_str_pos  = utility_def.find("type=");
  if (type_str_pos == string::npos)
  {
    LogF(kClassName, __func__, "Invalid utility definition.\n");
  }

  size_t  type_str_end_pos = utility_def.find(":", type_str_pos);
  if (type_str_end_pos == string::npos)
  {
    LogF(kClassName, __func__, "Invalid utility definition.\n");
  }

  string  utility_def_type = utility_def.substr(type_str_pos + 5,
                                                type_str_end_pos - 5);

  if (utility_def_type != "LOG")
  {
    LogF(kClassName, __func__, "%s, %s utility function not supported.\n",
         flow_id_str_, utility_def_type.c_str());
    return;
  }

  flow_utility_fn_ =
    new (std::nothrow) iron::LogUtility(queue_depths, bin_idx_,
                                        tcp_proxy_.k_val(), flow_tag_);

  if (flow_utility_fn_ == NULL)
  {
    LogF(kClassName, __func__, "Unable to allocate memory for utility "
               "function\n");
    return;
  }

  ConfigInfo  ci;
  List<string>  tokens;
  StringUtils::Tokenize(utility_def, ":", tokens);
  List<string>::WalkState tokens_ws;
  tokens_ws.PrepareForWalk();

  string  token;
  while (tokens.GetNextItem(tokens_ws, token))
  {
    if (token.find("=") == string::npos)
    {
      continue;
    }

    List<string>  token_values;
    StringUtils::Tokenize(token, "=", token_values);

    if (token_values.size() == 2)
    {
      string  name;
      token_values.Pop(name);
      string  value;
      token_values.Peek(value);
      ci.Add(name, value);
    }
  }

  flow_utility_fn_->Initialize(ci);
}

//============================================================================
void Socket::ResetUtilityFn(string utility_def, QueueDepths& queue_depths)
{
  if (flow_utility_fn_)
  {
    LogD(kClassName, __func__, "%s, Resetting utility function.\n",
         flow_id_str_);
    delete flow_utility_fn_;
    flow_utility_fn_ = NULL;
    ConfigureUtilityFn(utility_def, queue_depths);
  }
}

//============================================================================
void Socket::TurnFlowOff()
{
  if (flow_utility_fn_)
  {
    LogD(kClassName, __func__, "%s, Turning flow off.\n", flow_id_str_);
    flow_utility_fn_->set_flow_state(iron::FLOW_OFF);
  }
}

//============================================================================
bool Socket::CanAdmitPacket(Time& now)
{
  if (cfg_if_id_ == LAN)
  {
    LogF(kClassName, __func__, "%s, attempting to do IRON admission control "
         "on LAN side socket. Aborting...\n", flow_id_str_);
  }

  LogD(kClassName, __func__, "%s, now is %s, next admission time is %s, now "
       "+ burst interval is %s.\n", flow_id_str_,
       now.ToString().c_str(), next_admission_time_.ToString().c_str(),
       (now + min_burst_usec_.Multiply(kBurstIntervalMultiplier)).
       ToString().c_str());

  if (next_admission_time_ <=
      (now + min_burst_usec_.Multiply(kBurstIntervalMultiplier)))
  {
    double  rate = flow_utility_fn_->GetSendRate();

    if (rate > 0.0)
    {
      last_send_rate_ = rate;

      // Make sure that if the rate is very low, we'll try again in a second
      // or so.
      if (last_send_rate_ < kMinSendRate)
      {
        last_send_rate_ = kMinSendRate;
      }

      return true;
    }
  }

  return false;
}

//============================================================================
int Socket::Write(PktInfo* pkt_info)
{
  if ((pkt_info == NULL) || (pkt_info->pkt == NULL))
  {
    LogW(kClassName, __func__, "%s, invalid PktInfo provided as parameter.\n",
         flow_id_str_);
    return 0;
  }

  LogD(kClassName, __func__, "%s, transmitting pkt with len %zd bytes.\n",
       flow_id_str_, pkt_info->pkt->GetLengthInBytes());

  size_t  tot_length_bytes = pkt_info->pkt->GetLengthInBytes();

  if (cfg_if_id_ == LAN)
  {
    return tcp_proxy_.SendToLan(pkt_info->pkt);
  }

  if (pkt_info->pkt->ref_cnt() > 1)
  {
    // The Packet has already been provided to the BPF and the BPF still
    // has a reference to it. The near-term solution when this occurs is
    // to clone the Packet, recycle the original Packet in the TCP Proxy,
    // and provide the clone to the BPF.
    Packet*  packet_clone = packet_pool_.Clone(pkt_info->pkt, false,
                                               iron::PACKET_NO_TIMESTAMP);
    packet_pool_.Recycle(pkt_info->pkt);
    pkt_info->pkt = packet_clone;
  }

  // We always make a shallow copy as the Packet may need to be
  // retransmitted by the TCP Proxy in the future.
  packet_pool_.PacketShallowCopy(pkt_info->pkt);
  packet_pool_.AssignPacketId(pkt_info->pkt);

  // \todo Restructure Send to allow sending multiple packets at once.
  if (!tcp_proxy_.SendToWan(pkt_info->pkt))
  {
    // If the Send() method fails, we must call Recycle(). This will
    // reclaim the shallow copy that we made above.
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(pkt_info->pkt);
    return 0;
  }

  // If the Send() method succeeds, the Packet in shared memory is being
  // handed over to the backpressure forwarder, so we cannot Recycle() it.

  // XXX Add function to gather statistics. Record rate lookup when
  // CanAdmitPacket is called and use it here (as this should only be called
  // after that method). Add function to update admission times. This function
  // gets really small....

  LogD(kClassName, __func__, "%s, rate is %f, bin depth is %" PRIu32 ".\n",
       flow_id_str_, last_send_rate_, tcp_proxy_.GetBinDepth(bin_idx_));

  // Gather flow statistics.
  IncrementSentBytes(pkt_info->data_len);

  double  instantaneous_utility =
    flow_utility_fn_->ComputeUtility(last_send_rate_);
  cumulative_utility_ += instantaneous_utility;
  utility_            += instantaneous_utility;
  utility_sample_cnt_++;

  LogD(kClassName, __func__, "%s, computed instantaneous utility is %f.\n",
       flow_id_str_, instantaneous_utility);

  // Compute the serialization time for the transmission.
  Time serialization_time(static_cast<double>(tot_length_bytes) * 8.0 /
                          last_send_rate_);

  // Adjust the next admission time.
  if (flow_is_idle_ == true)
  {
    LogW(kClassName, __func__, "%s, flow is idle.\n", flow_id_str_);

    next_admission_time_ = Time::Now() + serialization_time;
    flow_is_idle_        = false;
  }
  else
  {
    next_admission_time_ = next_admission_time_.Add(serialization_time);
  }

  LogD(kClassName, __func__, "%s, send rate is %f, now is %s, next admission "
       "time is %s.\n", flow_id_str_, last_send_rate_,
       Time::Now().ToString().c_str(),
       next_admission_time_.ToString().c_str());

  return tot_length_bytes;
}

//============================================================================
void Socket::UpdateHeaderForMoveToPeer(PktInfo* pkt_info)
{
  uint8_t  opt_buf[kMaxTcpOptLen];
  size_t   new_tcp_opt_len = peer_->GetOptions(opt_buf, kMaxTcpOptLen);

  struct iphdr*   ip_hdr  = pkt_info->pkt->GetIpHdr();
  struct tcphdr*  tcp_hdr = pkt_info->pkt->GetTcpHdr();

  // Before we do any work here, we grab the TCP checksum from the received
  // packet and compute the checksum over just the TCP header for the received
  // packet and stash both of these values in the PktInfo object. The values
  // will be used to incrementally update the TCP checksum when the peer
  // transmits the packet.
  pkt_info->orig_tcp_cksum = tcp_hdr->th_sum;
  uint16_t  tcp_hdr_cksum  = 0;
  if (!pkt_info->pkt->ComputeTransportChecksum(tcp_hdr->th_off * 4,
                                               tcp_hdr_cksum))
  {
    // This should never fail. If it does, something is terribly wrong.
    LogF(kClassName, __func__, "%s, error computing received packet's TCP "
         "header checksum.\n", flow_id_str_);
  }
  else
  {
    pkt_info->orig_tcp_hdr_cksum = tcp_hdr_cksum;
  }

  // If the socket is configured for seamless server handoff, fix the address
  // and port in the packet. For LAN side sockets the source address needs to
  // be modified and for WAN side sockets the destination needs to be
  // modified.
  if (do_seamless_handoff_)
  {
    if (cfg_if_id_ == LAN)
    {
      ip_hdr->daddr     = seamless_handoff_endpoint_.address();
      tcp_hdr->th_dport = seamless_handoff_endpoint_.port();
    }
    else
    {
      ip_hdr->saddr     = client_configured_server_endpoint_.address();
      tcp_hdr->th_sport = client_configured_server_endpoint_.port();
    }
  }

  // If the TCP option length is different, move the IP and TCP headers
  // appropriately in the Packet.
  uint16_t  tot_len     = ntohs(ip_hdr->tot_len);
  size_t    tcp_opt_len = (tcp_hdr->th_off << 2) - sizeof(struct tcphdr);

  if (new_tcp_opt_len < tcp_opt_len)
  {
    LogD(kClassName, __func__, "%s, new TCP option len (%zd) < original TCP "
         "option len (%zd).\n", flow_id_str_, new_tcp_opt_len, tcp_opt_len);

    // The new TCP header options are smaller than the existing TCP
    // options. Move the IP and TCP headers to the "right" in the Packet
    // buffer and remove the extra bytes from the beginning of the Packet.
    //
    // Move the TCP header.
    memmove(pkt_info->pkt->GetBuffer(sizeof(struct iphdr) +
                                     (tcp_opt_len - new_tcp_opt_len)),
            tcp_hdr, sizeof(struct tcphdr));

    // Move the IP header.
    memmove(pkt_info->pkt->GetBuffer(tcp_opt_len - new_tcp_opt_len),
            ip_hdr, sizeof(struct iphdr));

    // Remove the extra bytes from the beginning of the Packet to
    // accommodate the decreased size of the TCP options. This will
    // correctly update the length of the Packet in bytes.
    if (!pkt_info->pkt->RemoveBytesFromBeginning(tcp_opt_len -
                                                 new_tcp_opt_len))
    {
      LogF(kClassName, __func__, "%s, unable to remove %zd bytes from "
           "Packet.\n", flow_id_str_, (tcp_opt_len - new_tcp_opt_len));
    }

    // Adjust the data offset in the TCP header.
    pkt_info->pkt->GetTcpHdr()->th_off =
      (sizeof(struct tcphdr) + new_tcp_opt_len) >> 2;

    // Adjust the total length in the IP header.
    pkt_info->pkt->GetIpHdr()->tot_len =
      htons(tot_len - (tcp_opt_len - new_tcp_opt_len));
  }
  else if (new_tcp_opt_len > tcp_opt_len)
  {
    LogD(kClassName, __func__, "%s, original TCP option len (%zd) < new TCP "
         "option len (%zd).\n", flow_id_str_, tcp_opt_len, new_tcp_opt_len);

    // The new TCP header options are bigger than the existing TCP
    // options. Grow the Packet buffer and move the IP and TCP headers to
    // the "right" in the Packet buffer.
    //
    // Add bytes to the beginning of the Packet buffer first to
    // accommodate the increased size of the TCP options. This will
    // correctly update the length of the Packet in bytes.
    if (!pkt_info->pkt->AddBytesToBeginning(new_tcp_opt_len -
                                            tcp_opt_len))
    {
      LogF(kClassName, __func__, "%s, unable to add %zd bytes to Packet of "
           "size %" PRIu32 ".\n", flow_id_str_,
           (new_tcp_opt_len - tcp_opt_len),
           pkt_info->pkt->GetLengthInBytes());
    }

    // Move the IP header.
    memmove(pkt_info->pkt->GetBuffer(), ip_hdr, sizeof(struct iphdr));

    // Move the TCP header.
    memmove(pkt_info->pkt->GetBuffer(sizeof(struct iphdr)), tcp_hdr,
            sizeof(struct tcphdr));

    // Adjust the data offset in the TCP header.
    pkt_info->pkt->GetTcpHdr()->th_off =
      (sizeof(struct tcphdr) + new_tcp_opt_len) >> 2;

    // Adjust the total length in the IP header.
    pkt_info->pkt->GetIpHdr()->tot_len =
      htons(tot_len - (new_tcp_opt_len - tcp_opt_len));
  }

  // The headers are now in the correct location, so copy the options into
  // the Packet.
  size_t  tcp_opt_offset = sizeof(struct iphdr) + sizeof(struct tcphdr);
  memcpy(pkt_info->pkt->GetBuffer(tcp_opt_offset), opt_buf,
         new_tcp_opt_len);
}

//============================================================================
void Socket::CheckAndClosePeerIfWarranted()
{
  // If the out of sequence buffer is empty and the peer has sent a FIN, the
  // peer can be closed.
  if (((state_ == TCP_NASCENT) ||
       (state_ == TCP_CLOSE) ||
       (!out_seq_buf_->size_bytes())) &&
      (peer_->gw_flags() & PROXY_SEND_FIN))
  {
    peer_->gw_flags() &= ~PROXY_SEND_FIN;

    LogI(kClassName, __func__, "%s, closing peer...\n", flow_id_str_);

    peer_->Close();
  }
}

//============================================================================
void Socket::Flush()
{
  uint32_t  send_buf_bytes_in_buffer = send_buf_->BytesInBuffer();

  // If there is pending data, send it.
  if (send_buf_bytes_in_buffer < send_buf_->max_size_bytes())
  {
    // We can enqueue data to go out, give it a shot.
    if (send_buf_bytes_in_buffer > 0)
    {
      flags_ |= TH_PUSH;

      send_buf_->SetPacketsPushFlag();
    }

    PktInfo*  pkt_info = pkt_info_pool_.Get();
    if (!pkt_info)
    {
      return;
    }

    // If we're here, we've got a PktInfo so we we've managed to enqueue all
    // our data to send. Build a FIN if necessary.
    if (send_buf_bytes_in_buffer >= send_buf_->max_size_bytes())
    {
      pkt_info_pool_.Recycle(pkt_info);
      return;
    }

    // Must allocate PktInfo before calling BuildHdr and pass it in.  This
    // is a hack to say that this segment will be queued for transmission,
    // not sent immediately. As a result, the maximum sequence number BUILT,
    // not SENT should be used. (If this were an ACK, we would allow
    // BuildHdr to allocate the PktInfo, and use the sequence number most
    // recently SENT in the header.)
    flags_    = TH_ACK | TH_FIN;
    last_ack_ = ack_num_;

    if (peer_)
    {
      last_uwe_ = peer_->send_buf_->uwe();
    }
    else
    {
      last_uwe_ = ack_num_ + peer_send_buf_max_bytes_;
    }

    BuildHdr(pkt_info, 0, false);
    send_buf_->Enqueue(pkt_info);

    Send(NULL, false);
  }
}

//============================================================================
void Socket::Reset(const struct tcphdr* tcp_hdr)
{
  his_port_  = tcp_hdr->th_sport;
  my_port_   = tcp_hdr->th_dport;

  if (tcp_hdr->th_flags & TH_ACK)
  {
    ack_num_  = ntohl(tcp_hdr->th_seq) + 0;
    seq_sent_ = ntohl(tcp_hdr->th_ack) + 0;
    snd_max_  = ntohl(tcp_hdr->th_ack) + 0;
    seq_num_  = ntohl(tcp_hdr->th_ack) + 0;
  }
  else
  {
    ack_num_  = ntohl(tcp_hdr->th_seq) + 0;
    seq_sent_ = 0;
    snd_max_  = 0;
    seq_num_  = 0;
  }

  if (peer_)
  {
    last_uwe_ = peer_->send_buf_->uwe();
  }
  else
  {
    last_uwe_ = ack_num_ + peer_send_buf_max_bytes_;
  }

  state_ = TCP_ESTABLISHED;
  Abort();
}

//============================================================================
void Socket::SetProxyOptions()
{
  uint32_t  buffer_size      = kDefaultBufferSize;
  uint32_t  peer_buffer_size = kDefaultBufferSize;

  int       i_val;
  uint32_t  l_val;

  // Set the socket's send buffer size.
  l_val = proxy_config_.GetIfBufSize(cfg_if_id_);
  if (l_val != 0)
  {
    buffer_size = l_val;
  }
  send_buf_->set_max_size_bytes(buffer_size);

  l_val = proxy_config_.GetIfMaxBufSize(cfg_if_id_ == WAN ? LAN : WAN);
  if (l_val != 0)
  {
    peer_buffer_size = l_val;
  }
  if (adaptive_buffers_)
  {
    send_buf_->set_adaptive_buffer_size_limit(l_val);
  }
  peer_send_buf_max_bytes_ = peer_buffer_size;

  // If we're doing window scaling and haven't sent a SYN yet, can go ahead
  // and recompute the window scale factor. Since this is set only on the SYN,
  // if the SYN's gone out, must not change the value, regardless of the
  // buffer size.
  if ((state_ < TCP_SYN_SENT) && (sock_flags_ & TF_REQ_SCALE))
  {
    // For now, we set the advertised window scaling to be the mimimum of 8
    // and TCP_MAX_WINSHIFT. This is because with an MTU of 1332 bytes we will
    // be ensured to advertise a window that is a multiple of the MSS.
    request_r_scale_  = 8 < TCP_MAX_WINSHIFT ? 8 : TCP_MAX_WINSHIFT;

    // request_r_scale_ = 0;

    // while ((request_r_scale_ < TCP_MAX_WINSHIFT) &&
    //        ((TCP_MAXWIN << request_r_scale_) < (int)peer_send_buf_max_bytes_))
    // {
    //   request_r_scale_++;
    // }
  }

  // Set the socket's congestion control configuration items.
  switch (proxy_config_.GetIfCongCtrlAlg(cfg_if_id_))
  {
    case NO_CONGESTION_CONTROL:
      capabilities_ &= ~CAP_CONGEST;
      ClearCcAlgSelection();
      cc_algs_[NO_CONGESTION_CONTROL]->Select();
      break;

    case VJ_CONGESTION_CONTROL:
      ClearCcAlgSelection();
      cc_algs_[VJ_CONGESTION_CONTROL]->Select();
      break;
  }

  // Set the socket's ACK behavior.
  if ((i_val = proxy_config_.GetIfAckBehavior(cfg_if_id_)) != -1)
  {
    ack_freq_ = i_val;
  }

  // Set the socket's ACK delay value.
  if ((i_val = proxy_config_.GetIfAckDelay(cfg_if_id_)) != 0)
  {
    ack_delay_us_ = i_val * 1000;
  }

  // Set the socket's Timestamp behavior.
  if ((i_val = proxy_config_.GetIfTs(cfg_if_id_)) == 0)
  {
    // Can't set option after initiating connection.
    if ((state_ == TCP_NASCENT) || (state_ == TCP_CLOSE))
    {
      capabilities_ &= ~CAP_TIMESTAMP;
      sock_flags_   &= ~TF_REQ_TSTMP;
    }
  }

  // Set the socket's SACK behavior.
  if (((cfg_if_id_ == WAN) &&
       (i_val = proxy_config_.GetIfSack(cfg_if_id_)) == 1))
  {
    // Can't set option after initiating connection.
    if ((state_ == TCP_NASCENT) || (state_ == TCP_CLOSE))
    {
      capabilities_ |= CAP_SACK;
      sock_flags_   |= TF_REQ_SACK;
    }
  }

  // Set the socket's NODELAY behavior.
  if ((i_val = proxy_config_.GetIfNoDelay(cfg_if_id_)) == 1)
  {
    sock_flags_ |= SOCK_NDELAY;
  }

  // Set the socket's RTT Max Shift value.
  t_rxtmaxshift_ = proxy_config_.rtt_max_shift();

  // Set the socket's mtu value
  // For now, don't let user configure LAN-facing socket's MTU. We do this so
  // that we ensure that the advertised window to the application is a
  // multiple of the MSS which will eliminate overhead for short packets.
  if (cfg_if_id_ != LAN)
  {
    mtu_ = proxy_config_.GetIfMtu(cfg_if_id_);
  }
  else
  {
    if ((capabilities_ & CAP_TIMESTAMP) == CAP_TIMESTAMP)
    {
      // The socket being configured is the LAN-facing socket and timestamps
      // will be included in the TCP header. Since we are including
      // timestamps, we will increase the MTU by 12 bytes (size of the
      // timestamp option). We do this because the MSS is decreased by the
      // size of any TCP header options. We still want to have a payload size
      // of 1280 bytes so we must increase the size of the MTU here to ensure
      // that. NOTE: in order avoid issues with SACK blocks in the TCP header
      // options we have disabled SACK on the LAN-facing socket.
      mtu_ += 12;
    }
  }
}

//============================================================================
void Socket::SetMss(uint32_t offer)
{
  uint32_t  mss;
  mss = (mtu_) ?
    mtu_ - sizeof(struct tcphdr) - sizeof(struct iphdr) :
    MSS_DEFAULT;

  t_srtt_   = (int)((proxy_config_.GetIfInitialRto(cfg_if_id_) * 1000000) <<
                    TCP_RTT_SHIFT);
  t_rttvar_ = (int)(t_srtt_ / 2);
  t_rxtcur_ = t_srtt_;

  if (t_srtt_ == 0)
  {
    t_srtt_   = initial_rtt_ << TCP_RTT_SHIFT;
    t_rttvar_ = (int)(t_srtt_ / 2);
    t_rxtcur_ = t_srtt_;
  }

  if ((t_srtt_ == 0) && (initial_rtt_))
  {
    // Note: this isn't the default case, since the default rtt value (in
    // initial_rtt_) is 0.  This conforms to Stevens, where the initial
    // variance is 3s, and the inital RTO is 6s.
    t_rttvar_ = initial_rtt_var_ << TCP_RTTVAR_SHIFT;
    t_rxtcur_ = initial_rto_ << TCP_RTT_SHIFT;
  }
  else
  {
    // This is the 'default' case.  If there's no variance in the socket
    // structure but there IS a default variance, use the default variance
    if ((t_rttvar_ == 0) && (initial_rtt_var_))
    {
      t_rttvar_ = initial_rtt_var_ << TCP_RTTVAR_SHIFT;
      t_rxtcur_ = initial_rto_;
    }
  }

  // If the other side specified an mss, it's our max.
  if (offer)
  {
    mss = (mss < offer) ? mss : offer;

    // Save the offer for MSS value
    remote_mss_offer_ = offer;
  }
  else
  {
    remote_mss_offer_ = MSS_DEFAULT;
  }

  mss = (mss > MSS_MIN) ? mss : MSS_MIN;
  mss = mss & ~1;

  if (send_buf_->max_size_bytes() > (1 << 16))
  {
    snd_ssthresh_ = (1 << 30);
  }
  else
  {
    snd_ssthresh_ = (1 << 16);
  }

  sock_flags_ &= ~TF_CC_LINEAR;
  t_maxseg_     = mss;
  max_data_    = t_maxseg_ - GetTcpHdrLen();
}

//============================================================================
int Socket::GetTcpHdrLen()
{
  if ((sock_flags_ & TF_TSTMPING) == TF_TSTMPING)
  {
    return 12;
  }
  else
  {
    return 0;
  }
}

//============================================================================
void Socket::UpdateScheduledAdmissionEvent(Time& now)
{
  if (cfg_if_id_ == LAN)
  {
    return;
  }

  double  new_rate =
    flow_utility_fn_->GetSendRate();

  if (new_rate < kMinSendRate)
  {
    new_rate = kMinSendRate;
  }

  // Adjust the next_admission_time in the socket.
  Time  next_sched_socket_svc_time = tcp_proxy_.next_sched_socket_svc_time();
  Time  admission_target_time = next_admission_time_;
  Time  admission_delta       = admission_target_time -
    next_sched_socket_svc_time;

  if (admission_delta > Time())
  {
    Time
      next_target_time(static_cast<double>(admission_delta.GetTimeInUsec()) *
                       last_send_rate_ / (new_rate * 1000000.0));

    next_target_time =
      next_target_time.Add(next_sched_socket_svc_time);
    next_admission_time_ = next_target_time;

    LogD(kClassName, __func__, "%s, updated admission time: next scheduled "
         "socket service time is %s, original admission time is %s, new "
         "admission time is %s, last send rate is %f, new send rate is %f.\n",
         flow_id_str_, next_sched_socket_svc_time.ToString().c_str(),
         admission_target_time.ToString().c_str(),
         next_admission_time_.ToString().c_str(), last_send_rate_, new_rate);
  }
  else
  {
    LogD(kClassName, __func__, "%s, next admission time is in the past, now "
         "is %s, next admission time is %s.\n", flow_id_str_,
         now.ToString().c_str(),
         next_admission_time_.ToString().c_str());
  }

  // Finally, save the new old rate.
  last_send_rate_ = new_rate;
}

//============================================================================
void Socket::InvertTunnelHdrs()
{
  // For now, we only support VXLAN tunnels. We need to swap:
  //
  // - the source and destination addresses in the outer IP header
  // - the destination and source MAC addresses in the inner Ethernet header
  if (tunnel_hdrs_ == NULL)
  {
    LogE(kClassName, __func__, "Socket has no stored tunnel headers. Unable "
         "to invert header information.\n");
    return;
  }

  // Swap the source address and destination address in the outer IPv4
  // header.
  struct iphdr*  ip_hdr   = reinterpret_cast<struct iphdr*>(tunnel_hdrs_);
  uint32_t       tmp_addr = ip_hdr->saddr;

  ip_hdr->saddr = ip_hdr->daddr;
  ip_hdr->daddr = tmp_addr;

  // Swap the destination MAC address and source MAC address in the inner
  // Ethernet header.
  struct ethhdr*  eth_hdr = reinterpret_cast<struct ethhdr*>(
    tunnel_hdrs_ + 20 + 8 + 8);
  uint8_t   tmp_eth_addr[ETH_ALEN];

  memcpy(tmp_eth_addr, eth_hdr->h_dest, ETH_ALEN);
  memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
  memcpy(eth_hdr->h_source, tmp_eth_addr, ETH_ALEN);
}

//============================================================================
void Socket::IncrementSentBytes(uint32_t sent_bytes)
{
  sent_pkt_cnt_++;
  cumulative_sent_pkt_cnt_++;
  sent_bytes_cnt_            += sent_bytes;
  cumulative_sent_bytes_cnt_ += sent_bytes;
}

//============================================================================
void Socket::IncrementRcvdBytes(uint32_t rcvd_bytes)
{
  rcvd_pkt_cnt_++;
  cumulative_rcvd_pkt_cnt_++;
  rcvd_bytes_cnt_            += rcvd_bytes;
  cumulative_rcvd_bytes_cnt_ += rcvd_bytes;
}

//============================================================================
void Socket::WriteStats(string& log_str, Writer<StringBuffer>* writer)
{
  // The collected statistics for a flow are reported via the following
  // name/value pairs.
  //
  //   "flow_id" : "xxx.xxx.xxx.xxx:aaaaa -> yyy.yyy.yyy.yyy:bbbb",
  //   "priority" : xx.xx,
  //   "bin_id" : x,
  //   "flow_state" : x,
  //   "cumulative_sent_pkt_cnt" : xx,
  //   "cumulative_sent_bytes_cnt" : xx,
  //   "cumulative_acked_bytes" : xx,
  //   "send_rate_bps" : xx.xx,
  //   "send_rate_pps" : xx.xx,
  //   "cumulative_rcvd_pkt_cnt" : xx,
  //   "cumulative_rcvd_bytes_cnt" : xx,
  //   "recv_rate_bps" : xx.xx,
  //   "recv_rate_pps" : xx.xx,
  //   "ave_instantaneous_utility" : xx.xx
  //   "avg_pkt_delay_ms" : xx

  Time      now           = Time::Now();
  double    send_rate_bps = 0.0;
  double    send_pps      = 0.0;
  double    recv_rate_bps = 0.0;
  double    recv_pps      = 0.0;
  uint64_t  delta_time_us = 0.0;

  // Compute the average send/receive pps and rates in bps for the collection
  // interval.
  if (now > last_report_time_)
  {
    delta_time_us = (now - last_report_time_).GetTimeInUsec();

    send_rate_bps = static_cast<double>(
      (sent_bytes_cnt_ * 8 * 1000000.0) / delta_time_us);

    send_pps = static_cast<double>((sent_pkt_cnt_ * 1000000.0) /
                                   delta_time_us);

    recv_rate_bps = static_cast<double>((rcvd_bytes_cnt_ * 8 * 1000000.0) /
                                        delta_time_us);

    recv_pps = static_cast<double>((rcvd_pkt_cnt_ * 1000000.0) /
                                   delta_time_us);
  }

  // Compute the average instantaneous utility for the collection interval.
  if (utility_sample_cnt_ != 0)
  {
    ave_utility_ = utility_ / static_cast<double>(utility_sample_cnt_);
  }
  else
  {
    ave_utility_ = 0.0;
  }

  // Compute the average packet delay for the collection interval.
  if (pkt_delay_sample_cnt_ != 0)
  {
    ave_pkt_delay_ms_ = cumulative_pkt_delay_ms_ / pkt_delay_sample_cnt_;
  }
  else
  {
    ave_pkt_delay_ms_ = 0;
  }

  int flow_state =  static_cast<int>(flow_utility_fn_->flow_state());

  // Append the collected statistics to the log string, if configured to do
  // so.
  if (tcp_proxy_.log_stats())
  {
    log_str.append(
      StringUtils::FormatString(256, "'%s -> %s':{",
                                stats_src_endpt_.ToString().c_str(),
                                stats_dst_endpt_.ToString().c_str()));

    log_str.append(
      StringUtils::FormatString(256, "'prio':'%f', ",
                                flow_utility_fn_->priority()));

    if (bin_map_.IsMcastBinIndex(bin_idx_))
    {
      // MCAST TODO: bin_id is the wrong title, and leads to ambiguity (since
      // mcast ids may be equal to bin ids).
      log_str.append(
        StringUtils::FormatString(256, "'bin_id':'%" PRIMcastId "', ",
                                  bin_map_.GetMcastId(bin_idx_)));
    }
    else
    {
      log_str.append(
        StringUtils::FormatString(256, "'bin_id':'%" PRIBinId "', ",
                                  bin_map_.GetPhyBinId(bin_idx_)));
    }


    log_str.append(
      StringUtils::FormatString(256, "'flow_state':'%" PRIu8 "', ", flow_state));

    log_str.append(
      StringUtils::FormatString(256, "'sent_pkts':'%" PRIu64 "', ",
                                cumulative_sent_pkt_cnt_));

    log_str.append(
      StringUtils::FormatString(256, "'sent_bytes':'%" PRIu64
                                "', ", cumulative_sent_bytes_cnt_));

    log_str.append(
      StringUtils::FormatString(256, "'cumulative_acked_bytes':'%" PRIu32
                                "',", send_buf_->cum_acked_bytes()));

    log_str.append(
      StringUtils::FormatString(256, "'sent_rate_bps':'%f', ", send_rate_bps));

    log_str.append(
      StringUtils::FormatString(256, "'sent_rate_pps':'%f', ", send_pps));

    log_str.append(
      StringUtils::FormatString(256, "'rcvd_pkts':'%" PRIu64 "', ",
                                cumulative_rcvd_pkt_cnt_));

    log_str.append(
      StringUtils::FormatString(256, "'rcvd_bytes':'%" PRIu64
                                "', ", cumulative_rcvd_bytes_cnt_));

    log_str.append(
      StringUtils::FormatString(256, "'rcvd_rate_bps':'%f', ", recv_rate_bps));

    log_str.append(
      StringUtils::FormatString(256, "'rcvd_rate_pps':'%f', ", recv_pps));

    log_str.append(
      StringUtils::FormatString(256, "'utility':'%f', ",
                                ave_utility_));

    log_str.append(
      StringUtils::FormatString(256, "'avg_pkt_delay_ms':'%" PRIu32 "'}",
                                ave_pkt_delay_ms_));
  }

  // Append the collected statistics, if required.
  if (writer)
  {
    // Append "flow_id" :
    writer->Key("flow_id");

    // Append the flow id, xxx.xxx.xxx.xxx:aaaaa -> yyy.yyy.yyy.yyy:bbbbb
    writer->String(
      StringUtils::FormatString(256, "%s -> %s",
                                stats_src_endpt_.ToString().c_str(),
                                stats_dst_endpt_.ToString().c_str()).c_str());

    // Append "priority" : xx.xx
    writer->Key("priority");
    writer->Double(flow_utility_fn_->priority());

    if (bin_map_.IsMcastBinIndex(bin_idx_))
    {
      // MCAST TODO This is ambiguous and mis-titled.
      // Append "bin_id" : x
      writer->Key("bin_id");
      writer->Uint(bin_map_.GetMcastId(bin_idx_));
    }
    else
    {
      // Append "bin_id" : x
      writer->Key("bin_id");
      writer->Uint(bin_map_.GetPhyBinId(bin_idx_));
    }

    // Append "flow_state: x
    writer->Key("flow_state");
    writer->Int(flow_state);

    // Append "cumulative_sent_pkt_cnt" : xx
    writer->Key("cumulative_sent_pkt_cnt");
    writer->Uint64(cumulative_sent_pkt_cnt_);

    // Append "cumulative_sent_bytes_cnt" : xx
    writer->Key("cumulative_sent_bytes_cnt");
    writer->Uint64(cumulative_sent_bytes_cnt_);

    // Append "cumulative_acked_bytes" : xx
    writer->Key("cumulative_acked_bytes");
    writer->Uint64(send_buf_->cum_acked_bytes());

    // Append "send_rate_bps" : xx.xx
    writer->Key("send_rate_bps");
    writer->Double(send_rate_bps);

    // Append "send_pps" : xx.xx
    writer->Key("send_rate_pps");
    writer->Double(send_pps);

    // Append "cumulative_rcvd_pkt_cnt" : xx
    writer->Key("cumulative_rcvd_pkt_cnt");
    writer->Uint64(cumulative_rcvd_pkt_cnt_);

    // Append "cumulative_rcvd_bytes_cnt" : xx
    writer->Key("cumulative_rcvd_bytes_cnt");
    writer->Uint64(cumulative_rcvd_bytes_cnt_);

    // Append "recv_rate_bps" : xx.xx
    writer->Key("recv_rate_bps");
    writer->Double(recv_rate_bps);

    // Append "recv_pps" : xx.xx
    writer->Key("recv_rate_pps");
    writer->Double(recv_pps);

    // Append "ave_instantaneous_utility" : xx.xx
    writer->Key("ave_instantaneous_utility");
    writer->Double(ave_utility_);

    // Append "avg_pkt_delay_ms" : xx
    writer->Key("avg_pkt_delay_ms");
    writer->Uint64(ave_pkt_delay_ms_);
  }

  // Reset the per interval statistics.
  sent_pkt_cnt_            = 0;
  sent_bytes_cnt_          = 0;
  rcvd_pkt_cnt_            = 0;
  rcvd_bytes_cnt_          = 0;
  utility_                 = 0.0;
  utility_sample_cnt_      = 0;
  cumulative_pkt_delay_ms_ = 0;
  pkt_delay_sample_cnt_    = 0;
  last_report_time_        = now;
}

//============================================================================
void Socket::SilentAbort()
{
  LogI(kClassName, __func__, "%s, performing a silent abort, server %s is "
       "unreachable.\n", flow_id_str_,
       seamless_handoff_endpoint_.ToString().c_str());

  tcp_proxy_.MarkServerAsUnreachable(seamless_handoff_endpoint_);
  tcp_proxy_.Reconnect(orig_syn_pkt_info_->pkt);

  // The ownership of the socket's original SYN packet has been transferred to
  // the TCP Proxy. We must ensure that it doesn't get recycled.
  orig_syn_pkt_info_->pkt = NULL;
  pkt_info_pool_.Recycle(orig_syn_pkt_info_);

  orig_syn_pkt_info_ = NULL;

  socket_mgr_.MarkSocketForRemoval(this);
}

//============================================================================
void Socket::AckFin()
{
  // We are ACKing a FIN packet that has been received. The socket will
  // transition to the next state. This transition is based on the current
  // state and possibly the state of the peer socket.
  switch (state_)
  {
    case TCP_ESTABLISHED:
      // The current state is TCP_ESTABLISHED and we are sending an ACK for a
      // received FIN. The next state is TCP_CLOSE_WAIT.
      prev_state_  = state_;
      state_       = TCP_CLOSE_WAIT;

      LogD(kClassName, __func__, "%s, transitioning from state "
           "TCP_ESTABLISHED to TCP_CLOSE_WAIT.\n", flow_id_str_);

      break;

    case TCP_FIN_WAIT1:
    {
      if (peer_->state_ == TCP_CLOSING)
      {
        LogD(kClassName, __func__, "%s, transitioning from state "
             "TCP_FIN_WAIT1 to TCP_CLOSING.\n", flow_id_str_);

        prev_state_ = state_;
        state_      = TCP_CLOSING;
      }
      else
      {
        LogD(kClassName, __func__, "%s, transitioning from state "
             "TCP_FIN_WAIT1 to TCP_TIME_WAIT.\n", flow_id_str_);

        prev_state_ = state_;
        state_      = TCP_TIME_WAIT;

        timeout_    = k2MslTimeout;

        Time  duration(static_cast<time_t>(k2MslTimeout));
        ScheduleTimeWaitEvent(duration);
      }
      break;
    }

    case TCP_FIN_WAIT2:
    {
      LogD(kClassName, __func__, "%s, transitioning from state TCP_FIN_WAIT2 "
           "to TCP_TIME_WAIT.\n", flow_id_str_);

      prev_state_ = state_;
      state_      = TCP_TIME_WAIT;

      timeout_    = k2MslTimeout;

      Time  duration(static_cast<time_t>(k2MslTimeout));
      ScheduleTimeWaitEvent(duration);

      break;
    }

    default:
      LogW(kClassName, __func__, "%s, directed to ACK a FIN but current state "
           "is %d.\n", flow_id_str_, state_);

      return;
  }

  sock_flags_ |= SOCK_ACKNOW;
  BuildAndSendAck();
}

//============================================================================
void Socket::TimePkt(PktInfo* pkt_info)
{
  // Figure out if we should be timing the transmission or canceling the
  // timing of a transmission. We only do this if we aren't using the TCP
  // Timestamp Option.
  if (!((sock_flags_ & TF_REQ_TSTMP) && (sock_flags_ & TF_RCVD_TSTMP)))
  {
    if (t_rtt)
    {
      if (pkt_info->seq_num == t_rtseq)
      {
        // This is a retransmission of a packet that we were timing. Cancel
        // the timing of the packet.
        t_rtt = false;
      }
    }
    else
    {
      if ((pkt_info->data_len > 0) && pkt_info->rexmit_time.IsInfinite())
      {
        // We aren't currently timimg a transmission and this is not a
        // retransmission, so time it.
        t_rtt         = true;
        rtseq_ts_val_ = Time::Now();
        t_rtseq       = pkt_info->seq_num;
      }
    }
  }
}

//============================================================================
uint32_t Socket::SendPkt(PktInfo* pkt_info)
{
  uint32_t  now = Clock::ValueRough();

  int write_len_bytes = 0;

  // Adjust the packet timing, if necessary.
  TimePkt(pkt_info);

  // Update window and ack fields.
  UpdateWinSizeAndAckNum(pkt_info->pkt->GetTcpHdr());

  // Set the total length of the packet in the IP header.
  pkt_info->pkt->GetIpHdr()->tot_len =
    htons(pkt_info->pkt->GetLengthInBytes());

  // Update the checksums. For now, update the IP checksum for packets that
  // are not being tunneled by the IRON CATs. In the future, we may disable
  // this and offload it to the NIC.
  if (cfg_if_id_ == LAN)
  {
    pkt_info->pkt->UpdateIpChecksum();
  }

  // The TCP header may have been changed by our peer, as the LAN-side and
  // WAN-side options may be different. We need to ensure that the TCP
  // checksum is correct prior to transmission. First, compute the checksum
  // over the new TCP header. Then incrementally compute the new TCP checksum
  // according to the information in RFC1624. Consider the following notation,
  // identified in the RFC:
  //
  //   HC  - old checksum in header
  //   HC' - new checksum in header
  //   m   - old value of 16-bit field
  //   m'  - new value of 16-bit field
  //
  // Thus, according to RFC1624,
  //
  //   HC' = HC - ~m - m'
  //
  // We will extend this to work over values larger than a single 16-bit
  // value. Consider the following new notation:
  //
  //   h  - checksum of the original TCP header (in 1s complement)
  //   h' - checksum of the modified TCP header (in 1s complement)
  //
  // So, the new checksum in the header is:
  //
  //   HC' = HC - h - ~h'
  struct tcphdr*  tcp_hdr = pkt_info->pkt->GetTcpHdr();
  uint16_t        new_tcp_hdr_cksum = 0;
  if (!pkt_info->pkt->ComputeTransportChecksum(tcp_hdr->th_off * 4,
                                               new_tcp_hdr_cksum))
  {
    // This should never fail. If it does, something is terribly wrong.
    LogF(kClassName, __func__, "%s, error computing received packet's TCP "
         "header checksum.\n", flow_id_str_);
  }

  int32_t  new_tcp_cksum = pkt_info->orig_tcp_cksum -
    pkt_info->orig_tcp_hdr_cksum - (uint16_t)~new_tcp_hdr_cksum;

  // Add high 16 bits to low 16 bits and add back carry from top 16 bits to
  // low 16 bits.
  new_tcp_cksum  = (new_tcp_cksum >> 16) + (new_tcp_cksum & 0xffff);
  new_tcp_cksum += (new_tcp_cksum >> 16);

  tcp_hdr->th_sum = (unsigned short)new_tcp_cksum;

  // if (pkt_info->pkt->GetTcpHdr()->th_flags & TH_SYN)
  // {
  //   if (pkt_info->pkt->GetTcpHdr()->th_flags & TH_ACK)
  //   {
  //     LogW(kClassName, __func__, "tag: %" PRId32 ", sending SYN/ACK on %s IF "
  //          "with flow myport(%" PRIu16 ") hisport(%" PRIu16 ") seq_num_ (%"
  //          PRIu32 "), data len (%" PRIu32 ")\n",
  //          cfg_if_id_ == WAN ? (int32_t)flow_tag() : -(int32_t)flow_tag(),
  //          cfg_if_id_ == WAN ? "WAN" : "LAN", ntohs(my_port_), ntohs(his_port_),
  //          pkt_info->seq_num, pkt_info->data_len);
  //   }
  //   else
  //   {
  //     LogW(kClassName, __func__, "tag: %" PRId32 ", sending SYN on %s IF "
  //          "with flow myport(%" PRIu16 ") hisport(%" PRIu16 ") seq_num_ (%"
  //          PRIu32 "), data len (%" PRIu32 ")\n",
  //          cfg_if_id_ == WAN ? (int32_t)flow_tag() : -(int32_t)flow_tag(),
  //          cfg_if_id_ == WAN ? "WAN" : "LAN", ntohs(my_port_), ntohs(his_port_),
  //          pkt_info->seq_num, pkt_info->data_len);
  //   }
  // }

  LogD(kClassName, __func__, "%s, sending pkt with seq num (%" PRIu32
       "), data len (%" PRIu32 ")\n", flow_id_str_, pkt_info->seq_num,
       pkt_info->data_len);

  // If the socket is supporting encapsulated packets, we add the
  // encapsulating headers for:
  //   - All LAN-facing transmissions
  //   - WAN-facing transmissions if the SYN bit is set
  if (is_tunneled_)
  {
    LogD(kClassName, __func__, "Transmitting VXLAN tunneled packet.\n");

    if ((cfg_if_id_ == LAN) || (tcp_hdr->th_flags & TH_SYN))
    {
      LogD(kClassName, __func__, "Adding encapsulated packet headers.\n");

      // Add the encapsulating headers.
      if (!pkt_info->has_been_encapsulated)
      {
        LogD(kClassName, __func__, "Moving original packet bytes and "
             "prepending tunnel hdrs.\n");

        size_t   pkt_len_bytes     = pkt_info->pkt->GetLengthInBytes();
        size_t   enc_pkt_len_bytes = pkt_len_bytes + iron::kVxlanTunnelHdrLen;
        uint8_t* buf               = pkt_info->pkt->GetBuffer();
        memmove(buf + iron::kVxlanTunnelHdrLen, buf, pkt_len_bytes);
        memcpy(buf, tunnel_hdrs_, iron::kVxlanTunnelHdrLen);
        pkt_info->pkt->SetLengthInBytes(enc_pkt_len_bytes);
        pkt_info->has_been_encapsulated = true;
      }
      else
      {
        LogD(kClassName, __func__, "Prepending tunnel hdrs.\n");

        pkt_info->pkt->AddBytesToBeginning(iron::kVxlanTunnelHdrLen);
        memcpy(pkt_info->pkt->GetBuffer(), tunnel_hdrs_, iron::kVxlanTunnelHdrLen);
      }

      // Fix up the information in the VXLAN headers and recompute the
      // checksums.
      struct iphdr*   ip_hdr  = pkt_info->pkt->GetIpHdr();
      struct udphdr*  udp_hdr = pkt_info->pkt->GetUdpHdr();
      ip_hdr->tot_len  = htons(pkt_info->pkt->GetLengthInBytes());
      udp_hdr->uh_ulen = htons(ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4));
      pkt_info->pkt->UpdateChecksums();
    }
  }

  write_len_bytes = Write(pkt_info);

  if (write_len_bytes < 0)
  {
    write_len_bytes = 0;
  }

  if (write_len_bytes > 0)
  {
    if (write_len_bytes > 500)
    {
      total_sent_ += write_len_bytes;
      if (total_sent_ > 2000)
      {
        is_carrying_data_ = true;
      }
    }

    if (snd_wnd_ > pkt_info->data_len)
    {
      snd_wnd_ -= pkt_info->data_len;
    }
    else
    {
      snd_wnd_ = 0;
    }

    if (snd_awnd_ >= pkt_info->data_len)
    {
      snd_awnd_ -= pkt_info->data_len;
    }
    else
    {
      snd_awnd_ = 0;
    }

    if (snd_cwnd_ >= pkt_info->data_len)
    {
      snd_cwnd_ -= pkt_info->data_len;
    }
    else
    {
      snd_cwnd_ = 0;
    }

    if (pkt_info->timestamp == 1)
    {
      pkt_info->timestamp = now;
    }
    else
    {
      pkt_info->timestamp = 0;
    }

    // If this packet was retransmitted because of an RTO, we must set the
    // time for Vegas to function properly.
    if (SEQ_LT(seq_sent_, snd_max_))
    {
      pkt_info->timestamp = now;
    }
  }

  return write_len_bytes;
}

//============================================================================
void Socket::ProcessPktListenState(const struct iphdr* ip_hdr,
                                   const struct tcphdr* tcp_hdr)
{
  if (tcp_hdr->th_flags & TH_SYN)
  {
    HandleNewConnection(ip_hdr, tcp_hdr);
  }
}

//============================================================================
void Socket::ProcessPktListenState()
{
  if (orig_syn_pkt_info_ == NULL)
  {
    LogF(kClassName, __func__, "%s, expected an original SYN packet to be "
         "saved but it is NULL.\n", flow_id_str_);
    return;
  }

  struct iphdr*   ip_hdr  = orig_syn_pkt_info_->pkt->GetIpHdr();
  struct tcphdr*  tcp_hdr = orig_syn_pkt_info_->pkt->GetTcpHdr();

  ProcessPktListenState(ip_hdr, tcp_hdr);

  pkt_info_pool_.Recycle(orig_syn_pkt_info_);
  orig_syn_pkt_info_ = NULL;
}

//============================================================================
int Socket::ProcessPktSynSentState(const struct tcphdr* tcp_hdr)
{
  // Make sure that the parameters are valid.
  if (tcp_hdr == NULL)
  {
    LogW(kClassName, __func__, "%s, parameter tcp_hdr is NULL.\n",
         flow_id_str_);
    return -1;
  }

  uint32_t ack_hbo    = ntohl(tcp_hdr->th_ack);
  uint32_t seq_hbo    = ntohl(tcp_hdr->th_seq);
  uint32_t window_hbo = ntohs(tcp_hdr->th_win);

  uint16_t tcp_hdr_flags;

  tcp_hdr_flags = tcp_hdr->th_flags;

  if (tcp_hdr_flags & TH_SYN)
  {
    ack_num_++;
    timeout_ = kTimeout;

    if ((prev_state_ == TCP_CLOSE) && (tcp_hdr_flags & TH_ACK) &&
        (ack_hbo == (snd_una_ + 1)))
    {
      // This is a SYN,ACK in response to our active open.
      CancelScheduledEvent(rto_time_);

      // Initially, send an ACK fairly soon in case the ACK that opens up the
      // window gets lost.
      Time  duration(1.0);
      ScheduleKeepAliveEvent(duration);

      // Initialize the Congestion Control Algorithm implementations.
      for (int i = 0; i < MAX_CC_ALG_CNT; i++)
      {
        if (cc_algs_[i] != NULL)
        {
          cc_algs_[i]->Init();
        }
      }

      initial_seq_num_rec_ = seq_hbo;
      prev_state_          = state_;
      state_               = TCP_ESTABLISHED;
      flow_is_idle_        = true;

      sock_flags_ &= ~SOCK_ACKNOW;

      // We have an open connection, make the socket as writeable.
      snd_una_++;
      ack_delay_ = 0;
      ack_num_   = seq_hbo + 1;
      last_ack_  = ack_num_;

      // Free the SYN's Packet.
      LogD(kClassName, __func__, "%s, trimming send buffer to seq num %"
           PRIu32 "\n", flow_id_str_, (snd_una_ - 1));

      send_buf_->Trim(snd_una_);

      // If we are acked up, we can optionally reset the retransmission timer
      // values to their initial values (a la linux 2.0.32 kernel). We don't
      // care if rtt is set or not (retransmitted SYN?).
      /*
      if (SEQ_GEQ(ack_hbo, rt_seq_))
      {
        t_srtt_     = initial_rtt_ << (TCP_RTT_SHIFT);
        t_rtt_var_  = initial_rtt_var_ << TCP_RTTVAR_SHIFT;
        t_rx_t_cur_ = initial_rto_ << TCP_RTT_SHIFT;
      }
      */
      capabilities_ |= CAP_CONGEST;

      // Deselect the current congestion control algorithm and
      for (int i = 0; i < MAX_CC_ALG_CNT; i++)
      {
        if ((cc_algs_[i] != NULL) &&
            (cc_algs_[i]->selected()))
        {
          cc_algs_[i]->Deselect();
          break;
        }
      }

      // select the desired congestion control algorithm (VJ in this case).
      cc_algs_[VJ_CONGESTION_CONTROL]->Select();

      if ((sock_flags_ & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
          (TF_RCVD_SCALE | TF_REQ_SCALE))
      {
        snd_scale_ = requested_s_scale_;
        rcv_scale_ = request_r_scale_;
      }

      // Don't scale windows in SYN packets
      snd_awnd_ = window_hbo;

      // Make sure to initialize last_uwe_in_
      last_uwe_in_ = ack_hbo + snd_awnd_;;

      snd_wnd_ = MIN(snd_cwnd_, snd_awnd_ + snd_una_ - snd_max_);

      // We now need to "poke" our peer so it can finish its handshake. We set
      // our peer's starting sequence number (and associated data) equal to
      // the sequence number in the received packet.
      peer_->seq_num_     = ntohl(tcp_hdr->th_seq);
      peer_->snd_una_     = ntohl(tcp_hdr->th_seq);
      peer_->seq_sent_    = ntohl(tcp_hdr->th_seq);
      peer_->snd_max_     = ntohl(tcp_hdr->th_seq);
      peer_->last_uwe_in_ = ntohl(tcp_hdr->th_seq) +
        ntohs(peer_->orig_syn_pkt_info_->pkt->GetTcpHdr()->th_win);
      peer_->initial_seq_num_ = ntohl(tcp_hdr->th_seq);
      peer_->send_buf_->init_una_seq(ack_hbo);
      peer_->send_buf_->init_nxt_seq(ack_hbo);
      last_uwe_ = peer_->send_buf_->uwe();

      // Send the SYN/ACK out the peer socket.
      peer_->ProcessPktListenState();

      // Build an ACK in a Packet and send it. This logic is not quite right,
      // since we declare the connection open possibly without having sent
      // this ACK.
      PktInfo*  ack_pkt_info = NULL;
      if ((ack_pkt_info = BuildHdr(NULL, 0, true)))
      {
        Send(ack_pkt_info, false);

        pkt_info_pool_.Recycle(ack_pkt_info);
      }
    }
    else
    {
      // Not quite correct protection against old duplicate SYNs: We have
      // sent a SYN, To get to this point, we have sent a SYN and received a
      // SYN but the acknum on the incoming SYN is wrong... Neglecting
      // simultaneous opens, we should be sending a RST here and remaining
      // in the SYNSENT state.
      //
      // We need to check our state prior to this, if it was CLOSED:
      //     If this packet is a pure SYN we have a simultaneous open.
      //         Handle it.
      //     If this packet is a SYN,ACK but has an ACK < seqsent,
      //         it is a old duplicate, send a reset and kill it!

      // Figure out why we are here...
      if ((prev_state_ == TCP_CLOSE))
      {
        if (!(tcp_hdr->th_flags & TH_ACK))
        {
          // Simultaneous open... handle it.
        }
        else if (SEQ_LT(ack_hbo, (snd_una_ + 1)))
        {
          // Old duplicate SYN,ACK - send a RST.
          flags_ = TH_RST | TH_ACK;

          PktInfo*  rst_pkt_info = NULL;
          if ((rst_pkt_info = BuildHdr(NULL, 0, true)))
          {
            // Need to doctor the sequence number of the packet to be that in
            // the incoming ACK number...
            uint32_t temp_seq = snd_max_;
            snd_max_     = ack_hbo;
            Send(rst_pkt_info, true);
            snd_max_     = temp_seq;

            pkt_info_pool_.Recycle(rst_pkt_info);
          }
        }
        else
        {
          // What could this be... a SYN,ACK with an acknum >
          // max_seqsent...
          //
          // Roll into above by sending a RST (but if this case is valid,
          // someone is very broken on the other-side!
        }
      }
      else
      {
        // This was a passive open to begin with...
      }
    }

    max_data_ = t_maxseg_ - TP_HDR_LEN;

    if (mtu_)
    {
      max_data_ = MIN(max_data_, mtu_ - sizeof(struct tcphdr) -
                      sizeof(struct iphdr) - TP_HDR_LEN);
    }

    snd_cwnd_ = snd_prev_cwnd_ = MIN(4 * max_data_, MAX(2 * max_data_, 4380));

    snd_wnd_ = MIN(snd_cwnd_, snd_awnd_ + snd_una_ - snd_max_);
  }

  if (tcp_hdr->th_flags & TH_FIN)
  {
    return -2;
  }

  if (peer_)
  {
    peer_->CheckAndClosePeerIfWarranted();

    if (peer_->sock_flags_ & SOCK_ACKNOW)
    {
      peer_->flags_ = TH_ACK;

      PktInfo*  ack_pkt_info = NULL;
      if (!(ack_pkt_info = peer_->BuildHdr(NULL, 0, true)))
      {
        LogW(kClassName, __func__, "%s, Error building header.\n",
             flow_id_str_);
      }
      else
      {
        if ((peer_->Send(ack_pkt_info, false)) > 0)
        {
          peer_->sock_flags_  &= ~(SOCK_ACKNOW | SOCK_CANACK | SOCK_DELACK);
          peer_->unacked_segs_ = 0;
          peer_->last_ack_     = ack_num_;
          peer_->CancelDelayedAckEvent();
          peer_->last_uwe_     = send_buf_->uwe();
          peer_->ack_delay_    = 0;
        }

        pkt_info_pool_.Recycle(ack_pkt_info);
      }
    }
  }

  return 1;
}

//============================================================================
int Socket::ProcessPktSynRecState(PktInfo* pkt_info,
                                  const struct tcphdr* tcp_hdr,
                                  const struct iphdr* ip_hdr)
{
  // Validate the parameters.
  if (pkt_info == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter pkt_info is NULL.\n",
         flow_id_str_);

    return -1;
  }

  if (tcp_hdr == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter tcp_hdr is NULL.\n",
         flow_id_str_);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return -1;
  }

  if (ip_hdr == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter ip_hdr is NULL.\n",
         flow_id_str_);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return -1;
  }

  uint32_t  ack_hbo    = ntohl(tcp_hdr->th_ack);
  uint32_t  window_hbo = ntohs(tcp_hdr->th_win);

  if (tcp_hdr->th_flags & TH_SYN)
  {
    flags_ = TH_SYN | TH_ACK;

    // Just retransmit the original syn off the retransmission queue.
    Send(send_buf_->snd_una(), true);
  }

  if ((tcp_hdr->th_flags & TH_ACK) && (ack_hbo == seq_num_))
  {
    max_data_ = t_maxseg_ - TP_HDR_LEN;

    if (mtu_)
    {
      max_data_ = MIN(max_data_, mtu_ - sizeof(struct tcphdr) -
                      sizeof(struct iphdr) - TP_HDR_LEN);
    }

    // snd_cwnd_ = snd_prev_cwnd_ = max_data_;
    // Use the Sally Floyd proposal for optionally increasing initial cwnd:
    snd_cwnd_ = snd_prev_cwnd_ = MIN(4 * max_data_, MAX(2 * max_data_, 4380));

    snd_wnd_ = MIN(snd_cwnd_, snd_awnd_ + snd_una_ - snd_max_);

    // Initialize the Congestion Control Algorithm implementations.
    for (int i = 0; i < MAX_CC_ALG_CNT; i++)
    {
      if (cc_algs_[i] != NULL)
      {
        cc_algs_[i]->Init();
      }
    }

    prev_state_   = state_;
    state_        = TCP_ESTABLISHED;
    flow_is_idle_ = true;

    // Initially we want to send an ACK fairly soon in case the ACK that opens
    // up the window gets lost.
    Time  duration(1.0);
    ScheduleKeepAliveEvent(duration);

    snd_una_++;

    // Free the Packet associated with the SYN.
    send_buf_->Trim(snd_una_);

    t_srtt_   = initial_rtt_ << (TCP_RTT_SHIFT);
    t_rttvar_ = initial_rtt_var_ << TCP_RTTVAR_SHIFT;
    t_rxtcur_ = initial_rto_ << TCP_RTT_SHIFT;

    if ((sock_flags_ & (TF_RCVD_SCALE | TF_REQ_SCALE)) ==
        (TF_RCVD_SCALE | TF_REQ_SCALE))
    {
      snd_scale_ = requested_s_scale_;
      rcv_scale_ = request_r_scale_;
    }

    snd_awnd_ = window_hbo << snd_scale_;

    snd_wnd_ = MIN(snd_cwnd_, (snd_awnd_ - (snd_max_ - snd_una_)));

    ProcessRcvdData(pkt_info, tcp_hdr);

    timeout_ = kTimeout;
    CancelScheduledEvent(rto_time_);

    // If there is any OutSeq data that was really in-order, bring it into the
    // fold now...
    if ((out_seq_buf_->head()) &&
        (SEQ_LEQ(out_seq_buf_->head()->seq_num, ack_num_)))
    {
      PktInfo*  deq_pkt_info = out_seq_buf_->Dequeue();
      if (deq_pkt_info == NULL)
      {
        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
	// Need to recycle the packet.
        pkt_info_pool_.Recycle(pkt_info);

        return -1;
      }

      ack_num_ += deq_pkt_info->data_len;

      UpdateHeaderForMoveToPeer(deq_pkt_info);
      peer_->send_buf_->Enqueue(deq_pkt_info);
    }

    peer_->CheckAndClosePeerIfWarranted();
  }

  return 1;
}

//============================================================================
int Socket::ProcessPktEstablishedState(PktInfo* pkt_info,
                                       const struct tcphdr* tcp_hdr)
{
  uint32_t  seq_hbo = ntohl(tcp_hdr->th_seq);

  if ((tcp_hdr->th_flags & TH_ACK) == 0)
  {
    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return 1;
  }

  if (peer_)
  {
    if ((tcp_hdr->th_flags & TH_URG) && (ntohs(tcp_hdr->urg_ptr)))
    {
      peer_->rel_seq_num_urg_ptr_ = seq_hbo + ntohs(tcp_hdr->urg_ptr) -
        initial_seq_num_rec_;
      peer_->funct_flags_ = peer_->funct_flags_ | FUNCT_REL_SEQ_NUM_URG_PTR;
    }

    if ((peer_->funct_flags_ & FUNCT_REL_SEQ_NUM_URG_PTR) &&
        SEQ_GT(seq_hbo, peer_->rel_seq_num_urg_ptr_ + initial_seq_num_rec_))
    {
      peer_->rel_seq_num_urg_ptr_ = 0;
      peer_->funct_flags_         =
        peer_->funct_flags_ & (~FUNCT_REL_SEQ_NUM_URG_PTR);
    }
  }

  if (tcp_hdr->th_flags & TH_SYN)
  {
    // Probably lost the ACK of the SYN/ACK.
    sock_flags_ |= SOCK_ACKNOW;

    BuildAndSendAck();
  }

  ProcessAck(pkt_info, tcp_hdr);

  if ((tcp_hdr->th_flags & ~TH_ACK) || (pkt_info->data_len > 0))
  {
    ProcessRcvdData(pkt_info, tcp_hdr);
  }
  else
  {
    if (pkt_info->seq_num == (ack_num_ - 1))
    {
      // We have received a KeepAlive packet. Respond by sending back and
      // ACK.
      sock_flags_ |= SOCK_ACKNOW;
      BuildAndSendAck();
    }

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);
  }

  return 1;
}

//============================================================================
int Socket::ProcessPktFinWait1State(PktInfo* pkt_info,
                                    const struct tcphdr* tcp_hdr)
{
  if (!(tcp_hdr->th_flags & (TH_ACK | TH_FIN)))
  {
    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return -1;
  }

  if (tcp_hdr->th_flags & TH_ACK)
  {
    ProcessAck(pkt_info, tcp_hdr);
  }

  if (ntohl(tcp_hdr->th_ack) == fin_seq_num_ + 1)
  {
    CancelScheduledEvent(rto_time_);
    timeout_ = 0x7ffffff;
    send_buf_->Trim(ntohl(tcp_hdr->th_ack));

    CancelScheduledEvent(delayed_ack_time_);
    sock_flags_   &= ~SOCK_DELACK;
    persist_shift_ = 0;
    CancelScheduledEvent(persist_time_);

    // Set the ACK number in our peer. It is equal to the sequence number of
    // the FIN that we sent + 1.
    peer_->ack_num_ = ntohl(tcp_hdr->th_ack);

    if (!(tcp_hdr->th_flags & TH_FIN))
    {
      // The received packet does not have the FIN bit set and the ACK covers
      // the FIN that we sent.
      if (peer_->state_ != TCP_FIN_WAIT1)
      {
        // Our peer's state is not TCP_FIN_WAIT1, which would indicate a
        // simultaneous close. Since this is not a simultaneous close, we
        // transition to state TCP_FIN_WAIT2.
        prev_state_ = state_;
        state_      = TCP_FIN_WAIT2;

        LogD(kClassName, __func__, "%s, transitioning from state "
             "TCP_FIN_WAIT1 to TCP_FIN_WAIT2.\n", flow_id_str_);
      }
      else
      {
        // Our peer's state is TCP_FIN_WAIT1, which indicates we are doing a
        // simultaneous close. Since this is a simultaneous close, we
        // transition to state TCP_CLOSING.
        prev_state_ = state_;
        state_      = TCP_CLOSING;

        LogD(kClassName, __func__, "%s, transitioning from state "
             "TCP_FIN_WAIT1 to TCP_CLOSING.\n", flow_id_str_);
      }

      // Notify our peer to ACK the FIN that was received.
      peer_->AckFin();
    }
  }

  if ((pkt_info->data_len > 0) ||
      ((pkt_info->data_len == 0) && (pkt_info->flags & TH_FIN)))
  {
    ProcessRcvdData(pkt_info, tcp_hdr);
  }
  else
  {
    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);
  }

  return 1;
}

//============================================================================
void Socket::ProcessPktFinWait2State(PktInfo* pkt_info,
                                     const struct tcphdr* tcp_hdr)
{
  CancelScheduledEvent(delayed_ack_time_);
  sock_flags_   &= ~SOCK_DELACK;
  persist_shift_ = 0;
  CancelScheduledEvent(persist_time_);
  ProcessAck(pkt_info, tcp_hdr);

  if (pkt_info->data_len > 0)
  {
    ProcessRcvdData(pkt_info, tcp_hdr);
  }
  else
  {
    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);
  }
}

//============================================================================
void Socket::ProcessPktClosingState(PktInfo* pkt_info,
                                    const struct tcphdr* tcp_hdr)
{
  if (ntohl(tcp_hdr->th_ack) == fin_seq_num_ + 1)
  {
    // The FIN that we sent has been ACKed.
    prev_state_ = state_;
    state_      = TCP_TIME_WAIT;

    LogD(kClassName, __func__, "%s, transitioning from state TCP_CLOSING to "
         "state TCP_TIME_WAIT.\n", flow_id_str_);

    timeout_ = k2MslTimeout;

    Time  duration(static_cast<time_t>(k2MslTimeout));
    ScheduleTimeWaitEvent(duration);

    CancelScheduledEvent(rto_time_);
    ProcessAck(pkt_info, tcp_hdr);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);
  }
}

//============================================================================
int Socket::ProcessPktLastAckState(PktInfo* pkt_info,
                                   const struct tcphdr* tcp_hdr)
{
  CancelScheduledEvent(delayed_ack_time_);
  sock_flags_    &= ~SOCK_DELACK;
  persist_shift_  = 0;
  CancelScheduledEvent(persist_time_);

  if (ntohl(tcp_hdr->th_ack) == fin_seq_num_ + 1)
  {
    ProcessAck(pkt_info, tcp_hdr);

    // The FIN that we sent has been ACKed.
    prev_state_ = 0;
    state_      = TCP_CLOSE;

    LogD(kClassName, __func__, "%s, transitioning from state TCP_LAST_ACK to "
         "state TCP_CLOSE.\n", flow_id_str_);

    CancelScheduledEvent(rto_time_);

    // Set the ACK number in our peer. It is equal to the sequence number of
    // the FIN that we sent + 1.
    peer_->ack_num_ = fin_seq_num_ + 1;

    peer_->AckFin();

    return -1;
  }

  return 1;
}

//============================================================================
void Socket::ProcessPktTimeWaitState(const struct tcphdr* tcp_hdr,
                                     const struct iphdr* ip_hdr)
{
  uint32_t seq_hbo = ntohl(tcp_hdr->th_seq);

  // If this is a SYN and the starting sequence number is greater than the
  // final we've seen here, we are allowed to reincarnate this connection. See
  // Stevens Vol2 fig 28.28.
  if ((tcp_hdr->th_flags & TH_SYN) && SEQ_GT(seq_hbo, ack_num_))
  {
    HandleNewConnection(ip_hdr, tcp_hdr);
  }

  // Otherwise, build a pure ACK and send it.
  last_ack_ = ack_num_;
  last_uwe_ = peer_->send_buf_->uwe();

  PktInfo*  pkt_info = NULL;
  if ((pkt_info = BuildHdr(NULL, 0, true)))
  {
    Send(pkt_info, false);

    pkt_info_pool_.Recycle(pkt_info);
  }
}

//============================================================================
void Socket::HandleNewConnection(const struct iphdr* ip_hdr,
                                 const struct tcphdr* tcp_hdr)
{
  int16_t    option_len = (tcp_hdr->th_off << 2) - 20;
  uint32_t   seq_num_hbo  = ntohl(tcp_hdr->th_seq);

  int        ts_present;
  uint32_t   ts_val;
  uint32_t   ts_ecr;

  initial_seq_num_rec_ = seq_num_hbo;
  ack_num_             = seq_num_hbo + 1;
  his_port_            = tcp_hdr->th_sport;

  his_addr_.s_addr  = ip_hdr->saddr;
  my_addr_.s_addr   = ip_hdr->daddr;
  t_template_.saddr = ip_hdr->daddr;

  ph_.dst = his_addr_;

  // Add checks to make sure that the Packet isn't underrun.
  flags_    = TH_SYN | TH_ACK;
  last_ack_ = ack_num_;

  // Set the values in the new socket's IP header template structure. Note
  // that the source and destination addresses are meant to be swapped here.
  t_template_.daddr = ip_hdr->saddr;
  t_template_.saddr = ip_hdr->daddr;

  bool  pkt_changed_snd_buf = false;
  DoOptions(option_len, tcp_hdr, &ts_present, &ts_val, &ts_ecr,
            pkt_changed_snd_buf);

  PktInfo*  pkt_info = NULL;
  if ((pkt_info = BuildHdr(NULL, 0, true)))
  {
    send_buf_->Enqueue(pkt_info);
  }

  if (send_buf_->snd_nxt())
  {
    Send(NULL, false);
  }

  prev_state_ = state_;
  state_      = TCP_SYN_RECV;

  timeout_ = kLongTimeout;

  capabilities_ |= CAP_CONGEST;

  // Deselect the current congestion control algorithm and
  // select the desired congestion control algorithm (VJ in this case).

  for (int i = 0; i < MAX_CC_ALG_CNT; i++)
  {
    if ((cc_algs_[i] != NULL) &&
        (cc_algs_[i]->selected()))
    {
      cc_algs_[i]->Deselect();
      break;
    }
  }

  cc_algs_[VJ_CONGESTION_CONTROL]->Select();
}

//============================================================================
void Socket::ProcessAck(PktInfo* pkt_info, const struct tcphdr* tcp_hdr)
{
  uint32_t   temp  = 0;
  int        diff  = 0;
  uint32_t   ack_hbo;

  // ProcessAck should *not* recycle packets, since they may be needed in
  // subsequent calls.

  // Make sure that the parameters are valid.
  if (tcp_hdr == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter tcp_hdr is NULL.\n",
         flow_id_str_);
    return;
  }

  PktInfo* supi = send_buf_->snd_una();
  if (supi && supi->seq_num != snd_una_)
  {
    LogF(kClassName, __func__, "%s, snd una seq number (%" PRIu32 ") is out "
         "of sync with the send buffer (%" PRIu32 ").\n", flow_id_str_,
         snd_una_, supi->seq_num);
  }

  // If this ack advances snd_una_, print it.
  //
  // Reset the rexmit timer (we'll clear it later if appropriate).
  //
  // When we use the rttvar in calculating the rxtcur, we need to make sure
  // the var is at least 0.5 seconds. Rational is the following: With
  // implementation of TCP, the unit of variance is 1/4 of a tick and a tick
  // is 0.5 seconds. The smallest value of the variable is 0.125 seconds.
  // Therefore when you multiply it by 4, the minimum value of the variance
  // term is 500000 microseconds.

  t_rxtshift_ = 0;

  int64_t  rto_delta = (t_srtt_ >> TCP_RTT_SHIFT) +
    MAX(MIN_RTTVAR, ((t_rttvar_ >> TCP_RTTVAR_SHIFT) << 2));
  rto_delta = MAX(rto_delta, min_rto_us_);
  rto_delta = rto_delta << t_rxtshift_;  // Scale the rtt
  rto_delta = MIN(rto_delta, max_rto_us_);

  Time  duration = Time::FromUsec(rto_delta);
  ScheduleRtoEvent(duration);

  // Determine whether to start the persist timer.
  //
  // If the advertised window is less than a segment in size, we have
  // data to send, and the persist timer is not already set then we set
  // the persist timer.

  if (((((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_) < max_data_) &&
      (send_buf_->snd_nxt()) && (persist_time_.IsInfinite()))
  {
    // Transition into persist state.
    // ack_hbo = ntohl(tcp_hdr->th_ack);
    // diff    = ack_hbo - snd_una_;
    persist_shift_++;

    if (persist_shift_ == kMaxPersistShift)
    {
      persist_shift_ = kMaxPersistShift - 1;
    }

    int64_t  usec = kPersistTimeouts[persist_shift_] * 1000 * 1000;
    Time  duration = Time::FromUsec(usec);
    SchedulePersistEvent(duration);

    CancelScheduledEvent(rto_time_);

    timeout_ = kLongTimeout;
  }
  else if (!persist_time_.IsInfinite())
  {
    // Otherwise, the link is now available (we got something in),
    // so make sure to clear the persist timer.
    persist_shift_  = 0;
    CancelScheduledEvent(persist_time_);
  }

  // Diff represents the amount of hitherto unacknowledged data acknowledged
  // by this segment.

  ack_hbo = ntohl(tcp_hdr->th_ack);
  diff    = ack_hbo - snd_una_;

  if (cfg_if_id_ == LAN)
  {
    LogD(kClassName, __func__, "%s, ACKing %" PRIu32 " with window of %"
         PRIu32 "\n", flow_id_str_, ack_hbo,
         ((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_);
  }

  // If we are moving forward..
  if (SEQ_GT(ack_hbo, snd_una_))
  {
    snd_una_ = ack_hbo;

    // If you move snd_una_ between seq_sent_ and snd_max_ you must set
    // seq_sent_ to snd_una_. You must also walk sendBuf->send through the
    // list of packets in the buffer until you walk past the sequence number
    // snd_una_. This will allow the packet after snd_una_ to be emitted next.

    if ((SEQ_GT(snd_una_, seq_sent_)) &&
        (SEQ_LEQ(snd_una_, snd_max_)))
    {
      seq_sent_ = snd_una_;
    }

    // Process the positive ACK in the Congestion Control Algorithm
    // implementations (LAN side only)
    if (cfg_if_id_ == LAN)
    {
      for (int i = 0; i < MAX_CC_ALG_CNT; i++)
      {
        if (cc_algs_[i] != NULL)
        {
          cc_algs_[i]->AckRcvd(ack_hbo, diff);
        }
      }
    }

    // Clear running count of duplicate acks.
    t_dupacks_ = 0;

    // Release all the acknowledged data from the send buffer.
    send_buf_->Trim(snd_una_);

    // Now see if we are still okay
    // send_buf_->RexmitSanityCheck();

    // Calculate the new value of last upper window edge.
    if (!(tcp_hdr->th_flags & TH_SYN))
    {
      temp = ack_hbo + (((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_);
    }
    else
    {
      temp = ack_hbo + ((uint32_t)ntohs(tcp_hdr->th_win));
    }

    if (SEQ_GT(last_uwe_in_, temp))
    {
      LogD(kClassName, __func__, "%s, last_uwe_in_ going negative: from %"
           PRIu32 " to %" PRIu32 " (%" PRIu32 "+%" PRIu32 ")\n", flow_id_str_,
           last_uwe_in_, ack_hbo + snd_awnd_, ack_hbo,
           (((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_));
      temp = last_uwe_in_;
    }

    last_uwe_in_ = temp;

    if (IsLeavingFlowCtrlBlockedState())
    {
      Send(NULL, false);
    }

    // Calculate the new value of space remaining in advertised window:
    //
    // seq_sent_ is the sequence number of the last octet sent, subtracting this
    // from the current upper window edge provides us with the remaining
    // advertised window we have available

    snd_awnd_ = ((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_;

    // If we've disabled congestion control, set the available cwnd equal to
    // the available flow-control window.

    timeout_ = kTimeout;
  }

  // If necessary, instruct our "peer" to build and send a gratuitous ACK.
  if ((peer_->last_adv_wnd_ == 0) &&
      (send_buf_->GetUsableWindow() >= 1500))
  {
    peer_->sock_flags_ |= SOCK_ACKNOW;
    peer_->BuildAndSendAck();
  }

  // We may have set ack_hbo to snd_una_ above: if so, this is *not* a DUP ACK
  // Only way to tell is to check the value of 'diff'
  //if (ack_hbo == snd_una_)
  if (diff == 0)
  {
    // This is a duplicate ack...
    //
    // Increment cwnd by one mss regardless, a segment has left the network.
    // But, if this has a window update, it is *not* a duplicate ACK,
    if ((SEQ_GEQ(last_uwe_in_,
                 ack_hbo + (((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_)))
                 && (pkt_info->data_len == 0))
    {
      // Up the duplicate ack count.
      t_dupacks_++;

      if (t_dupacks_ == DUPACK_THRESH)
      {
        PktInfo*  snd_una_pkt_info = send_buf_->snd_una();
        if (snd_una_pkt_info != NULL)
        {
          if (cfg_if_id_ == LAN)
          {
            LogD(kClassName, __func__, "%s, marking hole (DUP ACK) at seq %"
                 PRIu32" with length %" PRIu32".\n", flow_id_str_,
                 snd_una_pkt_info->seq_num, snd_una_pkt_info->data_len);

            snd_una_pkt_info->rexmit_time = Time::Now();
            send_buf_->MoveToHeadOfRexmitList(snd_una_pkt_info);
          }
        }
      }
    }

    // Process the duplicate Ack in the Congestion Control Algorithm
    // implementations (LAN side only)
    if (cfg_if_id_ == LAN)
    {
      for (int i = 0; i < MAX_CC_ALG_CNT; i++)
      {
        if (cc_algs_[i] != NULL)
          {
            cc_algs_[i]->DupAckRcvd(tcp_hdr, pkt_info->data_len);
          }
      }
    }

    // This may be increasing our window size.
    snd_awnd_ = ((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_;

    if (SEQ_GT(last_uwe_in_, ack_hbo + snd_awnd_))
    {
      LogD(kClassName, __func__, "%s, last_uwe_in_ going negative: from %"
           PRIu32 " to %" PRIu32 " (%" PRIu32 "+%" PRIu32 ")\n", flow_id_str_,
           last_uwe_in_, ack_hbo + snd_awnd_, ack_hbo,
           (((uint32_t)ntohs(tcp_hdr->th_win)) << snd_scale_));
      snd_awnd_ = last_uwe_in_ - ack_hbo;
    }

    last_uwe_in_ = ack_hbo + snd_awnd_;

    if (IsLeavingFlowCtrlBlockedState())
    {
      Send(NULL, false);
    }

    if (SEQ_GT(snd_max_, last_uwe_in_))
    {
      temp = 0;
    }
    else
    {
      temp = last_uwe_in_ - snd_max_;
    }

    snd_wnd_ = MIN(snd_cwnd_, temp);

    temp = peer_->send_buf_->GetUsableWindow() >> rcv_scale_;

    if ((last_adv_wnd_ == 0) && temp > 0)
    {
      // Send an immediate ack.
      PktInfo*  pkt_info = NULL;
      if ((pkt_info = BuildHdr(NULL, 0, true)))
      {
        flags_ = TH_ACK;

        if (Send(pkt_info, false) < 0)
        {
          LogW(kClassName, __func__, "%s, Error sending ACK.\n",
               flow_id_str_);
          TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        }

        pkt_info_pool_.Recycle(pkt_info);
      }
    }
  }

  // XXX Do we need this?
  if ((!(sock_flags_ & SOCK_NDELAY)) && (!(send_buf_->snd_una())) &&
      (send_buf_->BytesInBuffer()))
  {
    // We've just gotten ACKed up, so we if had a tiny_gram outstanding, we
    // don't anymore. If we've got more outstanding data in app_sbuff it's
    // less than a full-segment's worth, so call flush() to push this tinygram
    // out.
    Flush();
  }

  if (peer_)
  {
    peer_->CheckAndClosePeerIfWarranted();
  }

  // If we're all Acked up, clear the Rexmit timer that we reset
  if (ack_hbo == seq_sent_)
  {
    CancelScheduledEvent(rto_time_);

    if (snd_cwnd_ <= max_data_)
    {
      snd_cwnd_ = max_data_;
    }
  }

  if (adaptive_buffers_ && (cfg_if_id_ == WAN))
  {
    LogD(kClassName, __func__, "%s, t_srtt_ is %" PRIu32 ", last send rate "
         "is %f, queue depth is %" PRIu32 ", desired send buffer size is %f "
         "bytes.\n", flow_id_str_, (t_srtt_ >> TCP_RTT_SHIFT),
         last_send_rate_,  tcp_proxy_.GetBinDepth(bin_idx_),
         (2 * (t_srtt_ >> TCP_RTT_SHIFT) * last_send_rate_ / 8000000.0));

    send_buf_->UpdateBufferSize((t_srtt_ >> TCP_RTT_SHIFT),
                                last_send_rate_,
                                tcp_proxy_.GetBinDepth(bin_idx_));
  }
}

//============================================================================
void Socket::ProcessRcvdData(PktInfo* pkt_info, const struct tcphdr* tcp_hdr)
{
  int  ack_now = 0;

  // Validate the parameters.
  if (pkt_info == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter pkt_info is NULL.\n",
         flow_id_str_);
    return;
  }

  if (tcp_hdr == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter tcp_hdr is NULL.\n",
         flow_id_str_);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return;
  }

  uint8_t  tcp_hdr_flags = tcp_hdr->th_flags;

  // If this segment had ANY data associated with it, valid or not, bump the
  // delayed ack counter. This test makes sure we still ACK out-of-sequence
  // data (albeit delayed), but we don't ACK ACKs.
#define MAX_UNACKED_SEGS 2

  if ((pkt_info->data_len > 0) && (state_ != TCP_SYN_RECV))
  {
    ack_delay_++;
    unacked_segs_++;
    if ((ack_freq_ == 1) ||
        ((ack_freq_ == 2) && (unacked_segs_ >= MAX_UNACKED_SEGS)))
    {
      ack_now = 1;
    }
    else
    {
      if (delayed_ack_time_.IsInfinite())
      {
        Time  duration = Time::FromUsec(static_cast<int64_t>(ack_delay_us_));
        ScheduleDelayedAckEvent(duration);

        sock_flags_ |= SOCK_DELACK;
      }
    }
  }

  // Establish the upper window edge.
  uint32_t  uwe = peer_->send_buf_->uwe();

  // If the received packet is outside of the window, discard it and return.
  if (SEQ_GEQ(pkt_info->seq_num, uwe))
  {
    LogW(kClassName, __func__, "%s, rcvd packet seq num (%" PRIu32 " >= uwe "
         "(%" PRIu32 "). Compare to sent ack of %" PRIu32 " and adv win of "
         "%" PRIu32 ".\n", flow_id_str_, pkt_info->seq_num, uwe, ack_num_,
         last_adv_wnd_);
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return;
  }

  if (pkt_info->seq_num != ack_num_)
  {
    // See if the packet is lower than what we've already ACKed
    if ((state_ == TCP_ESTABLISHED) &&
        SEQ_LT(pkt_info->seq_num, ack_num_))
    {
      // This is a rexmit. Just recycle the packet and return.
      pkt_info_pool_.Recycle(pkt_info);

      flags_ = TH_ACK;
      PktInfo*  ack_pkt_info;
      if (!(ack_pkt_info = BuildHdr(NULL, 0, true)))
      {
        LogW(kClassName, __func__, "%s, Error building packet.\n",
             flow_id_str_);
      }
      else
      {
        if (SendPkt(ack_pkt_info) > 0)
        {
          sock_flags_   &= ~(SOCK_ACKNOW | SOCK_CANACK | SOCK_DELACK);
          ack_delay_     = 0;
          CancelDelayedAckEvent();
        }
        pkt_info_pool_.Recycle(ack_pkt_info);
      }

      return;
    }
    else  // Else enqueue the out of sequence packet
    {
      // Don't call ProcessOutOfSequenceData for packets which have already
      // been acked.  DO call it if the packet is a FIN with 0 length.
      if ((pkt_info->data_len > 0) || (tcp_hdr_flags & TH_FIN))
      {
        if (SEQ_LT(ack_num_, ntohl(tcp_hdr->th_seq) + pkt_info->data_len) ||
            ((tcp_hdr_flags & TH_FIN) && (ntohl(tcp_hdr->th_seq) == ack_num_)))
        {
          ProcessOutOfSequenceData(pkt_info, tcp_hdr);
        }

        // Always immediately ACK for an out-of-sequence segment if we are
        // NOT doing massively delayed ACKs.
        if (ack_freq_)
        {
          ack_now = 1;
        }
        else
        {
          sock_flags_ |= SOCK_CANACK;

          BuildAndSendAck();
        }

        if (((out_seq_buf_->tail()) &&
             SEQ_GEQ((out_seq_buf_->tail()->seq_num +
                      out_seq_buf_->tail()->data_len), last_uwe_)) ||
            (tcp_hdr_flags & TH_FIN))
        {
          ack_now = 1;
        }

        tcp_hdr_flags &= ~TH_FIN;
      }

      if (ack_now)
      {
        goto ACKNOW;
      }
      else
      {
        return;
      }
    }
  }

  // If we get here, we can place the data directly into the send
  // buffer. Additionally, we can move any data from the out-of-sequence
  // buffer that is now in sequence.
  if ((pkt_info->data_len > 0) ||
      ((pkt_info->data_len == 0) && (pkt_info->flags & TH_FIN)))
  {
    // Place the new segment into the peer's send queue.
    UpdateHeaderForMoveToPeer(pkt_info);
    out_seq_buf_->set_last_inserted_seq(pkt_info->seq_num);
    if (!peer_->send_buf_->Enqueue(pkt_info))
    {
      // The enqueue failed. Recycle the packet and delete the PktInfo.
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      pkt_info_pool_.Recycle(pkt_info);

      return;
    }

    ack_num_ = pkt_info->seq_num + pkt_info->data_len;

    LogD(kClassName, __func__, "%s, Rcvd. Packet: seq (%" PRIu32 "), data "
         "len (%" PRIu32 ").\n", flow_id_str_, pkt_info->seq_num,
         pkt_info->data_len);

    while (out_seq_buf_->head() &&
           SEQ_LEQ(out_seq_buf_->head()->seq_num, ack_num_))
    {
      PktInfo*  out_seq_pkt_info = NULL;
      if ((out_seq_pkt_info = out_seq_buf_->Dequeue()) == NULL)
      {
        break;
      }

      // Set flags here in case the only thing in the out-of-sequence buffer
      // is the FIN, in which case, out_seq_pkt_info is the FIN and we want to
      // close out the connection below. Note that the processing between here
      // and where we check for the FIN bit will not happen since it's looking
      // for something ELSE on the out-of-sequence queue.
      tcp_hdr_flags = out_seq_pkt_info->flags;

      if (SEQ_GEQ(ack_num_,
                  (out_seq_pkt_info->seq_num + out_seq_pkt_info->data_len)))
      {
        LogD(kClassName, __func__, "%s, Deleting out of sequence buffer "
             "Packet: seq (%" PRIu32 "), data len (%" PRIu32 ").\n",
             flow_id_str_, out_seq_pkt_info->seq_num,
             out_seq_pkt_info->data_len);

        // If new packet fully overlaps an out-of-sequence data packet just free
        // the out-of-sequence packet and move on.
        pkt_info_pool_.Recycle(out_seq_pkt_info);

        out_seq_pkt_info = NULL;
      }
      else
      {
        if (ack_num_ == out_seq_pkt_info->seq_num)
        {
          ack_num_ += out_seq_pkt_info->data_len;
        }
        // XXX Straddling? Not important to us???
        else
        {
          LogW(kClassName, __func__, "%s, ack number check failed\n",
               flow_id_str_);

          if (SEQ_GT(ack_num_, out_seq_pkt_info->seq_num))
          {
            LogW(kClassName, __func__, "%s, really odd ack number check "
                 "failed\n", flow_id_str_);
            ack_num_ = pkt_info->seq_num + pkt_info->data_len;
          }
        }

        UpdateHeaderForMoveToPeer(out_seq_pkt_info);
        if (!peer_->send_buf_->Enqueue(out_seq_pkt_info))
        {
          LogF(kClassName, __func__, "%s, Error enqueuing packet into send "
               "buffer.\n", flow_id_str_);
        }
      }

      ack_now = 1;

      // If the *next* outseq element is the FIN, we must pull it off here.
      if ((out_seq_buf_->head()) &&
          (ack_num_ == out_seq_buf_->head()->seq_num) &&
          (out_seq_buf_->head()->flags & TH_FIN))
      {
        out_seq_pkt_info = out_seq_buf_->Dequeue();

        if (out_seq_pkt_info)
        {
          tcp_hdr_flags = out_seq_pkt_info->flags;
          ack_num_ += out_seq_pkt_info->data_len;

          UpdateHeaderForMoveToPeer(out_seq_pkt_info);
          peer_->send_buf_->Enqueue(out_seq_pkt_info);

          ack_now = 1;
        }
      }

      CheckAndClosePeerIfWarranted();
    }

    if (capabilities_ & CAP_SACK)
    {
      if (out_seq_buf_->head())
      {
        ack_now = 1;

        LogD(kClassName, __func__, "%s, Requesting Sack at ack_num_ %lu\n",
             flow_id_str_, ack_num_);
      }
    }
  }

  // Setting a flag here and checking it when we check the timers accomplishes
  // the RFC1122 requirement of not sending any ACKS until the receive queue
  // has been exhausted (so as not to send a bunch of acks in a row).
  if ((ack_now) || ((ack_delay_) && (state_ < TCP_CLOSING)))
  {
    ACKNOW:
    if (ack_now)
    {
      sock_flags_ |= SOCK_ACKNOW;

      // Send an immediate ack.
      PktInfo*  ack_pkt_info = NULL;
      if ((ack_pkt_info = BuildHdr(NULL, 0, true)))
      {
        flags_ = TH_ACK;

        if (Send(ack_pkt_info, false) > 0)
        {
          unacked_segs_ = 0;
          last_uwe_     = peer_->send_buf_->uwe();
          last_ack_     = ack_num_;
          ack_delay_    = 0;
          CancelScheduledEvent(delayed_ack_time_);
          sock_flags_  &= ~(SOCK_ACKNOW | SOCK_DELACK | SOCK_CANACK);
          ack_delay_    = 0;
        }

        pkt_info_pool_.Recycle(ack_pkt_info);
      }
      else
      {
        LogW(kClassName, __func__, "%s, BuildHdr() failed...\n",
             flow_id_str_);
      }
    }
  }
}

//============================================================================
void Socket::ProcessOutOfSequenceData(PktInfo* pkt_info,
                                      const struct tcphdr* tcp_hdr)
{
  // Validate the parameters.
  if (pkt_info == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter pkt_info is NULL.\n",
         flow_id_str_);
    return;
  }

  if (tcp_hdr == NULL)
  {
    LogW(kClassName, __func__, "%s, Parameter tcp_hdr is NULL.\n",
         flow_id_str_);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return;
  }

  // If this is the FIN, just enqueue it in out_seq_buf_.
  if (tcp_hdr->th_flags & TH_FIN)
  {
    if (out_seq_buf_ == NULL)
    {
      LogF(kClassName, __func__, "%s, Socket does not have an "
           "out-of-sequence buffer. Something is really wrong...\n",
           flow_id_str_);
      return;
    }

    if (out_seq_buf_->tail())
    {
      struct tcphdr*  out_seq_buf_tail_tcp_hdr =
        out_seq_buf_->tail()->pkt->GetTcpHdr();

      if (out_seq_buf_tail_tcp_hdr->th_flags & TH_FIN)
      {
        // Need to recycle the packet.
        pkt_info_pool_.Recycle(pkt_info);

        return;
      }
    }

    if (cfg_if_id_ == LAN)
    {
      LogD(kClassName, __func__, "%s, Enqueueing to OOSeq buf.\n",
           flow_id_str_);
    }

    out_seq_buf_->Enqueue(pkt_info);

    return;
  }

  if (cfg_if_id_ == LAN)
  {
    LogD(kClassName, __func__, "%s, Inserting into OOSeq buf.\n",
         flow_id_str_);
  }

  if (!out_seq_buf_->Insert(pkt_info))
  {
    LogD(kClassName, __func__, "%s, last_uwe_ = %" PRIu32 ", ack_num_ = %"
         PRIu32 "\n", flow_id_str_, last_uwe_, ack_num_);

    // Need to recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    return;
  }
}

//============================================================================
void Socket::UpdateRttEstimate(uint32_t rtt_sample)
{
  int  delta;

  // If you have to RTO a packet at least 4 times, then the rtt is probably
  // bogus, so you should obtain a new sample.  While we are at it, we might
  // as well change rttbest as well.
  if (t_rxtshift_ >= 4)
  {
    t_srtt_ = 0;
  }

  if (t_srtt_ != 0)
  {
    // srtt is stored as fixed point with 3 bits after the binary point.
    // The following magic is equivalent to the smoothing algorithm in
    // rfc793 with an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed point.
    delta = rtt_sample - (t_srtt_ >> TCP_RTT_SHIFT);
    if ((t_srtt_ += delta) <= 0)
    {
      t_srtt_ = 1;
    }

    // Accumulate smoothed rtt variance (smoothed mean difference), then set
    // retransmit timer to smoothed rtt + 4xsmoothed variance. rttvar is
    // stored as fixed points, with 2 bits after the binary point (i.e.,
    // scaled by 4). The following is equivalent to RFC793 smoothing with
    // alpha=0.75 rttar = rttvar*3/4 + |delta|/4. This replaces RFC793's
    // wired-in beta.
    if (delta < 0)
    {
      delta = -delta;
    }

    delta -= (t_rttvar_ >> TCP_RTTVAR_SHIFT);
    if ((t_rttvar_ += delta) <= 0)
    {
      t_rttvar_ = 1;
    }
  }
  else
  {
    // No rtt measurement yet - use unsmoothed rtt. Set variance to half the
    // RTT (so our first rexmit happens at 3*rtt).
    t_srtt_   = rtt_sample << TCP_RTT_SHIFT;
    t_rttvar_ = rtt_sample << (TCP_RTTVAR_SHIFT - 1);
  }

  t_rxtshift_ = 0;

  // When we use the rttvar in calculating the rxtcur, we need to make sure
  // the var is at least 0.5 seconds. Rational is the following: with
  // implementation of TCP, the unit of variance is 1/4 of a tick and a tick
  // is 0.5 seconds. The smallest value of the variable is 0.125 seconds.
  // Therefore when you multiply it by 4, the minimum value of the variance
  // term is 500000 microseconds.
  t_rxtcur_ = (t_srtt_ >> TCP_RTT_SHIFT) + MAX(t_rttvar_, MIN_RTTVAR);

  if (rtt_cur_ && (t_rxtcur_ > (rtt_cur_ << 1)))
  {
    t_rxtcur_ = MAX(rtt_cur_ << 1, MIN_RTTVAR);
  }

  t_rxtcur_ = MAX(t_rxtcur_, min_rto_us_);
  t_rxtcur_ = MIN(t_rxtcur_, max_rto_us_);
}

//============================================================================
void Socket::DoOptions(int cnt, const struct tcphdr* tcp_hdr,
                       int* ts_present, uint32_t* ts_val, uint32_t* ts_ecr,
                       bool& pkt_changed_snd_buf)
{
  int       opt;
  int       opt_len;
  uint8_t*  cp;
  uint16_t  mss;

  cp = (uint8_t*)tcp_hdr + sizeof(struct tcphdr);

  for (; cnt > 0; cnt -= opt_len, cp += opt_len)
  {
    opt = cp[0];
    if (opt == TCPOPT_EOL)
    {
      break;
    }

    if (opt == TCPOPT_NOP)
    {
      opt_len = 1;
    }
    else
    {
      opt_len = cp[1];
      if (opt_len <= 0)
      {
        break;
      }
    }

    switch (opt)
    {
      default:
        continue;

      case TCPOPT_MAXSEG:
        if (opt_len != TCPOLEN_MAXSEG)
        {
          continue;
        }

        if (!(tcp_hdr->th_flags & TH_SYN))
        {
          continue;
        }

        memcpy((uint8_t*)&mss, ((uint8_t*)cp + 2), sizeof(mss));

        SetMss(ntohs(mss));

        break;

      case TCPOPT_SACK_PERMITTED:
        if (opt_len != TCPOLEN_SACK_PERMITTED)
        {
          continue;
        }

        if (!(tcp_hdr->th_flags & TH_SYN))
        {
          continue;
        }

        sock_flags_ |= TF_RCVD_SACK;
        break;

      case TCPOPT_WINDOW:
        if (opt_len != TCPOLEN_WINDOW)
        {
          continue;
        }

        if (!(tcp_hdr->th_flags & TH_SYN))
        {
          continue;
        }

        sock_flags_       |= TF_RCVD_SCALE;
        requested_s_scale_ = (cp[2] < TCP_MAX_WINSHIFT) ? cp[2] :
          TCP_MAX_WINSHIFT;
        break;

      case TCPOPT_TIMESTAMP:
        if (opt_len != TCPOLEN_TIMESTAMP)
        {
          continue;
        }

        *ts_present = 1;

        memcpy((uint8_t*)ts_val, ((uint8_t*)cp + 2), sizeof(*ts_val));
        *ts_val = ntohl(*ts_val);

        memcpy((uint8_t*)ts_ecr, ((uint8_t*)cp + 6), sizeof(*ts_ecr));
        *ts_ecr = ntohl(*ts_ecr);

        // A timestamp received in a SYN makes it OK to send timestamp
        // requests and replies.
        if (tcp_hdr->th_flags & TH_SYN)
        {
          sock_flags_   |= TF_RCVD_TSTMP;
          ts_recent_     = *ts_val;
          ts_recent_age_ = Clock::ValueRough();

          if (*ts_ecr != 0)
          {
            ts_ecr_recent_ = *ts_ecr;
          }
          else
          {
            ts_ecr_recent_ = Clock::ValueRough();
          }
        }
        break;

      case TCPOPT_SACK:
        uint32_t num_blocks     = (opt_len - 2) >> 3;
        uint32_t upper_hole_seq = 0;

        LogD(kClassName, __func__, "%s, Received SACK info with %" PRIu32
             " blocks\n", flow_id_str_, num_blocks);

        OutSeqBuffer::PlugInfo  cur_sack_plugs[4];
        OutSeqBuffer::PlugInfo  unique_sack_plugs[4];
        memset(&cur_sack_plugs, 0, sizeof(cur_sack_plugs));
        memset(&unique_sack_plugs, 0, sizeof(unique_sack_plugs));

        cp += 2;
        for (uint32_t i = 0; i < num_blocks; i++)
        {
          // Parse the SACK info.
          uint32_t lower_plug_seq  = ntohl(*((uint32_t*)(cp + 0)));
          uint32_t upper_plug_seq  = ntohl(*((uint32_t*)(cp + 4)));

          cur_sack_plugs[i].lower_seq = lower_plug_seq;
          cur_sack_plugs[i].upper_seq = upper_plug_seq;

          if ((i == 0) || (SEQ_GT(lower_plug_seq, upper_hole_seq)))
          {
            upper_hole_seq = lower_plug_seq;
          }

          plug_send_seq_  = lower_plug_seq;
          plug_send_size_ = upper_plug_seq - lower_plug_seq;

          LogD(kClassName, __func__, "%s, received plug from %" PRIu32
               ", to %" PRIu32 ", size %" PRIu32 "\n", flow_id_str_,
               lower_plug_seq, upper_plug_seq, plug_send_size_);

          cp += 8;
        }

        // Sort the current SACK plugs.
        for (uint32_t i = 0; i < num_blocks; i++)
        {
          if (((cur_sack_plugs[i + 1].lower_seq != 0) &&
               (cur_sack_plugs[i + 1].upper_seq != 0))
              &&
              SEQ_GT(cur_sack_plugs[i].lower_seq, cur_sack_plugs[i + 1].lower_seq))
          {
            OutSeqBuffer::PlugInfo  tmp = cur_sack_plugs[i];
            cur_sack_plugs[i]           = cur_sack_plugs[i + 1];
            cur_sack_plugs[i + 1]       = tmp;
          }
        }

        // Populate the unique SACK plug array.
        uint32_t  ack_num          = ntohl(tcp_hdr->th_ack);
        uint32_t  num_unique_plugs = 0;
        for (uint32_t i = 0; i < num_blocks; i++)
        {
          bool  plug_in_cache = false;

          for (uint32_t j = 0; j < 4; j++)
          {
            if ((sack_plug_cache_[j].lower_seq ==
                 cur_sack_plugs[i].lower_seq)
                &&
                (sack_plug_cache_[j].upper_seq ==
                 cur_sack_plugs[i].upper_seq))
            {
              plug_in_cache = true;
              break;
            }
          }
          if (!plug_in_cache &&
              SEQ_GT(cur_sack_plugs[i].lower_seq, ack_num))
          {
            unique_sack_plugs[num_unique_plugs++] = cur_sack_plugs[i];
          }
        }

        if (num_unique_plugs != 0)
        {
          // Process the SACK plugs.
          send_buf_->ProcessPlugs(cur_sack_plugs, num_unique_plugs,
                                  pkt_changed_snd_buf);
        }

        // Cache the most recently received plugs.
        memcpy(&sack_plug_cache_, &cur_sack_plugs, sizeof(cur_sack_plugs));

        break;
    }
  }
}

//============================================================================
size_t Socket::GetOptions(uint8_t* opt_buf, size_t opt_buf_max_size)
{
  if (opt_buf_max_size < kMaxTcpOptLen)
  {
    LogW(kClassName, __func__, "%s, Provided option buffer size of %zd is "
         "less than maximum size of %zd.\n", flow_id_str_, opt_buf_max_size,
         kMaxTcpOptLen);
    return 0;
  }

  size_t  opt_len = 0;

  // Setup items (only on SYN packets)
  if (flags_ & TH_SYN)
  {
    // Send MAXSEG Option
    opt_buf[opt_len]     = TCPOPT_MAXSEG;
    opt_buf[opt_len + 1] = 4;

    int16_t  max_seg_nbo = htons(t_maxseg_);
    memcpy((void *)(opt_buf + opt_len + 2), (void *)&(max_seg_nbo),
           sizeof(t_maxseg_));
    my_mss_offer_  = t_maxseg_;
    opt_len       += 4;

    // Window Scaling Option
    if ((sock_flags_ & TF_REQ_SCALE) &&
        ((flags_ & TH_ACK) == 0 || (sock_flags_ & TF_RCVD_SCALE)))
    {
      *((uint32_t*)(opt_buf + opt_len)) = htonl(TCPOPT_NOP << 24 |
                                                TCPOPT_WINDOW << 16 |
                                                TCPOLEN_WINDOW << 8 |
                                                request_r_scale_);
      opt_len += 4;
    }

    // SACK option
    if ((sock_flags_ & TF_REQ_SACK) &&
        ((flags_ & TH_ACK) == 0 || (sock_flags_ & TF_RCVD_SACK)))
    {
      opt_buf[opt_len++] = TCPOPT_SACK_PERMITTED;
      opt_buf[opt_len++] = TCPOLEN_SACK_PERMITTED;
    }
  }

  // Timestamp option
  if (capabilities_ & CAP_TIMESTAMP)
  {
    // Send a timestamp and echo-reply if this is a SYN and our side wants to
    // use timestamps (TF_REQ_TSTMP is set) or both our side and our peer have
    // sent timestamps in our SYN's.
    if ((sock_flags_ & TF_REQ_TSTMP) &&
        ((flags_ & TH_RST) == 0) &&
        (((flags_ & (TH_SYN | TH_ACK)) == TH_SYN) ||
         (sock_flags_ & TF_RCVD_TSTMP)))
    {
      uint32_t*  lp = (uint32_t*)(opt_buf + opt_len);

      // Form timestamp option as shown in appendix A of RFC 1323.
      *lp++    = htonl(TCPOPT_TSTAMP_HDR);
      *lp++    = htonl(Clock::ValueRough());
      *lp      = htonl(ts_recent_);
      opt_len += TCPOLEN_TSTAMP_APPA;
    }
  }

  // SACK option. We do this last to figure out how many blocks we can insert
  if ((capabilities_ & CAP_SACK) && (sock_flags_ & TF_RCVD_SACK)
      && !(flags_ & TH_SYN))
  {
    // Only do this if we can insert at least one plug
    if (kMaxTcpOptLen >= opt_len + 10)
    {
      // We can send no more than 4 SACK blocks due to TCP option max size
      OutSeqBuffer::PlugInfo  plugs[4];

      uint32_t  max_plugs = (kMaxTcpOptLen - opt_len - 2) / 8;
      LogD(kClassName, __func__, "%s, Can insert up to %" PRIu32
           " blocks of SACK information\n", flow_id_str_, max_plugs);

      uint32_t  num_plugs_found = out_seq_buf_->GatherPlugs(plugs, max_plugs);
      if (num_plugs_found > 0)
      {
        // Align the SACK option
        opt_buf[opt_len++] = TCPOPT_NOP;
        opt_buf[opt_len++] = TCPOPT_NOP;

        // Insert the SACK information. First the header
        // Note: we will rewrite the length of this option once we
        // know how many SACK blocks we actually have.
        // Hence we dont change the opt_len variable after this
        // first write so we can save the write position

        opt_buf[opt_len++] = TCPOPT_SACK;
        opt_buf[opt_len  ] = 2 + 8 * max_plugs; // two seq nums per block

        // Set up to insert the sequence numbers
        uint32_t*  sack_blocks = (uint32_t*)(&opt_buf[opt_len+1]);
        uint32_t  insert_pos   = 0;

        // The following call to get the covering SACK block can fail
        // if the last packet received cleared that particular SACK
        // block and so is not actually in the OOS buffer

        bool cover_found = false;

        OutSeqBuffer::PlugInfo  cover;
        if ((cover_found = out_seq_buf_->GetPlugCoveringLastPkt(cover)) == true)
        {
          // We know we at least have a covering SACK block
          sack_blocks[insert_pos++] = htonl(cover.lower_seq);
          sack_blocks[insert_pos++] = htonl(cover.upper_seq);
        }

        // Add as many remaining unique SACK blocks that can fit
        for (uint32_t i = 0; i < num_plugs_found; i++)
        {
          // Make sure we can hold this SACK block
          if (insert_pos >= (2 * max_plugs))
          {
            break;
          }
          // And if its not the same as the covering block then
          // go ahead and insert it

          if ((cover_found == false) ||
              (plugs[i].lower_seq != cover.lower_seq))
          {
            sack_blocks[insert_pos++] = htonl(plugs[i].lower_seq);
            sack_blocks[insert_pos++] = htonl(plugs[i].upper_seq);
          }
        }

        // Now that we know how many we've inserted, rewrite
        // the option header
        opt_buf[opt_len++]  = 2 + (4 * insert_pos); // one seq num per insert
        opt_len            +=     (4 * insert_pos);
      }
    }
  }

  // Make sure to pad out the remainder of the options header
  while ((opt_len % 4) != 0)
  {
    opt_buf[opt_len++] = TCPOPT_EOL;
  }

  return opt_len;
}

//============================================================================
void Socket::UpdateWinSizeAndAckNum(struct tcphdr* tcp_hdr)
{
  uint32_t  temp;
  uint32_t  wndw = 0;

  if (tcp_hdr == NULL)
  {
    return;
  }

  if ((ack_num_ == 0) && (orig_syn_pkt_info_ != NULL))
  {
    // We have not yet processed an ACK but are sending a packet. This is most
    // likely the case when we receive a RST during the SYN handshake. We need
    // to initialize the ACK number, it is equal to the sequence number in the
    // orig_syn_pkt_info_ + 1.
    struct tcphdr*  syn_tcp_hdr = orig_syn_pkt_info_->pkt->GetTcpHdr();
    uint32_t        seq_num     = ntohl(syn_tcp_hdr->th_seq);

    ack_num_ = seq_num + 1;
  }

  tcp_hdr->th_ack = htonl(ack_num_);

  if (peer_)
  {
    temp = peer_->send_buf_->GetUsableWindow();
  }
  else
  {
    temp = peer_send_buf_max_bytes_;
  }
  wndw = temp;

  // if ((temp < (uint32_t)(peer_send_buf_max_bytes_ / 4)) &&
  if (temp < (uint32_t)(t_maxseg_))
  {
    temp = 0;
  }

  // Ensure that the window size is a multiple of the MSS.
  temp = (temp / (uint32_t)t_maxseg_) * (uint32_t)t_maxseg_;

  if (temp > (uint32_t)(TCP_MAXWIN << rcv_scale_))
  {
    temp = (uint32_t)(TCP_MAXWIN << rcv_scale_);
  }

  // The following used to fail consistently. Now all good.
  if ((state_ != TCP_SYN_SENT) && (state_ != TCP_CLOSE))
  {
    if (SEQ_LT(last_uwe_, ack_num_ + temp))
    {
      if (SEQ_GEQ(last_uwe_, ack_num_))
      {
        temp = (uint32_t)(last_uwe_ - ack_num_);
      }
      else
      {
        LogW(kClassName, __func__, "%s, Proxy state fault detected! "
             " last_uwe_: %" PRIu32 " ack_num_: %" PRIu32 "\n", flow_id_str_,
             last_uwe_, ack_num_);
      }
    }
  }

  // This is to prevent being bitten by Little Endian machines when we want to
  // advertise a window greater than 65535, but we don't have window-scaling
  // option available.
  if ((temp > 0xFFFF) && (!rcv_scale_))
  {
    tcp_hdr->th_win = 0xFFFF;
  }
  else
  {
    tcp_hdr->th_win = htons((uint16_t)(temp >> rcv_scale_));
  }

  uint32_t  adv_win = ((uint32_t)ntohs(tcp_hdr->th_win)) << rcv_scale_;

  if ((adv_win == 0) && (peer_->send_buf_->GetUsableWindow() != 0))
  {
    // Note: this can happen simply due to scaling and small usable windows.
    LogD(kClassName, __func__, "%s, Window fault detected! Zeroing advertised "
         "window  with usable window of %" PRIu32 ".\n", flow_id_str_,
         peer_->send_buf_->GetUsableWindow());
  }

  if ((last_adv_wnd_ != 0) && (adv_win == 0))
  {
    LogD(kClassName, __func__, "%s, Closing advertised window.\n",
         flow_id_str_);
  }
  else if ((last_adv_wnd_ == 0) && (adv_win != 0))
  {
    LogD(kClassName, __func__, "%s, Opening advertised window.\n",
         flow_id_str_);
  }

  last_adv_wnd_ = adv_win;

  if (capabilities_ & CAP_TIMESTAMP)
  {
    if (((tcp_hdr->th_off << 2) > 22) &&
        (((uint8_t*)tcp_hdr)[22] == TCPOPT_TIMESTAMP))
    {
      uint32_t now = Clock::ValueRough();
      uint32_t*  lp = (uint32_t*)(((uint8_t*)tcp_hdr) + 24);
      *lp++ = htonl(now);
      *lp   = htonl(ts_recent_ + (now - ts_recent_age_));
      // Standard mechanism does not compensate for hold times
      // *lp   = htonl(ts_recent_);
    }
  }

  if ((wndw < 100000) && (cfg_if_id_ == WAN))
  {
    LogD(kClassName, __func__, "%s, not moving data! Window is %" PRIu32
         ".\n", flow_id_str_, wndw);
  }
}

//============================================================================
bool Socket::IsLeavingFlowCtrlBlockedState()
{
  if (!flow_ctrl_blocked_)
  {
    return false;
  }

  if (SEQ_LEQ((flow_ctrl_blocked_seq_num_ + flow_ctrl_blocked_data_len_),
              last_uwe_in_))
  {
    flow_ctrl_blocked_          = false;
    flow_ctrl_blocked_seq_num_  = 0;
    flow_ctrl_blocked_data_len_ = 0;

    return true;
  }

  return false;
}

//============================================================================
void Socket::DelayedAckTimeout()
{
  LogD(kClassName, __func__, "%s, delayed ack timer fired.\n",
       flow_id_str_);

  // Clear the delayed ack timer.
  delayed_ack_time_.SetInfinite();

  if (sock_flags_ & SOCK_DELACK)
  {
    sock_flags_   &= ~SOCK_DELACK;
    sock_flags_   |= SOCK_ACKNOW;
    unacked_segs_  = 0;

    BuildAndSendAck();
  }
}

//============================================================================
void Socket::KeepAliveTimeout()
{
  LogD(kClassName, __func__, "%s, keep alive timeout fired.\n",
       flow_id_str_);

  // Clear the keep alive timer.
  keep_alive_time_.SetInfinite();

  if ((state_ >= TCP_SYN_SENT)  && (state_ <= TCP_LAST_ACK))
  {
    sock_flags_ |= SOCK_ACKNOW;

    BuildAndSendAck();
  }

  Time  duration(static_cast<time_t>(ka_timeout_));
  ScheduleKeepAliveEvent(duration);
}

//============================================================================
void Socket::PersistTimeout()
{
  LogD(kClassName, __func__, "%s, persist timeout fired.\n", flow_id_str_);

  // Clear the persist timer.
  persist_time_.SetInfinite();

  if (!send_buf_->snd_nxt())
  {
    if (persist_shift_ == kMaxPersistShift)
    {
      persist_shift_ = kMaxPersistShift - 1;
    }

    int64_t  usec = kPersistTimeouts[persist_shift_] * 1000 * 1000;
    Time  duration = Time::FromUsec(usec);
    SchedulePersistEvent(duration);

    CancelScheduledEvent(rto_time_);

    timeout_ = kLongTimeout;

    return;
  }

  if ((state_ == TCP_FIN_WAIT2) || (state_ == TCP_LAST_ACK) ||
      (state_ == TCP_TIME_WAIT) || (state_ == TCP_CLOSE))
  {
    return;
  }

  // Find a segment.
  PktInfo*  pkt_info = send_buf_->snd_una();
  if (pkt_info == NULL)
  {
    Time  now = Time::Now();
    pkt_info = send_buf_->GetNextTransmission(now, last_uwe_in_, cfg_if_id_);
  }

  if (pkt_info && pkt_info->data_len)
  {
    // Ship the packet.
    LogW(kClassName, __func__, "%s, Sending packet.\n", flow_id_str_);

    if (SendPkt(pkt_info) <= 0)
    {
      LogW(kClassName, __func__, "%s, Tried to send packet and failed.\n",
           flow_id_str_);
    }

    if ((pkt_info->seq_num + pkt_info->data_len) > seq_sent_)
    {
      seq_sent_ = pkt_info->seq_num + pkt_info->data_len;

      if (SEQ_GT(seq_sent_, snd_max_))
      {
        snd_max_ = seq_sent_;
      }
    }
  }
  else
  {
    sock_flags_ |= SOCK_DELACK;
  }

  persist_shift_++;
  if (persist_shift_ == kMaxPersistShift)
  {
    persist_shift_ = kMaxPersistShift - 1;
  }

  int64_t  usec = kPersistTimeouts[persist_shift_] * 1000 * 1000;
  Time  duration = Time::FromUsec(usec);
  SchedulePersistEvent(duration);

  CancelScheduledEvent(rto_time_);

  timeout_ = kLongTimeout;
}

//============================================================================
void Socket::RtoTimeout()
{
  LogD(kClassName, __func__, "%s, RTO timer fired.\n", flow_id_str_);

  // Clear the RTO timer.
  rto_time_.SetInfinite();

  if ((!send_buf_) || (state_ == TCP_FIN_WAIT2))
  {
    return;
  }

  if (state_ == TCP_CLOSE)
  {
    return;
  }

  PktInfo*  send_buf_snd_una = send_buf_->snd_una();
  if (send_buf_snd_una)
  {
    LogD(kClassName, __func__, "%s, RTO fired: snd_una seq %" PRIu32 "\n",
         flow_id_str_, send_buf_->snd_una()->seq_num);

    // This portion of code rolls back ->send back to ->snd_una on an RTO -
    // send_buf_->HandleRto();

    if (capabilities_ & CAP_SACK)
    {
      send_buf_->ResendAllPkts();
    }
    else
    {
      send_buf_->GoBackN();
    }

    funct_flags_   = funct_flags_ & (~FUNCT_HIGH_SEQ);
    funct_flags_   = funct_flags_ & (~FUNCT_HIGH_CONGESTION_SEQ);
    high_seq_      = 0;
    high_cong_seq_ = 0;

    snd_cwnd_ = max_data_;

    pkts_ack_in_epoch_ = 0;

    // Setting the flow is idle flag here indicates that the outbound flow's
    // next admission time should be based on the current time.
    flow_is_idle_ = true;

    // It's now a retranmission, we can't time this.
    if (send_buf_snd_una->timestamp)
    {
      send_buf_snd_una->timestamp = Clock::ValueRough();
    }

    // Process the timeout in the Congestion Control Algorithm
    // implementations.
    if (cfg_if_id_ == LAN)
    {
      for (int i = 0; i < MAX_CC_ALG_CNT; i++)
      {
        if (cc_algs_[i] != NULL)
        {
          cc_algs_[i]->Timeout();
        }
      }
    }

    // Abort fast retransmit.
    if (funct_flags_ & FUNCT_HIGH_SEQ)
    {
      LogD(kClassName, __func__, "%s, RTO out of FR, snd_cwnd(%lu) relative "
           "snduna(%lu)\n", flow_id_str_, snd_cwnd_, snd_una_ -
           initial_seq_num_);

      high_seq_          = 0;
      funct_flags_       = funct_flags_ & (~FUNCT_HIGH_SEQ);
      pkts_ack_in_epoch_ = 0;
    }

    funct_flags_   = funct_flags_ & (~FUNCT_HIGH_CONGESTION_SEQ);
    high_cong_seq_ = 0;

    t_rxtshift_++;

    if (t_rxtshift_ > t_rxtmaxshift_)
    {
      t_rxtshift_ = t_rxtmaxshift_;
    }

    if ((cfg_if_id_ == WAN) && do_seamless_handoff_ &&
        (state_ == TCP_SYN_SENT) &&
        (t_rxtshift_ > kMaxSeamlessHandoffSynRexmits))
    {
      // We have tried to connect to the chosen server the maximum number of
      // times for a socket configured to perform seamless handoffs. We now
      // abort the socket and "silent abort" the peer, which will find another
      // available server to try.
      Abort();
      peer_->SilentAbort();

      return;
    }

    timeout_--;

    int64_t  rto_delta = ((t_srtt_ >> TCP_RTT_SHIFT) +
                          MAX(MIN_RTTVAR,
                              ((t_rttvar_ >> TCP_RTTVAR_SHIFT) << 2)));

    // Scale the rtt.
    rto_delta = MAX(min_rto_us_, rto_delta) << t_rxtshift_;
    rto_delta = MIN(rto_delta, max_rto_us_);

    Time duration = Time::FromUsec(rto_delta);
    ScheduleRtoEvent(duration);
  }

  if (timeout_ <= 0)
  {
    if (state_ == TCP_TIME_WAIT)
    {
      prev_state_ = 0;
      state_      = TCP_CLOSE;
    }

    Abort();
    if (peer_)
    {
      peer_->Abort();
    }
  }
}

//============================================================================
void Socket::TimeWaitTimeout()
{
  LogD(kClassName, __func__, "%s, time wait timer fired.\n", flow_id_str_);

  // Clear the time wait timer.
  time_wait_time_.SetInfinite();

  LogD(kClassName, __func__, "%s, transitioning from state TCP_TIME_WAIT to "
       "state TCP_CLOSE.\n", flow_id_str_);

  prev_state_ = state_;
  state_      = TCP_CLOSE;

  if (peer_)
  {
    if (peer_->state_ == TCP_CLOSE)
    {
      socket_mgr_.MarkSocketForRemoval(peer_);
      socket_mgr_.MarkSocketForRemoval(this);
    }
  }
  else
  {
    // We should never get here. If we do for some reason, simply mark this
    // socket for removal. We don't have to worry about our peer because for
    // some reason we don't have one.
    socket_mgr_.MarkSocketForRemoval(this);
  }
}

//============================================================================
void Socket::ClearCcAlgSelection()
{
  // Deselect the currently selected congestion control algorithm.
  for (int i = 0; i < MAX_CC_ALG_CNT; i++)
  {
    if ((cc_algs_[i] != NULL) && cc_algs_[i]->selected())
    {
      cc_algs_[i]->Deselect();
      return;
    }
  }
}

//============================================================================
void Socket::ScheduleDelayedAckEvent(Time& time_delta)
{
  delayed_ack_time_ = Time::Now() + time_delta;
}

//============================================================================
void Socket::ScheduleKeepAliveEvent(Time& time_delta)
{
  keep_alive_time_ = Time::Now() + time_delta;
}

//============================================================================
void Socket::SchedulePersistEvent(Time& time_delta)
{
  persist_time_ = Time::Now() + time_delta;
}

//============================================================================
void Socket::ScheduleRtoEvent(Time& time_delta)
{
  rto_time_ = Time::Now() + time_delta;
}

//============================================================================
void Socket::ScheduleTimeWaitEvent(Time& time_delta)
{
  time_wait_time_ = Time::Now() + time_delta;
}

//============================================================================
void Socket::CancelAllScheduledEvents()
{
  CancelScheduledEvent(next_admission_time_);
  CancelScheduledEvent(delayed_ack_time_);
  CancelScheduledEvent(keep_alive_time_);
  CancelScheduledEvent(persist_time_);
  CancelScheduledEvent(rto_time_);
  CancelScheduledEvent(time_wait_time_);
}

//============================================================================
void Socket::CancelScheduledEvent(Time& time)
{
  time.SetInfinite();
}
