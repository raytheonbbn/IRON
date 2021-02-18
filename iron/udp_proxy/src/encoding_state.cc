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

#include "admission_controller.h"
#include "encoding_state.h"
#include "flog_admission_controller.h"
#include "ipv4_endpoint.h"
#include "iron_types.h"
#include "log.h"
#include "log_admission_controller.h"
#include "packet_pool.h"
#include "strap_admission_controller.h"
#include "string_utils.h"
#include "trap_admission_controller.h"
#include "udp_proxy.h"
#include "unused.h"
#include "utility_fn_if.h"
#include "vdmfec.h"

#include <ctime>
#include <limits>

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

using ::iron::BinIndex;
using ::iron::DstVec;
using ::iron::FlowState;
using ::iron::Ipv4Address;
using ::iron::Ipv4Endpoint;
using ::iron::KVal;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::QueueDepths;
using ::iron::FourTuple;
using ::iron::StringUtils;
using ::iron::Time;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::std::map;
using ::std::numeric_limits;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char  kClassName[] = "EncodingState";
}

//============================================================================
EncodingState::EncodingState(UdpProxy& udp_proxy,
                             iron::QueueDepths& queue_depths,
                             iron::PacketPool& packet_pool,
                             iron::BinMap& bin_map,
                             iron::KVal& k_val,
                             const iron::FourTuple& four_tuple,
                             uint32_t max_queue_depth,
                             iron::DropPolicy queue_drop_policy,
                             iron::BinIndex bin_idx, uint32_t flow_tag,
                             NormFlowController* flow_controller)
    : last_time_(Time::GetNowInSec()),
      group_id_(rand() & FEC_GROUPID_MASK),
      pkt_id_(0),
      orig_count_(0),
      have_blob_(false),
      blob_sz_bytes_(0),
      blob_pkt_cnt_(0),
      have_straggler_(false),
      orig_cache_(),
      fec_count_(0),
      fec_cache_(),
      last_base_rate_(0),
      last_total_rate_(0),
      in_order_(false),
      max_chunk_sz_(0),
      reorder_time_(Time(0)),
      udp_proxy_(udp_proxy),
      queue_depths_(queue_depths),
      packet_pool_(packet_pool),
      bin_map_(bin_map),
      four_tuple_(four_tuple),
      flow_tag_(flow_tag),
      bin_idx_(bin_idx),
      k_val_(k_val),
      encoded_pkts_queue_(packet_pool),
      max_encoded_pkts_queue_depth_(max_queue_depth),
      admission_controller_(NULL),
      flow_controller_(flow_controller),
      src_rate_estimator_(),
      src_info_(encoded_pkts_queue_),
      timeout_(0),
      time_to_go_(),
      time_to_go_valid_(false),
      dscp_(0),
      mgen_seq_num_(0),
      original_pkt_seq_num_(1),
      admitted_seq_num_(0),
      acked_seq_num_(0),
      loss_rate_pct_(0),
      dump_byte_number_(0),
      dump_pkt_number_(0),
      total_byte_number_(0),
      total_pkt_number_(0),
      last_report_time_(Time::Now()),
      utility_(0.0),
      utility_str_(),
      mcast_dst_vec_(0),
      has_mcast_dst_vec_(false)
{
  memset(&group_start_time_, 0, sizeof(timeval));
  memset(&flush_time_, 0, sizeof(timeval));
  memset(&max_hold_time_, 0, sizeof(timeval));

  encoded_pkts_queue_.SetQueueLimits(max_queue_depth);
  encoded_pkts_queue_.set_drop_policy(queue_drop_policy);
}

//============================================================================
EncodingState::~EncodingState()
{
  // Destroy the admission controller.
  if (admission_controller_ != NULL)
  {
    delete admission_controller_;
    admission_controller_ = NULL;
  }

  // Destroy the flow controller.
  if (flow_controller_ != NULL)
  {
    delete flow_controller_;
    flow_controller_ = NULL;
  }

  // Recycle any Packets in the cache.
  FlushCache();
}

//============================================================================
bool EncodingState::CreateAdmissionController(string utility_def)
{
  // First, get the utility function type for the flow.
  size_t  type_str_pos = utility_def.find("type=");
  if (type_str_pos == string::npos)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", invalid utility "
         "definition.\n", flow_tag_);
    return false;
  }

  size_t  type_str_end_pos = utility_def.find(":", type_str_pos);
  if (type_str_end_pos == string::npos)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", invalid utility "
         "definition.\n", flow_tag_);
    return false;
  }

  std::string  utility_def_type = utility_def.substr(type_str_pos + 5,
                                                     type_str_end_pos - 5);
  uint32_t  toggle_count = 0;
  // If there is an existing admission controller, it should be recreated
  // if any parameter of the utility function is different, else it should
  // be updated.
  if (admission_controller_ != NULL)
  {
    if (utility_str_ != utility_def)
    {
      LogD(kClassName, __func__,
           "New utility function, recreating admission control.\n");
      toggle_count = admission_controller_->toggle_count();
      delete admission_controller_;
      admission_controller_ = NULL;
    }
    else if ((flow_state() == iron::FLOW_TRIAGED) ||
             (flow_state() == iron::FLOW_OFF))
    {
      LogD(kClassName, __func__, "Restarting flow.\n");
      admission_controller_->set_flow_state(iron::FLOW_ON);
      return true;
    }
    else
    {
      LogE(kClassName, __func__,
           "Flow is neither OFF or TRIAGED and cannot be restarted.\n");
      return false;
    }
  }

  // Finally, create the admission controller for the flow.
  if (utility_def_type == "LOG")
  {
    LogI(kClassName, __func__, "fid: %" PRIu32 ", flow has LOG utility.\n",
         flow_tag_);
    admission_controller_ = new (std::nothrow) LogAdmissionController(*this);
  }
  else if (utility_def_type == "TRAP")
  {
    LogI(kClassName, __func__, "fid: %" PRIu32 ", flow has TRAP utility.\n",
         flow_tag_);
    admission_controller_ = new (std::nothrow) TrapAdmissionController(*this);
  }
  else if (utility_def_type == "STRAP")
  {
    LogI(kClassName, __func__, "fid: %" PRIu32 ", flow has STRAP utility.\n",
         flow_tag_);
    admission_controller_ = new (std::nothrow)
      StrapAdmissionController(*this, src_rate_estimator_, src_info_);
  }
  else if (utility_def_type == "FLOG")
  {
    LogI(kClassName, __func__, "fid: %" PRIu32 ", flow has FLOG utility.\n",
         flow_tag_);
    admission_controller_ = new (std::nothrow)
      FlogAdmissionController(*this, src_rate_estimator_, src_info_);
  }
  else
  {
    LogW(kClassName, __func__, "fid: %" PRIu32 ", %s utility is currently "
         "unsupported.\n", flow_tag_, utility_def_type.c_str());
    return false;
  }

  if (admission_controller_ == NULL)
  {
    LogF(kClassName, __func__, "fid: %" PRIu32 ", error allocating new "
         "encoding state admission controller.\n", flow_tag_);
    return false;
  }

  if (!admission_controller_->CreateUtilityFn(utility_def, flow_tag_,
                                              queue_depths_))
  {
    LogE(kClassName, __func__, "fid: %" PRIu32 ", error creating admission "
         "controller utility function.\n", flow_tag_);
    return false;
  }

  admission_controller_->set_toggle_count(toggle_count);

  return true;
}

//============================================================================
void EncodingState::HandlePkt(Packet* pkt)
{
  last_time_ = iron::Time::GetNowInSec();

  // Update the source rate.
  src_info_.UpdateTotalBytesSent(pkt->GetLengthInBytes());

  if (udp_proxy_.do_latency_checks())
  {
    // Check the latency requirements of the flow.
    if ((flow_state() == iron::UNREACHABLE) &&
        (udp_proxy_.GetMinLatency(bin_idx_) < time_to_go_.GetTimeInUsec()))
    {
      set_flow_state(iron::FLOW_ON);
      LogD(kClassName, __func__, "fid: %" PRIu32 ", flow to %s "
           " now reachable.\n", flow_tag_,
           bin_map_.GetIdToLog(bin_idx_).c_str());
    }
    else if ((flow_state() == iron::FLOW_ON) &&
             (udp_proxy_.GetMinLatency(bin_idx_) > time_to_go_.GetTimeInUsec()))
    {
      // TODO: If we want to flush the backlog, here's the spot.
      set_flow_state(iron::UNREACHABLE);
      LogD(kClassName, __func__, "fid: %" PRIu32 ", flow to %s "
           " not reachable. Minimum latency: %" PRIu32 " microseconds, ttg: "
           "%s\n", flow_tag_, bin_map_.GetIdToLog(bin_idx_).c_str(),
           udp_proxy_.GetMinLatency(bin_idx_),
           time_to_go_.ToString().c_str());
    }
  }

  // Drop the packet if the flow is not on.
  if (flow_state() != iron::FLOW_ON)
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 " is off, dropping packet.\n",
         flow_tag_);
    packet_pool_.Recycle(pkt);
    return;
  }

  // If the EncodedPacketsQueue is full, better drop it now.
  if (encoded_pkts_queue_.GetCount() > (max_encoded_pkts_queue_depth_ - 10))
  {
    udp_proxy_.IncrementTotalSrcDrop();
    packet_pool_.Recycle(pkt);
    return;
  }

  // See if we will overrun the cache holding the original chunks.
  int  paylen = pkt->GetIpPayloadLengthInBytes();

  // Assign the DSCP field.
  if (dscp_ != -1)
  {
    // The dscp value has already been checked, so can cast to unsigned.
    if (pkt->SetIpDscp(static_cast<uint8_t>(dscp_)))
    {
      LogD(kClassName, __func__, "fid: %" PRIu32 ", changing packet's DSCP "
           "field to %u.\n", flow_tag_, static_cast<uint8_t>(dscp_));
    }
  }

  struct timeval  current_time;
  if (WillOverrun(paylen))
  {
    // Looks like we will overrun. Force an FEC flush by making the current
    // time equal to the flush time.
    current_time = flush_time_;

    if (UpdateFEC(&current_time))
    {
      LogD(kClassName, __func__, "fid: %" PRIu32 ", preemptive FEC "
           "completed. Sending FEC packets for %d, %d, %d\n", flow_tag_,
           group_id_, orig_count_, fec_count_);

      // Send out the FEC repair packets, including any stragglers.
      SendFecPackets();
    }

    // We just flushed the cache, so should have plenty of room but worth
    // checking to see if it will fit at all...
    if (WillOverrun(paylen))
    {
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(pkt);
      LogF(kClassName, __func__, "fid: %" PRIu32 ", something amiss with "
           "encoder settings.\n", flow_tag_);
      return;
    }
  }

  // Drop this packet into the FEC construction cache, carving it up as
  // needed.
  int  num_pkts;
  int  start_index;
  DisassembleIntoCache(pkt, &start_index, &num_pkts);

  // Send the (now FEC managed) packet/chunks.
  for (int i = 0; i < num_pkts; i++)
  {
    Packet*  cpkt = NULL;
    if ((cpkt = FetchFromCache(FEC_ORIGINAL, start_index + i))
        == NULL)
    {
      LogW(kClassName, __func__, "fid: %" PRIu32 ", fetchFromCache failed.\n",
           flow_tag_);
      break;
    }

    // Increment ref count before passing to BPF.
    //
    // We increment the ref count here (and do a shallow copy) because while
    // the UDP Proxy hangs on to this cpkt for FEC, the packet is also
    // enqueued waiting to be admitted. Following admission, the packet will
    // be passed to the BPF and ownership will be handed off. Only if the
    // transfer to the BPF fails will we decrement the ref count. Doing the
    // ref count increment here also prevents yanking the packet from the
    // EncodedPktQueue in case the FEC code calls for the cache to be
    // flushed. When the BPF is done with the packet, it will decrement the
    // ref count, and the other ref count decrement will happen when the FEC
    // calls flush on orig_cache_.
    packet_pool_.PacketShallowCopy(cpkt);

    // Enqueue the packets, they will be sent by the Encoding State's
    // admission control.
    if (!encoded_pkts_queue_.Enqueue(cpkt))
    {
      LogW(kClassName, __func__, "fid: %" PRIu32 ", error enqueuing FEC "
           "packet to encoded packets queue.\n", flow_tag_);

      packet_pool_.Recycle(cpkt);
    }

    if (flow_controller_)
    {
      flow_controller_->HandleRcvdPkt(cpkt);
    }
  }

  // See if we can generate the FEC packets.
  Time now     = Time::Now();
  current_time = now.ToTval();

  if (UpdateFEC(&current_time))
  {
    LogD(kClassName, __func__, "fid: %" PRIu32 ", FEC completed. Sending FEC "
         "packets for %d, %d, %d\n", flow_tag_, group_id_, orig_count_,
         fec_count_);

    // We were able to generate the FEC packets, so send them out.
    SendFecPackets();
  }
}

//============================================================================
void EncodingState::SvcEvents(Time& now)
{
  LogD(kClassName, __func__, "fid: %" PRIu32 ", servicing events.\n",
       flow_tag_);

  if (src_info_.total_bytes_sent() > 0)
  {
    src_rate_estimator_.UpdateRate(src_info_.total_bytes_sent(), 0);
  }

  // Service all events that have expired.
  if (admission_controller_ != NULL)
  {
    admission_controller_->SvcEvents(now);
  }
}

//============================================================================
size_t EncodingState::AdmitPacket()
{
  if (encoded_pkts_queue_.GetCount() == 0)
  {
    return 0;
  }

  Packet* pkt = encoded_pkts_queue_.Dequeue();
  if (!pkt)
  {
    LogW(kClassName, __func__, "fid: %" PRIu32 ", Dequeue from encoded "
         "packets queue returned no packet.\n", flow_tag_);
    return 0;
  }



  if (udp_proxy_.mgen_diag_mode() != "none")
  {
     struct timeval now_tv;

     if (udp_proxy_.mgen_diag_mode() == "ow-time")
     {
       Time now  = Time::Now();
       now_tv    = now.ToTval();
     }
     else if (udp_proxy_.mgen_diag_mode() == "ow-wallclock")
     {
       gettimeofday(&now_tv, 0);
     }
     else
     {
       LogF(kClassName, __func__, "Unsupported mgen_diag_mode: %s\n",
         udp_proxy_.mgen_diag_mode().c_str());
     }
     ResetMgen(pkt, now_tv);
   }

  packet_pool_.AssignPacketId(pkt);

  // Note: this will enable tracking time-to-go all UDP packets, including
  // those with TTG set and those that are using dummy (infinite) TTG.
  // \todo This is should be true if
  //   1. It is a log flow and it has a ttg.
  //   2. It is a TRAP or STRAP flow. This is used to calculate the source
  //      rate at the destination, for the ReleaseController, and is needed
  //      even if it is not a low latency flow.
  // This should be moved into the encoding state packet processing when
  // that method is implemented.

#ifdef LAT_MEASURE
  if (pkt->GetLatencyClass() == iron::NORMAL_LATENCY)
  {
    struct  timeval now_tv;
    gettimeofday(&now_tv, 0);
    Time            now(now_tv);

    pkt->set_origin_ts_ms(static_cast<uint16_t>(now.GetTimeInMsec() & 0x7fff));
  }
  // Track time-to-go for all packets demo mode.
  pkt->set_track_ttg(true);
#else
  // Only EF packets track time-to-go.
  pkt->set_track_ttg(pkt->GetLatencyClass() == iron::LOW_LATENCY);
#endif

  // Zero out the checksums.
  pkt->ZeroChecksums();

  // Print hold times, used by plotting script
  Time hold_time = Time::Now() - pkt->recv_time();
  LogD(kClassName, __func__, "fid: %" PRIu32 ", packet hold time: %" PRId64
       " microseconds.\n",  flow_tag_, hold_time.GetTimeInUsec());

//  uint32_t fec_group = 0;
//  uint32_t fec_slot  = 0;
//  if (pkt->GetGroupId(fec_group))
//  {
//    if (pkt->GetSlotId(fec_slot))
//    {
//      LogA(cn, __func__, "Map: Group <%" PRIu32 "> Slot <%"
//           PRIu32"> %s (send to bpf).\n", fec_group, fec_slot,
//           pkt->GetPacketMetadataString().c_str());
//    }
//  }

  uint32_t seq_num = 0;
  pkt->GetFecSeqNum(seq_num);
  admitted_seq_num_ = seq_num;

  // \todo Extend Send() to allow multiple packets per call.
  // if (udp_to_bpf_pkt_fifo_.Send(pkt))
  // {
  //   // If the Send() succeeds, the Packet in shared memory is being
  //   // handed over to the backpressure forwarder, so we cannot Recycle()
  //   // it.
  //   AccumulatePacketInfo(bytes_sent);
  // }
  size_t  bytes_sent = pkt->GetLengthInBytes();

  // Add the destination bit vector to the packet, if required.
  struct iphdr*  ip_hdr   = pkt->GetIpHdr();
  Ipv4Address    dst_addr(ip_hdr->daddr);
  BinIndex       dst_bidx = bin_map_.GetDstBinIndexFromAddress(dst_addr);

  if (dst_bidx == iron::kInvalidBinIndex)
  {
    LogD(kClassName, __func__, "Unable to find Bin Index and IRON Node "
         "Address for received packet with destination address %s.\n",
         dst_addr.ToString().c_str());

    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(pkt);
    pkt = NULL;
    return 0;
  }

  if (bin_map_.IsMcastBinIndex(dst_bidx))
  {
    DstVec  dst_vec = 0;

    has_mcast_dst_vec_ ? dst_vec = mcast_dst_vec_ :
      dst_vec = bin_map_.GetMcastDst(dst_bidx);

    if (dst_vec == 0)
    {
      packet_pool_.Recycle(pkt);
      return 0;
    }

    pkt->set_dst_vec(dst_vec);
    LogD(kClassName, __func__, "Set packet %p w/ destination bit vector %X "
         "for bin %s\n", pkt, dst_vec, bin_map_.GetIdToLog(dst_bidx).c_str());
  }

  if (udp_proxy_.SendToBpf(pkt))
  {
    // If the Send() succeeds, the Packet in shared memory is being
    // handed over to the backpressure forwarder, so we cannot Recycle()
    // it.
    AccumulatePacketInfo(bytes_sent);

    if (flow_controller_)
    {
      flow_controller_->HandleSentPkt(pkt);
    }
  }
  else
  {
    LogW(kClassName, __func__, "fid: %" PRIu32 ", admitted packet "
         "transmission failed. Recycling packet...\n", flow_tag_);
    // TODO: Re-enqueue at the front.
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(pkt);
    return 0;
  }
  std::string metadata = pkt->GetPacketMetadataString();
  LogD(kClassName, __func__, "SEND: Proxy to BPF IPC, size %" PRId32
       " bytes, pkt %s.\n", bytes_sent, metadata.c_str());

  return bytes_sent;
}

//============================================================================
bool EncodingState::SendFecPackets()
{
  int      count;
  int      i;
  Packet*  rpkt = NULL;
  bool     rc   = true;

  // FEC generation succeeded
  //
  // We may get a straggler packet from forcing an FEC generation when we have
  // an incomplete blob. If we have one, it will always be the last packet in
  // the original packet cache.
  if (have_straggler_)
  {
    count = orig_count_;

    if ((rpkt = FetchFromCache(FEC_ORIGINAL, count-1)) == NULL)
    {
      LogW(kClassName, __func__, "fid: %" PRIu32 ", Failed to fetch packet "
           "from cache.\n", flow_tag_);

      rc = false;
      goto ErrorExit;
    }

    LogD(kClassName, __func__, "fid: %" PRIu32 ", sending straggler "
         "packet.\n", flow_tag_);

    // Enqueue the packets. They will be sent by admission control. Increment
    // ref count before passing to the BPF.
    packet_pool_.PacketShallowCopy(rpkt);
    if (!encoded_pkts_queue_.Enqueue(rpkt))
    {
      LogW(kClassName, __func__, "fid: %" PRIu32 ", error enqueuing FEC "
           "packet to encoded packets queue.\n", flow_tag_);

      packet_pool_.Recycle(rpkt);
      goto ErrorExit;
    }

    LogD(kClassName, __func__, "fid: %" PRIu32 ", encoded straggler packet "
         "enqueued.\n", flow_tag_);
  }

  // Retrieve the FEC packets and send them
  for (i = 0; i < fec_count_; i++)
  {
    if ((rpkt = FetchFromCache(FEC_REPAIR, i)) == NULL)
    {
      LogW(kClassName, __func__, "fid: %" PRIu32 ", Failed to fetch packet "
           "from cache.\n", flow_tag_);

      rc = false;
      goto ErrorExit;
    }

    // Enqueue the packets, they will be sent by admission control. Increment
    // ref count before sending to BPF.
    packet_pool_.PacketShallowCopy(rpkt);
    if (!encoded_pkts_queue_.Enqueue(rpkt))
    {
      LogW(kClassName, __func__, "fid: %" PRIu32 ", error enqueuing FEC "
           "packet to encoded packets queue.\n", flow_tag_);

      packet_pool_.Recycle(rpkt);
      goto ErrorExit;
    }

    std::string metadata = rpkt->GetPacketMetadataString();
    LogD(kClassName, __func__, "fid: %" PRIu32 ", FEC packet %s enqueued.\n",
         flow_tag_, metadata.c_str());
  }

  ErrorExit:

  // All done with this set. Flush the cache and get ready for the next set.
  FlushCache();
  set_group_id(group_id_ + 1);

  return rc;
}

//============================================================================
bool EncodingState::UpdateFEC(struct timeval *currentTime)
{
  Packet *qpkt;
  Packet *rpkt;

  FECControlTrailer fecTrlr;
  FECControlTrailer savFecTrlr;
  FECRepairTrailer  repTrlr;

  unsigned char *qptr;
  unsigned char *qdata;
  int            qlen;

  unsigned char *rptr;
  unsigned char *rdata;
  int            rlen;

  unsigned short fecLen;

  int fecRate;
  int i;
  int j;

  int baseRate;
  int totalRate;

  bool flush;

  // Return if we have nothing to do

  if ((orig_count_ == 0) && !(have_blob_))
  {
    return false;
  }

  // See if we need to flush based on timeouts
  // Here we also insist that we have at least one packet in the
  // cache to keep the cleanup function from triggering an
  // FEC generation without actually having any data to do so with

  if (timercmp(currentTime, &flush_time_, >=))
  {
    flush = true;

    // If we are forcing a flush, make sure to clean up any blobs

    if (have_blob_)
    {
      CommitBlobToCache();

      // We need to signal that we have an untransmitted original packet
      have_straggler_ = true;
    }
  }
  else
  {
    flush = false;
  }

  // See if we have enough packets to generate any FEC packets
  // or we need to generate FEC packets anyway since we have
  // timed out and need to flush using whatever packets we have

  if ((orig_count_ < last_base_rate_) && !flush)
  {
    return false;
  }

  // Retrieve the current FEC settings
  baseRate  = last_base_rate_;
  totalRate = last_total_rate_;

  // Take care of conditions that can arise due to on-the-fly
  // modifications of the encoding rate
  LogD(kClassName, __func__, "Base rate is %d, origin count is %d\n",
       baseRate,orig_count_);

  if (orig_count_ > baseRate)
  {
    // Larger codes are more efficient, so we round down

    totalRate = (totalRate * orig_count_) / baseRate;
    if (totalRate > MAX_FEC_RATE + baseRate)
    {
      totalRate = MAX_FEC_RATE + baseRate;
    }
    baseRate = orig_count_;
  }
  else if ((orig_count_ < baseRate) && flush)
  {
    // Shorter codes are less efficient, so we round up

    totalRate = (totalRate * orig_count_ + baseRate - 1) / baseRate;
    if (totalRate < orig_count_)
    {
      totalRate = orig_count_;
    }
    baseRate = orig_count_;
  }

  fecRate = totalRate - baseRate;

  LogD(kClassName, __func__, "FEC rate is %d\n", fecRate);
  // First check for benign encoding

  if (fecRate == 0)
  {
    fec_count_ = 0;
    return true;
  }

  // We support two special modes: rate 1/N, and rate N/(N+1)
  // in addition to the more general N/(N+K) Vandermond matrix
  // based FEC encoder

  if (baseRate == 1) // rate 1/N mode
  {
    // Grab the first packet from the cache (only have one for this mode)
    LogD(kClassName, __func__, " Base rate 1\n");
    qpkt = orig_cache_[0];

    int nFecPkts    = totalRate - baseRate;

    repTrlr.base_rate = baseRate;
    repTrlr.fec_rate  = nFecPkts;
    repTrlr.fec_len   = qpkt->GetLengthInBytes();

    fec_count_ = 0;
    for (j=0; j<nFecPkts; j++)
    {
      rpkt = packet_pool_.Clone(qpkt, false, iron::PACKET_NOW_TIMESTAMP);

      // Note: cached packets have the FEC trailer appended to them
      // We trim them back to make the bookkeeping work
      if (!rpkt->RemoveBlockFromEnd((uint8_t*)&fecTrlr,(int)sizeof(fecTrlr)))
      {
        LogW(kClassName, __func__, "Failed to remove block from end\n");
      }

      fecTrlr.type             = FEC_REPAIR;
      fecTrlr.slot_id          = j;
      fecTrlr.total_bytes_sent = src_info_.total_bytes_sent();
      fecTrlr.seq_number       = original_pkt_seq_num_;

      rpkt->AppendBlockToEnd((uint8_t*)&repTrlr,sizeof(repTrlr));
      rpkt->AppendBlockToEnd((uint8_t*)&fecTrlr,sizeof(fecTrlr));
      // rpkt->UpdateChecksums();

      fec_cache_[fec_count_++] = rpkt;
    }
  }

  else if (fecRate == 1) // rate N/(N+1) mode
  {
    // Grab the first packet from the cache

    LogD(kClassName, __func__, " FEC-- rate 1\n");
    qpkt = orig_cache_[0];

    // Snarf the FEC trailer (just need the original destination port)

    if (!qpkt->CopyBlockFromEnd((uint8_t*)&fecTrlr,(int)sizeof(fecTrlr)))
    {
      LogW(kClassName, __func__, "Failed to remove block from end\n");
    }

    fecTrlr.type = FEC_REPAIR;

    rpkt  = packet_pool_.Clone(qpkt, false, iron::PACKET_NO_TIMESTAMP);
    rptr  = rpkt->GetBuffer();
    rdata = rptr + rpkt->GetIpPayloadOffset();
    rlen  = rpkt->GetLengthInBytes();

    memset (&rptr[rlen],0,rpkt->GetMaxLengthInBytes()-rlen);
    rlen -= (rdata - rptr);

    fecLen = (unsigned short)rlen;

    // Pull remaining packets in sequence from the cache
    // and use to compute the single FEC block

    for (i=1; i< orig_count_; i++)
    {
      qpkt = orig_cache_[i];

      qptr  = qpkt->GetBuffer();
      qdata = qptr + qpkt->GetIpPayloadOffset();
      qlen  = qpkt->GetLengthInBytes() - (qdata - qptr) - sizeof(fecTrlr);

      for (j=0; j<qlen; j++)
      {
        rdata[j] ^= qdata[j];
      }

      if (rlen < qlen)
      {
        rlen = qlen;
      }

      // Also compute the FEC over the lengths to tuck
      // into the repair header when we're done

      fecLen ^= (unsigned short)qlen;
    }

    LogD(kClassName, __func__, "N/N+1 payload length is: %d\n",rlen);

    // Set the various lengths
    rpkt->UpdateIpLen (rlen + (rdata - rptr));

    // Finish setting up the FEC control and repair headers
    fecTrlr.slot_id          = 0;
    fecTrlr.total_bytes_sent = src_info_.total_bytes_sent();
    fecTrlr.seq_number       = original_pkt_seq_num_;

    repTrlr.base_rate = baseRate;
    repTrlr.fec_rate  = fecRate;
    repTrlr.fec_len   = fecLen;

    rpkt->AppendBlockToEnd((uint8_t*)&repTrlr,sizeof(repTrlr));
    rpkt->AppendBlockToEnd((uint8_t*)&fecTrlr,sizeof(fecTrlr));

    // Update the checksum
    // rpkt->UpdateChecksums();

    fec_count_ = 0;
    fec_cache_[fec_count_++] = rpkt;
  }
  else // Use the VDM FEC encoding function
  {
    unsigned char *pdata  [MAX_FEC_RATE];
    unsigned short szArray[MAX_FEC_RATE];
    unsigned char *pfec   [MAX_FEC_RATE];
    unsigned short fecSz  [MAX_FEC_RATE];

    ::memset(pdata,   0, sizeof(pdata));
    ::memset(szArray, 0, sizeof(szArray));
    ::memset(pfec,    0, sizeof(pfec));
    ::memset(fecSz,   0, sizeof(fecSz));

    rlen = 0;

    for (i=0; i< orig_count_; i++)
    {
      // Grab a packet from the cache
      qpkt = orig_cache_[i];

      // If its the first packet we have grabbed, then snarf
      // the FEC trailer (to get the original destination port)

      if (i == 0)
      {
        if (!qpkt->CopyBlockFromEnd((uint8_t*)&fecTrlr,(int)sizeof(fecTrlr)))
        {
          LogW(kClassName, __func__,  "Failed to remove block from end\n");
        }

        fecTrlr.type    = FEC_REPAIR;
      }

      qptr  = qpkt->GetBuffer();
      qdata = qptr + qpkt->GetIpPayloadOffset();
      qlen  = qpkt->GetLengthInBytes() - (qdata - qptr) - sizeof(fecTrlr);

      pdata[i]   = qdata;
      szArray[i] = qlen;

      if (rlen < qlen)
      {
        rlen = qlen;
      }
    }

    // Make sure repair packets are always an even number of bytes in length
    // This is because the vdm code uses unsigned shorts for computation
    // and any roll over will end up in the low order bits -- which we'll
    // need to preserve

    if (rlen & 0x1)
    {
      rlen++;
    }

    qpkt = orig_cache_[0];

    fec_count_ = 0;
    for (i=0; i<fecRate; i++)
    {
      // On the first pass we clone an original packet and set its length
      if (i == 0)
      {
        qpkt = orig_cache_[0];
        rpkt = packet_pool_.Clone(qpkt, false, iron::PACKET_NOW_TIMESTAMP);
        rpkt->UpdateIpLen(rlen + rpkt->GetIpPayloadOffset());
      }

      // On subsequent passes can simply duplicate an existing repair packet
      else
      {
        qpkt = fec_cache_[i-1];
        rpkt = packet_pool_.Clone(qpkt, false, iron::PACKET_NOW_TIMESTAMP);
      }

      fec_cache_[i] = rpkt;
      fec_count_++;

      rptr    = rpkt->GetBuffer();
      rdata   = rptr + rpkt->GetIpPayloadOffset();
      pfec[i] = rdata;
    }

    encode_vdmfec (pdata, szArray, orig_count_, pfec, fecSz, fec_count_);

    // Finish setting up the FEC control and repair trailers

    repTrlr.base_rate = baseRate;
    repTrlr.fec_rate  = fecRate;

    for (i=0; i<fec_count_; i++)
    {
      fecTrlr.slot_id          = i;
      fecTrlr.total_bytes_sent = src_info_.total_bytes_sent();
      fecTrlr.seq_number       = original_pkt_seq_num_;
      repTrlr.fec_len          = fecSz[i];

      rpkt = fec_cache_[i];
      rpkt->AppendBlockToEnd((uint8_t*)&repTrlr,sizeof(repTrlr));
      rpkt->AppendBlockToEnd((uint8_t*)&fecTrlr,sizeof(fecTrlr));
    }
  }

  // If we had a straggler, we need to restore the FEC control trailer
  // and recompute the checksums (the straggler hasn't yet been
  // transmitted)

  return (true);
}

//============================================================================
bool EncodingState::UpdateEncodingParams(int baseRate, int totalRate,
                                         bool in_order, int maxChunkSz,
                                         struct timeval maxHoldTime,
                                         time_t timeout,
                                         const Time& time_to_go,
                                         bool ttg_valid,
                                         int8_t dscp,
                                         const Time& reorder_time,
					 const DstVec& dst_vec)
{
  struct timeval maxHoldTimeTmp = maxHoldTime;

  // Update the flush time, if necessary.
  if ((orig_count_ > 0) || have_blob_)
  {
    timeradd(&group_start_time_, &maxHoldTimeTmp, &flush_time_);
  }

  // Update the current FEC settings
  // .. the straggler removal processing will need 'em.
  last_base_rate_   = baseRate;
  last_total_rate_  = totalRate;
  in_order_         = in_order;
  max_chunk_sz_     = maxChunkSz;
  max_hold_time_    = maxHoldTime;
  timeout_          = timeout;
  time_to_go_       = time_to_go;
  time_to_go_valid_ = ttg_valid;
  dscp_             = dscp;
  reorder_time_     = reorder_time;
  mcast_dst_vec_    = dst_vec;

  if (mcast_dst_vec_ == 0)
  {
    has_mcast_dst_vec_ = false;
  }
  else
  {
    has_mcast_dst_vec_ = true;
  }

  if (flow_controller_)
  {
    flow_controller_->UpdateEncodingRate(baseRate / totalRate);
  }

  return true;
}

//============================================================================
int EncodingState::FlushCache()
{
  int i;

  for (i = 0; i < orig_count_; ++i)
  {
    // Decrement ref count / recycle (no longer needed).
    packet_pool_.Recycle(orig_cache_[i]);
  }
  orig_count_ = 0;

  for (i = 0; i < fec_count_; ++i)
  {
    // Decrement ref count / recycle (no longer needed).
    packet_pool_.Recycle(fec_cache_[i]);
  }
  fec_count_ = 0;

  // Update the last time this was touched for state cleanup actions.
  last_time_ = Time::GetNowInSec();


  // Push the maximum hold expiration time into the future.
  flush_time_.tv_sec  = 0x7fff0000;
  flush_time_.tv_usec = 0x00000000;

  pkt_id_ =  0;

  // Clear out any blob state.
  have_blob_      = false;
  blob_pkt_cnt_    = 0;
  blob_sz_bytes_   = 0;

  have_straggler_ = false;

  return FECSTATE_OKAY;
}

//============================================================================
void EncodingState::set_flow_state(FlowState flow_state)
{
  if (admission_controller_ != NULL)
  {
    admission_controller_->set_flow_state(flow_state);
  }
}

//============================================================================
const Time& EncodingState::sched_svc_time() const
{
  return udp_proxy_.sched_service_time();
}

//============================================================================
void EncodingState::AccumulatePacketInfo(uint64_t length_bytes)
{
  dump_byte_number_ += length_bytes;
  dump_pkt_number_++;
  total_byte_number_ += length_bytes;
  total_pkt_number_++;

  LogD(kClassName, __func__, "fid: %" PRIu32 ", accumulating packet of size "
       "%" PRIu64 " bytes (total %" PRIu64 ").\n", flow_tag_, length_bytes,
       total_byte_number_);
}

//============================================================================
void EncodingState::UpdateReceiverStats(uint32_t sn,
                                        uint32_t loss_rate_pct)
{
  if (sn >= acked_seq_num_)
  {
    acked_seq_num_    = sn;
    loss_rate_pct_  = loss_rate_pct;
  }
}

//============================================================================
void EncodingState::WriteStats(Time& now, string& log_str,
                               Writer<StringBuffer>* writer)
{
  // The collected statistics for outbound flows are reported via the
  // following name/value pairs.
  //
  //   "flow_id"         : "a.b.c.d:eph -> e.f.g.h:svc",
  //   "prio"            : xxxx.xxx,
  //   "pkts"            : xxxxxx,
  //   "bytes"           : xxxxxx,
  //   "rate_bps"        : xxxx.xxx,
  //   "rate_pps"        : xxxx.xxx,
  //   "acked_seq_num"   : xxxx,
  //   "loss_rate_pct"   : xx,
  //   "utility"         : xxxx.xxx,
  //   "flow_state"      : x,
  //   "bin_id"          : x,
  //   "src_rate"        : xxx.xxx
  //   "toggle_count"    : xxx

  double  rate_bps = 0.0;
  double  pps      = 0.0;

  if (now > last_report_time_)
  {
    double  delta_usec = static_cast<double>(
      (now - last_report_time_).GetTimeInUsec());

    rate_bps = static_cast<double>(
      (dump_byte_number_ * 8000000.0) / delta_usec);
    pps      = static_cast<double>(
      (dump_pkt_number_ * 1000000.0) / delta_usec);
  }

  int    flow_state = iron::UNDEFINED;
  double priority       = 0.0;
  uint32_t toggle_count = 0;
  if (admission_controller_ != NULL)
  {
    utility_     = admission_controller_->ComputeUtility(rate_bps);
    flow_state   = static_cast<int>(admission_controller_->flow_state());
    priority     = admission_controller_->priority();
    toggle_count = admission_controller_->toggle_count();
  }

  string  flow_id_str = (Ipv4Endpoint(four_tuple_.src_addr_nbo(),
                                      four_tuple_.src_port_nbo()).ToString() +
                         " -> " +
                         Ipv4Endpoint(four_tuple_.dst_addr_nbo(),
                                      four_tuple_.dst_port_nbo()).ToString());

  if (udp_proxy_.log_stats())
  {
    log_str.append(
      StringUtils::FormatString(256, "'%s':{", flow_id_str.c_str()));

    log_str.append(
      StringUtils::FormatString(256, "'prio':'%f', ", priority));

    log_str.append(
      StringUtils::FormatString(256, "'sent_pkts':'%" PRIu32 "', ",
                                admitted_seq_num_));

    log_str.append(
      StringUtils::FormatString(256, "'sent_bytes':'%" PRIu64 "', ",
                                total_byte_number_));

    log_str.append(
      StringUtils::FormatString(256, "'sent_rate_bps':'%f', ", rate_bps));

    log_str.append(
      StringUtils::FormatString(256, "'sent_rate_pps':'%f', ", pps));

    log_str.append(
      StringUtils::FormatString(256, "'acked_sn':'%" PRIu32 "', ",
                                acked_seq_num_));

    log_str.append(
      StringUtils::FormatString(256, "'loss_rate_pct':'%" PRIu32 "', ",
                                loss_rate_pct_));

    log_str.append(
      StringUtils::FormatString(256, "'utility':'%f', ", utility_));

    log_str.append(
      StringUtils::FormatString(256, "'flow_state':'%d', ", flow_state));

    if (bin_map_.IsMcastBinIndex(bin_idx_))
    {
      log_str.append(
        StringUtils::FormatString(256, "'mcast_id':'%" PRIMcastId "', ",
                                  bin_map_.GetMcastId(bin_idx_)));
    }
    else
    {
      log_str.append(
        StringUtils::FormatString(256, "'bin_id':'%" PRIBinId "', ",
                                  bin_map_.GetPhyBinId(bin_idx_)));
    }

    log_str.append(
      StringUtils::FormatString(256, "'src_rate':'%f'",
                                src_rate_estimator_.avg_src_rate()));
    log_str.append(
      StringUtils::FormatString(256, "'toggle_count':'%" PRIu32 "'}",
      toggle_count));

  }

  if (writer)
  {
    writer->StartObject();

    writer->Key("flow_id");
    writer->String(flow_id_str.c_str());

    writer->Key("prio");
    writer->Double(priority);

    writer->Key("pkts");
    writer->Uint(admitted_seq_num_);

    writer->Key("bytes");
    writer->Uint64(total_byte_number_);

    writer->Key("rate_bps");
    writer->Double(rate_bps);

    writer->Key("rate_pps");
    writer->Double(pps);

    writer->Key("acked_seq_num");
    writer->Uint(acked_seq_num_);

    writer->Key("loss_rate_pct");
    writer->Uint(loss_rate_pct_);

    writer->Key("utility");
    writer->Double(utility_);

    writer->Key("flow_state");
    writer->Int(flow_state);

    if (bin_map_.IsMcastBinIndex(bin_idx_))
    {
      writer->Key("mcast_id");
      writer->Uint(bin_map_.GetMcastId(bin_idx_));
    }
    else
    {
      writer->Key("bin_id");
      writer->Uint(bin_map_.GetPhyBinId(bin_idx_));
    }

    writer->Key("src_rate");
    writer->Double(src_rate_estimator_.avg_src_rate());

    writer->Key("toggle_count");
    writer->Uint(toggle_count);

    writer->EndObject();
  }

  // Reset the per interval statistics.
  dump_byte_number_ = 0;
  dump_pkt_number_  = 0;
  last_report_time_ = now;
}

//============================================================================
void EncodingState::UpdateUtilityFn(std::string param)
{
  if (admission_controller_ != NULL)
  {
    admission_controller_->UpdateUtilityFn(param);
    return;
  }
  LogE(kClassName, __func__, "Admission controller does not exist.\n");
}

//============================================================================
bool EncodingState::PushStats() const
{
  if (admission_controller_ != NULL)
  {
    return admission_controller_->push_stats();
  }
  return false;
}

//============================================================================

int EncodingState::AppendChunkTrailer(Packet* qpkt, int haveBlob, int chunkID,
                                      int nChunks)
{
  FECChunkTrailer chunkTrlr;

  chunkTrlr.is_blob  = haveBlob;
  chunkTrlr.chunk_id = chunkID;
  chunkTrlr.n_chunks = nChunks;
  chunkTrlr.pkt_id   = pkt_id_;

  qpkt->AppendBlockToEnd ((unsigned char *)&chunkTrlr,
      sizeof(chunkTrlr));

  return FECSTATE_OKAY;
}

//============================================================================
int EncodingState::AddToCache(Packet* qpkt)
{
  FECControlTrailer fecTrlr;

  if (orig_count_ > (MAX_FEC_RATE - 1))
  {
    return FECSTATE_OUTOFBOUNDS;
  }

  // If this is the first entry into the cache, record the entry time
  Time now;
  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get time now\n");
    return FECSTATE_CLOCKFAIL;
  }

  if ((orig_count_ == 0) && (!have_blob_))
  {
    group_start_time_ = now.ToTval();
    timeradd(&group_start_time_, &max_hold_time_, &flush_time_);
  }

  orig_cache_[orig_count_] = qpkt;

  // Setup the FEC trailer
  fecTrlr.type        = FEC_ORIGINAL;
  fecTrlr.in_order    = in_order_;
  fecTrlr.loss_thresh = admission_controller_->loss_thresh_pct();
  if (std::numeric_limits<uint8_t>::max() < admission_controller_->priority())
  {
    fecTrlr.priority  = std::numeric_limits<uint8_t>::max();
  }
  else
  {
    fecTrlr.priority  = static_cast<uint8_t>(admission_controller_->priority());
  }

  if (std::numeric_limits<uint16_t>::max() < reorder_time_.GetTimeInMsec())
  {
    fecTrlr.reorder_time_ms = std::numeric_limits<uint16_t>::max();
  }
  else
  {
    fecTrlr.reorder_time_ms = reorder_time_.GetTimeInMsec();
  }

  if (last_total_rate_ == 1)
  {
    // Handle the special case where we aren't doing FEC. Hence, we have a 1/1
    // code.
    fecTrlr.fec_used = 0;
  }
  else
  {
    fecTrlr.fec_used = 1;
  }
  fecTrlr.slot_id          = orig_count_;
  fecTrlr.group_id         = group_id_;
  fecTrlr.total_bytes_sent = src_info_.total_bytes_sent();
  fecTrlr.seq_number       = original_pkt_seq_num_;
  original_pkt_seq_num_++;
  qpkt->AppendBlockToEnd ((unsigned char *)&fecTrlr,
      sizeof(fecTrlr));

  // Only call gettimeofday if low-latency packet.
  if (qpkt->GetLatencyClass() == iron::LOW_LATENCY)
  {
    // The origin timestamp is a 15-bit representation of the time in ms.
    struct timeval  now_tval;
    gettimeofday(&now_tval, 0);

    now = Time(now_tval);
  }
  else
  {
    now = Time(0);
  }
  qpkt->set_origin_ts_ms(static_cast<uint16_t>(now.GetTimeInMsec() & 0x7fff));
  qpkt->SetTimeToGo(time_to_go_, time_to_go_valid_);
  // qpkt->UpdateChecksums();

  orig_count_++;

  last_time_ = now.GetTimeInSec();

  return FECSTATE_OKAY;
}

//============================================================================
int EncodingState::HoldBlobInCache(Packet *qpkt)
{
  if (orig_count_ > (MAX_FEC_RATE - 1))
  {
    return FECSTATE_OUTOFBOUNDS;
  }

  // If this is the first entry into the cache, record the entry time

  Time now;
  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Failed to get time now\n");
    return FECSTATE_CLOCKFAIL;
  }

  if ((orig_count_ == 0) && (!have_blob_))
  {
    group_start_time_ = now.ToTval();
    timeradd(&group_start_time_, &max_hold_time_, &flush_time_);
  }

  orig_cache_[orig_count_] = qpkt;

  have_blob_ = true;

  last_time_ = now.GetTimeInSec();

  return FECSTATE_OKAY;
}

//============================================================================
int EncodingState::CommitBlobToCache()
{
  bool rc;

  Packet *cpkt = orig_cache_[orig_count_];
  if ((rc = AppendChunkTrailer(cpkt,1,0,blob_pkt_cnt_)) != FECSTATE_OKAY)
  {
    return (rc);
  }

  // Need to update the pktID before we commit this to the cache
  // or we lose the blob count

  pkt_id_ += blob_pkt_cnt_;

  if ((rc = AddToCache(cpkt)) != FECSTATE_OKAY)
  {
    return (rc);
  }

  // Finally, clear out any blob state

  have_blob_    = false;
  blob_pkt_cnt_  = 0;
  blob_sz_bytes_ = 0;

  return FECSTATE_OKAY;
}

//============================================================================
bool EncodingState::WillOverrun(int paylen)
{
  // If we already have the maximum number of packets, we will overrun

  if (pkt_id_ >= MAX_FEC_RATE -1)
  {
    return true;
  }

  // Alternately, if we end up splitting this we may also overrun

  int nChunks = (paylen + max_chunk_sz_ - 1) / max_chunk_sz_;

  // If we have an outstanding blob, we may have to close it out
  // which will increase the chunk count by 1

  if (have_blob_)
  {
    // If we have a blob and it can still fit, we are good to go

    if (blob_sz_bytes_ + paylen <= max_chunk_sz_)
    {
      return false;
    }

    // Otherwise, account for closing out the current blob

    nChunks += 1;
  }

  // Now we test against the FEC limits

  if (orig_count_ + nChunks > MAX_FEC_RATE)
  {
    return true;
  }
  else
  {
    return false;
  }
}

//============================================================================
bool EncodingState::DisassembleIntoCache(Packet* qpkt, int* start,
                                         int* nToSend)
{
  int payLen;
  int payLeft;
  int nChunks;
  int copySz;
  int chunkSz;
  int i;

  bool rc;

  unsigned char *qbffr;

  // Get the packet payload and payload length
  payLen = qpkt->GetIpPayloadLengthInBytes();
  qbffr  = qpkt->GetBuffer() + qpkt->GetIpPayloadOffset();

  // Initialize the position variables. The caller uses these to
  // control sending of packets once we're done

  *start   = orig_count_;
  *nToSend = 0;

  // First decide if we are fragmenting or aggregating

  if (payLen >= max_chunk_sz_)
  {
    // Looks like we are fragmenting this packet

    // Close out any outstanding partial chunks

    if (have_blob_)
    {
      if ((rc = CommitBlobToCache()) != FECSTATE_OKAY)
      {
        return (rc);
      }

      // Remember to update the number of packets we need to send

      *nToSend += 1;
    }

   // Split the packet into multiple chunks as needed
    nChunks   = (payLen + max_chunk_sz_ - 1) / max_chunk_sz_;
    *nToSend += nChunks;

    if (nChunks > 1)
    {

      // We resize the target chunk size so that we still generate
      // the same number of chunks, but more evenly distribute the
      // payload across the chunks

      chunkSz = (payLen + nChunks - 1) / nChunks;
      copySz  = chunkSz;
      payLeft = payLen;

      for (i=0; i<nChunks; i++)
      {
        // Allocate a new chunk

        Packet *cpkt = packet_pool_.CloneHeaderOnly(
          qpkt, iron::PACKET_NOW_TIMESTAMP);
        if (!cpkt)
        {
          LogW(kClassName, __func__, "Packet could not be cloned\n");
          TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
          packet_pool_.Recycle(qpkt);
          return(false);
        }

        // Copy in the appropriate piece of the original packet
        cpkt->AppendBlockToEnd(&qbffr[i*chunkSz],copySz);


        // Append the chunk management trailer
        AppendChunkTrailer(cpkt,0,i,nChunks);


        // Figure out how much of the payload we have left
        payLeft -= chunkSz;
        if (copySz > payLeft)
        {
          copySz = payLeft;
        }


        // Update the encoding state.
        // NOTE: This modifies cpkt by adding an FEC control trailer
        AddToCache(cpkt);
      }

      // qpkt is no longer needed, so destroy it
      packet_pool_.Recycle(qpkt);
    }
    else
    {
      // Append the chunk management trailer directly to the original packet
      AppendChunkTrailer(qpkt,0,0,1);

      // Update the encoding state.
      // NOTE: This modifies qpkt by adding an FEC control trailer
      AddToCache(qpkt);
    }

    // Finally, bump the packet ID
    pkt_id_++;
  }
  else
  {
    // Looks like we are aggregating
    bool wasAdded = false;

    // If we already have a blob, See if this will fit
    if (have_blob_)
    {
      if  ((payLen + blob_sz_bytes_) > max_chunk_sz_)
      {
        // It won't fit. Close out any outstanding partial chunks
        if ((rc = CommitBlobToCache()) != FECSTATE_OKAY)
        {
          return (rc);
        }

        // Remember to update the number of packets we need to send
        *nToSend += 1;
        wasAdded  = false;
      }
      else
      {
        // Looks like it will fit. Add the size info, and then concatenate
        // the payload itself onto the end of the current blob
        Packet *cpkt = orig_cache_[orig_count_];

        unsigned short sPayLen = payLen;
        cpkt->AppendBlockToEnd ((unsigned char *)&sPayLen, sizeof(sPayLen));
        cpkt->AppendBlockToEnd (qbffr,payLen);

        // Update the blob control parameters
        blob_sz_bytes_ += payLen;
        blob_pkt_cnt_  ++;

        // If another one of this size won't fit, we close it out
        if  ((payLen + blob_sz_bytes_) > max_chunk_sz_)
        {
          // It won't fit. Close out any outstanding partial chunks
          if ((rc = CommitBlobToCache()) != FECSTATE_OKAY)
          {
            return (rc);
          }

          // Remember to update the number of packets we need to send
          *nToSend += 1;
        }

        // Record that we have handled this packet
        wasAdded = true;
        packet_pool_.Recycle(qpkt);
      }
    }

    // When we get here we may or may not have added the packet to the existing
    // blob depending on whether we were able to fit it in. See if we still need
    // to process it
    if (!wasAdded)
    {
      // See if this new blob is likely to hold more than one packet
      // If not, or the hold time is set to 0, we just process it as if it were
      // a single chunk.
      if ((max_chunk_sz_ < 2 * payLen) ||
          ((max_hold_time_.tv_sec + max_hold_time_.tv_usec) == 0))
      {
        // Append the chunk management trailer directly to the original packet
        AppendChunkTrailer(qpkt,0,0,1);

        // Update the encoding state.
        // NOTE: This modifies qpkt by adding an FEC control trailer
        AddToCache(qpkt);

        pkt_id_++;
        *nToSend += 1;
      }
      else
      {
        // Looks like we will be aggregating more than one packet. Set
        // up a blob. Allocate a new chunk to hold the blob.
        Packet *cpkt = packet_pool_.CloneHeaderOnly(
          qpkt, iron::PACKET_NOW_TIMESTAMP);

        if (!cpkt)
        {
          LogE(kClassName, __func__, "Could not pkt clone header\n");
          TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
          packet_pool_.Recycle(qpkt);
          return(false);
        }

        // Add the size info, and then concatenate the payload itself
        // onto the end of the blob.
        unsigned short sPayLen = payLen;
        cpkt->AppendBlockToEnd((unsigned char *)&sPayLen, sizeof(sPayLen));
        cpkt->AppendBlockToEnd(qbffr, payLen);

        HoldBlobInCache(cpkt);

        // Update the blob control parameters

        have_blob_      = true;
        blob_sz_bytes_ += payLen;
        blob_pkt_cnt_   = 1;

        // Since we have copied the contents of this packet, we no longer need it

        packet_pool_.Recycle(qpkt);
      }
    }
  }

  return (true);
}

//============================================================================
Packet* EncodingState::FetchFromCache(unsigned long type, int index)
{
  if (type == FEC_ORIGINAL)
  {
    if ((index <           0) ||
        (index >= orig_count_))
    {
      return ((Packet *)NULL);
    }
    return ( orig_cache_[index] );
  }

  else // if (type == FEC_REPAIR)
  {
    if ((index <           0) ||
        (index >=  fec_count_))
    {
      return ((Packet *)NULL);
    }
    return ( fec_cache_[index] );
  }
}

//============================================================================
FlowState EncodingState::flow_state() const
{
  if (admission_controller_ == NULL)
  {
    return iron::UNDEFINED;
  }

  return admission_controller_->flow_state();
}

//============================================================================
bool  EncodingState::ResetMgen(Packet* pkt, struct timeval tv)
{
  // Do some sanity checking.
  if (!pkt)
  {
    return false;
  }

  FECControlTrailer*  fec_trlr    = reinterpret_cast<FECControlTrailer*>(
    pkt->GetBuffer(pkt->GetLengthInBytes() - sizeof(FECControlTrailer)));
  FECChunkTrailer*    chunk_trlr  = NULL;

  if (!fec_trlr)
  {
    LogD(kClassName, __func__, "Packet contains no FEC controler trailer.\n");
    return false;
  }

  // REPAIR packets are excluded.
  if (fec_trlr->type == FEC_ORIGINAL)
  {
    chunk_trlr  = reinterpret_cast<FECChunkTrailer*>(
      pkt->GetBuffer(pkt->GetLengthInBytes() - sizeof(FECControlTrailer) -
      sizeof(FECChunkTrailer)));

    if (!chunk_trlr)
    {
      LogW(kClassName, __func__, "Chunk trailer missing from ORIGINAL FEC "
           "packet.\n");
      return false;
    }

    LogD(kClassName, __func__, "There are %" PRIu16 " chunks in packet %p "
         "(%s blob).\n", chunk_trlr->n_chunks, pkt,
         chunk_trlr->is_blob == 1 ? "is" : "is not");

    if ((chunk_trlr->is_blob == 1) || (chunk_trlr->n_chunks == 1) ||
      (chunk_trlr->chunk_id == 0))
    {
      // If the packet is:
      // * a blob, aggregated packets with multiple chunks, or
      // * not split or aggregated with only one chunk, or
      // * the first packet of a number of split packets with multiple chunks.
      // then update the MGEN header info.
      uint8_t*  data_ptr  = pkt->GetBuffer(pkt->GetIpPayloadOffset());

      // Do this for all blobs (except if the packet is split, in which case do
      // this only for the first packet).
      for (uint8_t  blob_iter = 0; blob_iter < chunk_trlr->n_chunks;
        ++blob_iter)
      {
        if (!data_ptr)
        {
          LogW(kClassName, __func__, "Could not find blob %" PRIu8
               " in chunk.\n", blob_iter);
          break;
        }

        uint16_t  chunk_length  = 0;

        // If the packet is a blob of aggregated frames, we expect to find a
        // chunk length before every chunk (that is, before every MGEN header).
        if (chunk_trlr->is_blob == 1)
        {
          // Read the chunk length, advance pointer to MGEN header.
          chunk_length  = *(reinterpret_cast<uint16_t*>(data_ptr));
          data_ptr      += sizeof(chunk_length);
        }

        struct Packet::MgenHdr* mgen_hdr =
          reinterpret_cast<struct Packet::MgenHdr*>(data_ptr);

        if (!mgen_hdr)
        {
          LogD(kClassName, __func__, "No more MGEN header.\n");
          break;
        }

        uint8_t version = mgen_hdr->version;

        if (version > Packet::GetMgenMaxDecodableVersion())
        {
          LogW(kClassName, __func__, "Packet (%p) has MGEN version %" PRIu8
               ", cannot decode.\n", pkt, version);
          return false;
        }

        uint32_t        UNUSED(old_mgen_sn) = ntohl(mgen_hdr->sequenceNumber);
        uint32_t        new_mgen_sn = GetAndIncrementMgenSeqNum();
        struct timeval  UNUSED(old_tv);

        old_tv.tv_sec   = ntohl(mgen_hdr->txTimeSeconds);
        old_tv.tv_usec  = ntohl(mgen_hdr->txTimeMicroseconds);

        mgen_hdr->sequenceNumber      = htonl(new_mgen_sn);
        mgen_hdr->txTimeSeconds       = htonl(tv.tv_sec);
        mgen_hdr->txTimeMicroseconds  = htonl(tv.tv_usec);

        LogD(kClassName, __func__, "Packet (%p)'s seq num and timestamp "
             "switched from %" PRIu32 " to %" PRIu32" and %" PRIu32
             ".%06" PRIu32 " to %" PRIu32 ".%06" PRIu32 ".\n",
             pkt, old_mgen_sn, new_mgen_sn, old_tv.tv_sec, old_tv.tv_usec,
             tv.tv_sec, tv.tv_usec);

        data_ptr  += chunk_length;

        // If this packet is not a blob, stop here after doing first chunk of a
        // split packet.
        if (chunk_trlr->is_blob != 1)
        {
          break;
        }
      }
    }
    return true;
  }

  if (fec_trlr->type == FEC_REPAIR)
  {
    return false;
  }

  return false;
}
