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

/// \file nplb_bin_queue_mgr.cc

#include "nplb_bin_queue_mgr.h"
#include "queue_depths.h"

#include "config_info.h"
#include "log.h"
#include "packet.h"
#include "string_utils.h"
#include "unused.h"
#include "zombie.h"


using ::iron::ConfigInfo;
using ::iron::NPLBBinQueueMgr;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::QueueDepths;
using ::iron::Time;
using ::iron::Zombie;

//
// Constants.
//
namespace
{
  /// Class name for logging.
  const char      kClassName[]                = "NPLBBinQueueMgr";

  // MCAST TODO FIXME FIXME FIXME - DUPLICATE FROM PARENT CLASS
  const bool IS_PKTLESS_Z_QUEUE[iron::NUM_LATENCY_DEF] = {
    false, false, false, true, true, true, false, true, true, true
  };

  /// \brief Default value for whether to generate NPLB graphs.
  const bool  kDefaultGenerateNPLBGraphs        = false;
}

//============================================================================
NPLBBinQueueMgr::NPLBBinQueueMgr(
  BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map)
    : BinQueueMgr(bin_idx, packet_pool, bin_map),
      delay_weight_(kDefaultQueueDelayWeight),
      delay_stickiness_threshold_(Time(kDefaultQueueDelayStickinessThreshSecs)),
      nplb_values_(bin_map),
      nplb_xplot_()
{
}


//============================================================================
NPLBBinQueueMgr::~NPLBBinQueueMgr()
{
  BinIndex  bin_idx = kInvalidBinIndex;

  for (bool bin_idx_valid = bin_map_.GetFirstBinIndex(bin_idx);
       bin_idx_valid;
       bin_idx_valid = bin_map_.GetNextBinIndex(bin_idx))
  {
    if (nplb_xplot_[bin_idx])
    {
      delete nplb_xplot_[bin_idx];
      nplb_xplot_[bin_idx] = NULL;
    }
  }
}

//============================================================================
bool NPLBBinQueueMgr::Initialize(const ConfigInfo& config_info,
                                 BinIndex node_bin_idx)
{
  // First initialize the parent.
  BinQueueMgr::Initialize(config_info, node_bin_idx);
  initialized_ = false;

  delay_weight_ =
    config_info.GetDouble("Bpf.QueueDelayWeight", kDefaultQueueDelayWeight);
  delay_stickiness_threshold_ =
    Time(config_info.GetDouble("Bpf.DelayStickinessThresholdSecs",
                               kDefaultQueueDelayStickinessThreshSecs));

  if (!nplb_xplot_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize NPLB xplot array.\n");
    return false;
  }
  nplb_xplot_.Clear(NULL);

#ifdef XPLOT
  bool do_nplb_xplot =
    config_info.GetBool("Bpf.GenerateNPLBGraphs", kDefaultGenerateNPLBGraphs);

  if (do_nplb_xplot)
  {
    BinIndex  bin_idx = kInvalidBinIndex;

    for (bool bin_idx_valid = bin_map_.GetFirstDstBinIndex(bin_idx);
         bin_idx_valid;
         bin_idx_valid = bin_map_.GetNextDstBinIndex(bin_idx))
    {
      nplb_xplot_[bin_idx] = new (std::nothrow) iron::GenXplot();
      if (!nplb_xplot_[bin_idx])
      {
        // log and go on. We just won't generate the graph.
        LogE(kClassName, __func__,
             "Unable to allocate NPLB GenXplot for bin index %"
             PRIBinIndex ".\n", bin_idx);
      }
      else
      {
        std::stringstream title;
        title << "nplb_" << bin_map_.GetIdToLog(bin_idx) << ".xplot";
        std::stringstream graphname;
        graphname << "NPLB terms for bin " << bin_map_.GetIdToLog(bin_idx);
        if (!nplb_xplot_[bin_idx]->Initialize(title.str(),
                                              graphname.str(),
                                              true))
        {
          delete nplb_xplot_[bin_idx];
          nplb_xplot_[bin_idx] = NULL;
        }
        else
        {
          nplb_xplot_[bin_idx]->AddLineToKey(YELLOW,
                                             "Depth term)");
          nplb_xplot_[bin_idx]->AddLineToKey(RED, "Depth + delay");
        }
      }
    }
  }
#endif // XPLOT

  LogC(kClassName, __func__, "NPLBBinQueueMgr configuration:\n");
  LogC(kClassName, __func__, "Delay Weight:                    %f\n",
       delay_weight_);
  LogC(kClassName, __func__, "Delay Stickiness Threshold:      %" PRIu64
       " usec\n", delay_stickiness_threshold_.GetTimeInUsec());

  initialized_ = true;
  return true;
}

//============================================================================
QueueDepths* NPLBBinQueueMgr::GetQueueDepthsForBpf()
{
  return ComputeNPLB();
}

//============================================================================
QueueDepths* NPLBBinQueueMgr::GetDepthsForBpfQlam()
{
  return ComputeNPLB();
}

//============================================================================
uint32_t NPLBBinQueueMgr::GetQueueDepthForProxies()
{
  // MCAST TODO: this is wrong for multicast.
  return ComputeNPLB()->GetBinDepthByIdx(my_bin_index_);
}

//============================================================================
void NPLBBinQueueMgr::OnDequeue(const DequeuedInfo& dq_info, bool cloned)
{
  BinQueueMgr::OnDequeue(dq_info, cloned);

  if ((delay_weight_ > 0) &&
      !Packet::IsZombie(dq_info.lat))
  {
    // MCAST TODO: may need to be per destination.
    IncrementDelayStickiness(my_bin_index_, dq_info.recv_time);
  }
}

//============================================================================
void NPLBBinQueueMgr::IncrementDelayStickiness(BinIndex bin_idx,
                                               Time dequeued_pkt_recv_time)
{
  // MCAST TODO: do we need the bin id?
  // This is a private function. We can assume we've already checked the
  // validity of the bin id when we were dequeuing the packet.

  Time      oldest_pkt_recv_time = Time::Now();
  Packet*   pkt                  = NULL;
  uint32_t  oldest_pkt_dst_addr  = 0;

  // Find the oldest enqueued packet (which could be the next packet in any
  // latency queue). We ignore the high latency (aka zombie) queue, since
  // these are not real data packets.
  for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
  {
    if (Packet::IsZombie(static_cast<LatencyClass>(it)) ||
      IS_PKTLESS_Z_QUEUE[it])
    {
      // Ignore zombie packets.
      continue;
    }
    PacketQueue* queue =
      static_cast<PacketQueue*>(phy_queue_.lat_queues[it]);
    if (!queue)
    {
      // No queue, nothing to consider.
      continue;
    }
    pkt = queue->Peek();
    if (!pkt)
    {
      // Nothing in the queue, nothing to consider
      continue;
    }
    if (pkt->recv_time() < oldest_pkt_recv_time)
    {
      oldest_pkt_recv_time = pkt->recv_time();
      pkt->GetIpDstAddr(oldest_pkt_dst_addr);
    }
  }
  Time diff = oldest_pkt_recv_time - dequeued_pkt_recv_time;
  if (diff > delay_stickiness_threshold_)
  {
    uint32_t stickiness_incr = static_cast<uint32_t>(
      (diff - delay_stickiness_threshold_).GetTimeInUsec());

    if (oldest_pkt_dst_addr != 0)
    {
      AddNewZombie(oldest_pkt_dst_addr, stickiness_incr, HIGH_LATENCY_NPLB);
    }
  }
}

//============================================================================
QueueDepths* NPLBBinQueueMgr::ComputeNPLB()
{
  if (!initialized_ || delay_weight_ == 0)
  {
    // Don't bother updating the delay portion of the values if we're not
    // going to use them.
    return &queue_depths_;
  }

  uint32_t  depth     = 0;
  uint32_t  ls_depth  = 0;
  Time      now       = Time::Now();
  Packet*   pkt       = NULL;
  uint32_t  nplb_zombies = 0;

  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_.GetFirstUcastBinIndex(bin_idx);
       valid;
       valid = bin_map_.GetNextUcastBinIndex(bin_idx))
  {
    depth    = queue_depths_.GetBinDepthByIdx(bin_idx, NORMAL_LATENCY);
    ls_depth = queue_depths_.GetBinDepthByIdx(bin_idx, LOW_LATENCY);

    Time oldest_pkt_recv_time     = now;
    Time oldest_ls_pkt_recv_time  = now;

    // Find the oldest enqueued packet (which could be the next packet in any
    // latency queue). We ignore the zombie queue, since these are not real
    // data packets.
    for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
    {
      if (Packet::IsZombie(static_cast<LatencyClass>(it)) ||
        IS_PKTLESS_Z_QUEUE[it])
      {
        if (it == HIGH_LATENCY_NPLB)
        {
          nplb_zombies = phy_queue_.lat_queues[it]->GetSize();
        }
        // Ignore zombie packets.
        continue;
      }
      PacketQueue* queue =
        static_cast<PacketQueue*>(phy_queue_.lat_queues[it]);
      if (!queue)
      {
        // No queue, nothing to consider.
        continue;
      }
      pkt = queue->Peek();
      if (!pkt)
      {
        // Nothing in the queue, nothing to consider
        continue;
      }

      if (it <= LOW_LATENCY)
      {
        if (pkt->recv_time() < oldest_ls_pkt_recv_time)
        {
          oldest_ls_pkt_recv_time = pkt->recv_time();
        }
      }

      if (pkt->recv_time() < oldest_pkt_recv_time)
      {
        oldest_pkt_recv_time = pkt->recv_time();
      }
    }
    // Note: if all queues were empty, then depth = 0 and oldest_pkt_recv_time
    // is still Now, so we'll set the depth to
    // 0 + (weight * bp_delay_stickiness_.stickiness_).
    uint32_t  delay = static_cast<uint32_t>(
      (now - oldest_pkt_recv_time).GetTimeInUsec());
    uint32_t  adjusted_depth  = depth + (delay_weight_ * delay);
    nplb_values_.SetBinDepthByIdx(bin_idx, adjusted_depth);
    delay = static_cast<uint32_t>(
      (now - oldest_ls_pkt_recv_time).GetTimeInUsec());
    uint32_t  adjusted_ls_depth = ls_depth + (delay_weight_ * delay);
    nplb_values_.SetBinDepthByIdx(bin_idx, adjusted_ls_depth, LOW_LATENCY);

    if (adjusted_ls_depth > adjusted_depth)
    {
      LogW(kClassName, __func__,
           "LS adjusted depth is larger than for all %" PRIu32 "B %" PRIu32 "B.\n",
           adjusted_ls_depth, adjusted_depth);
    }
    if (nplb_xplot_[bin_idx])
    {
      nplb_xplot_[bin_idx]->ContinueTimeLine(
        0,
        depth - nplb_zombies,
        YELLOW);
      nplb_xplot_[bin_idx]->ContinueTimeLine(
        1,
        depth + (delay_weight_ * delay),
        RED);
    }
  }
  return &nplb_values_;
}
