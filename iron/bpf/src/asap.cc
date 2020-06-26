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

#include "asap.h"

#include "bin_queue_mgr.h"
#include "iron_constants.h"
#include "log.h"
#include "packet.h"
#include "packet_pool.h"
#include "queue_depths.h"
#include "unused.h"
#include "zombie.h"

#include <limits>
#include <sstream>
#include <string>

#include <inttypes.h>

using ::iron::ASAP;
using ::iron::BinId;
using ::iron::BinQueueMgr;
using ::iron::Log;
using ::iron::Packet;
using ::iron::Time;
using ::iron::Zombie;
using ::std::string;

namespace
{
  const char  kClassName[]                      = "ASAP";

  /// \brief Coefficient for quadradic delay-to-bytes function in anti-
  /// starvation zombies
  const double kASZCoefficient = 2;

  /// \brief Max packet size that we anticipate, for ASZ threshold, based
  /// on ethernet MTU size.
  const uint32_t kMaxPktSizeBits = 1500 * 8;

  /// \brief Threshold computation slack constant
  const uint32_t kThresholdSlack = 50;

  /// \brief Threshold to increase sleep time for ASAP
  ///
  /// If the time between AddAntiStarvationZombie calls (called by
  /// FindNextTransmission) is greater than this threshold, we count
  /// that as part of the BPF "sleep time".  This indicates that an
  /// unexpected event (process swap out, IO, etc) has occured that
  /// we don't want to count against starvation.  This value is in ms.
  const uint32_t kThresholdSleepTimeMs = 10;

  /// \brief Minimum starvation threshold, in milliseconds.
  ///
  /// This is a uint64 to allow the use of the min() operator without casting.
  const uint64_t kMinStarvationThreshMs = 50;

}

//============================================================================
ASAP::ASAP(PacketPool& packet_pool, BinMap& bin_map, BinQueueMgr& q_mgr,
           BinIndex my_bin_index, BinIndex node_bin_index)
    : packet_pool_(packet_pool),
      bin_map_(bin_map),
      q_mgr_(q_mgr),
      my_bin_index_(my_bin_index),
      node_bin_index_(node_bin_index),
      sleep_time_by_bin_(0),
      time_of_last_asap_call_(0),
      delay_bytes_added_(0),
      gradient_based_cap_(),
      gradient_based_ls_cap_(),
      time_of_last_dequeue_(),
      capacity_estimates_(),
      average_capacity_(10000000),
      initialized_(false)
{
  // MCAST TODO: put these back if we need to track delay per destination.
//  memset(sleep_time_by_bin_, 0, sizeof(sleep_time_by_bin_));
//  memset(delay_bytes_added_, 0, sizeof(delay_bytes_added_));
  memset(capacity_estimates_, 0, sizeof(capacity_estimates_));
}

//============================================================================
bool ASAP::Initialize(const ConfigInfo& config_info)
{
  initialized_ = true;
  return true;
}

//============================================================================
ASAP::~ASAP()
{
  initialized_ = false;
}

//============================================================================
// MCAST TODO: Restore bin index as an argument if this is per destination.
uint32_t ASAP::BytesToAddGivenDelay(Time delay, bool is_ls) const
{

  // Conversion is y = a * x^2, units of a are (bytes / ms^2)
  // Setting a to 1 results in 10000 bytes at 100ms

  // Start with the total bytes to add based on delay
  uint32_t delay_ms = static_cast<uint32_t>(delay.GetTimeInMsec());

  // Don't count sleep time against us
  if (delay_ms > sleep_time_by_bin_)
  {
    delay_ms -= sleep_time_by_bin_;
  }
  else
  {
    delay_ms = 0;
  }

  uint32_t bytes_to_add = 0;
  uint32_t asz_delay_threshold = 0;
  if (average_capacity_ > 0)
  {
    // max pkt size in bits * 1000 (sec -> ms) * 50 (constant) / cap in bps
    asz_delay_threshold = std::min(kMaxPktSizeBits * 1000 *
      kThresholdSlack / average_capacity_, kMinStarvationThreshMs);

    LogD(kClassName, __func__, "Starvation check %s: threshold is %"
        PRIu32 "ms, delay is %" PRIu32 "ms"
        PRIu32 " bytes of zombies\n",
        bin_map_.GetIdToLog(my_bin_index_).c_str(),
        asz_delay_threshold, delay_ms);

    if (delay_ms > asz_delay_threshold)
    {
      bytes_to_add =
        static_cast<uint32_t>(kASZCoefficient * delay_ms * delay_ms);
    }
  }

  // Remove the bytes that we've already added since the last dequeue.
  // This is necessary because this function is called whenever
  // queue depths are used, but we don't want to over-count the
  // delay experienced by the same head-of-queue packet.
  // TODO: Note that this assumes that the head-of-queue packet is the
  // packet that will be dequeued next; is this the case with priorities?
  uint32_t bytes_added = delay_bytes_added_;
  if (bytes_added > bytes_to_add)
  {
    LogW(kClassName, __func__,
         "Inconsistent delay to bytes conversion\n");
    bytes_to_add = 0;
  }
  else
  {
    bytes_to_add -= bytes_added;
  }

  // Enforce a cap on the max to add. The cap should be slightly higher
  // than the overall max minus my current gradient, and we should
  // ensure that the cap is positive.  Note that there is a special
  // case where we have only one bin and that bin has a negative
  // gradient.  This is a "packet left behind" in the NPLB examples,
  // and to prevent this we want to help our gradient become positive
  // over time.
  if (is_ls)
  {
    if (bytes_to_add > gradient_based_ls_cap_)
    {
      bytes_to_add = gradient_based_ls_cap_;
      LogD(kClassName, __func__, "LS zombie cap is %" PRIu32 "\n",
           gradient_based_ls_cap_);
    }
  }
  else
  {
    if (bytes_to_add > gradient_based_cap_)
    {
      bytes_to_add = gradient_based_cap_;
      LogD(kClassName, __func__, "Zombie cap is %" PRIu32 "\n",
           gradient_based_cap_);
    }
  }

  if (bytes_to_add > 0)
  {
    LogD(kClassName, __func__, "Starvation detected (threshold is %"
        PRIu32 "ms, delay is %" PRIu32 "ms), adding %"
        PRIu32 " bytes of zombies\n", asz_delay_threshold, delay_ms,
        bytes_to_add);
  }

  return bytes_to_add;

}

//============================================================================
void ASAP::AdjustQueueValuesForAntiStarvation()
{
  if (!initialized_)
  {
    return;
  }

  // Add zombie bytes to bins to account for the delay term.
  // Specifically, track the amount of time the packet at the
  // head of the queue was at the head of the queue, and
  // continuously add zombies as that delay increases, according
  // to the BytesToAddGivenDelay function.  This helps prevent
  // starvation by forcing the gradient to be larger the longer
  // the delays become.

  Time      now                  = Time::Now();
  Packet*   pkt                  = NULL;
  uint32_t  oldest_pkt_dst_addr  = 0;
  uint32_t  since_last_call_ms   = 0;

  // Compute time elapsed since the last time this was called
  if (!time_of_last_asap_call_.IsZero())
  {
    Time timedelta = now - time_of_last_asap_call_;
    since_last_call_ms = static_cast<uint32_t>(timedelta.GetTimeInMsec());
  }
  time_of_last_asap_call_ = now;

  Time oldest_pkt_recv_time = now;

  // Find the oldest enqueued packet in the lowest latency bin,
  // ignoring zombies.
  bool is_ls  = false;
  for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
  {
    if (Packet::IsZombie(static_cast<LatencyClass>(it)))
    {
      // Ignore zombie packets.
      continue;
    }
    pkt = q_mgr_.Peek(it);

    if (!pkt)
    {
      // Nothing in the queue (or this is a packetless queue), nothing to
      // consider.
      continue;
    }

    // There is a packet in this latency class, use it
    if (it <= LOW_LATENCY)
    {
      // Note: zombie latency classes were excluded earlier in this loop
      is_ls = true;
    }
    oldest_pkt_recv_time = pkt->recv_time();
    pkt->GetIpDstAddr(oldest_pkt_dst_addr);
    break;
  }

  // TODO: We've obtained the oldest packet in the lowest latency class.
  // It's possible that this is stuck because there's no available path
  // with low enough latency.  This is a corner case that we may want to
  // not considered starved.

  // If all queues are empty, no need to add zombies.
  if (oldest_pkt_recv_time == now || oldest_pkt_dst_addr == 0)
  {
    return;
  }

  // Update sleep time for this bin.  Note this only occurs
  // if the bin contains some real packets.
  if (since_last_call_ms > kThresholdSleepTimeMs)
  {
    sleep_time_by_bin_ += since_last_call_ms;
    LogD(kClassName, __func__, "Update sleeptime: delta % " PRIu32
         ", new time %" PRIu32 "\n", since_last_call_ms, sleep_time_by_bin_);
  }

  // Add zombie bytes based on delay.
  // Delay is the minimum of time since last dequeue and time
  // oldest packet has spent in the queue.  This effectively
  // is the time the packet at the head of the queue has been
  // at the head of the queue.  The time of last dequeue
  // primarily captures this; the min is needed if the packet
  // is added after the last dequeue (so, the queue was empty).
  DstVec   asap_dst_vec = 0;
  uint32_t bytes_to_add = 0;
  if (bin_map_.IsMcastBinIndex(my_bin_index_))
  {
    DstVec    dst_vec  = bin_map_.GetMcastDst(my_bin_index_);
    BinIndex  dst_bidx = 0;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      Time delay = now -  q_mgr_.last_dequeue_time(dst_bidx);
      // Dont add zombies for the node this is running on
      if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx) &&
	  (dst_bidx != node_bin_index_))
      {
        bytes_to_add = BytesToAddGivenDelay(delay, is_ls);
        asap_dst_vec = bin_map_.AddBinToDstVec(asap_dst_vec, dst_bidx);
      }
    }
  }
  else
  {
    Time delay   = now - Time::Max(oldest_pkt_recv_time, time_of_last_dequeue_);
    bytes_to_add = BytesToAddGivenDelay(delay, is_ls);
  }

  if (bytes_to_add > 0)
  {
    q_mgr_.AddNewZombie(oldest_pkt_dst_addr, bytes_to_add,
                        is_ls ? HIGH_LATENCY_NPLB_LS : HIGH_LATENCY_NPLB,
                        asap_dst_vec);
    delay_bytes_added_ += bytes_to_add;
  }
}

//============================================================================
void ASAP::ProcessCapacityUpdate(uint32_t pc_num, double capacity_bps)
{
  if (pc_num >= kMaxPathCtrls)
  {
    LogW(kClassName, __func__,
        "Path controller number %" PRIu32 "out of bounds.\n", pc_num);
    return;
  }
  capacity_estimates_[pc_num] = static_cast<uint64_t>(capacity_bps);
  // Subtract 1 bin for ourself
  uint32_t num_bins = (bin_map_.GetNumUcastBinIds() +
                       bin_map_.GetNumMcastIds() - 1);
  uint64_t average_cap = 0;
  for (uint8_t it = 0; it < kMaxPathCtrls; ++it)
  {
    average_cap += capacity_estimates_[it];
  }
  if (num_bins != 0)
  {
    average_cap /= num_bins;
  }
  average_capacity_ = average_cap;
  LogD(kClassName, __func__,
       "Capacity within BinQueueMgr updated on pc %" PRIu32 " to %.1f, average "
       "is now %" PRIu64 " over %" PRIu32 " bins.\n", pc_num, capacity_bps,
       average_capacity_, num_bins);
}

//============================================================================
void ASAP::SetASAPCap(uint32_t new_cap, bool is_ls)
{
  if (is_ls)
  {
    gradient_based_ls_cap_ = new_cap;
  }
  else
  {
    gradient_based_cap_    = new_cap;
  }
}

//============================================================================
void ASAP::OnDequeue(const DequeuedInfo& dq_info)
{
  // Reset sleep time tracking
  sleep_time_by_bin_    = 0;

  // Reset bytes added counter for delay term.
  delay_bytes_added_    = 0;
  time_of_last_dequeue_ = Time::Now();
}
