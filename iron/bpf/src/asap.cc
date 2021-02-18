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
using ::iron::LatencyClass;
using ::std::string;
using ::std::queue;

namespace
{
  const char kClassName[] = "ASAP";

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
      time_of_last_asap_call_(0),
      gradient_based_cap_(),
      gradient_based_ls_cap_(),
      capacity_estimates_(),
      average_capacity_(10000000),
      initialized_(false)
{
  memset(capacity_estimates_, 0, sizeof(capacity_estimates_));
}

//============================================================================
bool ASAP::Initialize(const ConfigInfo& config_info)
{
  if (!enqueue_time_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to allocate enqueue time array.\n");
    return false;
  }

  enqueue_time_.Clear((queue<Time>*)NULL);

  if (!enqueue_time_ls_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to allocate latency-snsitive "
	 "enqueue time array.\n");
    return false;
  }

  enqueue_time_ls_.Clear((queue<Time>*)NULL);
  
  if (!delay_bytes_added_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to allocate delay bytes "
	 "added array.\n");
    return false;
  }

  delay_bytes_added_.Clear((uint32_t)0);
  
  if (!sleep_time_by_bin_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to allocate sleep time by bin array.\n");
    return false;
  }

  sleep_time_by_bin_.Clear((uint32_t)0);

  initialized_ = true;

  return true;
}

//============================================================================
ASAP::~ASAP()
{
  initialized_ = false;
  
  // Loop through the enqueue_time_ and enqueue_time_ls_ arrays to
  // delete any allocated std::queue objects

  BinIndex dst_bidx = 0;
  for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
       valid;
       valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
  {
    if (enqueue_time_[dst_bidx] != (queue<Time>*)NULL)
    {
      delete enqueue_time_[dst_bidx];
    }    

    if (enqueue_time_ls_[dst_bidx] != (queue<Time>*)NULL)
    {
      delete enqueue_time_ls_[dst_bidx];
    }    
  }
}

//============================================================================
uint32_t ASAP::BytesToAddGivenDelay(Time delay, bool is_ls,
				    BinIndex dst_bidx) const
{
  // Conversion is y = a * x^2, units of a are (bytes / ms^2)
  // Setting a to 1 results in 10000 bytes at 100ms

  // Start with the total bytes to add based on delay
  uint32_t delay_ms = static_cast<uint32_t>(delay.GetTimeInMsec());

  // Don't count sleep time against us
  if (delay_ms > sleep_time_by_bin_[dst_bidx])
  {
    delay_ms -= sleep_time_by_bin_[dst_bidx];
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

  uint32_t bytes_added = delay_bytes_added_[dst_bidx];
  if (bytes_added > bytes_to_add)
  {
    LogW(kClassName, __func__,
         "Inconsistent delay to bytes conversion: bytes_added is %" PRIu32
	 " vs bytes_to_add is %" PRIu32 ": delay_ms is %" PRIu32
	 "\n",bytes_added,bytes_to_add,delay_ms);
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
  // Specifically, track hold times for packets in the queue and
  // continuously add zombies as that delay increases, according
  // to the BytesToAddGivenDelay function.  This helps prevent
  // starvation by forcing the gradient to be larger the longer
  // the delays become.

  // Note that this implemnetation uses separate enqueue times queues
  // that astrictly fifo. When a packet is enqueued in the packet
  // queue, its queueing time (for each destination in the destination
  // vector if the packet is a multicast packet) are pushed onto
  // the enqueue time queues, and whenever a packet is dequeued, the
  // head of the enqueue time queue is removed/popped (for each destination
  // in the destination vector if the packet is a multicast packet). In
  // this way, packets can be (even partially) removed from anywhere
  // in the packet queue, yet the time-in-queue information remains
  // consistent with what is needed for ASAP to work correctly.

  Time      now                  = Time::Now();
  Packet*   pkt                  = NULL;
  uint32_t  oldest_pkt_dst_addr  =
    bin_map_.GetViableDestAddr(my_bin_index_).address();
  uint32_t  since_last_call_ms   = 0;

  // Compute the time elapsed since the last time this method was called
  if (!time_of_last_asap_call_.IsZero())
  {
    Time timedelta = now - time_of_last_asap_call_;
    since_last_call_ms = static_cast<uint32_t>(timedelta.GetTimeInMsec());
  }
  time_of_last_asap_call_ = now;

  Time oldest_pkt_recv_time = now;

  // Find the oldest enqueued packet in the lowest latency bin,
  // ignoring zombies. This primarily involves looking at the head
  // of the enqueue time queues
  
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

    // Note: zombie latency classes were excluded earlier in this loop
    // There is a packet in this latency class, use it
    
    if (it <= LOW_LATENCY)
    {
      is_ls = true;

      oldest_pkt_recv_time =
	GetOldestPktRecvTime(enqueue_time_ls_);
    }
    else
    {
      oldest_pkt_recv_time =
	GetOldestPktRecvTime(enqueue_time_);
    }

    // If we are here, we found a packet, so break out
    break;
  }
  
  // TODO: We've obtained the oldest packet in the lowest latency class.
  // It's possible that this is stuck because there's no available path
  // with low enough latency.  This is a corner case that we may want to
  // not considered starved.

  // If all queues are empty i.e., we didn't find a pkt, then
  // the oldest pkt receive time will still be set to its initial value
  // (now) and we don't need to add zombies.
  
  if (oldest_pkt_recv_time == now)
  {
    return;
  }

  // Add zombie bytes based on delay.
  // Delay is the minimum of time since last dequeue and time
  // oldest packet has spent in the queue.  This effectively
  // is the time at the head of the queue time queue. The time
  // of last dequeue primarily captures this; the min is needed
  // if the packet is added after the last dequeue (so, the queue
  // was empty).
  
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
      // Only process if destination dst_bidx is in the group
      // and is not the node this is running on
      
      if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx) &&
	  (dst_bidx != node_bin_index_))
      {
	// See if there are any pkts in this queue
	bool have_pkts = true;
	if (is_ls)
	{
	  if (enqueue_time_ls_[dst_bidx] != (queue<Time>*)NULL)
	  {
	    have_pkts = !enqueue_time_ls_[dst_bidx]->empty();
	  }
	}
	else
	{
	  if (enqueue_time_[dst_bidx] != (queue<Time>*)NULL)
	  {
	    have_pkts = !enqueue_time_[dst_bidx]->empty();
	  }
	}

	// Only process if there are packets enqueued for this dst
	if (have_pkts)
	{
          // See if the last dequeue time is still zero, meaning
	  // that nothing has yet been dequeued for this dst. If
	  // so, set the last dequeue time to "now", set the
	  // sleep time to zero, and skip

	  if (q_mgr_.last_dequeue_time(dst_bidx).IsZero())
	  {
	    q_mgr_.last_dequeue_time(dst_bidx) = now;
	    sleep_time_by_bin_[dst_bidx]       = 0;
	    continue;
	  }
	
	  Time delay = now - q_mgr_.last_dequeue_time(dst_bidx);
	
	  // Update sleep time for this bin.
	  
	  if (since_last_call_ms > kThresholdSleepTimeMs)
	  {
	    sleep_time_by_bin_[dst_bidx] += since_last_call_ms;
	    LogD(kClassName, __func__, "Update sleeptime: delta % " PRIu32
		 ", new time %" PRIu32 "\n", since_last_call_ms,
		 sleep_time_by_bin_[dst_bidx]);
	  }
	
	  bytes_to_add = BytesToAddGivenDelay(delay, is_ls, dst_bidx);
	  if (bytes_to_add > 0)
	  {
	    asap_dst_vec = bin_map_.AddBinToDstVec(0, dst_bidx);
	    q_mgr_.AddNewZombie(oldest_pkt_dst_addr, bytes_to_add,
				is_ls ? HIGH_LATENCY_NPLB_LS :
				HIGH_LATENCY_NPLB,
				asap_dst_vec);
	    delay_bytes_added_[dst_bidx] += bytes_to_add;
	  }
	}
      }
    }
  }
  else
  {
    // This is essentially identical to the above multicast code,
    // except that we only consider one destination bin index
    // which is identically my_bin_index_
    
    if (since_last_call_ms > kThresholdSleepTimeMs)
    {
      sleep_time_by_bin_[my_bin_index_] += since_last_call_ms;
      LogD(kClassName, __func__, "Update sleeptime: delta % " PRIu32
	   ", new time %" PRIu32 "\n", since_last_call_ms,
	   sleep_time_by_bin_[my_bin_index_]);
    }
    
    Time delay = now - Time::Max(oldest_pkt_recv_time,
				 q_mgr_.last_dequeue_time(my_bin_index_));
    
    bytes_to_add = BytesToAddGivenDelay(delay, is_ls, my_bin_index_);
    if (bytes_to_add > 0)
    {
      q_mgr_.AddNewZombie(oldest_pkt_dst_addr, bytes_to_add,
			  is_ls ? HIGH_LATENCY_NPLB_LS : HIGH_LATENCY_NPLB,
			  asap_dst_vec);
      delay_bytes_added_[my_bin_index_] += bytes_to_add;
    }
  }
}

//============================================================================
Time ASAP::GetOldestPktRecvTime
	(BinIndexableArray< std::queue<Time>* >& enq_time)
{
  Time oldest = Time::Now();

  if (bin_map_.IsMcastBinIndex(my_bin_index_))
  {
    BinIndex dst_bidx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (enq_time[dst_bidx] &&
	  (!enq_time[dst_bidx]->empty()))
      {
	if (oldest > enq_time[dst_bidx]->front())
	{
	  oldest = enq_time[dst_bidx]->front();
	}
      }
    }
  }
  else
  {
    if (enq_time[my_bin_index_] &&
	(!enq_time[my_bin_index_]->empty()))
    {
      oldest = enq_time[my_bin_index_]->front();
    }
  }

  return (oldest);
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
void ASAP::OnEnqueue(LatencyClass lat, DstVec dests)
{
  if (q_mgr_.IsNonZombieLatClass(lat))
  {
    if ((lat == LOW_LATENCY) || (lat == CRITICAL_LATENCY))
    {
      PushEnqueueTime(enqueue_time_ls_, dests);
    }
    else if (lat == NORMAL_LATENCY)
    {
      PushEnqueueTime(enqueue_time_, dests);
    }
    else
    {
      LogF(kClassName, __func__,
	   "OnEnqueue called for unsupported packet type %s\n",
	   LatencyClass_Name[lat].c_str());
    }   
  }
}

void ASAP::PushEnqueueTime ( BinIndexableArray< queue<Time>* >& enq_time,
			     DstVec dests)
{
  Time now = Time::Now();
  
  if (q_mgr_.is_multicast())
  {
    LogD(kClassName, __func__,
	 "PushEnqueueTime called for multicast bin %s\n",
	 bin_map_.GetIdToLog(my_bin_index_,true).c_str());
    
    BinIndex dst_bidx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dests, dst_bidx))
      {
	// If we haven't yet allocated the queue, do so now
	if (enq_time[dst_bidx] == (queue<Time>*)NULL)
	{
	  enq_time[dst_bidx] = new queue<Time>;
	}
	  
	enq_time[dst_bidx]->push(now);
	
	if (q_mgr_.non_zombie_queue_depth_bytes(dst_bidx) == 0)
	{
	  q_mgr_.last_dequeue_time(dst_bidx) = now;
	}
      }
    }
  }
  else
  {
    LogD(kClassName, __func__,
	 "PushEnqueueTime called for unicast bin %s\n",
	 bin_map_.GetIdToLog(my_bin_index_,true).c_str());
    
    // If we haven't yet allocated the queue, do so now
    if (enq_time[my_bin_index_] == (queue<Time>*)NULL)
    {
      enq_time[my_bin_index_] = new queue<Time>;
    }
    
    enq_time[my_bin_index_]->push(now);
    
    if (q_mgr_.non_zombie_queue_depth_bytes(my_bin_index_) == 0)
    {
      q_mgr_.last_dequeue_time(my_bin_index_) = now;
    }
  }
}

//============================================================================
void ASAP::OnDequeue(const DequeuedInfo& dq_info)
{
  LatencyClass lat = dq_info.lat;
  
  DstVec dests = dq_info.dst_vec;

  if (q_mgr_.IsNonZombieLatClass(lat))
  {
    if ((lat == LOW_LATENCY) || (lat == CRITICAL_LATENCY))
    {
      PopEnqueueTime(enqueue_time_ls_, dests, HIGH_LATENCY_NPLB_LS,
		     HIGH_LATENCY_ZLR_LS);
    }
    else if (lat == NORMAL_LATENCY)
    {
      PopEnqueueTime(enqueue_time_, dests, HIGH_LATENCY_NPLB,
		     HIGH_LATENCY_ZLR);
    }
    else
    {
      LogF(kClassName, __func__,
	   "OnDequeue called for unsupported packet type %s\n",
	   LatencyClass_Name[lat].c_str());
    }
  }
  
  ResetASAPTracking(dests);
}

void ASAP::PopEnqueueTime ( BinIndexableArray< queue<Time>* >& enq_time,
			    DstVec dests, LatencyClass asaplat,
			    LatencyClass zlrlat)
{
  Time now = Time::Now();

  if (q_mgr_.is_multicast())
  {
    LogD(kClassName, __func__,
	 "PopEnqueueTime called for multicast bin %s\n",
	 bin_map_.GetIdToLog(my_bin_index_,true).c_str());
    
    BinIndex dst_bidx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dests, dst_bidx))
      {
	if (enq_time[dst_bidx] == (queue<Time>*)NULL)
	{
	  LogF(kClassName, __func__,
	       "PopEnqueueTime called for a non-existent queue\n");
	}
	
	if (enq_time[dst_bidx]->empty())
	{
	  LogW(kClassName, __func__,
	       "-- pop would be called on an empty queue\n");
	}
	else
	{
	  enq_time[dst_bidx]->pop();
	}
      }
    }
  }
  else
  {
    LogD(kClassName, __func__,
	 "PopEnqueueTime called for unicast bin %s\n",
	 bin_map_.GetIdToLog(my_bin_index_,true).c_str());
    
    if (enq_time[my_bin_index_] == (queue<Time>*)NULL)
    {
      LogF(kClassName, __func__,
	   "PopEnqueueTime called for a non-existant queue\n");
    }
    
    if (enq_time[my_bin_index_]->empty())
    {
      LogW(kClassName, __func__,
	   "-- pop would be called on an empty queue\n");
    }
    else
    {
      enq_time[my_bin_index_]->pop();
    }
  }
}  

void ASAP::ResetASAPTracking (DstVec dests)
{
  Time now = Time::Now();
  
  if (q_mgr_.is_multicast())
  {
    BinIndex dst_bidx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      // Reset sleep time, delay bytes, and time-of-last dequeue for
      // if this bin index is in the destination vector
      
      // Also reset these parameters if the bucket has no physical packets,
      // so we don't try to add more zombies
      
      if ((bin_map_.IsBinInDstVec(dests, dst_bidx)) ||
	  (q_mgr_.non_zombie_queue_depth_bytes(dst_bidx) == 0))
      {
	// Reset sleep time tracking for this bin index
	sleep_time_by_bin_[dst_bidx] = 0;
	
	// Reset bytes added counter for delay term for this bin index
	delay_bytes_added_[dst_bidx] = 0;
	
	// Update the most recent dequeue time for this bin index
	q_mgr_.last_dequeue_time(dst_bidx) = now;
      }
    }
  }
  else // This isn't multicast, so process using my_bin_index_
  {
    // Reset sleep time tracking
    sleep_time_by_bin_[my_bin_index_] = 0;
    
    // Reset bytes added counter for delay term.
    delay_bytes_added_[my_bin_index_] = 0;
    
    // Update the most recent dequeue time
    q_mgr_.last_dequeue_time(my_bin_index_) = now;
  }
}  

