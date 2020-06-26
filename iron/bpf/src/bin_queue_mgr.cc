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

#include "bin_queue_mgr.h"

#include "queue_store.h"
#include "iron_constants.h"
#include "log.h"
#include "packet.h"
#include "packet_queue.h"
#include "queue_depths.h"
#include "unused.h"
#include "zombie.h"
#include "zombie_queue.h"

#include <limits>
#include <sstream>
#include <string>

#include <inttypes.h>

using ::iron::BinId;
using ::iron::BinQueueMgr;
using ::iron::DropPolicy;
using ::iron::LatencyClass;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketQueue;
using ::iron::Queue;
using ::iron::QueueDepths;
using ::iron::Time;
using ::iron::ZLR;
using ::iron::Zombie;
using ::iron::ZombieQueue;
using ::std::string;

namespace
{
  const char  kClassName[]                      = "BinQueueMgr";

  /// The default queue depth computation approach intended for proxy admission.
  const bool      kDefaultMaxDestinationProxyAdmission
                                                = true;

  /// The default drop policy in the BinQueueMgr.
  const char*     kDefaultBpfDropPolicy         = "NO_DROP";

  /// The default maximum bin depth in the BinQueueMgr, in packets.
  /// This is the maximum number of packets the queues can take.
  const uint32_t  kDefaultBpfMaxBinDepthPkts    = 50000;

  /// If true, add zombie packets when the queue is long to reduce the
  /// latency.
  const bool      kZombieLatencyReduction       = true;

  /// \brief Identifies which queues are packet-less zombie queues.
  ///
  /// If the position for a latency class is false, this queue will contain
  /// real packets, as expected. If true, packets will be discarded, and the
  /// queue will only maintain a number of bytes. Zombie packets are
  /// re-created on dequeue.
  ///
  /// NOTE: "true" values will be ignored for any latency classes that have
  /// latency constraints. Furthermore, data will be discarded if the value
  /// for a latency class is true, so this should only be used for
  /// signaling packets.
  const bool IS_PKTLESS_Z_QUEUE[iron::NUM_LATENCY_DEF] = {
    false, false, false, true, true, true, false, true, true, true
  };

  /// \brief Default value for whether to generate queue depth graphs.
  const bool  kDefaultGenerateQueueDepthGraphs  = false;

  /// \brief How often to run the anti-starvation algorithm.
  const iron::Time kAntiStarvationInterval      = iron::Time(0.005);

  /// \brief Number of traffic types for latency sensitive non-zombie
  /// classes. Size of LS_NON_ZOMBIE_TTYPES.
  const uint8_t kNumLSNonZombieTTypes           = 3;

  /// \brief Array of traffic types that are latency sensitive, non-zombie
  /// classes.
  ///
  /// Listed in reverse order because we are using this to look for packets,
  /// and we most likely to find LOW_LATENCY packets. So this is slightly more
  /// efficient.
  const LatencyClass LS_NON_ZOMBIE_TTYPES[kNumLSNonZombieTTypes] = {
    iron::LOW_LATENCY, iron::CONTROL_TRAFFIC_LATENCY, iron::CRITICAL_LATENCY
  };

  /// \brief Number of traffic types for non-zombie classes.
  /// Size of NON_ZOMBIE_TTYPES.
  const uint8_t kNumNonZombieTTypes            = 4;

  /// \brief Array of traffic types that are non-zombie classes.
  ///
  const LatencyClass NON_ZOMBIE_TTYPES[kNumNonZombieTTypes] = {
    iron::LOW_LATENCY, iron::CONTROL_TRAFFIC_LATENCY, iron::CRITICAL_LATENCY,
    iron::NORMAL_LATENCY
  };

}

//============================================================================
BinQueueMgr::BinQueueMgr(
  BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map)
    : packet_pool_(packet_pool),
      bin_map_(bin_map),
      my_bin_index_(bin_idx),
      initialized_(false),
      phy_queue_(),
      queue_depths_(bin_map),
      node_bin_idx_(kInvalidBinIndex),
      support_ef_(true),
      is_multicast_(bin_map_.IsMcastBinIndex(bin_idx)),
      max_dst_admission_(kDefaultMaxDestinationProxyAdmission),
      drop_policy_(HEAD),
      max_bin_depth_pkts_(DEFAULT_MAX_BIN_DEPTH_PKTS),
      nbr_queue_depths_(),
      use_anti_starvation_zombies_(kDefaultUseAntiStarvationZombies),
      asap_mgr_(NULL),
      do_zombie_latency_reduction_(kZombieLatencyReduction),
      zlr_manager_(packet_pool, bin_map, *this, bin_idx),
      last_anti_starvation_time_(),
      per_dst_per_lat_class_bytes_(),
      debug_stats_(NULL),
      queue_depths_xplot_(),
      last_dequeue_time_(),
      non_zombie_queue_depth_bytes_()
{
  // Set up the neighbor queue depths array.
  if (!nbr_queue_depths_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize neighbor queue depths "
         "array.\n");
    return;
  }
  nbr_queue_depths_.Clear(NULL);

  // Allocate the neighbor queue depths for unicast destinations and interior
  // nodes.  Multicast destinations cannot be neighbors.
  BinIndex  loop_bin_idx = kInvalidBinIndex;

  for (bool loop_bin_idx_valid = bin_map_.GetFirstPhyBinIndex(loop_bin_idx);
       loop_bin_idx_valid;
       loop_bin_idx_valid = bin_map_.GetNextPhyBinIndex(loop_bin_idx))
  {
    nbr_queue_depths_[loop_bin_idx] = new (std::nothrow) QueueDepths(bin_map);

    if (!nbr_queue_depths_[loop_bin_idx])
    {
      LogF(kClassName, __func__, "Error allocating QueueDepths object.\n");
      return;
    }
  }
}

//============================================================================
bool BinQueueMgr::Initialize(const ConfigInfo& config_info,
                             BinIndex node_bin_idx)
{
  if (!bin_map_.BinIndexIsAssigned(my_bin_index_))
  {
    LogF(kClassName, __func__,
         "My bin id %s is invalid.\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str());
    return false;
  }

  // Store the node's bin index for use in generating Zombie packets.
  node_bin_idx_ = node_bin_idx;

  // Set the queue depth computation for proxy admission.
  max_dst_admission_   = config_info.GetBool("Bpf.Alg.Mcast.MaxAdmission",
    kDefaultMaxDestinationProxyAdmission);

  // Set the drop policy.
  string drop_policy_str = config_info.Get(
    "Bpf.BinQueueMgr.DropPolicy",
    kDefaultBpfDropPolicy);

  if (drop_policy_str == "HEAD")
  {
    SetDefaultDropPolicy(iron::HEAD);
  }
  else if (drop_policy_str == "TAIL")
  {
    SetDefaultDropPolicy(iron::TAIL);
  }
  else if (drop_policy_str == "NO_DROP")
  {
    SetDefaultDropPolicy(iron::NO_DROP);
  }
  else
  {
    LogE(kClassName, __func__, "Invalid BinQueueMgr.DropPolicy %s.\n",
         drop_policy_str.c_str());
    return false;
  }

  uint32_t  max_bin_depth_pkts =
    config_info.GetUint("Bpf.BinQueueMgr.MaxBinDepthPkts",
                        kDefaultBpfMaxBinDepthPkts);
  set_max_bin_depth_pkts(max_bin_depth_pkts);

  std::string ef_ordering_str = config_info.Get("Bpf.Alg.EFOrdering", "");
  EFOrdering ef_ordering = kDefaultEFOrdering;

  if (ef_ordering_str == "DeliveryMargin")
  {
    ef_ordering  = EF_ORDERING_DELIVERY_MARGIN;
  }
  else if (ef_ordering_str == "Ttg")
  {
    ef_ordering  = EF_ORDERING_TTG;
  }

  // Initialize the physical queue for the node's bin index / bin id.
  BinId        my_bin_id = bin_map_.GetPhyBinId(my_bin_index_);
  Ipv4Address  dst_addr(htonl((static_cast<in_addr_t>(10) << 24) |
                              static_cast<in_addr_t>(my_bin_id)));

  for (uint8_t lat = 0; lat < NUM_LATENCY_DEF; ++lat)
  {
    // Free any existing queues to allow re-Initialization without a memory
    // leak. This is used in unit tests.
    Queue* queue = phy_queue_.lat_queues[lat];
    if (queue)
    {
      delete queue;
    }
    queue = NULL;
    if (!IS_PKTLESS_Z_QUEUE[lat])
    {
      queue = new (std::nothrow) PacketQueue(
        packet_pool_, max_bin_depth_pkts_, drop_policy_,
          ((ef_ordering == EF_ORDERING_DELIVERY_MARGIN) ||
           (ef_ordering == EF_ORDERING_TTG)) &&
          (lat == LOW_LATENCY));
    }
    else
    {
      queue = new (std::nothrow) ZombieQueue(
        packet_pool_, bin_map_, is_multicast_, static_cast<LatencyClass>(lat),
        node_bin_idx, dst_addr);
    }

    if (!queue)
    {
      LogF(kClassName, __func__, "Error allocating Queue object.\n");
      return false;
    }
    phy_queue_.lat_queues[lat] = queue;

  }

  // Set up the parameters for anti-starvation
  use_anti_starvation_zombies_ =
    config_info.GetBool("Bpf.UseAntiStarvationZombies",
                       kDefaultUseAntiStarvationZombies);
  if (use_anti_starvation_zombies_)
  {
    asap_mgr_ = new (std::nothrow) ASAP(
      packet_pool_, bin_map_, *this, my_bin_index_, node_bin_idx_);
    if (!asap_mgr_)
    {
      LogF(kClassName, __func__, "Error allocating ASAP manager\n");
      return false;
    }
    if (!asap_mgr_->Initialize(config_info))
    {
      LogF(kClassName, __func__, "Initialization error for ASAP\n");
      return false;
    }
  }

  // Set up the parameters for latency reduction via zombies
  do_zombie_latency_reduction_ = config_info.GetBool(
    "Bpf.ZombieLatencyReduction", kZombieLatencyReduction);

  if (do_zombie_latency_reduction_)
  {
    zlr_manager_.Initialize(config_info);
  }

  // Set up the byte count storage.
  for (int i = 0; i < NUM_LATENCY_DEF; ++i)
  {
    if (!per_dst_per_lat_class_bytes_[i].Initialize(bin_map_))
    {
      LogF(kClassName, __func__, "Unable to initialize byte count array "
           "%d.\n", i);
      return false;
    }
    per_dst_per_lat_class_bytes_[i].Clear(0);
  }

  // Set up the queue depths plotting array.
  if (!queue_depths_xplot_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize queue depths plotting "
         "array.\n");
    return false;
  }
  queue_depths_xplot_.Clear(NULL);

#ifdef XPLOT
  bool do_qd_xplot =
    config_info.GetBool("Bpf.GenerateQueueDepthsGraphs",
                        kDefaultGenerateQueueDepthGraphs);
  if (do_qd_xplot)
  {
    if (is_multicast_)
    {
      // Set up xplot objects for unicast and multicast destination bin
      // indexes.
      DstVec    my_dst_vec = bin_map_.GetMcastDst(my_bin_index_);
      BinIndex  bin_idx    = 0;

      for (bool valid = bin_map_.GetFirstDstBinIndex(bin_idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(bin_idx))
      {
        if (bin_map_.IsBinInDstVec(my_dst_vec, bin_idx))
        {
          SetUpQueueDepthsXplot(bin_idx);
        }
      }
    }
    SetUpQueueDepthsXplot(my_bin_index_);
  }
#endif // XPLOT

  // Set up the last dequeue time array.
  if (!last_dequeue_time_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize last dequeue time "
         "array.\n");
    return false;
  }
  Time  zero_time;
  zero_time.Zero();
  last_dequeue_time_.Clear(zero_time);

  // Set up the last dequeue time array.
  if (!non_zombie_queue_depth_bytes_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize non-zombie queue depth "
         "array.\n");
    return false;
  }
  non_zombie_queue_depth_bytes_.Clear(0);

  LogC(kClassName, __func__, "BinQueueMgr configuration:\n");
  LogC(kClassName, __func__, "Bpf.Alg.Mcast.MaxAdmission:      %s\n",
       max_dst_admission_ ? "Max" : "Sum");
  LogC(kClassName, __func__, "Drop Policy:                     %s\n",
       drop_policy_str.c_str());
  LogC(kClassName, __func__, "Bpf.BinQueueMgr.MaxBinDepthPkts:    %" PRIu32 
       " packets\n", max_bin_depth_pkts);
  LogC(kClassName, __func__, "Anti-starvation zombies (ASAP):  %s\n",
       (use_anti_starvation_zombies_ ? "ON" : "OFF"));
  LogC(kClassName, __func__, "kDefaultZombieCompression:       %s\n",
       (kDefaultZombieCompression ? "ON" : "OFF"));
  LogC(kClassName, __func__, "Zombie-based latency reduction:  %s\n",
       (do_zombie_latency_reduction_ ? "ON" : "OFF"));
  LogC(kClassName, __func__, "Bin Id: %s\n",
       bin_map_.GetIdToLog(my_bin_index_).c_str());

  initialized_ = true;
  return true;
}

//============================================================================
void BinQueueMgr::SetUpQueueDepthsXplot(BinIndex bin_idx)
{
  queue_depths_xplot_[bin_idx] = new (std::nothrow) iron::GenXplot();
  if (!queue_depths_xplot_[bin_idx])
  {
    // log and go on. We just won't generate the graph.
    LogE(kClassName, __func__,
         "Unable to allocate GenXplot for bin index %" PRIBinIndex ".\n",
         bin_idx);
  }
  else
  {
    std::stringstream title;
    std::stringstream graphname;
    if (is_multicast_)
    {
      title << "queue_depths_" << bin_map_.GetIdToLog(my_bin_index_)
            << "_" << bin_map_.GetIdToLog(bin_idx) << ".xplot";
      graphname << "Queue Depths for group "
                << bin_map_.GetIdToLog(my_bin_index_) << ", bin "
                << bin_map_.GetIdToLog(bin_idx);
    }
    else
    {
      title << "queue_depths_" << bin_map_.GetIdToLog(bin_idx) << ".xplot";
      graphname << "Queue Depths for bin "
                << bin_map_.GetIdToLog(bin_idx);
    }
    if (!queue_depths_xplot_[bin_idx]->Initialize(
          title.str(), graphname.str(), true))
    {
      delete queue_depths_xplot_[bin_idx];
      queue_depths_xplot_[bin_idx] = NULL;
    }
    else
    {
      LogC(kClassName, __func__,
           "Set up xplot graph for group %s, dst %s. Filename %s.\n",
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           bin_map_.GetIdToLog(bin_idx).c_str(),
           title.str().c_str());
      for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
      {
        queue_depths_xplot_[bin_idx]->AddLineToKey(
                  static_cast<iron::XPLOT_COLOR>(it % NUM_COLORS),
                  LatencyClass_Name[it]);
      }
    }
    zlr_manager_.set_qd_xplot(bin_idx, queue_depths_xplot_[bin_idx]);
  }
}

//============================================================================
BinQueueMgr::~BinQueueMgr()
{
  initialized_ = false;

  if (asap_mgr_)
  {
    delete asap_mgr_;
  }

  // Delete all of the Queues.
  for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
  {
    Queue* queue = phy_queue_.lat_queues[it];

    if (queue)
    {
      delete queue;
    }
  }

  // Delete the neighbor queue depths and xplot objects.
  BinIndex  bin_idx = kInvalidBinIndex;

  for (bool bin_idx_valid = bin_map_.GetFirstBinIndex(bin_idx);
       bin_idx_valid;
       bin_idx_valid = bin_map_.GetNextBinIndex(bin_idx))
  {
    // Delete the nbr queue depths object.
    if (nbr_queue_depths_[bin_idx])
    {
      delete nbr_queue_depths_[bin_idx];
      nbr_queue_depths_[bin_idx] = NULL;
    }

    if (queue_depths_xplot_.IsInitialized())
    {
      if (queue_depths_xplot_[bin_idx])
      {
        delete queue_depths_xplot_[bin_idx];
        queue_depths_xplot_[bin_idx] = NULL;
      }
    }
  }

}

//============================================================================
bool BinQueueMgr::IsPktlessZQueue(LatencyClass lat)
{
  return IS_PKTLESS_Z_QUEUE[lat];
}

//============================================================================
uint32_t BinQueueMgr::GetQueueDepthForProxies()
{
  if (is_multicast_)
  {
    uint32_t  value    = 0;
    BinIndex  dst_bidx = kInvalidBinIndex;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (!max_dst_admission_)
      {
        // Use the sum of the individual destination queues.
        value += queue_depths_.GetBinDepthByIdx(dst_bidx);
      }
      else if (queue_depths_.GetBinDepthByIdx(dst_bidx) > value)
      {
        // The the max of the destination queues.
        value = queue_depths_.GetBinDepthByIdx(dst_bidx);
      }
    }
    return value;
  }

  return queue_depths_.GetBinDepthByIdx(my_bin_index_);
}

//============================================================================
bool BinQueueMgr::Enqueue(Packet* pkt)
{
  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Error, adding NULL packet to bin with ID %s.\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str());
    return false;
  }

  LatencyClass  lat = pkt->GetLatencyClass();

  if (!support_ef_ && (lat == LOW_LATENCY))
  {
    pkt->SetIpDscp(NORMAL_LATENCY);
    lat = NORMAL_LATENCY;
  }

  Queue* queue = phy_queue_.lat_queues[lat];

  if (!queue)
  {
    LogF(kClassName, __func__,
         "Latency %" PRIu8 " queue for bin id %s is NULL.  "
         "Cannot enqueue packet.\n",
         lat, bin_map_.GetIdToLog(my_bin_index_).c_str());
    return false;
  }

  Time    UNUSED(ttg) = pkt->GetTimeToGo();
  size_t  pkt_size    = pkt->virtual_length();
  DstVec  dst_vec     = pkt->dst_vec();

  if (is_multicast_ && dst_vec == 0)
  {
    LogE(kClassName, __func__,
         "Attempt to enqueue multicast packet with no destinations\n");
    packet_pool_.Recycle(pkt);
    return false;
  }

  // Attempt to enqueue the packet.
  bool          rv          = queue->Enqueue(pkt);

  if (rv)
  {
    OnEnqueue(pkt_size, lat, dst_vec);
    if (WouldLogD(kClassName))
    {
      LogD(kClassName, __func__,
           "Enqueued pkt %p w/ deadline %s in latency queue %s for bin id %s"
           ": lat size %" PRIu32 "PB and total size now %" PRIu32 "B.\n",
           pkt,
           ttg.ToString().c_str(),
           LatencyClass_Name[lat].c_str(),
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           phy_queue_.lat_queues[lat]->GetSize(),
           queue_depths_.GetBinDepthByIdx(my_bin_index_));
    }
  }
  else
  {
    LogD(kClassName, __func__,
         "Failed to enqueue pkt %p w/ deadline %s in latency queue %s for "
         "bin id %s: lat size %" PRIu32 "PB and total size now %" PRIu32
         "B.\n", pkt,
         ttg.ToString().c_str(),
         LatencyClass_Name[lat].c_str(),
         bin_map_.GetIdToLog(my_bin_index_).c_str(),
         phy_queue_.lat_queues[lat]->GetSize(),
         queue_depths_.GetBinDepthByIdx(my_bin_index_));
  }
  return rv;
}

//============================================================================
Packet* BinQueueMgr::Peek()
{
  for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
  {
    Queue* queue = phy_queue_.lat_queues[it];

    if (!queue || IS_PKTLESS_Z_QUEUE[it])
    {
      // Not a packet queue, nothing to peek at.
      continue;
    }

    return static_cast<PacketQueue*>(queue)->Peek();
  }

  return NULL;
}

//============================================================================
Packet* BinQueueMgr::Peek(const uint8_t lat)
{
  Queue* queue = FindQueue(lat);

  if (!queue || IS_PKTLESS_Z_QUEUE[lat])
  {
    // Not a packet queue, nothing to peek at.
    return NULL;
  }

  return static_cast<PacketQueue*>(queue)->Peek();
}

//============================================================================
size_t BinQueueMgr::GetTotalDequeueSize(const uint8_t lat)
{
  Queue* queue = FindQueue(lat);
  if (!queue)
  {
    LogF(kClassName, __func__, "No queue for bin %s, latency class %" PRIu8
         ".\n", bin_map_.GetIdToLog(my_bin_index_).c_str(), lat);
    // Shouldn't be possible.
    return 0;
  }

  return queue->GetTotalDequeueSize();
}

//============================================================================
size_t BinQueueMgr::GetNextDequeueSize(const uint8_t lat)
{
  Queue* queue = FindQueue(lat);
  if (!queue)
  {
    LogF(kClassName, __func__, "No queue for bin %s, latency class %" PRIu8
         ".\n", bin_map_.GetIdToLog(my_bin_index_).c_str(), lat);
    // Shouldn't be possible.
    return 0;
  }

  return queue->GetNextDequeueSize();
}

//============================================================================
size_t BinQueueMgr::GetNextDequeueSize(const uint8_t lat, BinIndex bin_index)
{
  Queue* queue = FindQueue(lat);
  if (!queue)
  {
    LogF(kClassName, __func__, "No queue for bin %s, latency class %" PRIu8
         ".\n", bin_map_.GetIdToLog(my_bin_index_).c_str(), lat);
    // Shouldn't be possible.
    return 0;
  }

  return queue->GetNextDequeueSize(bin_index);
}

//============================================================================
Packet* BinQueueMgr::PeekNext(uint8_t lat, PacketQueue::QueueWalkState& ws)
{
  // Find the Latency Queue object for the bin.
  Queue*  queue = FindQueue(lat);

  if (!queue || IS_PKTLESS_Z_QUEUE[lat])
  {
    // Not a packet queue, nothing to peek at.
    return NULL;
  }

  return static_cast<PacketQueue*>(queue)->PeekNextPacket(ws);
}

//============================================================================
uint32_t BinQueueMgr::DropFromQueue(
  LatencyClass lat, uint32_t max_bytes, DstVec dst_vec)
{
  // Find the Latency Queue object for the bin.
  Queue*  queue = FindQueue(lat);

  if (!queue)
  {
    // Invalid queue, nothing to drop.
    return 0;
  }

  uint32_t num_dropped = queue->DropPacket(max_bytes, dst_vec);
  if (num_dropped > 0)
  {
    DequeuedInfo info(lat, num_dropped, dst_vec);
    OnDequeue(info, false);
  }
  return num_dropped;
}

//============================================================================
Packet* BinQueueMgr::DequeueAtCurrentIterator(uint8_t lat)
{
  // Find the Latency Queue object for the bin.
  Queue*  queue = FindQueue(lat);

  if (!queue || IS_PKTLESS_Z_QUEUE[lat])
  {
    // Not a packet queue, doesn't support iterators.
    return NULL;
  }

  Packet* pkt = static_cast<PacketQueue*>(queue)->DequeueAtIterator();

  if (pkt)
  {
    DequeuedInfo info(pkt, pkt->dst_vec());
    OnDequeue(info, false);
  }
  return pkt;
}

//============================================================================
PacketQueue::QueueWalkState BinQueueMgr::GetFrontIterator(uint8_t lat)
{
  // Find the Latency Queue object for the this bin.
  Queue*  queue = FindQueue(lat);

  if (!queue || IS_PKTLESS_Z_QUEUE[lat])
  {
    // Not a packet queue. Doesn't support iterators. We shouldn't be calling
    // this function for zombie latencies.
    LogF(kClassName, __func__,
         "No packet queue for bin %s, latency class %" PRIu8 ".\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str(), lat);
    PacketQueue::QueueWalkState ws;
    ws.PrepareForWalk();
    return ws;
  }

  return static_cast<PacketQueue*>(queue)->GetFrontIterator();
}

//============================================================================
bool BinQueueMgr::GetIterator(uint8_t lat, Packet* pkt,
                              PacketQueue::QueueWalkState& qws)
{
  // Find the Latency Queue object for the bin.
  Queue*  queue = FindQueue(lat);

  if (!queue || IS_PKTLESS_Z_QUEUE[lat])
  {
    // Not a packet queue, doesn't support iterators.
    return false;
  }
  qws = static_cast<PacketQueue*>(queue)->GetIterator(pkt);

  return true;
}

//============================================================================
void BinQueueMgr::PrepareIteration(uint8_t lat)
{
  // Find the Latency Queue object for the bin.
  Queue*  queue = FindQueue(lat);

  if (!queue || IS_PKTLESS_Z_QUEUE[lat])
  {
    // Not a packet queue, doesn't support iterators.
    return;
  }

  static_cast<PacketQueue*>(queue)->PrepareQueueIterator();
}

//============================================================================
Packet* BinQueueMgr::Dequeue()
{
  Packet* pkt = NULL;
  uint8_t lat = 0;

  for (lat = 0; lat < NUM_LATENCY_DEF; ++lat)
  {
    Queue* queue = phy_queue_.lat_queues[lat];

    if (!queue)
    {
      // No queue, nothing to dequeue.
      continue;
    }

    pkt = queue->Dequeue();
    if (pkt)
    {
      break;
    }
  }

  if (pkt)
  {
    DequeuedInfo info(pkt, pkt->dst_vec());
    OnDequeue(info, false);
  }

  return pkt;
}

//============================================================================
Packet* BinQueueMgr::DequeueAtIterator(LatencyClass lat,
                                       PacketQueue::QueueWalkState& qws,
                                       DstVec send_to)
{
  if (IS_PKTLESS_Z_QUEUE[lat])
  {
    LogE(kClassName, __func__,
         "Attempting to DequeueAtIterator from a Zombie Queue.\n");
    return NULL;
  }

  Queue*  queue     = FindQueue(lat);
  Packet* orig_pkt  = NULL;
  Packet* pkt       = NULL;
  bool    cloned    = false;

  if (queue)
  {
    // Check if we've been passed a send-to list, since send_to = 0 is a code
    // for "dequeue entire packet."
    if (send_to)
    {
      orig_pkt  = static_cast<PacketQueue*>(queue)->PeekAtIterator(qws);

      if (orig_pkt && (orig_pkt->dst_vec() != send_to))
      {
        pkt = packet_pool_.Clone(orig_pkt, true, iron::PACKET_COPY_TIMESTAMP);
        cloned = true;

        if (!pkt)
        {
          LogF(kClassName, __func__,
               "Packet %p clone operation failed.\n",
               orig_pkt);
          return NULL;
        }

        pkt->set_dst_vec(send_to);
        // Subtract function will LogF if the list we are subtracting is not a
        // subset of the list we are subtracting from.
        orig_pkt->set_dst_vec(
          bin_map_.DstVecSubtract(orig_pkt->dst_vec(), send_to));
        LogA(kClassName, __func__,
             "Cloned packet %p->%p and sending to destinations 0x%X, leaving "
             "0x%X in orig pkt.\n",
             orig_pkt, pkt, pkt->dst_vec(), orig_pkt->dst_vec());
      }
    }

    // We didn't need to remove a subset of the destinations, so just dequeue
    // the entire packet.
    if (!pkt)
    {
      pkt = static_cast<PacketQueue*>(queue)->DequeueAtIterator(qws);
    }
  }

  if (pkt)
  {
    DequeuedInfo info(pkt, send_to);
    OnDequeue(info, cloned);
  }
  else
  {
    LogD(kClassName, __func__,
         "Found no packet to dequeue for latency %s.\n",
         LatencyClass_Name[lat].c_str());
  }

  return pkt;
}

//============================================================================
Packet* iron::BinQueueMgr::Dequeue(LatencyClass lat, uint32_t max_size_bytes,
                                   DstVec dst_vec)
{
  Queue*   queue   = FindQueue(lat);
  Packet*  pkt     = NULL;

  if (queue)
  {
    pkt = queue->Dequeue(max_size_bytes, dst_vec);
  }

  if (pkt)
  {
    DequeuedInfo info(pkt, dst_vec);
    OnDequeue(info, false);
  }

  return pkt;
}

//============================================================================
bool BinQueueMgr::ZombifyPacket(Packet* pkt)
{
  if (!pkt)
  {
    LogF(kClassName, __func__,
         "Pkt is NULL!  Cannot Zombify.\n");
    return false;
  }

  LatencyClass  lat = pkt->GetLatencyClass();

  if ((lat == LOW_LATENCY) || (lat == CRITICAL_LATENCY))
  {
    Zombie::ZombifyExistingPacket(pkt);

    // MCAST TODO Has this packet already been dequeued from the low
    // latency queue? (Worth double checking, because we no longer totally
    // recompute all the queue depths the way we used to. Now that we're just
    // doing increment/decrement, it's really important that we call
    // AdjustDepths every time the class of a packet changes.
    if (!Enqueue(pkt))
    {
      LogD(kClassName, __func__,
           "Failed to move packet (%p) to lat insensitive queue."
           " Need to drop.\n",
           pkt);
      return false;
    }
  }
  else
  {
    LogD(kClassName, __func__,
         "Latency-insensitive packet %p is not movable. Need to drop.\n",
         pkt);
    return false;
  }

  if (debug_stats_)
  {
    std::stringstream num_zombies_str;
    num_zombies_str << "NUMZOMBIES" << bin_map_.GetIdToLog(my_bin_index_);
    debug_stats_->CountOccurrences(num_zombies_str.str().c_str(), Time(5.0));
  }

  LogD(kClassName, __func__,
       "Packet %p turned Zombie with new size %zuB and virtual size %zuB.\n",
       pkt, pkt->GetLengthInBytes(), pkt->virtual_length());
  return true;
}

//============================================================================
void BinQueueMgr::AddNewZombie(
  uint32_t dst_addr_nbo,
  uint32_t total_zombie_bytes,
  LatencyClass zombie_class,
  DstVec dst_vec)
{
  // Note: we allow adding packetless zombies of less than kMinZombieLenBytes
  // - the minimum packet size requirement will only be enforced when we
  // remove zombies.
  if (IS_PKTLESS_Z_QUEUE[zombie_class])
  {
    (static_cast<ZombieQueue*>(
      phy_queue_.lat_queues[zombie_class]))->AddZombieBytes(
        total_zombie_bytes, dst_vec);
    OnEnqueue(total_zombie_bytes, zombie_class, dst_vec);
  }
  else
  {
    // Encode the local node's BinId in a fake IPv4 source address.
    BinId      my_bin_id    = bin_map_.GetPhyBinId(my_bin_index_);
    in_addr_t  src_addr_nbo = htonl((static_cast<in_addr_t>(10) << 24) |
                                    static_cast<in_addr_t>(my_bin_id));

    Packet* zombie = NULL;
    while (total_zombie_bytes > 0)
    {
      size_t size = total_zombie_bytes;
      if (size > kMaxZombieLenBytes)
      {
        size = kMaxZombieLenBytes;
      }
      zombie = iron::Zombie::CreateNewZombie(
        packet_pool_, src_addr_nbo, dst_addr_nbo, size,
        zombie_class);
      if (!zombie)
      {
        LogF(kClassName, __func__, "Unable to generate zombie to enqueue.\n");
        return;
      }
      if (dst_vec != 0)
      {
        zombie->set_dst_vec(dst_vec);
      }
      if (zombie->GetLengthInBytes() > size)
      {
        // In case we tried to create a zombie smaller than the minimum size
        // packet, make sure our accounting is correct after creating the
        // packet.
        size = zombie->GetLengthInBytes();
      }
      if (!Enqueue(zombie))
      {
        LogF(kClassName, __func__, "Unable to enqueue zombie\n");
        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        packet_pool_.Recycle(zombie);
        zombie = NULL;
        return;
      }
      total_zombie_bytes -= size;
    }
  }
}

//============================================================================
bool BinQueueMgr::CriticalizePacket(Packet* pkt)
{
  if (!pkt)
  {
    LogF(kClassName, __func__,
         "Pkt is NULL!  Cannot Criticalize.\n");
    return false;
  }

  if (pkt->GetLatencyClass() == LOW_LATENCY)
  {
    Queue* queue = phy_queue_.lat_queues[CRITICAL_LATENCY];

    if (!queue)
    {
      // No queue, error.
      LogF(kClassName, __func__, "Latency Queue NULL.\n");
      return false;
    }

    // Attempt to enqueue the packet.
    size_t  pkt_size = pkt->virtual_length();
    DstVec  dst_vec  = pkt->dst_vec();
    pkt->SetLatencyClass(CRITICAL_LATENCY);
    bool    rv       = queue->Enqueue(pkt);

    // MCAST TODO Has this packet already been dequeued from the normal
    // latency queue? (Worth double checking, because we no longer totally
    // recompute all the queue depths the way we used to. Now that we're just
    // doing increment/decrement, it's really important that we call
    // AdjustDepths every time the class of a packet changes.
    if (is_multicast_)
    {
      MulticastAdjustDepths(dst_vec, CRITICAL_LATENCY, pkt_size);
    }
    else
    {
      UnicastAdjustDepths(CRITICAL_LATENCY, pkt_size);
    }

    if (WouldLogD(kClassName))
    {
      if (rv)
      {
        LogD(kClassName, __func__,
             "Enqueued pkt %p in latency queue CRITICAL for bin id %s"
             ": lat size %" PRIu32 "B and total size now %"
             PRIu32 "B.\n",
             pkt, bin_map_.GetIdToLog(my_bin_index_).c_str(),
             phy_queue_.lat_queues[pkt->GetLatencyClass()]->GetSize(),
             queue_depths_.GetBinDepthByIdx(my_bin_index_));
      }
      else
      {
        LogD(kClassName, __func__,
             "Failed pkt %p enqueue in latency queue CRITICAL for bin id %s"
             ": lat size %" PRIu32 "B and total size %" PRIu32 "B.\n",
             pkt, bin_map_.GetIdToLog(my_bin_index_).c_str(),
             phy_queue_.lat_queues[pkt->GetLatencyClass()]->GetSize(),
             queue_depths_.GetBinDepthByIdx(my_bin_index_));
      }
    }
    return rv;
  }
  else
  {
    LogD(kClassName, __func__,
         "Latency-insensitive packet %p is not movable.\n",
         pkt);
  }

  return false;
}

//============================================================================
bool BinQueueMgr::IsOrdered(LatencyClass lat) const
{
  Queue* queue  = FindQueue(lat);

  if (!queue)
  {
    return false;
  }

  return queue->IsOrdered();
}

//============================================================================
void BinQueueMgr::Print()
{
  if (!WouldLogD(kClassName))
  {
    return;
  }

  std::stringstream bin_str("");
  uint64_t          total_count = 0;
  for (uint8_t lat = 0; lat < NUM_LATENCY_DEF; ++lat)
  {
    bin_str << " (Lat " << LatencyClass_Name[lat] << " ";
    bin_str << phy_queue_.lat_queues[lat]->ToString() << ")";

    total_count += phy_queue_.lat_queues[lat]->GetCount();
  }

  if (total_count == 0)
  {
    LogD(kClassName, __func__, "BinId %s: 0B.\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str());
  }
  else
  {
    LogD(kClassName, __func__,
         "BinId %s:%s.\n", bin_map_.GetIdToLog(my_bin_index_).c_str(),
         bin_str.str().c_str());
  }
}

//============================================================================
uint32_t BinQueueMgr::depth_packets() const
{
  uint32_t ret = 0;

  for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
  {
    Queue* queue = phy_queue_.lat_queues[it];

    if (queue)
    {
      ret += queue->GetCount();
    }
  }

  return ret;
}

//============================================================================
void BinQueueMgr::set_nbr_queue_depths(BinIndex nbr_bin_idx, QueueDepths* qd)
{
  if (!qd)
  {
    LogW(kClassName, __func__,
         "Queue depth NULL, cannot set queues for bin id %s.\n",
         bin_map_.GetIdToLog(nbr_bin_idx).c_str());
    return;
  }

  if (nbr_queue_depths_[nbr_bin_idx])
  {
    LogF(kClassName, __func__,
         "There is a QueueDepth already in for nbr bin %s"
         "!  Setting would overwrite and leak memory.\n",
         bin_map_.GetIdToLog(nbr_bin_idx).c_str());
    return;
  }
  nbr_queue_depths_[nbr_bin_idx] = qd;
}

//============================================================================
bool BinQueueMgr::ContainsNonZombies() const
{
  return ContainsPacketsWithTtypes(NON_ZOMBIE_TTYPES,
                                   kNumNonZombieTTypes);
}

//============================================================================
bool BinQueueMgr::ContainsLSNonZombies() const
{
  return ContainsPacketsWithTtypes(LS_NON_ZOMBIE_TTYPES,
                                   kNumLSNonZombieTTypes);
}

//============================================================================
bool BinQueueMgr::ContainsPacketsWithTtypes(
  const LatencyClass* ttypes_to_query, uint8_t num_ttypes_to_query) const
{
  Queue* queue = NULL;
  for (uint8_t idx = 0; idx < num_ttypes_to_query; ++idx)
  {
    queue = phy_queue_.lat_queues[ttypes_to_query[idx]];
    if (queue && queue->GetSize() > 0)
    {
      return true;
    }
  }
  return false;
}

//============================================================================
uint32_t  BinQueueMgr::GetTtypeDepthBytes(
  BinIndex dst_to_get, const LatencyClass* ttypes_to_get,
  uint8_t num_ttypes_to_get)
{
  uint32_t  ret = 0;

  for (uint8_t idx = 0; idx < num_ttypes_to_get; ++idx)
  {
    if ((ttypes_to_get[idx] >= 0) && (ttypes_to_get[idx] < NUM_LATENCY_DEF))
    {
      ret += per_dst_per_lat_class_bytes_[ttypes_to_get[idx]][dst_to_get];
    }
  }

  return ret;
}

//============================================================================
void BinQueueMgr::PeriodicAdjustQueueValues()
{
  Time now = Time::Now();
    // Adjust queue depths for anti-starvation.
  if (asap_mgr_ &&
      ((now - last_anti_starvation_time_) > kAntiStarvationInterval))
  {
    asap_mgr_->AdjustQueueValuesForAntiStarvation();
    last_anti_starvation_time_ = now;
  }
}

//============================================================================
void BinQueueMgr::ProcessCapacityUpdate(uint32_t pc_num, double capacity_bps)
{
  if (asap_mgr_)
  {
    asap_mgr_->ProcessCapacityUpdate(pc_num, capacity_bps);
  }
}

//============================================================================
void BinQueueMgr::SetASAPCap(uint32_t new_cap, bool is_ls)
{
  if (asap_mgr_)
  {
    asap_mgr_->SetASAPCap(new_cap, is_ls);
  }
}

//============================================================================
void BinQueueMgr::set_drop_policy(DropPolicy policy)
{
  LogD(kClassName, __func__, "Setting the drop policy of bin ID %s"
       " to %d.\n", bin_map_.GetIdToLog(my_bin_index_).c_str(),
       static_cast<int>(policy));

  // Set drop policy for all latency queues.
  for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
  {
    if (IS_PKTLESS_Z_QUEUE[it])
    {
      // No drop policy for zombie queues.
      continue;
    }
    PacketQueue* queue =
      static_cast<PacketQueue*>(phy_queue_.lat_queues[it]);

    if (queue)
    {
      queue->set_drop_policy(policy);
    }
  }
}

//============================================================================
void BinQueueMgr::set_drop_policy(LatencyClass lat,
                                  DropPolicy policy)
{
  if (IS_PKTLESS_Z_QUEUE[lat])
  {
    // No need to set drop policy for zombie queues.
    return;
  }

  LogD(kClassName, __func__, "Setting the drop policy of bin ID %s"
       " for latency %d to %d.\n",
       bin_map_.GetIdToLog(my_bin_index_).c_str(), lat,
       static_cast<int>(policy));

  PacketQueue* queue = static_cast<PacketQueue*>(FindQueue(lat));
  if (queue)
  {
    queue->set_drop_policy(policy);
  }
}

//============================================================================
inline Queue* BinQueueMgr::FindQueue(uint8_t lat) const
{
  if (lat >= NUM_LATENCY_DEF)
  {
    LogE(kClassName, __func__,
         "Attempting to find a queue for invalid latency class %" PRIu8 ".\n",
         lat);
    return NULL;
  }

  return phy_queue_.lat_queues[lat];
}

//============================================================================
DropPolicy iron::BinQueueMgr::drop_policy() const
{
  return drop_policy(NORMAL_LATENCY);
}

//============================================================================
DropPolicy iron::BinQueueMgr::drop_policy(LatencyClass lat) const
{
  if (IS_PKTLESS_Z_QUEUE[lat])
  {
    return UNDEFINED_DP;
  }
  PacketQueue* queue = static_cast<PacketQueue*>(FindQueue(lat));
  if (queue)
  {
    return queue->drop_policy();
  }
  return UNDEFINED_DP;
}

//============================================================================
void BinQueueMgr::OnEnqueue(
  uint32_t pkt_length_bytes, LatencyClass lat, DstVec dsts)
{
  if (is_multicast_)
  {
    MulticastAdjustDepths(dsts, lat, pkt_length_bytes);
  }
  else
  {
    UnicastAdjustDepths(lat, pkt_length_bytes);
  }

  if (do_zombie_latency_reduction_)
  {
    zlr_manager_.DoZLREnqueueProcessing(pkt_length_bytes, lat, dsts);
  }
}

//============================================================================
void BinQueueMgr::OnDequeue(const DequeuedInfo& dq_info, bool cloned)
{
  LatencyClass  lat     = dq_info.lat;
  DstVec        dst_vec = dq_info.dst_vec;

  if (is_multicast_)
  {
    MulticastAdjustDepths(
      dst_vec, lat, -1 * (static_cast<int64_t>(dq_info.dequeued_size)));
  }
  else
  {
    UnicastAdjustDepths(
      lat, -1 * (static_cast<int64_t>(dq_info.dequeued_size)));
  }

  if (do_zombie_latency_reduction_)
  {
    zlr_manager_.DoZLRDequeueProcessing(dq_info);
  }

  if (debug_stats_)
  {
    if (Packet::IsZombie(dq_info.lat))
    {
      std::stringstream zombie_sent_str;
      zombie_sent_str << "SENTZOMBIES" << bin_map_.GetIdToLog(my_bin_index_);
      debug_stats_->CountOccurrences(zombie_sent_str.str().c_str(),
                                     Time(5.0));
    }
  }

  if (WouldLogD(kClassName))
  {
    if (dq_info.is_ip)
    {
      LogD(kClassName, __func__,
           "%s pkt with dscp %" PRIu8 " and size %zuB "
           "from latency queue %s for bin_id %s: lat size %" PRIu32 
           "B and total size now %" PRIu32 "B.\n",
           (cloned ? "Cloned" : "Dequeued"),
           dq_info.dscp, dq_info.dequeued_size,
           LatencyClass_Name[dq_info.lat].c_str(),
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           phy_queue_.lat_queues[dq_info.lat]->GetSize(),
           queue_depths_.GetBinDepthByIdx(my_bin_index_));
    }
    else
    {
      LogD(kClassName, __func__,
           "%s non-IP pkt from latency queue %s for "
           "bin_id %s: lat size %" PRIu32 "B and total size now %"
           PRIu32 "B.\n",
           (cloned ? "Cloned" : "Dequeued"),
           LatencyClass_Name[lat].c_str(),
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           phy_queue_.lat_queues[lat]->GetSize(),
           queue_depths_.GetBinDepthByIdx(my_bin_index_));
    }
  }

  // TODO: Should we do ASAP on a cloned packet? Assuming yes.
  if (asap_mgr_)
  {
    asap_mgr_->OnDequeue(dq_info);
  }
}

//============================================================================
bool BinQueueMgr::IsNonZombieLatClass(LatencyClass lat)
{
  for (uint8_t idx = 0; idx < kNumNonZombieTTypes; ++idx)
  {
    if (NON_ZOMBIE_TTYPES[idx] == lat)
    {
      return true;
    }
  }
  return false;
}

//============================================================================
void BinQueueMgr::UnicastAdjustDepths(LatencyClass lat, int64_t delta_bytes)
{
  AdjustQueueDepth(my_bin_index_, lat, delta_bytes);
}

//============================================================================
void BinQueueMgr::MulticastAdjustDepths(
  DstVec dst_vec, LatencyClass lat, int64_t delta_bytes)
{
  uint8_t   num_dsts            = 0;
  BinIndex  dst_bidx            = 0;
  bool      is_mcast_non_zombie = IsNonZombieLatClass(lat);

  // Multicast bins can't be in a DstVec, so iterate over all unicast
  // destination bin indexes.
  for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
       valid;
       valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
  {
    if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx))
    {
      AdjustQueueDepth(dst_bidx, lat, delta_bytes);
      ++num_dsts;
      if (is_mcast_non_zombie)
      {
        if (delta_bytes < 0)
        {
          last_dequeue_time_[dst_bidx] = Time::Now();
        }
        else if (non_zombie_queue_depth_bytes_[dst_bidx] == 0)
        {
          last_dequeue_time_[dst_bidx] = Time::Now();
        }
        non_zombie_queue_depth_bytes_[dst_bidx] += delta_bytes;
      }
    }
  }
  AdjustQueueDepth(my_bin_index_, lat, (num_dsts * delta_bytes));
}

//============================================================================
void BinQueueMgr::AdjustQueueDepth(
  BinIndex bin_idx, LatencyClass lat, int64_t delta_bytes)
{
  int64_t UNUSED(prev_depth)    = queue_depths_.GetBinDepthByIdx(bin_idx);
  int64_t UNUSED(prev_ls_depth) = queue_depths_.GetBinDepthByIdx(bin_idx,
    LOW_LATENCY);

  // Validate the latency class value since it will be used as an array index
  // in this method.
  if ((lat < 0) || (lat >= NUM_LATENCY_DEF))
  {
    LogF(kClassName, __func__, "Invalid latency class %d.\n", lat);
    return;
  }

  // AdjustByAmt checks internally for overflow.
  queue_depths_.AdjustByAmt(
    bin_idx, delta_bytes, (Packet::IsLatencySensitive(lat) ? delta_bytes : 0));

  int64_t UNUSED(new_depth)     = queue_depths_.GetBinDepthByIdx(bin_idx);
  int64_t UNUSED(new_ls_depth)  = queue_depths_.GetBinDepthByIdx(bin_idx,
                                                                 LOW_LATENCY);

  LogD(kClassName, __func__,
       "Modify Bin id %s queue depths of %" PRIu32 "B (LS %" PRIu32 
       "B) by %ldB for latency %s to %" PRIu32 "B (LS %" PRIu32 "B).\n",
       bin_map_.GetIdToLog(bin_idx).c_str(),
       prev_depth, prev_ls_depth,
       delta_bytes, LatencyClass_Name[lat].c_str(),
       new_depth, new_ls_depth);

  // Adjust per-class/per-destination byte counts (with overflow checks).
  if ((delta_bytes < 0) &&
      (per_dst_per_lat_class_bytes_[lat][bin_idx] < -delta_bytes))
  {
    LogW(kClassName, __func__,
         "Attempt to decrease queue depth to below 0. MC bin %s"
         ", dst bin %" PRIBinId ", latency %s: depth was %" PRIu32
         ", attempted to decrement by %" PRId64 ".\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str(),
         bin_map_.GetIdToLog(bin_idx).c_str(), LatencyClass_Name[lat].c_str(),
         per_dst_per_lat_class_bytes_[lat][bin_idx], -delta_bytes);
    per_dst_per_lat_class_bytes_[lat][bin_idx] = 0;
  }
  else if ((delta_bytes > 0) &&
           (UINT32_MAX - per_dst_per_lat_class_bytes_[lat][bin_idx] <
            delta_bytes))
  {
    LogF(kClassName, __func__,
         "Queue overflow. MC bin %s"
         ", dst bin %s, latency %s: depth was %" PRIu32
         ", attempted to increment by %" PRId64 ".\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str(),
         bin_map_.GetIdToLog(bin_idx).c_str(), LatencyClass_Name[lat].c_str(),
         per_dst_per_lat_class_bytes_[lat][bin_idx], delta_bytes);
    per_dst_per_lat_class_bytes_[lat][bin_idx] = UINT32_MAX;
  }
  else
  {
    per_dst_per_lat_class_bytes_[lat][bin_idx] += delta_bytes;
  }

  GraphNewQueueDepths(bin_idx);

  // Let subclasses handle sample-gathering and smoothing, if appropriate.
  AdjustQueueValuesOnChange(bin_idx);
}

//============================================================================
void BinQueueMgr::GraphNewQueueDepths(BinIndex bin_idx)
{
  if (queue_depths_xplot_[bin_idx])
  {
    uint64_t now_usec        = Time::GetNowInUsec() - iron::kStartTime;
    uint32_t y_val           = 0;

    // Loop backwards so that we get lowest latency classes at the top of the
    // graph.
    for (uint8_t it = NUM_LATENCY_DEF; it > 0; --it)
    {
      y_val += per_dst_per_lat_class_bytes_[it-1][bin_idx];
      if (per_dst_per_lat_class_bytes_[it-1][bin_idx] > 0)
      {
        queue_depths_xplot_[bin_idx]->DrawPoint(
          now_usec, y_val, static_cast<iron::XPLOT_COLOR>((it-1) % NUM_COLORS),
          XPLOT_DOT);
      }
    }
  }
}
