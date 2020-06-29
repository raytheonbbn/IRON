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

/// \file uber_fwd_alg.cc

#include "uber_fwd_alg.h"

#include "backpressure_fwder.h"
#include "iron_constants.h"
#include "iron_types.h"
#include "iron_utils.h"
#include "path_controller.h"
#include "zombie.h"
#include "zombie_queue.h"

#include <limits>
#include <queue>
#include <string>

#include <math.h>

using ::iron::LatencyClass;
using ::iron::OrderedList;
using ::iron::Packet;
using ::iron::PathController;
using ::iron::UberFwdAlg;

namespace
{
  /// Class name for logging.
  const char          kClassName[]                  = "UberFwdAlg";

  /// The default search depth in the queues when using LatencyAware
  /// forwarding, in bytes.
  const uint32_t      kDefaultQueueSearchDepthBytes = 5000;

  /// The (unchangeable) search depth in the queues when using Base
  /// forwarding.
  const uint8_t       kQueueSearchDepthBaseBytes    = 1;

  /// The default threshold under which a path controller's transmit buffer is
  /// considered free (and can accept new packets).  2000 is a reasonable value.
  /// Set to kDefaultBpfXmitQueueThreshBytes to disable multi-dequeues, to a
  /// lower value to allow
  /// kDefaultBpfXmitQueueThreshByte - kDefaultBpfXmitQueueFreeThreshBytes bytes
  /// of multi-dequeues.
  const uint32_t      kDefaultBpfXmitQueueFreeThreshBytes = 2000;

  /// The default boolean whether to use opportunistic forwarding for mcast
  /// fwding.
  const bool          kDefaultEnableMcastOpportunisticFwding
                                                          = false;

  /// The default opportunistic forwarding floor for mcast fwding.
  const int64_t       kDefaultMcastOpportunisticFwdingFloor
                                                          = -4000;

  /// Enable hierarchical forwarding by default.
  const bool          kDefaultHierarchicalFwding    = true;

  /// The traffic types that may be Zombifiable.
  const LatencyClass  ZOMBIFIABLE_TTYPES[2]         =
    {iron::CRITICAL_LATENCY, iron::LOW_LATENCY};

  /// The traffic types that may be dequeued first.
  // TODO: Add other LS types.
  const LatencyClass  PRIO_DEQUEUE_TTYPES[4]    = {iron::LOW_LATENCY,
                                                   iron::HIGH_LATENCY_EXP,
                                                   iron::HIGH_LATENCY_NPLB_LS,
                                                   iron::HIGH_LATENCY_ZLR_LS};

  const LatencyClass  PRIO_DEQUEUE_TTYPES_ZOMBIES_FIRST[4]
                                                = {iron::HIGH_LATENCY_NPLB_LS,
                                                   iron::HIGH_LATENCY_ZLR_LS,
                                                   iron::LOW_LATENCY,
                                                   iron::HIGH_LATENCY_EXP};

  /// The traffic types that are not preferentially dequeued first.
  const LatencyClass  STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES[4] =
    {iron::NORMAL_LATENCY,
     iron::HIGH_LATENCY_RCVD,
     iron::HIGH_LATENCY_NPLB,
     iron::HIGH_LATENCY_ZLR};

  /// The traffic types that are not preferentially dequeued first, zombies first.
  const LatencyClass  STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES_ZOMBIES_FIRST[4] =
    {iron::HIGH_LATENCY_NPLB,
     iron::HIGH_LATENCY_ZLR,
     iron::NORMAL_LATENCY,
     iron::HIGH_LATENCY_RCVD};


  /// The default update coefficient for the queuing delay EW moving-average.
  const double  kDefaultQueueDelayAlpha       = 0.999;

  /// The default boolean to generate queue delay graph.
  const bool kDefaultGenerateQueueDelayGraphs = false;
}

//============================================================================
UberFwdAlg::UberFwdAlg(BPFwder& bpfwder, PacketPool& packet_pool,
                       BinMap& bin_map, QueueStore* q_store,
                       PacketHistoryMgr* packet_history_mgr,
                       size_t num_path_ctrls, PathCtrlInfo* path_ctrls)
    : initialized_(false),
      queue_store_(q_store),
      bin_map_(bin_map),
      packet_history_mgr_(packet_history_mgr),
      num_path_ctrls_(num_path_ctrls),
      path_ctrls_(path_ctrls),
      hysteresis_(kBpfAlgHysteresisBytes),
      xmit_buf_max_thresh_(kDefaultBpfXmitQueueThreshBytes),
      xmit_buf_free_thresh_(kDefaultBpfXmitQueueFreeThreshBytes),
      mcast_gradients_(),
      rng_(),
      bpfwder_(bpfwder),
      packet_pool_(packet_pool),
      alg_name_(kDefaultBpfwderAlg),
      base_(true),
      queue_search_depth_(kDefaultQueueSearchDepthBytes),
      zombifiable_ttypes_(),
      num_zombifiable_ttypes_(0),
      priority_dequeue_ttypes_(),
      priority_dequeue_ttypes_zombies_first_(),
      num_priority_dequeue_ttypes_(0),
      standard_dequeue_ttypes_(),
      standard_dequeue_ttypes_zombies_first_(),
      num_standard_dequeue_ttypes_(0),
      zombie_dequeue_ttypes_(),
      num_zombie_dequeue_ttypes_(0),
      drop_expired_(kDefaultDropExpired),
      anti_circ_(AC_TECH_NONE),
      enable_hierarchical_fwding_(kDefaultHierarchicalFwding),
      multi_deq_(kDefaultMultiDeq),
      exclude_infinite_paths_(false),
      enable_mcast_opportunistic_fwding_(
        kDefaultEnableMcastOpportunisticFwding),
      opportunistic_fwding_floor_(kDefaultMcastOpportunisticFwdingFloor),
      avg_queue_delay_(),
      dequeued_bytes_(),
      has_prio_ttypes_(),
      xplot_queue_delay_(kDefaultGenerateQueueDelayGraphs),
      delay_xplot_()
{
  if (!path_ctrls)
  {
    LogF(kClassName, __func__,
        "Array of path controllers is empty.\n");
  }

  if (num_path_ctrls_ > kMaxPathCtrls)
  {
    LogF(kClassName, __func__,
         "Error: number of path controllers %zd cannot exceed max %" PRIu8 ".\n",
         num_path_ctrls_, kMaxPathCtrls);
  }
}

//============================================================================
UberFwdAlg::~UberFwdAlg()
{
  BinIndex  bin_idx = kInvalidBinIndex;

  for (bool bin_idx_valid = bin_map_.GetFirstBinIndex(bin_idx);
       bin_idx_valid;
       bin_idx_valid = bin_map_.GetNextBinIndex(bin_idx))
  {
    if (delay_xplot_[bin_idx])
    {
      delete delay_xplot_[bin_idx];
      delay_xplot_[bin_idx] = NULL;
    }
  }

  initialized_ =  false;
}

//============================================================================
void UberFwdAlg::Initialize(const ConfigInfo& config_info)
{
  //
  // Extract the path controller xmit queue threshold, in bytes.
  //

  xmit_buf_max_thresh_    = config_info.GetUint("Bpf.XmitQueueThreshBytes",
    kDefaultBpfXmitQueueThreshBytes);
  xmit_buf_free_thresh_   = config_info.GetUint("Bpf.XmitBufFreeThreshBytes",
    kDefaultBpfXmitQueueFreeThreshBytes);

  hysteresis_             = config_info.GetUint("Bpf.Alg.HysteresisBytes",
    kBpfAlgHysteresisBytes);

  alg_name_               = config_info.Get("Bpf.Alg.Fwder",
                                            kDefaultBpfwderAlg);

  std::string anti_circ_s = config_info.Get("Bpf.Alg.AntiCirculation",
                                            kDefaultAntiCirculation);

  if (alg_name_ == "LatencyAware")
  {
    base_               = false;
    queue_search_depth_ = config_info.GetUint("Bpf.Alg.QueueSearchDepth",
      kDefaultQueueSearchDepthBytes);

    if (anti_circ_s == "HeuristicDAG")
    {
      anti_circ_  = AC_TECH_HEURISTIC_DAG;
    }
    else if (anti_circ_s == "ConditionalDAG")
    {
      anti_circ_  = AC_TECH_CONDITIONAL_DAG;
    }
  }
  else
  {
    queue_search_depth_ = kQueueSearchDepthBaseBytes;
  }

  drop_expired_ = config_info.GetBool("Bpf.Alg.DropExpired",
    kDefaultDropExpired || base_);

  if (!base_)
  {
    if (anti_circ_ == AC_TECH_HEURISTIC_DAG)
    {
      zombifiable_ttypes_           = ZOMBIFIABLE_TTYPES;
      num_zombifiable_ttypes_       = sizeof(ZOMBIFIABLE_TTYPES) /
        sizeof(*ZOMBIFIABLE_TTYPES);
    }
    else
    {
      zombifiable_ttypes_     = &ZOMBIFIABLE_TTYPES[1];
      num_zombifiable_ttypes_ = 1;
    }

    priority_dequeue_ttypes_      = PRIO_DEQUEUE_TTYPES;
    num_priority_dequeue_ttypes_  = sizeof(PRIO_DEQUEUE_TTYPES) /
      sizeof(*PRIO_DEQUEUE_TTYPES);

    enable_hierarchical_fwding_ = config_info.GetBool(
      "Bpf.Alg.HierarchicalFwding", kDefaultHierarchicalFwding);
  }
  else
  {
    // There can be no hierarchical forwarding with base.
    enable_hierarchical_fwding_ = false;
  }

  standard_dequeue_ttypes_      = STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES;
  num_standard_dequeue_ttypes_  = sizeof(STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES) /
    sizeof(*STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES);

  priority_dequeue_ttypes_zombies_first_  = PRIO_DEQUEUE_TTYPES;
  standard_dequeue_ttypes_zombies_first_  =
    STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES_ZOMBIES_FIRST;

  multi_deq_                    = config_info.GetBool("Bpf.Alg.MultiDeq",
    kDefaultMultiDeq);

  // Initialize the multicast gradient array.
  if (!mcast_gradients_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize multicast gradients "
         "array.\n");
    return;
  }
  mcast_gradients_.Clear(0);

  // Initialize the average queue delay array.
  if (!avg_queue_delay_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize average queue delay "
         "array.\n");
    return;
  }
  avg_queue_delay_.Clear(0);

  // Initialize the dequeued bytes array.
  if (!dequeued_bytes_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize dequeued bytes "
         "array.\n");
    return;
  }
  dequeued_bytes_.Clear(0);

  // Initialize the priority traffic types array.
  if (!has_prio_ttypes_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize priority traffic types "
         "array.\n");
    return;
  }
  has_prio_ttypes_.Clear(false);

  exclude_infinite_paths_       = config_info.GetBool(
    "Bpf.Alg.Mcast.ExcludeInfinitePaths", false);

  enable_mcast_opportunistic_fwding_  = config_info.GetBool(
    "Bpf.Alg.Mcast.EnableOpportunisticFwding",
    kDefaultEnableMcastOpportunisticFwding);

  opportunistic_fwding_floor_   = config_info.GetInt(
    "Bpf.Alg.Mcast.OpportunisticFwdingFloor",
    kDefaultMcastOpportunisticFwdingFloor);

  // Set up the delay plotting array.
  if (!delay_xplot_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize delay plotting "
         "array.\n");
    return;
  }
  delay_xplot_.Clear(NULL);

#ifdef XPLOT
  xplot_queue_delay_  = config_info.GetBool("Bpf.GenerateQueueDelayGraphs",
    kDefaultGenerateQueueDelayGraphs);

  if (xplot_queue_delay_)
  {
    BinIndex  bin_idx = kInvalidBinIndex;

    for (bool bin_idx_valid = bin_map_.GetFirstDstBinIndex(bin_idx);
         bin_idx_valid;
         bin_idx_valid = bin_map_.GetNextDstBinIndex(bin_idx))
    {
      delay_xplot_[bin_idx] = new (std::nothrow) iron::GenXplot();

      if (!delay_xplot_[bin_idx])
      {
        LogE(kClassName, __func__,
             "Failed to allocate GenXplot for queue delays, bin index %"
             PRIBinIndex ".\n", bin_idx);
        continue;
      }

      std::stringstream title;
      title << "queue_delays_" << bin_map_.GetIdToLog(bin_idx) << ".xplot";
      std::stringstream graphname;
      graphname << "Queue Delays for bin " << bin_map_.GetIdToLog(bin_idx);

      if (!delay_xplot_[bin_idx]->Initialize(title.str(), graphname.str()))
      {
        delete delay_xplot_[bin_idx];
        delay_xplot_[bin_idx] = NULL;
      }
      else
      {
        for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
        {
          delay_xplot_[bin_idx]->AddLineToKey(
            static_cast<iron::XPLOT_COLOR>(it), LatencyClass_Name[it]);
        }
      }
    }
  }
#endif  // XPLOT

  // Let bin queue mgrs know whether it needs to support EF traffic (if not,
  // incoming EF packets are rebranded as normal and enqueued accordingly).
  queue_store_->SetSupportEfForAllGroups(!base_);

  LogC(kClassName, __func__,
       "BPF forwarding algorithm configuration:\n");
  LogC(kClassName, __func__,
       "Hysteresis                    : %zd bytes\n", hysteresis_);
  LogC(kClassName, __func__,
       "Bpf.XmitQueueThreshBytes      : %zd bytes\n", xmit_buf_max_thresh_);
  LogC(kClassName, __func__,
       "Bpf.XmitBufFreeThreshBytes    : %zd bytes\n", xmit_buf_free_thresh_);
  LogC(kClassName, __func__,
       "Bpf.Alg.Fwder                 : %s\n", alg_name_.c_str());
  LogC(kClassName, __func__,
       "Bpf.Alg.QueueSearchDepth      : %" PRIu32 " bytes\n", queue_search_depth_);
  LogC(kClassName, __func__,
       "Bpf.Alg.DropExpired           : %s\n", drop_expired_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "Bpf.Alg.Mcast.ExcludeInfinitePaths: %s\n",
       exclude_infinite_paths_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "Bpf.Alg.Mcast.OppFwding       : %s\n",
      enable_mcast_opportunistic_fwding_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "Bpf.Alg.Mcast.OppFwdingFloor  : %zd\n", opportunistic_fwding_floor_);
  LogC(kClassName, __func__,
       "Bpf.Alg.AntiCirculation       : %s\n",
       anti_circ_ == AC_TECH_NONE ? "None" :
       anti_circ_ == AC_TECH_HEURISTIC_DAG ? "Heuristic DAG" :
       "Conditional DAG");
  LogC(kClassName, __func__,
       "Hierarchical forwarding       : %s\n",
       enable_hierarchical_fwding_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "Bpf.Alg.MultiDequeue          : %s\n", multi_deq_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "BPF forwarding algorithm configuration complete.\n");

  initialized_    = true;
}

//============================================================================
void UberFwdAlg::ResetFwdingAlg(const ConfigInfo& config_info)
{
  if (!initialized_)
  {
    return;
  }

  alg_name_               = config_info.Get("Bpf.Alg.Fwder", alg_name_);

  std::string anti_circ_s = config_info.Get("Bpf.Alg.AntiCirculation",
    "NoChange");
  hysteresis_             = config_info.GetUint("Bpf.Alg.HysteresisBytes",
    kBpfAlgHysteresisBytes);

  if (alg_name_ == "LatencyAware")
  {
    base_               = false;
    queue_search_depth_ = config_info.GetUint("Bpf.Alg.QueueSearchDepth",
      queue_search_depth_);

    if (anti_circ_s == "HeuristicDAG")
    {
      anti_circ_  = AC_TECH_HEURISTIC_DAG;
    }
    else if (anti_circ_s == "ConditionalDAG")
    {
      anti_circ_  = AC_TECH_CONDITIONAL_DAG;
    }
  }
  else
  {
    base_               = true;
    queue_search_depth_ = kQueueSearchDepthBaseBytes;
    anti_circ_          = AC_TECH_NONE;
  }

  drop_expired_ = config_info.GetBool("Bpf.Alg.DropExpired",
    drop_expired_ || base_);

  if (!base_)
  {
    if (anti_circ_ == AC_TECH_HEURISTIC_DAG)
    {
      zombifiable_ttypes_           = ZOMBIFIABLE_TTYPES;
      num_zombifiable_ttypes_       = sizeof(ZOMBIFIABLE_TTYPES) /
        sizeof(*ZOMBIFIABLE_TTYPES);
    }
    else
    {
      zombifiable_ttypes_     = &ZOMBIFIABLE_TTYPES[1];
      num_zombifiable_ttypes_ = 1;
    }

    priority_dequeue_ttypes_      = PRIO_DEQUEUE_TTYPES;
    num_priority_dequeue_ttypes_  = sizeof(PRIO_DEQUEUE_TTYPES) /
      sizeof(*PRIO_DEQUEUE_TTYPES);

    enable_hierarchical_fwding_ = config_info.GetBool(
      "Bpf.Alg.HierarchicalFwding", kDefaultHierarchicalFwding);
  }
  else
  {
    zombifiable_ttypes_           = NULL;
    num_zombifiable_ttypes_       = 0;

    priority_dequeue_ttypes_      = NULL;
    num_priority_dequeue_ttypes_  = 0;

    // There can be no hierarchical forwarding with base.
    enable_hierarchical_fwding_ = false;
  }

  standard_dequeue_ttypes_      = STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES;
  num_standard_dequeue_ttypes_  = sizeof(STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES) /
    sizeof(*STANDARD_AND_ZOMBIE_DEQUEUE_TTYPES);

  multi_deq_                    = config_info.GetBool("Bpf.Alg.MultiDeq",
    multi_deq_);

  xplot_queue_delay_            =
    config_info.GetBool("Bpf.GenerateQueueDelayGraphs", xplot_queue_delay_);

  queue_store_->SetSupportEfForAllGroups(!base_);

  LogC(kClassName, __func__,
       "New BPF forwarding algorithm configuration:\n");
  LogC(kClassName, __func__,
       "Bpf.Alg.Fwder                 : %s\n", alg_name_.c_str());
  LogC(kClassName, __func__,
       "Bpf.Alg.QueueSearchDepth      : %" PRIu16 " bytes.\n",
       queue_search_depth_);
  LogC(kClassName, __func__,
       "Bpf.Alg.AntiCirculation       : %s\n",
       anti_circ_ == AC_TECH_NONE ? "None" :
       anti_circ_ == AC_TECH_HEURISTIC_DAG ? "Heuristic DAG" :
       "Conditional DAG");
  LogC(kClassName, __func__,
       "Hierarchical forwarding      : %s\n",
       enable_hierarchical_fwding_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "Bpf.Alg.MultiDequeue          : %s\n", multi_deq_ ? "On" : "Off");
  LogC(kClassName, __func__,
       "BPF forwarding algorithm configuration complete.\n");
}

//============================================================================
uint8_t UberFwdAlg::FindNextTransmission(iron::TxSolution* solutions,
                                         uint8_t max_num_solutions)
{
  uint8_t num_solutions = 0;

  if (!initialized_)
  {
    LogE(kClassName, __func__,
         "Uber BPF alg is not initialized.  Cannot compute next transmission "
         "opportunity.\n");
    return 0;
  }

  // If there are NO packets in any queue, skip all ops.
  // The idea is to avoid computing latency stats and solutions when we have
  // strictly nothing to do.
  if (queue_store_->AreQueuesEmpty())
  {
    LogD(kClassName, __func__,
         "All queues empty, no transmit opportunity to compute.\n");

    BinIndex  idx = 0;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(idx))
    {
      // A packet coming to this queue would experience no queuing delay.  Add
      // to average.
      AddDelayToAverage(0, idx);
    }
    return 0;
  }

  Time  now = Time::Now();

  // Zombify pkts in Critical & Low-Lat queues. In the process, if we find a
  // critical candidate that can be sent over an interface that is currently
  // available send it.
  // Iterate through bins.
  BinQueueMgr*      q_mgr       = NULL;
  Time              ttg;
  ttg.SetInfinite();
  TransmitCandidate candidate;
  candidate.ttg.SetInfinite();

  size_t    min_lat_pc_index  = 0;

  int32_t   path_ctrl_size[kMaxPathCtrls];

  for (uint8_t pci = 0; pci < kMaxPathCtrls; ++pci)
  {
    path_ctrl_size[pci] = -1;
  }

  // Iterate through the bins to clean them up, i.e., Criticalize, Zombify, get
  // some time-to-reach.
  // MCAST TODO: this is just cleaning up unicast bins at the
  // moment. Eventually we probably want to include multicast bins as well.
  BinIndex  dst_bin_idx = 0;

  for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bin_idx);
       !base_ && valid;
       valid = bin_map_.GetNextUcastBinIndex(dst_bin_idx))
  {
    q_mgr = queue_store_->GetBinQueueMgr(dst_bin_idx);

    // Print the BinQueueMgr to see the make up of our queues.  Note this is a
    // little different than the BP values used for gradients (watch out for
    // NPLB).
    q_mgr->Print();

    if (!(q_mgr->ContainsLSNonZombies()))
    {
      // A packet coming to this queue would experience no delay.  Add to
      // average.
      AddDelayToAverage(0, dst_bin_idx);
    }

    if (q_mgr->depth_packets() == 0)
    {
      // There are no packets in the queue (maybe I am
      // the destination), therefore nothing to do for
      // this bin.
      continue;
    }

    uint32_t  latency_us[kMaxPathCtrls];
    memset(latency_us, 0, sizeof(latency_us));
    Time      min_ttr;
    min_ttr.SetInfinite();

    if (anti_circ_ == AC_TECH_HEURISTIC_DAG)
    {
      // Get the per path controller latency, which is same for all packets of
      // this bin.
      // Compute best path controller busy-ness.
      bpfwder_.GetPerPcLatencyToDst(dst_bin_idx, (uint32_t*) latency_us,
                                    false);

      // Check best path controller queue state: free or busy?
      if (GetMinLatencyPath(latency_us, num_path_ctrls_, min_lat_pc_index,
        min_ttr) && (path_ctrl_size[min_lat_pc_index] == -1))
      {
        // Not computed yet.
        PathController* path_ctrl = path_ctrls_[min_lat_pc_index].path_ctrl;

        if (!path_ctrl)
        {
          LogF(kClassName, __func__,
               "Path controller at index %" PRIu8 " is NULL.\n",
               min_lat_pc_index);
          return 0;
        }

        size_t  current_pc_queue_size = 0;

        if (!(path_ctrl->GetXmitQueueSize(current_pc_queue_size)))
        {
          // This path controller does not have a current transmit queue size.
          // Maybe it is still connecting to a peer.  Move on.
          LogD(kClassName, __func__,
               "Path to nbr %" PRIBinId " is currently not accepting "
               "packets.\n", path_ctrl->remote_bin_id());
          current_pc_queue_size = xmit_buf_free_thresh_;
        }

        path_ctrl_size[min_lat_pc_index] = current_pc_queue_size;

        if (WouldLogD(kClassName))
        {
          if (current_pc_queue_size >= xmit_buf_free_thresh_)
          {
            // Path Controller full, will not be able to use this neighbor for
            // this bin.
            LogD(kClassName, __func__,
                 "Path to nbr %" PRIBinId " is full (Q (%zd) > %" PRIu32
                 ") cannot use.\n", path_ctrl->remote_bin_id(),
                 current_pc_queue_size, xmit_buf_free_thresh_);
          }
          else
          {
            LogD(kClassName, __func__,
                 "Lowest lat path to nbr %" PRIBinId " is currently "
                 "available.\n", path_ctrl->remote_bin_id());
          }
        }
      }
    } // End heuristic_dag only.

    // Go through the EF and CRITICAL queues to zombify.
    for (uint8_t ttype_i = 0; ttype_i < num_zombifiable_ttypes_; ++ttype_i)
    {
      LatencyClass  ttype = zombifiable_ttypes_[ttype_i];

      uint32_t  num_available_bytes = 0;
      Packet*   prev_pkt            = NULL;

      q_mgr->PrepareIteration(ttype);
      PacketQueue::QueueWalkState saved_it;

      // Search inside the queue.
      while (num_available_bytes < queue_search_depth_)
      {
        Packet* pkt = q_mgr->PeekNext(ttype, saved_it);

        if (!pkt || (prev_pkt == pkt))
        {
          LogD(kClassName, __func__,
               "No pkt for bin %s for traffic type %s beyond.\n",
               bin_map_.GetIdToLog(dst_bin_idx).c_str(),
               LatencyClass_Name[ttype].c_str());
          break;
        }

        prev_pkt  = pkt;

        if (anti_circ_ == AC_TECH_CONDITIONAL_DAG)
        {
          // Get the per path controller latency, which is same for all packets
          // of this bin.
          // Compute best path controller busy-ness.
          bpfwder_.GetPerPcLatencyToDst(dst_bin_idx, (uint32_t*) latency_us,
            false, pkt);

          // Check best path controller queue state: free or busy?
          GetMinLatencyPath(latency_us, num_path_ctrls_, min_lat_pc_index,
            min_ttr);
        }

        // Figure out if this packet can still be delivered.
        // Get time to go from packet.
        if (pkt->time_to_go_valid())
        {
          ttg = pkt->GetTimeToGo() - (now - pkt->recv_time());
        }

        if (ttg < min_ttr)
        {
          // Packet cannot make it on any interface.
          LogD(kClassName, __func__,
               "Pkt %p with ttg %s cannot be delivered in time on any "
               "interface (min_ttr %s). Drop.\n",
               pkt, ttg.ToString().c_str(),
               min_ttr.ToString().c_str());
          pkt = q_mgr->DequeueAtCurrentIterator(ttype);

          if (pkt && pkt->HasQueuingDelay())
          {
            AddDelayToAverage(Time::GetNowInUsec() -
              pkt->recv_time().GetTimeInUsec(), dst_bin_idx);
          }

          uint16_t  packet_len  = pkt->virtual_length();
          if (drop_expired_ || !q_mgr->ZombifyPacket(pkt))
          {
            bpfwder_.AddDroppedBytes(dst_bin_idx, packet_len);
            TRACK_EXPECTED_DROP(kClassName, packet_pool_);
            LogD(kClassName, __func__,
                 "Dropped expired packet %p or Zombification failed.\n", pkt);
            packet_pool_.Recycle(pkt);
          }
          continue;
        }

        if (anti_circ_ == AC_TECH_HEURISTIC_DAG)
        {
          // Anti-circulation technique is heuristic_dag, deal with critical.
          if ((ttype == CRITICAL_LATENCY) && (ttg < candidate.ttg) &&
            (path_ctrl_size[min_lat_pc_index] <
              static_cast<int32_t>(xmit_buf_max_thresh_)))
          {
            // Critical packet has tighter deadline and can go on non-busy path
            // controller.
            candidate.is_valid          = true;
            candidate.pkt               = pkt;
            candidate.bin_idx           = dst_bin_idx;
            candidate.id_to_log         = bin_map_.GetIdToLog(dst_bin_idx);
            candidate.ttg               = ttg;
            candidate.ttr               = min_ttr;
            candidate.path_ctrl_index   = min_lat_pc_index;
            candidate.dequeue_loc       = saved_it;
            candidate.q_mgr             = q_mgr;
            LogD(kClassName, __func__,
                 "Critical packet %p with ttg %s on available path "
                 "controller %" PRIu8 " overtakes candidates.\n",
                 pkt, ttg.ToString().c_str(), min_lat_pc_index);
          }

          if ((ttype == LOW_LATENCY) &&
            IsHistoryConstrained(pkt, ttg, latency_us, num_path_ctrls_))
          {
            // EF packet is history-constrained and not yet in critical.
            // But this should not prevent us from assessing it as a candidate.
            pkt = q_mgr->DequeueAtCurrentIterator(ttype);

            if (!q_mgr->CriticalizePacket(pkt))
            {
              if (pkt->HasQueuingDelay())
              {
                AddDelayToAverage(Time::GetNowInUsec() -
                  pkt->recv_time().GetTimeInUsec(), dst_bin_idx);
              }

              TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
              LogD(kClassName, __func__,
                   "Dropped packet %p (Criticialization failed).\n", pkt);
              packet_pool_.Recycle(pkt);
            }
            else
            {
              if ((ttg < candidate.ttg) &&
                (path_ctrl_size[min_lat_pc_index] <
                  static_cast<int32_t>(xmit_buf_max_thresh_)))
              {
                // This pkt has a tighter deadline.
                candidate.is_valid          = true;
                candidate.pkt               = pkt;
                candidate.bin_idx           = dst_bin_idx;
                candidate.q_mgr             = q_mgr;
                candidate.id_to_log         = bin_map_.GetIdToLog(dst_bin_idx);
                candidate.ttg               = ttg;
                candidate.ttr               = min_ttr;
                candidate.path_ctrl_index   = min_lat_pc_index;
                if (!q_mgr->GetIterator(CRITICAL_LATENCY,
                  pkt, candidate.dequeue_loc))
                {
                  candidate.pkt = NULL;
                  candidate.is_valid = false;
                }
                LogD(kClassName, __func__,
                     "Low-latency packet %p with ttg %s on available path "
                     "controller %" PRIu8 " overtakes candidates.\n",
                     pkt, ttg.ToString().c_str(), min_lat_pc_index);
              }
            }
            continue;
          }
        } // End heuristic_dag condition.

        num_available_bytes  += pkt->virtual_length();
      } // End queue search.
    } // End Zombifiable iteration.
  } // End bin iteration clean up. MCAST TODO unicast iteration only.
  // END Zombification and Criticalization.

  // Now print all mcast bins, so we have a full list in the log.
  if (WouldLogD(kClassName))
  {
    dst_bin_idx = 0;

    for (bool valid = bin_map_.GetFirstMcastBinIndex(dst_bin_idx);
         valid;
         valid = bin_map_.GetNextMcastBinIndex(dst_bin_idx))
    {
      queue_store_->GetBinQueueMgr(dst_bin_idx)->Print();
    }
  }

  // If there is a critical candidate, send it.
  // MCAST TODO if there is one, we know it's unicast right now.
  if (candidate.is_valid && candidate.pkt)
  {
    solutions[0].pkt              = candidate.q_mgr->DequeueAtIterator(
      CRITICAL_LATENCY, candidate.dequeue_loc);
    solutions[0].bin_idx          = candidate.bin_idx;
    solutions[0].path_ctrl_index  = candidate.path_ctrl_index;;
    num_solutions                 = 1;

    if (solutions[0].pkt->HasQueuingDelay())
    {
      AddDelayToAverage(Time::GetNowInUsec() -
        solutions[0].pkt->recv_time().GetTimeInUsec(), solutions[0].bin_idx);
    }

    LogD(kClassName, __func__,
         "Selected immediate release of candidate %s.\n",
         candidate.ToString().c_str());
    return num_solutions;
  } // END sending critical candidate.

  // Only packets from the Critical queue can be selected without considering
  // gradients. Selection from all other queues requires using the
  // backpressure gradient.

  // Keep the gradients ordered.
  OrderedList<Gradient, int64_t>  ls_gradients(iron::LIST_DECREASING);
  OrderedList<Gradient, int64_t>* ef_gradients = &ls_gradients;
  OrderedList<Gradient, int64_t>  gradients(iron::LIST_DECREASING);

  // Get the queue depth of the queues for the priority types.  If zero, do not
  // attempt to find a packet for the gradient (during LS processing).
  has_prio_ttypes_.Clear(false);

  // First compute the backpressure gradient.
  for (size_t pc_index = 0; pc_index < num_path_ctrls_;
    ++pc_index)
  {
    PathController* path_ctrl = path_ctrls_[pc_index].path_ctrl;

    if (!path_ctrl)
    {
      continue;
    }

    if (!path_ctrl->ready())
    {
      LogD(kClassName, __func__,
           "Not considering unready path ctrl %" PRIu8 " (no QLAM received yet)."
           "\n",
           pc_index);
      continue;
    }

    // Check Path Controller queue state: free or busy?
    if (path_ctrl_size[pc_index] == -1)
    {
      size_t  current_pc_queue_size = 0;

      if (!(path_ctrl->GetXmitQueueSize(current_pc_queue_size)))
      {
        // This path controller does not have a current transmit queue size.
        // Maybe it is still connecting to a peer.  Move on.
        LogD(kClassName, __func__,
             "Path to nbr %" PRIBinId " currently has no queue.\n",
             path_ctrl->remote_bin_id());
        continue;
      }

      path_ctrl_size[pc_index] = current_pc_queue_size;

      if (WouldLogD(kClassName))
      {
        if (current_pc_queue_size >= static_cast<size_t>(xmit_buf_free_thresh_))
        {
          // Path Controller full, will not be able to use this neighbor for
          // this bin.
          LogD(kClassName, __func__,
               "Path to nbr %" PRIBinId " is full (Q (%zd) > %" PRIu32
               "B) cannot use.\n", path_ctrl->remote_bin_id(),
               current_pc_queue_size, xmit_buf_free_thresh_);
        }
        else
        {
          LogD(kClassName, __func__,
               "Path to nbr %" PRIBinId " is available.\n",
               path_ctrl->remote_bin_id());
        }
      }
    }

    if (path_ctrl_size[pc_index] >= static_cast<int32_t>(xmit_buf_free_thresh_))
    {
      // The path controller is busy.
      LogD(kClassName, __func__,
           "Skip busy path ctrl %" PRIu8 " to nbr %" PRIBinId ".\n",
           pc_index, path_ctrl->remote_bin_id());
      continue;
    }

    // Iterate through bins and compute the differential for each, including
    // unicast and multicast destination bins.
    BinIndex  dst_bin_idx = kInvalidBinIndex;

    for (bool dst_bin_idx_valid = bin_map_.GetFirstDstBinIndex(dst_bin_idx);
         dst_bin_idx_valid;
         dst_bin_idx_valid = bin_map_.GetNextDstBinIndex(dst_bin_idx))
    {
      LogD(kClassName, __func__,
           "=========== Nbr %" PRIBinId " (%" PRIBinId "), Dst Bin %s "
           "================\n",
           bin_map_.GetPhyBinId(path_ctrl->remote_bin_idx()),
           path_ctrl->remote_bin_id(),
           bin_map_.GetIdToLog(dst_bin_idx).c_str());

      if (!base_)
      {
        has_prio_ttypes_[dst_bin_idx]  = queue_store_->GetBinQueueMgr(
          dst_bin_idx)->ContainsPacketsWithTtypes(
            priority_dequeue_ttypes_, num_priority_dequeue_ttypes_);
      }
      if (queue_store_->GetBinQueueMgr(dst_bin_idx)->depth_packets() == 0)
      {
        LogD(kClassName, __func__,
             "My queue to Bin %s is empty, go on to next bin.\n",
             bin_map_.GetIdToLog(dst_bin_idx).c_str());
        // There are no packets in the queue (maybe I am the destination),
        // therefore nothing to do for this bin.
        continue;
      }

      // Get neighbor queue depths.
      QueueDepths* nbr_queue_depth  = queue_store_->GetBinQueueMgr(
        dst_bin_idx)->GetNbrQueueDepths(path_ctrl->remote_bin_idx());
      // NULL check done when computing gradients.

      // Get neighbor virtual queue depths.
      QueueDepths* nbr_v_queue_depth  =
        queue_store_->PeekNbrVirtQueueDepths(path_ctrl->remote_bin_idx());

      Gradient gradient;
      gradient.bin_idx             = dst_bin_idx;
      gradient.path_ctrl_index     = pc_index;
      gradient.is_dst              = false;
      gradient.dst_vec             = 0;

      Gradient ls_gradient;
      ls_gradient.bin_idx          = dst_bin_idx;
      ls_gradient.path_ctrl_index  = pc_index;
      ls_gradient.is_dst           = false;
      ls_gradient.dst_vec          = 0;

      // Note that GetVirtQueueDepths returns the reference to the virtual
      // QueueDepths object, therefore we need not check its return for NULL.
      if (bin_map_.IsMcastBinIndex(gradient.bin_idx))
      {
        // This function will return the per-destination gradients, which are
        // only used after we pick the multicast group and path controller.
        ComputeMulticastGradient(path_ctrl,
          queue_store_->GetQueueDepthsForBpf(dst_bin_idx),
          nbr_queue_depth,
          queue_store_->GetVirtQueueDepths(),
          nbr_v_queue_depth,
          gradient, ls_gradient);
      }
      else
      {
        ComputeOneBinGradient(dst_bin_idx, path_ctrl,
                              queue_store_->GetQueueDepthsForBpf(dst_bin_idx),
                              nbr_queue_depth,
                              queue_store_->GetVirtQueueDepths(),
                              nbr_v_queue_depth,
                              gradient.is_dst,
                              gradient.value, ls_gradient.value);
        if (gradient.value <=
            (gradient.is_dst ? 0 : static_cast<int64_t>(hysteresis_)))
        {
          LogD(kClassName, __func__,
               "Ucast gradient %" PRId64 "B is below hysteresis, setting to "
               "0B.\n",
               gradient.value);
          gradient.value  = 0;
        }
        if (ls_gradient.value <= static_cast<int64_t>(hysteresis_))
        {
          LogD(kClassName, __func__,
               "Ucast LS gradient %" PRId64 "B is below hysteresis, setting to "
               "0B.\n",
               ls_gradient.value);
          ls_gradient.value  = 0;
        }
        ls_gradient.is_dst = gradient.is_dst;
      }

      // Gradient value is given +1 if goes to destination directly to give
      // it preference.
      if (gradient.value > 0)
      {
        gradients.Push(gradient, gradient.value + (gradient.is_dst? 1 : 0));
        LogD(kClassName, __func__,
             "Found %s gradient %" PRId64 "B on (bin %s, pc %" PRIu8 ") %s"
             " 0x%X.\n",
             (gradient.dst_vec == 0 ? "unicast" : "multicast"),
             gradient.value, bin_map_.GetIdToLog(dst_bin_idx).c_str(),
             pc_index,
             gradient.is_dst ? "to dst" : "not to dst",
             gradient.dst_vec);
      }
      else
      {
        LogD(kClassName, __func__,
             "%s gradient %dB is negative or below hysteresis %" PRIu32 "B.\n",
             (gradient.dst_vec == 0 ? "Unicast" : "Multicast"),
             gradient.value, hysteresis_);
      }

      // Gradient value is given +1 if goes to destination directly to give it
      // preference.
      if (ls_gradient.value > 0)
      {
        ls_gradients.Push(ls_gradient, ls_gradient.value +
                          (ls_gradient.is_dst? 1 : 0));
        LogD(kClassName, __func__,
             "Found LS gradient %" PRId64 "B on (bin %s, pc %" PRIu8 ") %s"
             " 0x%X.\n",
             ls_gradient.value, bin_map_.GetIdToLog(dst_bin_idx).c_str(),
             pc_index,
             ls_gradient.is_dst ? "to dst" : "not to dst",
             ls_gradient.dst_vec);
      }
      else
      {
        LogD(kClassName, __func__,
             "LS gradient %dB is negative or below hysteresis %" PRIu32 "B.\n",
             ls_gradient.value, hysteresis_);
      }
    } // End bin iterations.
  } // END gradient computations.

  // Provide BinQueueMgr gradient info to help with addressing starvation
  queue_store_->ProcessGradientUpdate(ls_gradients, gradients);

  // *** Low-Latency Solution ***
  // Now, try to find a solution in the low-latency traffic first.
  OrderedList<TransmitCandidate, Time>      candidates(iron::LIST_INCREASING);
  OrderedList<Gradient, int64_t>::WalkState grad_ws;
  Gradient                                  gradient;
  int32_t                                   max_bytes         = 1;
  uint32_t                                  cand_bytes_found  = 0;

  if (!enable_hierarchical_fwding_)
  {
    ef_gradients  = &gradients;
  }

  for (uint8_t ttype_i = 0;
    ttype_i < num_priority_dequeue_ttypes_;
    ++ttype_i)
  {
    LatencyClass  ttype = priority_dequeue_ttypes_[ttype_i];

    // TODO: If no packet in the EF class, skip.

    grad_ws.PrepareForWalk();

    while (ef_gradients->GetNextItem(grad_ws, gradient))
    {
      if (!path_ctrls_[gradient.path_ctrl_index].path_ctrl ||
          !has_prio_ttypes_[gradient.bin_idx])
      {
        LogD(kClassName, __func__,
             "No priority ttype in this queue, skipping gradient %" PRIu32 "B.\n",
             gradient.value);
        continue;
      }

      if ((gradient.value <= 0) || (!candidates.Empty()))
      {
        // No positive gradient, or we already have candidates.
        break;
      }

      // TODO: Can we call this once at the start of the function, instead of
      // calling it for each latency class?
      max_bytes = 1;

      LogD(kClassName, __func__,
           "Exploring gradient %" PRId64 "B to bin_id %s on path ctrl %"
           PRIu8 " to nbr %" PRIBinId " / %" PRIBinId " (%s).\n",
           gradient.value,
           bin_map_.GetIdToLog(gradient.bin_idx).c_str(),
           gradient.path_ctrl_index,
           bin_map_.GetPhyBinId(
             path_ctrls_[gradient.path_ctrl_index].path_ctrl->remote_bin_idx()),
           path_ctrls_[gradient.path_ctrl_index].path_ctrl->remote_bin_id(),
           gradient.is_dst ? "is_dst" : "not dst");

      int32_t num_bytes_left_on_pc =
        static_cast<int32_t>(xmit_buf_max_thresh_) -
          path_ctrl_size[gradient.path_ctrl_index];

      if (multi_deq_)
      {
        // Note: The previous approach consisted in allowing to dequeue as least as
        // many bytes as the gap between the two largest gradients, and only 1B
        // when they were equal.  This was observed to be too conservative and led
        // to self-limiting low dequeue-rates.
        //
        // We now attempt to fill the path controller's transmit buffer.
        max_bytes = num_bytes_left_on_pc;
      }

      LogD(kClassName, __func__,
           "Allow %" PRId32 "B max to be dequeued at once."
           "\n",
           max_bytes);

      // For zombie ttypes, only return enough bytes to make up the difference
      // between what we've found so far and what we need. Otherwise, it's ok
      // to get max_bytes of real packets for each gradient and sort it out
      // later.
      uint32_t to_find = static_cast<uint32_t>(max_bytes);
      if (Packet::IsZombie(ttype))
      {
        if (to_find > cand_bytes_found)
        {
          to_find -= cand_bytes_found;
        }
        else
        {
          break;
        }
      }
      if (!bin_map_.IsMcastBinIndex(gradient.bin_idx))
      {
        cand_bytes_found += FindUcastPacketsForGradient(
          gradient, ttype, now, !base_, candidates, to_find);
      }
      else if (ttype_i == 0)
      {
        const LatencyClass* dequeue_order = NULL;
        if (gradient.is_zombie == true)
        {
         // The zombie gradient is larger, so find zombie solutions first.
          dequeue_order = priority_dequeue_ttypes_zombies_first_;
        }
        else
        {
          dequeue_order = priority_dequeue_ttypes_;
        }

        for (uint8_t ttype_j = 0;
             ttype_j < num_priority_dequeue_ttypes_; ++ttype_j)
        {
            LatencyClass  mcast_ttype = dequeue_order[ttype_j];
            cand_bytes_found += FindMcastPacketsForGradient(
              gradient, mcast_ttype, candidates, to_find);
        }
      }
    }

    // We have explored all packets that could match this gradient.
    TransmitCandidate                               selected_candidate;
    OrderedList<TransmitCandidate, Time>::WalkState cand_ws;
    cand_ws.PrepareForWalk();

    if (candidates.size() > 0)
    {
      while (candidates.GetNextItem(cand_ws, selected_candidate))
      {
        if (enable_mcast_opportunistic_fwding_)
        {
          McastOpportunisticForwarding(selected_candidate);
        }
        // We have at least one packet and the next gradient is strictly smaller.
        LogD(kClassName, __func__,
             "Selected candidate #%" PRIu8 " %s.\n",
             num_solutions + 1,
             selected_candidate.ToString().c_str());
        if (!selected_candidate.is_valid)
        {
          LogE(kClassName, __func__,
               "Invalid candidate in candidates list.\n");
          continue;
        }
        if (selected_candidate.pkt)
        {
          solutions[num_solutions].pkt  = queue_store_->GetBinQueueMgr(
            selected_candidate.bin_idx)->DequeueAtIterator(
              selected_candidate.pkt->GetLatencyClass(),
              selected_candidate.dequeue_loc, selected_candidate.dst_vec);

          if (solutions[num_solutions].pkt->HasQueuingDelay())
          {
            AddDelayToAverage(Time::GetNowInUsec() -
              solutions[num_solutions].pkt->recv_time().GetTimeInUsec(),
              selected_candidate.bin_idx);
          }
        }
        else
        {
          // This is a packetless Zombie.
          solutions[num_solutions].pkt =
            (selected_candidate.q_mgr)->Dequeue(
              selected_candidate.latency_class,
              selected_candidate.virtual_len,
              selected_candidate.dst_vec);

          if (!solutions[num_solutions].pkt)
          {
            if (selected_candidate.dst_vec == 0)
            {
              LogE(kClassName, __func__,
                   "Failed to dequeue %s packet of size %zdB from queue of %zdB.\n",
                   LatencyClass_Name[selected_candidate.latency_class].c_str(),
                   selected_candidate.virtual_len,
                   (selected_candidate.q_mgr)->GetNextDequeueSize(
                     selected_candidate.latency_class));
            }
            else
            {
              LogE(kClassName, __func__,
                   "Failed to dequeue %s packet of size %zdB from "
                   "multicast zombie queue.\n",
                   LatencyClass_Name[selected_candidate.latency_class].c_str(),
                   selected_candidate.virtual_len);
            }
            break;
          }
        }

        if (solutions[num_solutions].pkt == NULL)
        {
          LogF(kClassName, __func__, "Error dequeuing a packet.\n");
          continue;
        }

        solutions[num_solutions].bin_idx          = selected_candidate.bin_idx;
        solutions[num_solutions].path_ctrl_index  = selected_candidate.path_ctrl_index;

        path_ctrl_size[selected_candidate.path_ctrl_index] +=
          selected_candidate.virtual_len;
        max_bytes                                          -=
          selected_candidate.virtual_len;

        ++num_solutions;

        if (!multi_deq_ ||
          (path_ctrl_size[solutions[num_solutions - 1].path_ctrl_index] >
            static_cast<int32_t>(xmit_buf_max_thresh_)) ||
          (num_solutions >= max_num_solutions))
        {
          LogD(kClassName, __func__,
               "End packet selections%s%s%s.\n",
               multi_deq_ ? "" : "; no multi-dequeue",
               path_ctrl_size[solutions[num_solutions - 1].path_ctrl_index] >
                static_cast<int32_t>(xmit_buf_max_thresh_) ? "; path ctrl full" : "",
               num_solutions >= max_num_solutions ?
                "; max num solutions reached" : "");
          break;
        }
      }
      // Return for now.  TODO: Go back in, and explore the following gradients
      // for more solutions.
      return num_solutions;
    }
    else if (cand_bytes_found > 0)
    {
      // We found and dropped a packetless zombie candidate.
      return num_solutions;
    }
  } // END finding a packet for the low-latency traffic.
  // *** END Low-Latency Solution ***

  LogD(kClassName, __func__,
       "Did not find candidate for priority dequeue traffic types.\n");

  candidates.Clear();

  grad_ws.PrepareForWalk();
  max_bytes = 1;

  // *** Regular Solution ***
  // Now treat regular and Zombie packets.
  while (gradients.GetNextItem(grad_ws, gradient))
  {
    if (!path_ctrls_[gradient.path_ctrl_index].path_ctrl)
    {
      continue;
    }

    if ((gradient.value <= 0) || (!candidates.Empty()))
    {
      // No positive gradient, or gradient is smaller.  Nothing from here on.
      break;
    }

    max_bytes = 1;

    LogD(kClassName, __func__,
         "Exploring gradient %" PRId64 "B to bin_id %s on path ctrl %"
         PRIu8 " to nbr %" PRIBinId " / %" PRIBinId " (%s) for dsts 0x%X.\n",
         gradient.value,
         bin_map_.GetIdToLog(gradient.bin_idx).c_str(),
         gradient.path_ctrl_index,
         bin_map_.GetPhyBinId(
           path_ctrls_[gradient.path_ctrl_index].path_ctrl->remote_bin_idx()),
         path_ctrls_[gradient.path_ctrl_index].path_ctrl->remote_bin_id(),
         gradient.is_dst ? "is_dst" : "not dst",
         gradient.dst_vec);

    int32_t num_bytes_left_on_pc =
      static_cast<int32_t>(xmit_buf_max_thresh_) -
        path_ctrl_size[gradient.path_ctrl_index];

    if (multi_deq_)
    {
      // Note: The previous approach consisted in allowing to dequeue as least as
      // many bytes as the gap between the two largest gradients, and only 1B
      // when they were equal.  This was observed to be too conservative and led
      // to self-limiting low dequeue-rates.
      //
      // We now attempt to fill the path controller's transmit buffer.
      max_bytes = num_bytes_left_on_pc;
    }

    LogD(kClassName, __func__,
         "Allow %" PRId32 "B max to be dequeued at once."
         "\n",
         max_bytes);

    // Figure out if a bin already has a normal latency solution.  If so, then
    // we should not look at Zombie packets for this bin.  If this solution has
    // been investigated and then replaced, we still would have no reason to
    // look at the Zombie packet.
    // TODO: Should this be here, or can we include both normal and zombie
    // candidates if they fit?

    LatencyClass  ttype;
    for (uint8_t ttype_i = 0;
      ttype_i < num_standard_dequeue_ttypes_; ++ttype_i)
    {
      if ((!bin_map_.IsMcastBinIndex(gradient.bin_idx)) ||
          (gradient.is_zombie == false))
      {
        ttype = standard_dequeue_ttypes_[ttype_i];
      }
      else
      {
        ttype = standard_dequeue_ttypes_zombies_first_[ttype_i];
      }
      // For zombie ttypes, only return enough bytes to make up the difference
      // between what we've found so far and what we need. Otherwise, it's ok
      // to get max_bytes of real packets for each gradient and sort it out
      // later.
      uint32_t to_find = static_cast<uint32_t>(max_bytes);
      if (Packet::IsZombie(ttype))
      {
        if (to_find > cand_bytes_found)
        {
          to_find -= cand_bytes_found;
        }
        else
        {
          break;
        }
      }
      if (!bin_map_.IsMcastBinIndex(gradient.bin_idx))
      {
        cand_bytes_found += FindUcastPacketsForGradient(
          gradient, ttype, now, false, candidates, to_find);
      }
      else
      {
        cand_bytes_found += FindMcastPacketsForGradient(
          gradient, ttype, candidates, to_find);
      }
    }

    if (cand_bytes_found > 0)
    {
      // For now, don't combine multiple gradients (i.e., multiple
      // destinations or path controllers) in the same set of results.
      // TODO: consider removing this condition later, but we'll need some
      // extra conditions to evaluate max_bytes with consideration for how
      // many packets we already picked for a particular path controller.
      break;
    }

    // Otherwise, look at the case when the next gradient is equal.
  } // END treating normal and Zombie packets.
  // *** END Regular Solution ***

  // We have explored all packets that could match this gradient.
  if (candidates.size() > 0)
  {
    TransmitCandidate                               selected_candidate;
    OrderedList<TransmitCandidate, Time>::WalkState cand_ws;
    cand_ws.PrepareForWalk();

    while (candidates.GetNextItem(cand_ws, selected_candidate))
    {
      // We have at least one packet and the next gradient is strictly smaller.
      LogD(kClassName, __func__,
           "Selected candidate %s.\n",
           selected_candidate.ToString().c_str());
      if (!selected_candidate.is_valid)
      {
        LogE(kClassName, __func__, "Invalid candidate in candidates list.\n");
        continue;
      }
      if (selected_candidate.pkt)
      {
        if (enable_mcast_opportunistic_fwding_)
        {
          McastOpportunisticForwarding(selected_candidate);
        }
        solutions[num_solutions].pkt  =
          (selected_candidate.q_mgr)->DequeueAtIterator(
            selected_candidate.pkt->GetLatencyClass(),
            selected_candidate.dequeue_loc, selected_candidate.dst_vec);
        if (!solutions[num_solutions].pkt)
        {
          LogF(kClassName, __func__, "DequeueAtIterator returned null.\n");
        }
        if (bin_map_.IsMcastBinIndex(selected_candidate.bin_idx))
        {
          if (solutions[num_solutions].pkt != selected_candidate.pkt)
          {
            // If the packet is multicast and the dequeue gave us a different
            // packet than the selected candidate, it means that it was cloned.
            // Switch to the clone so that we point to proper destination bit
            // vector.
            selected_candidate.pkt  = solutions[num_solutions].pkt;
          }
          LogD(kClassName, __func__,
               "Dequeued mcast packet %s for bin %s: %s\n",
               solutions[num_solutions].pkt->GetPacketMetadataString().c_str(),
               selected_candidate.id_to_log.c_str(),
               selected_candidate.ToString().c_str());
        }
        if (solutions[num_solutions].pkt->HasQueuingDelay())
        {
          // HasQueuingDelay is always false because this is normal
          // (non-packetless) traffic.
          AddDelayToAverage(Time::GetNowInUsec() -
            solutions[num_solutions].pkt->recv_time().GetTimeInUsec(),
            selected_candidate.bin_idx);
        }
      }
      else
      {
        // This is a packetless Zombie.
        solutions[num_solutions].pkt = (selected_candidate.q_mgr)->Dequeue(
            selected_candidate.latency_class,
            selected_candidate.virtual_len,
            selected_candidate.dst_vec);

        if (!solutions[num_solutions].pkt)
        {
          if (selected_candidate.dst_vec == 0)
          {
            LogE(kClassName, __func__,
                 "Failed to dequeue %s packet of size %zdB from queue of %zdB.\n",
                 LatencyClass_Name[selected_candidate.latency_class].c_str(),
                 selected_candidate.virtual_len,
                 (selected_candidate.q_mgr)->GetNextDequeueSize(
                   selected_candidate.latency_class));
          }
          else
          {
            LogE(kClassName, __func__,
                 "Failed to dequeue %s packet of size %zdB from "
                 "multicast zombie queue.\n",
                 LatencyClass_Name[selected_candidate.latency_class].c_str(),
                 selected_candidate.virtual_len);
          }
        }
      }
      if (solutions[num_solutions].pkt == NULL)
      {
        LogF(kClassName, __func__, "Error dequeuing a packet.\n");
        continue;
      }

      solutions[num_solutions].bin_idx          = selected_candidate.bin_idx;
      solutions[num_solutions].path_ctrl_index  =
        selected_candidate.path_ctrl_index;

      path_ctrl_size[selected_candidate.path_ctrl_index] +=
        selected_candidate.virtual_len;
      max_bytes                                          -=
        selected_candidate.virtual_len;

      ++num_solutions;

      if (!multi_deq_ ||
        (path_ctrl_size[solutions[num_solutions - 1].path_ctrl_index] >
          static_cast<int32_t>(xmit_buf_max_thresh_)) ||
        (max_bytes <= 0) ||
        (num_solutions >= max_num_solutions))
      {
        LogD(kClassName, __func__,
             "End packet selections:%s%s%s%s.\n",
             multi_deq_ ? "" : " no multi-dequeue",
             path_ctrl_size[solutions[num_solutions - 1].path_ctrl_index] >
              static_cast<int32_t>(xmit_buf_max_thresh_) ? "; path ctrl full"
              : "",
             max_bytes <= 0 ? "; num bytes reached" : "",
             num_solutions >= max_num_solutions ?
              "; max num solutions reached" : "");
        break;
      }
    }
    return num_solutions;
  }

  LogD(kClassName, __func__,
       "Found no solution, nothing dequeued.\n");
  return 0;
}

//============================================================================
void UberFwdAlg::ComputeOneBinGradient(
  BinIndex bin, PathController* path_ctrl,
  QueueDepths* my_qd_for_bin, QueueDepths* nbr_qd_for_bin,
  QueueDepths* my_v_queue_depth, QueueDepths* nbr_v_queue_depth,
  bool& is_dst, int64_t& differential, int64_t& ls_differential)
{
  uint32_t  my_qd           = my_qd_for_bin->GetBinDepthByIdx(bin);
  uint32_t  my_ls           = my_qd_for_bin->GetBinDepthByIdx(bin, LOW_LATENCY);
  uint32_t  my_v_queue_len  = 0;
  uint32_t  nbr_v_queue_len = 0;

  if (my_v_queue_depth)
  {
    my_v_queue_len  = my_v_queue_depth->GetBinDepthByIdx(bin);
  }

  // The virtual queue length may be set to UINT32_MAX, which identifies
  // an unreachable node (i.e., it requires an "infinite" number of hops)
  // If so, set the differential to zero so that this destination isn't
  // selected

  if (my_v_queue_len == UINT32_MAX)
  {
    differential    = 0;
    ls_differential = 0;
  }
  else
  {
    differential    = my_qd + my_v_queue_len;
    ls_differential = my_ls + my_v_queue_len;
  }

  LogD(kClassName, __func__,
       "My queue depth to %s is %" PRIu32 "B (%" PRIu32 "B LS), virtual queue "
       "depth %" PRIu32 "B.\n",
       bin_map_.GetIdToLog(bin).c_str(), my_qd, my_ls, my_v_queue_len);

  if (!nbr_qd_for_bin)
  {
    LogF(kClassName, __func__,
         "No queue depth for bin %s on path to %" PRIBinId ".\n",
         bin_map_.GetIdToLog(bin).c_str(),
         path_ctrl->remote_bin_id());
    return;
  }

  // Check if the neighbor happens to be the bin destination: in that
  // case, this neighbor has an implicit queue size of 0 on that bin.
  // TODO: use path ctrl index to get path ctrl
  if (path_ctrl->remote_bin_idx() == bin)
  {
    is_dst    = true;
    // This neighbor is the bin's destination! Woohoo it will take it all!
    LogD(kClassName, __func__,
         "Nbr %" PRIBinId " is the bin Id %s destination - Q len is 0.\n",
         path_ctrl->remote_bin_id(), bin_map_.GetIdToLog(bin).c_str());
  }
  else
  {
    is_dst = false;
    uint32_t nbr_qd  = nbr_qd_for_bin->GetBinDepthByIdx(bin, NORMAL_LATENCY);
    uint32_t nbr_ls  = nbr_qd_for_bin->GetBinDepthByIdx(bin, LOW_LATENCY);
    if (nbr_v_queue_depth)
    {
      nbr_v_queue_len = nbr_v_queue_depth->GetBinDepthByIdx(bin);
    }
    LogD(kClassName, __func__,
         "Nbr has a bin %s depth of %" PRIu32 "B (%" PRIu32 "B LS), virtual queue"
         " depth %" PRIu32 "B.\n",
         bin_map_.GetIdToLog(bin).c_str(), nbr_qd, nbr_ls, nbr_v_queue_len);

    // The virtual queue length may be set to UINT32_MAX, which identifies
    // a "deadend" that we don't want to use for this destination
    // If so, set the differential to a large negative number.
    if (nbr_v_queue_len == UINT32_MAX)
    {
      differential    = INT32_MIN;
      ls_differential = INT32_MIN;
    }
    else
    {
      differential    -= nbr_qd + nbr_v_queue_len;
      ls_differential -= nbr_ls + nbr_v_queue_len;
    }
  }

  LogD(kClassName, __func__, "Gradient differential is %" PRId64
       "B, LS differential is %" PRId64 "B.\n", differential,
       ls_differential);
}

//============================================================================
void UberFwdAlg::ComputeMulticastGradient(
  PathController* path_ctrl,
  QueueDepths* my_qd_for_bin, QueueDepths* nbr_qd_for_bin,
  QueueDepths* my_v_queue_depth, QueueDepths* nbr_v_queue_depth,
  Gradient& gradient, Gradient& ls_gradient)
{
  DstVec  UNUSED(dst_vec) = bin_map_.GetMcastDst(gradient.bin_idx);
  LogD(kClassName, __func__, "========================================\n");
  LogD(kClassName, __func__, "Computing multicast gradient for bin %s with "
       "nbr %" PRIBinId " and dsts 0x%X.\n",
       bin_map_.GetIdToLog(gradient.bin_idx).c_str(),
       path_ctrl->remote_bin_id(), static_cast<unsigned int>(dst_vec));

  // Set value to 0 in case this is called without initializing gradient.
  gradient.value           = 0;
  ls_gradient.value        = 0;
  Gradient zombie_gradient;
  Gradient zombie_ls_gradient;
  zombie_gradient.value    = 0;
  zombie_ls_gradient.value = 0;
  BinQueueMgr* q_mgr = queue_store_->GetBinQueueMgr(gradient.bin_idx);

  // Skim through all unicast destination bins and compute gradient for each.
  // For efficiency, don't even bother looking at bins that aren't
  // destinations for this multicast group.
  DstVec    send_to           = 0;
  DstVec    ls_send_to        = 0;
  DstVec    zombie_send_to    = 0;
  DstVec    zombie_ls_send_to = 0;
  BinIndex  dst_idx           = 0;

  for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_idx);
       valid;
       valid = bin_map_.GetNextUcastBinIndex(dst_idx))
  {
    // NOTE: This iteration through the destination vector could include the
    // node itself, so be mindful of that when computing gradients.
    if (my_qd_for_bin->GetBinDepthByIdx(dst_idx) > 0)
    {
      if (exclude_infinite_paths_)
      {
        uint32_t  latency_us[kMaxPathCtrls];
        memset(latency_us, 0, sizeof(latency_us));
        // Get the latency to the destination bin to find infinite paths.
        bpfwder_.GetPerPcLatencyToDst(dst_idx, (uint32_t*) latency_us, false);

        if (latency_us[path_ctrl->path_controller_number()] == UINT32_MAX)
        {
          LogD(kClassName, __func__,
               "Excluding destination %s through nbr %" PRIBinId " because "
               "it is an infinite path.\n",
               bin_map_.GetIdToLog(dst_idx).c_str(),
               path_ctrl->remote_bin_id());
          continue;
        }
      }
      LogD(kClassName, __func__,
           "Including bin %" PRIBinId " (index %" PRIBinIndex ") in mcast "
           "gradient, because it has a non-zero queue depth %" PRIu32 "B.\n",
           bin_map_.GetPhyBinId(dst_idx), dst_idx,
           my_qd_for_bin->GetBinDepthByIdx(dst_idx));
      bool      is_dst          = false;
      int64_t   differential    = 0;
      int64_t   ls_differential = 0;
      ComputeOneBinGradient(dst_idx, path_ctrl,
                            my_qd_for_bin, nbr_qd_for_bin,
                            my_v_queue_depth, nbr_v_queue_depth,
                            is_dst, differential, ls_differential);

      // Gradients are the sum of the positive per-destination gradients.
      // We only want to send to destinations that had a positive
      // per-destination gradient.
      if (differential > static_cast<int64_t>(is_dst ? 0 : hysteresis_))
      {
        // Keep track of the zombie and non-zombie gradients separately.
        if (q_mgr->non_zombie_queue_depth_bytes(dst_idx) > 0)
        {
          gradient.value           += differential;
          send_to                   = bin_map_.AddBinToDstVec(send_to,
                                                              dst_idx);
          LogD(kClassName, __func__,
               "With differential %" PRId64 "B (hysteresis %uB), adding bin "
               "index %" PRIBinIndex " to dst vec, now 0x%X.\n",
               differential, hysteresis_, dst_idx, send_to);
        }
        else
        {
          zombie_gradient.value           += differential;
          zombie_send_to                   = bin_map_.AddBinToDstVec(send_to,
                                                                     dst_idx);
          LogD(kClassName, __func__,
               "Zombie With differential %" PRId64 "B (hysteresis %uB), adding bin "
               "index %" PRIBinIndex " to dst vec, now 0x%X.\n",
               differential, hysteresis_, dst_idx, zombie_send_to);
        }
        mcast_gradients_[dst_idx] = differential;
      }
      else
      {
        LogD(kClassName, __func__,
             "Differential %" PRId64 "B is below hysteresis %uB or is dst, not"
             " adding.\n",
             differential, hysteresis_);
        mcast_gradients_[dst_idx] = 0;
      }
      if (ls_differential > static_cast<int64_t>(is_dst ? 0 : hysteresis_))
      {
        if (q_mgr->non_zombie_queue_depth_bytes(dst_idx) > 0)
        {
          ls_gradient.value += ls_differential;
          ls_send_to = bin_map_.AddBinToDstVec(ls_send_to, dst_idx);
          LogD(kClassName, __func__,
               "With LS differential %" PRId64 "B (hysteresis %uB), adding bin "
               "index %" PRIBinIndex " to LS dst vec, now 0x%X.\n",
               ls_differential, hysteresis_, dst_idx, ls_send_to);
        }
        else
        {
          zombie_ls_gradient.value += ls_differential;
          zombie_ls_send_to = bin_map_.AddBinToDstVec(ls_send_to, dst_idx);
          LogD(kClassName, __func__,
               "With Zombie LS differential %" PRId64 "B (hysteresis %uB), "
               "adding bin index %" PRIBinIndex " to LS dst vec, now 0x%X.\n",
               ls_differential, hysteresis_, dst_idx, ls_send_to);
        }
      }
    }
    else
    {
      LogD(kClassName, __func__,
           "NOT including bin %" PRIBinId " (index %" PRIBinIndex ") in mcast "
           "gradient (dsts 0x%x), because it has a 0 queue depth.\n",
           bin_map_.GetPhyBinId(dst_idx), dst_idx, dst_vec);
    }
  }

  LogD(kClassName, __func__, "Zombie Multicast gradient: %" PRId64
       ", non zombie: %" PRId64 "\n", zombie_gradient.value, gradient.value);

  // Set the gradient and destination bit vector.
  if (zombie_gradient.value <= gradient.value)
  {
    gradient.dst_vec      = send_to;
    ls_gradient.dst_vec   = ls_send_to;
    gradient.is_zombie    = false;
    ls_gradient.is_zombie = false;
    gradient.value       += zombie_gradient.value;
  }
  else
  {
    gradient.value       += zombie_gradient.value;
    gradient.dst_vec      = zombie_send_to;
    ls_gradient.dst_vec   = zombie_ls_send_to;
    gradient.is_zombie    = true;
    ls_gradient.is_zombie = true;
    LogD(kClassName, __func__, "Using zombie gradient.\n");
  }

  LogD(kClassName, __func__, "Multicast gradient for bin %s, "
       "nbr %" PRIBinId " = %" PRId64 ", with dst vec 0x%x\n",
       bin_map_.GetIdToLog(gradient.bin_idx).c_str(),
       path_ctrl->remote_bin_id(), gradient.value,
       static_cast<unsigned int>(gradient.dst_vec));
}

//============================================================================
bool UberFwdAlg::IsHistoryConstrained(Packet* pkt, iron::Time& ttg,
                                      uint32_t* latencies_us,
                                      size_t num_latencies)
{
  if (anti_circ_ != AC_TECH_HEURISTIC_DAG)
  {
    return false;
  }

  LogD(kClassName, __func__,
       "Determining packet %s (%p) mode for the first time.\n",
       pkt->GetPacketMetadataString().c_str(),
       pkt);

  // Check if any viable path is still allowed by history.
  for (size_t lat_pc_index = 0; lat_pc_index < num_latencies; ++lat_pc_index)
  {
    PathController* lat_path_ctrl = path_ctrls_[lat_pc_index].path_ctrl;

    if (lat_path_ctrl == NULL)
    {
      LogD(kClassName, __func__,
           "No path controller at index %zd.\n", lat_pc_index);
      continue;
    }

    if (lat_path_ctrl->ready())
    {
      BinIndex  remote_bin_idx = lat_path_ctrl->remote_bin_idx();
      if ((ttg > Time::FromUsec(latencies_us[lat_pc_index])) &&
          (!packet_history_mgr_->PacketVisitedBin(
            pkt, bin_map_.GetPhyBinId(remote_bin_idx))))
      {
        // Found at least one viable path.
        LogD(kClassName, __func__,
             "Pkt (%p) still has a potential non-visited nbr %" PRIBinId
             " (%" PRIBinId ").\n", pkt,
             bin_map_.GetPhyBinId(remote_bin_idx),
             lat_path_ctrl->remote_bin_id());
        LogD(kClassName, __func__,
             "Packet (%p) is in gradient mode.\n",
             pkt);
        // End early and break out of the for loop to find viable
        // paths (lat_pc_index).
        return false;
      }
    }
  }

  LogD(kClassName, __func__,
       "Packet (%p) is in history-constrained mode.\n",
       pkt);
  return true;
}

//============================================================================
bool UberFwdAlg::GetMinLatencyPath(uint32_t* latencies_us, size_t num_latencies,
                                   size_t& path_ctrl_index, Time& min_ttr)
{
  path_ctrl_index = std::numeric_limits<uint8_t>::max();
  min_ttr.SetInfinite();
  bool  res       = false;

  if (num_latencies > kMaxPathCtrls)
  {
    num_latencies = kMaxPathCtrls;
  }

  // Find the minimum latency to the destination.
  for (size_t pc_i = 0; pc_i < num_latencies; ++pc_i)
  {
    LogD(kClassName, __func__,
         "Pkt latency on interface %zu: %" PRIu32 "us.\n",
         pc_i, latencies_us[pc_i]);

    if (latencies_us[pc_i] == std::numeric_limits<uint32_t>::max())
    {
      continue;
    }

    Time this_ttr = Time::FromUsec(latencies_us[pc_i]);
    if (min_ttr > this_ttr)
    {
      min_ttr         = this_ttr;
      path_ctrl_index = pc_i;
      res             = true;
    }
  }
  return res;
}

//============================================================================
uint32_t UberFwdAlg::FindUcastPacketsForGradient(const Gradient& gradient,
                         LatencyClass& ttype,
                         Time& now, bool consider_latency,
                         OrderedList<TransmitCandidate, Time>& candidates,
                         uint32_t max_bytes)
{
  BinIndex        dst_bin_idx = gradient.bin_idx;
  bool            is_dst      = gradient.is_dst;
  uint32_t        latency_us[kMaxPathCtrls];
  // TODO: bytes_found and num_candidate_bytes seem to be always the same. Is
  // that true? If so, can we remove one of them?
  uint32_t        bytes_found  = 0;
  BinQueueMgr*    q_mgr        = queue_store_->GetBinQueueMgr(dst_bin_idx);

  PathController* path_ctrl    =
    path_ctrls_[gradient.path_ctrl_index].path_ctrl;

  if (!path_ctrl || !q_mgr || (ttype >= iron::NUM_LATENCY_DEF))
  {
    return 0;
  }

  // Low-latency traffic.
  if (!path_ctrl->ready())
  {
    LogD(kClassName, __func__,
         "Path ctrl %" PRIu8 " not ready.\n",
         gradient.path_ctrl_index);
    return 0;
  }

  LogD(kClassName, __func__,
       "Attempting to find a match for gradient %" PRId64 "B, to bin %s"
       " on path ctrl %" PRIu8 " among packets with ttype %s in limit of %"
       PRIu32 "B.\n",
       gradient.value, bin_map_.GetIdToLog(dst_bin_idx).c_str(),
       gradient.path_ctrl_index, LatencyClass_Name[ttype].c_str(), max_bytes);

  if (!base_ && (anti_circ_ != AC_TECH_CONDITIONAL_DAG))
  {
    // Get the per path controller latency, which is same for all packets of
    // this bin.
    // Compute best path controller busy-ness.
    bpfwder_.GetPerPcLatencyToDst(dst_bin_idx, (uint32_t*) latency_us, false);
  }

  uint32_t  num_candidate_bytes = 0;
  Packet*   prev_pkt            = NULL;

  Time      ttg                 = Time::Infinite();

  if (consider_latency)
  {
    // We have to treat packetless zombie queues separately from packet
    // queues, since we can't peek through existing packets if the queue type
    // only stores a length.
    if (!q_mgr->IsPktlessZQueue(ttype))
    {
      uint32_t  num_visited_bytes = 0;

      q_mgr->PrepareIteration(ttype);
      PacketQueue::QueueWalkState saved_it;

      // Search inside the queue, do not exceed max number of bytes to dequeue,
      // explore queue.
      // For latency-sensitive traffic, look at at least max_bytes, but also add
      // queue_search_depth_ since some of the packets so far may not be feasible
      // for the path controller.
      while ((num_visited_bytes < max_bytes + queue_search_depth_) &&
        (!q_mgr->IsOrdered(ttype) || (num_candidate_bytes < max_bytes)))
      {
        // While we have fewer candidates than our multi-dequeue limit and we
        // have looked at fewer than that limit plus some buffer, keep searching.
        Packet* pkt = q_mgr->PeekNext(ttype, saved_it);

        if (!pkt || (prev_pkt == pkt))
        {
          LogD(kClassName, __func__,
               "No pkt for bin %s for traffic type %s beyond this pkt.\n",
               bin_map_.GetIdToLog(dst_bin_idx).c_str(),
               LatencyClass_Name[ttype].c_str());
          break;
        }

        LogD(kClassName, __func__,
             "Inspecting %s pkt %p.\n",
             LatencyClass_Name[ttype].c_str(), pkt);
        num_visited_bytes  += pkt->virtual_length();
        LogD(kClassName, __func__,
             "Inspecting %s pkt %p with length %zu. Total visited = %" PRIu32
             ".\n", LatencyClass_Name[ttype].c_str(), pkt,
             pkt->virtual_length(), num_visited_bytes);
        prev_pkt            = pkt;

        if ((anti_circ_ != AC_TECH_NONE) &&
            (packet_history_mgr_->PacketVisitedBin(
              pkt, bin_map_.GetPhyBinId(path_ctrl->remote_bin_idx()))))
        {
          LogD(kClassName, __func__,
               "Pkt %p has already visited bin %" PRIBinId ", no match.\n",
               pkt, bin_map_.GetPhyBinId(path_ctrl->remote_bin_idx()));
          continue;
        }

        if (anti_circ_ == AC_TECH_CONDITIONAL_DAG)
        {
          bpfwder_.GetPerPcLatencyToDst(dst_bin_idx, (uint32_t*) latency_us,
                                        false, pkt);
        }

        // Figure out if this packet can still be delivered.
        // Get time to go from packet.
        if (pkt->time_to_go_valid())
        {
          ttg = pkt->GetTimeToGo() - (now - pkt->recv_time());
        }
        else
        {
          ttg.SetInfinite();
        }

        Time  ttr = Time::FromUsec(latency_us[gradient.path_ctrl_index]);
        if (ttr < ttg)
        {
          // Pkt can be delivered on this path controller.
          LogD(kClassName, __func__,
               "Pkt %p with ttg %s fits on interface %" PRIu8
               " with ttr %s.\n",
               pkt, ttg.ToString().c_str(),
               gradient.path_ctrl_index, ttr.ToString().c_str());

            TransmitCandidate candidate(pkt, gradient.value, dst_bin_idx,
                                        bin_map_.GetIdToLog(dst_bin_idx),
                                        is_dst, ttg,
                                        gradient.path_ctrl_index,
                                        ttr, q_mgr, pkt->virtual_length(),
                                        ttype);
            candidate.dequeue_loc = saved_it;
            candidates.Push(candidate, ttg);
            num_candidate_bytes  += pkt->virtual_length();  // Pkt still here.
            LogD(kClassName, __func__,
                 "Added candidate %p with order %s, have %" PRIu32
                 "B candidates after visiting %" PRIu32 "B.\n",
                 pkt, ttg.ToString().c_str(),
                 num_candidate_bytes, num_visited_bytes);
            bytes_found += pkt->virtual_length();
        }
        else
        {
          LogD(kClassName, __func__,
               "Pkt %p with ttg %s cannot fit on interface %" PRIu8
               " with ttr %s.\n",
               pkt, ttg.ToString().c_str(),
               gradient.path_ctrl_index, ttr.ToString().c_str());
        }
      }
    }
    else
    {
      // We are dequeuing from a packetless LS Zombie queue.
      Time      infinite        = Time::Infinite();
      uint32_t  bytes_available = q_mgr->GetTotalDequeueSize(ttype);
      uint32_t  max_z_size      = q_mgr->GetNextDequeueSize(ttype);

      // If we're not using multi dequeue, then max_bytes and num_bytes won't
      // be set. Instead, limit the zombies to kZombieSingleDequeueLenBytes.
      uint32_t  bytes_allowed = ((multi_deq_ && (max_bytes > 1)) ? max_bytes :
          kZombieSingleDequeueLenBytes);
      LogD(kClassName, __func__,
           "Have %" PRIu32 "B of LS Zombie available (%" PRIu32
           "B dequeuable), algorithm allows %" PRId32 "B for bin %s.\n",
           bytes_available, max_z_size, bytes_allowed,
           bin_map_.GetIdToLog(dst_bin_idx).c_str());

      while ((bytes_available >= kMinZombieLenBytes) && (bytes_allowed > 0))
      {
        uint32_t  candidate_size  = bytes_allowed > max_z_size ? max_z_size :
          bytes_allowed;
        candidate_size = (candidate_size < kMinZombieLenBytes ?
                          kMinZombieLenBytes : candidate_size);

        // Add candidate.
        TransmitCandidate candidate(
          NULL, gradient.value, dst_bin_idx,
          bin_map_.GetIdToLog(dst_bin_idx),
          is_dst, infinite, gradient.path_ctrl_index, infinite, q_mgr,
          candidate_size, ttype);
        candidates.Push(candidate, Time(0));
        bytes_found += candidate_size;

        // Decrement the number of bytes still available in the queue: project
        // what the number of bytes will be available once we dequeue.
        bytes_available = (bytes_available > candidate_size ?
                           bytes_available - candidate_size :
                           0);

        // The maximum packet size cannot be more than the number of available bytes.
        if (bytes_available < max_z_size)
        {
          max_z_size  = bytes_available;
        }

        // Decrement the number of bytes still allowed by the algorithm.
        bytes_allowed = (bytes_allowed > candidate_size ?
                         bytes_allowed - candidate_size :
                         0);
        num_candidate_bytes  += candidate_size;

        LogD(kClassName, __func__,
             "Packetizing Zombie candidate of %" PRIu32 "B selected, there should"
             " still be %" PRIu32 "B Zombies and still allowed %" PRIu32 "B.\n",
             candidate_size, bytes_available, bytes_allowed);
      }
    }
  }
  else
  {
    // Latency-insensitive traffic.
    if ((anti_circ_ == AC_TECH_HEURISTIC_DAG) &&
        (latency_us[gradient.path_ctrl_index] ==
          std::numeric_limits<uint32_t>::max()))
    {
      // If there is no path to the destination, terminate early for
      // heuristic-based latency-aware alg.
      LogD(kClassName, __func__, "Path controller %" PRIu8 " has no path to "
           "destination, latency_us[%zu]=%" PRIu32 ".\n",
           gradient.path_ctrl_index, gradient.path_ctrl_index,
           latency_us[gradient.path_ctrl_index]);
      return 0;
    }

    // We have to treat packetless zombie queues separately from packet
    // queues, since we can't peek through existing packets if the queue type
    // only stores a length.
    if (!q_mgr->IsPktlessZQueue(ttype))
    {
      Packet* pkt = q_mgr->Peek(ttype);

      if (!pkt)
      {
        LogD(kClassName, __func__,
             "No pkt for bin %s ttype %s.\n",
             bin_map_.GetIdToLog(dst_bin_idx).c_str(),
             LatencyClass_Name[ttype].c_str());
        return 0;
      }

      Time  latency_on_pc;
      latency_on_pc.SetInfinite();

      q_mgr->PrepareIteration(ttype);
      PacketQueue::QueueWalkState saved_it;

      // Search inside the queue, do not exceed max number of bytes to dequeue,
      // explore queue.
      // All Latency-Insensitive packets match the gradient, so
      // num_visited_bytes and num_candidate_bytes are the same.
      while (num_candidate_bytes < max_bytes)
      {
        Packet* pkt = q_mgr->PeekNext(ttype, saved_it);

        if (!pkt || (prev_pkt == pkt))
        {
          LogD(kClassName, __func__,
               "No pkt for bin %s for traffic type %s beyond this pkt.\n",
               bin_map_.GetIdToLog(dst_bin_idx).c_str(),
               LatencyClass_Name[ttype].c_str());
          break;
        }

        num_candidate_bytes += pkt->virtual_length();
        LogD(kClassName, __func__,
             "Inspecting %s pkt %p with length %zu. Num candidates = %" PRIu32
             ".\n", LatencyClass_Name[ttype].c_str(), pkt,
             pkt->virtual_length(), num_candidate_bytes);
        prev_pkt             = pkt;

        // Grab packet as candidate.
        TransmitCandidate candidate(
          pkt, gradient.value, dst_bin_idx, bin_map_.GetIdToLog(dst_bin_idx),
          is_dst, ttg, gradient.path_ctrl_index, latency_on_pc, q_mgr,
          pkt->virtual_length(), ttype);
        candidate.dequeue_loc = saved_it;
        candidates.Push(candidate, Time(0));
        LogD(kClassName, __func__,
             "Pkt %p is best candidate so far, selected with order %s. "
             "Length = %" PRIu32 ", virtual length = %" PRIu32 ".\n",
             pkt, is_dst ? "0" : "1", pkt->GetLengthInBytes(),
             pkt->virtual_length());
        bytes_found += pkt->virtual_length();
      } // End while we can use more candidates loop.
    } // End if not zombie queue type.
    else
    {
      // We are dequeuing from a packetless Zombie queue.
      Time infinite = Time::Infinite();
      uint32_t  bytes_available = q_mgr->GetTotalDequeueSize(ttype);
      uint32_t  max_z_size      = q_mgr->GetNextDequeueSize(ttype);

      // If we're not using multi dequeue, then max_bytes and num_bytes won't
      // be set. Instead, limit the zombies to the size of approximately one
      // standard packet.
      uint32_t  bytes_allowed  = ((multi_deq_ && (max_bytes > 1)) ? max_bytes :
        kZombieSingleDequeueLenBytes);
      LogD(kClassName, __func__,
           "Have %" PRIu32 "B of Zombie available (%" PRIu32 "B dequeuable), "
           "algorithm allows %" PRId32 "B for bin %s.\n",
           bytes_available, max_z_size, bytes_allowed,
           bin_map_.GetIdToLog(dst_bin_idx).c_str());
      while ((bytes_available >= kMinZombieLenBytes) && (bytes_allowed > 0))
      {
        uint32_t  candidate_size  = bytes_allowed > max_z_size ? max_z_size :
          bytes_allowed;
        candidate_size = (candidate_size < kMinZombieLenBytes ?
                          kMinZombieLenBytes : candidate_size);

        TransmitCandidate candidate(
          NULL, gradient.value, dst_bin_idx, bin_map_.GetIdToLog(dst_bin_idx),
          is_dst, infinite, gradient.path_ctrl_index, infinite, q_mgr,
          candidate_size, ttype);
        candidates.Push(candidate, Time(0));
        bytes_found += candidate_size;

        // Decrement the number of bytes still available in the queue.
        bytes_available = (bytes_available > candidate_size ?
                           bytes_available - candidate_size :
                           0);

        // The maximum packet size cannot be more than the number of available bytes.
        if (bytes_available < max_z_size)
        {
          max_z_size  = bytes_available;
        }

        // Decrement the number of bytes still allowed by the algorithm.
        bytes_allowed = (bytes_allowed > candidate_size ?
                         bytes_allowed - candidate_size :
                         0);
        num_candidate_bytes  += candidate_size;

        LogD(kClassName, __func__,
             "Packetizing Zombie candidate of %" PRIu32 "B selected, there "
             "should still be %" PRIu32 "B Zombies and still allowed %" PRIu32
             "B.\n",
             candidate_size, bytes_available, bytes_allowed);
      }
    } // End if zombie queue type
  } // End if not considering latency
  return bytes_found;
}

//============================================================================
uint32_t UberFwdAlg::FindMcastPacketsForGradient(
  const Gradient& gradient,
  LatencyClass& ttype,
  OrderedList<TransmitCandidate, Time>& candidates,
  uint32_t max_bytes)
{
  // Now that we know what multicast group and path controller we are looking
  // for, recompute the per-destinations gradients for that pair.

  // Note: we could have stored the multicast gradients the first time around
  // to avoid recomputing, but that would have required storing per group, per
  // path controller, per destination values, which is a lot to store.
  mcast_gradients_.Clear(0);
  Gradient  grad;
  grad.bin_idx          = gradient.bin_idx;
  grad.path_ctrl_index  = gradient.path_ctrl_index;
  grad.is_dst           = false;

  LogD(kClassName, __func__,
       "Attempting to find a match for multicast gradient %" PRId64 "B, to bin "
       "%s on path ctrl %" PRIu8 " among packets with ttype %s in limit of %"
       PRIu32 "B and destinations 0x%X.\n",
       gradient.value, bin_map_.GetIdToLog(grad.bin_idx).c_str(),
       gradient.path_ctrl_index, LatencyClass_Name[ttype].c_str(), max_bytes,
       gradient.dst_vec);

  BinQueueMgr*    q_mgr           = queue_store_->GetBinQueueMgr(grad.bin_idx);
  PathController* path_ctrl       = path_ctrls_[grad.path_ctrl_index].path_ctrl;
  QueueDepths*    nbr_queue_depth = queue_store_->GetBinQueueMgr(
    grad.bin_idx)->GetNbrQueueDepths(path_ctrl->remote_bin_idx());

  if (!nbr_queue_depth)
  {
    LogF(kClassName, __func__,
         "No queue depth for bin %s on path to %" PRIBinId " (%" PRIBinId
         ").\n", bin_map_.GetIdToLog(grad.bin_idx).c_str(),
         bin_map_.GetPhyBinId(path_ctrl->remote_bin_idx()),
         path_ctrl->remote_bin_id());
    return 0;
  }

  // Get neighbor virtual queue depths.
  QueueDepths*  nbr_v_queue_depth =
    queue_store_->PeekNbrVirtQueueDepths(path_ctrl->remote_bin_idx());

  ComputeMulticastGradient(path_ctrl,
    queue_store_->GetQueueDepthsForBpf(grad.bin_idx),
    nbr_queue_depth, queue_store_->GetVirtQueueDepths(), nbr_v_queue_depth,
    grad, grad);


  // Now we have the per destination gradients (mcast_gradients_) to multiply
  // by the intersection of the gradient's destination vector with the
  // destination vector in each packet. The packet(s) with the highest score
  // will be transmitted.

  // Now skim through packets in the queue to find the one that is the best
  // match for this gradient.

  uint32_t  num_cand_bytes = 0;
  if (q_mgr->IsPktlessZQueue(ttype))
  {
    // Drop zombie bytes for each destination with a positive
    // gradient.

    // Track the number of bytes "to be dequeued" for each bin, since we
    // don't do the dequeue until after returning from this function, so
    // the real record of queue depth isn't updated.
    //
    // \TODO This is messy - there must be a better way to handle this.
    dequeued_bytes_.Clear(0);

    while (num_cand_bytes < max_bytes)
    {
      // We don't care about the max zombie size if multi dequeue is enabled,
      // because we aren't sending (or even dequeueing) individual packets:
      // we're just going to drop them all in one big chunk. DropFromQueue will
      // internally ensure we don't drop more than are available.
      uint32_t bytes_allowed  = ((multi_deq_ && (max_bytes > 1)) ? max_bytes :
                                 kZombieSingleDequeueLenBytes);

      // First figure out the maximum size we will dequeue over all
      // destinations (and a destination that can dequeue this max
      // size). We will dequeue a single actual packet with this size and
      // destination for the sake of limiting the zombie dequeue rate to a
      // rate at which the CAT can actually transmit. For all other
      // destinations, we'll just drop bytes out of the zombie queue.
      BinIndex dequeue_dst   = 0;
      BinIndex examine_dst   = 0;
      uint32_t dequeue_bytes = 0;
      uint32_t bin_depth     = 0;

      for (bool valid = bin_map_.GetFirstUcastBinIndex(examine_dst);
           valid;
           valid = bin_map_.GetNextUcastBinIndex(examine_dst))
      {
        if (bin_map_.IsBinInDstVec(gradient.dst_vec, examine_dst))
        {
          bin_depth =
            q_mgr->per_dst_per_lat_class_bytes(examine_dst, ttype);
          if (dequeued_bytes_[examine_dst] > bin_depth)
          {
            LogF(kClassName, __func__, " Dequeued bytes (%" PRIu32
                 ") too high for bin %s, class %s. bin depth is %" PRIu32
                 "\n", dequeued_bytes_[examine_dst],
                 bin_map_.GetIdToLog(examine_dst).c_str(),
                 LatencyClass_Name[ttype].c_str(),
                 bin_depth);
          }
          bin_depth = bin_depth - dequeued_bytes_[examine_dst];
          LogD(kClassName, __func__, "Considering dst %s (class %s). "
               "Bin depth is %" PRIu32 ", bytes_allowed = %" PRIu32
               ", dequeue_bytes = %" PRIu32 "\n",
               bin_map_.GetIdToLog(examine_dst).c_str(),
               LatencyClass_Name[ttype].c_str(),
               bin_depth,
               bytes_allowed, dequeue_bytes);
          if (bin_depth > dequeue_bytes)
          {
            dequeue_dst = examine_dst;
            if (bin_depth >= bytes_allowed)
            {
              dequeue_bytes = bytes_allowed;
              break;
            }
            else
            {
              dequeue_bytes = bin_depth;
            }
          }
        }
      }

      // Max size for any destination is 0. Nothing to dequeue.
      if (dequeue_bytes == 0)
      {
        LogD(kClassName, __func__, "No zombie bytes to dequeue/drop.\n");
        return num_cand_bytes;
      }

      // Loop through and drop zombie bytes for all destinations except the
      // max destination (for which we'll dequeue a packet back in
      // FindNextTransmission).
      for (bool valid = bin_map_.GetFirstUcastBinIndex(examine_dst);
           valid;
           valid = bin_map_.GetNextUcastBinIndex(examine_dst))
      {
        if (bin_map_.IsBinInDstVec(gradient.dst_vec, examine_dst) &&
            (examine_dst != dequeue_dst))
        {
          DstVec  dequeue_dst_vec = 0;
          dequeue_dst_vec = bin_map_.AddBinToDstVec(
            dequeue_dst_vec, examine_dst);
          LogD(kClassName, __func__, "Attempting to drop %" PRIu32
               "zombie bytes (%s) for bin %s, dst %s.\n",
               bytes_allowed,
               LatencyClass_Name[ttype].c_str(),
               bin_map_.GetIdToLog(grad.bin_idx).c_str(),
               bin_map_.GetIdToLog(examine_dst).c_str());
          q_mgr->DropFromQueue(ttype, bytes_allowed, dequeue_dst_vec);
          // Note: we're not counting this as a dropped packet in the sense of
          // calling AddDroppedBytes in bpfwder or tracking this as an
          // expected drop. This is just local zombie accounting.
        }
      }

      // Finally, generate a dequeue candidate for a bin with the max amount
      // of bytes to dequeue. This is a bit of a hack to let us use
      // transmitting packets over a CAT as a means of rate-limiting zombie
      // dequeues. We already know from above exactly how big this packet
      // needs to be.
      DstVec  dequeue_dst_vec = 0;
      dequeue_dst_vec = bin_map_.AddBinToDstVec(
        dequeue_dst_vec, dequeue_dst);
      Time infinite = Time::Infinite();
      LogD(kClassName, __func__, "Adding transmit candidate from class %s "
           "with size %" PRIu32 " for bin %s, dst %s.\n",
           LatencyClass_Name[ttype].c_str(),
           bytes_allowed,
           bin_map_.GetIdToLog(grad.bin_idx).c_str(),
           bin_map_.GetIdToLog(dequeue_dst).c_str());
      TransmitCandidate candidate(
        gradient.value,
        gradient.bin_idx,
        bin_map_.GetIdToLog(gradient.bin_idx),
        infinite,
        gradient.path_ctrl_index,
        dequeue_dst_vec,
        q_mgr,
        dequeue_bytes,
        ttype);
      candidates.Push(candidate, Time(0));
      dequeued_bytes_[dequeue_dst] += dequeue_bytes;
      num_cand_bytes += dequeue_bytes;
    }
    return num_cand_bytes;
  }

  OrderedList<TransmitCandidate, uint64_t>  all_ordered_cands(
    iron::LIST_DECREASING);
  q_mgr->PrepareIteration(ttype);
  iron::PacketQueue::QueueWalkState saved_it;
  TransmitCandidate                 candidate;
  Time                              ttg = Time::Infinite();
  Packet*                           pkt = NULL;
  uint64_t                          num_exact_match_bytes = 0;

  while ((pkt = q_mgr->PeekNext(ttype, saved_it)))
  {
    DstVec  pkt_dst_vec = pkt->dst_vec();
    LogD(kClassName, __func__,
         "Pkt %p has dst vec 0x%X to be compared to gradient dst vec 0x%X.\n",
         pkt, pkt_dst_vec, gradient.dst_vec);
    uint64_t  current_score       = 0;
    BinIndex  idx                 = 0;
    DstVec    proposed_dst_vec    = 0;

    if ((anti_circ_ != AC_TECH_NONE) &&
        (packet_history_mgr_->PacketVisitedBin(
          pkt, bin_map_.GetPhyBinId(path_ctrl->remote_bin_idx()))))
    {
      LogD(kClassName, __func__, "Pkt %p has already visited bin %" PRIBinId
           ", no match.\n", pkt,
           bin_map_.GetPhyBinId(path_ctrl->remote_bin_idx()));
      continue;
    }

    for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(idx))
    {
      if (bin_map_.IsBinInDstVec(pkt_dst_vec, idx) &&
        bin_map_.IsBinInDstVec(gradient.dst_vec, idx) &&
        mcast_gradients_[idx] > 0)
      {
        current_score     += mcast_gradients_[idx];
        proposed_dst_vec =
          bin_map_.AddBinToDstVec(proposed_dst_vec, idx);
        LogD(kClassName, __func__,
             "Adding bin index %" PRIBinIndex " (bin %" PRIBinId
             ") to proposed dst vec 0x%X (positive gradient %uB).\n",
             idx, bin_map_.GetPhyBinId(idx),
             proposed_dst_vec, mcast_gradients_[idx]);
      }
    }

    if (current_score == 0)
    {
      continue;
    }

    candidate.is_valid        = true;
    candidate.pkt             = pkt;
    // TODO why do we store the gradient with the candidate? Should this
    // be the gradient that caused us to pick this PC x group or the score
    // that caused us to pick this packet?
    candidate.gradient        = gradient.value;
    candidate.bin_idx         = gradient.bin_idx;
    candidate.id_to_log       = bin_map_.GetIdToLog(gradient.bin_idx);
    candidate.path_ctrl_index = gradient.path_ctrl_index;
    candidate.dst_vec         = proposed_dst_vec;
    candidate.q_mgr           = q_mgr;
    candidate.dequeue_loc     = saved_it;
    candidate.virtual_len     = pkt->virtual_length();
    candidate.latency_class   = ttype;

    all_ordered_cands.Push(candidate, current_score);
    LogD(kClassName, __func__,
         "Added packet %p of size %zdB with gradient %" PRIu64 "B as "
         "potential %" PRIu8 "th candidate.\n",
         pkt, pkt->virtual_length(), current_score,
         all_ordered_cands.size());

    if (pkt_dst_vec == gradient.dst_vec)
    {
      num_exact_match_bytes += pkt->virtual_length();
      if (num_exact_match_bytes > max_bytes)
      {
        LogD(kClassName, __func__,
             "Collected %zdB of exact match packets, reached max bytes %zdB.\n",
             num_exact_match_bytes, max_bytes);
        break;
      }
    }
  } // end of skimming entire queue.

  OrderedList<TransmitCandidate, uint64_t>::WalkState ordered_ws;
  ordered_ws.PrepareForWalk();

  candidate.is_valid  = false;

  while (all_ordered_cands.GetNextItem(ordered_ws, candidate) &&
    (num_cand_bytes < max_bytes))
  {
    if (!candidate.is_valid)
    {
      LogW(kClassName, __func__,
           "Candidate pkt %p in ordered list invalid.\n", candidate.pkt);
      break;
    }

    num_cand_bytes += candidate.virtual_len;
    candidates.Push(candidate, ttg);
    LogD(kClassName, __func__,
         "Added packet %p as candidate.\n",
         candidate.pkt);
  }
  return num_cand_bytes;
}

//============================================================================
void UberFwdAlg::McastOpportunisticForwarding(TransmitCandidate& candidate)
{
  DstVec    pkt_dst_vec   = candidate.pkt->dst_vec();
  DstVec    new_dst_vec   = candidate.dst_vec;
  BinIndex  mcast_dst_idx = candidate.bin_idx;
  BinIndex  dst_idx       = 0;
  bool      is_dst        = false;

  LogD(kClassName, __func__,
       "Considering pkt %p with dsts 0x%X on path ctrl to nbr %" PRIBinId
       " to bin %s to add to proposed dst vec 0x%X.\n",
       candidate.pkt, static_cast<unsigned int>(pkt_dst_vec),
       path_ctrls_[candidate.path_ctrl_index].path_ctrl->remote_bin_id(),
       bin_map_.GetIdToLog(mcast_dst_idx).c_str(),
       static_cast<unsigned int>(new_dst_vec));

  // Skim through all destinations in the packet. For each one that is not
  // already included in the candidate destination vector, see if this path
  // controller has a higher (negative) differential than all other path
  // controllers. If so, include it.
  for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_idx);
       valid;
       valid = bin_map_.GetNextUcastBinIndex(dst_idx))
  {
    // The only destinations we want to consider adding are those that are in
    // the packet's destinatin vector but not yet in the proposed (candidate)
    // desination vector.
    if (bin_map_.IsBinInDstVec(pkt_dst_vec, dst_idx) &&
        !bin_map_.IsBinInDstVec(candidate.dst_vec, dst_idx))
    {
      int64_t cand_differential     = 0;
      int64_t comp_differential     = 0;
      int64_t cand_ls_differential  = 0;
      int64_t comp_ls_differential  = 0;
      bool    add_dst               = true; // assume true until proven false.
      // Start with the differential for the candidate path controller.
      PathController* path_ctrl =
        path_ctrls_[candidate.path_ctrl_index].path_ctrl;
      // ComputeOneBinGradient does not include hysteresis, which does not
      // matter since we only compare the relative values of gradient.
      ComputeOneBinGradient(dst_idx, path_ctrl,
        queue_store_->GetQueueDepthsForBpf(mcast_dst_idx),
        queue_store_->GetBinQueueMgr(mcast_dst_idx)->GetNbrQueueDepths(
          path_ctrl->remote_bin_idx()),
        queue_store_->GetVirtQueueDepths(),
        queue_store_->PeekNbrVirtQueueDepths(path_ctrl->remote_bin_idx()),
        is_dst, cand_differential, cand_ls_differential);

      LogD(kClassName, __func__,
           "Destination %s through considered nbr %" PRIBinId
           " has gradient %" PRId64 " B.",
           bin_map_.GetIdToLog(dst_idx).c_str(),
           path_ctrl->remote_bin_id(),
           cand_differential);

      if (cand_differential < opportunistic_fwding_floor_)
      {
        LogD(kClassName, __func__,
             "Excluding destination %s through considered nbr %" PRIBinId
             " because its gradient %" PRId64 "B is too strongly negative "
             "(less than %" PRId64 " B).\n",
             bin_map_.GetIdToLog(dst_idx).c_str(),
             path_ctrl->remote_bin_id(),
             cand_differential,
             opportunistic_fwding_floor_);
        add_dst  = false;
      }

      uint32_t  latency_us[kMaxPathCtrls];
      memset(latency_us, 0, sizeof(latency_us));
      // Get the latency to the destination bin to find infinite paths.
      bpfwder_.GetPerPcLatencyToDst(dst_idx, (uint32_t*) latency_us, false);

      if (exclude_infinite_paths_ &&
        (latency_us[path_ctrl->path_controller_number()] == UINT32_MAX))
      {
        LogD(kClassName, __func__,
             "Excluding destination %s through considered nbr %" PRIBinId
             " because it is an infinite path.\n",
             bin_map_.GetIdToLog(dst_idx).c_str(),
             path_ctrl->remote_bin_id());
        add_dst  = false;  // Ineffectual, but just in case.
        continue;
      }

      // Now see if there's another path controller with a higher
      // differential.
      for (size_t pc_index = 0; pc_index < num_path_ctrls_; ++pc_index)
      {
        if (candidate.path_ctrl_index == pc_index)
        {
          continue;
        }

        path_ctrl = path_ctrls_[pc_index].path_ctrl;

        if (latency_us[path_ctrl->path_controller_number()] == UINT32_MAX)
        {
          if (exclude_infinite_paths_)
          {
            LogD(kClassName, __func__,
                 "Excluding destination %s through nbr %" PRIBinId
                 " because it is an infinite path.\n",
                 bin_map_.GetIdToLog(dst_idx).c_str(),
                 path_ctrl->remote_bin_id());
            continue;
          }
        }

        if (!add_dst)
        {
          // If add_dst is false, as would be the case from a gradient below
          // floor, continue to count the non-dead-end neighbors.
          continue;
        }

        ComputeOneBinGradient(dst_idx, path_ctrl,
          queue_store_->GetQueueDepthsForBpf(mcast_dst_idx),
          queue_store_->GetBinQueueMgr(mcast_dst_idx)->GetNbrQueueDepths(
            path_ctrl->remote_bin_idx()),
          queue_store_->GetVirtQueueDepths(),
          queue_store_->PeekNbrVirtQueueDepths(path_ctrl->remote_bin_idx()),
          is_dst, comp_differential, comp_ls_differential);

        if (comp_differential > cand_differential)
        {
          LogD(kClassName, __func__,
               "Not adding bin index %" PRIBinIndex " (bin %s) through nbr %"
               PRIBinId " because the gradient %dB is higher than existing "
               "%dB.\n", dst_idx, bin_map_.GetIdToLog(dst_idx).c_str(),
               path_ctrl->remote_bin_id(), comp_differential,
               cand_differential);
          add_dst = false;
          break;
        }
        else
        {
          LogD(kClassName, __func__,
               "Bin index %" PRIBinIndex " (bin %s) through nbr %" PRIBinId
               " has gradient %dB lower than existing %dB.\n",
               dst_idx, bin_map_.GetIdToLog(dst_idx).c_str(),
               path_ctrl->remote_bin_id(),
               comp_differential, cand_differential);
        }
      } // End for each path controller.

      if (add_dst)
      {
        new_dst_vec = bin_map_.AddBinToDstVec(new_dst_vec, dst_idx);
        LogD(kClassName, __func__,
             "Adding bin index %" PRIBinIndex " (bin %s) to dst vec, now "
             "0x%X.\n",
             dst_idx, bin_map_.GetIdToLog(dst_idx).c_str(),
             new_dst_vec);
      }
    } // end if this is a destination we should consider adding
  } // end for each potential destination

  // Update the destination vector to add any opportunistic forwarding
  // destinations we discovered here.
  candidate.dst_vec = new_dst_vec;
}

//============================================================================
void UberFwdAlg::AddDelayToAverage(int64_t queue_delay_us, BinIndex bin_idx)
{
  double  alpha = kDefaultQueueDelayAlpha;

  // An+1 = alpha * An + (1 - alpha) * Yn+1.
  uint32_t  prev_aqd = avg_queue_delay_[bin_idx];
  uint32_t  new_aqd  = ((alpha * prev_aqd) +
                        ((1.0 - alpha) * queue_delay_us));

  avg_queue_delay_[bin_idx] = new_aqd;

  LogD(kClassName, __func__,
       "New average queue delay to BinId %s is %" PRIu32 "us (pkt adds %"
       PRId64 "us, alpha %.3f).\n",
       bin_map_.GetIdToLog(bin_idx).c_str(), new_aqd, queue_delay_us, alpha);

  if (xplot_queue_delay_ && delay_xplot_[bin_idx])
  {
    int64_t now_usec  = Time::GetNowInUsec();

    delay_xplot_[bin_idx]->DrawPoint(now_usec - iron::kStartTime,
                                     queue_delay_us,
                                     static_cast<iron::XPLOT_COLOR>(0),
                                     XPLOT_DOT);
    delay_xplot_[bin_idx]->DrawPoint(now_usec - iron::kStartTime, new_aqd,
                                     static_cast<iron::XPLOT_COLOR>(1),
                                     XPLOT_DIAMOND);
  }

  // TODO: Consider sending notification to BPFwder if large change (on-demand).
}
