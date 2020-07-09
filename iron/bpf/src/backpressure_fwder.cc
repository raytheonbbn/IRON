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

#include "backpressure_fwder.h"

#include "bpf_stats.h"
#include "bin_map.h"
#include "debugging_stats.h"
#include "fifo_if.h"
#include "packet_history_mgr.h"
#include "path_controller.h"
#include "queue_store.h"
#include "sliq_cat.h"
#include "sond.h"
#include "unused.h"

#include "iron_types.h"
#include "iron_utils.h"
#include "log.h"
#include "packet_pool.h"
#include "string_utils.h"
#include "timer.h"
#include "zombie.h"

#include <cmath>

#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <climits>
#include <errno.h>
#include <inttypes.h>


using ::iron::BinMap;
using ::iron::BpfStats;
using ::iron::BPFwder;
using ::iron::DebuggingStats;
using ::iron::FifoIF;
using ::iron::LatencyCacheShm;
using ::iron::Packet;
using ::iron::PacketHistoryMgr;
using ::iron::PACKET_OWNER_TCP_PROXY;
using ::iron::PACKET_OWNER_UDP_PROXY;
using ::iron::PacketPool;
using ::iron::PacketType;
using ::iron::SharedMemoryIF;
using ::iron::StringUtils;
using ::iron::Timer;
using ::iron::Zombie;
using ::rapidjson::SizeType;
using ::rapidjson::StringBuffer;
using ::rapidjson::Value;
using ::rapidjson::Writer;
using ::std::map;
using ::std::numeric_limits;
using ::std::string;


namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)            = "BPFwder";

  /// Class name for logging.
  const char*     UNUSED(kPIClassName)          = "PathInfo";

  /// The maximum number of path controller file descriptors.
  const int       kPathCtrlMaxFdCount           = 64;

  /// The default remote control TCP port number.
  const uint16_t  kDefaultBpfRmtCntlPort        = 5560;

  /// The default minimum allowable capacity estimate, in bits per second, in
  /// order to keep QLAMs flowing.
  const double    kMinCapacityBitsPerSec        = 256000.0;

  /// The default statistics collection interval.
  const uint32_t  kDefaultStatsCollectionIntervalMs = 5000;

  /// Default value for directive to log collected statistics.
  const bool      kDefaultLogStats              = true;

  /// The maximum number of packets to be dequeued at once after calling
  /// FindNextTransmission.
  const uint8_t   kMaxNumSolutions              = 127;

  /// The number of buckets in the latency cache's hash table.  A key is the
  /// combination of an 8bit destination and a 14bit history vector bit map, or
  /// 22bits.  The hash method is run over half of this value, or 2^11 = 2048
  /// buckets.
  const uint16_t  kLatencyCacheNumBuckets       = 2048;

  /// The number of buckets in the multicast group membership table.
  const uint16_t  kMcastGroupsNumBuckets        = 2048;

  /// Default minimum number of bytes changes in queue depth between copies to
  /// the shared memory segments.
  const uint32_t  kDefaultMinQdChangeShmCopyInBytes = 5000;

  /// Default portion of every link's capacity for QLAMs (0.01 = 1%)
  const double    kDefaultQlamOverheadRatio     = 0.01;

  /// The default LSA timer interval in milliseconds.
  const uint32_t  kDefaultLsaIntervalMs         = 1000;

  /// The default GRAM timer interval in milliseconds.
  const uint32_t kDefaultGramIntervalMs         = 10000;

  /// The estimated packet delivery delay (PDD) reporting change threshold.
  const double    kPddThresh                    = 0.10;

  /// The estimated PDD reporting minimum period, in seconds.
  const double    kPddMinPeriodSec              = 0.100;

  /// The estimated PDD reporting maximum period, in seconds.
  const double    kPddMaxPeriodSec              = 5.000;

  /// The default boolean to include queuing delays in path latency.
  const bool      kDefaultIncludeQueuingDelays  = false;

  /// The default boolean to exchange link capacity estimates for export.
  const bool      kDefaultIncludeLinkCapacity   = false;

  /// The default LSA hold down time in milliseconds.
  const uint32_t  kDefaultLsaHoldDownTimeMs     = 500;

  /// The minimum time between updating the latencies for all
  /// destination through all path controllers, in milliseconds.
  const uint64_t  kLatencyCalculationIntervalMs = 100;

  /// Set to true if we want to include received QLAM values on the queue
  /// depth xplot graphs. These clutter the graphs, but are useful for
  /// understanding/debugging forwarding algorithm decisions.
  const bool      kGraphReceivedQlamVals        = false;

  /// Set to true if we want to include the dropped number of bytes on the
  /// queue depth xplot graphs (as down arrows).
  /// These clutter the graphs but are useful for understanding queue depths.
  const bool      kGraphDroppedBytes            = false;

  /// How long to wait before waking up the BPF main select loop in the case
  /// where there are no arriving packets or other triggers.
  const iron::Time kBackstopTime                = iron::Time(0.001);

  /// The time after which a qlam is considered stale.
  const iron::Time kMaxQlamInt                  = iron::Time(10);

  /// Whether or not to drop zombies when we dequeue them. If false, zombies
  /// are sent when they are dequeued.
  const bool      kDefaultDropDequeuedZombies   = false;

  /// Whether or not to drop zombies we receive. If false, received zombies
  /// are enqueued to the specified destination.
  const bool      kDefaultDropRcvdZombies       = true;

  /// Constant deciding whether to drop expired arriving packets.
  const bool      kDefaultDropExpiredRcvdPackets = false;

  /// Constant deciding whether or not to support multicast forwarding.
  const bool      kDefaultMcastFwding           = true;

  /// Default virtual queue multiplier.
  const uint32_t  kDefaultVirtQueueMult         = 1100;
}

//============================================================================
BPFwder::BPFwder(PacketPool& packet_pool,
                 Timer& timer,
                 BinMap& bin_map,
                 SharedMemoryIF& weight_qd_shared_memory,
                 FifoIF* bpf_to_udp_pkt_fifo,
                 FifoIF* bpf_to_tcp_pkt_fifo,
                 FifoIF* udp_to_bpf_pkt_fifo,
                 FifoIF* tcp_to_bpf_pkt_fifo,
                 ConfigInfo& config_info)
    : node_records_(),
      incl_queue_delays_(kDefaultIncludeQueuingDelays),
      incl_link_capacity_(kDefaultIncludeLinkCapacity),
      running_(false),
      my_bin_id_(numeric_limits<BinId>::max()),
      my_bin_idx_(numeric_limits<BinIndex>::max()),
      is_int_node_(false),
      num_path_ctrls_(0),
      path_ctrls_(),
      bin_map_shm_(bin_map),
      bpf_to_udp_pkt_fifo_(packet_pool, bpf_to_udp_pkt_fifo,
                           PACKET_OWNER_UDP_PROXY, 0),
      bpf_to_tcp_pkt_fifo_(packet_pool, bpf_to_tcp_pkt_fifo,
                           PACKET_OWNER_TCP_PROXY, 0),
      udp_to_bpf_pkt_fifo_(packet_pool, udp_to_bpf_pkt_fifo,
                           PACKET_OWNER_UDP_PROXY,
                           kMaxPktsPerFifoRecv),
      tcp_to_bpf_pkt_fifo_(packet_pool, tcp_to_bpf_pkt_fifo,
                           PACKET_OWNER_TCP_PROXY,
                           kMaxPktsPerFifoRecv),
      queue_store_(NULL),
      bpf_fwd_alg_(NULL),
      last_qlam_size_bits_(256),
      min_path_ctrl_cap_est_bps_(kMinCapacityBitsPerSec),
      packet_history_mgr_(NULL),
      virt_queue_info_(),
      path_info_(),
      packet_pool_(packet_pool),
      timer_(timer),
      weight_qd_shared_memory_(weight_qd_shared_memory),
      per_qlam_overhead_bytes_(0),
      qlam_sequence_number_(),
      last_qlam_time_(),
      multi_deq_(kDefaultMultiDeq),
      xmit_buf_max_thresh_(kDefaultBpfXmitQueueThreshBytes),
      bpf_stats_(bin_map),
      remote_control_(),
      stats_push_(),
      flow_stats_push_(),
      last_qd_shm_copy_time_(),
      min_qd_change_shm_bytes_(kDefaultMinQdChangeShmCopyInBytes),
      num_bytes_processed_(0),
      virt_queue_mult_(kDefaultVirtQueueMult),
      broadcast_seq_nums_(),
      ttr_sigma_factor_(0),
      ls_latency_collection_(kDefaultLinkStateLatency),
      lsa_seq_num_(0),
      conditional_dags_(false),
      latency_cache_(),
      latency_cache_reset_time_(Time::Now()),
      shm_latency_cache_(bin_map, SHM_TYPE_CREATE),
      latency_pbpp_update_time_ms_(Time::Now().GetTimeInMsec()),
      lsa_hold_down_time_(Time::FromMsec(kDefaultLsaHoldDownTimeMs)),
      lsa_hold_down_(false),
      lsa_interval_ms_(kDefaultLsaIntervalMs),
      last_lsa_send_time_(),
      lsa_timer_handle_(),
      lsa_info_(),
      gram_interval_ms_(kDefaultGramIntervalMs),
      gram_timer_handle_(),
      overhead_ratio_(kDefaultQlamOverheadRatio),
      max_qlam_intv_usec_(3600000000),
      stats_interval_ms_(kDefaultStatsCollectionIntervalMs),
      do_packet_tracing_(kDefaultPacketTrace),
      do_ttg_tracking_(kDefaultTtgTracking),
      ef_ordering_(kDefaultEFOrdering),
      rng_(),
      debugging_stats_(NULL),
      drop_expired_(kDefaultDropExpired),
      dropped_bytes_(),
      drop_dequeued_zombies_(kDefaultDropDequeuedZombies),
      drop_rcvd_zombies_(kDefaultDropRcvdZombies),
      drop_expired_rcvd_packets_(kDefaultDropExpiredRcvdPackets),
      num_stale_qlams_rcvd_(0),
      mcast_fwding_(kDefaultMcastFwding),
      mcast_agg_(true),
      mcast_group_cache_(),
      mcast_group_memberships_(),
      config_info_(config_info),
      send_grams_(kDefaultSendGrams)
{
  LogI(kClassName, __func__, "Creating Backpressure Forwarder...\n");
}

//============================================================================
BPFwder::~BPFwder()
{
  if (num_stale_qlams_rcvd_ > 0)
  {
    LogW(kClassName, __func__, "Received %" PRIu32 " stale QLAMs. "
         "If this node is not dual homed, this may indicate a problem.\n",
         num_stale_qlams_rcvd_);
  }

  LogI(kClassName, __func__, "Destroying Backpressure Forwarder...\n");

  // Cancel the stats timer.
  timer_.CancelTimer(stats_push_.timer_handle);

  // Cancel the flow stats timer.
  timer_.CancelTimer(flow_stats_push_.timer_handle);

  // Purge the BPF stats. This is a short term fix to cleanup the double
  // bookkeeping that the BpfStats object introduces. When the BPF unit tests
  // are run, the static BpfStats object is not cleaned up between the
  // BPF unit test runs, which causes Valgrind to complain about using a
  // PathController that is no longer valid. The longer term fix is to address
  // the double bookkeeping.
  bpf_stats_.Purge();

  // Print our history stats and destroy the packet history manager.
  if (packet_history_mgr_)
  {
    packet_history_mgr_->LogCirculationStats();
    delete packet_history_mgr_;
  }

#ifdef DEBUG_STATS
  if (debugging_stats_)
  {
    delete debugging_stats_;
  }
#endif // DEBUG_STATS

  // Destroy the queue store.
  delete queue_store_;

  // Destroy the BPFwder algorithm.
  delete bpf_fwd_alg_;

  // Destroy the Path Controllers and their QLAM generation timers.
  for (size_t i = 0; i < kMaxPathCtrls; ++i)
  {
    if (path_ctrls_[i].path_ctrl != NULL)
    {
      timer_.CancelTimer(path_ctrls_[i].timer_handle);

      delete path_ctrls_[i].path_ctrl;
      path_ctrls_[i].path_ctrl = NULL;
    }
  }

  // Clean up the latency cache.
  HashTable<CacheKey, CachedLatencyData*>::WalkState  ws;
  CacheKey                                            dummy_key;
  CachedLatencyData*                                  dummy_lat;
  while (latency_cache_.GetNextPair(ws, dummy_key, dummy_lat))
  {
    dummy_lat->DestroyLatencies();
    delete  dummy_lat;
    dummy_lat = NULL;
  }
  latency_cache_.Clear();

  // Clean up the group membership table.
  iron::MashTable<Ipv4Address, List<string>*>::WalkState mg_ws;
  List<string>* host_list = NULL;

  while (mcast_group_cache_.GetNextItem(mg_ws, host_list))
  {
    if (host_list)
    {
      host_list->Clear();
      delete host_list;
    }
  }
  mcast_group_cache_.Clear();

  // Clean up the node records.  Loop over all possible BinIndex values to
  // make sure everything gets cleaned up.
  BinIndex  bin_idx = 0;

  for (bool more_bin_idx = bin_map_shm_.GetFirstBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_shm_.GetNextBinIndex(bin_idx))
  {
    if (node_records_[bin_idx] != NULL)
    {
      delete node_records_[bin_idx];
      node_records_[bin_idx] = NULL;
    }
  }

  // Cancel all of the timers, and clean up the timer callback object pools.
  timer_.CancelAllTimers();
  CallbackNoArg<BPFwder>::EmptyPool();
  CallbackTwoArg<BPFwder, uint32_t, uint32_t>::EmptyPool();

  running_ = false;
}

//============================================================================
bool BPFwder::Initialize()
{
  LogI(kClassName, __func__, "Configuring Backpressure Forwarder...\n");

  send_grams_ = config_info_.GetBool("Bpf.SendGrams", kDefaultSendGrams);

  // Make sure that the bin map is already initialized.
  if (!bin_map_shm_.initialized())
  {
      return false;
  }

  // Get the node's bin id.
  string  bin_id_str = config_info_.Get("Bpf.BinId", "");

  if (bin_id_str.empty())
  {
    LogF(kClassName, __func__, "No Bpf.BinId found for node in "
         "configuration.\n");
    return false;
  }

  my_bin_id_  = static_cast<BinId>(StringUtils::GetUint(bin_id_str,
                                                        kInvalidBinId));

  // Get the node's bin index and determine if this node is an interior node.
  my_bin_idx_  = bin_map_shm_.GetPhyBinIndex(my_bin_id_);
  is_int_node_ = bin_map_shm_.IsIntNodeBinIndex(my_bin_idx_);

  if (my_bin_idx_ == kInvalidBinIndex)
  {
    LogF(kClassName, __func__, "Invalid Bpf.BinId value: %s\n", bin_id_str);
    return false;
  }

  // Initialize the node records.
  if (!node_records_.Initialize(bin_map_shm_))
  {
    LogE(kClassName, __func__, "Unable to initialize node records array.\n");
    return false;
  }
  node_records_.Clear(NULL);

  // Initialize the virtual queue array.
  if (!virt_queue_info_.Initialize(bin_map_shm_))
  {
    LogE(kClassName, __func__, "Unable to initialize virtual queue "
         "information array.\n");
    return false;
  }

  // Initialize the path information.
  if (!path_info_.Initialize(bin_map_shm_))
  {
    LogE(kClassName, __func__, "Unable to initialize path information.\n");
    return false;
  }

  // Initialize the LSA node information array.
  if (!lsa_info_.Initialize(bin_map_shm_))
  {
    LogE(kClassName, __func__, "Unable to initialize LSA information "
         "array.\n");
    return false;
  }

  // Create a node record for this IRON node since this is always needed.
  if (AccessOrAllocateNodeRecord(my_bin_idx_) == NULL)
  {
    LogF(kClassName, __func__, "Unable to create node record for my bin "
         "index %" PRIBinIndex "\n", my_bin_idx_);
    return false;
  }

  // Initialize the BPF statistics.
  if (!bpf_stats_.Initialize())
  {
    LogE(kClassName, __func__, "Unable to initialize BPF statistics.\n");
    return false;
  }

  // Initialize broadcast sequence numbers to 0.
  for (int i = 0; i < NUM_BC_IDX; ++i)
  {
    if (!broadcast_seq_nums_[i].Initialize(bin_map_shm_))
    {
      LogW(kClassName, __func__, "Unable to initialize broadcast sequence "
           "number array %d.\n", i);
      return false;
    }
    broadcast_seq_nums_[i].Clear(0);
  }

  // Set up the packet history manager.
  bool pkt_history = config_info_.GetBool("PacketHistory",
                                         kDefaultPacketHistory);
  if (pkt_history)
  {
    packet_history_mgr_ =
      new (std::nothrow) PacketHistoryMgr(bin_map_shm_, my_bin_id_);
    if (!packet_history_mgr_ )
    {
      LogW(kClassName, __func__, "Unable to create PacketHistoryMgr.\n");
      return false;
    }
  }

  // We only send qlams to unicast destinations and interior nodes, not to
  // multicast destinations.
  if (!qlam_sequence_number_.Initialize(bin_map_shm_))
  {
    LogW(kClassName, __func__, "Unable to initialize QLAM sequence number "
         "array.\n");
    return false;
  }
  qlam_sequence_number_.Clear(0);

  // We only send qlams to unicast destinations and interior nodes, not to
  // multicast destinations.
  Time  zero_time;
  zero_time.Zero();
  if (!last_qlam_time_.Initialize(bin_map_shm_))
  {
    LogW(kClassName, __func__, "Unable to initialize last QLAM time "
         "array.\n");
    return false;
  }
  last_qlam_time_.Clear(zero_time);

#ifdef DEBUG_STATS
  debugging_stats_ = new (std::nothrow) DebuggingStats();
  if (!debugging_stats_)
  {
    LogF(kClassName, __func__,
         "Error: Count not allocate debugging stats object.\n");
    return false;
  }
#endif // DEBUG_STATS

  queue_store_ = new (std::nothrow) QueueStore(
    packet_pool_, bin_map_shm_, weight_qd_shared_memory_);

  if (!queue_store_)
  {
    LogW(kClassName, __func__, "Unable to create new queue depth manager.\n");
    return false;
  }
  queue_store_->Initialize(config_info_, my_bin_idx_);
#ifdef DEBUG_STATS
  queue_store_->SetDebuggingStats(debugging_stats_);
#endif // DEBUG_STATS

  overhead_ratio_ = config_info_.GetFloat("Bpf.QlamOverheadRatio",
                                         overhead_ratio_);

  drop_expired_          = config_info_.GetBool("Bpf.Alg.DropExpired",
    kDefaultDropExpired);

  if (!dropped_bytes_.Initialize(bin_map_shm_))
  {
    LogW(kClassName, __func__, "Unable to initialize dropped bytes array.\n");
    return false;
  }
  dropped_bytes_.Clear(0);

  drop_dequeued_zombies_ = config_info_.GetBool(
    "Bpf.DropDequeuedZombies", kDefaultDropDequeuedZombies);
  drop_rcvd_zombies_     = config_info_.GetBool(
    "Bpf.DropRcvdZombies", kDefaultDropRcvdZombies);
  drop_expired_rcvd_packets_  = config_info_.GetBool(
    "Bpf.Laf.DropExpiredRcvdPackets", kDefaultDropExpiredRcvdPackets);
  mcast_fwding_          = config_info_.GetBool("Bpf.Alg.McastFwding",
    kDefaultMcastFwding);
  mcast_agg_             = config_info_.GetBool("Bpf.Alg.McastAgg",
    true);

  // Extract the Path Controller information.
  uint32_t  num_path_ctrls = config_info_.GetUint(
    "Bpf.NumPathControllers", 0, false);

  if (num_path_ctrls > kMaxPathCtrls)
  {
    LogE(kClassName, __func__, "Too many Path Controllers (%" PRIu32
         ") specified.\n", num_path_ctrls);
    return false;
  }

  for (uint32_t i = 0; i < num_path_ctrls; i++)
  {
    if (path_ctrls_[i].path_ctrl != NULL)
    {
      LogE(kClassName, __func__, "Path Controller %" PRIu32 " already "
           "created.\n", i);
      return false;
    }

    // Extract the Path Controller Type from the configuration file.
    string  config_prefix("PathController.");
    config_prefix.append(StringUtils::ToString(static_cast<int>(i)));
    config_prefix.append(".Type");

    string path_ctrl_type = config_info_.Get(config_prefix, "");

    // Create the Path Controller object.
    PathController*  path_ctrl = NULL;

    if (path_ctrl_type == "Sond")
    {
      path_ctrl = new (std::nothrow) Sond(this, packet_pool_, timer_);
    }
    else if (path_ctrl_type == "SliqCat")
    {
      path_ctrl = new (std::nothrow) SliqCat(this, packet_pool_, timer_);
    }
    else
    {
      LogE(kClassName, __func__, "Unknown Path Controller type %s.\n",
           path_ctrl_type.c_str());

      return false;
    }

    if (path_ctrl == NULL)
    {
      LogW(kClassName, __func__, "Unable to create new Path Controller %"
           PRIu32 " .\n",  i);
      return false;
    }

    // Add this Path Controller to the collection of configured Path
    // Controllers.
    path_ctrls_[i].path_ctrl         = path_ctrl;
    path_ctrls_[i].in_timer_callback = false;
    path_ctrls_[i].timer_handle.Clear();
    path_ctrls_[i].bucket_depth_bits = 0.0;
    path_ctrls_[i].link_capacity_bps = 0.0;
    path_ctrls_[i].last_qlam_tx_time.Zero();
    path_ctrls_[i].last_capacity_update_time.Zero();

    if (i >= num_path_ctrls_)
    {
      num_path_ctrls_ = (i + 1);
    }

    // Initialize the path controller.
    if ((!path_ctrl->Initialize(config_info_, i)) ||
        (!path_ctrl->ConfigurePddReporting(kPddThresh, kPddMinPeriodSec,
                                           kPddMaxPeriodSec)))
    {
      LogE(kClassName, __func__, "Unable to Initialize Path Controller %"
           PRIu32 ".\n", i);
      return false;
    }

    // Detect if the endpoints for the path controller have been reused.  This
    // is an error.
    Ipv4Endpoint  new_local_endpoint  = path_ctrl->local_endpt();
    Ipv4Endpoint  new_remote_endpoint = path_ctrl->remote_endpt();

    for (uint32_t j = 0; j < i; j++)
    {
      if ((path_ctrls_[j].path_ctrl != NULL) &&
          (path_ctrls_[j].path_ctrl->local_endpt() == new_local_endpoint) &&
          (path_ctrls_[j].path_ctrl->remote_endpt() == new_remote_endpoint))
      {
        LogE(kClassName, __func__, "Error, Path Controller %" PRIu32 " has "
             "same endpoints (%s->%s) as Path Controller %" PRIu32 ".\n", i,
             new_local_endpoint.ToString().c_str(),
             new_remote_endpoint.ToString().c_str(), j);
        return false;
      }
    }

    // Initialize the graphing of received QLAMs if needed.
    if (kGraphReceivedQlamVals)
    {
      BinIndex  bin_idx = kInvalidBinIndex;

      for (bool bin_idx_valid = bin_map_shm_.GetFirstDstBinIndex(bin_idx);
           bin_idx_valid;
           bin_idx_valid = bin_map_shm_.GetNextDstBinIndex(bin_idx))
      {
        BinIndex  dst_idx = kInvalidBinIndex;

        for (bool dst_idx_valid = bin_map_shm_.GetFirstUcastBinIndex(dst_idx);
             dst_idx_valid;
             dst_idx_valid = bin_map_shm_.GetNextUcastBinIndex(dst_idx))
        {
          GenXplot*  genxplot =
            queue_store_->GetBinQueueMgr(bin_idx)->GetQueueDepthsXplot(dst_idx);

          if (genxplot)
          {
            std::stringstream pclabel;

            pclabel << "Qlams from PC " << path_ctrl->path_controller_number();
            pclabel << ": " << path_ctrl->endpoints_str();

            genxplot->AddLineToKey(
              static_cast<iron::XPLOT_COLOR>(
                path_ctrl->path_controller_number() % NUM_COLORS),
              pclabel.str());
          }
        }
      }
    }
  }

  if (num_path_ctrls > 0)
  {
    per_qlam_overhead_bytes_ = path_ctrls_[0].path_ctrl->GetPerQlamOverhead();
  }

  multi_deq_          = config_info_.GetBool("Bpf.Alg.MultiDeq",
    kDefaultMultiDeq);

  xmit_buf_max_thresh_= config_info_.GetUint("Bpf.XmitQueueThreshBytes",
    kDefaultBpfXmitQueueThreshBytes);

  do_packet_tracing_ = config_info_.GetBool("PacketTrace",
                                           kDefaultPacketTrace);
  do_ttg_tracking_   = config_info_.GetBool("TtgTracking",
                                           kDefaultTtgTracking);

  string  ef_ordering_str = config_info_.Get("Bpf.Alg.EFOrdering", "");

  if (ef_ordering_str == "DeliveryMargin")
  {
    ef_ordering_  = EF_ORDERING_DELIVERY_MARGIN;
  }
  else if (ef_ordering_str == "Ttg")
  {
    ef_ordering_  = EF_ORDERING_TTG;
  }
  else if (ef_ordering_str == "None")
  {
    ef_ordering_  = EF_ORDERING_NONE;
  }
  else if (ef_ordering_str == "")
  {
    ef_ordering_  = kDefaultEFOrdering;
  }
  else
  {
    LogF(kClassName, __func__,
         "Did not recognize EF Ordering %s as valid.\n",
         ef_ordering_str.c_str());
    return false;
  }

  ls_latency_collection_  = config_info_.GetBool("LinkStateLatency",
    kDefaultLinkStateLatency);

  last_lsa_send_time_     = Time(0);
  lsa_interval_ms_        = config_info_.GetUint("Bpf.LsaIntervalMs",
    kDefaultLsaIntervalMs);
  conditional_dags_       = (config_info_.Get("Bpf.Alg.AntiCirculation",
                                             kDefaultAntiCirculation)
    == "ConditionalDAG") ? true : false;

  // Do not support conditional DAGS if we have bin ids that are too large.
  if (conditional_dags_)
  {
    // All of the unicast destination and interior node bin ids must be
    // between 0 and 13 for the latency cache key to fit all possible packet
    // history bin ids.
    BinIndex  phy_idx = kInvalidBinIndex;

    for (bool phy_valid = bin_map_shm_.GetFirstPhyBinIndex(phy_idx);
         phy_valid;
         phy_valid = bin_map_shm_.GetNextPhyBinIndex(phy_idx))
    {
      BinId  phy_id = bin_map_shm_.GetPhyBinId(phy_idx);

      if (phy_id > 13)
      {
        LogF(kClassName, __func__, "ConditionalDAGs cannot be used in "
             "networks having bin ids greater than 13 (found bin id %"
             PRIBinId ").\n", phy_id);
        return false;
      }
    }
  }

  incl_queue_delays_      = config_info_.GetBool("Bpf.Laf.IncludeQueuingDelays",
    kDefaultIncludeQueuingDelays);

  incl_link_capacity_     = config_info_.GetBool("Bpf.IncludeLinkCapacity",
    kDefaultIncludeLinkCapacity);

  // Initialize the shared memory latency cache.
  if (!shm_latency_cache_.Initialize())
  {
    LogF(kClassName, __func__, "Unable to initialize LatencyCacheShm.\n");
    return false;
  }

  // Initialize the latency cache hash table.
  if (!latency_cache_.Initialize(kLatencyCacheNumBuckets))
  {
    LogF(kClassName, __func__,
         "Initialize latency cache to %" PRIu16 " buckets failed.\n",
         kLatencyCacheNumBuckets);
    return false;
  }

  // Initialize the multicast group membership mash table.
  if (!mcast_group_cache_.Initialize(kMcastGroupsNumBuckets))
  {
    LogF(kClassName, __func__,
         "Initialize multicast groups to %" PRIu16 " buckets failed.\n",
         kMcastGroupsNumBuckets);
    return false;
  }

  // Extract Backpressure Forwarder algorithm info.
  string  bpf_alg       = config_info_.Get("Bpf.Alg.Fwder", kDefaultBpfwderAlg);

  string  bpf_anti_circ = config_info_.Get("Bpf.Alg.AntiCirculation",
    kDefaultAntiCirculation);

  if ((bpf_alg == "LatencyAware") &&
    (!do_ttg_tracking_ || !ls_latency_collection_))
  {
    LogF(kClassName, __func__,
         "Latency-aware fwding cannot operate without ttg tracking and latency "
         "sensing.\n");
    return false;
  }

  bpf_fwd_alg_  = new (std::nothrow) iron::UberFwdAlg(
    *this, packet_pool_, bin_map_shm_, queue_store_, packet_history_mgr_,
    num_path_ctrls_, path_ctrls_);

  if (!bpf_fwd_alg_)
  {
    LogW(kClassName, __func__, "Unable to create new Backpressure Forwarder "
         "algorithm.\n");
    return false;
  }

  // Break up the object creation and initialization to keep method signatures
  // reasonably small.
  bpf_fwd_alg_->Initialize(config_info_);

  // Preseed the virtual queues (will be left to 0 if the multiplier is set to 0.
  PreseedVirtQueues(config_info_);

  // If the local node is not an interior node, then initialize the
  // inter-process communications with the UDP and TCP Proxies.
  if (!is_int_node_)
  {
    if (!InitializeFifos())
    {
      return false;
    }
  }

  // Initialize the remote control communications server.
  uint16_t  rmt_cntl_port =
    static_cast<uint16_t>(config_info_.GetUint("Bpf.RemoteControl.Port",
                                              kDefaultBpfRmtCntlPort));

  if (!remote_control_.Initialize(rmt_cntl_port))
  {
    LogE(kClassName, __func__, "Unable to initialize remote control "
         "communications module.\n");
    return false;
  }

  // Extract the statistics collection interval.
  stats_interval_ms_ =
    config_info_.GetUint("Bpf.StatsCollectionIntervalMs",
                        kDefaultStatsCollectionIntervalMs);

  // Extract the directive that controls whether the statistics will be
  // logged.
  bool  log_stats = config_info_.GetBool("Bpf.LogStatistics",
                                        kDefaultLogStats);

  if (log_stats)
  {
    // Start logging the BpfStats
    bpf_stats_.StartDump();
  }

  // Log the configuration information.
  LogC(kClassName, __func__, "Backpressure Forwarder configuration:\n");
  LogC(kClassName, __func__, "Packet tracing                : %s\n",
       (do_packet_tracing_ ? "On" : "Off"));
  LogC(kClassName, __func__, "Ttg Tracking                  : %s\n",
       (do_ttg_tracking_ ? "On" : "Off"));
  LogC(kClassName, __func__, "EF Queue Ordering             : %s\n",
       EFOrdering_Name[ef_ordering_].c_str());
  LogC(kClassName, __func__, "LSA Latency Sensing           : %s\n",
       ls_latency_collection_ ? "On" : "Off");
  LogC(kClassName, __func__, "LSA interval in ms            : %" PRIu32 "\n",
    lsa_interval_ms_);
  LogC(kClassName, __func__, "LSA hold down time in ms      : %" PRIu32 "\n",
    lsa_hold_down_time_.GetTimeInMsec());
  LogC(kClassName, __func__, "Bpf.BinId                     : %" PRIBinId "\n",
       my_bin_id_);
  LogC(kClassName, __func__, "Bpf.RemoteControl.Port        : %" PRIu16 "\n",
       rmt_cntl_port);
  LogC(kClassName, __func__, "AntiCirculation               : %s\n",
       conditional_dags_ ? "Conditional DAGs" : "Not Conditional DAGs");
  LogC(kClassName, __func__, "Include Queuing Delay         : %s\n",
       incl_queue_delays_ ? "Yes" : "No");
  LogC(kClassName, __func__, "Include Link Capacity Est.    : %s\n",
       incl_link_capacity_ ? "Yes" : "No");
  LogC(kClassName, __func__, "Bpf.NumPathControllers        : %" PRIu32 "\n",
       num_path_ctrls);
  LogC(kClassName, __func__, "Bpf.QlamOverheadRatio         : %f%%\n",
       overhead_ratio_ * 100.0);
  LogC(kClassName, __func__, "Bpf.StatsCollectionIntervalMs : %" PRIu32 "\n",
       stats_interval_ms_);
  LogC(kClassName, __func__, "Bpf.LogStatistics             : %s\n",
       log_stats ? "true" : "false");
  LogC(kClassName, __func__, "Bpf.DropDequeuedZombies       : %s\n",
       drop_dequeued_zombies_ ? "true" : "false");
  LogC(kClassName, __func__, "Bpf.DropRcvdZombies           : %s\n",
       drop_rcvd_zombies_ ? "true" : "false");
  LogC(kClassName, __func__, "Bpf.Laf.DropExpiredRcvdPackets: %s\n",
       drop_expired_rcvd_packets_ ? "true" : "false");
  LogC(kClassName, __func__, "Bpf.SendGrams                 : %s\n",
       send_grams_ ? "true" : "false");
  LogC(kClassName, __func__, "Backpressure Forwarder configuration "
       "complete.\n");

  return true;
}

//============================================================================
void BPFwder::ResetFwdingAlg()
{
  bpf_fwd_alg_->ResetFwdingAlg(config_info_);

  conditional_dags_ = (config_info_.Get("Bpf.Alg.AntiCirculation", "NoChange")
    == "ConditionalDAG") ? true : false;

  // Log the configuration information.
  LogC(kClassName, __func__, "New Backpressure Forwarder configuration:\n");
  LogC(kClassName, __func__, "AntiCirculation : %s\n",
       conditional_dags_ ? "Conditional DAGs" : "Not Conditional DAGs");
  LogC(kClassName, __func__, "Backpressure Forwarder configuration "
       "complete.\n");
}

//============================================================================
void BPFwder::Start(uint32_t num_pkts_to_process, uint32_t max_iterations)
{
  LogI(kClassName, __func__, "Starting Backpressure Forwarder "
       "execution...\n");

  // Counters for halting unit tests.
  uint32_t pkts_processed = 0;
  uint32_t num_iterations = 0;

  running_ = true;

  // Do not schedule the first QLAM packet now: we do not know if the SOND or
  // CAT is connected yet, so sending a QLAM would result in the QLAM being
  // dropped.

  // Start the statistics collection timer.
  CallbackNoArg<BPFwder>  cbna(this, &BPFwder::PushStats);
  Time                    delta_time = Time::FromMsec(stats_interval_ms_);

  if (!timer_.StartTimer(delta_time, &cbna, stats_push_.timer_handle))
  {
    LogE(kClassName, __func__, "Error setting next statistics push timer.\n");
  }

  if (ls_latency_collection_)
  {
    // Set the periodic LSA timer (in case there are no udpates from the CATS).
    CallbackNoArg<BPFwder>  cb_lsa(this, &BPFwder::SendNewLsa);
    delta_time  = Time::FromMsec(lsa_interval_ms_);

    if (!timer_.StartTimer(delta_time, &cb_lsa, lsa_timer_handle_))
    {
      LogE(kClassName, __func__, "Failed to set LSA timer.\n");
    }
  }

  // If we are doing multicast forwarding and sending GRAMs then start
  // the periodic timer.
  if (mcast_fwding_ && send_grams_)
  {
    // Set the periodic GRAM timer.
    CallbackNoArg<BPFwder>  cb_gram(this, &BPFwder::SendGram);
    delta_time  = Time::FromMsec(gram_interval_ms_);

    if (!timer_.StartTimer(delta_time, &cb_gram, gram_timer_handle_))
    {
      LogE(kClassName, __func__, "Failed to set GRAM timer.\n");
    }
  }

  // The Backpressure Forwarder main event loop.
  //
  // - Wait in a select call for data to appear on a socket with a backstop
  //   time equal to the next expiration time of any timer events that are
  //   supposed to fire.
  // - Service the file descriptors.
  // - Service the timer events.
  // - Invoke the Backpressure Forwarder algorithm.

  fd_set           read_fds;
  fd_set           write_fds;
  size_t           num_path_ctrl_fds = 0;
  FdEventInfo      fd_event_info[kPathCtrlMaxFdCount];
  PathController*  path_ctrl_ptrs[kPathCtrlMaxFdCount];

  while (running_)
  {
    if (max_iterations != 0)
    {
      // Counter for halting unit tests.
      num_iterations++;
    }
    int  max_fd = -1;

    // Prepare for the ::select() call. Add our file descriptors to the
    // read and write sets and get the backstop time for the select() call.
    //
    // Start by adding the Path Controller file descriptors.
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    num_path_ctrl_fds = 0;

    for (size_t i = 0; i < num_path_ctrls_; ++i)
    {
      PathController*  pc = path_ctrls_[i].path_ctrl;

      if (pc == NULL)
      {
        continue;
      }

      size_t  num_fds = pc->GetFileDescriptors(
        &fd_event_info[num_path_ctrl_fds],
        (kPathCtrlMaxFdCount - num_path_ctrl_fds));

      for (size_t j = num_path_ctrl_fds; j < num_path_ctrl_fds + num_fds; ++j)
      {
        if ((fd_event_info[j].events == kFdEventRead) ||
            (fd_event_info[j].events == kFdEventReadWrite))
        {
          FD_SET(fd_event_info[j].fd, &read_fds);
        }

        if ((fd_event_info[j].events == kFdEventWrite) ||
            (fd_event_info[j].events == kFdEventReadWrite))
        {
          FD_SET(fd_event_info[j].fd, &write_fds);
        }

        path_ctrl_ptrs[j] = pc;

        if (max_fd < fd_event_info[j].fd)
        {
          max_fd = fd_event_info[j].fd;
        }
      }

      num_path_ctrl_fds += num_fds;
    }

    // If the local node is not an interior node, then add the file
    // descriptors for the inter-process communications with the UDP and TCP
    // proxies.
    if (!is_int_node_)
    {
      udp_to_bpf_pkt_fifo_.AddFileDescriptors(max_fd, read_fds);
      tcp_to_bpf_pkt_fifo_.AddFileDescriptors(max_fd, read_fds);
    }

    // Add the file descriptors for the remote control communications.
    remote_control_.AddFileDescriptors(max_fd, read_fds);

    // Get the next expiration time from the timer.
    Time            next_exp_time = timer_.GetNextExpirationTime(kBackstopTime);
    struct timeval  next_exp_time_tv = next_exp_time.ToTval();

    int  rv = ::select(max_fd + 1, &read_fds, &write_fds, NULL,
                       &next_exp_time_tv);

    if (rv < 0)
    {
      LogE(kClassName, __func__, "select() error %s.\n", strerror(errno));
    }
    else if (rv > 0)
    {
      // First, service the Path Controller file descriptors.
      for (size_t  i = 0; i < num_path_ctrl_fds; ++i)
      {
        bool  read_flag  = (FD_ISSET(fd_event_info[i].fd, &read_fds) != 0);
        bool  write_flag = (FD_ISSET(fd_event_info[i].fd, &write_fds) != 0);

        if (!read_flag && !write_flag)
        {
          continue;
        }

        FdEvent  event = (read_flag ? (write_flag ? kFdEventReadWrite
                                       : kFdEventRead)
                          : kFdEventWrite);

        LogD(kClassName, __func__, "Servicing fd %d, event %d.\n",
             fd_event_info[i].fd, event);

        path_ctrl_ptrs[i]->ServiceFileDescriptor(fd_event_info[i].fd, event);
      }

      // Next, service the UDP and TCP Proxies.  Only do this if the local
      // node is not an interior node.
      if (!is_int_node_)
      {
        // Service the UDP Proxy.
        if (udp_to_bpf_pkt_fifo_.InSet(&read_fds))
        {
          ReceiveFromProxy(udp_to_bpf_pkt_fifo_, "UDP");
        }

        // Service the TCP Proxy.
        if (tcp_to_bpf_pkt_fifo_.InSet(&read_fds))
        {
          ReceiveFromProxy(tcp_to_bpf_pkt_fifo_, "TCP");
        }
      }

      // Next, service the remote control communications.
      if (remote_control_.ServiceFileDescriptors(read_fds))
      {
        ProcessRemoteControlMessage();
      }
    }

    // Process the timer callbacks.
    timer_.DoCallbacks();

    // Do periodic adjustments of queue values. Note: this is not called
    // "periodically" since there is nothing regular about the timing other
    // than that it's once per select loop. Timing of any periodic behaviors
    // is done within the different queue depth managers.
    queue_store_->PeriodicAdjustQueueValues();

    // Execute the algorithm.
    size_t            path_ctrl_index;
    PathController*   path_ctrl;
    BinIndex          xmit_bin_idx;

    uint32_t          num_bytes_sent_since_shm_write = 0;

    uint8_t           num_solutions = kMaxNumSolutions;

    uint32_t          num_bytes_sent= 0;
    uint32_t          max_free_bytes= 0;

    if (multi_deq_)
    {
      for (size_t pc_index = 0; pc_index < num_path_ctrls_; ++pc_index)
      {
        PathController* path_ctrl = path_ctrls_[pc_index].path_ctrl;

        if (!path_ctrl)
        {
          continue;
        }

        size_t  current_pc_queue_size = 0;

        if (!(path_ctrl->GetXmitQueueSize(current_pc_queue_size)))
        {
          // This path controller does not have a current transmit queue size.
          // Maybe it is still connecting to a peer.  Move on.
          LogD(kClassName, __func__, "Path to nbr %" PRIBinId " currently "
               "has no queue.\n", path_ctrl->remote_bin_id());
          continue;
        }

        if (xmit_buf_max_thresh_ > current_pc_queue_size)
        {
          max_free_bytes += xmit_buf_max_thresh_ - current_pc_queue_size;
        }
      }

      LogD(kClassName, __func__,
           "There are %" PRIu32 "B of free space in the path controllers, "
           "allow at most this many bytes to be dequeued.\n", max_free_bytes);
    }

    // In multi-dequeue, dequeue at most as many bytes as there is free buffer
    // space among all path controllers.
    // Note: We do not consider path controller busy-ness as this requires some
    // more parameters to be shared between the fwding algorithm and this bpf
    // object.
    do
    {
      iron::TxSolution  solutions[kMaxNumSolutions];
      num_solutions       = 0;

      if ((num_solutions = bpf_fwd_alg_->FindNextTransmission(solutions,
        kMaxNumSolutions)) > 0)
      {
        for (uint8_t n = 0; n < num_solutions; ++n)
        {
          Packet* packet  = solutions[n].pkt;

          if (packet == NULL)
          {
            break;
          }
          path_ctrl_index = solutions[n].path_ctrl_index;
          xmit_bin_idx    = solutions[n].bin_idx;

          Time ttg;

          path_ctrl = path_ctrls_[path_ctrl_index].path_ctrl;

          bool     packet_has_ip_hdr       = packet->HasIpHeader();
          bool     packet_track_ttg        = packet->track_ttg();
          uint32_t packet_size_bytes       = packet->GetLengthInBytes();
          uint8_t  protocol                = 0;

          if (packet_has_ip_hdr && !packet->GetIpProtocol(protocol))
          {
            LogW(kClassName, __func__, "Failed to retrieve protocol from "
                 "packet.\n");
          }

          if (packet_track_ttg)
          {
            ttg = packet->GetTimeToGo();
            ttg = ttg - (Time::Now() - packet->recv_time());
          }

          num_bytes_sent_since_shm_write += packet->GetLengthInBytes();
          num_bytes_sent                 += packet->GetLengthInBytes();

          // Send the packet id if (a) someone already marked it (for instance,
          // if this packet arrived with metadata), (b) we are configured to do
          // packet tracing, or (c) we need it for latency sensing.
          packet->set_send_packet_id(packet->send_packet_id() ||
                                     do_packet_tracing_ ||
                                     packet->track_ttg());

          // Modify the flow statistics for the path controller. Note: If the
          // transmission fails or the path controller for some reason does not
          // transmit the packet, the accuracy of the flow statistics may
          // decrease.
          path_ctrls_[path_ctrl_index].flow_stats.Record(packet);

          // TODO This is a very inefficient way to drop zombies, since by now
          // we've generated a whole new packet and done some stuff with it. Fix
          // that if/when we decide dropping zombies on dequeue is the right
          // things to do. (For now, this is just keeping "drop instead of
          // dequeue" as a minimal change.)
          bool dropped_zombie = false;
          if (drop_dequeued_zombies_ ||
               ((packet->virtual_length() < kMinZombieLenBytes)
              && packet->IsZombie()))
          {
            dropped_zombie = true;
            LogD(kClassName, __func__, "RECV: Zombie Dequeued. Drop. (%p, %s)\n",
                 packet, packet->GetPacketMetadataString().c_str());
            TRACK_EXPECTED_DROP(kClassName, packet_pool_);
            packet_pool_.Recycle(packet);
          }
	  DstVec  dst_vec = packet->dst_vec();
          if (dropped_zombie || path_ctrl->SendPacket(packet))
          {
            // Ownership of packet has been transeferred to the path controller.
            packet = NULL;

            if (packet_has_ip_hdr)
            {
              bpf_stats_.IncrementNumDataBytesSentToBinOnPathCtrl(
                path_ctrl, xmit_bin_idx, packet_size_bytes,
		dst_vec);
            }
          }
          else
          {
            // DO NOT DROP THE PACKET HERE!!!!
            //
            // The packet should go back into the correct bin exactly where it
            // was before the forwarding algorithm dequeued it.  Dropping the
            // packet will lower the bin depths, and if enough packets are
            // dropped, then admission control will speed up, causing the
            // proxies to use more packets, .... BOOM!
            //
            // \todo The current APIs do not support putting the packet back
            // into the bin where it was before.  For now, treat the packet as
            // if it just arrived in order to at least get it back into the
            // correct bin.
            LogE(kClassName, __func__, "Error sending packet via Path "
                 "Controller. Re-enqueueing the packet.\n");
            ForwardPacket(packet, xmit_bin_idx);
            packet = NULL;
          }

          if (num_bytes_sent_since_shm_write >= min_qd_change_shm_bytes_)
          {
            if (!queue_store_->PublishWQueueDepthsToShm())
            {
              LogW(kClassName, __func__,
                   "Could not write queue depths to shared memory.\n");
            }
            else
            {
              LogD(kClassName, __func__,
                   "Wrote queue depths to shared memory early after sending %"
                   PRIu32 "B.\n", num_bytes_sent_since_shm_write);
              num_bytes_sent_since_shm_write  = 0;
              num_bytes_processed_            = 0;
            }
          }
        }
        if (num_pkts_to_process != 0)
        {
          // Counter for halting unit tests.
          pkts_processed += num_solutions;
        }
      }
    } while ((num_solutions > 0) && (multi_deq_ && (num_bytes_sent <
      max_free_bytes)));

    if (num_bytes_sent_since_shm_write + num_bytes_processed_ != 0)
    {
      if (!queue_store_->PublishWQueueDepthsToShm())
      {
        LogW(kClassName, __func__,
             "Could not write queue depths to shared memory.\n");
      }
      else
      {
        LogD(kClassName, __func__,
             "Wrote queue depths to shared memory after sending %" PRIu32
             "B and processing %" PRIu32 "B.\n",
             num_bytes_sent_since_shm_write,
             num_bytes_processed_);
      }
      num_bytes_processed_            = 0;
    }

    // Check if we need to halt for unit tests.
    if ((num_pkts_to_process != 0 && pkts_processed >= num_pkts_to_process) ||
        (max_iterations != 0 && num_iterations >= max_iterations))
    {
      running_ = false;
    }
  }
}

//============================================================================
void BPFwder::Stop()
{
  running_ = false;
}

//============================================================================
void BPFwder::BroadcastPacket(Packet* packet, BinIndex nbr_to_omit)
{
  for (size_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    // If the neighbor to omit is a valid bin index, then check this path
    // controller's remote bin index to see if it should be skipped.
    if ((nbr_to_omit != kInvalidBinIndex) &&
        (path_ctrls_[pc_i].path_ctrl->remote_bin_idx() == nbr_to_omit))
    {
      continue;
    }

    if (path_ctrls_[pc_i].path_ctrl)
    {
      // It is possible for each path controller to modify (e.g., add headers)
      // the packet passed to it.  Thus, perform a deep copy of the packet for
      // each path controller.
      Packet*  pkt_copy = packet_pool_.Clone(packet, true,
                                             iron::PACKET_COPY_TIMESTAMP);
      if (path_ctrls_[pc_i].path_ctrl->SendPacket(pkt_copy))
      {
        LogD(kClassName, __func__, "Sent packet %p over path controller %"
             PRIu8 " to nbr %" PRIBinId ".\n", pkt_copy,
             path_ctrls_[pc_i].path_ctrl->path_controller_number(),
             path_ctrls_[pc_i].path_ctrl->remote_bin_id());
        // The deep copy of packet is now owned by the path controller.
      }
      else
      {
        LogD(kClassName, __func__, "Packet %p failed transmission to nbr "
             "%" PRIBinId ".\n", pkt_copy,
             path_ctrls_[pc_i].path_ctrl->remote_bin_id());
        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        // This releases the deep copy of packet.  This method still owns the
        // original packet, though.
        packet_pool_.Recycle(pkt_copy);
      }
    }
  }
  // The caller still owns the packet that was passed to this method.
}

//============================================================================
void BPFwder::ReceiveFromProxy(PacketFifo& fifo, const char* proxy_name)
{
  // Read in packets from the proxy.  Errors are logged internally.
  while (fifo.Recv())
  {
    Packet *packet = NULL;
    while (fifo.GetNextRcvdPacket(&packet))
    {
      if (packet != NULL)
      {
        packet->set_bin_id(my_bin_id_);
        LogD(kClassName, __func__, "Received packet from proxy %s: %s\n",
             proxy_name, packet->GetPacketMetadataString().c_str());

        ProcessRcvdPacket(packet);
      }
    }
  }
}

//============================================================================
void BPFwder::ProcessRcvdPacket(Packet* packet, PathController* path_ctrl)
{
  // Figure out what type of packet we have received and process it
  // appropriately.
  PacketType  pkt_type = packet->GetType();

  if (path_ctrl)
  {
    LogD(kClassName, __func__, "Received packet type %x: %s\n",
         pkt_type, packet->GetPacketMetadataString().c_str());

    LogD(kClassName, __func__, "Got pkt with dst vec: 0x%X.\n",
         packet->dst_vec());
  }

  switch (pkt_type)
  {
    case QLAM_PACKET:
      ProcessQlam(packet, path_ctrl);
      break;

    case LSA_PACKET:
      ProcessBroadcastPacket(packet, path_ctrl);
      break;

    case ZOMBIE_PACKET:
    case IPV4_PACKET:
      ProcessIpv4Packet(packet, path_ctrl);
      break;

    default:
      LogF(kClassName, __func__, "Unknown packet type received: %" PRIu32
           "\n", pkt_type);
  }
}

//============================================================================
void BPFwder::ProcessIpv4Packet(Packet* packet, PathController* path_ctrl)
{
  if (packet_history_mgr_)
  {
    // Make sure we continue to track history.
    packet->set_send_packet_history(true);
    // Record that we've seen this packet.
    packet_history_mgr_->TrackHistory(packet, (path_ctrl == NULL));
    packet_history_mgr_->LogPacketHistory(packet);
  }

  uint8_t  protocol;

  if (!packet->GetIpProtocol(protocol))
  {
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  // Get the packet's destination address and port number.
  uint16_t       dport    = 0;
  struct iphdr*  ip_hdr   = packet->GetIpHdr();
  Ipv4Address    dst_addr(ip_hdr->daddr);

  packet->GetDstPort(dport);

  // Get the Bin Index from the destination address.
  BinIndex  bin_idx  = bin_map_shm_.GetDstBinIndexFromAddress(dst_addr);

  if (bin_idx == kInvalidBinIndex)
  {
    LogD(kClassName, __func__, "Unable to find Bin Index for received IPv4 "
         "packet with destination address %s.\n",
         dst_addr.ToString().c_str());

    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    packet = NULL;
    return;
  }

  if (packet->IsZombie() && drop_rcvd_zombies_)
  {
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    packet = NULL;
    return;
  }

  // Update statistics. If the path_ctrl is NULL path_ctrl, the packet
  // originated at either the UDP Proxy or the TCP Proxy. These packets are
  // not counted as "received packets".
  if (path_ctrl)
  {
    bpf_stats_.IncrementNumDataBytesRcvdForBinOnPathCtrl(
      path_ctrl, bin_idx, packet->GetLengthInBytes(), packet->dst_vec());
  }
  else if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP ||
           protocol == IPPROTO_ESP)
  {
    bpf_stats_.IncrementNumDataBytesRcvdForBinOnProxy(
      protocol, bin_idx, packet->GetLengthInBytes(), packet->dst_vec());
  }

  DstVec  dst_vec = packet->dst_vec();

  if ((!bin_map_shm_.IsMcastBinIndex(bin_idx)) && (dst_vec != 0))
  {
    struct iphdr*  ip_hdr = packet->GetIpHdr();
    dst_addr              = Ipv4Address(ip_hdr->daddr);
    LogF(kClassName, __func__, "Unicast packet (dst addr: %s, bin_idx: %"
         PRIBinIndex ") with non-zero dst vec %x\n",
         dst_addr.ToString().c_str(), bin_idx, dst_vec);
  }

  if (bin_map_shm_.IsOnlyBinInDstVec(dst_vec, my_bin_idx_) ||
      (bin_idx == my_bin_idx_))
  {
    LogD(kClassName, __func__, "RECV: Data packet for local node only.\n");
    if (packet->IsGram())
    {
      // It is a GRAM and needs to be processed locally.
      ProcessGram(packet);
      bin_map_shm_.Print();
    }
    else
    {
      // It is for the local application only.
      ProcessIpv4PacketForLocalApp(packet, protocol, bin_idx);
    }
    return;
  }
  else if (bin_map_shm_.IsBinInDstVec(dst_vec, my_bin_idx_))
  {
    LogD(kClassName, __func__,
         "RECV: Data packet for local & remote nodes: %X.\n",
         dst_vec);

    // It's for the local application as well as for remote destinations.
    DstVec  new_dst_vec = bin_map_shm_.RemoveBinFromDstVec(dst_vec,
                                                           my_bin_idx_);

    Packet* pkt_copy = packet_pool_.Clone(packet, true,
      iron::PACKET_COPY_TIMESTAMP);
    if (packet->IsGram())
    {
      // It is a GRAM and needs to be processed locally.
      ProcessGram(packet);
    }
    else
    {
      // It is for the local application only.
      ProcessIpv4PacketForLocalApp(pkt_copy, protocol, bin_idx);
      LogA(kClassName, __func__, "New dst vec is %X.\n", new_dst_vec);
    }
    packet->set_dst_vec(new_dst_vec);
    LogD(kClassName, __func__, "New dst vec is %X.\n", new_dst_vec);
  }
  // The received packet needs to be forwarded.
  LogD(kClassName, __func__,
       "RECV: Data packet for a bin: %s (if MGEN: sn %" PRIu32 ").\n",
       bin_map_shm_.GetIdToLog(bin_idx).c_str(), packet->GetMgenSeqNum());

  ForwardPacket(packet, bin_idx);
}

//============================================================================
void BPFwder::ProcessIpv4PacketForLocalApp(Packet* packet, uint8_t protocol,
                                           BinIndex bin_idx)
{
  // If the local node is an interior node, then there should never be a
  // packet destined to a local application.
  if (is_int_node_)
  {
    LogE(kClassName, __func__, "Error, interior nodes have no local "
         "applications.  Drop packet with protocol %" PRIu8 ".\n", protocol);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  if (packet->track_ttg())
  {
    packet->UpdateTimeToGo();
  }

  if (packet->IsZombie())
  {
    LogD(kClassName, __func__,
         "RECV: Zombie Data packet for a local application.  Drop.\n");
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  // Send the packet to the appropriate proxy.
  LogD(kClassName, __func__, "RECV: Data packet for a local application\n");

  if (drop_expired_rcvd_packets_ && packet->track_ttg() &&
    packet->time_to_go_valid() && (packet->GetTimeToGo() <= Time(0)))
  {
    LogW(kClassName, __func__,
         "Data packet is expired. Drop.\n");
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  PacketFifo* fifo = NULL;
  switch (protocol)
  {
    case IPPROTO_TCP:
      fifo = &bpf_to_tcp_pkt_fifo_;
      break;

    case IPPROTO_UDP:
    case IPPROTO_ESP:
      fifo = &bpf_to_udp_pkt_fifo_;

        if (protocol == IPPROTO_UDP)
        {
          uint16_t  dport;
          packet->GetDstPort(dport);
          if (ntohs(dport) == iron::kVxlanTunnelDstPort)
          {
            // We have received a UDP packet to the VXLAN destination port.
            struct iphdr*  ip_hdr = reinterpret_cast<struct iphdr*>(
              packet->GetBuffer(iron::kVxlanTunnelHdrLen));
            if (ip_hdr->protocol == IPPROTO_TCP)
            {
              // The protocol in the VXLAN inner IPv4 header indicates that
              // the packet is a TCP packet, so we will direct the received
              // packet to the TCP Proxy.
              fifo = &bpf_to_tcp_pkt_fifo_;
            }
          }
        }

      break;

    default:
      LogF(kClassName, __func__, "Unsupported IPv4 protocol received: %" PRIu8
           "\n", protocol);
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
      return;
  }

  bool  sent_pkt = false;

  // \todo Add ability to aggregate multiple packets into a single Send.
  if (fifo != NULL)
  {
    bool  fifo_is_open = fifo->IsOpen();

    if (!fifo_is_open)
    {
      fifo_is_open = fifo->OpenSender();

      if (!fifo_is_open)
      {
        LogW(kClassName, __func__, "Proxy packet FIFO not ready yet, packet "
             "will be dropped.\n");
      }
    }

    if (fifo_is_open)
    {
      sent_pkt = fifo->Send(packet);
    }
  }

  if (sent_pkt)
  {
    // If the Send() succeeds, the Packet in shared memory is being handed
    // over to the UDP proxy, so we cannot Recycle() it.
    bpf_stats_.IncrementNumDataBytesSentToBinOnProxy(protocol, bin_idx,
                                                     packet->GetLengthInBytes(),
						     packet->dst_vec());
  }
  else
  {
    // Send failed.
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
  }
}

//============================================================================
void BPFwder::SendQlamToPathCtrl(uint32_t path_ctrl_num, uint32_t sn)
{
  // Find the path controller information.
  if ((path_ctrl_num >= kMaxPathCtrls) ||
      (path_ctrls_[path_ctrl_num].path_ctrl == NULL))
  {
    LogE(kClassName, __func__, "Path controller number %" PRIu32
         " invalid or pointer is NULL.\n", path_ctrl_num);
    return;
  }

  PathCtrlInfo&  pc_info = path_ctrls_[path_ctrl_num];

  // Get the current time.
  Time  now;

  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Could not get current time.\n");
    return;
  }

  // Get a Packet to use for the QLAM packet.
  Packet*  packet = packet_pool_.Get();

  if (packet == NULL)
  {
    LogF(kClassName, __func__, "Unable to allocate a Packet.\n");
  }
  else
  {
    // Generate the QLAM.
    if (GenerateQlam(packet, pc_info.path_ctrl->remote_bin_idx(), sn))
    {
      // Record this QLAM packet's length in bits.
      last_qlam_size_bits_ = (packet->GetLengthInBytes() +
        per_qlam_overhead_bytes_) * 8;

      // Send the QLAM packet.
      //
      // Note that this can call back into ProcessCapacityUpdate(), so use the
      // in_timer_callback flag to avoid unnecessary timer resets.
      pc_info.in_timer_callback = true;
      if (!pc_info.path_ctrl->SendPacket(packet))
      {
        LogD(kClassName, __func__, "Error sending QLAM packet via Path "
             "Controller. Drop.\n");
        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        packet_pool_.Recycle(packet);
      }
      else
      {
        LogD(kClassName, __func__, "SEND QLAM: to pc %" PRIu32 " size %"
             PRIu32 " bits (%" PRIu32 " b w/ overhead).\n",
             pc_info.path_ctrl->path_controller_number(),
             last_qlam_size_bits_ - (per_qlam_overhead_bytes_ * 8),
             last_qlam_size_bits_);
      }

      packet                    = NULL;
      pc_info.in_timer_callback = false;
    }
    else
    {
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
      packet = NULL;
    }
  }

  // Reset the token bucket and reference times.
  pc_info.bucket_depth_bits         = 0.0;
  pc_info.last_qlam_tx_time         = now;
  pc_info.last_capacity_update_time = now;

  // Compute next QLAM send timer duration.
  Time  next_exp_time;

  if (ComputeNextQlamTimer(pc_info, next_exp_time))
  {
    uint32_t t_usec = (now.GetTimeInUsec() + next_exp_time.GetTimeInUsec())
                        & 0x00000000FFFFFFFF;
    LogD(kClassName, __func__, "QLAM sn: %u\n", t_usec);
    // Start a timer for the next QLAM send time.
    CallbackTwoArg<BPFwder, uint32_t, uint32_t>
      cb(this, &BPFwder::SendQlamToPathCtrl, path_ctrl_num, t_usec);

    if (!timer_.StartTimer(next_exp_time, &cb, pc_info.timer_handle))
    {
      LogE(kClassName, __func__, "Failed to set QLAM timer\n");
    }
  }
}

//============================================================================
bool BPFwder::InitializeFifos()
{
  // Initialize the inter-process communications with the UDP and TCP Proxies.
  if (!udp_to_bpf_pkt_fifo_.OpenReceiver())
  {
    LogE(kClassName, __func__, "Unable to open UDP proxy packet FIFO.\n");
    return false;
  }

  if (!tcp_to_bpf_pkt_fifo_.OpenReceiver())
  {
    LogE(kClassName, __func__, "Unable to open TCP proxy packet FIFO.\n");
    return false;
  }

  if (!bpf_to_udp_pkt_fifo_.OpenSender())
  {
    LogD(kClassName, __func__, "UDP proxy packet FIFO not ready yet.\n");
  }

  if (!bpf_to_tcp_pkt_fifo_.OpenSender())
  {
    LogD(kClassName, __func__, "TCP proxy packet FIFO not ready yet.\n");
  }

  return true;
}

//============================================================================
void BPFwder::PreseedVirtQueues(const ConfigInfo& config_info)
{
  // Expect virtual gradients to be entered by building queue depths.
  // Each node specifies what its virtual queue depths and its neighbors' should
  // be using a hop count and multiplier.
  // Bpf.VirtQueueDepths.Multiplier: Specifies multiplier M.
  // Bpf.VirtQueueDepths.X.Hops: Specifies number of hops H(X) to X.
  // The virtual queue depths is: M x H(X).

  // Look for the "Bpf.VirtQueueDepths.Multiplier" key.  If it is not
  // specified in the configuration, then use the default multiplier value
  // (already set in the class constructor) with LSA packets to dynamically
  // set the virtual queue depths, and do not look for any initial virtual
  // queue values in the configuration.
  string  vqd_mult_str = config_info.Get("Bpf.VirtQueueDepths.Multiplier",
                                         "");

  if (vqd_mult_str.empty())
  {
    return;
  }

  // Get the virtual queue depths multiplier to use.
  virt_queue_mult_ = config_info.GetUint("Bpf.VirtQueueDepths.Multiplier",
                                         kDefaultVirtQueueMult);

  // If the virtual queue depths multiplier is zero, then do not look for any
  // initial virtual queue values in the configuration, as they will all be
  // multiplied by zero.
  if (virt_queue_mult_ == 0)
  {
    return;
  }

  // A non-zero virtual queue multiplier has been specified.  Load in the
  // initial virtual queue values from the configuration.  Virtual queues can
  // only be configured for unicast destination and interior nodes
  // (i.e. neighbors), not for multicast destinations.
  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    BinId  bin_id = bin_map_shm_.GetPhyBinId(bin_idx);

    LogD(kClassName, __func__, "Setting the virtual queues for bin id %"
         PRIBinId ".\n", bin_id);

    string virt_queues_hops = config_info.Get("Bpf.VirtQueueDepths."
      + StringUtils::ToString(static_cast<uint32_t>(bin_id))
      + ".Hops", "");

    if (virt_queues_hops.empty())
    {
      LogW(kClassName, __func__, "Virtual queue configuration missing for "
           "bin %" PRIBinId ".\n", bin_id);
      return;
    }

    List<string>  tokens;
    StringUtils::Tokenize(virt_queues_hops, ",", tokens);

    List<string>::WalkState ws;
    ws.PrepareForWalk();

    string  token;

    while (tokens.GetNextItem(ws, token))
    {
      if (token.find(":") == string::npos)
      {
        LogF(kClassName, __func__, "Virtual queue configuration (%s) not "
             "readable.\n", token.c_str());
        continue;
      }

      List<string>  token_values;
      StringUtils::Tokenize(token, ":", token_values);

      string    nbr_bin_id_str;
      string    node_virt_queue_depth_hops;
      token_values.Pop(nbr_bin_id_str);
      token_values.Peek(node_virt_queue_depth_hops);

      uint32_t  nbr_bin_id            = StringUtils::GetUint(nbr_bin_id_str, 0);
      uint32_t  node_virt_queue_depth =
        StringUtils::GetUint(node_virt_queue_depth_hops, 0) * virt_queue_mult_;

      if (nbr_bin_id == my_bin_id_)
      {
        queue_store_->GetVirtQueueDepths()->SetBinDepthByIdx(bin_idx,
            node_virt_queue_depth);
	LogD(kClassName, __func__, "Setting virtual queue depth of %" PRIu32
             "B to reach node % " PRIBinId " via relay node % " PRIBinId
             ".\n", node_virt_queue_depth, bin_id, nbr_bin_id);
      }
      else
      {
        BinIndex  nbr_bin_idx = bin_map_shm_.GetPhyBinIndex(nbr_bin_id);

        if (nbr_bin_idx == kInvalidBinIndex)
        {
          LogE(kClassName, __func__, "Invalid virtual queue depth neighbor "
               "bin id %" PRIBinId ".\n", nbr_bin_id);
        }

        if (ApplyVirtQueueSet(bin_idx, nbr_bin_idx, node_virt_queue_depth))
        {
          // This should succeed almost solely for unit tests, where we cannot
          // wait for a QLAM that will never come.
	  LogD(kClassName, __func__, "Setting virtual queue depth of %" PRIu32
               "B to reach node %s via relay node %s.\n",
               node_virt_queue_depth,
               bin_map_shm_.GetIdToLog(bin_idx).c_str(),
	       bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());
        }
        else
        {
          // The path controller for this IP address was not found, very likely
          // because it is still early and the neighbors have not sent a first
          // QLAM (and the IP address associated with the path controller is
          // 0.0.0.0).  Try again when we receive a QLAM.
          LogF(kClassName, __func__, "Failed to set virtual queue depth for "
               "bin id %" PRIBinId ", will try again later (should not "
               "persist over connected link).\n", bin_id);
        }
      }
    }
  }
}

//============================================================================
void BPFwder::SendGram()
{
  Packet* gram = packet_pool_.Get(iron::PACKET_NOW_TIMESTAMP);
  gram->InitIpPacket();
  struct iphdr* iphdr = gram->GetIpHdr();

  if (!iphdr)
  {
    LogF(kClassName, __func__,
         "Failed to get IP header in new packet.\n");
    return;
  }

  // Encode the local node's BinId in a fake source address.
  in_addr_t  src_addr = htonl((static_cast<in_addr_t>(10) << 24) |
                              static_cast<in_addr_t>(my_bin_id_));

  LogD(kClassName, __func__, "Generating gram.\n");

  iphdr->id       = htons(packet_pool_.GetNextIpId());
  iphdr->protocol = IPPROTO_UDP;

  iphdr->saddr    = src_addr;
  iphdr->daddr    = kDefaultGramGrpAddr.address();

  gram->SetIpDscp(DSCP_EF);
  gram->SetTimeToGo(
    Time::FromUsec(static_cast<int64_t>(iron::kUnsetTimeToGo)));
  // Length is 20B.
  size_t  length          = gram->GetLengthInBytes();

  length                 +=  sizeof(struct udphdr);
  // Length is 28B.
  gram->SetLengthInBytes(length);

  gram->SetSrcPort(htons(kDefaultGramPort));
  gram->SetDstPort(htons(kDefaultGramPort));

  uint8_t*  buf           = gram->GetBuffer(gram->GetIpPayloadOffset());

  // Length is expected to be 32B.
  length += sizeof(uint32_t);

  if (length > kMaxPacketSizeBytes)
  {
    LogF(kClassName, __func__,
         "GRAM length %zd is larger than max packet size.\n", length);
    return;
  }

  uint32_t num_groups = htonl(mcast_group_memberships_.size());
  memcpy(buf, &num_groups, sizeof(uint32_t));
  buf += sizeof(uint32_t);

  // Start list of multicast groups.
  List<Ipv4Address>::WalkState ws;
  ws.PrepareForWalk();
  Ipv4Address mcast_group;

  while (mcast_group_memberships_.GetNextItem(ws, mcast_group))
  {
    length += sizeof(in_addr_t);

    if (length > kMaxPacketSizeBytes)
    {
      LogF(kClassName, __func__,
           "GRAM length %zd is larger than max packet size.\n", length);
      return;
    }
    in_addr_t grp_addr = mcast_group.address();
    memcpy(buf, &grp_addr, sizeof(in_addr_t));
    buf += sizeof(in_addr_t);
  }

  gram->SetLengthInBytes(length);
  gram->UpdateIpLen();
  gram->UpdateChecksums();

  LogD(kClassName, __func__,
       "Created GRAM with length %zuB, num grps: %" PRIu32 ".\n",
       length, num_groups);

  // Cancel timer if set.
  timer_.CancelTimer(gram_timer_handle_);

  // Reset the periodic GRAM timer.
  CallbackNoArg<BPFwder>  cb_gram(this, &BPFwder::SendGram);
  Time                    delta_time  = Time::FromMsec(gram_interval_ms_);

  if (!timer_.StartTimer(delta_time, &cb_gram, gram_timer_handle_))
  {
    LogE(kClassName, __func__, "Failed to set GRAM timer.\n");
  }

  BinIndex  bin_idx =
    bin_map_shm_.GetDstBinIndexFromAddress(kDefaultGramGrpAddr);

  if (bin_idx == kInvalidBinIndex)
  {
    LogE(kClassName, __func__, "Failed to get GRAM group address %s bin "
         "index.\n", kDefaultGramGrpAddr.ToString().c_str());
  }
  else
  {
    DstVec  dst_vec     = bin_map_shm_.GetMcastDst(bin_idx);
    DstVec  new_dst_vec = bin_map_shm_.RemoveBinFromDstVec(dst_vec,
                                                           my_bin_idx_);
    gram->set_dst_vec(new_dst_vec);

    LogD(kClassName, __func__, "Set GRAM with destination vector %X.\n",
         new_dst_vec);
  }

  ForwardPacket(gram, bin_idx);
}
//============================================================================
bool BPFwder::ProcessGram(Packet* gram)
{
  // TODO: Add a sequence number to GRAMs and check for wrapping.
  size_t  pkt_length  = gram->GetLengthInBytes();
  uint32_t src_addr;
  if (!gram->GetIpSrcAddr(src_addr))
  {
    LogF(kClassName, __func__, "Unable to get source IP from packet.\n");
  }
  BinId     src_bin_id  = static_cast<BinId>(ntohl(src_addr) & 0xff);
  BinIndex  src_bin_idx = bin_map_shm_.GetPhyBinIndex(src_bin_id);

  if (src_bin_idx == kInvalidBinIndex)
  {
    LogF(kClassName, __func__, "Error getting bin index for GRAM source "
         "address containing bin id %" PRIBinId ".\n", src_bin_id);
    return false;
  }

  size_t current_length = sizeof(struct iphdr) + sizeof(struct udphdr) +
      sizeof(uint32_t);

  if (pkt_length < current_length)
  {
    LogF(kClassName, __func__, "Packet of size %zd is too short for a "
         "GRAM.\n", pkt_length);
    return false;
  }

  bin_map_shm_.PurgeDstFromMcastGroups(src_bin_idx);

  uint8_t* buf = gram->GetBuffer(gram->GetIpPayloadOffset());
  uint32_t num_groups = 0;
  uint32_t group_addr;

  // Get the number of groups.
  memcpy(&num_groups, buf, sizeof(num_groups));
  buf += sizeof(num_groups);

  num_groups = ntohl(num_groups);

  LogD(kClassName, __func__,"========== GRAM: %s ============\n",
       Ipv4Address(src_addr).ToString().c_str());

  // Get the group memberships and update the bin maps.
  for (size_t i = 0; i < num_groups; i++)
  {
    if (pkt_length < (current_length + sizeof(uint32_t)))
    {
      LogF(kClassName, __func__, "GRAM packet shorter than expected.\n");
    }

    memcpy(&group_addr, buf, sizeof(group_addr));
    buf            += sizeof(group_addr);
    current_length += sizeof(group_addr);

    Ipv4Address  grp_ip_addr = Ipv4Address(group_addr);

    bin_map_shm_.AddDstToMcastGroup(grp_ip_addr, src_bin_idx);

    McastId   mcast_id = bin_map_shm_.GetMcastIdFromAddress(grp_ip_addr);
    BinIndex  idx      = bin_map_shm_.GetMcastBinIndex(mcast_id);

    if ((idx != kInvalidBinIndex) &&
        (queue_store_->GetBinQueueMgr(idx) == NULL))
    {
      queue_store_->AddQueueMgr(config_info_, idx, my_bin_idx_);
      LogD(kClassName, __func__," Add queue mgr for: %s\n",
           grp_ip_addr.ToString().c_str());
    }
  }
  LogD(kClassName, __func__,"========== END GRAM ============\n");

  return true;
}

//============================================================================
bool BPFwder::GenerateQlam(Packet* packet, BinIndex dst_bin_idx, uint32_t sn)
{
  size_t  max_length = packet->GetMaxLengthInBytes();

  // Add the type of message to the Packet (1 byte).
  size_t    offset  = 0;
  uint8_t*  buffer  = packet->GetBuffer(offset);
  *buffer           = static_cast<uint8_t>(QLAM_PACKET);
  offset           += sizeof(uint8_t);

  // Add the Source Node Bin Id to the Packet (1 byte).
  buffer   = packet->GetBuffer(offset);
  *buffer  = static_cast<uint8_t>(my_bin_id_);
  offset  += sizeof(uint8_t);

  // Add the Sequence Number in network byte order (4 bytes).
  uint32_t  sn_nbo = htonl(sn);
  memcpy(packet->GetBuffer(offset), &sn_nbo, sizeof(sn_nbo));
  offset += sizeof(sn_nbo);

  QueueDepths*  queue_depths  = NULL;
  if (!queue_store_)
  {
    LogF(kClassName, __func__, "Queue depth mgr NULL.\n");
    return false;
  }

  if (dst_bin_idx == my_bin_idx_)
  {
    LogW(kClassName, __func__, "Requested Qlam with destination as my bin "
         "index.\n");
    return false;
  }

  // Add the Number of Groups to be reported in the QLAM in network byte order
  // (2 bytes).  Set it to 1 here (since there will always be a unicast
  // group of "0.0.0.0"), then update the value as additional multicast groups
  // are added below.
  uint8_t*  num_groups_loc  = packet->GetBuffer(offset);
  uint16_t  num_groups      = 1;
  uint16_t  num_groups_nbo  = htons(num_groups);
  memcpy(num_groups_loc, &num_groups_nbo, sizeof(num_groups_nbo));
  offset                   += sizeof(num_groups_nbo);

  // Fill in the unicast portion of the QLAM.
  LogD(kClassName, __func__, "Serializing all ucast groups.\n");

  // Add the Group Id 0.0.0.0 (for unicast) in network byte order (4 bytes).
  memset(packet->GetBuffer(offset), 0, sizeof(McastId));
  offset += sizeof(McastId);

  // Add the Number of Queue Depth Pairs to be reported in the current Group
  // (1 byte).  Set it to 0 here, then update the value as additional pairs
  // are added below.
  uint8_t*  num_pairs_loc  = packet->GetBuffer(offset);
  uint8_t   num_pairs      = 0;
  *num_pairs_loc           = num_pairs;
  offset                  += sizeof(num_pairs);

  // Serialize the unicast group's pairs.
  BinIndex  group_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstUcastBinIndex(group_idx);
       valid;
       valid = bin_map_shm_.GetNextUcastBinIndex(group_idx))
  {
    uint8_t  curr_num_pairs = 0;
    LogD(kClassName, __func__, "Serializing ucast group bin id %" PRIBinId
         ".\n", bin_map_shm_.GetPhyBinId(group_idx));

    // Add serialization of the Queue Depth object to the packet.
    queue_depths = queue_store_->GetQueueDepthsForBpfQlam(group_idx);

    // Report these queue depths to the stats accumulator for averaging later.
    bpf_stats_.ReportQueueDepthsForBins(group_idx, queue_depths);

    size_t  payload_length = queue_depths->Serialize(
      packet->GetBuffer(offset), (max_length - offset), curr_num_pairs);

    if (curr_num_pairs > 1)
    {
      LogF(kClassName, __func__, "Unicast group serialized more than one "
           "(dst bin, count) pairs.\n");
      return false;
    }

    // Update the Number of Queue Depth Pairs in this Group (1 byte).
    num_pairs      += curr_num_pairs;
    *num_pairs_loc  = num_pairs;

    // Move the offset forward.
    offset += payload_length;

    if (max_length < offset)
    {
      LogW(kClassName, __func__, "Packet buffer too small for serialized "
           "QueueDepths.\n");
      return false;
    }
  }

  // Serialize the multicast groups.
  for (bool valid = bin_map_shm_.GetFirstMcastBinIndex(group_idx);
       valid;
       valid = bin_map_shm_.GetNextMcastBinIndex(group_idx))
  {
    if (queue_store_->AreQueuesEmpty(group_idx))
    {
      LogD(kClassName, __func__, "Skipping serializing mcast group mcast id %"
           PRIMcastId " (empty).\n", bin_map_shm_.GetMcastId(group_idx));
      continue;
    }
    LogD(kClassName, __func__, "Serializing mcast group mcast id %" PRIMcastId
         ".\n", bin_map_shm_.GetMcastId(group_idx));

    // Add the Multicast Group Id in network byte order (4 bytes).
    uint32_t  group_id_nbo = bin_map_shm_.GetMcastId(group_idx);
    memcpy(packet->GetBuffer(offset), &group_id_nbo, sizeof(group_id_nbo));
    offset += sizeof(group_id_nbo);

    // Add the Number of Queue Depth Pairs to be reported in the current Group
    // (1 byte).  Set it to 0 here, then update the value as additional pairs
    // are added below.
    num_pairs_loc  = packet->GetBuffer(offset);
    num_pairs      = 0;
    *num_pairs_loc = num_pairs;
    ++offset;

    // Add serialization of the Queue Depth object to the packet.
    queue_depths  = queue_store_->GetQueueDepthsForBpfQlam(group_idx);

    // Report these queue depths to the stats accumulator for averaging later.
    bpf_stats_.ReportQueueDepthsForBins(group_idx, queue_depths);

    size_t  payload_length  = queue_depths->Serialize(
      packet->GetBuffer(offset), (max_length - offset), num_pairs);

    // Update the Number of Queue Depth Pairs in this Group (1 byte).
    *num_pairs_loc  = num_pairs;

    // Update the Number of Groups (2 bytes).
    num_groups     += 1;
    num_groups_nbo  = htons(num_groups);
    memcpy(num_groups_loc, &num_groups_nbo, sizeof(num_groups_nbo));

    // Move the offset forward.
    offset += payload_length;

    if (max_length < offset)
    {
      LogW(kClassName, __func__, "Packet buffer too small for serialized "
           "QueueDepths.\n");
      return false;
    }
  }

  // Bump the number of times that the average queue depths have been updated
  bpf_stats_.IncrementNumberOfQueueDepthUpdates();

  if (!kGraphReceivedQlamVals)
  {
    if (!mcast_agg_)
    {
      // MCAST TODO don't blindly want index 0.
      LogA(kClassName, __func__, "QLAM: Generated: %s",
           queue_store_->GetQueueDepthsForBpfQlam(0)->ToString().c_str());
    }
    // MCAST TODO: passing around aggregate queue depths doesn't make sense.
//    else
//    {
//      LogA(kClassName, __func__,
//           "QLAM: Generated: %s\n%s",
//           queue_store_->GetDepthsForBpfQlam(0)->ToString().c_str(),
//           queue_store_->GetAggDepthsForBpfQlam(0)->ToString().c_str());
//    }
  }
  // string qd_dict = queue_depths->ToQdDict();
  // if (qd_dict.length() > 25)
  // {
  //   LogI(kClassName,__func__,"%s", qd_dict.c_str());
  // }

  // Set the length, in bytes, of the packet that was just generated.
  packet->SetLengthInBytes(offset);

  return true;
}

//============================================================================
void BPFwder::SendNewLsa()
{
  lsa_hold_down_  = false;
  Packet* packet  = GenerateLsa();
  if (packet)
  {
    BroadcastPacket(packet);
    // BroadcastPacket does NOT take control of and recycle the original
    // packet. It makes (deep) copies to be distributed.
    packet_pool_.Recycle(packet);
    last_lsa_send_time_ = Time::Now();
    packet = NULL;
  }

  // Cancel timer if set.
  timer_.CancelTimer(lsa_timer_handle_);

  // Reset the periodic LSA timer (in case there are no udpates from the CATS).
  CallbackNoArg<BPFwder>  cb_lsa(this, &BPFwder::SendNewLsa);
  Time                    delta_time  = Time::FromMsec(lsa_interval_ms_);

  if (!timer_.StartTimer(delta_time, &cb_lsa, lsa_timer_handle_))
  {
    LogE(kClassName, __func__, "Failed to set LSA timer.\n");
  }
  // Recompute the virtual queues.
  UpdateVirtQueues();
}

//============================================================================
Packet* BPFwder::GenerateLsa()
{
  // Use the NodeInfo constructor to initialize the values in the LSA
  // information array.  This method needs mean latency initialize to 0.
  // Note that the queue_delay_ member of NodeInfo is used to store the
  // neighbor latency standard deviation in this method.
  NodeInfo  def_info(0, 0, 0, -1.0);

  lsa_info_.Clear(def_info);

  NodeRecord*  node_record = AccessOrAllocateNodeRecord(my_bin_idx_);
  bool         clear_cache = false;
  bool         send_lsa    = false;

  if (node_record == NULL)
  {
    LogE(kClassName, __func__, "Error getting node record for my bin index %"
         PRIBinIndex ", cannot send LSA.\n", my_bin_idx_);
    return NULL;
  }

  LogD(kClassName, __func__, "Sending LSA...\n");

  // First, find the minimum latency (which is the estimated packet delivery
  // time for low-latency data packets) from a node to its neighbors,
  // including dual-homes.  Figure out how many neighbors there are while at
  // it.
  for (size_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    PathController*  path_ctrl = path_ctrls_[pc_i].path_ctrl;

    if (path_ctrl == NULL)
    {
      continue;
    }

    Time  pdd_mean(path_ctrls_[pc_i].pdd_mean_sec);
    Time  pdd_sd(path_ctrls_[pc_i].pdd_std_dev_sec);

    if (pdd_mean.IsZero())
    {
      LogD(kClassName, __func__, "Path ctrl %" PRIu8 " has no PDD.\n",
           path_ctrl->path_controller_number());
      continue;
    }

    // We can only represent this delay in 100us increments, so truncate and
    // use locally to be consistent across nodes.
    int64_t   pdd_val_us  = pdd_mean.GetTimeInUsec();
    uint64_t  pdd_var_us2 = 0;

    if (pdd_val_us < 100)
    {
      pdd_mean = Time::FromUsec(100);
    }
    else
    {
      pdd_mean = Time::FromUsec(((pdd_val_us + 50) / 100) * 100);
    }

    pdd_val_us  = pdd_sd.GetTimeInUsec();

    if (pdd_val_us <= 0)
    {
      pdd_sd      = Time::FromUsec(0);
      pdd_var_us2 = 0;
    }
    else
    {
      pdd_val_us  = (((pdd_val_us + 50) / 100) * 100);
      pdd_val_us  = (pdd_val_us > UINT16_MAX * 100) ? UINT16_MAX * 100 :
                    pdd_val_us;
      pdd_sd      = Time::FromUsec(pdd_val_us);
      pdd_var_us2 = pdd_val_us * pdd_val_us;
    }

    BinIndex  nbr_bin_idx  = path_ctrl->remote_bin_idx();

    if (nbr_bin_idx == iron::kInvalidBinIndex)
    {
      LogD(kClassName, __func__, "Failed to get valid neighbor bin index %"
           PRIBinIndex " for nbr %" PRIBinId " on path ctrl %" PRIu8 ".\n",
           nbr_bin_idx, path_ctrl->remote_bin_id(),
           path_ctrl->path_controller_number());
      continue;
    }

    LogD(kClassName, __func__, "Path ctrl %" PRIu32 " has distant nbr %"
         PRIBinId " with id %s.\n", path_ctrl->path_controller_number(),
         path_ctrl->remote_bin_id(),
         bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());

    // Detect multi-homes.
    if (lsa_info_[nbr_bin_idx].nbr_lat_mean_ != 0)
    {
      if (lsa_info_[nbr_bin_idx].nbr_lat_mean_ < pdd_mean.GetTimeInUsec())
      {
        continue;
      }
    }

    // Make sure not 0 and "round" so that local info is same as that provided
    // to neighbors.
    lsa_info_[nbr_bin_idx].nbr_lat_mean_ = pdd_mean.GetTimeInUsec();
    lsa_info_[nbr_bin_idx].nbr_lat_var_  = pdd_var_us2;
    lsa_info_[nbr_bin_idx].queue_delay_  = pdd_sd.GetTimeInUsec();

    LogD(kClassName, __func__, "PDD to nbr id %s is %" PRIu32
         "us (sd=%" PRIu32 "us).\n",
         bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str(),
         lsa_info_[nbr_bin_idx].nbr_lat_mean_,
         lsa_info_[nbr_bin_idx].queue_delay_);

//    if ((lsa_info_[nbr_bin_idx].nbr_lat_mean_ > 100) ||
//        (lsa_info_[nbr_bin_idx].queue_delay_ > 100))
    if ((lsa_info_[nbr_bin_idx].nbr_lat_mean_ > 0) ||
        (lsa_info_[nbr_bin_idx].queue_delay_ > 0))
    {
      send_lsa  = true;
    }

    NodeInfo&  node_info = node_record->records_[nbr_bin_idx];

    node_info.nbr_lat_mean_ = lsa_info_[nbr_bin_idx].nbr_lat_mean_;
    node_info.nbr_lat_var_  = lsa_info_[nbr_bin_idx].nbr_lat_var_;

    uint8_t e                                     = 0;
    uint8_t i                                     = 0;
    uint8_t d                                     = 0;
    GetEncodedCapacity(nbr_bin_idx, e, i, d);
    node_info.capacity_ = DecodeCapacity(e, i, d);
    clear_cache = true;
  }

  // Consider clearing the cache.
  if (clear_cache)
  {
    LogD(kClassName, __func__, "Resetting cache.\n");
    latency_cache_reset_time_ = Time::Now();
  }

  if (!send_lsa)
  {
    LogD(kClassName, __func__, "No latency numbers to neighbors.  Not "
         "sending LSA.\n");
    return NULL;
  }

  Time  now = Time::Now();
  if ((now - last_lsa_send_time_) <= lsa_hold_down_time_)
  {
    // Not time to send yet.
    return NULL;
  }

  Packet* lsa = packet_pool_.Get(iron::PACKET_NOW_TIMESTAMP);

  lsa->PopulateBroadcastPacket(
    LSA_PACKET, my_bin_id_, GetAndIncrLSASeqNum());

  if (!lsa)
  {
    LogF(kClassName, __func__, "Failed to allocate LSA packet.\n");
    return NULL;
  }

  size_t    pkt_len = lsa->GetLengthInBytes();
  uint8_t*  buffer  = lsa->GetBuffer(pkt_len);

  // Number of neighbors listed in LSA, followed by:
  // 3 bytes padding or
  // the number of bins if queuing delays are included, and 2B padding
  // to keep the packet word-aligned.
  uint8_t*  num_nbrs_loc  = buffer;
  ++buffer;
  ++pkt_len;

  // Get latency to destinations.
  uint8_t* capacity_flag_loc = buffer + 1;
  size_t   num_bins          = bin_map_shm_.GetNumUcastBinIds();
  if (!incl_queue_delays_)
  {
    memset(buffer, 0, 3 * sizeof(uint8_t));
    buffer  += 3;
    pkt_len += 3;
  }
  else
  {
    // Copy all of the average queue delays for all unicast and multicast bin
    // indexes from the forwarding algorithm into the node record.
    // TODO: Is this copy of average queue delays correct?  The node record
    // queue delays are also set in ProcessLsa()!
    BinIndex  copy_bin_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstDstBinIndex(copy_bin_idx);
         valid;
         valid = bin_map_shm_.GetNextDstBinIndex(copy_bin_idx))
    {
      node_record->records_[copy_bin_idx].queue_delay_ =
        bpf_fwd_alg_->GetAvgQueueDelay(copy_bin_idx);
    }

    // The queuing delays are included, add number of bins then padding.
    *buffer = static_cast<uint8_t>(num_bins);
    ++buffer;
    ++pkt_len;

    memset(buffer, 0, 2 * sizeof(uint8_t));
    buffer  += 2;
    pkt_len += 2;
  }

  if (incl_link_capacity_)
  {
    *capacity_flag_loc  |= 0x1;
  }

  uint8_t num_nbrs  = 0;

  // Neighbor list with latency. Each looks like:
  /// \verbatim
  ///  0                   1                   2                   3
  ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// |  BinId        |          Mean Latency         |  Mean Std Dev
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// | Mean Std Dev  |  Bin Id ...
  /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /// \endverbatim
  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    uint16_t nbr_latency_mean = MAX_INT(1, (lsa_info_[bin_idx].nbr_lat_mean_ /
                                            100));
    uint16_t nbr_latency_sd   = MAX_INT(1, (lsa_info_[bin_idx].queue_delay_ /
                                            100));
    // if ((nbr_latency_mean + nbr_latency_sd) != 0)
    if ((lsa_info_[bin_idx].nbr_lat_mean_ +
         lsa_info_[bin_idx].queue_delay_) > 0)
    {
      *buffer = bin_map_shm_.GetPhyBinId(bin_idx);
      ++buffer;
      ++pkt_len;

      uint16_t nbr_lat_mean_nbo = htons(nbr_latency_mean);
      memcpy(buffer, &nbr_lat_mean_nbo, sizeof(nbr_latency_mean));
      buffer  += sizeof(nbr_latency_mean);
      pkt_len += sizeof(nbr_latency_mean);
      uint16_t nbr_lat_sd_nbo = htons(nbr_latency_sd);
      memcpy(buffer, &nbr_lat_sd_nbo, sizeof(nbr_latency_sd));
      buffer  += sizeof(nbr_latency_sd);
      pkt_len += sizeof(nbr_latency_sd);

      ++num_nbrs;

      if (incl_link_capacity_)
      {
        // Store as two bytes:
        //  0              .    1          .
        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // |   e   |   i   |       d       |
        // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        uint8_t e = 0;
        uint8_t i = 0;
        uint8_t d = 0;

        GetEncodedCapacity(bin_idx, e, i, d);
        e = (e << 4) | (i & 0xF);
        // Copy e and i.
        *buffer = e;
        ++buffer;
        ++pkt_len;
        // Copy d.
        *buffer = d;
        ++buffer;
        ++pkt_len;
      }
    }
    else
    {
      if (my_bin_idx_ != bin_idx)
      {
        LogD(kClassName, __func__, "Neighbor latency to bin %s"
             " is 0, packet length is %zuB.\n",
             bin_map_shm_.GetIdToLog(bin_idx).c_str(), pkt_len);
      }
    }
  }

  if (incl_queue_delays_)
  {
    std::stringstream bids_ss;
    std::stringstream qdel_ss;

    // List of bin Id - queuing delays.
    /// \verbatim
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Bin Id 0    |      Queuing Delay to Bin Id 0                |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Bin Id 1    |      Queuing Delay to Bin Id 1                |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   Bin Id 2    |      Queuing Delay to Bin Id 2    ...         |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// \endverbatim

    // Include queueing delays for all unicast destinations only.  Interior
    // nodes have bin indexes, but they are not destinations for packets.
    // Note that multicast destinations do not have BinIds, so they cannot be
    // included.
    BinIndex  bin_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstUcastBinIndex(bin_idx);
         valid;
         valid = bin_map_shm_.GetNextUcastBinIndex(bin_idx))
    {
      BinId     dst_bin_id  = bin_map_shm_.GetPhyBinId(bin_idx);
      uint32_t  queue_delay = node_record->records_[bin_idx].queue_delay_;

      bids_ss << std::setw(4);
      bids_ss << StringUtils::ToString(dst_bin_id) << " ";
      qdel_ss << std::setw(4);
      qdel_ss << (queue_delay & 0xFFFFFF00);
      qdel_ss << " ";

      *buffer = dst_bin_id;
      ++buffer;
      ++pkt_len;

      uint32_t  delay_nbo = htonl(queue_delay);

      memcpy(buffer, reinterpret_cast<uint8_t*>(&delay_nbo), 3);
      buffer  += 3;
      pkt_len += 3;
    }
    LogD(kClassName, __func__,
         "BinIds:   %s\n", bids_ss.str().c_str());
    LogD(kClassName, __func__,
         "Q Delays: %s\n", qdel_ss.str().c_str());
  }

  *num_nbrs_loc = num_nbrs;

  // Update the packet length, since we modified the buffer by hand instead of
  // using packet functions.
  lsa->SetLengthInBytes(pkt_len);

  LogD(kClassName, __func__, "Generated LSA packet %" PRIu16
       " (%p) of size %zuB for %" PRIu8 " nbrs.\n",
       broadcast_seq_nums_[LSA_BC_IDX][my_bin_idx_] - 1, lsa, pkt_len,
       num_nbrs);

  return lsa;
}

//============================================================================
void BPFwder::ProcessQlam(Packet* packet, PathController* path_ctrl)
{
  size_t        offset       = sizeof(uint8_t);  // Skip the type (1 byte).
  QueueDepths*  queue_depths = NULL;

  // Get the remote node's Bin Id (1 byte), convert it to a Bin Index, and
  // store it in the Path Controller.
  BinId  nbr_bin_id = static_cast<BinId>(*(packet->GetBuffer(offset)));
  offset += sizeof(uint8_t);

  // Convert the neighbor's global Bin Id to a local Bin Index.
  BinIndex  nbr_bin_idx = bin_map_shm_.GetPhyBinIndex(nbr_bin_id);

  if (nbr_bin_idx == kInvalidBinIndex)
  {
    LogE(kClassName, __func__, "Invalid QLAM source bin id %" PRIBinId
         ", ignoring received QLAM.\n", nbr_bin_id);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  // Store the Bin Index in the Path Controller if needed.
  if (path_ctrl->remote_bin_idx() == kInvalidBinIndex)
  {
    path_ctrl->set_remote_bin_id_idx(nbr_bin_id, nbr_bin_idx);
  }
  else if (nbr_bin_idx != path_ctrl->remote_bin_idx())
  {
    LogE(kClassName, __func__, "Received QLAM source bin index %" PRIBinIndex
         " does not match the path controller's stored bin index %"
         PRIBinIndex ", ignoring received QLAM.\n", nbr_bin_idx,
         path_ctrl->remote_bin_idx());
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  // Get the Sequence Number (4 bytes).
  uint32_t  seq_num = 0;
  std::memcpy(&seq_num, packet->GetBuffer(offset), sizeof(seq_num));
  seq_num  = ntohl(seq_num);
  offset  += sizeof(seq_num);

  LogD(kClassName, __func__, "Received QLAM from nbr %" PRIBinId " (bin idx %"
       PRIBinIndex ") with seq num %" PRIu32 " on path ctrl to nbr %" PRIBinId
       ".\n", nbr_bin_id, nbr_bin_idx, seq_num, path_ctrl->remote_bin_id());

  // Check if this is a stale QLAM. If we havent seen a QLAM in kMaxQlamInt
  // then just accept this one.
  Time  now = Time::Now();
  if ((seq_num - qlam_sequence_number_[nbr_bin_idx]) < 0x7FFFFFFF ||
      now > (last_qlam_time_[nbr_bin_idx] + kMaxQlamInt) ||
      last_qlam_time_[nbr_bin_idx].IsZero())
  {
    last_qlam_time_[nbr_bin_idx]       = now;
    qlam_sequence_number_[nbr_bin_idx] = seq_num;
  }
  else
  {
    LogW(kClassName, __func__, "Stale QLAM with sequence number %" PRIu32
         ", object sequence number is still %" PRIu32 ", received from nbr %"
         PRIBinId " (bin idx %" PRIBinIndex ") on path ctrl to nbr %" PRIBinId
         ".\n", seq_num, qlam_sequence_number_[nbr_bin_idx], nbr_bin_id,
         nbr_bin_idx, path_ctrl->remote_bin_id());
    num_stale_qlams_rcvd_++;
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  // Get the Number of Groups (2 bytes).
  size_t    total_deserialized_bytes = 0;
  uint16_t  num_groups               = 0;
  memcpy(&num_groups, packet->GetBuffer(offset), sizeof(num_groups));
  num_groups  = ntohs(num_groups);
  offset     += sizeof(num_groups);

  if (num_groups < 1)
  {
    LogE(kClassName, __func__, "QLAM number of groups is %" PRIu16 ". "
         "Malformed.\n", num_groups);
    packet_pool_.Recycle(packet);
    return;
  }

  LogD(kClassName, __func__, "QLAM lists %" PRIu16 " groups, will dump queue "
       "depths.\n", num_groups);

  // Get the first Group's Id (4 bytes), which should be "0.0.0.0" for
  // unicast.
  McastId  group_id = 0;
  memcpy(&group_id, packet->GetBuffer(offset), sizeof(group_id));
  offset += sizeof(group_id);

  if (group_id != 0)
  {
    LogF(kClassName, __func__, "QLAM first group id is %" PRIMcastId ", not "
         "unicast. Malformed.\n", ntohl(group_id));
    packet_pool_.Recycle(packet);
    return;
  }

  // Get the number of unicast Queue Depth Pairs (1 byte).
  uint8_t  num_pairs = *(packet->GetBuffer(offset));
  offset += sizeof(num_pairs);

  if (num_pairs == 0)
  {
    LogD(kClassName, __func__, "QLAM contains 0 pairs for unicast.\n");
  }

  // Get the unicast Queue Depths.
  while (num_pairs > 0)
  {
    if (packet->GetLengthInBytes() <= offset)
    {
      LogF(kClassName, __func__, "At %zuB, pointer has reached the end of "
           "the packet's %zuB.\n", offset, packet->GetLengthInBytes());
      packet_pool_.Recycle(packet);
      return;
    }

    // Peek at the Destination Bin Id (1 byte).  Do NOT update the offset
    // here, because we want to re-read the Bin Id from within Deserialize()
    // for the unicast case.
    BinId  dst_bin_id = *(packet->GetBuffer(offset));

    if (!bin_map_shm_.UcastBinIdIsInValidRange(dst_bin_id))
    {
      LogW(kClassName, __func__, "Received invalid bin id %" PRIBinId " in "
           "QLAM for group %" PRIMcastId ".\n", dst_bin_id, group_id);
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
      return;
    }

    BinIndex  dst_bin_idx = bin_map_shm_.GetPhyBinIndex(dst_bin_id);

    queue_depths = queue_store_->PeekNbrQueueDepths(dst_bin_idx, nbr_bin_idx);

    if (!queue_depths)
    {
      // There is no QueueDepths object in the neighbor queue depths
      // collection for the provided neighbor id, so we'll create one and add
      // it to the collection.
      queue_depths = new (std::nothrow) QueueDepths(bin_map_shm_);

      if (queue_depths == NULL)
      {
        LogW(kClassName, __func__, "Error dynamically allocating QueueDepths "
             "object.\n");

        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        packet_pool_.Recycle(packet);
        return;
      }

      queue_store_->SetNbrQueueDepths(dst_bin_idx, nbr_bin_idx,
                                      queue_depths);
    }

    size_t  deserialized_bytes =
      queue_depths->Deserialize(packet->GetBuffer(offset),
                                (packet->GetLengthInBytes() - offset), 1);

    if (deserialized_bytes == 0)
    {
      LogW(kClassName, __func__, "Unable to deserialize received QLAM packet "
           "for group %" PRIMcastId ".\n", group_id);
    }
    else
    {
      LogD(kClassName, __func__, "Ucast dst %" PRIBinId " (Index %"
           PRIBinIndex " translates to %s): %s.\n", dst_bin_id, dst_bin_idx,
           bin_map_shm_.GetIdToLog(dst_bin_idx).c_str(),
           queue_depths->ToString().c_str());
    }

    offset                   += deserialized_bytes;
    total_deserialized_bytes += deserialized_bytes;

    --num_pairs;
  }

  // Get the multicast Queue Depths.
  for (uint8_t group_i = 1; group_i < num_groups; ++group_i)
  {
    if (packet->GetLengthInBytes() <= offset)
    {
      LogF(kClassName, __func__, "At %zuB, pointer has reached the end of "
           "the packet's %zuB.\n", offset, packet->GetLengthInBytes());
      packet_pool_.Recycle(packet);
      return;
    }

    // Get the multicast Group Id (4 bytes).
    memcpy(&group_id, packet->GetBuffer(offset), sizeof(group_id));
    offset   += sizeof(group_id);

    BinIndex  group_idx = bin_map_shm_.GetMcastBinIndex(group_id);

    if (group_idx == kInvalidBinIndex)
    {
      LogF(kClassName, __func__, "Group/Bin id %s does not exist, cannot set "
           "queues.\n", bin_map_shm_.GetIdToLog(group_idx).c_str());
      packet_pool_.Recycle(packet);
      return;
    }

    // Get the number of multicast Queue Depth Pairs (1 byte).
    num_pairs  = *(packet->GetBuffer(offset));
    offset    += sizeof(num_pairs);

    queue_depths = queue_store_->PeekNbrQueueDepths(group_idx, nbr_bin_idx);

    if (!queue_depths)
    {
      // There is no QueueDepths object in the neighbor queue depths
      // collection for the provided neighbor id, so we'll create one and add
      // it to the collection.
      queue_depths = new (std::nothrow) QueueDepths(bin_map_shm_);

      if (queue_depths == NULL)
      {
        LogW(kClassName, __func__, "Error dynamically allocating QueueDepths "
             "object.\n");

        TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
        packet_pool_.Recycle(packet);
        return;
      }

      queue_store_->SetNbrQueueDepths(group_idx, nbr_bin_idx, queue_depths);
    }

    size_t  deserialized_bytes =
      queue_depths->Deserialize(packet->GetBuffer(offset),
                                (packet->GetLengthInBytes() - offset),
                                num_pairs);

    if ((num_pairs > 0) && (deserialized_bytes == 0))
    {
      LogW(kClassName, __func__, "Unable to deserialize received QLAM packet "
           "for group %" PRIMcastId ".\n", group_id);
    }
    else
    {
      LogD(kClassName, __func__, "Group id %s: %s.\n",
           bin_map_shm_.GetIdToLog(group_idx).c_str(),
           queue_depths->ToString().c_str());
    }

    offset                   += deserialized_bytes;
    total_deserialized_bytes += deserialized_bytes;
  }

  if (kGraphReceivedQlamVals || kGraphDroppedBytes)
  {
    BinIndex  bin_idx = kInvalidBinIndex;

    for (bool bin_idx_valid = bin_map_shm_.GetFirstDstBinIndex(bin_idx);
         bin_idx_valid;
         bin_idx_valid = bin_map_shm_.GetNextDstBinIndex(bin_idx))
    {
      BinIndex  dst_idx = 0;

      for (bool dst_idx_valid = bin_map_shm_.GetFirstUcastBinIndex(dst_idx);
           dst_idx_valid;
           dst_idx_valid = bin_map_shm_.GetNextUcastBinIndex(dst_idx))
      {
        GenXplot* genxplot =
          queue_store_->GetBinQueueMgr(bin_idx)->GetQueueDepthsXplot(dst_idx);
        if (genxplot)
        {
          if (kGraphReceivedQlamVals)
          {
            genxplot->DrawPoint(
              Time::GetNowInUsec() - iron::kStartTime,
              queue_depths->GetBinDepthByIdx(bin_idx),
              static_cast<iron::XPLOT_COLOR>(
                path_ctrl->path_controller_number() % NUM_COLORS),
              XPLOT_DIAMOND);
          }
          if (kGraphDroppedBytes)
          {
            genxplot->DrawPoint(
              Time::GetNowInUsec() - iron::kStartTime,
              dropped_bytes_[bin_idx],
              ORANGE, XPLOT_DARROW);
            dropped_bytes_[bin_idx] = 0;
          }
        }
      }
    }
  }

  packet_pool_.Recycle(packet);
}

//============================================================================
void BPFwder::ProcessRemoteControlMessage()
{
  // Switch on the type of request message.
  RmtCntlMsgType  msg_type = remote_control_.msg_type();

  switch (msg_type)
  {
    case RC_SET:
      ProcessSetMessage();
      break;

    case RC_GET:
      ProcessGetMessage();
      break;

    case RC_PUSHREQ:
      ProcessPushReqMessage();
      break;

    case RC_PUSHSTOP:
      ProcessPushStopMessage();
      break;

    case RC_INVALID:
    default:
      LogE(kClassName, __func__, "Unknown remote control message type: %d\n",
           static_cast<int>(msg_type));

      // Abort this client connection.
      remote_control_.AbortClient();
  }
}

//============================================================================
void BPFwder::ProcessSetMessage()
{
  bool          success  = false;
  const Value*  key_vals = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetSetMessage(target, key_vals)) ||
      (key_vals == NULL))
  {
    LogE(kClassName, __func__, "Error getting remote control set message.\n");
    remote_control_.SendSetReplyMessage(false, "Message processing error.");
    return;
  }

  LogD(kClassName, __func__, "Processing remote control set message for "
       "target %s.\n", target.c_str());

  // ---------- BPF target ----------
  if (target == "bpf")
  {
    success = ProcessBpfSetMessage(key_vals, err_msg);
    remote_control_.SendSetReplyMessage(success, err_msg);
    return;
  }

  // ---------- Path Controller target ----------
  if (target.substr(0, 3) == "pc:")
  {
    success = ProcessPcSetMessage(target, key_vals, err_msg);
    remote_control_.SendSetReplyMessage(success, err_msg);
    return;
  }

  LogE(kClassName, __func__, "Unknown remote control set message target: "
       "%s\n", target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.SendSetReplyMessage(false, err_msg);
}

//============================================================================
void BPFwder::ProcessGetMessage()
{
  bool          success = false;
  const Value*  keys    = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetGetMessage(target, keys)) || (keys == NULL))
  {
    LogE(kClassName, __func__, "Error getting remote control get message.\n");
    remote_control_.StartGetReplyMessage(false, "Message processing error.");
    remote_control_.SendGetReplyMessage(false);
    return;
  }

  LogD(kClassName, __func__, "Processing remote control get message for "
       "target %s.\n", target.c_str());

  // ---------- Bpf target ----------
  if (target == "bpf")
  {
    string  key = "";
    success     = true;

    // Only support the "stats", "capacities" and "cap_and_lat" keys right now, so make this
    // loop simple.
    for (SizeType i = 0; i < keys->Size(); ++i)
    {
      if ((*keys)[i].IsString())
      {
        key = (*keys)[i].GetString();

        if ((key == "stats") ||
	    (incl_link_capacity_ && (key == "capacities")) ||
	    (incl_link_capacity_ && (key == "cap_and_lat")))
        {
          continue;
        }

        if (!incl_link_capacity_ && ((key == "capacities") || (key == "cap_and_lat")))
        {
          LogE(kClassName, __func__,
               "Cannot get capacities if Bpf.IncludeLinkCapacity not set.\n");
          success = false;
          err_msg = "Bpf.IncludeLinkCapacity not set.";
        }
        else
        {
          LogE(kClassName, __func__, "Unsupported get message key %s.\n",
               key.c_str());
            success = false;
          err_msg = "Unsupported key " + key + ".";
        }
      }
      else
      {
        LogE(kClassName, __func__, "Non-string key is not supported.\n");
        success = false;
        err_msg = "Non-string key.";
      }
    }

    Writer<StringBuffer>* writer =
      remote_control_.StartGetReplyMessage(success, err_msg);

    if (success)
    {
      if (key == "stats")
      {
        bpf_stats_.WriteStats(writer);
      }
      else if (key == "capacities")
      {
        WriteCapacities(writer);
      }
      else if (key == "cap_and_lat")
      {
	WriteCapAndLat(writer);
      }
    }

    remote_control_.SendGetReplyMessage(success);
    return;
  }

  LogE(kClassName, __func__, "Unknown remote control get message target: "
       "%s\n", target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.StartGetReplyMessage(false, err_msg);
  remote_control_.SendGetReplyMessage(false);
}

//============================================================================
void BPFwder::ProcessPushReqMessage()
{
  bool          success   = false;
  uint32_t      client_id = 0;
  uint32_t      msg_id    = 0;
  double        interval  = 0.0;
  const Value*  keys      = NULL;
  string        target;
  string        err_msg = "";

  // Get the message contents.
  if ((!remote_control_.GetPushRequestMessage(client_id, msg_id, target,
                                              interval, keys)) ||
      (keys == NULL) || (interval < 0.01))
  {
    LogE(kClassName, __func__, "Error getting remote control push request "
         "message.\n");
    return;
  }

  LogD(kClassName, __func__, "Processing remote control push request message "
       "for client %" PRIu32 " msg %" PRIu32 " target %s interval %f.\n",
       client_id, msg_id, target.c_str(), interval);

  // ---------- Bpf target ----------
  if (target == "bpf")
  {
    bool  overall_success = true;

    // Only support the "stats" and "flow_stats" keys right now.
    for (SizeType i = 0; i < keys->Size(); ++i)
    {
      if ((*keys)[i].IsString())
      {
        string  key = (*keys)[i].GetString();

        if (key == "stats")
        {
          success = ProcessPushReqStatsMessage(client_id, msg_id, interval,
                                               err_msg);
          overall_success = (overall_success && success);
          if (overall_success)
          {
            bpf_stats_.set_push_active(true);
          }
          continue;
        }
        else if (key == "flow_stats")
        {
          string  options;

          LogD(kClassName, __func__, "pushreq for flow_stats.\n");
          if (!remote_control_.GetPushRequestOptions(key, options))
          {
            LogE(kClassName, __func__, "Error getting remote control "
                 "push request flow_stats message options.\n");
            err_msg.append("Missing pushreq options for flow_stats.");
            success = false;
          }
          else
          {
            success = ProcessPushReqFlowStatsMessage(client_id, msg_id,
                                                     interval, options,
                                                     err_msg);
          }

          overall_success = (overall_success && success);
          continue;
        }

        LogE(kClassName, __func__, "Unsupported push request message key "
             "%s.\n", key.c_str());
        success = false;
        err_msg.append("Unsupported key " + key + ".");
      }
      else
      {
        LogE(kClassName, __func__, "Non-string key is not supported.\n");
        success = false;
        err_msg.append("Non-string key.");
      }

      overall_success = (overall_success && success);
    }

    if (!overall_success)
    {
      remote_control_.SendPushErrorMessage(client_id, msg_id, err_msg);
    }

    return;
  }

  LogE(kClassName, __func__, "Unknown remote control get message target: "
       "%s\n", target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.SendPushErrorMessage(client_id, msg_id, err_msg);
}

//============================================================================
bool BPFwder::ProcessPushReqStatsMessage(uint32_t client_id, uint32_t msg_id,
                                         double interval, string& err_msg)
{
  // If currently pushing to a client, then return an error.
  if (stats_push_.is_active)
  {
    err_msg.append("Already pushing stats to a client.");
    return false;
  }

  // Set up pushing statistics to the client.  Start the first timer.
  CallbackNoArg<BPFwder>  cbna(this, &BPFwder::PushStats);
  Time                    delta_time(interval);

  // Cancel any existing stats timer.
  timer_.CancelTimer(stats_push_.timer_handle);

  if (!timer_.StartTimer(delta_time, &cbna, stats_push_.timer_handle))
  {
    err_msg.append("Error starting stats push timer.");
    return false;
  }

  // Record the necessary information.
  stats_push_.is_active    = true;
  stats_push_.client_id    = client_id;
  stats_push_.msg_id       = msg_id;
  stats_push_.interval_sec = interval;

  return true;
}

//============================================================================
bool BPFwder::ProcessPushReqFlowStatsMessage(uint32_t client_id,
                                             uint32_t msg_id, double interval,
                                             const string& options,
                                             string& err_msg)
{
  // If currently pushing to a client, then return an error.
  if (flow_stats_push_.is_active)
  {
    err_msg.append("Already pushing flow statistics to a client.");
    return false;
  }

  // Modify the flow stats filter spec in all of the Path Controllers.
  FlowFilter  flow_filter;
  flow_filter.Configure(options);

  for (size_t i = 0; i < num_path_ctrls_; ++i)
  {
    path_ctrls_[i].flow_stats.SetFilter(flow_filter);
  }

  // Cancel any existing flow statistics collection timer.
  timer_.CancelTimer(flow_stats_push_.timer_handle);

  // Start the flow statistics collection timer.
  CallbackNoArg<BPFwder>  cbna(this, &BPFwder::PushFlowStats);
  Time                    delta_time(interval);

  if (!timer_.StartTimer(delta_time, &cbna, flow_stats_push_.timer_handle))
  {
    LogE(kClassName, __func__, "Error setting next flow statistics push "
         "timer.\n");
    err_msg.append("Error starting flow stats timer.");
    return false;
  }

  // Record the necessary information.
  flow_stats_push_.is_active    = true;
  flow_stats_push_.client_id    = client_id;
  flow_stats_push_.msg_id       = msg_id;
  flow_stats_push_.interval_sec = interval;

  return true;
}

//============================================================================
void BPFwder::ProcessPushStopMessage()
{
  uint32_t  client_id = 0;
  uint32_t  msg_id = 0;
  string    target;
  uint32_t  to_stop_count = 0;

  // Get the message.
  if (!remote_control_.GetPushStopMessage(client_id, msg_id, target, to_stop_count))
  {
    LogE(kClassName, __func__, "Error getting remote control push stop "
         "message.\n");
    return;
  }
  LogD(kClassName, __func__, "Processing remote control push stop request "
       "message for client %" PRIu32 " msg %" PRIu32 " target %s.\n",
       client_id, msg_id, target.c_str());

  bool stop_stats = false;
  bool stop_flow_stats = false;
  if (to_stop_count == 0)
  {
    LogD(kClassName, __func__, "No stop ids, stopping all pushing activity.\n");
    stop_stats = true;
    stop_flow_stats = true;
  }
  else
  {
    for (uint32_t i = 0; i < to_stop_count; ++i)
    {
      uint32_t to_stop_id = 0;
      if (!remote_control_.GetPushStopToStopId(i, to_stop_id))
      {
        LogE(kClassName, __func__, "Error getting remote control push stop id.\n");
        remote_control_.SendPushErrorMessage(client_id, msg_id,
                                             "Message pushstop processing error.");
        return;
      }

      stop_stats = stop_stats || (stats_push_.is_active &&
                                  to_stop_id == stats_push_.msg_id);
      stop_flow_stats = stop_flow_stats || (flow_stats_push_.is_active &&
                                            to_stop_id == flow_stats_push_.msg_id);
    }
    if (!stop_stats && !stop_flow_stats)
    {
      LogE(kClassName, __func__, "Unexpected stop message id in push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "Unexpexted stop message id.");
      return;
    }
  }

  if (stop_stats)
  {
    LogD(kClassName, __func__, "Stopping pushes of statistics upon request.\n");

    // Stop the pushes.
    stats_push_.is_active    = false;
    stats_push_.client_id    = 0;
    stats_push_.msg_id       = 0;
    stats_push_.interval_sec = 0.0;
    bpf_stats_.set_push_active(false);
  }

  if (stop_flow_stats)
  {
    LogD(kClassName, __func__, "Stopping pushes of flow statistics upon request.\n");

    // Stop the pushes.
    flow_stats_push_.is_active    = false;
    flow_stats_push_.client_id    = 0;
    flow_stats_push_.msg_id       = 0;
    flow_stats_push_.interval_sec = 0.0;
  }
}

//============================================================================
bool BPFwder::ProcessBpfSetMessage(const Value* key_vals, string& err_msg)
{
  string  key;
  string  value;
  bool    outcome = true;

  err_msg.clear();

  // Loop over key/value pairs, processing each.
  for (Value::ConstMemberIterator it = key_vals->MemberBegin();
       it != key_vals->MemberEnd(); ++it)
  {
    // The key and value must both be strings.
    if (!(it->name.IsString()) || !(it->value.IsString()))
    {
      LogE(kClassName, __func__, "Error, key or value is not a string.\n");
      err_msg = "Error, key or value is not string.";
      return false;
    }

    key   = it->name.GetString();
    value = it->value.GetString();

    // Set the virtual queue depths in bytes.  We are expecting the following
    // string:  bid:<X>;<iron_addr1:length1>,<iron_addr2:length2>
    if (key == "VirtualQueueDepthsBytes")
    {
      LogD(kClassName, __func__, "Processing string '%s' to update virtual "
           "queue depths.\n", value.c_str());

      if (value.substr(0, 4) == "bid:")
      {
        // Get the Bin ID, which follows bid:.
        string       bid_num_str = value.substr(4);
        char*        end_ptr = NULL;
        const char*  str_ptr = bid_num_str.c_str();

        // Clear errno before the call, per strtoul(3).
        errno = 0;

        unsigned long  val = static_cast<uint32_t>(::strtoul(str_ptr,
                                                             &end_ptr, 10));

        // Check for overflow and any other conversion error.
        if (((errno == ERANGE) && (val == ULONG_MAX)) || (errno != 0))
        {
          LogE(kClassName, __func__, "Error converting string %s to unsigned "
               "integer: %s\n", bid_num_str.c_str(), strerror(errno));
          err_msg = "Bad BID number.";
          return false;
        }

        // Check for no conversion.
        if (end_ptr == str_ptr)
        {
          LogE(kClassName, __func__, "Error converting string %s to unsigned "
               "integer.\n", bid_num_str.c_str());
          err_msg = "Bad BID number (no conversion).";
          return false;
        }

        // Check for a valid bin_id.
        BinId     bin_id  = static_cast<BinId>(val);
        BinIndex  bin_idx = bin_map_shm_.GetPhyBinIndex(bin_id);

        if (bin_idx == kInvalidBinIndex)
        {
          LogE(kClassName, __func__, "Bin id cast to %" PRIBinId " does not "
               "exist in bin map.\n", bin_id);
          err_msg = "Bin id val does not exist.";
          return false;
        }

        // Now that we have the bin Id, let us make sure the next expected
        // character ';' is here
        if (*end_ptr != ';')
        {
          LogE(kClassName, __func__,
                "Error converting string: bad format, expected ; after bid\n");
          err_msg = "Bad format.";
          return false;
        }

        // Extract the string of addr:length pairs
        size_t virt_queue_lengths_index = value.find_first_of(";");
        if (virt_queue_lengths_index == string::npos)
        {
          LogE(kClassName, __func__,
                "Error converting string: bad format, expected ';' in %s\n",
                value.c_str());
          err_msg = "Bad format.";
          return false;
        }
        virt_queue_lengths_index++;
        string virt_queue_lengths_str = value.substr(virt_queue_lengths_index);

        LogD(kClassName, __func__,
              "Parsing string %s related to bin id %" PRIBinId "\n",
              virt_queue_lengths_str.c_str(), bin_id);
        // While the string is not empty
        while (!virt_queue_lengths_str.empty())
        {
          // Extract the first addr:length pair and cut it out of the string,
          // making sure to mind the ',' separator
          size_t separator_index = virt_queue_lengths_str.find_first_of(",");
          string addr_length_pair;
          if (separator_index == string::npos)
          {
            // This is the last token of the string, therefore, do not expect a
            // ',' to terminate it
            addr_length_pair  = virt_queue_lengths_str;
            virt_queue_lengths_str = "";
            LogD(kClassName, __func__,
                  "Processing last string %s\n", addr_length_pair.c_str());
          }
          else
          {
            // We will have a pair to parse after this one, and we expect a ','
            // to terminate this pair
            addr_length_pair  = virt_queue_lengths_str.substr(0,
                                                              separator_index);
            virt_queue_lengths_str.erase(0, separator_index + 1);
            LogD(kClassName, __func__,
                  "Removed and processing string %s, will inspect remaining "
                  "string %s after.\n", addr_length_pair.c_str(),
                  virt_queue_lengths_str.c_str());
          }

          // Inspect the current addr:length pair, check if the separator ':'
          // is even here
          separator_index = addr_length_pair.find_first_of(":");
          if (separator_index == string::npos)
          {
            LogE(kClassName, __func__,
                  "Error converting string: bad format, expected ':' in %s\n",
                  addr_length_pair.c_str());
            outcome = false;
            continue;
          }

          // We have our correct (addr:length) pair, and the following string
          // to process is ready to go, so failing here is OK
          string  nbr_bin_id_str  = addr_length_pair.substr(0, separator_index);
          string  length_str      = addr_length_pair.substr(separator_index+1);

          uint32_t  length =
                static_cast<uint32_t>(StringUtils::GetUint(length_str.c_str(),
                                                            99999));
          if (length == 99999)
          {
            LogE(kClassName, __func__,
                  "Length is invalid %s\n", length_str.c_str());
            outcome = false;
            continue;
          }

          uint32_t  nbr_bin_id  = StringUtils::GetUint(nbr_bin_id_str, 0);

          if (nbr_bin_id == my_bin_id_)
          {
            // I am the node whose address is provided!
            queue_store_->GetVirtQueueDepths()->SetBinDepthByIdx(
              bin_idx, length);
            BinIndex  nbr_bin_idx = bin_map_shm_.GetPhyBinIndex(nbr_bin_id);
	    LogI(kClassName, __func__, "Setting virtual queue depth of %"
		 PRIu32 " to reach node %s from node %s.\n",
		 length, bin_map_shm_.GetIdToLog(bin_idx).c_str(),
		 bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());
          }
          else
          {
            BinIndex  nbr_bin_idx = bin_map_shm_.GetPhyBinIndex(nbr_bin_id);

            if (nbr_bin_idx == kInvalidBinIndex)
            {
              LogE(kClassName, __func__, "Invalid virtual queue depth "
                   "neighbor bin id %" PRIBinId ".\n", nbr_bin_id);
            }

            // GetPhyBinIndex LogFs if invalid.

            // Length is at a different node, find the related path controller
            if (!ApplyVirtQueueSet(bin_idx, nbr_bin_idx, length))
            {
              // We found no Path Controller to that nbr!
              LogF(kClassName, __func__,
		   "Failed to update virtual queue depth to %" PRIu32
		   " to reach node %s via node %s,"
		   " PathCtrl not found!  Caching cmd\n",
		   length,  bin_map_shm_.GetIdToLog(bin_idx).c_str(),
		   bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());
            }
          }
        }
      }
      else
      {
        LogE(kClassName, __func__,
              "Bad format, expected 'bid:' in %s", value.c_str());
      }
    }
    else if (key == "update_group")
    {
      LogW(kClassName, __func__, "Got message to update multicast group %s\n",
           value.c_str());

      // The value string is of the form: "mcast_addr;action;host_addr"
      List<string>  tokens;
      StringUtils::Tokenize(value, ";", tokens);
      string mcast_addr;
      tokens.Pop(mcast_addr);
      Ipv4Address mcast_ip_addr = Ipv4Address(mcast_addr);
      McastId mcast_id = bin_map_shm_.GetMcastIdFromAddress(mcast_ip_addr);
      string action;
      tokens.Pop(action);
      string host_addr;
      tokens.Pop(host_addr);
      Ipv4Address host_ip_addr = Ipv4Address(host_addr);

      if (!mcast_ip_addr.IsMulticast())
      {
        LogE(kClassName, __func__,"Group address is not Class D.\n");
        return false;
      }

      iron::List<string>* host_list = NULL;
      bool group_membership = mcast_group_cache_.Find(mcast_ip_addr, host_list);
      LogW(kClassName, __func__, "Lookup: %s, mg size: %u\n",
           mcast_ip_addr.ToString().c_str(), mcast_group_cache_.size());

      // Handle the case where a host joins a group.
      if (action == "join")
      {
        // Update the local group membership table.
        if (group_membership)
        {
          LogD(kClassName, __func__, "Found group membership\n");
          if (!host_list->IsMember(host_addr))
          {
            host_list->Push(host_addr);
          }
          else
          {
            LogD(kClassName, __func__, "Host %s is already in host list.\n",
                 host_addr.c_str());
          }
        }
        else
        {
          LogD(kClassName, __func__, "New group membership\n");
          host_list = new (std::nothrow) iron::List<string>();
          if (host_list == NULL)
          {
            LogE(kClassName, __func__, "Error allocating new host list for a "
                 "new group membership.\n");
          }
          else
          {
            host_list->Push(host_addr);
            mcast_group_memberships_.Push(mcast_ip_addr);
            if(!mcast_group_cache_.Insert(mcast_ip_addr, host_list))
            {
              LogW(kClassName, __func__, "Insertion in the multicast group "
                   "membership tables failed\n");
            }
            bin_map_shm_.AddDstToMcastGroup(mcast_ip_addr, my_bin_idx_);
            BinIndex idx = bin_map_shm_.GetMcastBinIndex(mcast_id);
            if ((idx != kInvalidBinIndex) &&
                (queue_store_->GetBinQueueMgr(idx) == NULL))
            {
              queue_store_->AddQueueMgr(config_info_, idx, my_bin_idx_);
              LogD(kClassName, __func__," Add queue mgr for: %s\n",
                   mcast_addr.c_str());
            }
            if (send_grams_)
            {
              SendGram();
            }
            else
            {
              LogW(kClassName, __func__,
                   "New multicast group detected but GRAMs are disabled.\n");
            }
          }
        }
      }
      if (action == "leave")
      {
        if (!group_membership)
        {
          LogW(kClassName, __func__, "Cannot leave unknown group: %s\n",
                                     mcast_addr.c_str());
          return false;
        }
        if ((host_list->size() > 0) && (host_list->Remove(host_addr)))
        {
          LogD(kClassName, __func__, "Removed host %s from group %s.\n",
               host_addr.c_str(), mcast_addr.c_str());
        }
        if (host_list->size() == 0)
        {
          LogD(kClassName, __func__, "No remaining hosts on group %s.\n",
               mcast_addr.c_str());
          bin_map_shm_.RemoveDstFromMcastGroup(mcast_ip_addr, my_bin_idx_);
          mcast_group_memberships_.Remove(mcast_ip_addr);
          mcast_group_cache_.FindAndRemove(mcast_ip_addr, host_list);
          delete host_list;
          if (send_grams_)
          {
            SendGram();
          }
          else
          {
            LogW(kClassName, __func__,
                 "Multicast group deleted but GRAMs are disabled.\n");
          }
        }
      }
    }
    else
    {
      LogE(kClassName, __func__,
            "%s command not supported\n", key.c_str());
      err_msg = "Cmd not supported.";
      return false;
    }
  }

  return outcome;
}

//============================================================================
bool BPFwder::ProcessPcSetMessage(string& target, const Value* key_vals,
                                  string& err_msg)
{
  err_msg.clear();

  // Get the Path Controller identifier, which is the Path Controller number
  // set at initialization time.  Use 99999 as the default value in the
  // GetUint() call so that we can detect if the identifier cannot be parsed
  // (there is no chance that a BPF will ever be configured with 100,000 path
  // controllers).
  uint32_t  path_ctrl_num =
    static_cast<uint32_t>(StringUtils::GetUint(target.substr(3), 99999));

  if (path_ctrl_num == 99999)
  {
    LogE(kClassName, __func__, "Invalid Path Controller number %s.\n",
         target.substr(3).c_str());
    err_msg = "Invalid target format: " + target;
    return false;
  }

  // Find the Path Controller.
  if ((path_ctrl_num >= kMaxPathCtrls) ||
      (path_ctrls_[path_ctrl_num].path_ctrl == NULL))
  {
    LogE(kClassName, __func__, "Cannot find remote control set message "
         "target: %s\n", target.c_str());
    err_msg = "Cannot find target: " + target;
    return false;
  }

  // Loop over key/value pairs, processing each.
  string  key;
  string  val;

  for (Value::ConstMemberIterator it = key_vals->MemberBegin();
       it != key_vals->MemberEnd(); ++it)
  {
    // The key and value must both be strings.
    if (!(it->name.IsString()) || !(it->value.IsString()))
    {
      LogE(kClassName, __func__, "Error, key or value is not a string.\n");
      err_msg = "Error, key or value is not string.";
      return false;
    }

    key = it->name.GetString();
    val = it->value.GetString();

    // Set the Path Controller parameter.
    if (!(path_ctrls_[path_ctrl_num].path_ctrl->SetParameter(key.c_str(),
                                                             val.c_str())))
    {
      LogE(kClassName, __func__, "Error setting Path Controller %s to "
           "%s.\n", key.c_str(), val.c_str());
      err_msg = "Error setting Path Controller " + key + " to " + val + ".";
      return false;
    }
  }

  return true;
}

//============================================================================
void BPFwder::WriteCapacities(Writer<StringBuffer>* writer)
{
  if (!writer)
  {
    return;
  }

  // Capacities keyvals json format.
  // "capacities_bps" :
  // {
  //   "xxx.xxx.xxx.001" :
  //   {
  //     xxx.xxx.xxx.002" : c_1-2,
  //     xxx.xxx.xxx.003" : c_1-3,
  //     ...
  //   },
  //   "xxx.xxx.xxx.002" :
  //   {
  //     xxx.xxx.xxx.001" : c_2-3,
  //     xxx.xxx.xxx.003" : c_2-3,
  //     ...
  //   },
  //   ...
  // }

  writer->Key("capacities_bps");
  writer->StartObject();

  NodeRecord*  node_record = NULL;

  // Only unicast destinations and interior nodes have capacities to report.
  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    BinId        bin_id = bin_map_shm_.GetPhyBinId(bin_idx);
    Ipv4Address  node_addr(htonl((static_cast<in_addr_t>(10) << 24) |
                                 static_cast<in_addr_t>(bin_id)));

    writer->Key(node_addr.ToString().c_str());
    writer->StartObject();

    node_record = AccessOrAllocateNodeRecord(bin_idx);

    if (node_record == NULL)
    {
      LogE(kClassName, __func__, "Error getting node record for bin index %"
           PRIBinIndex ".\n", bin_idx);
      continue;
    }

    BinIndex  remote_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(remote_idx);
         valid;
         valid = bin_map_shm_.GetNextPhyBinIndex(remote_idx))
    {
      if (bin_idx == remote_idx)
      {
        continue;
      }

      BinId        remote_id = bin_map_shm_.GetPhyBinId(remote_idx);
      Ipv4Address  remote_addr(htonl((static_cast<in_addr_t>(10) << 24) |
                                     static_cast<in_addr_t>(remote_id)));

      double  capacity = node_record->records_[remote_idx].capacity_;

      if (capacity < 0.0)
      {
        // No link between the two nodes.
        continue;
      }

      writer->Key(remote_addr.ToString().c_str());
      writer->Uint(capacity);
    }
    writer->EndObject();  // End node address.
  }
  writer->EndObject();  // End capacities_bps.
}

//============================================================================
void BPFwder::WriteCapAndLat(Writer<StringBuffer>* writer)
{
  if (!writer)
  {
    return;
  }

  // CapAndLat keyvals json format.
  // "cap_and_lat" :
  // {
  //   "xxx.xxx.xxx.001" :
  //   {
  //     xxx.xxx.xxx.002" : [c_1-2, l_1-2]
  //     xxx.xxx.xxx.003" : [c_1-3, l_1-3]
  //     ...
  //   },
  //   "xxx.xxx.xxx.002" :
  //   {
  //     xxx.xxx.xxx.001" : [c_2-1, l_2-1]
  //     xxx.xxx.xxx.003" : [c_2-3, l_2-3]
  //     ...
  //   },
  //   ...
  // }

  writer->Key("cap_and_lat");
  writer->StartObject();

  NodeRecord*  node_record = NULL;

  // Only unicast destinations and interior nodes have capacities and
  // latencies to report.
  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    BinId        bin_id = bin_map_shm_.GetPhyBinId(bin_idx);
    Ipv4Address  node_addr(htonl((static_cast<in_addr_t>(10) << 24) |
                                 static_cast<in_addr_t>(bin_id)));

    writer->Key(node_addr.ToString().c_str());
    writer->StartObject();

    node_record = AccessOrAllocateNodeRecord(bin_idx);

    if (node_record == NULL)
    {
      LogE(kClassName, __func__, "Error getting node record for bin index %"
           PRIBinIndex ".\n", bin_idx);
      continue;
    }

    BinIndex  remote_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(remote_idx);
         valid;
         valid = bin_map_shm_.GetNextPhyBinIndex(remote_idx))
    {
      if (bin_idx == remote_idx)
      {
        continue;
      }

      BinId        remote_id = bin_map_shm_.GetPhyBinId(remote_idx);
      Ipv4Address  remote_addr(htonl((static_cast<in_addr_t>(10) << 24) |
                                     static_cast<in_addr_t>(remote_id)));

      double  capacity = node_record->records_[remote_idx].capacity_;

      if (capacity < 0.0)
      {
        // No link between the two nodes.
        continue;
      }

      uint32_t  latency = node_record->records_[remote_idx].nbr_lat_mean_;

      writer->Key(remote_addr.ToString().c_str());
      writer->StartArray();
      writer->Uint(capacity);
      writer->Uint(latency);
      writer->EndArray();
    }
    writer->EndObject();  // End node address.
  }
  writer->EndObject();  // End capacities_bps.
}

//============================================================================
bool BPFwder::ApplyVirtQueueSet(
  BinIndex bin_idx, BinIndex nbr_bin_idx, uint32_t length)
{
  QueueDepths* qd = queue_store_->PeekNbrVirtQueueDepths(nbr_bin_idx);

  // We found our path ctrl, check if is in the nbr_virt_q map or add it
  if (qd)
  {
    // It was already there and found!
    qd->SetBinDepthByIdx(bin_idx, length);
    LogD(kClassName, __func__, "Setting virtual queue depth of %"
         PRIu32 " to reach node %s via relay node %s.\n",
         length, bin_map_shm_.GetIdToLog(bin_idx).c_str(),
	 bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());
  }
  else
  {
    // It was not found, create the entry
    LogD(kClassName, __func__, "Did not find nbr virt queue depths for nbr "
         "%s, creating...\n", bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());

    qd = new (std::nothrow) QueueDepths(bin_map_shm_);
    if (!qd)
    {
      LogF(kClassName, __func__, "Could not allocate queue depth "
           "object.\n");
      return false;
    }
    qd->SetBinDepthByIdx(bin_idx, length);
    if (!queue_store_->SetNbrVirtQueueDepths(nbr_bin_idx, qd))
    {
      delete qd;
      return false;
    }
  }
  return true;
}

//============================================================================
void BPFwder::ProcessCapacityUpdate(PathController* path_ctrl,
                                    double chan_cap_est_bps,
                                    double trans_cap_est_bps)
{
  // The QLAM rate computation is as follows.
  //
  // The QLAM capacity = Cx, where C is path controller capacity and x is the
  // ratio for QLAMs.
  //
  // The QLAM capacity is also equal to L_Q / T, where L_Q is the QLAM packet
  // size and T is the time interval between QLAMs.
  //
  // Thus:  Cx = L_Q / T.
  //
  // Rearranging, we have:  T = L_Q / Cx.
  //
  // However, the capacity is not always constant.  Therefore, this uses a
  // token bucket algorithm that fills based on the current capacity and the
  // time interval.  For instance, if we receive a capacity update, we place
  // C(t_update - t_last_update)x bits in the bucket.  The time to the next
  // QLAM becomes:  T = (L_Q - B) / Cx, where B is the bucket size.

  // Make sure that we always send QLAMs, even at a low rate.  If we don't
  // send QLAMs to distribute bin depths, then other BPFs can't send data
  // packets.
  double  usable_capacity_bps = chan_cap_est_bps;

  if (usable_capacity_bps < min_path_ctrl_cap_est_bps_)
  {
    usable_capacity_bps = min_path_ctrl_cap_est_bps_;
  }

  // Find the path controller information.
  if (path_ctrl == NULL)
  {
    LogE(kClassName, __func__, "Path controller pointer is NULL.\n");
    return;
  }

  uint32_t  pc_num = path_ctrl->path_controller_number();

  if ((pc_num >= kMaxPathCtrls) ||
      (path_ctrls_[pc_num].path_ctrl != path_ctrl))
  {
    LogE(kClassName, __func__, "Path controller number %" PRIu32
         " or pointer %p invalid.\n", pc_num, path_ctrl);
    return;
  }

  PathCtrlInfo&  pc_info = path_ctrls_[pc_num];

  // Get the current time.
  Time  now;

  if (!now.GetNow())
  {
    LogF(kClassName, __func__, "Could not get current time.\n");
    return;
  }

  // If the last QLAM send time is zero (no QLAMs have been sent yet), then
  // initialize it to the current time.
  if (pc_info.last_qlam_tx_time.IsZero())
  {
    pc_info.last_qlam_tx_time = now;
  }

  // Update the token bucket using the old link capacity estimate.
  if (!pc_info.last_capacity_update_time.IsZero())
  {
    double  delta_time_usec = static_cast<double>(
      (now - pc_info.last_capacity_update_time).GetTimeInUsec());

    double  bits_accumulated = ((pc_info.link_capacity_bps * delta_time_usec *
                                 overhead_ratio_) / 1000000.0);

    pc_info.bucket_depth_bits += bits_accumulated;
  }
  else
  {
    pc_info.bucket_depth_bits = 0.0;
  }

  // Record the new capacity estimate.
  pc_info.link_capacity_bps         = usable_capacity_bps;
  pc_info.last_capacity_update_time = now;

  // Cancel any existing QLAM send timer for this Path Controller.
  timer_.CancelTimer(pc_info.timer_handle);

  // Only update the QLAM send timer if not in a timer callback right now.
  if (!pc_info.in_timer_callback)
  {
    // Compute next QLAM send timer duration using the new capacity estimate.
    Time  next_exp_time;

    if (ComputeNextQlamTimer(pc_info, next_exp_time))
    {
      uint32_t  t_usec = ((now.GetTimeInUsec() +
                           next_exp_time.GetTimeInUsec()) &
                          0x00000000FFFFFFFF);

      LogD(kClassName, __func__, "b QLAM sn: %u\n", t_usec);
      // Start a timer for the next QLAM send time.
      CallbackTwoArg<BPFwder, uint32_t, uint32_t>
        cb(this, &BPFwder::SendQlamToPathCtrl, pc_num, t_usec);

      if (!timer_.StartTimer(next_exp_time, &cb, pc_info.timer_handle))
      {
        LogE(kClassName, __func__, "Failed to set QLAM timer\n");
      }
    }
  }

  // Send update to BinQueueMgr, via QueueStore
  queue_store_->ProcessCapacityUpdate(pc_num, usable_capacity_bps);

  // Update the statistics.
  bpf_stats_.ReportCapacityUpdateForPC(path_ctrl, chan_cap_est_bps,
                                       trans_cap_est_bps);

  LogD(kClassName, __func__, "Capacity update on pc %" PRIu32 " to %.1f "
       "bps, using %.1f bps, %.1f bps for QLAMs.\n", pc_num, chan_cap_est_bps,
       usable_capacity_bps, (usable_capacity_bps * overhead_ratio_));
}

//============================================================================
void BPFwder::ProcessPktDelDelay(PathController* path_ctrl, double pdd_mean,
                                 double pdd_variance)
{
  if (!path_ctrl)
  {
    LogE(kClassName, __func__,
         "Cannot process PDD update from NULL path controller.\n");
    return;
  }

  if (!ls_latency_collection_)
  {
    return;
  }

  PathCtrlInfo& path_ctrl_info  =
    path_ctrls_[path_ctrl->path_controller_number()];
  double        pdd_std_dev     = sqrt(pdd_variance);

  LogA(kClassName, __func__,
       "PDD update for path controller %" PRIu8 ": mean: %fs var: %fs^2 "
       "std dev: %fs.\n",
       path_ctrl->path_controller_number(), pdd_mean, pdd_variance,
       pdd_std_dev);

  if ((path_ctrl_info.pdd_mean_sec == pdd_mean) &&
      (path_ctrl_info.pdd_variance_secsq == pdd_variance))
  {
    // No change.
    LogD(kClassName, __func__,
         "No change in PDD for path controller %" PRIu8 ".\n",
         path_ctrl->path_controller_number());
    return;
  }

  // Keep the new estimated packet delivery time for low-latency data packets
  // in the path controller.  Do not start using locally until we send the
  // LSA.  The reason is that this could lead to having big discrepancies
  // between local and neighbor info, which causes the packets to travel
  // unnecessarily---and add to their history constrains.
  path_ctrl_info.pdd_mean_sec       = pdd_mean;
  path_ctrl_info.pdd_variance_secsq = pdd_variance;
  path_ctrl_info.pdd_std_dev_sec    = pdd_std_dev;

  Time  now = Time::Now();

  if (!lsa_hold_down_)
  {
    // If LSA timer not already set.
    if (now - last_lsa_send_time_ > lsa_hold_down_time_)
    {
      // And it has been longer than hold time since last LSA send.
      LogD(kClassName, __func__,
           "Update past hold down time, send LSA.\n");
      SendNewLsa();
      return;
    }
    else
    {
      // And it has been less than hold time since last LSA send.
      LogD(kClassName, __func__,
           "Update within hold down time, schedule LSA.\n");

      // Cancel timer if set.
      timer_.CancelTimer(lsa_timer_handle_);

      // Set timer to go last_time_sent + hold_down - now:
      //   |-------------|    ||
      // last_t        now   last_t + hold
      CallbackNoArg<BPFwder>  cb_lsa(this, &BPFwder::SendNewLsa);
      Time  delta_time  = lsa_hold_down_time_ +
        last_lsa_send_time_ - now;

      if (!timer_.StartTimer(delta_time, &cb_lsa, lsa_timer_handle_))
      {
        LogE(kClassName, __func__, "Failed to set LSA timer.\n");
      }
      lsa_hold_down_  = true;
      return;
    }
  }

  // Else the timer is set, wait for it to expire.
  LogD(kClassName, __func__,
      "Hold down timer already set.\n");
}

//============================================================================
bool BPFwder::ComputeNextQlamTimer(PathCtrlInfo& pc_info, Time& next_exp_time)
{
  // The next QLAM interval is:  T = (L_Q - B) / Cx
  //
  // Where:
  //   L_Q: QLAM size in bits
  //   B:   bucket size in bits
  //   C:   channel capacity in bits/second
  //   x:   ratio of capacity for QLAM
  //
  // If the token bucket is empty, then this is the inter-QLAM interval.
  // Otherwise, it is the time to the next QLAM given the current token bucket
  // depth.

  // Set the next expiration time to the maximum value, in case the method
  // returns early.
  next_exp_time = Time::FromUsec(max_qlam_intv_usec_);

  // The next expected time defaults to zero.
  uint64_t  next_time_us = 0;

  // Compute the capacity for sending QLAMs.
  double  qlam_capacity_bps = (pc_info.link_capacity_bps * overhead_ratio_);

  // Next time = (size_of_qlam - bucket) / (capacity * qlam_overhead).
  // Check the denominator to make sure we will not divide by zero.
  if (qlam_capacity_bps == 0.0)
  {
    return false;
  }

  // Check if the token bucket is not full enough to send a QLAM immediately.
  if (last_qlam_size_bits_ > pc_info.bucket_depth_bits)
  {
    // No division by zero is possible (checked above).
    next_time_us = static_cast<uint64_t>(
      (1000000.0 * (static_cast<double>(last_qlam_size_bits_) -
                    pc_info.bucket_depth_bits)) / qlam_capacity_bps);

    // Check if this interval is going to be longer than the maximum allowed.
    if (next_time_us > max_qlam_intv_usec_)
    {
      next_time_us = max_qlam_intv_usec_;
    }
  }

  // Return the next expected QLAM send time.
  next_exp_time = Time::FromUsec(next_time_us);

  return true;
}

//============================================================================
bool BPFwder::GetPerPcLatencyToDst(BinIndex dst_idx, uint32_t* all_latency_us,
                                   bool add_src_queue_delay, Packet* pkt)
{
  if (dst_idx == kInvalidBinIndex)
  {
    return false;
  }

  NodeRecord*  node_record = AccessOrAllocateNodeRecord(my_bin_idx_);

  if (node_record == NULL)
  {
    LogE(kClassName, __func__, "Error getting node record for my bin "
         "index %" PRIBinIndex ".\n", my_bin_idx_);
    return false;
  }

  // Get this node's queue delay to the destination now and use it later.
  uint32_t  queue_delay = node_record->records_[dst_idx].queue_delay_;

  bool      res = true;
  CacheKey  cache_key;
  uint32_t  latency_us[kMaxPathCtrls];

  memset(latency_us, 0, sizeof(latency_us));

  // Exclude this node from the routes.
  path_info_.num_nodes_to_exclude_ = 0;
  path_info_.ExcludeNode(my_bin_idx_);

  if (conditional_dags_)
  {
    BinId  visited_bins[kNumNodesInHistory];

    // The following returns 0 if pkt is NULL.
    uint32_t  num_visited_bins  =
      packet_history_mgr_->GetAllVisitedBins(pkt, visited_bins,
                                             kNumNodesInHistory);

    // Add the visited bin indices from the packet to the cache key.
    for (uint8_t i = 0; i < num_visited_bins; ++i)
    {
      // Note the field width for the visited bin indices is only 14 bits.
      if (visited_bins[i] >= 14)
      {
        LogE(kClassName, __func__, "Visited bin %" PRIBinId " is too large "
             "for cache key history bit vector.\n", visited_bins[i]);
        continue;
      }

      BinIndex  visited_nbr_idx =
        bin_map_shm_.GetPhyBinIndex(visited_bins[i]);

      if ((visited_nbr_idx == kInvalidBinIndex) ||
          (visited_nbr_idx == my_bin_idx_) ||
          (visited_nbr_idx == dst_idx))
      {
        continue;
      }

      LogD(kClassName, __func__, "Visited bin %" PRIBinId " (index %"
           PRIBinIndex ") will be excluded.\n", visited_bins[i],
           visited_nbr_idx);

      path_info_.ExcludeNode(visited_nbr_idx);

      // Visited map with conditionaldags is:
      // <------8bits-----><----------14bits---------->
      // |  destination   |     visit history map     |
      cache_key.visited_his_map_ |= (0x1 << visited_bins[i]);
    }

    cache_key.visited_his_map_ |= dst_idx << 14;
  }
  else
  {
    // Visited map with heuristicdags is:
    // <----------14bits----------><------8bits----->
    // |0 0 0 0 0 0 0 0 0 0 0 0 0 0|  dst bin index |
    cache_key.visited_his_map_ = dst_idx & 0xFF;
  }

  CachedLatencyData*  cached_data;
  if (latency_cache_.Find(cache_key, cached_data) &&
    (cached_data->cache_time() > latency_cache_reset_time_))
  {
    if (cached_data->destination() != dst_idx)
    {
      LogF(kClassName, __func__,
           "Cached destination index %" PRIBinIndex " does not match target %"
           PRIBinIndex ".\n",
           cached_data->destination(), dst_idx);
      return false;
    }

    memcpy(all_latency_us, cached_data->latencies(),
           (num_path_ctrls_ * sizeof(*all_latency_us)));

    LogD(kClassName, __func__, "Cache hit for destination bin id %s.\n",
         bin_map_shm_.GetIdToLog(dst_idx).c_str());

    if (incl_queue_delays_ && add_src_queue_delay)
    {
      for (uint8_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
      {
        if ((static_cast<uint64_t>(all_latency_us[pc_i]) + queue_delay) <
            UINT32_MAX)
        {
          all_latency_us[pc_i] += (queue_delay & 0xFFFFFF00);
        }
      }
    }

    return res;
  }

  LogD(kClassName, __func__,
       "Cache miss for destination bin id %s, will recompute.\n",
       bin_map_shm_.GetIdToLog(dst_idx).c_str());

  // Convert the LSA records to a connection matrix (and a variance matrix).
  ConvertNodeRecordsToMatrix();

  // Use the connection matrix to find the minimum latency path to the dst.
  FindMinimumLatencyPath(dst_idx);

  for (size_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    PathController* path_ctrl = path_ctrls_[pc_i].path_ctrl;
    BinIndex        nbr_idx   = path_ctrl->remote_bin_idx();

    if (!bin_map_shm_.BinIndexIsAssigned(nbr_idx))
    {
      LogW(kClassName, __func__, "Remote bin %s for nbr %" PRIBinId
           " on path ctrl %" PRIu32 " is invalid.\n",
           bin_map_shm_.GetIdToLog(nbr_idx).c_str(),
           path_ctrl->remote_bin_id(), path_ctrl->path_controller_number());
      latency_us[pc_i]  = UINT32_MAX;
      res = false;
      continue;
    }

    PathCtrlInfo& path_ctrl_info  = path_ctrls_[pc_i];

    LogD(kClassName, __func__,
         "Adding mean %" PRIu32 "us var %" PRIu64 "us2 delay to nbr %s"
         " (index %" PRIBinIndex ") for dst bin %s"
         " (index %" PRIBinIndex ") latency %" PRIu32 "us w/ var %" PRIu64
         "us2.\n",
         static_cast<uint32_t>(path_ctrl_info.pdd_mean_sec * 1e6),
         static_cast<uint64_t>(path_ctrl_info.pdd_variance_secsq * 1e12),
         bin_map_shm_.GetIdToLog(nbr_idx).c_str(), nbr_idx,
         bin_map_shm_.GetIdToLog(dst_idx).c_str(), dst_idx,
         path_info_.MinLatMean(nbr_idx), path_info_.MinLatVar(nbr_idx));

    uint64_t  latency =
      (static_cast<uint64_t>(path_info_.MinLatMean(nbr_idx)) +
       static_cast<uint64_t>(path_ctrl_info.pdd_mean_sec * 1e6) +
       (2.2 * sqrt(path_info_.MinLatVar(nbr_idx) +
                   (path_ctrl_info.pdd_variance_secsq * 1e12))));

    // Add the time to reach the neighbor to the total latency to the
    // destination.
    latency_us[pc_i]      = latency > UINT32_MAX ? UINT32_MAX : latency;
    all_latency_us[pc_i]  = latency_us[pc_i];

    LogD(kClassName, __func__,
         "Latency on path ctrl %" PRIu8 " to dst Bin Id %s is %uus.\n",
         pc_i, bin_map_shm_.GetIdToLog(dst_idx).c_str(), latency_us[pc_i]);

    if (incl_queue_delays_ && add_src_queue_delay)
    {
      latency += queue_delay;

      all_latency_us[pc_i]    = latency > UINT32_MAX ? UINT32_MAX : latency;
    }
  }

  // Cache the results.
  if (latency_cache_.Find(cache_key, cached_data) && cached_data)
  {
    if (cached_data->destination() != dst_idx)
    {
      LogF(kClassName, __func__,
           "Cached destination index %" PRIBinIndex " does not match target %"
           PRIBinIndex ".\n",
           cached_data->destination(), dst_idx);
      return false;
    }
    cached_data->UpdateLatencyData(dst_idx, latency_us, num_path_ctrls_);
  }
  else
  {
    uint32_t*  cached_latencies =
      new (std::nothrow) uint32_t[num_path_ctrls_];

    if (cached_latencies == NULL)
    {
      LogE(kClassName, __func__, "Error allocating cached latency array.\n");
    }
    else
    {
      memcpy(cached_latencies, latency_us,
             (num_path_ctrls_ * sizeof(*cached_latencies)));

      cached_data = new (std::nothrow) CachedLatencyData(dst_idx,
                                                         cached_latencies);

      if (cached_data == NULL)
      {
        LogE(kClassName, __func__, "Error allocating cached latency "
             "entry.\n");
        delete [] cached_latencies;
      }
      else
      {
        latency_cache_.Insert(cache_key, cached_data);
      }
    }
  }

  return res;
}

//============================================================================
void BPFwder::PrintNodeRecords()
{
  NodeRecord*        node_record = NULL;
  std::stringstream  ss;

  if (!WouldLogD(kClassName))
  {
    return;
  }

  // We only want unicast destinations and interior nodes, not multicast
  // destinations.
  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    node_record = node_records_[bin_idx];

    if (node_record == NULL)
    {
      continue;
    }

    ss.str("");
    ss << "Node Id ";
    ss << std::setw(2)
       << static_cast<uint32_t>(bin_map_shm_.GetPhyBinId(bin_idx));
    ss << " (idx " << std::setw(2) << static_cast<uint32_t>(bin_idx) << "):";

    // We only want unicast destinations and interior nodes, not multicast
    // destinations.
    BinIndex  nbr_idx = 0;

    for (bool nbr_valid = bin_map_shm_.GetFirstPhyBinIndex(nbr_idx);
         nbr_valid;
         nbr_valid = bin_map_shm_.GetNextPhyBinIndex(nbr_idx))
    {
      NodeInfo&  node_info = node_record->records_[nbr_idx];

      if (node_info.nbr_lat_mean_ == UINT32_MAX)
      {
        ss << "      I";
      }
      else
      {
        ss << " ";
        ss << std::setw(6) << node_info.nbr_lat_mean_ / 1000.;
      }
      if (node_info.nbr_lat_var_ == UINT32_MAX)
      {
        ss << " / (+-)   I";
      }
      else
      {
        ss << " / (+-)";
        ss << std::setw(4) << node_info.nbr_lat_var_ / 1000.;
      }
    }
    LogD(kClassName, __func__,
         "%s\n", ss.str().c_str());
  }

  // We only want unicast destinations and interior nodes, not multicast
  // destinations.
  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    node_record = node_records_[bin_idx];

    if (node_record == NULL)
    {
      continue;
    }

    ss.str("");
    ss << "Node Id ";
    ss << std::setw(2)
       << static_cast<uint32_t>(bin_map_shm_.GetPhyBinId(bin_idx));
    ss << " (idx " << std::setw(2) << static_cast<uint32_t>(bin_idx) << "):";

    // We only want unicast destinations and interior nodes, not multicast
    // destinations.
    BinIndex  nbr_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(nbr_idx);
         valid;
         valid = bin_map_shm_.GetNextPhyBinIndex(nbr_idx))
    {
      ss << " ";
      ss << std::setw(6) << node_record->records_[nbr_idx].capacity_ / 1000.;
    }
    LogD(kClassName, __func__,
         "%s (kbps)\n", ss.str().c_str());
  }

  if (incl_queue_delays_)
  {
    LogD(kClassName, __func__,
         "Queuing Delays to destination bins:\n");

    // We only want unicast destinations and interior nodes, not multicast
    // destinations.
    bin_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
         valid;
         valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
    {
      node_record = node_records_[bin_idx];

      if (node_record == NULL)
      {
        continue;
      }

      ss.str("");
      ss << "Node Id ";
      ss << " (idx " << std::setw(2) << static_cast<uint32_t>(
        bin_map_shm_.GetPhyBinId(bin_idx)) << "):";

      // We only want unicast destinations and interior nodes, not multicast
      // destinations.
      BinIndex  dst_idx = 0;

      for (bool dst_valid = bin_map_shm_.GetFirstPhyBinIndex(dst_idx);
           dst_valid;
           dst_valid = bin_map_shm_.GetNextPhyBinIndex(dst_idx))
      {
        ss << " ";
        ss << std::setw(6) <<
          node_record->records_[dst_idx].queue_delay_ / 1000.;
      }
      LogD(kClassName, __func__,
           "%s\n", ss.str().c_str());
    }
  }
}

//============================================================================
void BPFwder::ConvertNodeRecordsToMatrix()
{
  // Latency-related operations are dependent on dst bins, not multicast
  // destinations.
  NodeRecord*  node_record = NULL;
  uint32_t     infinity    = UINT32_MAX;

  // Reset the path matrixes before setting specific elements.
  path_info_.ResetMatrixes();

  // We only want the unicast destinations and interior nodes, not the
  // multicast destinations.
  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    node_record = AccessOrAllocateNodeRecord(bin_idx);

    // We only want the unicast destinations and interior nodes, not the
    // multicast destinations.
    BinIndex  nbr_idx = 0;

    for (bool nbr_valid = bin_map_shm_.GetFirstPhyBinIndex(nbr_idx);
         nbr_valid;
         nbr_valid = bin_map_shm_.GetNextPhyBinIndex(nbr_idx))
    {
      // Reset node_info each iteration, and copy over it from the node record
      // if the node record exists.
      NodeInfo  node_info;

      if (node_record != NULL)
      {
        node_info = node_record->records_[nbr_idx];
      }

      if (bin_idx == nbr_idx)
      {
        // cost_matrix[bin_idx][nbr_idx] = 0
        path_info_.LatMean(bin_idx, nbr_idx) = 0;
        path_info_.LatVar(bin_idx, nbr_idx)  = 0;
      }
      else
      {
        // cost_matrix[bin_idx][nbr_idx] = latency
        path_info_.LatMean(bin_idx, nbr_idx) = node_info.nbr_lat_mean_;
        path_info_.LatVar(bin_idx, nbr_idx)  = node_info.nbr_lat_var_;
      }

      if (incl_queue_delays_)
      {
        if (infinity >
            static_cast<uint64_t>(node_info.queue_delay_) +
            static_cast<uint64_t>(path_info_.LatMean(bin_idx, nbr_idx)))
        {
          // Include queue latency.
          // This adds the queuing delay for the node itself in the matrix, but
          // that value is (correctly) ignored when computing the overall
          // latency in FindMinimumLatencyPath.
          path_info_.LatMean(bin_idx, nbr_idx) += node_info.queue_delay_;
        }
        else
        {
          path_info_.LatMean(bin_idx, nbr_idx) = infinity;
        }
      }
    }
  }

  for (size_t exclude_bin_i = 0;
       exclude_bin_i < path_info_.num_nodes_to_exclude_;
       ++exclude_bin_i)
  {
    BinIndex  exclude_bin_idx = path_info_.nodes_to_exclude_[exclude_bin_i];

    // We only want the unicast destinations and interior nodes, not the
    // multicast destinations.
    BinIndex  bin_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
         valid;
         valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
    {
      if (bin_idx == exclude_bin_idx)
      {
        continue;
      }
      path_info_.LatMean(bin_idx, exclude_bin_idx) = infinity;
      path_info_.LatMean(exclude_bin_idx, bin_idx) = infinity;
      // Set variance to 0 so as not to overflow in later computations.
      path_info_.LatVar(bin_idx, exclude_bin_idx) = 0;
      path_info_.LatVar(exclude_bin_idx, bin_idx) = 0;
    }
  }
}

//============================================================================
void BPFwder::PrintMatrix(BPFwder::PathInfo& path_info)
{
  if (!WouldLogD(kClassName))
  {
    return;
  }

  BinIndex  bin_idx = 0;
  BinIndex  nbr_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    std::stringstream ss;

    for (bool nbr_valid = bin_map_shm_.GetFirstPhyBinIndex(nbr_idx);
         nbr_valid;
         nbr_valid = bin_map_shm_.GetNextPhyBinIndex(nbr_idx))
    {
      if (path_info.LatMean(bin_idx, nbr_idx) == UINT32_MAX)
      {
        ss << "     I ";
      }
      else
      {
        ss << std::setw(6);
        ss << path_info.LatMean(bin_idx, nbr_idx) / 1000.0 << " ";
      }
    }

    LogD(kClassName, __func__, "BinIdx %" PRIBinIndex ": %s\n", bin_idx,
         ss.str().c_str());
  }
}

//============================================================================
void BPFwder::UpdateVirtQueues()
{
  // Update virtual queues for self.  The results are in virt_queue_info_.
  ComputeVirtQueues(my_bin_idx_);

  BinIndex  bin_idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
  {
    // The following prevents multiplying 'infinite' values for the
    // hop count by the hop count multiplier, which will of course
    // roll over and potentially cause problems downstream

    uint32_t  virt_queue_value =
      ((virt_queue_info_[bin_idx].hop_count_ == UINT32_MAX) ? UINT32_MAX :
       (virt_queue_info_[bin_idx].hop_count_ * virt_queue_mult_));

    queue_store_->GetVirtQueueDepths()->SetBinDepthByIdx(
      bin_idx, virt_queue_value);

    LogD(kClassName, __func__, "Setting virtual queue depth of %"
         PRIu32 "B to reach node %s from node %s (self).\n",
	 virt_queue_value,
         bin_map_shm_.GetIdToLog(bin_idx).c_str(),
	 bin_map_shm_.GetIdToLog(my_bin_idx_).c_str());
  }

  // Update virtual queues for neighbors.
  for (size_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    BinIndex nbr_bix = path_ctrls_[pc_i].path_ctrl->remote_bin_idx();

    if (!bin_map_shm_.BinIndexIsAssigned(nbr_bix))
    {
      // If the path controller's bin index is still kInvalidBinIndex, then
      // the path controller is not fully initialized yet (it still needs to
      // receive a QLAM message from its neighbor to set its remote bin id and
      // bin index values).  A warning message is not needed for this case.
      if (nbr_bix == kInvalidBinIndex)
      {
        LogA(kClassName, __func__, "Remote bin index for nbr on path ctrl %"
             PRIu32 " is not initialized yet, still waiting for a QLAM.\n",
             path_ctrls_[pc_i].path_ctrl->path_controller_number());
      }
      else
      {
        LogW(kClassName, __func__, "Remote bin %s for nbr %" PRIBinId
             " on path ctrl %" PRIu32 " is invalid.\n",
             bin_map_shm_.GetIdToLog(nbr_bix).c_str(),
             path_ctrls_[pc_i].path_ctrl->remote_bin_id(),
             path_ctrls_[pc_i].path_ctrl->path_controller_number());
      }
      continue;
    }

    ComputeVirtQueues(nbr_bix);

    for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
         valid;
         valid = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
    {
      // The following prevents multiplying 'infinite' values for the
      // hop count by the hop count multiplier, which will of course
      // roll over and potentially cause problems downstream

      uint32_t  virt_queue_value =
	((virt_queue_info_[bin_idx].hop_count_ == UINT32_MAX) ? UINT32_MAX :
	 (virt_queue_info_[bin_idx].hop_count_ * virt_queue_mult_));

      if (ApplyVirtQueueSet(bin_idx, nbr_bix, virt_queue_value))
      {
        // This should succeed almost solely for unit tests, where we
	// cannot wait for a QLAM that will never come.
	LogD(kClassName, __func__, "Setting virtual queue depth of %"
	     PRIu32 "B to reach node %s via relay node %s.\n",
	     virt_queue_value,
	     bin_map_shm_.GetIdToLog(bin_idx).c_str(),
	     bin_map_shm_.GetIdToLog(nbr_bix).c_str());
      }
      else
      {
        LogF(kClassName, __func__,
             "Failed to set virtual queue depth to reach node %s via node %s"
             ", will try again later (should not persist over connected "
             "link).\n",
	     bin_map_shm_.GetIdToLog(bin_idx).c_str(),
	     bin_map_shm_.GetIdToLog(nbr_bix).c_str());
      }
    }
  }

  // Since these have been updated, log them if "I" is set
  LogForwardingBiases();
}

//============================================================================
void BPFwder::ComputeVirtQueues(BinIndex ref_bin_idx)
{
  if (ref_bin_idx == my_bin_idx_)
  {
    LogD(kClassName, __func__, "Starting node is %s (self)\n",
	 bin_map_shm_.GetIdToLog(ref_bin_idx).c_str());
  }
  else
  {
    LogD(kClassName, __func__, "Starting node is %s (nbr)\n",
	 bin_map_shm_.GetIdToLog(ref_bin_idx).c_str());
  }

  // Initialize the hop count information.
  VirtQueueInfo  def_vqi(false, UINT32_MAX);

  virt_queue_info_.Clear(def_vqi);
  virt_queue_info_[ref_bin_idx].hop_count_ = 0;

  LogD(kClassName, __func__, "Node %s has a hop count "
       "of %" PRIu32 "\n",
       bin_map_shm_.GetIdToLog(ref_bin_idx).c_str(),
       virt_queue_info_[ref_bin_idx].hop_count_);

  while (true)
  {
    // Find the node with the shortest hop count.
    BinIndex  bin_idx      = 0;
    bool      more_bin_idx = false;
    uint32_t  min_hops     = UINT32_MAX;
    BinIndex  to_add       = kInvalidBinIndex;

    // Look for the node with the minimum hop count that
    // has not yet been visited -- i.e., marked as accepted
    for (more_bin_idx = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
          more_bin_idx;
          more_bin_idx = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
     {
       if ((virt_queue_info_[bin_idx].hop_count_ < min_hops) &&
           (virt_queue_info_[bin_idx].visited_ == false))
       {
         min_hops = virt_queue_info_[bin_idx].hop_count_;
         to_add   = bin_idx;
       }
     }

    // Add this node to the shortest path tree and set the distance for its
    // neighbors that are not yet in the tree.
    if (min_hops != UINT32_MAX)
    {
      NodeRecord*  node_record = node_records_[to_add];

      virt_queue_info_[to_add].visited_ = true;

      LogD(kClassName, __func__, "Adding node %s to tree\n",
	   bin_map_shm_.GetIdToLog(to_add).c_str());

      for (more_bin_idx = bin_map_shm_.GetFirstPhyBinIndex(bin_idx);
           more_bin_idx;
           more_bin_idx = bin_map_shm_.GetNextPhyBinIndex(bin_idx))
      {
        if ((!virt_queue_info_[bin_idx].visited_) &&
            (virt_queue_info_[bin_idx].hop_count_ == UINT32_MAX) &&
            (node_record != NULL) &&
            (node_record->records_[bin_idx].nbr_lat_mean_ != UINT32_MAX) &&
            (bin_idx != my_bin_idx_))
        {
          virt_queue_info_[bin_idx].hop_count_ =
            (virt_queue_info_[to_add].hop_count_ + 1);
          LogD(kClassName, __func__, "Node %s has a hop count "
               "of %" PRIu32 "\n",
	       bin_map_shm_.GetIdToLog(bin_idx).c_str(),
	       virt_queue_info_[bin_idx].hop_count_);
        }
      }
    }
    else
    {
      LogD(kClassName, __func__, "Hop count computation is done.\n");
      break;
    }
  }
}

//============================================================================
void BPFwder::LogForwardingBiases()
{
  LogI(kClassName, __func__, "Reporting forwarding biases:\n");

  // Retrieve the virtual queue for this node
  QueueDepths* qd = queue_store_->GetVirtQueueDepths();

  // Loop over all path controllers
  for (size_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    // Obtain the neighbor bin index from the controller
    BinIndex nbr_bin_idx = path_ctrls_[pc_i].path_ctrl->remote_bin_idx();

    if (!bin_map_shm_.BinIndexIsAssigned(nbr_bin_idx))
    {
      // If the path controller's bin index is still kInvalidBinIndex, then
      // the path controller is not fully initialized yet (it still needs to
      // receive a QLAM message from its neighbor to set its remote bin id and
      // bin index values).  A warning message is not needed for this case.
      if (nbr_bin_idx == kInvalidBinIndex)
      {
        LogI(kClassName, __func__, "  Remote bin index for nbr on path ctrl %"
             PRIu32 " is not yet initialized, waiting for a QLAM.\n",
             path_ctrls_[pc_i].path_ctrl->path_controller_number());
      }
      else
      {
        LogW(kClassName, __func__, "  Remote bin %s for nbr %" PRIBinId
             " on path ctrl %" PRIu32 " is invalid.\n",
             bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str(),
             path_ctrls_[pc_i].path_ctrl->remote_bin_id(),
             path_ctrls_[pc_i].path_ctrl->path_controller_number());
      }
      continue;
    }

    LogI(kClassName, __func__, "  Using neighbor node %s as a relay:\n",
	 bin_map_shm_.GetIdToLog(nbr_bin_idx).c_str());

    // Retrieve the Virtual QueueDepths object for this neighbor
    QueueDepths* nqd = queue_store_->PeekNbrVirtQueueDepths(nbr_bin_idx);

    if (nqd == NULL)
    {
      continue;
    }

    // Loop over all physical destinations

    BinIndex bin_idx = 0;
    for (bool valid = bin_map_shm_.GetFirstUcastBinIndex(bin_idx);
         valid;
         valid = bin_map_shm_.GetNextUcastBinIndex(bin_idx))
    {
      uint32_t my_depth  = qd->GetBinDepthByIdx(bin_idx);
      uint32_t nbr_depth = nqd->GetBinDepthByIdx(bin_idx);

      int32_t fwd_bias = 0;

      if ((my_depth == UINT32_MAX) && (nbr_depth == UINT32_MAX))
      {
	fwd_bias = 0;
      }
      else if (my_depth == UINT32_MAX)
      {
	fwd_bias = INT32_MAX;
      }
      else if (nbr_depth == UINT32_MAX)
      {
	fwd_bias = INT32_MIN;
      }
      else
      {
	fwd_bias = (int32_t)my_depth - (int32_t)nbr_depth;
      }

      if (fwd_bias == INT32_MAX)
      {
	LogI(kClassName, __func__, "    Bias to reach node %3s is    inf\n",
	     bin_map_shm_.GetIdToLog(bin_idx).c_str());
      }
      else if (fwd_bias == INT32_MIN)
      {
	LogI(kClassName, __func__, "    Bias to reach node %3s is   -inf\n",
	     bin_map_shm_.GetIdToLog(bin_idx).c_str());
      }
      else
      {
	LogI(kClassName, __func__, "    Bias to reach node %3s is %6" PRId32
	     " \n",bin_map_shm_.GetIdToLog(bin_idx).c_str(),fwd_bias);
      }
    }
  }
}

//============================================================================
void BPFwder::FindMinimumLatencyPath(BinIndex src_bin_idx)
{
  // Dijkstra using latency as a cost metric

  // Reset the arrays before setting specific elements.  Note that this uses
  // values from the matrixes in the path information.
  path_info_.ResetArrays(src_bin_idx);

  BinIndex  i = 0;
  BinIndex  j = 0;

  for (bool i_valid = bin_map_shm_.GetFirstPhyBinIndex(i);
       i_valid;
       i_valid = bin_map_shm_.GetNextPhyBinIndex(i))
  {
    int32_t  current = -1;

    for (bool j_valid = bin_map_shm_.GetFirstPhyBinIndex(j);
         j_valid;
         j_valid = bin_map_shm_.GetNextPhyBinIndex(j))
    {
      if (path_info_.Visited(j))
      {
        continue;
      }

      if ((current == -1) ||
          (path_info_.MinCost(j) < path_info_.MinCost(current)))
      {
        current = j;
      }
    }

    if (current < 0)
    {
      LogF(kClassName, __func__, "Current index is negative %" PRId32 ".\n",
           current);
    }

    path_info_.Visited(current) = true;

    for (bool j_valid = bin_map_shm_.GetFirstPhyBinIndex(j);
         j_valid;
         j_valid = bin_map_shm_.GetNextPhyBinIndex(j))
    {
      uint64_t  path  =
        (static_cast<uint64_t>(path_info_.MinLatMean(current)) +
         static_cast<uint64_t>(path_info_.LatMean(j, current)) +
         (2.2 * sqrt(path_info_.MinLatVar(current) +
                     path_info_.LatVar(j, current))));

      if (path < static_cast<uint32_t>(path_info_.MinCost(j)))
      {
        path_info_.MinCost(j)    = path;
        path_info_.NextHop(j)    = current;
        path_info_.MinLatMean(j) = (path_info_.MinLatMean(current) +
                                    path_info_.LatMean(j, current));
        path_info_.MinLatVar(j)  = (path_info_.MinLatVar(current) +
                                    path_info_.LatVar(j, current));
      }
    }
  }
}

//============================================================================
void BPFwder::PushStats()
{
  // Make sure that the pushing to an external client is still active.
  if (!stats_push_.is_active)
  {
    // We aren't pushing stats to an external client, but they still may be
    // logged to the log file.
    bpf_stats_.WriteStats();
  }
  else
  {
    // Start the next push of statistics to the remote control client.
    Writer<StringBuffer>* writer =
      remote_control_.StartPushMessage(stats_push_.client_id,
                                       stats_push_.msg_id);

    // If NULL is returned, then we must stop pushing statistics immediately.
    if (writer == NULL)
    {
      LogD(kClassName, __func__, "Stopping statistics pushing.\n");

      stats_push_.is_active    = false;
      stats_push_.client_id    = 0;
      stats_push_.msg_id       = 0;
      stats_push_.interval_sec = 0.0;

      // The external client is no longer connected but the stats may still be
      // logged to the log file.
      bpf_stats_.WriteStats();
    }
    else
    {
      // Add in the statistics.
      bpf_stats_.WriteStats(writer);

      // Complete the push message and send it.
      remote_control_.SendPushMessage(stats_push_.client_id);
    }
  }

  // Start the next timer.
  CallbackNoArg<BPFwder>  cbna(this, &BPFwder::PushStats);
  Time                    delta_time;

  if (stats_push_.is_active)
  {
    // We use the statistics interval extracted from the JSON message received
    // from the external client.
    delta_time = Time(stats_push_.interval_sec);
  }
  else
  {
    // We will use the statistics interval from the configuration.
    delta_time = Time::FromMsec(stats_interval_ms_);
  }

  if (!timer_.StartTimer(delta_time, &cbna, stats_push_.timer_handle))
  {
    LogE(kClassName, __func__, "Error setting next statistics push timer.\n");

    if (stats_push_.is_active)
    {
      remote_control_.SendPushErrorMessage(stats_push_.client_id,
                                           stats_push_.msg_id,
                                           "Timer error.");
    }

    stats_push_.is_active    = false;
    stats_push_.client_id    = 0;
    stats_push_.msg_id       = 0;
    stats_push_.interval_sec = 0.0;
  }
}

//============================================================================
void BPFwder::PushFlowStats()
{
  // The flow statistics are never logged to the log file.
  //
  // "flow_stats" "keyvals" format of the "push" message is as follows:
  //
  //   "flow_stats" :
  //   [
  //     {
  //       "endpoints" : "a.b.c.d[:xx]->e.f.g.h[:yy]",
  //       "byte_cnt" : xx
  //     },
  //   ]

  // Make sure that the pushing to an external client is still active.
  if (!flow_stats_push_.is_active)
  {
    return;
  }

  // Start the next push of flow statistics to the remote control client.
  Writer<StringBuffer>* writer =
    remote_control_.StartPushMessage(flow_stats_push_.client_id,
                                     flow_stats_push_.msg_id);

  // If NULL is returned, then we must stop pushing statistics immediately.
  if (writer == NULL)
  {
    LogD(kClassName, __func__, "Stopping flow statistics pushing.\n");

    flow_stats_push_.is_active    = false;
    flow_stats_push_.client_id    = 0;
    flow_stats_push_.msg_id       = 0;
    flow_stats_push_.interval_sec = 0.0;
  }
  else
  {
    // Append "flow_stats" : [
    writer->Key("flow_stats");
    writer->StartArray();

    // Add the "flow_stats" information. This is extracted from the path
    // controllers.
    for (size_t i = 0; i < num_path_ctrls_; ++i)
    {
      // Start the current path information with the "{' character.
      writer->StartObject();

      // Append "endpoints" : "a.b.c.d[:xx]->e.f.g.h[:yy]"
      writer->Key("endpoints");
      writer->String(path_ctrls_[i].path_ctrl->endpoints_str().c_str());

      // Append "byte_cnt" : xxxx
      writer->Key("byte_cnt");
      writer->Uint64(path_ctrls_[i].flow_stats.Report());

      // End the current path information with the '}' character.
      writer->EndObject();
    }

    // End the "flow_stats" array with the ']' character.
    writer->EndArray();

    // Complete the push message and send it.
    remote_control_.SendPushMessage(flow_stats_push_.client_id);
  }

  // Start the next timer.
  if (flow_stats_push_.is_active)
  {
    CallbackNoArg<BPFwder>  cbna(this, &BPFwder::PushFlowStats);
    Time                    delta_time = Time(flow_stats_push_.interval_sec);

    if (!timer_.StartTimer(delta_time, &cbna, flow_stats_push_.timer_handle))
    {
      LogE(kClassName, __func__, "Error setting next flow statistics push "
           "timer.\n");

      remote_control_.SendPushErrorMessage(flow_stats_push_.client_id,
                                           flow_stats_push_.msg_id,
                                           "Timer error.");

      flow_stats_push_.is_active    = false;
      flow_stats_push_.client_id    = 0;
      flow_stats_push_.msg_id       = 0;
      flow_stats_push_.interval_sec = 0.0;
    }
  }
}

//============================================================================
void BPFwder::ProcessBroadcastPacket(Packet* packet, PathController* path_ctrl)
{
  BinId           src_bin_id = 0;
  uint16_t        seq_num    = 0;
  const uint8_t*  data       = NULL;
  size_t          data_len   = 0;

  if (!packet->ParseBroadcastPacket(src_bin_id, seq_num, &data, data_len))
  {
    LogE(kClassName, __func__, "Invalid broadcast packet received.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    packet = NULL;
    return;
  }

  BinIndex  src_bin_idx = bin_map_shm_.GetPhyBinIndex(src_bin_id);

  if (src_bin_idx == kInvalidBinIndex)
  {
    LogF(kClassName, __func__, "Broadcast packet has invalid source bin id: %"
         PRIBinId ".\n", src_bin_id);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    packet = NULL;
    return;
  }

  if (src_bin_id == my_bin_id_)
  {
    LogD(kClassName, __func__,
         "Broadcast packet came from self, do not forward or process.\n");
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  LogD(kClassName, __func__,
       "Broadcast packet %p from src bin id %" PRIBinId " with seq num %"
       PRIu16 "\n", packet, src_bin_id, seq_num);

  BroadcastIndex  bc_idx      = LSA_BC_IDX;

  // Detect new info vs repeat/old, including rollover.
  //
  // Note: if subtracting two unsigned values would result in a
  // negative number, the result is the negative number modulo MAX+1, which is
  // the same as "counting backwards" around the ring of unsigned values.
  // By casting the result to a signed value of the same size and comparing to
  // 0, we are examining the most significant digit in the result, which is
  // essentially checking whether or not the distance (in the ring) is greater
  // than or equal to 0x8000 (2^15).
  if ((int16_t)(seq_num - broadcast_seq_nums_[bc_idx][src_bin_idx]) <= 0)
  {
    LogD(kClassName, __func__, "Broadcast packet (%p) is repeated or old, "
         "dropping. Received seq_num %" PRIu16 ", Last seq num %" PRIu16
         "\n", packet, seq_num, broadcast_seq_nums_[bc_idx][src_bin_idx]);
    TRACK_EXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }

  // Update the sequence number to record this new packet.
  broadcast_seq_nums_[LSA_BC_IDX][src_bin_idx] = seq_num;

  // Send it on. BroadcastPacket does NOT take control of the original
  // packet. It uses deep copies and does NOT recycle the original.
  BroadcastPacket(packet, path_ctrl->remote_bin_idx());

  // And process.
  PacketType type = packet->GetType();
  switch(type)
  {
    case LSA_PACKET:
      ProcessLsa(src_bin_idx, data, data_len);
      break;
    default:
      LogE(kClassName, __func__,
           "No code to handle broadcast packet of type %d.\n", type);
  }
  // It's safe to recycle here even though the packet has been re-broadcast
  // because BroadcastPacket made a (deep) copy for each distribution.
  packet_pool_.Recycle(packet);
}

//============================================================================
void BPFwder::ProcessLsa(BinIndex src_bin_index,
                         const uint8_t* data, size_t data_len)
{
  NodeRecord*  node_record = AccessOrAllocateNodeRecord(src_bin_index);

  if (node_record == NULL)
  {
    LogE(kClassName, __func__, "Error getting node record for bin index %"
         PRIBinIndex ".\n", src_bin_index);
    return;
  }

  // Check that all CATs have been properly initialized before
  // processing LSAs.
  for (size_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    PathController* path_ctrl = path_ctrls_[pc_i].path_ctrl;
    if (iron::kInvalidBinIndex == path_ctrl->remote_bin_idx())
    {
      LogW(kClassName, __func__, "Not ready to process LSAs\n");
      return;
    }
  }

  uint8_t num_nbrs  = *data;
  ++data;

  uint8_t num_bin_ids = *data;
  ++data;

  bool  capacity_included = (((*data) & 0x1) == 0x1 ? true : false);

  data += 2; // Move by one, skip byte of padding.

  LogD(kClassName, __func__,
       "LSA from node id %" PRIBinId " lists %" PRIu8 " neighbors, %s"
       "queuing delay and %scapacity.\n",
       bin_map_shm_.GetPhyBinId(src_bin_index),
       num_nbrs, num_bin_ids == 0 ? "no " : "",
       capacity_included ? "" : "no ");

  // Use the default NodeInfo constructor to initialize the values in the LSA
  // information array.  The mean latency is initialized to UINT32_MAX and the
  // capacity is initialized to -1.0.
  NodeInfo  def_info;

  lsa_info_.Clear(def_info);

  for (uint8_t nbr_i = 0; nbr_i < num_nbrs; ++nbr_i)
  {
    // Each neighbor in the list has:
    // 1 byte BinId
    // 2 bytes latency (mean)
    // 2 bytes latency (standard deviation)
    BinId  nbr_id = *data;
    data++; // Bin id.

    uint16_t  nbr_lat_mean;
    uint16_t  nbr_lat_sd;
    memcpy(&nbr_lat_mean, data, sizeof(nbr_lat_mean));
    nbr_lat_mean  = ntohs(nbr_lat_mean);
    data         += sizeof(nbr_lat_mean);
    memcpy(&nbr_lat_sd, data, sizeof(nbr_lat_sd));
    nbr_lat_sd    = ntohs(nbr_lat_sd);
    data         += sizeof(nbr_lat_sd);

    BinIndex  nbr_idx = bin_map_shm_.GetPhyBinIndex(nbr_id);

    if (nbr_idx == kInvalidBinIndex)
    {
      LogF(kClassName, __func__, "Malformed LSA: record %" PRIu8 " contains "
           "invalid nbr_id %" PRIBinId ".\n", nbr_i, nbr_id);
    }

    lsa_info_[nbr_idx].nbr_lat_mean_ =
      static_cast<uint32_t>(nbr_lat_mean) * 100;
    lsa_info_[nbr_idx].nbr_lat_var_  = static_cast<uint64_t>(nbr_lat_sd) *
      static_cast<uint64_t>(nbr_lat_sd) * 1e4;

    LogD(kClassName, __func__, "Node %" PRIBinId " (idx %" PRIBinIndex
         ") has %" PRIu32 "us latency (%" PRIu32 "us sd) to neighbor %"
         PRIBinId " (idx %" PRIBinIndex ").\n",
         bin_map_shm_.GetPhyBinId(src_bin_index), src_bin_index,
         static_cast<uint32_t>(nbr_lat_mean) * 100,
         static_cast<uint32_t>(nbr_lat_sd) * 100, nbr_id, nbr_idx);

    if (capacity_included)
    {
      //  0              .    1          .
      //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
      // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      // |   e   |   i   |       d       |
      // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      uint8_t e = *data;
      uint8_t i = e & 0xF;
      e       >>= 4;
      data     += sizeof(e);

      uint8_t d = *data;
      data     += sizeof(d);

      lsa_info_[nbr_idx].capacity_ = DecodeCapacity(e, i, d);
      LogD(kClassName, __func__,
           "Capacity between node %s and its nbr %" PRIBinId
           " is %.0fbps.\n",
           bin_map_shm_.GetPhyBinId(src_bin_index),
           nbr_id, lsa_info_[nbr_idx].capacity_);
    }
  }

  // Copy the new NodeInfo values into the node record.  Do this for unicast
  // destination, interior node, and multicast destination bin indexes.
  BinIndex  bin_idx = kInvalidBinIndex;

  for (bool bin_idx_valid = bin_map_shm_.GetFirstBinIndex(bin_idx);
       bin_idx_valid;
       bin_idx_valid = bin_map_shm_.GetNextBinIndex(bin_idx))
  {
    NodeInfo&  node_info = node_record->records_[bin_idx];

    node_info.nbr_lat_mean_ = lsa_info_[bin_idx].nbr_lat_mean_;
    node_info.nbr_lat_var_  = lsa_info_[bin_idx].nbr_lat_var_;
    node_info.capacity_     = lsa_info_[bin_idx].capacity_;
  }

  for (uint8_t bin_id_idx = 0; bin_id_idx < num_bin_ids; ++bin_id_idx)
  {
    BinId  bin_id = *data;
    ++data;

    bin_idx = bin_map_shm_.GetPhyBinIndex(bin_id);

    if (bin_idx == kInvalidBinIndex)
    {
      LogF(kClassName, __func__, "Malformed LSA: contained out-of-range "
           "bin id %" PRIu8 ".\n", bin_id);
    }

    uint32_t  delay_nbo = 0;
    memcpy(reinterpret_cast<uint8_t*>(&delay_nbo), data, 3);
    data  += 3;
    node_record->records_[bin_idx].queue_delay_ = (ntohl(delay_nbo));
    LogD(kClassName, __func__,
         "Node %" PRIBinId " has a queue delay of %" PRIu32 "us to dst "
         "BinId %" PRIBinId ".\n",
         bin_map_shm_.GetPhyBinId(src_bin_index),
         node_record->records_[bin_idx].queue_delay_,
         bin_id);
  }

  // TODO: Consider if we could clear out only portions of the cache.
  LogD(kClassName, __func__, "Resetting cache.\n");
  Time now                  = Time::Now();
  latency_cache_reset_time_ = now;

  // Update the historyless latency cache.
  if ((now.GetTimeInMsec() - latency_pbpp_update_time_ms_) >
      kLatencyCalculationIntervalMs)
  {
    latency_pbpp_update_time_ms_ = now.GetTimeInMsec();
    // Latencies to each destination node in the network means that the bin
    // indexes considered are for unicast destinations only.
    uint32_t  latencies_us[kMaxPathCtrls];
    BinIndex  dst_bin_idx = 0;

    for (bool valid = bin_map_shm_.GetFirstUcastBinIndex(dst_bin_idx);
         valid;
         valid = bin_map_shm_.GetNextUcastBinIndex(dst_bin_idx))
    {
      if (dst_bin_idx == my_bin_idx_)
      {
        continue;
      }
      GetPerPcLatencyToDst(dst_bin_idx, (uint32_t*) latencies_us, true);
      uint32_t min_latency = numeric_limits<uint32_t>::max();
      for (size_t pc=0; pc < num_path_ctrls_; ++pc)
      {
        BinIndex  pc_bin_idx = path_ctrls_[pc].path_ctrl->remote_bin_idx();

        // Skip path controllers that have not connected yet.
        if (pc_bin_idx == kInvalidBinIndex)
        {
          continue;
        }

        string  next_hop =
          bpf_stats_.CreateRemoteNodeAddrForPC(path_ctrls_[pc].path_ctrl);
        bpf_stats_.ReportLatencyUpdate(dst_bin_idx, next_hop, latencies_us[pc]);
        LogD(kClassName, __func__,
             "Report %" PRIu32 "us latency to proxy for bin %s on pc "
             "%zu.\n",
             latencies_us[pc], bin_map_shm_.GetIdToLog(dst_bin_idx).c_str(), pc);
        if ((latencies_us[pc] != 0) && (latencies_us[pc] < min_latency))
        {
          min_latency = latencies_us[pc];
        }
      }
      shm_latency_cache_.SetMinLatency(dst_bin_idx, min_latency);
    }
  }
}

//============================================================================
void BPFwder::ForwardPacket(Packet* packet, BinIndex dst_bin_idx)
{
  if (bin_map_shm_.BinIndexIsAssigned(dst_bin_idx))
  {
    // Don't look for TTG rules for multicast packets - we won't have a
    // latency to that destination.
    // MCAST TODO: change this when we implement latency results for
    // multicast.
    if ((packet->GetLatencyClass() == iron::LOW_LATENCY) &&
        (!bin_map_shm_.IsMcastBinIndex(dst_bin_idx)))
    {
      // Prepare the low-latency packet by giving it an ordering time.
      uint32_t  latencies_us[kMaxPathCtrls];
      memset(latencies_us, 0, sizeof(latencies_us));
      size_t    dummy_path_ctrl_index = 0;
      Time      min_ttr               = Time(0);

      GetPerPcLatencyToDst(
        dst_bin_idx, (uint32_t*) latencies_us, true, packet);
      iron::UberFwdAlg::GetMinLatencyPath(latencies_us, num_path_ctrls_,
        dummy_path_ctrl_index, min_ttr);
      LogD(kClassName, __func__,
           "Pkt %s (%p) with ttg %s can reach dst in at least %s.\n",
           packet->GetPacketMetadataString().c_str(), packet,
           packet->GetTimeToGo().ToString().c_str(),
           min_ttr.ToString().c_str());

      if (packet->GetTimeToGo() < min_ttr)
      {
        BinQueueMgr* q_mgr    = queue_store_->GetBinQueueMgr(dst_bin_idx);
        uint16_t  packet_len  = packet->virtual_length();
        if (drop_expired_ || !q_mgr->ZombifyPacket(packet))
        {
          dropped_bytes_[dst_bin_idx] += packet_len;
          TRACK_EXPECTED_DROP(kClassName, packet_pool_);
          LogD(kClassName, __func__,
               "Dropped packet %p (Zombification failed).\n", packet);
          packet_pool_.Recycle(packet);
        }
        else
        {
          LogD(kClassName, __func__,
               "Pkt %p Zombified, cannot reach.\n", packet);
        }
        return;
      }
      if (ef_ordering_ == EF_ORDERING_DELIVERY_MARGIN)
      {
        packet->SetOrderTime(packet->GetTimeToGo() - min_ttr);
      }
      else if (ef_ordering_ == EF_ORDERING_TTG)
      {
        packet->SetOrderTime(packet->GetTimeToGo());
      }
      else
      {
        packet->SetOrderTime(packet->recv_time());
      }
    }

    // Enqueue the received packet for forwarding.
    if (!queue_store_->GetBinQueueMgr(dst_bin_idx)->Enqueue(packet))
    {
      LogF(kClassName, __func__, "Queue is full for bin_id %s.\n",
           bin_map_shm_.GetIdToLog(dst_bin_idx).c_str());
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(packet);
      packet = NULL;
    }
    else
    {
      num_bytes_processed_  += packet->GetLengthInBytes();

      if (num_bytes_processed_ >= min_qd_change_shm_bytes_)
      {
        if (!queue_store_->PublishWQueueDepthsToShm())
        {
          LogW(kClassName, __func__, "Could not write queue depths to shared "
               "memory.\n");
        }
        else
        {
          LogD(kClassName, __func__, "Wrote queue depths to shared memory "
               "early after processing %" PRIu32 "B.\n",
               num_bytes_processed_);
          num_bytes_processed_  = 0;
        }
      }
    }
  }
  else
  {
    LogE(kClassName, __func__, "Cannot forward a packet to non-existent bin "
         "%s (idx %" PRIBinIndex ").\n",
         bin_map_shm_.GetIdToLog(dst_bin_idx).c_str(), dst_bin_idx);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    packet = NULL;
  }
}

//============================================================================
void BPFwder::GetEncodedCapacity(BinIndex bin_idx, uint8_t& e, uint8_t& i,
  uint8_t& d)
{
  double  capacity  = 0.;

  for (uint8_t pc_i = 0; pc_i < num_path_ctrls_; ++pc_i)
  {
    PathCtrlInfo* pc_info = &(path_ctrls_[pc_i]);

    if (pc_info->path_ctrl &&
      (pc_info->path_ctrl->remote_bin_idx() == bin_idx))
    {
      capacity  = pc_info->link_capacity_bps;
      break;
    }
  }

  if (capacity == 0)
  {
    e = 0;
    i = 0;
    d = 0;
    return;
  }

// Define an appropriate value for resizing the
// decimal. For 8bits 0.99.. can be represented over
// 255 values, or close to 4e-3.  The scaled decimal
// value should therefore never be above 249.
#define K_DECIMAL_FACTOR  (4e-3)
  e               = log10(capacity);
  uint64_t  e_int = pow(10, e);
  i               = capacity / e_int;
  // e_int cannot be 0.
  d               = round(static_cast<double>(capacity - i * e_int)
    / (e_int * K_DECIMAL_FACTOR));

  if ((e > 0xF) || (i > 9) || (d > 250))
  {
    LogW(kClassName, __func__,
         "Encoding error: e=%" PRIu8 " i=%" PRIu8 " or d=%" PRIu8 " is too big."
         " Is the capacity %.0f too large to encode (max supported: 9.99x10^15)"
         "?\n",
         e, i, d, capacity);
    return;
  }

  LogD(kClassName, __func__,
       "Capacity %.0fbps should be encoded with (i=%" PRIu8 ".(d=%"
       PRIu8 " x %.3f) x 10^%" PRIu8 ").\n",
       capacity, i, d, K_DECIMAL_FACTOR, e);
}

//============================================================================
double BPFwder::DecodeCapacity(uint8_t e, uint8_t i, uint8_t d)
{
  return static_cast<double>((i + (d * K_DECIMAL_FACTOR)) * pow(10, e));
}

//============================================================================
BPFwder::NodeRecord* BPFwder::AccessOrAllocateNodeRecord(BinIndex bin_idx)
{
  // First, validate the bin index.
  if (!bin_map_shm_.BinIndexIsAssigned(bin_idx))
  {
    LogE(kClassName, __func__, "Error, invalid bin index %" PRIBinIndex
         ".\n", bin_idx);
    return NULL;
  }

  // Look up the node record.
  NodeRecord*  node_record = node_records_[bin_idx];

  if (node_record == NULL)
  {
    // Allocate and initialize a new node record.
    node_record = new (std::nothrow) NodeRecord();

    if (node_record == NULL)
    {
      LogE(kClassName, __func__, "Error allocating new node record.\n");
      return NULL;
    }

    if (!node_record->Initialize(bin_map_shm_))
    {
      LogE(kClassName, __func__, "Error initializing new node record for bin "
           "index %" PRIBinIndex ".\n", bin_idx);
      delete node_record;
      return NULL;
    }

    // Store the new node record.
    node_records_[bin_idx] = node_record;
  }

  return node_record;
}

//============================================================================
void BPFwder::PrintLsa(Packet* packet)
{
  if (!packet)
  {
    return;
  }

  uint8_t*  buffer  = packet->GetBuffer();

  if (*buffer != LSA_PACKET)
  {
    LogW(kClassName, __func__,
         "Error: not LSA packet.  Cannot process.\n");
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(packet);
    return;
  }
  ++buffer;

  BinId  sender_id = *buffer;
  ++buffer;

  if (bin_map_shm_.GetPhyBinIndex(sender_id) == kInvalidBinIndex)
  {
    LogF(kClassName, __func__,
         "Malformed LSA: sender_id is %" PRIBinId ".\n", sender_id);
  }

  uint16_t  lsa_seq_num;
  memcpy(&lsa_seq_num, buffer, sizeof(lsa_seq_num));
  buffer     += sizeof(lsa_seq_num);
  lsa_seq_num = ntohs(lsa_seq_num);

  uint8_t num_nbrs    = *buffer;
  ++buffer;
  uint8_t UNUSED(num_bin_ids) = *buffer;
  ++buffer;
  bool    capacity_included = (*buffer == 0x1);
  buffer                   += 2; // Skip padding.

  LogD(kClassName, __func__,
       "---- Print LSA (%p) ----\n", packet);

  LogD(kClassName, __func__,
       "Sender Id: %" PRIBinId ", NumNbrs: %" PRIu8 ", NumBinIds: %" PRIu8
       ", SeqNum: %" PRIu16 ", %s capacity.\n",
       sender_id, num_nbrs, num_bin_ids, lsa_seq_num,
       capacity_included ? "includes" : "does not include");

  for (uint8_t nbr_i = 0; nbr_i < num_nbrs; ++nbr_i)
  {
    BinId  nbr_id = *buffer;
    ++buffer;

    uint16_t  nbr_latency_mean;
    uint16_t  nbr_latency_sd;
    memcpy(&nbr_latency_mean, buffer, sizeof(nbr_latency_mean));
    nbr_latency_mean  = ntohs(nbr_latency_mean);
    buffer           += sizeof(nbr_latency_mean);
    memcpy(&nbr_latency_sd, buffer, sizeof(nbr_latency_sd));
    nbr_latency_sd    = ntohs(nbr_latency_sd);
    buffer           += sizeof(nbr_latency_sd);

    if (bin_map_shm_.GetPhyBinIndex(nbr_id) == kInvalidBinIndex)
    {
      LogF(kClassName, __func__,
           "Malformed LSA: record %" PRIu8 " shows nbr_id is %" PRIBinId
           ".\n", nbr_i, nbr_id);
    }
    LogD(kClassName, __func__,
         "NbrId: %" PRIBinId ", Latency: %" PRIu16 "us (standard dev: %"
         PRIu32 "us).\n",
         nbr_id, nbr_latency_mean * 100,
         static_cast<uint32_t>(nbr_latency_sd) * 100);

    if (capacity_included)
    {
      uint8_t e = *buffer;
      ++buffer;
      uint8_t UNUSED(i) = e & 0xF;
      e       >>= 4;
      uint8_t UNUSED(d) = *buffer;
      ++buffer;
      LogD(kClassName, __func__,
           "Capacity is %.0fbps.\n", DecodeCapacity(e, i, d));
    }
  }

  BinIndex  idx = 0;

  for (bool valid = bin_map_shm_.GetFirstPhyBinIndex(idx);
       valid;
       valid = bin_map_shm_.GetNextPhyBinIndex(idx))
  {
    ++buffer;

    uint32_t  queue_delay = 0;
    memcpy(&queue_delay, buffer, 3);
    buffer  += 3;
    queue_delay = ntohl(queue_delay);
    LogD(kClassName, __func__,
         "Latency to BinId %s is %" PRIu32 "ms.\n",
         bin_map_shm_.GetIdToLog(idx).c_str(), queue_delay / 1000);
  }

  LogD(kClassName, __func__,
       "------- LSA (%p) -------\n", packet);
}

//============================================================================
bool BPFwder::PathInfo::Initialize(BinMap& bin_map)
{
  // Allocate and initialize the BinIndex to array index mapping.  This
  // mapping needs to support unicast destination and interior node
  // BinIndexes.
  size_t  max_dst_bin_idx = (bin_map.ucast_bin_idx_offset() +
                             bin_map.max_num_ucast_bin_idxs());
  size_t  max_int_bin_idx = (bin_map.int_bin_idx_offset() +
                             bin_map.max_num_int_bin_idxs());
  size_t  mapping_size    = ((max_int_bin_idx > max_dst_bin_idx) ?
                             max_int_bin_idx : max_dst_bin_idx);

  LogD(kPIClassName, __func__, "Allocating bin index to array index mapping "
       "of size %zu elements.\n", mapping_size);

  a_idx_ = new (std::nothrow) BinIndex[mapping_size];

  if (a_idx_ == NULL)
  {
    return false;
  }

  BinIndex  bin_idx = 0;

  for (bin_idx = 0; bin_idx < mapping_size; ++bin_idx)
  {
    a_idx_[bin_idx] = kInvalidBinIndex;
  }

  max_bin_idx_ = (mapping_size - 1);
  num_         = 0;

  for (bool valid = bin_map.GetFirstPhyBinIndex(bin_idx);
       valid;
       valid = bin_map.GetNextPhyBinIndex(bin_idx))
  {
    if (bin_idx >= mapping_size)
    {
      LogF(kPIClassName, __func__, "Mapping array size exceeded, bin_idx %"
           PRIBinIndex " size %zu.\n", bin_idx, mapping_size);
      return false;
    }

    LogD(kPIClassName, __func__, "Mapping bin index %" PRIBinIndex
         " to array index %zu.\n", bin_idx, num_);

    a_idx_[bin_idx] = num_;
    ++num_;
  }

  LogD(kPIClassName, __func__, "Allocating arrays of size %zu.\n", num_);

  // Allocate the arrays using num_ as the size of each dimension.
  nodes_to_exclude_ = new (std::nothrow) BinIndex[num_];

  lat_mean_matrix_ = new (std::nothrow) uint32_t[num_ * num_];
  lat_var_matrix_  = new (std::nothrow) uint64_t[num_ * num_];

  min_lat_mean_ = new (std::nothrow) uint32_t[num_];
  min_lat_var_  = new (std::nothrow) uint64_t[num_];
  next_hop_     = new (std::nothrow) uint32_t[num_];
  visited_      = new (std::nothrow) bool[num_];
  min_cost_     = new (std::nothrow) uint32_t[num_];

  if ((nodes_to_exclude_ == NULL) || (lat_mean_matrix_ == NULL) ||
      (lat_var_matrix_ == NULL) || (min_lat_mean_ == NULL) ||
      (min_lat_var_ == NULL) || (next_hop_ == NULL) || (visited_ == NULL) ||
      (min_cost_ == NULL))
  {
    return false;
  }

  ResetMatrixes();

  for (size_t i = 0; i < num_; ++i)
  {
    nodes_to_exclude_[i] = 0;
    min_lat_mean_[i]     = UINT32_MAX;
    min_lat_var_[i]      = 0;
    next_hop_[i]         = 0;
    visited_[i]          = false;
    min_cost_[i]         = UINT32_MAX;
  }

  return true;
}

//============================================================================
void BPFwder::PathInfo::ResetMatrixes()
{
  memset(lat_mean_matrix_, UINT8_MAX, (num_ * num_ * sizeof(uint32_t)));
  memset(lat_var_matrix_,  0,         (num_ * num_ * sizeof(uint64_t)));
}

//============================================================================
void BPFwder::PathInfo::ResetArrays(BinIndex src)
{
  BinIndex  ai = a_idx_[src];

  if (ai >= num_)
  {
    LogE(kPIClassName, __func__, "Error, for src %" PRIBinIndex ", index %"
         PRIBinIndex " >= num_ %zu\n", src, ai, num_);
    ai = (num_ - 1);
  }

  for (size_t i = 0; i < num_; ++i)
  {
    min_lat_mean_[i] = lat_mean_matrix_[((i * num_) + ai)];
    min_lat_var_[i]  = lat_var_matrix_[((i * num_) + ai)];
    next_hop_[i]     = ai;
    visited_[i]      = false;
    min_cost_[i]     = (min_lat_mean_[i] + (2.2 * sqrt(min_lat_var_[i])));
  }
}

//============================================================================
BPFwder::PathInfo::~PathInfo()
{
  if (a_idx_ != NULL)
  {
    delete [] a_idx_;
    a_idx_ = NULL;
  }

  if (nodes_to_exclude_ != NULL)
  {
    delete [] nodes_to_exclude_;
    nodes_to_exclude_ = NULL;
  }

  if (lat_mean_matrix_ != NULL)
  {
    delete [] lat_mean_matrix_;
    lat_mean_matrix_ = NULL;
  }

  if (lat_var_matrix_ != NULL)
  {
    delete [] lat_var_matrix_;
    lat_var_matrix_ = NULL;
  }

  if (min_lat_mean_ != NULL)
  {
    delete [] min_lat_mean_;
    min_lat_mean_ = NULL;
  }

  if (min_lat_var_ != NULL)
  {
    delete [] min_lat_var_;
    min_lat_var_ = NULL;
  }

  if (next_hop_ != NULL)
  {
    delete [] next_hop_;
    next_hop_ = NULL;
  }

  if (visited_ != NULL)
  {
    delete [] visited_;
    visited_ = NULL;
  }

  if (min_cost_ != NULL)
  {
    delete [] min_cost_;
    min_cost_ = NULL;
  }
}
