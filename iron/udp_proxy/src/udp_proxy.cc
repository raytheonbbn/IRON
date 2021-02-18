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

#include "udp_proxy.h"
#include "bin_map.h"
#include "fifo_if.h"
#include "ipv4_endpoint.h"
#include "iron_constants.h"
#include "list.h"
#include "log.h"
#include "packet_pool.h"
#include "release_controller.h"
#include "rrm.h"
#include "string_utils.h"
#include "shared_memory_if.h"
#include "string_utils.h"
#include "timer.h"
#include "unused.h"
#include "utility_fn_if.h"
#include "vdmfec.h"

#include <algorithm>
#include <limits>
#include <sstream>

#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/types.h>
#include <linux/filter.h>

using ::iron::BinIndex;
using ::iron::BinMap;
using ::iron::CallbackNoArg;
using ::iron::ConfigInfo;
using ::iron::DstVec;
using ::iron::FifoIF;
using ::iron::FourTuple;
using ::iron::HashTable;
using ::iron::Ipv4Address;
using ::iron::Ipv4Endpoint;
using ::iron::IPV4_PACKET;
using ::iron::kInvalidBinIndex;
using ::iron::KVal;
using ::iron::List;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketFifo;
using ::iron::PACKET_OWNER_BPF;
using ::iron::PacketPool;
using ::iron::PacketType;
using ::iron::PktMemIndex;
using ::iron::RmtCntlMsgType;
using ::iron::SharedMemoryIF;
using ::iron::StringUtils;
using ::iron::Time;
using ::iron::Timer;
using ::rapidjson::SizeType;
using ::rapidjson::StringBuffer;
using ::rapidjson::Value;
using ::rapidjson::Writer;
using ::std::map;
using ::std::set;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(cn) = "UdpProxy";

  /// Starting timer tag for UDP contexts (must be larger than ones
  /// defined above) and must be even
  const uint32_t  kStartTag = 10;

  /// The default queue depth update interval.
  const uint32_t  kDefaultQueueDepthUpdateIntervalUs = 1000;

  /// The default statistics collection interval.
  const uint32_t  kDefaultStatsCollectionIntervalMs = 5000;

  /// The maximum number of packets to be read from a FIFO at once.
  const size_t    kMaxPktsPerFifoRecv = 16;

  /// Default value for directive to log collected statistics.
  const bool      kDefaultLogStats = true;

  /// Must release packets at least this many seconds before
  /// their expiration.
  const Time      kDeadlineMod = Time(0.0001);

  /// Default for the maximum size (in packets) of the encoded_pkts_queue.
  /// Once packets are encoded, they are stored in this queue until they
  /// are admitted into the network by admissions control.
  const uint32_t  kDefaultMaxQueueDepthPerFlowPkts = 500;

  // Default port used to control the UDP proxy.
  const unsigned short kDefaultRemoteControlPort = 3144;

  // Default for whether to overwrite the sequence number and tx timestamp of
  // an MGEN packet.
  const char*     kDefaultMGENDiagnosticsMode = "none";

  // Default for the garbage collection cleanup interval in seconds.
  const unsigned long kDefaultGCIntervalSec = 120;

  // Default for the decoder cleanup timeout interval.
  const unsigned long kDefaultDecoderTimeoutSec = 120;

  // Default for maximum hold time when reordering packets. 0 means packets
  // are not held.
  const double    kDefaultMaxHoldTimeSec = 0.0;

  // How often we perform periodic processing.
  const unsigned long kPPIntervalMsec = 20000;

  /// The number of buckets in the encoding hash table.  This value supports
  /// fast lookups with up to 10,000 flows.
  const size_t  kEncodingHashTableBuckets = 32768;

  /// The number of buckets in the decoding hash table.  This value supports
  /// fast lookups with up to 10,000 flows.
  const size_t  kDecodingHashTableBuckets = 32768;

  /// The number of buckets in the flow definition hash table.  This value
  /// supports fast lookups with up to 10,000 flows.
  const size_t  kFlowDefnHashTableBuckets = 32768;

  /// The number of buckets in the release records hash tables.
  // TODO: Not profiled.  Currently supports 16flows per source.
  const size_t  kRecordsHashTableBuckets  = 16;

  /// The default RRM interval to send periodic loss-rate feedback,
  /// in milliseconds.
  const uint32_t  kPeriodicRrmIntervalMsec = 100;

  /// Latency checks are not enabled by default.
  const bool      kDefaultDoLatencyChecks = false;

  /// Loss triage is enabled by default.
  const bool kDefaultEnableLossTriage = true;

  /// The default service flows interval, in microseconds.
  const uint32_t  kDefaultSvcFlowsIntervalUs =
    iron::kDefaultBpfMinBurstUsec / 2;

  /// The default service definition.
  const std::string kDefaultService = "1-65535;1/1;1500;0;0;120;0;type=LOG:"
              "a=20:m=10000000:p=1:label=def_service";

  /// The default NORM multicast address range.
  const std::string kDefaultNormAddressRange = "224.0.0.0->225.255.255.255";

  /// Identifier for PIM Register packet type;
  const uint8_t kPimRegisterPktType = 1;

  /// Length of PIM header, in bytes.
  const uint8_t kPimHdrLen = 8;
}

//============================================================================
double UdpProxy::ReleaseRecord::ReleaseFecState(FecState& fec_state)
{
  iron::Time now = iron::Time::Now();

  // Reset the loss rate if we haven't seen a packet in a while.
  // It's either the first packet of the flow, or the first packet
  // after triage ended.
  if (now > (last_release_time_ + iron::Time(kMaxInterarrivalTime)))
  {
    LogD(cn, __func__, "Resetting release stats\n");
    highest_num_packets_ = fec_state.min_pkt_sn();
    avg_byte_loss_rate_ = 0;
  }

  // fill in for missing FecStates.
  for (uint32_t i = highest_num_packets_ + 1; i < fec_state.min_pkt_sn(); i++)
  {
    circ_release_hist_[i % kDefaultHistorySizePkts] = 1;
  }

  // This calculation only includes bytes received or lost since the last
  // call.
  uint64_t  inc_bytes_srced = fec_state.bytes_sourced() - highest_num_bytes_;
  uint64_t  inc_bytes_lost  = inc_bytes_srced - fec_state.bytes_released();
  double    inc_loss_rate = 0.0;
  if (inc_bytes_srced != 0)
  {
    inc_loss_rate = (static_cast<double>(inc_bytes_lost)/inc_bytes_srced);
  }

  avg_byte_loss_rate_      = avg_byte_loss_rate_*(1 - alpha_) +
    (inc_loss_rate*alpha_);

  LogD(cn, __func__, "inc_bytes_srced: %" PRIu64 ", inc_bytes_lost: %" PRIu64
       ", inc_loss_rate: %f, avg_byte_loss_rate: %f\n", inc_bytes_srced,
       inc_bytes_lost, inc_loss_rate, avg_byte_loss_rate_);

  highest_num_packets_ = fec_state.max_pkt_sn();
  highest_num_bytes_   = fec_state.bytes_sourced();
  num_released_bytes_ += fec_state.bytes_released();
  last_release_time_   = now;

  for (int i = 0; i <= fec_state.max_pkt_id(); i++)
  {
    if (fec_state.pkt_sent(i))
    {
      num_released_packets_++;
      circ_release_hist_[(fec_state.min_pkt_sn() + i)
        % kDefaultHistorySizePkts] = 0;
    }
    else
    {
      circ_release_hist_[(fec_state.min_pkt_sn() + i)
        % kDefaultHistorySizePkts] = 1;
    }
  }

  LogD(cn, __func__,"%s:bitset:%s, CLR: %f\n",
    fec_state.decoding_state()->four_tuple().ToString().c_str(),
    circ_release_hist_.to_string().c_str(), avg_byte_loss_rate_);

  return avg_byte_loss_rate_;
}

//============================================================================
UdpProxy::UdpProxy(iron::PacketPool& packet_pool,
                   iron::VirtualEdgeIf& edge_if,
                   iron::BinMap& bin_map,
                   FecStatePool& fecstate_pool, iron::Timer& timer,
                   iron::SharedMemoryIF& weight_qd_shared_memory,
                   iron::FifoIF* bpf_to_udp_pkt_fifo,
                   iron::FifoIF* udp_to_bpf_pkt_fifo)
    : edge_if_(edge_if),
      running_(false),
      weight_qd_shared_memory_(weight_qd_shared_memory),
      local_queue_depths_(bin_map),
      bin_map_shm_(bin_map),
      timer_(timer),
      gc_interval_sec_(kDefaultGCIntervalSec),
      decoder_timeout_sec_(kDefaultDecoderTimeoutSec),
      config(),
      default_service_(NULL),
      encoding(),
      decoding(),
      flow_defn_cache_(),
      bpf_to_udp_pkt_fifo_(packet_pool, bpf_to_udp_pkt_fifo,
                           PACKET_OWNER_BPF, kMaxPktsPerFifoRecv),
      udp_to_bpf_pkt_fifo_(packet_pool, udp_to_bpf_pkt_fifo,
                           PACKET_OWNER_BPF, 0),
      packet_pool_(packet_pool),
      fecstate_pool_(fecstate_pool),
      default_utility_def_(),
      bin_states_map_(),
      k_val_(),
      max_queue_depth_pkts_(kDefaultMaxQueueDepthPerFlowPkts),
      drop_policy_(::iron::HEAD),
      bpf_min_burst_usec_(iron::kDefaultBpfMinBurstUsec),
      flow_tag_(kStartTag),
      mgen_diag_mode_(kDefaultMGENDiagnosticsMode),
      remote_control_port_(kDefaultRemoteControlPort),
      remote_control_(),
      qd_direct_access_(iron::kDirectAccessQueueDepths),
      qd_update_interval_us_(kDefaultQueueDepthUpdateIntervalUs),
      stats_push_(),
      stats_interval_ms_(kDefaultStatsCollectionIntervalMs),
      log_stats_(true),
      total_utility_(0),
      svc_flows_timer_handle_(),
      next_sched_svc_flows_time_(Time::Now()),
      rrm_transmission_time_(Time::Now()),
      straggler_cleanup_time_(Time::Now()),
      garbage_collection_time_(Time::Now()),
      reorder_max_hold_time_(Time(kDefaultMaxHoldTimeSec)),
      release_records_(),
      next_decode_exp_time_(Time::Infinite()),
      do_ttg_tracking_(::iron::kDefaultTtgTracking),
      garbage_collected_flows_(),
      ls_latency_collection_(iron::kDefaultLinkStateLatency),
      total_pkts_sent_(0),
      total_src_drop_(0),
      shm_latency_cache_(bin_map, ::iron::SHM_TYPE_ATTACH),
      do_latency_checks_(kDefaultDoLatencyChecks),
      debug_stats_(NULL),
      max_queue_(),
      enable_loss_triage_(kDefaultEnableLossTriage)
{
  LogI(cn, __func__," Creating UdpProxy...\n");
}

//============================================================================
UdpProxy::UdpProxy(iron::PacketPool& packet_pool,
                   iron::VirtualEdgeIf& edge_if,
                   iron::BinMap& bin_map,
                   FecStatePool& fecstate_pool, iron::Timer& timer,
                   iron::SharedMemoryIF& weight_qd_shared_memory,
                   iron::FifoIF* bpf_to_udp_pkt_fifo,
                   iron::FifoIF* udp_to_bpf_pkt_fifo,
                   bool qd_direct_access)
    : edge_if_(edge_if),
      weight_qd_shared_memory_(weight_qd_shared_memory),
      local_queue_depths_(bin_map),
      bin_map_shm_(bin_map),
      timer_(timer),
      gc_interval_sec_(kDefaultGCIntervalSec),
      decoder_timeout_sec_(kDefaultDecoderTimeoutSec),
      config(),
      default_service_(NULL),
      encoding(),
      decoding(),
      flow_defn_cache_(),
      bpf_to_udp_pkt_fifo_(packet_pool, bpf_to_udp_pkt_fifo,
                           PACKET_OWNER_BPF, kMaxPktsPerFifoRecv),
      udp_to_bpf_pkt_fifo_(packet_pool, udp_to_bpf_pkt_fifo,
                           PACKET_OWNER_BPF, 0),
      packet_pool_(packet_pool),
      fecstate_pool_(fecstate_pool),
      default_utility_def_(),
      bin_states_map_(),
      k_val_(),
      max_queue_depth_pkts_(kDefaultMaxQueueDepthPerFlowPkts),
      drop_policy_(::iron::HEAD),
      bpf_min_burst_usec_(iron::kDefaultBpfMinBurstUsec),
      flow_tag_(kStartTag),
      mgen_diag_mode_(kDefaultMGENDiagnosticsMode),
      remote_control_port_(kDefaultRemoteControlPort),
      remote_control_(),
      qd_direct_access_(qd_direct_access),
      qd_update_interval_us_(kDefaultQueueDepthUpdateIntervalUs),
      stats_push_(),
      stats_interval_ms_(kDefaultStatsCollectionIntervalMs),
      log_stats_(true),
      total_utility_(0),
      svc_flows_timer_handle_(),
      next_sched_svc_flows_time_(Time::Now()),
      rrm_transmission_time_(Time::Now()),
      straggler_cleanup_time_(Time::Now()),
      garbage_collection_time_(Time::Now()),
      reorder_max_hold_time_(Time(kDefaultMaxHoldTimeSec)),
      release_records_(),
      next_decode_exp_time_(Time::Infinite()),
      do_ttg_tracking_(::iron::kDefaultTtgTracking),
      garbage_collected_flows_(),
      ls_latency_collection_(iron::kDefaultLinkStateLatency),
      total_pkts_sent_(0),
      total_src_drop_(0),
      shm_latency_cache_(bin_map, ::iron::SHM_TYPE_ATTACH),
      do_latency_checks_(kDefaultDoLatencyChecks),
      debug_stats_(NULL),
      max_queue_(),
      enable_loss_triage_(kDefaultEnableLossTriage),
      norm_low_addr_(),
      norm_high_addr_()
{
  LogI(cn, __func__, "Creating UdpProxy...\n");
}

//============================================================================
UdpProxy::~UdpProxy()
{
  LogI(cn, __func__, "Destroying UdpProxy...\n");

  // Cancel all timers.
  timer_.CancelAllTimers();

#ifdef DEBUG_STATS
  if (debug_stats_)
  {
    delete debug_stats_;
  }
#endif // DEBUG_STATS

  // Clean up the timer callback object pools.
  CallbackNoArg<UdpProxy>::EmptyPool();

  // Delete the collection of Service context information.
  map<int, FECContext*>::iterator  c_iter;
  for (c_iter = config.begin(); c_iter != config.end(); ++c_iter)
  {
    delete c_iter->second;
  }
  config.clear();

  if(default_service_)
  {
     delete default_service_;
  }

  // Now clean up the EncodingState and DecodingState maps.
  iron::MashTable<FourTuple, EncodingState*>::WalkState es_ws;
  EncodingState*                                        es    = NULL;

  while (encoding.GetNextItem(es_ws, es))
  {
    if (es)
    {
      delete es;
    }
  }
  encoding.Clear();

  map<BinIndex, set<EncodingState*> >::iterator  bin_iter;
  set<EncodingState*>::iterator                  set_iter;
  for (bin_iter = bin_states_map_.begin();
       bin_iter != bin_states_map_.end();
       ++bin_iter)
  {
    // The memory pointed to by the pointers in the set = bin_iter->second has
    // all just been freed.  Just get rid of the set itself.
    bin_iter->second.clear();
  }
  bin_states_map_.clear();

  iron::MashTable<FourTuple, DecodingState*>::WalkState ds_ws;
  DecodingState*                                        ds    = NULL;

  while (decoding.GetNextItem(ds_ws, ds))
  {
    if (ds)
    {
      delete ds;
    }
  }
  decoding.Clear();

  // Clean the flow definition cache.
  HashTable<FourTuple, FECContext*>::WalkState  fc_ws;
  FECContext* context = NULL;
  FourTuple tuple;

  while (flow_defn_cache_.EraseNextPair(fc_ws, tuple, context))
  {
    if (context != NULL)
    {
      delete context;
    }
  }
  flow_defn_cache_.Clear();


  // Clean the release records.
  BinIndex  dst_bin_idx = kInvalidBinIndex;
  for (bool dst_bin_idx_valid = bin_map_shm_.GetFirstBinIndex(dst_bin_idx);
       dst_bin_idx_valid;
       dst_bin_idx_valid = bin_map_shm_.GetNextBinIndex(dst_bin_idx))
  {
    iron::MashTable<FourTuple, ReleaseRecord*>::WalkState  ws;
    ReleaseRecord*  record = NULL;
    while (release_records_[dst_bin_idx].GetNextItem(ws, record))
    {
      delete record;
    }
  }

  // Detached the shared memory.
  weight_qd_shared_memory_.Detach();
  LogD(cn, __func__, "Detached shared memory segments.\n");

  LogA(cn, __func__,
       "pktcount: Total packets sent: %" PRIu32 ".\n", total_pkts_sent_);
  LogA(cn, __func__,
       "pktcount: Total packets dropped: %" PRIu32 ".\n", total_src_drop_);

  // Close the various sockets.
  edge_if_.Close();

  // Clean up the garbage collected flow list.
  garbage_collected_flows_.Clear();

  LogI(cn, __func__,"UdpProxy successfully terminated.\n");
}

//============================================================================
bool UdpProxy::Configure(ConfigInfo& ci, const char* prefix)
{
  // Initialize the hash tables.
  if ((!encoding.Initialize(kEncodingHashTableBuckets)) ||
      (!decoding.Initialize(kDecodingHashTableBuckets)) ||
      (!flow_defn_cache_.Initialize(kFlowDefnHashTableBuckets)))
  {
    LogF(cn, __func__, "Unable to initialize hash tables.\n");
    return false;
  }

  if (!bin_map_shm_.initialized())
  {
    LogF(cn, __func__, "BinMap not yet initialized!!\n");
  }
  bin_map_shm_.Print();

  if (!max_queue_.Initialize(bin_map_shm_))
  {
    LogF(cn, __func__, "Unable to initialize max queue array.\n");
    return false;
  }
  max_queue_.Clear(0);

  if (!release_records_.Initialize(bin_map_shm_))
  {
    LogF(cn, __func__, "Unable to initialize release records array.\n");
    return false;
  }
  BinIndex  dst_bin_idx = kInvalidBinIndex;
  for (bool dst_bin_idx_valid = bin_map_shm_.GetFirstBinIndex(dst_bin_idx);
       dst_bin_idx_valid;
       dst_bin_idx_valid = bin_map_shm_.GetNextBinIndex(dst_bin_idx))
  {
    release_records_[dst_bin_idx].Initialize(kRecordsHashTableBuckets);
  }

  // Initialize the state shared by the NORM flow controllers.
  if (!NormFlowController::Initialize(ci))
  {
    LogF(cn, __func__, "Error initializing NORM flow controller.\n");
    return false;
  }

#ifdef DEBUG_STATS
  debug_stats_ = new (std::nothrow) iron::DebuggingStats();
  if (!debug_stats_)
  {
    LogF(cn, __func__,
         "Error: Count not allocate debugging stats object.\n");
    return false;
  }
#endif // DEBUG_STATS

  // Set up the TCP port used for controlling the UDP proxy
  remote_control_port_ = ci.GetInt("Udp.RemoteControl.Port",
                                   kDefaultRemoteControlPort);

  // Set up the old state collection cleanup interval (in seconds)
  gc_interval_sec_ = ci.GetInt("GCIntervalSec", kDefaultGCIntervalSec);


  // Set up the decoder timeout limit
  decoder_timeout_sec_ = ci.GetInt("DecoderTimeoutSec",
                                   kDefaultDecoderTimeoutSec);

  // Set up the k value (queue normalizer) for all utility functions
  double double_k = ci.GetDouble("KVal", ::iron::kDefaultK);
  if (double_k > std::numeric_limits<uint64_t>::max())
  {
    LogE(cn, __func__, "k val is too large.\n");
    k_val_.set_k_current(static_cast<uint64_t>(::iron::kDefaultK));
  }
  else
  {
    k_val_.set_k_current(static_cast<uint64_t>(double_k));
  }

  // Set up the maximum queue size for the encoded packets queues
  max_queue_depth_pkts_ = ci.GetInt("MaxQueueDepthPerFlowPkts",
                               kDefaultMaxQueueDepthPerFlowPkts);

  // Set up the minimum burst window to admit packets
  bpf_min_burst_usec_ = ci.GetUint("BpfMinBurstUsec",
    iron::kDefaultBpfMinBurstUsec);

  // Set up the maximum hold time when reordering packets.
  reorder_max_hold_time_ =
    Time(ci.GetDouble("MaxHoldTimeSec", kDefaultMaxHoldTimeSec));

  // Set up the drop policy for the encoded packets queues
  std::string drop_policy_str = ci.Get("DropPolicy","HEAD");

  if (drop_policy_str == "HEAD")
  {
    drop_policy_ = iron::HEAD;
  }
  else if (drop_policy_str == "TAIL")
  {
    drop_policy_ = iron::TAIL;
  }
  else if (drop_policy_str == "NO_DROP")
  {
    drop_policy_ = iron::NO_DROP;
  }
  else
  {
    LogF(cn, __func__, "Invalid BinQueueMgr.DropPolicy %s.\n",
         drop_policy_str.c_str());
    return false;
  }

  // Get the default utility function definition
  default_utility_def_  = ci.Get("DefaultUtilityDef","");

  // Extract whether to re-write timestamp and sequence number in MGEN packets.
  mgen_diag_mode_ = ci.Get(
    "MGENDiagnosticsMode", kDefaultMGENDiagnosticsMode, false);

  // Extract the update queue depth interval.
  qd_update_interval_us_  = ci.GetUint("QueueDepthUpdateIntervalUs",
                                       kDefaultQueueDepthUpdateIntervalUs);

  // Extract the statistics collection interval.
  stats_interval_ms_ = ci.GetUint("StatsCollectionIntervalMs",
                                  kDefaultStatsCollectionIntervalMs);

  // Extract the directive that controls whether the statistics will be
  // logged.
  bool  UNUSED(log_stats) = ci.GetBool("LogStatistics", kDefaultLogStats);

  do_ttg_tracking_    = ci.GetBool("TtgTracking", ::iron::kDefaultTtgTracking);

  ls_latency_collection_  = ci.GetBool("LinkStateLatency",
    iron::kDefaultLinkStateLatency);

  do_latency_checks_ = ci.GetBool("LatencyChecks", kDefaultDoLatencyChecks);

  enable_loss_triage_ = ci.GetBool("EnableLossTriage", kDefaultEnableLossTriage);

  string  norm_addr_range_str = ci.Get("NormAddressRange",
                                       kDefaultNormAddressRange);
  ParseNormAddrRangeString(norm_addr_range_str);

  // Log the configuration information.
  LogC(cn, __func__, "UDP Proxy configuration:\n");
  LogC(cn, __func__, "RemoteControlPort         : %d\n",
       remote_control_port_);
  LogC(cn, __func__, "PPInterval                : %d\n", kPPIntervalMsec);
  LogC(cn, __func__, "GCIntervalSec             : %d\n", gc_interval_sec_);
  LogC(cn, __func__, "DecoderTimeoutSec         : %d\n",
       decoder_timeout_sec_);
  LogC(cn, __func__, "K                         : %.2e\n",
       static_cast<double>(k_val_.GetValue()));
  LogC(cn, __func__, "MaxQueueDepthPerFlowPkts  : %d\n",
       max_queue_depth_pkts_);
  LogC(cn, __func__, "DropPolicy                : %s\n",
       drop_policy_str.c_str());
  LogC(cn, __func__, "DefaultUtilityFn          : %s\n",
       default_utility_def_.c_str());
  LogC(cn, __func__, "DirectAccess              : %s\n",
       qd_direct_access_ ? "On" : "Off");
  LogC(cn, __func__, "QueueDepthUpdateIntervalUs: %" PRIu32 "\n",
       qd_update_interval_us_);
  LogC(cn, __func__, "StatsCollectionIntervalMs : %" PRIu32 "\n",
       stats_interval_ms_);
  LogC(cn, __func__, "LogStatistics             : %s\n",
       log_stats ? "true" : "false");
  LogC(cn, __func__, "Time-to-go tracking       : %s\n",
       (do_ttg_tracking_ ? "On" : "Off"));
  LogC(cn, __func__, "LS Latency collection     : %s\n",
       ls_latency_collection_ ? "On" : "Off");
  LogC(cn, __func__, "Latency checking          : %s\n",
       (do_latency_checks_ ? "On" : "Off"));
  LogC(cn, __func__, "Loss Triage               : %s\n",
       (enable_loss_triage_ ? "On" : "Off"));
  LogC(cn, __func__, "NORM address range        : %s\n",
       norm_addr_range_str.c_str());

  // Retrieve zero or more service configurations
  string  pvar;
  char    parm[300];
  char    servName[100];
  for (int i = 0; i < 16; i++)
  {
    snprintf(&servName[0], sizeof(servName) - 1, "Service%d", i);

    if ((pvar = ci.Get(servName, "")) != "")
    {
      strncpy(&parm[0], pvar.c_str(), sizeof(parm) - 1);

      FECContext*  context = NULL;
      if ((context = ParseService(&parm[0], FECModAction)) != NULL)
      {
        // Enable this service
        if (ModService(context) == false)
        {
          LogE(cn, __func__, "Addition of service %s failed\n",
               pvar.c_str());
          return false;
        }

        delete context;

        LogC(cn, __func__, "Service: %s\n", pvar.c_str());
      }
    }
  }

  // Set up the default service definition
  if ((pvar = ci.Get("defaultService", kDefaultService)) != "")
  {
    strncpy(&parm[0], pvar.c_str(), sizeof(parm)-1);
    if ((default_service_ = ParseService(&parm[0],FECModAction)) == NULL)
    {
      LogE(cn, __func__, "Failed to parse default service: %s\n", pvar.c_str());
    }
    else
    {
      LogC(cn, __func__, "Default Service set to: %s\n", pvar.c_str());
    }
  }
  else
  {
    LogW(cn, __func__, "Default service definition not configured.\n");
  }

  LogC(cn, __func__, "UDP Proxy configuration complete.\n");

  return true;
}

//============================================================================
bool UdpProxy::InitSockets()
{
  // Create the edge interface and insert the iptables rules and attach the
  // Berkeley Packet Filter that will divert packets into the UDP Proxy.
  if (!edge_if_.Open())
  {
    LogW(cn, __func__, "Error opening edge interface.\n");
    return false;
  }

  // Initialize the inter-process communications between the UDP Proxy and the
  // Backpressure Forwarder.
  if (!bpf_to_udp_pkt_fifo_.OpenReceiver())
  {
    LogW(cn, __func__, "Unable to open backpressure forwarder packet "
         "FIFO.\n");
    return false;
  }

  if (!udp_to_bpf_pkt_fifo_.OpenSender())
  {
    LogD(cn, __func__, "Backpressure forwarder packet FIFO not ready yet.\n");
  }

  // Initialize the remote control communications server.
  if (!remote_control_.Initialize(remote_control_port_))
  {
    LogF(cn, __func__, "Unable to initialize remote control communications "
         "module.\n");
    return false;
  }

  return true;
}

//============================================================================
bool UdpProxy::AttachSharedMemory(const ConfigInfo& ci)
{
  key_t   w_key   = ci.GetUint("Udp.Weight.SemKey",
                               iron::kDefaultWeightSemKey);
  string  w_name  = ci.Get("Udp.Weight.ShmName", kDefaultWeightShmName);

  LogI(cn, __func__, "Attaching weights queue depth shared memory...\n");
  bool  weights_attached  =
    weight_qd_shared_memory_.Attach(w_key, w_name.c_str(),
                                    local_queue_depths_.GetShmSize());

  uint32_t  wait_count  = 0;

  while (!weights_attached)
  {
    sleep(1);

    ++wait_count;
    if (wait_count % 10 == 0)
    {
      if (wait_count % 120 == 0)
      {
        LogW(cn, __func__, "... Waiting to attach to queue depths shared "
             "memory.\n");
      }
      else
      {
        LogD(cn, __func__, "... Waiting to attach.\n");
      }
    }

    weights_attached  =
      weight_qd_shared_memory_.Attach(w_key, w_name.c_str(),
                                      local_queue_depths_.GetShmSize());
  }

  LogI(cn, __func__, "Queue Weights shared memory attached "
       "(after %" PRIu32 " seconds)!\n", wait_count);

  if (qd_direct_access_)
  {
    if (!local_queue_depths_.InitializeShmDirectAccess(
          &weight_qd_shared_memory_))
    {
      LogE(cn, __func__, "Unable to attach to shared memory for weight "
           "queue depth information.\n");
      return false;
    }
  }

  // Initialize the shared memory latency cache.
  if (!shm_latency_cache_.Initialize())
  {
    LogW(cn, __func__, "Unable to initialize LatencyCacheShm.\n");
    return false;
  }

  return true;
}

//============================================================================
void UdpProxy::Start()
{
  LogI(cn, __func__, "Starting UDP Proxy main service loop...\n");

  init_vdmfec();

  running_ = true;

  Time  now = Time::Now();

  // Schedule the initial statistics collection event.
  stats_push_.next_push_time = now + Time::FromMsec(stats_interval_ms_);

  // Schedule the garbage collection event.
  garbage_collection_time_ = now + Time::FromSec(gc_interval_sec_);

  // Schedule the straggler cleanup event.
  straggler_cleanup_time_ = now + Time::FromMsec(kPPIntervalMsec);

  // Schedule the RRM transmission event.
  rrm_transmission_time_ = now + Time::FromMsec(kPeriodicRrmIntervalMsec);

  // Start the service flows timer.
  Time                          duration =
    Time::FromUsec(kDefaultSvcFlowsIntervalUs);
  CallbackNoArg<UdpProxy>  callback(this, &UdpProxy::SvcFlowsTimeout);

  if (!timer_.StartTimer(duration, &callback,
                         svc_flows_timer_handle_))
  {
    LogE(cn, __func__, "Error starting service flows timer.\n");
  }

  LogD(cn, __func__, "Started service flows timer with duration %s for handle "
       "%" PRId64 ".\n", duration.ToString().c_str(),
       svc_flows_timer_handle_.id());

  while (running_)
  {
    fd_set  read_fds;
    int     max_fd = 0;

    FD_ZERO(&read_fds);
    edge_if_.AddFileDescriptors(max_fd, read_fds);
    bpf_to_udp_pkt_fifo_.AddFileDescriptors(max_fd, read_fds);

    // Add the file descriptors for the remote control communications.
    remote_control_.AddFileDescriptors(max_fd, read_fds);

    // Get the next expiration time from the timer, which will be the backstop
    // time for the select() call.
    Time  next_exp_time = timer_.GetNextExpirationTime();
    struct timeval  next_exp_time_tv = next_exp_time.ToTval();

    LogD(cn, __func__, "TIMER: select timeout in %d microseconds.\n",
         next_exp_time_tv.tv_usec + (1000000 * next_exp_time_tv.tv_sec));

    int  num_fds = Select(max_fd + 1, &read_fds, &next_exp_time_tv);

    if (num_fds < 0)
    {
      LogE(cn, __func__, "select() error %s.\n", strerror(errno));
    }
    else if (num_fds > 0)
    {
      BinIndex  idx = kInvalidBinIndex;
      for (bool idx_valid = bin_map_shm_.GetFirstBinIndex(idx);
           idx_valid;
           idx_valid = bin_map_shm_.GetNextBinIndex(idx))
      {
        max_queue_[idx] = std::max(max_queue_[idx],
                                   local_queue_depths_.GetBinDepthByIdx(idx));
      }

      if (edge_if_.InSet(&read_fds))
      {
        bool done = false;
        do
        {
          // Read a packet from the LAN interface and process it.
          Packet* pkt = packet_pool_.Get(iron::PACKET_NOW_TIMESTAMP);

          if (pkt == NULL)
          {
            LogF(cn, __func__, "Unable to allocate new Packet.\n");
            continue;
          }

          if (edge_if_.Recv(pkt) <= 0)
          {
            done = true;
            packet_pool_.Recycle(pkt);
          }
          else
          {
            LogD(cn, __func__, "RECV: UDP proxy from LAN IF, size: %d bytes.\n",
                 pkt->GetLengthInBytes());

            RunEncoder(pkt);
          }
        }
        while (!done);
      }

      if (bpf_to_udp_pkt_fifo_.InSet(&read_fds))
      {
        ReceivePktsFromBpf();
      }

      if (remote_control_.ServiceFileDescriptors(read_fds))
      {
        // Process a received remote control message.
        ProcessRemoteControlMessage();
      }
    }

    // Process the timer callbacks.
    LogD(cn, __func__, "Processing timer callbacks...\n");
    timer_.DoCallbacks();
  }

  LogI(cn, __func__, "Stopping UDP Proxy main service loop...\n");
}

//============================================================================
void UdpProxy::Stop()
{
  running_ = false;
}

//============================================================================
bool UdpProxy::SendToBpf(Packet* pkt)
{
  if (!pkt)
  {
    return false;
  }

  if (!udp_to_bpf_pkt_fifo_.IsOpen())
  {
    if (!udp_to_bpf_pkt_fifo_.OpenSender())
    {
      LogW(cn, __func__, "Backpressure forwarder packet FIFO not ready yet, "
           "dropping packet.\n");
      return false;
    }
  }

  return udp_to_bpf_pkt_fifo_.Send(pkt);
}

//============================================================================
ssize_t UdpProxy::SendToLan(Packet* pkt) const
{
  ssize_t bytes_sent = edge_if_.Send(pkt);

  LogD(cn, __func__, "SEND: Proxy to LAN IF, size %" PRId32 "bytes.\n",
       bytes_sent);

  if (bytes_sent == -1)
  {
    return 0;
  }

  // The transmission was successful, so we can recycle the packet.
  packet_pool_.Recycle(pkt);

  return bytes_sent;
}

//============================================================================
void UdpProxy::SvcFlowsTimeout()
{
  LogD(cn, __func__, "Service flows timeout fired for handle %" PRIu64 ".\n",
       svc_flows_timer_handle_.id());

  Time  now = Time::Now();

  // If we aren't configured to do direct access to the queue depths, update
  // them now.
  if (!qd_direct_access_)
  {
    local_queue_depths_.CopyFromShm(weight_qd_shared_memory_);
  }

  LogD(cn, __func__, "Servicing flows, Queue depths are: %s.\n",
       local_queue_depths_.ToString().c_str());

  // Service all of the encoding states.
  iron::MashTable<FourTuple, EncodingState*>::WalkState es_walk_state;
  EncodingState*                                        es  = NULL;
  bool push_stats_now                                 = false;
  while (encoding.GetNextItem(es_walk_state, es))
  {
    es->SvcEvents(now);
    push_stats_now = push_stats_now || es->PushStats();
  }

  if (push_stats_now)
  {
    LogD(cn, __func__, "Toggle event detected, pushing non-periodic stats.\n");
    PushStats(false);
  }

  // Service all of the decoding states.
  iron::MashTable<FourTuple, DecodingState*>::WalkState ds_walk_state;
  DecodingState*                                        ds  = NULL;
  while (decoding.GetNextItem(ds_walk_state, ds))
  {
    ds->SvcEvents(now);
  }

  // Service the UDP Proxy events.
  if (stats_push_.next_push_time <= now)
  {
    PushStats(true);
  }

  if (straggler_cleanup_time_ <= now)
  {
    StragglerCleanupTimeout(now);
  }

  if (garbage_collection_time_ <= now)
  {
    GarbageCollectionTimeout(now);
  }

  if (rrm_transmission_time_ <= now)
  {
    SendRRMs(now);
  }

  // Schedule the next service flows timer.
  Time  end_time = Time::Now();
  Time  duration = Time::FromUsec(kDefaultSvcFlowsIntervalUs) -
    (end_time - now);
  if (duration.GetTimeInUsec() < 0)
  {
    duration = 0.0;
  }
  CallbackNoArg<UdpProxy>  callback(this, &UdpProxy::SvcFlowsTimeout);

  if (!timer_.StartTimer(duration, &callback, svc_flows_timer_handle_))
  {
    LogE(cn, __func__, "Error starting service flows timer.\n");
  }

  next_sched_svc_flows_time_ = now + duration;

  LogD(cn, __func__, "Started service flows timer with duration %s for "
       "handle %" PRId64 ".\n", duration.ToString().c_str(),
       svc_flows_timer_handle_.id());

  LogD(cn, __func__, "Finished servicing flows.\n");
}

//============================================================================
bool UdpProxy::CreateReleaseRecord(BinIndex bin_idx, FourTuple& four_tuple,
                                   uint64_t total_bytes_sent,
                                   uint32_t seq_num, uint8_t priority)
{
  ReleaseRecord*  release_record  =
    new (std::nothrow) ReleaseRecord(four_tuple, total_bytes_sent, seq_num,
                                     priority);

  if (!release_record)
  {
    LogF(cn, __func__, "Failed to allocate release record.\n");
    return false;
  }

  if (release_records_[bin_idx].Insert(four_tuple, release_record))
  {
    LogD(cn, __func__, "fid: %" PRIu32 ", successfully inserted record "
         "for flow %s.\n", flow_tag_, four_tuple.ToString().c_str());
  }
  else
  {
    LogW(cn, __func__, "fid: %" PRIu32 ", Failed to insert record for "
         "flow %s.\n", flow_tag_, four_tuple.ToString().c_str());
    delete release_record;
    return false;
  }

  return true;
}

//============================================================================
bool UdpProxy::GetReleaseRecord(BinIndex bin_idx, const FourTuple& four_tuple,
                                ReleaseRecord*& release_record)
{
  return release_records_[bin_idx].Find(four_tuple, release_record);
}

//============================================================================
void UdpProxy::SendRRMs(Time& now)
{
  LogD(cn, __func__, "sending RRMs\n");
  // Send one RRM per flow originator. These must be destination bins.
  BinIndex dst_bin_idx = 0;
  for (bool valid = bin_map_shm_.GetFirstUcastBinIndex(dst_bin_idx);
       valid;
       valid = bin_map_shm_.GetNextUcastBinIndex(dst_bin_idx))
  {
    iron::MashTable<FourTuple, ReleaseRecord*>::WalkState ws;
    ws.PrepareForWalk();

    ReleaseRecord*  release_record  = NULL;

    while (release_records_[dst_bin_idx].GetNextItem(ws, release_record))
    {
      Packet* rrm = iron::Rrm::CreateNewRrm(packet_pool_,
        release_record->four_tuple_);

      if (!rrm)
      {
        LogF(cn, __func__, "Failed to allocate RRM packet.\n");
        return;
      }

      uint64_t  highest_num_bytes  = 0;
      uint64_t  num_released_bytes = 0;
      release_record->GetBytes(highest_num_bytes, num_released_bytes);

      uint32_t  highest_num_pkts   = 0;
      uint32_t  num_released_pkts  = 0;
      release_record->GetPackets(highest_num_pkts, num_released_pkts);

      // Reset the loss rate if we haven't seen a packet in a while.
      // It's either the first packet of the flow, or the first packet
      // after triage ended.
      if (now > (release_record->last_release_time_ + iron::Time(kMaxInterarrivalTime)))
      {
        LogD(cn, __func__, "Resetting release stats\n");
        release_record->avg_byte_loss_rate_ = 0;
      }

      uint8_t   cur_loss_rate = 100 * release_record->avg_byte_loss_rate_;
      LogA(cn, __func__,
           "Current loss rate for flow %s: %" PRIu8 "%.\n",
           release_record->four_tuple_.ToString().c_str(), cur_loss_rate);

      iron::Rrm::FillReport(rrm, highest_num_bytes, highest_num_pkts,
        num_released_bytes, num_released_pkts, cur_loss_rate);

      bool  sent_pkt     = false;
      bool  fifo_is_open = udp_to_bpf_pkt_fifo_.IsOpen();

      if (!fifo_is_open)
      {
        fifo_is_open = udp_to_bpf_pkt_fifo_.OpenSender();

        if (!fifo_is_open)
        {
          LogW(cn, __func__, "Backpressure forwarder packet FIFO not ready "
               "yet, dropping RRM packet.\n");
        }
      }

      if (fifo_is_open)
      {
        sent_pkt = udp_to_bpf_pkt_fifo_.Send(rrm);
      }

      if (!sent_pkt)
      {
        LogE(cn, __func__, "Error sending RRM packet.\n");
        packet_pool_.Recycle(rrm);
      }
      else
      {
        // If the Send() succeeds, the Packet in shared memory is being handed
        // over to the backpressure forwarder, so we cannot Recycle() it.
        LogD(cn, __func__, "Initiated RRM packet %s for bin %s"
             " flow %s.\n",
             rrm->GetPacketMetadataString().c_str(),
             bin_map_shm_.GetIdToLog(dst_bin_idx).c_str(),
             release_record->four_tuple_.ToString().c_str());
        iron::Rrm::PrintRrm(rrm);
      }
    }
  }

  // Schedule the next RRM transmission event time.
  rrm_transmission_time_ = now + Time::FromMsec(kPeriodicRrmIntervalMsec);
}

//============================================================================
int UdpProxy::Select(int nfds, fd_set* readfs, struct timeval* timeout)
{
  return select(nfds, readfs, NULL, NULL, timeout);
}

//============================================================================
bool UdpProxy::GetContext(const FourTuple& four_tuple, FECContext& context)
{
  bool  found = false;

  // First check the flow definition cache.
  FECContext* flow_defn_context = NULL;
  if (flow_defn_cache_.Find(four_tuple, flow_defn_context))
  {
    context = *flow_defn_context;
    return true;
  }

  unsigned short dport_hbo = ntohs(four_tuple.dst_port_nbo());
  unsigned short sport_hbo = ntohs(four_tuple.src_port_nbo());

  // Retrieve the configuration info for this service. We can't tell whether
  // the source or destination port is the service port. So we try the dport
  // first, then the sport.
  map<int, FECContext*>::reverse_iterator  iter;
  for (iter = config.rbegin(); iter != config.rend(); ++iter)
  {
    if (iter->first <= dport_hbo)
    {
      // Found the (lower) bounding context, using the destination port. Now
      // see if its the correct one.
      if (iter->second->hi_port() >= dport_hbo)
      {
        context = *(iter->second);
        found = true;
        break;
      }
    }
  }

  // If the check using the destination port failed, check using the source
  // port.
  if (!found)
  {
    for (iter = config.rbegin(); iter != config.rend(); ++iter)
    {
      if (iter->first <= sport_hbo)
      {
        if (iter->second->hi_port() >= sport_hbo)
        {
          context = *(iter->second);
          found = true;
          break;
        }
      }
    }
  }

  if (!found)
  {
    if (default_service_)
    {
      context = *default_service_;
      found = true;
    }
  }

  return found;
}

//============================================================================
FECContext* UdpProxy::ParseService(char* command, FECActionType action,
                                   bool is_flow_defn)
{
  // Service definitions for the UDP proxy has the following format:
  //   * loPort-hiPort;baseRate/totrate;maxChunkSz;maxHoldTimeMsecs;
  //       orderFlag;timeout;timeToGo;utilityFunction[;dscp=VALUE][;rord=VALUE]
  //  1) port numbers are between 1 and 65535.
  //  2) baseRate/totRate is the default FEC encoding rate.
  //  3) maximum payload chunk size is in bytes (1 to 65535).
  //  4) maximum hold time (msecs) before we force FEC generation (>= 0).
  //  5) orderFlag: ~0 -> strict ordering, 0 -> release immediately.
  //  6) timeout (sec) how long gateway keeps old state (0 is forever).
  //  7) Time-to-go time, in microseconds. A value of 0 indicates that.
  //     time-to-go time has the maximum value permitted (maximum of signed
  //     32-bit quantity).
  //  8) Utility function definition. This is a colon-separated string.
  //  9) dscp value to overwrite in each packet under this service. Optional.
  //
  //  Flow definitions are preceded with a semicolon-separated four-tuple
  //  string, but otherwise the same as the service definition.

  int      baseRate            = 1;
  int      totalRate           = 0;
  int      maxChunkSz          = 65535;
  time_t   maxHoldTimeMsecs    = 100000;
  time_t   maxReorderTimeMsecs = 0;
  int      inOrder             = 0;
  time_t   timeOut             = 120;
  int8_t   dscp                = -1;
  string   util_fn             = "";
  Time     time_to_go(0);
  bool     time_to_go_valid    = false;
  int      loPort              = 0;
  int      hiPort              = 0;
  DstVec   dst_vec             = 0;

  struct timeval  maxHoldTime;
  FECContext*     context;

  List<string>  tokens;
  StringUtils::Tokenize(command, ";", tokens);

  string  token;
  bool    isMulticast = false;

  if (is_flow_defn)
  {
    LogD(cn, __func__, "Flow definition : %s\n", command);
    if (tokens.size() < 11)
    {
      LogW(cn, __func__, "Insufficient number of arguments in "
           " flow specification.\n");
      return (FECContext*)NULL;
    }
    // Remove the four tuple. First the src and dst ports, then src addr
    tokens.Pop(token);
    tokens.Pop(token);
    tokens.Pop(token);

    // Grab the fourth token (dst addr) in case this is a multicast flow
    string  dstAddr_str;
    tokens.Pop(dstAddr_str);

    /// Check to see if the destinaton address is a multicast address
    iron::Ipv4Address dstAddr = dstAddr_str;
    isMulticast               = dstAddr.IsMulticast();
  }
  else
  {
    LogD(cn, __func__, "Service definition : %s\n", command);
    if (tokens.size() < 8)
    {
      LogW(cn, __func__, "Insufficient number of arguments in "
           " service specification.\n");
      return (FECContext*)NULL;
    }

    // Parse the port range settings
    tokens.Pop(token);
    List<string>  range;
    StringUtils::Tokenize(token, "-", range);
    if (range.size() != 2)
    {
      LogW(cn, __func__, "'-' separator missing from port range "
           "specification.\n");
      return (FECContext*)NULL;
    }

    string  range_token;
    range.Peek(range_token);
    loPort = StringUtils::GetInt(range_token);
    range.PeekBack(range_token);
    hiPort = StringUtils::GetInt(range_token);

    if ((loPort < 0) ||
        (loPort > 65535) ||
        (hiPort < 0) ||
        (hiPort > 65535) ||
        (loPort > hiPort))
    {
      // Error out. Port settings are screwy
      LogW(cn, __func__, "Improper port range setting.\n");
      return (FECContext*)NULL;
    }
  }

  // If action is "mod", need remaining info
  if (action == FECModAction)
  {
    if (tokens.size() < 6)
    {
      LogW(cn, __func__, "Insufficient number of parameters in "
        " service specification\n");
      return (FECContext*)NULL;
    }

    // Parse the coding rate string
    tokens.Pop(token);
    List<string>  rates;
    StringUtils::Tokenize(token, "/", rates);
    LogD(cn, __func__, "Rate       : %s\n", token.c_str());
    if (rates.size() != 2)
    {
      // Error out. We must have this setting.
      LogW(cn, __func__, "'/' separator missing from coding rate "
           "specification.\n");
      return (FECContext*)NULL;
    }

    string  rate_str;
    rates.Peek(rate_str);
    baseRate  = StringUtils::GetInt(rate_str);

    rates.PeekBack(rate_str);
    totalRate = StringUtils::GetInt(rate_str);

    if ((baseRate < 1) ||
        (baseRate > MAX_FEC_RATE) ||
        (totalRate < 1) ||
        (baseRate > totalRate) ||
        (totalRate - baseRate > MAX_FEC_RATE))
    {
      // Error out. Rate settings are screwy
      LogW(cn, __func__, "Improper coding rate specification.\n");
      return (FECContext*)NULL;
    }

    // Convert the maximum chunk size specification and make sure its an even
    // number of bytes to keep the FEC calculation happy.
    string  chunk_size_str;
    tokens.Pop(chunk_size_str);
    maxChunkSz = StringUtils::GetInt(chunk_size_str);
    LogD(cn, __func__, "maxChunkSz : %s\n", chunk_size_str.c_str());

    if ((maxChunkSz < 1    ) ||
        (maxChunkSz > 65535))
    {
      // Error out. Maximum chunk size settings are screwy
      LogW(cn, __func__, "Improper maximum chunk size specification.\n");
      return (FECContext*)NULL;
    }

    // Get the maximum hold time.
    string  hold_time_str;
    tokens.Pop(hold_time_str);
    maxHoldTimeMsecs = StringUtils::GetInt(hold_time_str);
    LogD(cn, __func__, "Hold time  : %s\n", hold_time_str.c_str());

    if (maxHoldTimeMsecs < 0)
    {
      // Error out. Maximum hold time must be positive
      LogW(cn, __func__, "Maximum hold time must be non-negative.\n");
      return (FECContext*)NULL;
    }

    // Convert the order flag
    string  in_order_str;
    tokens.Pop(in_order_str);
    inOrder = StringUtils::GetInt(in_order_str);
    LogD(cn, __func__, "inOrder    : %s\n", in_order_str.c_str());

    tokens.Pop(token);
    if (token.size() == 0)
    {
      LogW(cn, __func__, "Timeout parameter missing from service "
           "specification.\n");
      return (FECContext*)NULL;
    }

    // Get the encoding timeout from the definition.
    timeOut = StringUtils::GetInt(token);
    LogD(cn, __func__, "timeOut    : %s\n", token.c_str());

    // Get the time-to-go.
    tokens.Pop(token);
    int32_t  ttg_us = StringUtils::GetInt(token);
    LogD(cn, __func__, "ttg        : %s\n", token.c_str());
    time_to_go = Time::FromUsec(ttg_us);

    if (time_to_go.IsZero())
    {
      time_to_go =
        Time::FromUsec(static_cast<int64_t>(iron::kUnsetTimeToGo));
      time_to_go_valid = false;
    }
    else
    {
      time_to_go_valid = true;
    }

    // Get next token -- utility function string. Utility function string
    // always start with type=xxxxx.
    tokens.Peek(util_fn);
    LogD(cn, __func__, "utility    : %s\n", util_fn.c_str());
    if (util_fn.find("type") == std::string::npos)
    {
      LogW(cn, __func__, "Service definition does not contain utility"
               "function definition, using default.\n");
      if (default_utility_def_.length() !=0)
      {
        util_fn = default_utility_def_;
      }
      else
      {
        LogF(cn,__func__, "Default utility not specified.\n");
      }
    }
    else
    {
      tokens.Pop(token);
    }

    // Parse any optional tokens. Only "dscp=xx" and "rord=yy" are currently
    // supported.
    while (tokens.size() > 0)
    {
      tokens.Peek(token);

      // There is a string, look at it.
      List<string>  opt_toks;
      StringUtils::Tokenize(token, "=", opt_toks);
      if (opt_toks.size() != 2)
      {
        LogW(cn, __func__, "Optional fields must be of the form X=Y\n");
        tokens.Pop(token);
        continue;
      }

      string opt_tok;
      opt_toks.Peek(opt_tok);
      if (opt_tok == "dscp")
      {
        // The string starts with dscp=.  Means specifying DSCP val.
        string dscp_str;
        opt_toks.PeekBack(dscp_str);

        if (dscp_str.empty())
        {
          // The value of DSCP is missing.
          LogF(cn, __func__, "DSCP token detected but no value specified.\n");
          return NULL;
        }
        else
        {
          // There is a value for the DSCP.
          uint32_t dscp_val = StringUtils::GetUint(dscp_str);
          // DSCP value cannot exceed 111 111 - 63)
          if ((dscp_val == INT_MAX) || (dscp_val >= (1 << 6)))
          {
            // The DSCP value is invalid.
            LogF(cn, __func__,
                  "DSCP value %s is invalid or exceeds 63.\n",
                  dscp_str.c_str());
            return NULL;
          }
          else
          {
            // The DSCP value is valid and does not exceed 63.  Use it.
            dscp = static_cast<int8_t>(dscp_val);
            LogD(cn, __func__,
                  "DSCP value set to %d.\n", dscp);
          }
        }
      }
      else if (opt_tok == "rord")
      {
        string rord_str;
        opt_toks.PeekBack(rord_str);
        // rord indeicates how long packets are held for reording in
        // the decoder.
        if (rord_str.size() == 0)
        {
          // The value of Reorder hold time is missing.
          LogF(cn, __func__, "RODR token detected but no value specified.\n");
          return NULL;
        }
        else
        {
          // There is a value for the reorder hold time
          maxReorderTimeMsecs = StringUtils::GetInt(rord_str);
          LogD(cn, __func__, "Reordering : %s\n", rord_str.c_str());
        }
      }
      else if (opt_tok == "dstlist")
      {
	// Make sure this is for a flow definition
	if (!is_flow_defn)
	{
          // Can only specify a destination list for a flow definition
          LogF(cn, __func__, "'dstlist' can only be used with flow defns.\n");
	}

	// Make sure this is for a multicast flow
	if (!isMulticast)
	{
          // Can only specify a destination list for multicast flows
          LogF(cn, __func__, "'dstlist' can only be used with mcast flows.\n");
	}

        string dstlist_str;
        opt_toks.PeekBack(dstlist_str);

        if (dstlist_str.size() == 0)
        {
          // The value of dstlist is missing
          LogF(cn, __func__, "'dstlist' token detected but no value specified.\n");
          return NULL;
        }
        else
        {
          // There is a value for the dstlist

	  // dstlist specifies the GNAT node addresses for a multicast group
	  // and is a comma separated list of GNAT lan side addresses: e.g.
	  //  a.b.c.d,e.f.g.h,...i.j.k.l

	  List<string>  dsts;
	  StringUtils::Tokenize(dstlist_str, ",", dsts);
	  while (dsts.size() > 0)
	  {
	    string  dst;
	    dsts.Pop(dst);
	    Ipv4Address  address(dst);

	    iron::BinIndex  bin_idx =
              bin_map_shm_.GetDstBinIndexFromAddress(address);

	    if (bin_idx == iron::kInvalidBinIndex)
	    {
	      LogF(cn, __func__, "No mapping for destination address %s found in "
		   "BinMap.\n", address.ToString().c_str());
	      return NULL;
	    }

            dst_vec = bin_map_shm_.AddBinToDstVec(dst_vec, bin_idx);
	  }
        }
      }
      else
      {
        // The string starts with something unsupported.  Drop it.
        LogW(cn, __func__, "Unrecognized token %s.\n", token.c_str());
      }
      tokens.Pop(token);
    }

    // else: no string here, use default DSCP, RODR, and dstlist values.
  }

  maxHoldTime.tv_sec  =  maxHoldTimeMsecs / 1000;
  maxHoldTime.tv_usec = (maxHoldTimeMsecs - maxHoldTime.tv_sec * 1000) * 1000;

  Time maxReorderTime(static_cast<double>(maxReorderTimeMsecs) / 1000);

  // If we are here, we successfully found all info needed for a context
  context = new (std::nothrow) FECContext(loPort, hiPort, baseRate, totalRate,
                                          maxChunkSz, maxHoldTime, inOrder,
                                          timeOut, time_to_go,
                                          time_to_go_valid, util_fn, dscp,
                                          maxReorderTime, dst_vec);

  if (context == NULL)
  {
    LogF(cn, __func__, "Error allocating new FECContext.\n");
  }

  return context;
}

//============================================================================
bool UdpProxy::ModService(FECContext* ref_context)
{
  bool rc = false;

  // Insert into the collection of Service context information. See if we
  // already have this entry, in which case its a "mod" operation
  map<int, FECContext*>::iterator  iter;
  if ((iter = config.find(ref_context->lo_port())) !=
      config.end())
  {
    FECContext* cur_context = iter->second;

    // Make sure we have a match.
    if (cur_context->hi_port() == ref_context->hi_port())
    {
      // We have a match. Just overwrite the values.
      *cur_context = *ref_context;

      rc = true;
    }
    else
    {
      LogW(cn, __func__, "Inconsistent ports: existing port range "
           "(%u:%u) mismatch with requested port range (%u:%u).\n",
           cur_context->lo_port(), cur_context->hi_port(),
           ref_context->lo_port(), ref_context->hi_port());
      rc = false;
    }
  }
  else
  {
    // Looks like we don't already have this entry, in which case its an "add"
    // operation. First we copy the context and insert the copy for
    // consistent behavior.
    FECContext*  context =
      new (std::nothrow) FECContext(ref_context->lo_port(),
                                    ref_context->hi_port(),
                                    ref_context->base_rate(),
                                    ref_context->total_rate(),
                                    ref_context->max_chunk_sz(),
                                    ref_context->max_hold_time(),
                                    ref_context->in_order(),
                                    ref_context->timeout(),
                                    ref_context->time_to_go(),
                                    ref_context->time_to_go_valid(),
                                    ref_context->util_fn_defn(),
                                    ref_context->dscp(),
                                    ref_context->reorder_time(),
                                    ref_context->dst_vec());

    if (context == NULL)
    {
      LogF(cn, __func__, "Error allocating new FECContext.\n");
      rc = false;
    }

    config[context->lo_port()] = context;
    rc = true;
  }

  return rc;
}

//============================================================================
bool UdpProxy::DelService(FECContext* ref_context)
{
  bool rc = false;

  // Retrieve from the collection of Service context information.
  map<int, FECContext*>::iterator  iter;
  if ((iter = config.find(ref_context->lo_port())) !=
      config.end())
  {
    FECContext* cur_context = iter->second;

    // Make sure we have a match.
    if (cur_context->hi_port() == ref_context->hi_port())
    {
      // We have a match. Delete the context that was saved and remove from
      // the entry from the map.
      delete cur_context;
      config.erase(iter);

      rc = true;
    }
    else
    {
      LogW(cn, __func__, "Inconsistent ports: existing port range "
           "(%u:%u) mismatch with requested port range (%u:%u).\n",
           cur_context->lo_port(), cur_context->hi_port(),
           ref_context->lo_port(), ref_context->hi_port());
      rc = false;
    }
  }

  return rc;
}

//============================================================================
void UdpProxy::SetFlowDefn(const FourTuple& four_tuple, FECContext* flow_defn)
{
  FECContext* old_context = NULL;
  if (flow_defn_cache_.FindAndRemove(four_tuple, old_context))
  {
    delete old_context;
  }
  if (!flow_defn_cache_.Insert(four_tuple, flow_defn))
  {
    LogE(cn, __func__, "Error add flow definition for four-tuple %s.\n",
     four_tuple.ToString().c_str());
  }
}

//============================================================================
void UdpProxy::DelFlowDefn(const iron::FourTuple& four_tuple)
{
  FECContext* context;
  if (flow_defn_cache_.FindAndRemove(four_tuple, context))
  {
    delete context;
  }
}

//============================================================================
void UdpProxy::ReceivePktsFromBpf()
{
  // Read in packet indices from the backpressure forwarder.
  if (bpf_to_udp_pkt_fifo_.Recv())
  {
    Packet* packet;
    while (bpf_to_udp_pkt_fifo_.GetNextRcvdPacket(&packet))
    {
      if (packet != NULL)
      {
        ProcessPktFromBpf(packet);
      }
    }
  }
}

//============================================================================
void UdpProxy::ProcessPktFromBpf(Packet* pkt)
{
  PacketType  pkt_type = pkt->GetType();

  if (pkt_type == IPV4_PACKET)
  {
    LogD(cn, __func__, "RECV: From BPF, size: %zd bytes\n",
        pkt->GetLengthInBytes());

    uint16_t  dst_port  = 0;
    if (pkt->GetDstPort(dst_port) == false)
    {
      LogE(cn, __func__, "Error retrieving destinatin port from "
           "packet.\n");
      TRACK_UNEXPECTED_DROP(cn, packet_pool_);
      packet_pool_.Recycle(pkt);
      pkt = NULL;
      return;
    }

    if (ntohs(dst_port) == iron::Rrm::kDefaultRrmPort)
    {
      ProcessRRM(pkt);
    }
    else
    {
      RunDecoder(pkt);
    }
  }
  else
  {
    LogF(cn, __func__, "Unknown packet type received: %" PRIu32 "\n",
        pkt_type);
  }
}

//============================================================================
void UdpProxy::RunEncoder(Packet* pkt)
{
  // TODO: Figure out if we need to handle VXLAN tunneled UDP
  // packets. Currently, we don't handle these.

  // We first need to determine if the received packet is a tunneled UDP
  // packet. If so, the flow's IP and UDP headers are encapsulated and we need
  // to strip off the encapsulating headers before processing the received
  // packet.
  uint8_t  protocol;
  if (!pkt->GetIpProtocol(protocol))
  {
    LogE(cn, __func__, "Unable to get packet protocol from received "
         "packet.\n");
    TRACK_UNEXPECTED_DROP(cn, packet_pool_);
    packet_pool_.Recycle(pkt);
    pkt = NULL;
    return;
  }

  if (protocol == IPPROTO_PIM)
  {
    // We expect that the received PIM packet is a PIM Register packet. Make
    // sure that this is the case.
    struct iphdr*  ip_hdr   = pkt->GetIpHdr();
    uint8_t        hdr_len  = ip_hdr->ihl * 4;
    uint8_t        pim_type = *(pkt->GetBuffer(hdr_len)) & 0xf;

    if (pim_type != kPimRegisterPktType)
    {
      LogE(cn, __func__, "Received unexpected PIM packet type (%" PRIu8
           ").\n", pim_type);
      TRACK_UNEXPECTED_DROP(cn, packet_pool_);
      packet_pool_.Recycle(pkt);
      pkt = NULL;
      return;
    }

    // We have received a PIM Register packet. Strip off the outer IP header
    // and PIM header from the received packet before we continue processing
    // it.
    LogD(cn, __func__, "Received PIM Register packet.\n");
    LogD(cn, __func__, "Removing %d bytes from PIM Register packet.\n",
         (hdr_len + kPimHdrLen));

    if (!pkt->RemoveBytesFromBeginning(hdr_len + kPimHdrLen))
    {
      LogE(cn, __func__, "Error removing encapsulating IP Header and PIM "
           "header from received PIM Register packet.\n");
      TRACK_UNEXPECTED_DROP(cn, packet_pool_);
      packet_pool_.Recycle(pkt);
      pkt = NULL;
      return;
    }
  }

  uint16_t  sport_nbo;
  uint16_t  dport_nbo;
  uint32_t  saddr_nbo;
  uint32_t  daddr_nbo;
  uint32_t  proto;

  // Extract the 5-tuple from the packet.
  if (!pkt->GetFiveTuple(saddr_nbo, daddr_nbo, sport_nbo, dport_nbo,
                         proto))
  {
    LogW(cn, __func__, "5-tuple retrieval failed.\n");
    TRACK_UNEXPECTED_DROP(cn, packet_pool_);
    packet_pool_.Recycle(pkt);
    pkt = NULL;
    return;
  }

  FourTuple  four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);

  // Retrieve the encoding state. If this is not successful, ignore (and
  // recycle) the received packet.
  EncodingState*  encoding_state = NULL;
  Ipv4Address     dst_addr(daddr_nbo);

  // Verify that the destination address of the received packet has a mapping
  // in the BinMap.
  BinIndex  bin_idx = bin_map_shm_.GetDstBinIndexFromAddress(dst_addr);

  if (bin_idx == iron::kInvalidBinIndex)
  {
    LogW(cn, __func__, "No mapping for destination address %s found in "
         "BinMap.\n", dst_addr.ToString().c_str());
    packet_pool_.Recycle(pkt);
    pkt = NULL;
    return;
  }

  if (!GetEncodingState(bin_idx, four_tuple, encoding_state))
  {
    LogE(cn, __func__, "Encoding State retrieval failure, ignoring "
         "packet...\n");
    TRACK_UNEXPECTED_DROP(cn, packet_pool_);
    packet_pool_.Recycle(pkt);
    return;
  }

  std::string UNUSED(metadata) = pkt->GetPacketMetadataString();
  encoding_state->HandlePkt(pkt);

  LogD(cn, __func__, "fid: %" PRIu32 ", packet (%s) enqueued, bin %s"
       ", Q size: %" PRIu32 "\n", flow_tag_, metadata.c_str(),
       bin_map_shm_.GetIdToLog(encoding_state->bin_idx()).c_str(),
       encoding_state->GetCountFromEncodedPktsQueue());
}

//============================================================================
bool UdpProxy::GetEncodingState(const BinIndex bin_idx,
                                const FourTuple& four_tuple,
                                EncodingState*& encoding_state)
{
  bool success = true;
  if (!encoding.Find(four_tuple, encoding_state))
  {
    NormFlowController*  flow_controller = NULL;
    Ipv4Address          dst_addr        = four_tuple.dst_addr_nbo();

    if ((dst_addr >= norm_low_addr_) &&
        (dst_addr <= norm_high_addr_))
    {
      // The destination address falls in the configured range of NORM
      // addresses, so we will create a NORM Flow Controller for the flow.
      flow_controller = new (std::nothrow)
        NormFlowController(*this, packet_pool_, four_tuple,
                           max_queue_depth_pkts_);

      if (flow_controller == NULL)
      {
        LogE(cn, __func__, "Error allocating new NormFlowController.\n");
      }
    }

    // Create and configure a new EncodingState.
    encoding_state = new (std::nothrow) EncodingState(*this,
                                                      local_queue_depths_,
                                                      packet_pool_,
                                                      bin_map_shm_,
                                                      k_val_,
                                                      four_tuple,
                                                      max_queue_depth_pkts_,
                                                      drop_policy_, bin_idx,
                                                      flow_tag(),
                                                      flow_controller);

    if (encoding_state == NULL)
    {
      LogF(cn, __func__, "Error allocating new EncodingState.\n");
      return false;
    }

    if (!encoding.Insert(four_tuple, encoding_state))
    {
      LogE(cn, __func__, "Error inserting new EncodingState.\n");
      delete encoding_state;
      return false;
    }

    map<BinIndex, set<EncodingState*> >::iterator  it =
      bin_states_map_.find(bin_idx);
    if (it == bin_states_map_.end())
    {
      // No current set of states for this bin. Create an empty set and
      // inserts it in map.
      set<EncodingState*>  enc_states_set;
      bin_states_map_[bin_idx] = enc_states_set;
    }
    bin_states_map_[bin_idx].insert(encoding_state);

    // Look up the context. If we don't find one, this isn't a supported
    // service so we discard the packet.
    FECContext  context;
    if (!GetContext(four_tuple, context))
    {
      LogW(cn, __func__, "fid: %" PRIu32 ", context not found for src,dst "
           "ports %" PRIu16 ",%" PRIu16 ".\n", encoding_state->flow_tag(),
           ntohs(four_tuple.src_port_nbo()),
           htons(four_tuple.dst_port_nbo()));
      return false;
    }

    // Get the Utility Function Definition from the collection of definitions.
    string  utility_def = "";
    if (!GetUtilityFn(context, utility_def))
    {
      LogF(cn, __func__, " No utility function found for src, dst ports %"
           PRIu16 ", %" PRIu16 ".\n", four_tuple.src_port_nbo(),
           four_tuple.dst_port_nbo());
      return false;
    }

    // Complete configuration of EncodingState.
    encoding_state->UpdateEncodingParams(context.base_rate(),
                                         context.total_rate(),
                                         context.in_order(),
                                         context.max_chunk_sz(),
                                         context.max_hold_time(),
                                         context.timeout(),
                                         context.time_to_go(),
                                         context.time_to_go_valid(),
                                         context.dscp(),
                                         context.reorder_time(),
                                         context.dst_vec());

    // and create the EncodingState's admission controller.
    success = encoding_state->CreateAdmissionController(utility_def);
    LogI(cn, __func__, "fid: %" PRIu32 " <==> %s\n",
         encoding_state->flow_tag(), four_tuple.ToString().c_str());
  }

  return success;
}

//============================================================================
bool UdpProxy::ResetEncodingState(EncodingState* es)
{
  if (es == NULL)
  {
    LogE(cn, __func__, "Failed to reset NULL encoding state\n");
    return false;
  }

  FECContext  context;
  FourTuple   four_tuple = es->four_tuple();
  if (!GetContext(four_tuple, context))
  {
    LogF(cn, __func__, "Did not find context for flow %s\n",
         four_tuple.ToString().c_str());
    return false;
  }

  // Get the Utility Function Definition from the collection of definitions,
  string  utility_def = "";
  if (!GetUtilityFn(context, utility_def))
  {
    return false;
  }

  // update the encoding state parameters.
  es->UpdateEncodingParams(context.base_rate(),
                           context.total_rate(),
                           context.in_order(),
                           context.max_chunk_sz(),
                           context.max_hold_time(),
                           context.timeout(),
                           context.time_to_go(),
                           context.time_to_go_valid(),
                           context.dscp(),
                           context.reorder_time(),
                           context.dst_vec());

  // create the admission controller for the flow, and
  bool success = es->CreateAdmissionController(utility_def);

  es->FlushBacklog();
  return success;
}

//============================================================================
void UdpProxy::RunDecoder(Packet* pkt)
{
  uint16_t  sport_nbo;
  uint16_t  dport_nbo;
  uint32_t  saddr_nbo;
  uint32_t  daddr_nbo;
  uint32_t  proto;

  // Extract the 5-tuple from the packet.
  if (!pkt->GetFiveTuple(saddr_nbo, daddr_nbo, sport_nbo, dport_nbo,
                         proto))
  {
    LogW(cn, __func__, "5-tuple retrieval failed.\n");
    TRACK_UNEXPECTED_DROP(cn, packet_pool_);
    packet_pool_.Recycle(pkt);
    return;
  }

  // Retrieve the decoding state. This will only fail on a memory allocation
  // failure. If that happens its time to quit.
  FourTuple       four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);
  DecodingState*  decoding_state;
  if (!GetDecodingState(four_tuple, decoding_state))
  {
    LogE(cn, __func__, "State retrieval failure -- should not happen.\n");
    TRACK_UNEXPECTED_DROP(cn, packet_pool_);
    packet_pool_.Recycle(pkt);
    return;
  }

  // Pass the received packet the the decoding state for processing. Note that
  // ownership of the received packet is passed to the decoding state.
  decoding_state->HandlePkt(pkt);
}

//============================================================================
bool UdpProxy::GetDecodingState(const FourTuple& four_tuple,
                                DecodingState*& decoding_state)
{
  if (!decoding.Find(four_tuple, decoding_state))
  {
    decoding_state = new (std::nothrow) DecodingState(*this, packet_pool_,
                                                      bin_map_shm_,
                                                      k_val_, fecstate_pool_,
                                                      four_tuple, flow_tag());

    if (decoding_state == NULL)
    {
      LogF(cn, __func__, "Error allocating new DecodingState.\n");
      return false;
    }

    // Get the Utility Function Definition from the collection of definitions.
    // Look up the context.
    FECContext  context;
    if (!GetContext(four_tuple, context))
    {
      delete decoding_state;
      decoding_state = NULL;
      return false;
    }

    string  utility_def = "";
    if (!GetUtilityFn(context, utility_def))
    {
      delete decoding_state;
      decoding_state = NULL;
      LogF(cn, __func__, " No utility function found for src, dst ports %"
           PRIu16 ", %" PRIu16 ".\n", four_tuple.src_port_nbo(),
           four_tuple.dst_port_nbo());
      return false;
    }

    // Create the packet release controller for the decoding state.
    decoding_state->CreateReleaseController(utility_def);

    Time reorder_time = context.reorder_time();
    if (reorder_time.GetTimeInUsec() == 0)
    {
      decoding_state->set_max_reorder_time(reorder_max_hold_time_);
      LogD(cn, __func__, "Using global max reorder time:%s\n",
           reorder_max_hold_time_.ToString().c_str());
    }
    else
    {
      decoding_state->set_max_reorder_time(reorder_time);
      LogD(cn, __func__, "Using context max reorder time:%s\n",
           reorder_time.ToString().c_str());
    }

    if (!decoding.Insert(four_tuple, decoding_state))
    {
      LogE(cn, __func__, "Error inserting new DecodingState.\n");
      delete decoding_state;
      decoding_state = NULL;
      return false;
    }
  }

  // decoding_state is valid, and a reference is stored in "decoding".
  return true;
}

//============================================================================
bool UdpProxy::ResetDecodingState(DecodingState* ds)
{
  // Note: The Decoding state does not have FEC parameters.
  // These are derived, as needed, from the packets.
  // Only the utility function and reordering hold time
  // needs to be reset.

  if (ds == NULL)
  {
    LogE(cn, __func__, "Failed to reset NULL decoding state\n");
    return false;
  }

  FourTuple  four_tuple = ds->four_tuple();
  FECContext context;
  if (!GetContext(four_tuple, context))
  {
    LogF(cn, __func__, "Did not find context for flow %s\n",
      four_tuple.ToString().c_str());
    return false;
  }

  Time reorder_time = context.reorder_time();
  if (reorder_time.GetTimeInUsec() == 0)
  {
    ds->set_max_reorder_time(reorder_max_hold_time_);
    LogD(cn, __func__, "Using global max reorder time:%s\n",
         reorder_max_hold_time_.ToString().c_str());
  }
  else
  {
    ds->set_max_reorder_time(reorder_time);
    LogD(cn, __func__, "Using context max reorder time:%s\n",
         reorder_time.ToString().c_str());
  }

  // Reset packet release control.
  string  utility_def;
  if (!GetUtilityFn(context, utility_def))
  {
    return false;
  }

  ds->CreateReleaseController(utility_def);

  return true;
}

//============================================================================
void UdpProxy::TurnFlowOff(const FourTuple& four_tuple)
{
  EncodingState*  encoding_state = NULL;
  if (GetExistingEncodingState(four_tuple, encoding_state))
  {
    LogW(cn, __func__, "Turning flow off in encoding state: %s.\n",
         four_tuple.ToString().c_str());
    encoding_state->set_flow_state(iron::FLOW_OFF);
  }
}

//============================================================================
void UdpProxy::ProcessRRM(Packet* pkt)
{
  LogD(cn, __func__, "Processing RRM packet.\n");

  iron::Rrm::PrintRrm(pkt);
  FourTuple four_tuple;
  iron::Rrm::GetFlowFourTuple(pkt, four_tuple);

  uint64_t  highest_num_bytes   = 0;
  uint64_t  num_released_bytes  = 0;
  uint32_t  highest_num_pkts    = 0;
  uint32_t  num_released_pkts   = 0;
  uint32_t  cur_loss_rate_pct   = 0;

  iron::Rrm::GetReport(pkt, highest_num_bytes, highest_num_pkts,
    num_released_bytes, num_released_pkts, cur_loss_rate_pct);

  // For each flow being reported in the this RRM, the data is
  // structured as follows:
  // 32 bits: source address
  // 32 bits: dest address
  // 16 bits: source port
  // 16 bits: dest port
  // 64 bits: bytes sourced
  // 32 bits: packets sources
  // 64 bits: bytes released
  // 32 bits: packets released
  // 32 bits: average loss rate

  EncodingState*  state;
  if (!encoding.Find(four_tuple, state))
  {
    LogE(cn, __func__,
         "Failed to find flow for tuple %s.\n",
         four_tuple.ToString().c_str());
  }
  else
  {
    LogA(cn, __func__,
         "RRM updating flow for tuple %s. Bytes: Hi %" PRIu64 " / Re %" PRIu64
         ", packets: Hi %" PRIu32 " / Re %" PRIu32 ", current loss rate: %" PRIu8
         "\%\n",
         four_tuple.ToString().c_str(),
         highest_num_bytes, num_released_bytes,
         highest_num_pkts, num_released_pkts, cur_loss_rate_pct);
    state->UpdateReceiverStats(highest_num_pkts, cur_loss_rate_pct);
  }

  packet_pool_.Recycle(pkt);
}

//============================================================================
void UdpProxy::ProcessRemoteControlMessage()
{
  LogD(cn, __func__, "Processing Remote Control message.\n");

  // Switch on the type of request message.
  RmtCntlMsgType  msg_type = remote_control_.msg_type();

  switch (msg_type)
  {
    case iron::RC_SET:
      ProcessSetMessage();
      break;

    case iron::RC_GET:
      ProcessGetMessage();
      break;

    case iron::RC_PUSHREQ:
      ProcessPushReqMessage();
      break;

    case iron::RC_PUSHSTOP:
      ProcessPushStopMessage();
      break;

    case iron::RC_INVALID:
    default:
      LogE(cn, __func__, "Unknown remote control message type: %d\n",
           static_cast<int>(msg_type));

      // Abort this client connection.
      remote_control_.AbortClient();
  }
}

//============================================================================
void UdpProxy::ProcessSetMessage()
{
  bool          success  = false;
  const Value*  key_vals = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetSetMessage(target, key_vals)) ||
      (key_vals == NULL))
  {
    LogE(cn, __func__, "Error getting remote control set message.\n");
    remote_control_.SendSetReplyMessage(false, "Message processing error.");
    return;
  }

  LogD(cn, __func__, "Processing remote control set message for target %s.\n",
       target.c_str());

  // ---------- UDP proxy target ----------
  if (target == "udp_proxy")
  {
    bool  overall_success = true;

    // Loop over the key/value pairs, processing each one.
    for (Value::ConstMemberIterator it = key_vals->MemberBegin();
         it != key_vals->MemberEnd(); ++it)
    {
      // The key must be a string.
      if (!(it->name.IsString()))
      {
        LogE(cn, __func__, "Error, key is not a string.\n");
        success = false;
        err_msg = "Key is not a string.";
      }
      else
      {
        string  key = it->name.GetString();

        // ---------- Service Definition ----------
        if (key == "add_service")
        {
          success = ProcessServiceDefnUpdateMsg(key, it->value, err_msg);
        }
        // ---------- Flow Definition ----------
        else if ((key == "add_flow") || (key == "del_flow") ||
          (key == "off_flow") || (key == "update_util"))
        {
          success = ProcessFlowDefnUpdateMsg(key, it->value, err_msg);
        }
        // ---------- Multicast Destination Bit Vector ----------
        else if (key == "add_mcast_dst_list")
        {
          success = ProcessMcastDstListMsg(key, it->value, err_msg);
        }
        else
        {
          success = false;
          err_msg = "Unknown set key: " + key;
        }
      }

      overall_success = (overall_success && success);
    }

    success = overall_success;
  }
  else
  {
    LogE(cn, __func__, "Unknown remote control set message target: %s\n",
         target.c_str());
    err_msg = "Unknown target: " + target;
  }

  remote_control_.SendSetReplyMessage(success, err_msg);
}

//============================================================================
bool UdpProxy::ProcessServiceDefnUpdateMsg(const string& key,
                                           const Value& val_obj,
                                           string& err_msg)
{
  LogD(cn, __func__, "Processing Service definition update.\n");

  if (!(val_obj.IsString()))
  {
    err_msg = "Service update must contain exactly 1 value string.";
    return false;
  }

  // update the context cache for encoded states to be created in the future
  string  val = val_obj.GetString();
  if (key != "add_service")
  {
    LogW(cn, __func__, "Unsupported operation for Service.\n");
    err_msg = "Unsupported service operation.";
    return false;
  }

  char  parm[300];
  strncpy(&parm[0], val.c_str(), sizeof(parm)-1);
  parm[sizeof(parm)-1] = '\0';


  FECContext*  context;
  if ((context = ParseService(&parm[0],FECModAction)) != NULL)
  {
    // check if it is the default service
    if (context->lo_port() == 0)
    {
      delete default_service_;
      default_service_ = context;
      LogI(cn, __func__, " Default Service Updated : %s\n",val.c_str());
      return true;
    }
    // Enable this service
    if (ModService(context) == false)
    {
      LogW(cn, __func__, "Addition of service %s failed\n",
               val.c_str());
      err_msg = "Service definition update failed\n";
      return false;
    }
    LogI(cn, __func__, "Service Updated : %s\n",val.c_str());
  }
  else
  {
    LogE(cn, __func__, "Failed to create context from RC Service "
                       "add message: %s\n", val.c_str());
    err_msg = "Unable to parse service\n";
    return false;
  }

  // Update the utility function definition in existing Encoding states.
  iron::MashTable<FourTuple, EncodingState*>::WalkState es_ws;
  EncodingState*                                        es  = NULL;
  FourTuple                                             four_tuple;

  while (encoding.GetNextItem(es_ws, es))
  {
    four_tuple  = es->four_tuple();
    if (ntohs(four_tuple.dst_port_nbo()) >= context->lo_port() &&
        ntohs(four_tuple.dst_port_nbo()) <= context->hi_port())
    {

      // This state is affected so reset the utility function.

      // If the EncodingState that we just found has a Flow definition, move
      // on (the Flow definition takes precedence over the Service
      // definition).
      if (HasFlowDefn(four_tuple))
      {
        continue;
      }

      LogD(cn, __func__, "Updating encoding state: %s\n",
                          four_tuple.ToString().c_str());

      // Reset the utility function and update the FEC parameters.
      ResetEncodingState(es);
    }
  }

  // Update the utility function definition in existing decoding states.
  iron::MashTable<FourTuple, DecodingState*>::WalkState ds_ws;
  DecodingState*                                        ds  = NULL;

  while (decoding.GetNextItem(ds_ws, ds))
  {
    four_tuple  = ds->four_tuple();
    if (ntohs(four_tuple.dst_port_nbo()) >= context->lo_port() &&
        ntohs(four_tuple.dst_port_nbo()) <= context->hi_port())
    {

      // If the DecodingState that we just found has a Flow definition, move
      // on (the Flow definition takes precedence over the Service
      // definition).
      if (HasFlowDefn(four_tuple))
      {
        continue;
      }

      LogD(cn, __func__, "Updating decoding state: %s\n",
           four_tuple.ToString().c_str());

      // There is not a Flow definition for the EncodingState, so we'll use
      // the Service definition or the default utility definition if there is
      // no Service definition.
      ResetDecodingState(ds);
    }
  }

  delete context;
  return true;
}

//============================================================================
bool UdpProxy::ProcessFlowDefnUpdateMsg(const string& key,
                                        const Value& val_obj,
                                        string& err_msg)
{
  LogD(cn, __func__, "Processing Flow definition update.\n");
  EncodingState  *enc_state;
  DecodingState  *dec_state;

  if (!(val_obj.IsString()))
  {
    err_msg = "Flow update must contain exactly 1 value string.";
    return false;
  }

  // update the flow defn cache for encoded states to be created in the future
  if ((key != "add_flow") && (key != "del_flow") && (key != "off_flow") &&
      (key != "update_util"))
  {
    LogE(cn, __func__, "Unsupported operation for Flow defn:%s.\n",
            key.c_str());
    err_msg = "Unsupported flow operation.";
    return false;;
  }

  string        val    = val_obj.GetString();
  List<string>  tokens;
  StringUtils::Tokenize(val, ";", tokens);

  if ((key == "add_flow") || (key == "update_util"))
  {
    if (tokens.size() < 5)
    {
      err_msg = "Flow add or update command requires at least 5 parameters.\n";
      LogE(cn, __func__,
            "flow_add and util_update requires at least 5 parameters.\n");
      return false;
    }
  }

  string  token;
  tokens.Pop(token);
  unsigned short sport_nbo = htons(StringUtils::GetUint(token));
  tokens.Pop(token);
  unsigned short dport_nbo = htons(StringUtils::GetUint(token));
  tokens.Pop(token);
  unsigned long saddr_nbo  =
     (unsigned long)StringUtils::GetIpAddr(token).address();
  tokens.Peek(token);
  unsigned long daddr_nbo  =
     (unsigned long)StringUtils::GetIpAddr(token).address();

  FourTuple  four_tuple(saddr_nbo, sport_nbo, daddr_nbo, dport_nbo);
  FECContext* context = NULL;

  if (key == "add_flow")
  {
    char  parm[300];
    strncpy(&parm[0], val.c_str(), sizeof(parm)-1);
    parm[sizeof(parm)-1] = '\0';

    if ((context = ParseService(&parm[0], FECModAction, true)) != NULL)
    {
      SetFlowDefn(four_tuple, context);
    }
    else
    {
      LogE(cn, __func__, "Failed to parse flow defn: %s\n", val.c_str());
      err_msg = "Unable to parse flow.\n";
    }
  }
  else if (key == "del_flow")
  {
    if (flow_defn_cache_.FindAndRemove(four_tuple, context))
    {
      if (context != NULL)
      {
        delete context;
        LogD(cn, __func__, "Removed exisiting flow defn: %s\n", val.c_str());
      }
    }
    else
    {
      LogE(cn, __func__, "Unable to removed flow defn: %s\n", val.c_str());
    }
  }
  else if(key == "off_flow")
  {
    TurnFlowOff(four_tuple);
    return true;
  }

  // Update the existing encoding state.
  if (GetExistingEncodingState(four_tuple, enc_state))
  {
    if (key == "update_util")
    {
      string  value;
      tokens.PeekBack(value);
      LogD(cn, __func__, "Updating utility fn param %s encoding state: %s\n",
                          value.c_str(),
                          four_tuple.ToString().c_str());
      enc_state->UpdateUtilityFn(value);
    }
    else
    {
      LogD(cn, __func__, "Updating encoding state: %s\n",
                          four_tuple.ToString().c_str());
      ResetEncodingState(enc_state);
    }
  }

  // Update the utility and reordering time in decoding states.
  if (GetExistingDecodingState(four_tuple, dec_state))
  {
    LogD(cn, __func__, "Updating decoding state: %s\n",
                          four_tuple.ToString().c_str());
    ResetDecodingState(dec_state);
  }

  return true;
}

//============================================================================
bool UdpProxy::ProcessMcastDstListMsg(const string& key, const Value& val_obj,
                                      string& err_msg)
{
  LogD(cn, __func__, "Processing add multicast destination list message.\n");

  if (!(val_obj.IsString()))
  {
    err_msg = "Add multicast destination list update must contain exactly 1 "
      "value string.";
    return false;
  }

  if (key != "add_mcast_dst_list")
  {
    LogW(cn, __func__, "Unsupported operation for multicast destination list "
         "modification.\n");
    err_msg = "Unsupported operation for multicast destination list "
      "modification.";
    return false;
  }

  // Add the destination list to the EncodingState for the flow.
  //
  // The value string is of the form:
  //
  //   "a.b.c.d:xx->e.f.g.h:yy;i.j.k.l,m.n.o.p,...q.r.s.t"
  string        value = val_obj.GetString();
  List<string>  tokens;
  StringUtils::Tokenize(value, ";", tokens);

  string  flow_tuple_str;
  tokens.Pop(flow_tuple_str);
  string  dst_list_str;
  tokens.Pop(dst_list_str);

  // The first token is the flow tuple and has the following format:
  //
  //   saddr:sport->daddr:dport
  List<string>  four_tuple_tokens;
  StringUtils::Tokenize(flow_tuple_str, "->", four_tuple_tokens);
  if (four_tuple_tokens.size() != 2)
  {
    LogW(cn, __func__, "Improperly formatted flow tuple.\n");
    err_msg = "Improperly formatted flow tuple.";
    return false;
  }
  string  src_token;
  four_tuple_tokens.Pop(src_token);
  string  dst_token;
  four_tuple_tokens.Pop(dst_token);

  Ipv4Endpoint  src_endpt(src_token);
  Ipv4Endpoint  dst_endpt(dst_token);

  FourTuple  four_tuple(src_endpt.address(), src_endpt.port(),
                        dst_endpt.address(), dst_endpt.port());

  EncodingState*  encoding_state = NULL;
  BinIndex        bin_idx        = iron::kInvalidBinIndex;

  // Verify that the destination address has a mapping in the BinMap.
  bin_idx = bin_map_shm_.GetMcastBinIndex(dst_endpt.address());
  if (bin_idx == 0)
  {
    LogW(cn, __func__, "No mapping for destination address %s found in "
         "BinMap.\n", Ipv4Address(dst_endpt.address()).ToString().c_str());
    err_msg = "No mapping for destination address " +
      Ipv4Address(dst_endpt.address()).ToString() + " found in BinMap.";
    return false;
  }

  if (!GetEncodingState(bin_idx, four_tuple, encoding_state))
  {
    LogE(cn, __func__, "Unable to set destination list for flow: %s\n",
         flow_tuple_str.c_str());
    err_msg = "Unable to set destination list for flow: " + flow_tuple_str;
    return false;
  }

  // We have found the EncodingState object for the flow. Now, create the
  // DstVec and set it in the EncodingState.
  //
  // The second token is the destination list and has the following format:
  //
  //   a.b.c.d,e.f.g.h,...i.j.k.l
  DstVec        dst_vec = 0;
  List<string>  dsts;
  StringUtils::Tokenize(dst_list_str, ",", dsts);
  while (dsts.size() > 0)
  {
    string  dst;
    dsts.Pop(dst);

    Ipv4Address  address(dst);

    bin_idx = bin_map_shm_.GetDstBinIndexFromAddress(address);

    if (bin_idx == iron::kInvalidBinIndex)
    {
      LogE(cn, __func__, "No mapping for destination address %s found in "
           "BinMap.\n", address.ToString().c_str());
      err_msg = "No mapping for destination address " + address.ToString() +
        " found in BinMap.";
      return false;
    }

    dst_vec = bin_map_shm_.AddBinToDstVec(dst_vec, bin_idx);
  }

  LogD(cn, __func__, "Multicast destination bit vector: %" PRIu32 "\n",
       dst_vec);
  encoding_state->set_mcast_dst_vec(dst_vec);

  return true;
}

//============================================================================
void UdpProxy::ProcessGetMessage()
{
  bool          success = false;
  const Value*  keys    = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetGetMessage(target, keys)) || (keys == NULL))
  {
    LogE(cn, __func__, "Error getting remote control get message.\n");
    remote_control_.StartGetReplyMessage(false, "Message processing error.");
    remote_control_.SendGetReplyMessage(false);
    return;
  }

  LogD(cn, __func__, "Processing remote control get message for target %s.\n",
       target.c_str());

  // ---------- UDP proxy target ----------
  if (target == "udp_proxy")
  {
    success = true;

    // Only support the "stats" key right now, so make this loop simple.
    for (SizeType i = 0; i < keys->Size(); ++i)
    {
      if ((*keys)[i].IsString())
      {
        string  key = (*keys)[i].GetString();

        if (key == "stats")
        {
          continue;
        }

        LogE(cn, __func__, "Unsupported get message key %s.\n", key.c_str());
        success = false;
        err_msg = "Unsupported key " + key + ".";
      }
      else
      {
        LogE(cn, __func__, "Non-string key is not supported.\n");
        success = false;
        err_msg = "Non-string key.";
      }
    }

    Writer<StringBuffer>* writer =
      remote_control_.StartGetReplyMessage(success, err_msg);

    if (success)
    {
      WriteStats(false, writer);
    }

    remote_control_.SendGetReplyMessage(success);
    return;
  }

  LogE(cn, __func__, "Unknown remote control get message target: %s\n",
       target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.StartGetReplyMessage(false, err_msg);
  remote_control_.SendGetReplyMessage(false);
}

//============================================================================
void UdpProxy::ProcessPushReqMessage()
{
  bool          success   = false;
  uint32_t      client_id = 0;
  uint32_t      msg_id    = 0;
  double        interval  = 0.0;
  const Value*  keys      = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetPushRequestMessage(client_id, msg_id, target,
                                              interval, keys)) ||
      (keys == NULL) || (interval < 0.01))
  {
    LogE(cn, __func__, "Error getting remote control push request "
         "message.\n");
    return;
  }

  LogD(cn, __func__, "Processing remote control push request message for "
       "client %" PRIu32 " msg %" PRIu32 " target %s interval %f.\n",
       client_id, msg_id, target.c_str(), interval);

  // ---------- UDP proxy target ----------
  if (target == "udp_proxy")
  {
    success = true;

    // Only support the "stats" key right now, so make this loop simple.
    for (SizeType i = 0; i < keys->Size(); ++i)
    {
      if ((*keys)[i].IsString())
      {
        string  key = (*keys)[i].GetString();

        if (key == "stats")
        {
          continue;
        }

        LogE(cn, __func__, "Unsupported push request message key %s.\n",
             key.c_str());
        success = false;
        err_msg = "Unsupported key " + key + ".";
      }
      else
      {
        LogE(cn, __func__, "Non-string key is not supported.\n");
        success = false;
        err_msg = "Non-string key.";
      }
    }

    if (success)
    {
      // If currently pushing to a client, adjust the interval or return an
      // error.
      if (stats_push_.is_active)
      {
        msg_id    = stats_push_.msg_id;
        if (stats_push_.interval_sec >= interval)
        {
          client_id = stats_push_.client_id;
          LogD(cn, __func__, "Already pushing to a client, increasing rate "
               "of stats reporting to %.3f seconds.\n", interval);
        }
        else
        {
          remote_control_.SendPushErrorMessage(client_id, msg_id,
                                               "Already pushing to a client.");
          return;
        }
      }

      // Record the necessary information, including the next push time.
      stats_push_.is_active      = true;
      stats_push_.client_id      = client_id;
      stats_push_.msg_id         = msg_id;
      stats_push_.interval_sec   = interval;
      stats_push_.next_push_time = Time::Now().Add(interval);

      return;
    }

    remote_control_.SendPushErrorMessage(client_id, msg_id, err_msg);
    return;
  }

  LogE(cn, __func__, "Unknown remote control get message target: %s\n",
       target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.SendPushErrorMessage(client_id, msg_id, err_msg);
}

//============================================================================
void UdpProxy::ProcessPushStopMessage()
{
  uint32_t client_id = 0;
  uint32_t msg_id = 0;
  string   target;
  uint32_t to_stop_count = 0;

  // Get the message.
  if (!remote_control_.GetPushStopMessage(client_id, msg_id, target, to_stop_count))
  {
    LogE(cn, __func__, "Error getting remote control push stop message.\n");
    return;
  }

  if (to_stop_count != 0)
  {
    if (to_stop_count != 1)
    {
      LogE(cn, __func__, "More than one stop message id in push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "More than one stop message id");
      return;
    }
    uint32_t to_stop_id = 0;
    if (!remote_control_.GetPushStopToStopId(0, to_stop_id))
    {
      LogE(cn, __func__, "Failed to get stop message id from push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "Couldn't access id at index 0");
      return;
    }
    if (stats_push_.is_active && to_stop_id != stats_push_.msg_id)
    {
      LogE(cn, __func__, "Unexpected stop message id in push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "Unexpexted stop message id.");
      return;
    }
  }

  LogD(cn, __func__, "Stopping statistics pushing upon request.\n");

  // Stop the pushes.
  stats_push_.is_active      = false;
  stats_push_.client_id      = 0;
  stats_push_.msg_id         = 0;
  stats_push_.interval_sec   = 0.0;
  stats_push_.next_push_time = Time::Infinite();
}

//============================================================================
void UdpProxy::PushStats(bool is_periodic)
{
  if (!stats_push_.is_active)
  {
    // We aren't pushing stats to an external client, but they still may be
    // logged to the log file.
    WriteStats(is_periodic);
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
      LogD(cn, __func__, "Stopping statistics pushing.\n");

      stats_push_.is_active      = false;
      stats_push_.client_id      = 0;
      stats_push_.msg_id         = 0;
      stats_push_.interval_sec   = 0.0;
      stats_push_.next_push_time = Time::Infinite();

      // The external client is no longer connected but the stats may still be
      // logged to the log file.
      WriteStats(is_periodic);
    }
    else
    {
      // Add in the statistics.
      WriteStats(is_periodic, writer);

      // Complete the push message and send it.
      remote_control_.SendPushMessage(stats_push_.client_id);
    }
  }

  // Schedule the next stats push event time.
  if (is_periodic)
  {
    Time  delta_time;
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

    stats_push_.next_push_time = Time::Now() + delta_time;
  }
}

//============================================================================
void UdpProxy::WriteStats(bool is_periodic, Writer<StringBuffer>* writer)
{
  // If there is no writer and if the stats would not be written to the
  // log file, there is no need to continue.
  if ((writer == NULL) && (!log_stats_ || !WouldLogI(cn)))
  {
    return;
  }

  // Stats "keyvals" format.
  //  "stats" :
  //  {
  //    "NumActiveOutboundFlows" : xx,
  //    "NumActiveInboundFlows"  : xx,
  //    "MaxQueueDepthsBytes"    : [ b, n, b, n, b, n ],
  //    "InactiveFlows           :
  //    [
  //      a.b.c.d:eph -> e.f.g.h:svc,
  //      ...
  //    ],
  //    "ActiveOutboundFlows" :
  //    [
  //      { "flow_id"         : "a.b.c.d:eph -> e.f.g.h:svc",
  //        "prio"            : xxxx.xxx,
  //        "pkts"            : xxxxxx,
  //        "bytes"           : xxxxxx,
  //        "rate_bps"        : xxxx.xxx,
  //        "rate_pps"        : xxxx.xxx,
  //        "acked_seq_num"   : xxxx,
  //        "loss_rate_pct"   : xx,
  //        "utility"         : xxxx.xxx,
  //        "flow_state"      : x,
  //        "bin_id"          : x,
  //        "src_rate"        : xxx.xxx
  //      },
  //      ...
  //    ],
  //    "ActiveInboundFlows" :
  //    [
  //      { "flow_id"     : "a.b.c.d:eph -> e.f.g.h:svc",
  //        "pkts"        : xxxxxx,
  //        "bytes"       : xxxxxx,
  //        "rate_bps"    : xxxx.xxx,
  //        "rate_pps"    : xxxx.xxx,
  //        "avg_delay_ms": xxx.xxx,
  //        "max_delay_ms": xxx,
  //        "avg_delay_ms": xxx.xxx,
  //        "max_delay_ms": xxx,
  //        "utility"     : xxx.xxx,
  //      },
  //      ...
  //    ],
  //    "CumulativeUtility" : xxxx.xxx,
  //    "KVal" : x

  Time    now     = Time::Now();
  string  log_str = "";

  if (log_stats_)
  {
    LogI(cn, __func__, "---Udp Stats-------------\n");

    log_str.append(
      StringUtils::FormatString(256, "NumActiveOutboundFlows=%zd",
                                encoding.size()));
    LogI(cn, __func__, "%s\n", log_str.c_str());

    log_str.clear();
    log_str.append(
      StringUtils::FormatString(256, "NumActiveInboundFlows=%zd",
                                decoding.size()));
    LogI(cn, __func__, "%s\n", log_str.c_str());

    log_str.clear();
    log_str.append("InactiveFlows=[");
  }

  bool  first = true;
  if (writer)
  {
    if (is_periodic)
    {
      writer->Key("stats");
    }
    else
    {
      writer->Key("event_stats");
    }
    writer->StartObject();

    writer->Key("NumActiveOutboundFlows");
    writer->Uint(encoding.size());

    writer->Key("NumActiveInboundFlows");
    writer->Uint(decoding.size());

    writer->Key("MaxQueueDepthsBytes");
    writer->StartArray();
    BinIndex  idx = kInvalidBinIndex;
    for (bool idx_valid = bin_map_shm_.GetFirstBinIndex(idx);
         idx_valid;
         idx_valid = bin_map_shm_.GetNextBinIndex(idx))
    {
      if (bin_map_shm_.IsMcastBinIndex(idx))
      {
        writer->Uint(bin_map_shm_.GetMcastId(idx));
      }
      else
      {
        writer->Uint(bin_map_shm_.GetPhyBinId(idx));
      }
      writer->Uint(max_queue_[idx]);
      max_queue_[idx] = 0;  // reset for next interval.
    }
    writer->EndArray();
    writer->Key("InactiveOutboundFlows");
    writer->StartArray();
  }

  while (garbage_collected_flows_.size() > 0)
  {
    FourTuple ft;
    garbage_collected_flows_.Peek(ft);
    string     flow_id_str = (Ipv4Endpoint(ft.src_addr_nbo(),
                                           ft.src_port_nbo()).ToString() +
                              " -> " +
                              Ipv4Endpoint(ft.dst_addr_nbo(),
                                           ft.dst_port_nbo()).ToString());

    if (log_stats_)
    {
      if (first)
      {
        first = false;
      }
      else
      {
        log_str.append(",");
      }

      log_str.append(
        StringUtils::FormatString(256, "'%s'", flow_id_str.c_str()));
    }

    if (writer)
    {
      writer->String(flow_id_str.c_str());
    }

    garbage_collected_flows_.Pop(ft);
  }

  if (writer)
  {
    writer->EndArray();

    writer->Key("ActiveOutboundFlows");
    writer->StartArray();
  }

  if (log_stats_)
  {
    log_str.append("]");
    LogI(cn, __func__, "%s\n", log_str.c_str());

    log_str.clear();
    log_str.append("OutboundFlowStats=");
  }

  double cumulative_utility = 0.0;

  first = true;

  iron::MashTable<FourTuple, EncodingState*>::WalkState es_walk_state;
  EncodingState*  encoding_state  = NULL;
  while (encoding.GetNextItem(es_walk_state, encoding_state))
  {
    if (first)
    {
      first = false;
    }
    else
    {
      log_str.append(",");
    }

    encoding_state->WriteStats(now, log_str, writer);

    cumulative_utility += encoding_state->utility();
  }

  if (log_stats_)
  {
    LogI(cn, __func__, "%s\n", log_str.c_str());

    log_str.clear();
    log_str.append("InboundFlowStats=");
  }

  if (writer)
  {
    writer->EndArray();

    writer->Key("ActiveInboundFlows");
    writer->StartArray();
  }

  first = true;

  iron::MashTable<FourTuple, DecodingState*>::WalkState ds_walk_state;
  DecodingState*    decoding_state  = NULL;
  while (decoding.GetNextItem(ds_walk_state, decoding_state))
  {
    if (first)
    {
      first = false;
    }
    else
    {
      log_str.append(",");
    }

    decoding_state->WriteStats(now, log_str, writer);
  }

  total_utility_ += cumulative_utility;

  if (log_stats_)
  {
    LogI(cn, __func__, "%s\n", log_str.c_str());

    log_str.clear();
    log_str.append("AggStats=");
    log_str.append(
      StringUtils::FormatString(256, "'CumulativeUtility':'%f',",
                                cumulative_utility));
    log_str.append(
      StringUtils::FormatString(256, "'HistoricAggregateUtility':'%f'",
                                total_utility_));
    log_str.append(
      StringUtils::FormatString(256, "'KVal':'%" PRIu64 "'",
                                k_val_.GetValue()));
    LogI(cn, __func__, "%s\n", log_str.c_str());
  }

  if (writer)
  {
    writer->EndArray();

    writer->Key("CumulativeUtility");
    writer->Double(cumulative_utility);

    writer->Key("HistoricUtility");
    writer->Double(total_utility_);

    writer->Key("KVal");
    writer->Uint64(k_val_.GetValue());

    writer->EndObject();
  }

  if (log_stats_)
  {
    LogI(cn, __func__, "-------------Udp Stats---\n");
  }
}

//============================================================================
bool UdpProxy::GetUtilityFn(const FECContext& context, string& utility_def)
{
  if (context.util_fn_defn() != "")
  {
    LogD(cn, __func__, "context: %s\n",  context.util_fn_defn().c_str());
    utility_def = context.util_fn_defn();
  }
  else if (default_utility_def_ != "")
  {
    utility_def = default_utility_def_;
  }
  else
  {
    return false;
  }

  return true;
}

//============================================================================
void UdpProxy::StragglerCleanupTimeout(Time& now)
{
  struct timeval                                        now_tv = now.ToTval();
  iron::MashTable<FourTuple, EncodingState*>::WalkState es_ws;
  EncodingState*                                        state = NULL;

  while (encoding.GetNextItem(es_ws, state))
  {
    if (state->UpdateFEC(&now_tv))
    {
      // If we were able to generate the FEC packets, send them out.
      state->SendFecPackets();
    }
  }

  // Schedule the next straggler cleanup event.
  straggler_cleanup_time_ = now + Time::FromMsec(kPPIntervalMsec);
}

//============================================================================
void UdpProxy::GarbageCollectionTimeout(Time& now)
{
  // Run the garbage collector.
  LogD(cn, __func__, "Running garbage collector...\n");

  // Garbage collect EncodingStates.
  iron::MashTable<FourTuple, EncodingState*>::WalkState es_walk_state;
  EncodingState*                                        es            = NULL;
  EncodingState*                                        es_to_delete  = NULL;
  FourTuple                                             four_tuple;
  FourTuple                                             to_delete;
  bool                                                  to_delete_set = false;

  while (encoding.GetNextItem(es_walk_state, es))
  {
    // We can't delete the item we're currently looking at, since that will
    // mess up the iterator. Instead, we wait until the iterator has moved on
    // and then delete it.
    if (to_delete_set && encoding.FindAndRemove(to_delete, es_to_delete))
    {
      delete es_to_delete;
      es_to_delete = NULL;
      to_delete_set = false;
    }
    four_tuple  = es->four_tuple();
    if (Time::FromSec(es->last_time()) < (now - Time::FromSec(es->timeout())))
    {
      LogD(cn, __func__, "Deleting encoding state: %s\n",
           four_tuple.ToString().c_str());
      // The EncodingState is to be removed. Perform the following steps:
      //
      // 1. Cancel any timers associated with the EncodingState tag
      // 2. Remove the entry(ies) in the bin_states_map_ map for all bins
      // 3. Add it's four-tuple to the garbage collected flows list.
      // 4. Remove the entry from the encoding map
      // 5. Delete the Encoding State
      map<BinIndex, set<EncodingState*> >::iterator  bin_iter;

      bin_iter = bin_states_map_.find(es->bin_idx());
      if (bin_iter != bin_states_map_.end())
      {
        bin_iter->second.erase(es);
      }
      garbage_collected_flows_.Push(four_tuple);
      // Save this encoding state so we can delete it once the iterator moves
      // on.
      to_delete = four_tuple;
      to_delete_set = true;
    }
  }
  // Delete the last item in the list, now that we're done iterating.
  if (to_delete_set && encoding.FindAndRemove(to_delete, es_to_delete))
  {
    delete es_to_delete;
    es_to_delete = NULL;
    to_delete_set = false;
  }

  // Garbage collect DecodingStates.
  iron::MashTable<FourTuple, DecodingState*>::WalkState ds_walk_state;
  DecodingState*                                        ds           = NULL;
  DecodingState*                                        ds_to_delete = NULL;
  to_delete_set                                                      = false;

  while (decoding.GetNextItem(ds_walk_state, ds))
  {
    // As with encoding states, we delete each item after the iterator has
    // moved on.
    if (to_delete_set && decoding.FindAndRemove(to_delete, ds_to_delete))
    {
      delete ds_to_delete;
      ds_to_delete = NULL;
      to_delete_set = false;
    }
    four_tuple  = ds->four_tuple();
    if (Time::FromSec(ds->lastTime()) <
        (now - Time::FromSec(decoder_timeout_sec_)))
    {
      // The DecodingState is to be removed.
      // Store the four tuple so that next iteration (once the iterator
      // moves on) we can remove the entry from the decoding map and delete
      // the Decoding State.
      to_delete = four_tuple;
      to_delete_set = true;

      Ipv4Address  src_addr(four_tuple.src_addr_nbo());
      BinIndex     src_bin_idx =
        bin_map_shm_.GetDstBinIndexFromAddress(src_addr);

      if (src_bin_idx == iron::kInvalidBinIndex)
      {
        LogE(cn, __func__, "Failed to compute bin index for address %s "
             "(four tuple %s).\n", src_addr.ToString().c_str(),
             four_tuple.ToString().c_str());
        continue;
      }
      else
      {
        ReleaseRecord*  release_record = NULL;
        if (release_records_[src_bin_idx].FindAndRemove(
              four_tuple, release_record))
        {
          if (release_record)
          {
            LogD(cn, __func__, "Removed release record from source bin %s.\n",
                 bin_map_shm_.GetIdToLog(src_bin_idx).c_str());
            delete release_record;
            release_record  = NULL;
          }
          else
          {
            LogE(cn, __func__, "Did not find ReleaseRecord for flow %s.\n",
                 four_tuple.ToString().c_str());
          }
        }
      }
    }
  }
  // Delete the last item in the list, now that we're done iterating.
  if (to_delete_set && decoding.FindAndRemove(to_delete, ds_to_delete))
  {
    delete ds_to_delete;
    ds_to_delete = NULL;
    to_delete_set = false;
  }

  // Schedule the next garbage collection event time.
  garbage_collection_time_ = now + Time::FromSec(gc_interval_sec_);
}

//============================================================================
uint32_t UdpProxy::flow_tag()
{
  if (++flow_tag_ == 0)
  {
    LogW(cn, __func__, "Flow tag has looped.\n");
  }
  return flow_tag_;
}

//============================================================================
bool UdpProxy::ParseNormAddrRangeString(const string& nar_str)
{
  // The format to parse is:
  //  LOW_IP->HIGH_IP

  // Start by tokeninzing on the required "->" characters.
  List<string> tokens;
  StringUtils::Tokenize(nar_str, "->", tokens);

  if (tokens.size() != 2)
  {
    return false;
  }

  string  lo_addr_str;
  tokens.Pop(lo_addr_str);
  string  hi_addr_str;
  tokens.Pop(hi_addr_str);

  norm_low_addr_  = lo_addr_str;
  norm_high_addr_ = hi_addr_str;

  if (!norm_low_addr_.IsMulticast())
  {
    LogE(cn, __func__, "Configured NORM low address %s is not a multicast "
         "address.\n", lo_addr_str.c_str());
    return false;
  }

  if (!norm_high_addr_.IsMulticast())
  {
    LogE(cn, __func__, "Configured NORM high address %s is not a multicast "
         "address.\n", hi_addr_str.c_str());
    return false;
  }

  return true;
}

//============================================================================
void DumpFECTrailers(Packet* qpkt)
{
  unsigned int   qlen;
  unsigned int   UNUSED(oqlen);
  unsigned char *qptr;
  unsigned char *qdata;

  FECControlTrailer fecConTrlr;
  FECRepairTrailer  fecRepTrlr;
  FECChunkTrailer   fecChkTrlr;


  // Get the packet payload length and a pointer to the payload area
  qptr  = qpkt->GetBuffer();
  qdata = qptr + qpkt->GetIpPayloadOffset();
  qlen  = qpkt->GetLengthInBytes() - (qdata - qptr);
  oqlen = qlen;

  // Grab the FEC control trailer
  if (qlen < sizeof(FECControlTrailer))
  {
    LogD(cn, __func__, "Packet length of %u is too short: missing FEC "
         "control trailer", oqlen);
    return;
  }

  memcpy(&fecConTrlr, &qdata[qlen - sizeof(FECControlTrailer)],
         sizeof(FECControlTrailer));

  qlen -= sizeof(FECControlTrailer);

  // Grab the FEC repair trailer if this is a repair packet
  if (fecConTrlr.type == FEC_REPAIR)
  {
    if (qlen < sizeof(FECRepairTrailer))
    {
      LogD(cn, __func__, "Packet length of %u is too short: missing FEC "
           "repair trailer", oqlen);
      return;
    }

    memcpy(&fecRepTrlr,
        &qdata[qlen - sizeof(FECRepairTrailer)],
        sizeof(FECRepairTrailer));
    qlen -= sizeof(FECRepairTrailer);
  }

  // Grab the FEC chunk trailer
  if (qlen < sizeof(FECChunkTrailer))
  {
    LogD(cn, __func__, "Packet length of %u is too short: missing FEC chunk "
         "trailer", oqlen);
    return;
  }

  memcpy(&fecChkTrlr, &qdata[qlen - sizeof(FECChunkTrailer)],
         sizeof(FECChunkTrailer));

  // Print out the various trailer information depending on packet type
  if (fecConTrlr.type == FEC_REPAIR)
  {
    LogD(cn, __func__, "type=%u inOrder=%u slotID=%u groupID=%u baseRate=%u "
         "fecRate=%u\n", fecConTrlr.type, fecConTrlr.in_order,
         fecConTrlr.slot_id, fecConTrlr.group_id, fecRepTrlr.base_rate,
         fecRepTrlr.fec_rate);
  }
  else
  {
    LogD(cn, __func__, "type=%u inOrder=%u slotID=%u groupID=%u chunkID=%u "
         "nChunks=%u pktID=%u\n", fecConTrlr.type, fecConTrlr.in_order,
         fecConTrlr.slot_id, fecConTrlr.group_id, fecChkTrlr.chunk_id,
         fecChkTrlr.n_chunks, fecChkTrlr.pkt_id);
  }
}
