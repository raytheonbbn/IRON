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

/// \file zlr.cc, provides an implementation of the class for the zombie
/// latency reduction algorithm.

#include "zlr.h"

#include "iron_types.h"
#include "log.h"
#include "packet.h"
#include "bin_queue_mgr.h"
#include "unused.h"
#include "zombie.h"

#include <inttypes.h>
#include <sstream>

using ::iron::ConfigInfo;
using ::iron::LatencyClass;
using ::iron::Log;
using ::iron::QueueDepthDynamics;
using ::iron::BinQueueMgr;
using ::iron::Time;
using ::iron::ZLR;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName)            = "ZLR";

  /// Set to true to graph the values of the ZLR dynamic observation window
  /// over time.
  const bool     kGraphZLRWindows               = false;

  /// The initial value for min_bytes_reset_period_, which is the length of
  /// time we look into the past when examining the queue depth to determine
  /// how many zombie packets we should maintain.
  ///
  /// If dynamic floor estimation is disabled, this value will be used the
  /// entire time.
  const double    kDefaultDynamicWindowInitialSecs = 1.0;

  /// If true, this will dynamically adjust the minimum bytes time window
  /// (i.e., how long over the history of the queue depth we look to determine
  /// the number of zombies that can safely be added). In that case, the
  /// window for the minimum queue depth is increased (we look at the queue
  /// depth over a longer period of time) when zombies are being sent, so we
  /// are less likely to add zombies in the case of queue depth spikes. The
  /// window is decreased when we haven't sent zombies in a while, so we will
  /// more quickly change the number of zombies in reaction to network pattern
  /// changes.
  ///
  /// If false, the min queue depth window will remain constant at the
  /// initially configured value.
  const bool      kDefaultZLRDynamicWindow      = true;

  /// The lower bound for the dynamic min_bytes_reset_period_, which is the
  /// length of time we look into the past when examining the queue depth to
  /// determine how many zombie packets we should maintain.
  ///
  /// Increasing this value will allow us to handle longer spikes and dips in
  /// queue depth. Decreasing it will allow us to react faster to network
  /// events.
  ///
  /// If dynamic floor estimation is disabled, this value will be ignored.
  const double    kDefaultDynamicWindowLowerBoundSecs = 0.2;

  /// The upper bound for the dynamic min_bytes_reset_period_, which is the
  /// length of time we look into the past when examining the queue depth to
  /// determine how many zombie packets we should maintain.
  ///
  /// Increasing this value will allow us to handle longer spikes and dips in
  /// queue depth. Decreasing it will allow us to react faster to network
  /// events.
  ///
  /// If dynamic floor estimation is disabled, this value will be ignored.
  const double    kDefaultDynamicWindowUpperBoundSecs = 5.0;

  /// If true, we will add latency sensitive zombie packets when the latency
  /// sensitive queue is long to reduce the latency-sensitive-specific
  /// latency. If false, we revert back to whether standard zombie latency
  /// reduction is enabled (and may add normal zombie packets if the latency
  /// sensitive queue is too long, but won't add latency sensitive zombies).
  const bool      kLSZombieLatencyReduction     = true;

  /// Default value of the ZLR high water mark. If there are more non-zombie
  /// bytes in the queue than this over an entire ZLR window, then we will add
  /// zombies to reduce the queue delay. Increasing this will increase the
  /// latency. Decreasing this could lead to queues with no non-zombie packets,
  /// which would hurt goodput.
  const uint32_t  kZLRHighWaterMarkBytes        = 6000;

  /// Default value of the ZLR low water mark. If there are fewer than this
  /// many non-zombie bytes in the queue, we will start to increase the ZLR
  /// minimum queue depth window (which will make us less likely to add more
  /// zombies).
  const uint32_t  kZLRLowWaterMarkBytes         = 2000;

  /// Default for queue change rate below which we should NOT add zombie
  /// packets. That is, if the queue depth for a bin is changing at a rate
  /// less than this (if this is negative, that would mean dequeues are
  /// happening faster than enqueues), then we will not replace dequeued
  /// packets with zombies.
  const int16_t   kDefaultZLRQChangeMinThreshBytesPerS = -2000;

  /// Default for whether to follow the fast recovery algorithm, which
  /// attempts to differentiate quick queue depth blips from longer term
  /// stable state changes, allowing us to quickly re-grow zombies after a
  /// temporary dip.
  const bool      kFastRecovery                 = false;

  /// When the non-zombie depth is at least this high after a queue depth dip
  /// (in steady-state mode), we enter fast recovery.
  const uint32_t  kFastRecoveryStartThreshBytes = 10000;

  /// If this many bytes are dequeued within kFastRecoveryDipThreshTime, then
  /// we'll change to a "dip" fast recovery state. (Or if this is the second
  /// dip in a row, we'll switch to "oscillatory" state.)
  const uint32_t  kFastRecoveryDipThreshBytes   = 40000;

  /// If kFastRecoveryDipBytes bytes are dequeued within this time, then
  /// we'll change to a "dip" fast recovery state. (Or if this is the second
  /// dip in a row, we'll switch to "oscillatory" state.)
  const Time      kFastRecoveryDipThreshTime    = Time(0.5);

  /// If we've gone this long with no new queue depth dips, we re-enter
  /// steady-state and thus use fast recovery after the next observed dip.
  const Time      kFastRecoveryResetTime        = Time(3.0);

  /// Whether or not to note fast recovery state changes on the queue depths
  /// graphs.
  const bool      kGraphZLRFastRecovery         = false;

  /// \brief Size of ZLR_DECISION_TTYPES
  const uint8_t kNumZlrDecisionTtypes = 1;

  /// \brief Which latency classes are considered part of the real packet
  /// queue when making ZLR decisions
  ///
  /// This does NOT include LS packets or LS zombie packets at the moment, so
  /// ZLR Is acting on normal latency packets only. This means we will always
  /// keep a base floor of a small number of normal latency packets, even if
  /// there is a deep queue of LS packets as well.
  const LatencyClass ZLR_DECISION_TTYPES[kNumZlrDecisionTtypes] =
  {
    // Include the next line if we want to count LS packets towards the
    // minimum number of "real" packets in the queue before adding zombies.
    //iron::CRITICAL_LATENCY, iron::CONTROL_TRAFFIC_LATENCY, iron::LOW_LATENCY,
    // Include the next lines if we want to count LS Zombie packets towards
    // the minimum number of "real" packets in the queue before adding
    // zombies.
    //iron::HIGH_LATENCY_EXP, iron::HIGH_LATENCY_NPLB_LS,
    //iron::HIGH_LATENCY_ZLR_LS,
    iron::NORMAL_LATENCY
  };

  /// \brief Size of ZLR_LS_DECISION_TTYPES
  const uint8_t kNumZlrLsDecisionTtypes = 3;

  /// \brief Which latency classes are considered part of the real packet
  /// queue when making LS ZLR decisions
  const LatencyClass ZLR_LS_DECISION_TTYPES[kNumZlrLsDecisionTtypes] =
  {
    iron::CRITICAL_LATENCY,
    iron::CONTROL_TRAFFIC_LATENCY,
    iron::LOW_LATENCY
  };

  /// \brief Size of ZLR_ZOMBIE_TTYPES
  const uint8_t kNumZlrZombieTtypes = 3;

  /// \brief Which latency classes are considered zombies for ZLR
  /// computations.
  ///
  /// This does NOT include LS zombies at the moment, because non-zombie ZLR
  /// does not count LS packets as part of the queue for decision purposes.
  const LatencyClass ZLR_ZOMBIE_TTYPES[kNumZlrZombieTtypes] =
  {
    // Include the next lines if we are counting LS packets towards the minimum
    // number of "real" packets in the queue before adding zombies.
    //iron::HIGH_LATENCY_EXP, iron::HIGH_LATENCY_NPLB_LS,
    //iron::HIGH_LATENCY_ZLR_LS
    iron::HIGH_LATENCY_RCVD,
    iron::HIGH_LATENCY_NPLB,
    iron::HIGH_LATENCY_ZLR
  };

  /// \brief Size of ZLR_LS_ZOMBIE_TTYPES
  const uint8_t kNumZlrLsZombieTtypes = 3;

  /// \brief Which latency classes are considered zombies for LS ZLR
  /// computations.
  const LatencyClass ZLR_LS_ZOMBIE_TTYPES[kNumZlrLsZombieTtypes] =
  {
    iron::HIGH_LATENCY_EXP,
    iron::HIGH_LATENCY_NPLB_LS,
    iron::HIGH_LATENCY_ZLR_LS
  };
}

//============================================================================
ZLR::ZLR(PacketPool& packet_pool, BinMap& bin_map, BinQueueMgr& q_mgr,
         BinIndex bin_index)
    : packet_pool_(packet_pool),
      bin_map_(bin_map),
      q_mgr_(q_mgr),
      my_bin_index_(bin_index),
      is_multicast_(bin_map_.IsMcastBinIndex(bin_index)),
      do_ls_zombie_latency_reduction_(kLSZombieLatencyReduction),
      zlr_high_water_mark_bytes_(kZLRHighWaterMarkBytes),
      zlr_low_water_mark_bytes_(kZLRLowWaterMarkBytes),
      zlr_q_change_min_thresh_bytes_per_s_(
        kDefaultZLRQChangeMinThreshBytesPerS),
      zlr_queue_depth_dynamics_(),
      zlr_ls_queue_depth_dynamics_(),
      fast_recovery_(),
      ls_fast_recovery_(),
      is_zlr_decision_ttype_(),
      is_zlr_ls_decision_ttype_(),
      is_zlr_zombie_ttype_(),
      is_zlr_ls_zombie_ttype_(),
      zlr_xplot_(),
      qd_xplot_()
{
  // Set up boolean versions of the ttype maps.
  memset(is_zlr_decision_ttype_, 0, sizeof(is_zlr_decision_ttype_));
  for (uint8_t idx = 0; idx < kNumZlrDecisionTtypes; ++idx)
  {
    is_zlr_decision_ttype_[ZLR_DECISION_TTYPES[idx]] = true;
  }
  memset(is_zlr_ls_decision_ttype_, 0, sizeof(is_zlr_ls_decision_ttype_));
  for (uint8_t idx = 0; idx < kNumZlrLsDecisionTtypes; ++idx)
  {
    is_zlr_ls_decision_ttype_[ZLR_LS_DECISION_TTYPES[idx]] = true;
  }
  memset(is_zlr_zombie_ttype_, 0, sizeof(is_zlr_zombie_ttype_));
  for (uint8_t idx = 0; idx < kNumZlrZombieTtypes; ++idx)
  {
    is_zlr_zombie_ttype_[ZLR_ZOMBIE_TTYPES[idx]] = true;
  }
  memset(is_zlr_ls_zombie_ttype_, 0, sizeof(is_zlr_ls_zombie_ttype_));
  for (uint8_t idx = 0; idx < kNumZlrLsZombieTtypes; ++idx)
  {
    is_zlr_ls_zombie_ttype_[ZLR_LS_ZOMBIE_TTYPES[idx]] = true;
  }
}

//============================================================================
ZLR::~ZLR()
{
  BinIndex  bin_idx = kInvalidBinIndex;

  for (bool bin_idx_valid = bin_map_.GetFirstBinIndex(bin_idx);
       bin_idx_valid;
       bin_idx_valid = bin_map_.GetNextBinIndex(bin_idx))
  {
    if (zlr_xplot_.IsInitialized())
    {
      if (zlr_xplot_[bin_idx])
      {
        delete zlr_xplot_[bin_idx];
        zlr_xplot_[bin_idx] = NULL;
      }
    }

    if (qd_xplot_.IsInitialized())
    {
      if (qd_xplot_[bin_idx])
      {
        delete qd_xplot_[bin_idx];
        qd_xplot_[bin_idx] = NULL;
      }
    }
  }
}

//============================================================================
void ZLR::Initialize(const ConfigInfo& config_info)
{
  LogI(kClassName, __func__, "Configuring ZLR for bin %s\n",
       bin_map_.GetIdToLog(my_bin_index_).c_str());

  do_ls_zombie_latency_reduction_ = config_info.GetBool(
    "Bpf.LSZombieLatencyReduction", kLSZombieLatencyReduction);

  zlr_high_water_mark_bytes_ = config_info.GetUint(
    "Bpf.ZLR.HighWaterMarkBytes",
    kZLRHighWaterMarkBytes);

  zlr_low_water_mark_bytes_ = config_info.GetUint(
    "Bpf.ZLR.LowWaterMarkBytes",
    kZLRLowWaterMarkBytes);

  if (zlr_low_water_mark_bytes_ > zlr_high_water_mark_bytes_)
  {
    LogW(kClassName, __func__, "Bpf.ZLR.HighWaterMarkBytes (%" PRIu32
         ") is less than Bpf.ZLR.LowWaterMarkBytes (%" PRIu32
         "), which is safe but unusual.\n", zlr_high_water_mark_bytes_,
         zlr_low_water_mark_bytes_);
  }

  zlr_q_change_min_thresh_bytes_per_s_ = config_info.GetInt(
    "Bpf.ZLR.QChangeMinThreshBytesPerS",
    kDefaultZLRQChangeMinThreshBytesPerS);

  bool dynamic_window = config_info.GetBool(
    "Bpf.ZLR.DynamicWindow", kDefaultZLRDynamicWindow);

  double initial_window = config_info.GetFloat(
    "Bpf.ZLR.DynamicWindowInitialSecs",
    kDefaultDynamicWindowInitialSecs);

  double lower_bound_window = config_info.GetFloat(
    "Bpf.ZLR.DynamicWindowLowerBoundSecs",
    kDefaultDynamicWindowLowerBoundSecs);

  double upper_bound_window = config_info.GetFloat(
    "Bpf.ZLR.DynamicWindowUpperBoundSecs",
    kDefaultDynamicWindowUpperBoundSecs);

  if (!zlr_queue_depth_dynamics_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize ZLR queue depth "
         "dynamics array.\n");
    return;
  }

  if (!zlr_ls_queue_depth_dynamics_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize ZLR latency-sensitive "
         "queue depth dynamics array.\n");
    return;
  }

  BinIndex  binidx = 0;

  for (bool valid = bin_map_.GetFirstUcastBinIndex(binidx);
       valid;
       valid = bin_map_.GetNextUcastBinIndex(binidx))
  {
    zlr_queue_depth_dynamics_[binidx].Initialize(
      dynamic_window, initial_window,
      lower_bound_window, upper_bound_window);
    zlr_ls_queue_depth_dynamics_[binidx].Initialize(
      dynamic_window, initial_window,
      lower_bound_window, upper_bound_window);
  }

  if (!fast_recovery_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize fast recovery array.\n");
    return;
  }

  if (!ls_fast_recovery_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize latency-sensitive fast "
         "recovery array.\n");
    return;
  }

  if (!zlr_xplot_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize ZLR plotting array.\n");
    return;
  }
  zlr_xplot_.Clear(NULL);

  if (!qd_xplot_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize queue depth plotting "
         "array.\n");
    return;
  }
  qd_xplot_.Clear(NULL);

#ifdef XPLOT
  bool do_xplot =
    config_info.GetBool("Bpf.GenerateQueueDepthsGraphs", false);
  if (do_xplot && kGraphZLRWindows)
  {
    if (bin_map_.IsMulticastByBinIndex(my_bin_index_))
    {
      DstVec    my_dst_vec = bin_map_.GetMcastDst(my_bin_index_);
      BinIndex  bin_idx    = 0;

      for (bool valid = bin_map_.GetFirstUcastBinIndex(bin_idx);
           valid;
           valid = bin_map_.GetNextUcastBinIndex(bin_idx))
      {
        if (bin_map_.IsBinInDstVec(my_dst_vec, bin_idx))
        {
          SetUpZLRXplot(bin_idx);
        }
      }
    }
    else
    {
      SetUpZLRXplot(my_bin_index_);
    }
  }
#endif // XPLOT

  // Log the configuration information.
  LogC(kClassName, __func__, "ZLR configuration %s:\n",
       bin_map_.GetIdToLog(my_bin_index_).c_str());
  LogC(kClassName, __func__, "LS Zombie latency reduction   : %s\n",
       (do_ls_zombie_latency_reduction_ ? "On" : "Off"));
  LogC(kClassName, __func__, "ZLR queue change rate thresh  : %" PRId16
       " Bytes per sec\n", zlr_q_change_min_thresh_bytes_per_s_);
  LogC(kClassName, __func__, "ZLR High Water Mark        :  : %" PRIu32
       " Bytes\n", zlr_high_water_mark_bytes_);
  LogC(kClassName, __func__, "ZLR Low Water Mark            : %" PRIu32
       " Bytes\n", zlr_low_water_mark_bytes_);
  LogC(kClassName, __func__, "Dynamic Window                : %s\n",
       (dynamic_window ? "On" : "Off"));
  if (dynamic_window)
  {
    LogC(kClassName, __func__, "Min Bytes Initial Window      : %f s\n",
         initial_window);
    LogC(kClassName, __func__, "Min Bytes Window Lower Bound  : %f s\n",
         lower_bound_window);
    LogC(kClassName, __func__, "Min Bytes Window Upper Bound  : %f s\n",
         upper_bound_window);
  }
  else
  {
    LogC(kClassName, __func__, "Min Bytes Window              : %f s\n",
         initial_window);
  }
}

//============================================================================
void ZLR::SetUpZLRXplot(BinIndex bin_idx)
{
  zlr_xplot_[bin_idx] = new (std::nothrow) iron::GenXplot();
  if (!zlr_xplot_[bin_idx])
  {
    // log and go on. We just won't generate the graph.
    LogE(kClassName, __func__,
         "Unable to allocate ZLR GenXplot for bin index %" PRIBinIndex ".\n",
         bin_idx);
  }
  else
  {
    std::stringstream title;
    std::stringstream graphname;
    if (bin_map_.IsMcastBinIndex(my_bin_index_))
    {
      title << "zlr_" << bin_map_.GetIdToLog(my_bin_index_)
            << "_" << bin_map_.GetIdToLog(bin_idx) << ".xplot";
      graphname << "ZLR values for group "
                << bin_map_.GetMcastId(my_bin_index_) << ", bin "
                << static_cast<uint16_t>(bin_map_.GetPhyBinId(bin_idx));
    }
    else
    {
      title << "zlr_" << bin_map_.GetIdToLog(bin_idx) << ".xplot";
      graphname << "ZLR values for bin "
                << static_cast<uint16_t>(bin_map_.GetPhyBinId(bin_idx));
    }
    if (!zlr_xplot_[bin_idx]->Initialize(
          title.str(), graphname.str(), true))
    {
      delete zlr_xplot_[bin_idx];
      zlr_xplot_[bin_idx] = NULL;
    }
    else
    {
      LogC(kClassName, __func__,
           "Set up ZLR xplot graph for group %s, dst %s. Filename %s.\n",
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           bin_map_.GetIdToLog(bin_idx).c_str(),
           title.str().c_str());
      for (uint8_t it = 0; it < NUM_LATENCY_DEF; ++it)
      {
        zlr_xplot_[bin_idx]->AddLineToKey(RED, "Window");
        zlr_xplot_[bin_idx]->AddLineToKey(GREEN, "LS Window");
      }
    }
  }
}

//============================================================================
void ZLR::DoZLREnqueueProcessing(
  uint16_t bytes, LatencyClass lat, DstVec dsts)
{
  if (is_multicast_)
  {
    BinIndex  dst_bidx = 0;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dsts, dst_bidx))
      {
        DoPerBinEnqueueProcessing(bytes, lat, dst_bidx);
      }
    }
  }
  else
  {
    DoPerBinEnqueueProcessing(bytes, lat, my_bin_index_);
  }
}

//============================================================================
void ZLR::DoPerBinEnqueueProcessing(
  uint16_t bytes, LatencyClass lat, BinIndex bin_index)
{
  // When a packet is enqueued, we need to track it with the appropriate queue
  // depth dynamics object(s). Whether or not (and how) this class counts
  // towards each of the two QueueDepthDynamics (normal ZLR or LS-ZLR) is
  // determined using the ZLR_*_TTYPES constants. The queue depth dynamics
  // objects are responsible for tracking the minimum queue depth over the
  // window (of non-zombies only), the general queue depth change direction
  // (increasing or decreasing, including zombies), and how many zombies we've
  // already added towards the window. Any of these may change because of an
  // enqueue'd packet.
  if (do_ls_zombie_latency_reduction_ &&
      (is_zlr_ls_decision_ttype_[lat] || is_zlr_ls_zombie_ttype_[lat]))
  {
    uint32_t zlr_depth_bytes  = q_mgr_.GetTtypeDepthBytes(bin_index,
      ZLR_LS_DECISION_TTYPES, kNumZlrLsDecisionTtypes);
    if (kFastRecovery)
    {
      UpdateFastRecoveryStateOnEnqueue(bin_index, true, zlr_depth_bytes);
    }

    // This latency class counts towards LS-ZLR. Consider it in the LS
    // dynamics. We want to call this function for both LS zombies and LS
    // packets, since both are counted towards the change rate. However, we
    // only want to use the non-zombie packets in the "new depth" passed
    // in, since that is used to compute the min non-zombie depth over the ZLR
    // observation window.
    zlr_ls_queue_depth_dynamics_[bin_index].ProcessBytesAdded(
      bytes, lat, zlr_depth_bytes);
  }
  // NOTE: this is not an else, because some packets count towards both LS ZLR
  // and normal ZLR.
  if (is_zlr_decision_ttype_[lat] || is_zlr_zombie_ttype_[lat])
  {
    uint32_t zlr_depth_bytes  = q_mgr_.GetTtypeDepthBytes(bin_index,
      ZLR_DECISION_TTYPES, kNumZlrDecisionTtypes);
    if (kFastRecovery)
    {
      UpdateFastRecoveryStateOnEnqueue(bin_index, false, zlr_depth_bytes);
    }

    // This latency class counts towards normal ZLR. Consider it in the normal
    // dynamics. We want to call this function for both zombies and non-zombie
    // packets, since both are counted towards the change rate. However, we
    // only want to use the non-zombie packets in the "new depth" passed
    // in, since that is used to compute the min non-zombie depth over the ZLR
    // observation window.
    zlr_queue_depth_dynamics_[bin_index].ProcessBytesAdded(
      bytes, lat, zlr_depth_bytes);
  }
  if (do_ls_zombie_latency_reduction_ && is_zlr_ls_zombie_ttype_[lat])
  {
    // This latency class counts against the LS ZLR queue depth floor.
    zlr_ls_queue_depth_dynamics_[bin_index].ProcessZombieBytesAdded(bytes,
                                                                    lat);
  }
  if (is_zlr_zombie_ttype_[lat])
  {
    // This latency class counts against the normal ZLR queue depth floor.
    zlr_queue_depth_dynamics_[bin_index].ProcessZombieBytesAdded(bytes, lat);
  }
}

//============================================================================
void ZLR::UpdateFastRecoveryStateOnEnqueue(
  BinIndex bin_idx, bool process_ls, uint32_t zlr_depth_bytes)
{
  FastRecoveryData*   data     = &(fast_recovery_[bin_idx]);
  QueueDepthDynamics* dynamics = &(zlr_queue_depth_dynamics_[bin_idx]);

  if (process_ls)
  {
    data     = &(ls_fast_recovery_[bin_idx]);
    dynamics = &(zlr_ls_queue_depth_dynamics_[bin_idx]);
  }

  if (dynamics->GetChangeRateBytesPerSec() >
      zlr_q_change_min_thresh_bytes_per_s_)
  {
    data->deq_bytes = 0;
  }
  if (data->fast_recovery_state == QUEUE_DEPTH_DIP)
  {
    if (zlr_depth_bytes > kFastRecoveryStartThreshBytes)
    {
      data->fast_recovery_state = RECOVERY;
      if (kGraphZLRFastRecovery && qd_xplot_[bin_idx] != NULL)
      {
        qd_xplot_[bin_idx]->DrawVerticalLine(
          Time::Now().GetTimeInUsec() - iron::kStartTime,
          ORANGE);
      }
      LogI(kClassName, __func__, "Bin %s, %s"
           "Entering FastRecoveryState RECOVERY: zlr_depth_bytes = %"
           PRIu32 "\n", bin_map_.GetIdToLog(bin_idx).c_str(),
           (process_ls ? "LS, " : ""), zlr_depth_bytes);
    }
  }
}

//============================================================================
void ZLR::DoZLRDequeueProcessing(const DequeuedInfo& dq_info)
{
  if (is_multicast_)
  {
    DstVec    dsts     = dq_info.dst_vec;
    BinIndex  dst_bidx = 0;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dsts, dst_bidx))
      {
        DoPerBinDequeueProcessing(dq_info, dst_bidx);
      }
    }
  }
  else
  {
    DoPerBinDequeueProcessing(dq_info, my_bin_index_);
  }
}

//============================================================================
void ZLR::DoPerBinDequeueProcessing(
  const DequeuedInfo& dq_info, BinIndex bin_index)
{
  // When a packet is dequeued, we need to track it with the appropriate queue
  // depth dynamics object(s). Whether or not (and how) this class counts
  // towards each of the two QueueDepthDynamics (normal ZLR or LS-ZLR) is
  // determined using the ZLR_*_TTYPES constants. The queue depth dynamics
  // objects need to know about a dequeue to maintain the minimum non-zombie
  // queue depth over the window as well as the general queue depth change
  // direction (increasing or decreasing, including zombies). We will include
  // zombies in BytesRemoved calls for the sake of updating the change rate,
  // but not in the ZLR_*_TTYPES constant passed in for updating min depth.
  if (do_ls_zombie_latency_reduction_ &&
      (is_zlr_ls_decision_ttype_[dq_info.lat] ||
       is_zlr_ls_zombie_ttype_[dq_info.lat]))
  {
    // This latency class counts towards LS-ZLR. Consider it in the LS
    // dynamics. We want to call this function for both zombies and non-zombie
    // packets, since both are counted towards the change rate. However, we
    // only want to use the non-zombie packets in the "new depth" passed
    // in, since that is used to compute the min non-zombie depth over the ZLR
    // observation window.
    uint32_t zlr_depth_bytes  = q_mgr_.GetTtypeDepthBytes(bin_index,
      ZLR_LS_DECISION_TTYPES, kNumZlrLsDecisionTtypes);
    if (kFastRecovery)
    {
      UpdateFastRecoveryStateOnDequeue(
        dq_info, bin_index, true, zlr_depth_bytes);
    }

    zlr_ls_queue_depth_dynamics_[bin_index].BytesRemoved(
      dq_info.dequeued_size, dq_info.lat, zlr_depth_bytes);
  }
  // NOTE: this is not an else, because some packets count towards both LS ZLR
  // and normal ZLR.
  if (is_zlr_decision_ttype_[dq_info.lat] ||
      is_zlr_zombie_ttype_[dq_info.lat])
  {
    // This latency class counts towards normal ZLR. Consider it in the normal
    // dynamics. We want to call this function for both zombies and non-zombie
    // packets, since both are counted towards the change rate. However, we
    // only want to use the non-zombie packets in the "new depth" passed
    // in, since that is used to compute the min non-zombie depth over the ZLR
    // observation window.
    uint32_t zlr_depth_bytes  = q_mgr_.GetTtypeDepthBytes(bin_index,
      ZLR_DECISION_TTYPES, kNumZlrDecisionTtypes);
    if (kFastRecovery)
    {
      UpdateFastRecoveryStateOnDequeue(
        dq_info, bin_index, false, zlr_depth_bytes);
    }
    zlr_queue_depth_dynamics_[bin_index].BytesRemoved(
      dq_info.dequeued_size, dq_info.lat, zlr_depth_bytes);
  }
  if (dq_info.is_ip)
  {
    // Perform ZLR zombie addition algorithm.
    DoZombieLatencyReduction(dq_info, bin_index);
  }
}

//============================================================================
void ZLR::UpdateFastRecoveryStateOnDequeue(const DequeuedInfo& dq_info,
  BinIndex bin_idx, bool process_ls, uint32_t zlr_depth_bytes)
{
  //
  // This function has two goals:
  // 1. Update the Fast Recovery state if necessary (see state machine drawing
  // in zlr.h).
  // 2. Update the dynamic observation window size if necessary.
  //
  FastRecoveryData*   data     = &(fast_recovery_[bin_idx]);
  QueueDepthDynamics* dynamics = &(zlr_queue_depth_dynamics_[bin_idx]);

  // Number of zombies counted against this ZLR window. This will be used to
  // determine whether it's appropriate to increase the ZLR window, since we
  // don't want to increase it unless there's been some action on a queue that
  // counts. It will also be used to determine whether a fast recovery is
  // complete.
  uint32_t            zombie_depth_bytes = q_mgr_.GetTtypeDepthBytes(bin_idx,
    ZLR_ZOMBIE_TTYPES, kNumZlrZombieTtypes);

  if (process_ls)
  {
    // If we are responding to a dequeued LS packet, use the LS-ZLR data
    // structures and values instead.
    data               = &(ls_fast_recovery_[bin_idx]);
    dynamics           = &(zlr_ls_queue_depth_dynamics_[bin_idx]);
    zombie_depth_bytes = q_mgr_.GetTtypeDepthBytes(bin_idx,
      ZLR_LS_ZOMBIE_TTYPES, kNumZlrLsZombieTtypes);
  }

  Time now = Time::Now();

  // First see if it's time to reset the fast recovery state machine to
  // STEADY_STATE due to the "reset time" amount having passed since our last
  // state change.
  if (data->fast_recovery_state != STEADY_STATE &&
      (now - data->fast_recovery_start_time > kFastRecoveryResetTime))
  {
    data->fast_recovery_state = STEADY_STATE;
    if (!process_ls && kGraphZLRFastRecovery && qd_xplot_[bin_idx] != NULL)
    {
      qd_xplot_[bin_idx]->DrawVerticalLine(
        now.GetTimeInUsec() - iron::kStartTime,
        WHITE);
    }
    LogI(kClassName, __func__, "Bin %s, %s Entering "
         "FastRecoveryState STEADY_STATE: more than 3 seconds passed.\n",
         bin_map_.GetIdToLog(bin_idx).c_str(), (process_ls ? "LS, " : ""));
  }

  // If we're in steady state and this is the potential beginning of a queue
  // depth dip (our dequeue counter is 0), record the time that this dip (if
  // it turns out to be a dip) started and the number of zombies present at
  // the start of the potential dip. Add to the count of dequeued bytes. The
  // dequeued byte and dequeue start time values will be used to determine
  // whether this is a dip. The recovery zombie depth bytes will be used as
  // part of recovering should fast recovery kick in after this dip.
  if (data->deq_bytes == 0 && data->fast_recovery_state == STEADY_STATE)
  {
    data->deq_start_time.GetNow();
    data->recovery_zombie_depth_bytes = zombie_depth_bytes;
  }
  data->deq_bytes += dq_info.dequeued_size;

  // If we're dequeueing a zombie, that's a flag for considering whether we're
  // now in a dip state (fast recovery won't do anything if we haven't
  // dequeued any zombies, so no need to change the state unless/until we
  // dequeue a zombie). If we are in a dip (dequeue bytes is big enough over a
  // small enough dequeue time), then update the state machine accordingly. If
  // this was the first dip out of steady state, move to "QUEUE_DEPTH_DIP"
  // (from which we'll use fast recovery). If we're already recovering or
  // recovered from a dip, then a second (or later) dip before a reset means
  // we want to consider this oscillatory - i.e., no fast recovery and
  // increase the dynamic observation window.
  if (Packet::IsZombie(dq_info.lat))
  {
    if ((now - data->deq_start_time < kFastRecoveryDipThreshTime) &&
        (data->deq_bytes > kFastRecoveryDipThreshBytes))
    {
      if (data->fast_recovery_state == STEADY_STATE)
      {
        data->fast_recovery_state = QUEUE_DEPTH_DIP;
        data->fast_recovery_start_time.GetNow();
        if (!process_ls && kGraphZLRFastRecovery && qd_xplot_[bin_idx] != NULL)
        {
          qd_xplot_[bin_idx]->DrawVerticalLine(
            now.GetTimeInUsec() - iron::kStartTime,
            RED);
        }
        LogI(kClassName, __func__, "Bin %s, %s Entering "
             "FastRecoveryState QUEUE_DEPTH_DIP: deq_bytes = %" PRIu32
             ".\n", bin_map_.GetIdToLog(bin_idx).c_str(),
             (process_ls ? "LS, " : ""),
             data->deq_bytes);
      }
      else if (data->fast_recovery_state >= RECOVERY)
      {
        data->fast_recovery_state = OSCILLATORY;
        // As long as we keep seeing dips, extend the time before we'll
        // consider entering fast recovery again.
        data->fast_recovery_start_time.GetNow();
        LogI(kClassName, __func__, "Bin %s, %s Entering "
             "FastRecoveryState OSCILLATORY: deq_bytes = %" PRIu32
             ".\n", bin_map_.GetIdToLog(bin_idx).c_str(),
             (process_ls ? "LS, " : ""),
             data->deq_bytes);
        if (!process_ls && kGraphZLRFastRecovery && qd_xplot_[bin_idx] != NULL)
        {
          qd_xplot_[bin_idx]->DrawVerticalLine(
            now.GetTimeInUsec() - iron::kStartTime,
            GREEN);
        }
      }
    }
  }
  // If we're not in fast recovery mode, adjust the ZLR floor window. i.e.,
  // over how long into the past we should look for the sake of ignoring
  // queue depth spikes.
  //
  // If we dequeued a zombie packet or have few non-zombies left, then our
  // observation window is probably too small. If we haven't dequeued a
  // zombie in a while, then we can probe a smaller window.
  if ((data->fast_recovery_state == STEADY_STATE  ||
       data->fast_recovery_state == OSCILLATORY) &&
      (zombie_depth_bytes > 0) &&
      (Packet::IsZombie(dq_info.lat) ||
       (zlr_depth_bytes < zlr_low_water_mark_bytes_)))
  {
    // Note: rate regulation of window changes is done within
    // IncrementMinBytesResetPeriod.
    dynamics->IncrementMinBytesResetPeriod();
  }
  // Whenever we dequeue a non-zombie, check whether it's time to shrink the
  // obvservation window. Logic to determine whether it's time and by how much
  // to shrink the window is inside DecrementMinBytesResetPeriod.
  if (!Packet::IsZombie(dq_info.lat))
  {
    dynamics->DecrementMinBytesResetPeriod();

    if (data->fast_recovery_state == RECOVERY &&
        zombie_depth_bytes > data->recovery_zombie_depth_bytes)
    {
      LogI(kClassName, __func__, "Bin %s, %s Entering "
           "FastRecoveryState RECOVERED: zombie_depth_bytes = %" PRIu32
           ", recovery_zombie_depth_bytes = %" PRIu32 ".\n",
           bin_map_.GetIdToLog(bin_idx).c_str(), (process_ls ? "LS, " : ""),
           zombie_depth_bytes, data->recovery_zombie_depth_bytes);
      data->fast_recovery_state = RECOVERED;
      if (!process_ls && kGraphZLRFastRecovery && qd_xplot_[bin_idx] != NULL)
      {
        qd_xplot_[bin_idx]->DrawVerticalLine(
          now.GetTimeInUsec() - iron::kStartTime,
          YELLOW);
      }
    }
  }
}

//============================================================================
void ZLR::DoZombieLatencyReduction(
  const DequeuedInfo& dq_info, BinIndex bin_idx)
{
  // Function performs the heart of ZLR, where we determine whether or not to
  // add a zombie based on the queue depth state and dynamics. For more
  // documentation about the ZLR algorithm, see the \class level doxygen in
  // zlr.h.
  bool                is_ls            = do_ls_zombie_latency_reduction_ &&
    (Packet::IsLatencySensitive(dq_info.lat));
  // Which queue depth dynamics we should look at based on this packet to
  // determine whether to add a zombie (ls or normal). We will only add normal
  // zombies if we dequeued a normal packet, and we will only add an LS zombie
  // if we dequeued a LS packet.
  QueueDepthDynamics* dynamics         = &(zlr_queue_depth_dynamics_[bin_idx]);
  // Fast recovery data: used to determine whether we're using the
  // instantaneous queue depth or the minimum over the observation window.
  FastRecoveryData*   data             = &(fast_recovery_[bin_idx]);
  // If we're adding a zombie, which type we should add.
  LatencyClass        new_zombie_class = HIGH_LATENCY_ZLR;
  // The instantaneous queue depth to consider for ZLR, which includes a
  // different set of latency classes depending on whether this is normal
  // latency ZLR or LS ZLR.
  uint32_t            zlr_depth_bytes  = q_mgr_.GetTtypeDepthBytes(
    bin_idx, ZLR_DECISION_TTYPES, kNumZlrDecisionTtypes);
  // Whether or not we have any zombies that should be counted against this
  // ZLR window. This will be used to determine whether it's appropriate to
  // increase the ZLR window, since we don't want to increase it unless
  // there's been some action on a queue that counts.

  if (is_ls)
  {
    dynamics         = &(zlr_ls_queue_depth_dynamics_[bin_idx]);
    data             = &(ls_fast_recovery_[bin_idx]);
    new_zombie_class = HIGH_LATENCY_ZLR_LS;
    zlr_depth_bytes  = q_mgr_.GetTtypeDepthBytes(bin_idx,
      ZLR_LS_DECISION_TTYPES, kNumZlrLsDecisionTtypes);
  }
  int32_t  change_rate     = dynamics->GetChangeRateBytesPerSec();
  uint32_t min_depth_bytes = dynamics->GetMinQueueDepthBytes();

  if (zlr_xplot_[bin_idx])
  {
    XPLOT_COLOR color    = RED;
    uint8_t     line_num = 0;
    if (is_ls)
    {
      color = GREEN;
      line_num++;
    }
    zlr_xplot_[bin_idx]->ContinueTimeLine(line_num,
      dynamics->min_bytes_reset_period().GetTimeInMsec(), color);
  }

  Time now = Time::Now();
  if (!is_ls && qd_xplot_[bin_idx] != NULL && kGraphZLRWindows)
  {
    uint32_t zombie_depth_bytes = q_mgr_.GetTtypeDepthBytes(
      bin_idx,
      ZLR_ZOMBIE_TTYPES, kNumZlrZombieTtypes);
    qd_xplot_[bin_idx]->ContinueTimeLine(
      1, zombie_depth_bytes + min_depth_bytes,
      GREEN);
  }

  if (!Packet::IsZombie(dq_info.lat))
  {
    LogD(kClassName, __func__,
         "Reacting to a non-zombie dequeue: min_depth_bytes = %" PRIu32 
         ", zlr_high_water_mark_bytes_ = %" PRIu32 ", change_rate = %" PRId32 
         ", zlr_q_change_min_thresh_bytes_per_s_ = %" PRId32 ".\n",
         min_depth_bytes, zlr_high_water_mark_bytes_, change_rate,
         zlr_q_change_min_thresh_bytes_per_s_);
    // Determine whether to add a zombie packet.
    // During fast recovery, we use the instantaneous queue depth to make this
    // decision. Otherwise, we use the minimum depth over the observation
    // window.
    if ((kFastRecovery &&
         data->fast_recovery_state == RECOVERY &&
         zlr_depth_bytes >= zlr_high_water_mark_bytes_) ||
        ((min_depth_bytes > zlr_high_water_mark_bytes_)
         && (change_rate >= zlr_q_change_min_thresh_bytes_per_s_)))
    {
      // This is not a zombie packet, and the non-zombie queue is long enough,
      // and the queue change rate is high enough.
      // Add a zombie packet (the triggering packet has already been dequeued).
      if (dq_info.is_ip && dq_info.dst_addr != 0)
      {
        size_t zombie_len = dq_info.dequeued_size;
        if (zombie_len > kMaxZombieLenBytes)
        {
          zombie_len = kMaxZombieLenBytes;
        }
        // For multicast packets, we want to add zombies just for the single
        // destination bin we are currently evaluating.
        DstVec  dst_vec = 0;
        if (is_multicast_)
        {
          dst_vec = bin_map_.AddBinToDstVec(dst_vec, bin_idx);
        }
        q_mgr_.AddNewZombie(dq_info.dst_addr, zombie_len, new_zombie_class,
                            dst_vec);
      }
    }
  }
}
