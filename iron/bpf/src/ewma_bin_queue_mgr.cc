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

/// \file ewma_bin_queue_mgr.cc

#include "ewma_bin_queue_mgr.h"
#include "queue_depths.h"

#include "config_info.h"
#include "log.h"
#include "packet.h"
#include "packet_pool.h"
#include "timer.h"
#include "shared_memory_if.h"
#include "string_utils.h"
#include "unused.h"

#include <sstream>

#include <math.h>

using ::iron::ConfigInfo;
using ::iron::EWMABinQueueMgr;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::QueueDepths;

//
// Constants.
//
namespace
{
  /// Class name for logging.
  const char     kClassName[]               = "EWMABinQueueMgr";

  /// Default tau value for weight computation. This is the length of
  /// time for a smoothing window, in microseconds. (5 ms)
  const uint32_t kDefaultTauUsec            = 5000;

  /// Default value for whether we compute tau based on the queue depth
  /// oscillation periods.
  const bool     kDefaultUseDynamicTau      = true;

  /// Default for whether to use the linear interpolation version of EWMA.
  const bool     kUseLinearInterpolation    = false;

  /// Maximum amount of time to wait before recomputing the weight for a bin,
  /// even if the queue depth hasn't changed. This will allow the weights to
  /// convert on the exact value when the exact value isn't changing.
  const uint32_t kMaximumWeightIntervalUsec = 10000;
}

//============================================================================
EWMABinQueueMgr::EWMABinQueueMgr(BinIndex bin_idx,
                                 PacketPool& packet_pool,
                                 BinMap& bin_map)
    : BinQueueMgr(bin_idx, packet_pool, bin_map),
      last_weight_time_(),
      tau_usec_(kDefaultTauUsec),
      ls_tau_usec_(kDefaultTauUsec),
      weights_(NULL),
      previous_queue_depth_bytes_(NULL),
      queue_depth_osc_mgr_(),
      ls_queue_depth_osc_mgr_(),
      use_dynamic_tau_(kDefaultUseDynamicTau)
{
  LogI(kClassName, __func__,
        "Creating EWMA QueueDepth Management...\n");

  if (!last_weight_time_.Initialize(bin_map))
  {
    LogF(kClassName, __func__, "Unable to initialize last weight time "
         "array.\n");
    return;
  }

  weights_ = new (std::nothrow) QueueDepths(bin_map);

  if (!weights_)
  {
    LogF(kClassName, __func__,
          "Error allocating QueueDepths object for weights.\n");
    return;
  }

  previous_queue_depth_bytes_ = new (std::nothrow) QueueDepths(bin_map);

  if (!previous_queue_depth_bytes_)
  {
    LogF(kClassName, __func__,
          "Error allocating QueueDepths object for previous queue depths.\n");
    return;
  }

  if (!queue_depth_osc_mgr_.Initialize(bin_map))
  {
    LogF(kClassName, __func__, "Unable to initialize queue depth oscillation "
         "manager array.\n");
    return;
  }

  if (!ls_queue_depth_osc_mgr_.Initialize(bin_map))
  {
    LogF(kClassName, __func__, "Unable to initialize latency-sensitive queue "
         "depth oscillation manager array.\n");
    return;
  }

  // Initialize the last weight time array.
  int64_t  now = Time::Now().GetTimeInUsec();
  last_weight_time_.Clear(now);
}

//============================================================================
EWMABinQueueMgr::~EWMABinQueueMgr()
{
  LogI(kClassName, __func__,
        "Destroying EWMABinQueueMgr...\n");

  tau_usec_ = 0;
  ls_tau_usec_ = 0;

  // Get rid of weights.
  if (weights_)
  {
    delete weights_;
    weights_ = NULL;
  }

  if (previous_queue_depth_bytes_)
  {
    delete previous_queue_depth_bytes_;
    previous_queue_depth_bytes_ = NULL;
  }

}

//============================================================================
bool EWMABinQueueMgr::Initialize(const ConfigInfo& config_info,
                                 BinIndex node_bin_idx)
{
  // Initialize the bin queue mgr in the usual manner.
  bool result  = BinQueueMgr::Initialize(config_info, node_bin_idx);
  initialized_ = false;

  // Initialize EWMA.
  LogI(kClassName, __func__,
        "Initializing EWMABinQueueMgr...\n");


  tau_usec_ = static_cast<uint32_t>
                  (config_info.GetUint("Bpf.EWMA.TauUsec", kDefaultTauUsec));
  ls_tau_usec_ = tau_usec_;

  use_dynamic_tau_ = config_info.GetBool(
    "Bpf.EWMA.DynamicTau", kDefaultUseDynamicTau);

  // Read and log config values for the oscillation managers.
  if (use_dynamic_tau_)
  {
    QueueDepthOscConfig osc_config;
    if (!osc_config.Initialize(config_info))
    {
      // Logged within the failed function.
      return false;
    }

    BinIndex  bin_idx = kInvalidBinIndex;

    for (bool bin_idx_valid = bin_map_.GetFirstDstBinIndex(bin_idx);
         bin_idx_valid;
         bin_idx_valid = bin_map_.GetNextDstBinIndex(bin_idx))
    {
      BinIndex  dst_idx = kInvalidBinIndex;

      for (bool dst_idx_valid = bin_map_.GetFirstDstBinIndex(dst_idx);
           dst_idx_valid;
           dst_idx_valid = bin_map_.GetNextDstBinIndex(dst_idx))
      {
        // MCAST TODO fix all of this to be per group/dst
        if (!queue_depth_osc_mgr_[bin_idx].Initialize(osc_config) ||
            !ls_queue_depth_osc_mgr_[bin_idx].Initialize(osc_config))
        {
          // Logged within the failed function.
          return false;
        }
        queue_depth_osc_mgr_[bin_idx].set_qd_xplot(
          GetQueueDepthsXplot(dst_idx));
        queue_depth_osc_mgr_[bin_idx].set_log_id(bin_map_.GetIdToLog(bin_idx));
        queue_depth_osc_mgr_[bin_idx].set_ls_queue(false);
        ls_queue_depth_osc_mgr_[bin_idx].set_log_id(bin_map_.GetIdToLog(bin_idx));
        ls_queue_depth_osc_mgr_[bin_idx].set_ls_queue(true);
      }
    }
  }

  // Print EWMA-specific values.
  LogC(kClassName, __func__,
       "Bpf.EWMA.TauUsec              : %" PRIu32 "\n", tau_usec_);

  LogC(kClassName, __func__,
       "Bpf.EWMA.DynamicTau           : %s\n",
       (use_dynamic_tau_ ? "true" : "false"));
  LogC(kClassName, __func__,
       "Linear Interpolation          : %s\n",
       (kUseLinearInterpolation ? "true" : "false"));

  initialized_ = true;
  return result;
}

//============================================================================
void EWMABinQueueMgr::PeriodicAdjustQueueValues()
{
  // First handle any adjustments by the super class, which includes
  // anti-starvation.
  int64_t now = Time::Now().GetTimeInUsec();
  BinQueueMgr::PeriodicAdjustQueueValues();

  // MCAST TODO: short cut for unicast bins - skip the for loop.
  BinIndex  dst_idx = kInvalidBinIndex;

  for (bool dst_idx_valid = bin_map_.GetFirstDstBinIndex(dst_idx);
       dst_idx_valid;
       dst_idx_valid = bin_map_.GetNextDstBinIndex(dst_idx))
  {
    if (use_dynamic_tau_)
    {
      // Take the next sample for oscillation manager, if appropriate. The
      // timing is performed within the oscillation manager.
        queue_depth_osc_mgr_[dst_idx].QueueDepthOscCheckPoint(
        queue_depths_.GetBinDepthByIdx(dst_idx),
        weights_->GetBinDepthByIdx(dst_idx));
      ls_queue_depth_osc_mgr_[dst_idx].QueueDepthOscCheckPoint(
        queue_depths_.GetBinDepthByIdx(dst_idx, iron::LOW_LATENCY),
        weights_->GetBinDepthByIdx(dst_idx, iron::LOW_LATENCY));
    }

    // And recompute the weight if we've gone the max interval without a queue
    // depth change.
    if (now - last_weight_time_[dst_idx] > kMaximumWeightIntervalUsec)
    {
      ComputeWeight(dst_idx);
      // last_weight_time_ is updated within ComputeWeight.
    }
  }
}

//============================================================================
void EWMABinQueueMgr::AdjustQueueValuesOnChange(BinIndex dst_idx)
{
  BinQueueMgr::AdjustQueueValuesOnChange(dst_idx);

  // Recompute the weight for the bin whose value changed..
  ComputeWeight(dst_idx);
}

//============================================================================
QueueDepths* EWMABinQueueMgr::GetQueueDepthsForBpf()
{
  // No need to recompute weights here. Computing weights too often causes
  // problems, and we already do checkpoints whenever the queue depth changes
  // and whenever we generate QLAMs, which should be sufficient.

  // Use exact queue depths for BPF.
  return GetQueueDepths();
}

//============================================================================
QueueDepths* EWMABinQueueMgr::GetDepthsForBpfQlam()
{
  // QLAMs advertised smoothed queue depths.
  return weights_;
}

//============================================================================
uint32_t EWMABinQueueMgr::GetQueueDepthForProxies()
{
  // No need to recompute weights here. Computing weights too often causes
  // problems, and we already do checkpoints whenever the queue depth changes
  // and whenever we generate QLAMs, which should be sufficient.

  // Admission control uses smoothed queue depths.
  // MCAST TODO: this is wrong for multicast.
  return weights_->GetBinDepthByIdx(my_bin_index_);
}

//============================================================================
void EWMABinQueueMgr::ComputeWeight(BinIndex dst_idx)
{
  uint32_t queue_depth_bytes    = queue_depths_.GetBinDepthByIdx(dst_idx);
  uint32_t queue_ls_depth_bytes =
    queue_depths_.GetBinDepthByIdx(dst_idx, iron::LOW_LATENCY);
  bool     compute_weight       = true;
  bool     compute_ls_weight    = true;

  // Seed the weights equal to the exact values, in case we're not ready to
  // start weight computations yet. We will set the weights before returning
  // even if we don't recompute them.
  uint32_t weight_bytes    = queue_depth_bytes;
  uint32_t ls_weight_bytes = queue_ls_depth_bytes;

  if (use_dynamic_tau_ &&
      !queue_depth_osc_mgr_[dst_idx].have_usable_period())
  {
    compute_weight = false;
  }
  if (use_dynamic_tau_ &&
      !ls_queue_depth_osc_mgr_[dst_idx].have_usable_period())
  {
    compute_ls_weight = false;
  }

  int64_t current_time_usec = Time::GetNowInUsec();
  int64_t time_diff_usec = current_time_usec - last_weight_time_[dst_idx];

  if (compute_weight)
  {
    if (use_dynamic_tau_)
    {
      tau_usec_ = queue_depth_osc_mgr_[dst_idx].GetOscPeriodToUse();
      LogD(kClassName, __func__, "Bin Id %s, Destination %s"
           ": Updating tau to %" PRIu32 "\n",
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           bin_map_.GetIdToLog(dst_idx).c_str(), tau_usec_);
    }

    // beta will be e^{-delta_time/tau}, but set it to 1 (i.e., use only the
    // previous value) if the times don't make sense to avoid exceptions.
    double beta = 1;
    double beta_linear_inter = 1;
    double normalized_time_diff = 0;
    if (time_diff_usec <= 0)
    {
      LogE(kClassName, __func__,
           "Last time weight was computed was in the future for bin id %s"
           ", destination %s. Time diff = %" PRId64 "\n",
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           bin_map_.GetIdToLog(dst_idx).c_str(),
           time_diff_usec);
      // beta will be larger than 1. Instead, just reuse the old weight by
      // leaving beta = 1.
    }
    else
    {
      normalized_time_diff = time_diff_usec / static_cast<double>(tau_usec_);
      beta = exp(-1 * normalized_time_diff);
      if (kUseLinearInterpolation)
      {
        // Used to interpolate the value between the two most recent samples, in
        // case samples are sparse.
        beta_linear_inter = (1 - beta) / normalized_time_diff;
      }
    }
    weight_bytes = weights_->GetBinDepthByIdx(dst_idx) * beta;
    if (kUseLinearInterpolation)
    {
      uint32_t previous = previous_queue_depth_bytes_->GetBinDepthByIdx(dst_idx);
      weight_bytes    += (1 - beta_linear_inter) * queue_depth_bytes;
      weight_bytes    += (beta_linear_inter - beta) * previous;
      previous_queue_depth_bytes_->SetBinDepthByIdx(dst_idx, queue_depth_bytes);
    }
    else
    {
      weight_bytes    += (1 - beta) * queue_depth_bytes;
    }
    LogD(kClassName, __func__,
         "Bin: %s, Destination: %s"
         "Weight: %" PRIu32 "B, Queue: %" PRIu32
         "B (time diff %" PRIu64
         "usec, beta %.3f, beta_linear_inter %.3f).\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str(),
         bin_map_.GetIdToLog(dst_idx).c_str(),
         weight_bytes,
         queue_depth_bytes,
         time_diff_usec, beta, beta_linear_inter);
  }

  if (compute_ls_weight)
  {
    if (use_dynamic_tau_)
    {
      ls_tau_usec_ = ls_queue_depth_osc_mgr_[dst_idx].GetOscPeriodToUse();
      LogD(kClassName, __func__, "Bin %s, Dest %s"
           ": Updating LS tau to %" PRIu32 "\n",
           bin_map_.GetIdToLog(my_bin_index_).c_str(),
           bin_map_.GetIdToLog(dst_idx).c_str(), ls_tau_usec_);
    }

    double ls_beta = 1;
    double ls_beta_linear_inter = 1;
    double ls_normalized_time_diff = 0;
    if (time_diff_usec > 0)
    {
      ls_normalized_time_diff = time_diff_usec /
        static_cast<double>(ls_tau_usec_);
      ls_beta = exp(-1 * ls_normalized_time_diff);
      if (kUseLinearInterpolation)
      {
        // Used to interpolate the value between the two most recent samples,
        // in case samples are sparse.
        ls_beta_linear_inter = (1 - ls_beta) / ls_normalized_time_diff;
      }
    }
    ls_weight_bytes =
      weights_->GetBinDepthByIdx(dst_idx, iron::LOW_LATENCY) * ls_beta;
    if (kUseLinearInterpolation)
    {
      uint32_t ls_previous = previous_queue_depth_bytes_->GetBinDepthByIdx(
        dst_idx, iron::LOW_LATENCY);
      ls_weight_bytes += (1 - ls_beta_linear_inter) * queue_ls_depth_bytes;
      ls_weight_bytes += (ls_beta_linear_inter - ls_beta) * ls_previous;
      previous_queue_depth_bytes_->SetBinDepthByIdx(
        dst_idx, queue_ls_depth_bytes, iron::LOW_LATENCY);
    }
    else
    {
      ls_weight_bytes += (1 - ls_beta) * queue_ls_depth_bytes;
    }
    LogD(kClassName, __func__,
         "Bin %s, Dest %s, LS Weight: %" PRIu32
         "B, LS Queue: %" PRIu32 "B (time diff %" PRIu64
         "usec, ls_beta %.3f, ls_beta_linear_inter %.3f).\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str(),
         bin_map_.GetIdToLog(dst_idx).c_str(),
         ls_weight_bytes,
         queue_ls_depth_bytes,
         time_diff_usec, ls_beta, ls_beta_linear_inter);
  }

  // Record the new weight for this bin, which may be set to the exact QD, may
  // be the same as the previous weights, or may be new.
  weights_->SetBinDepthByIdx(dst_idx, weight_bytes, ls_weight_bytes);

  if (GetQueueDepthsXplot(dst_idx) && compute_weight)
  {
    uint64_t now_usec  = Time::GetNowInUsec() - iron::kStartTime;
    GetQueueDepthsXplot(dst_idx)->DrawPoint(
      now_usec, weight_bytes, YELLOW, XPLOT_DIAMOND);
  }

  last_weight_time_[dst_idx] = current_time_usec;
}

//============================================================================
void EWMABinQueueMgr::PrintDepths()
{
  uint32_t UNUSED(queue_depth_bytes)    = 0;
  uint32_t UNUSED(queue_ls_depth_bytes) = 0;
  uint32_t UNUSED(bin_weight_bytes)     = 0;
  uint32_t UNUSED(bin_ls_weight_bytes)  = 0;

  LogD(kClassName, __func__, "====== Depths ======\n");
  LogD(kClassName, __func__, "Tau = %" PRIu32 ".\n", tau_usec_);

  BinIndex  idx = kInvalidBinIndex;

  for (bool idx_valid = bin_map_.GetFirstDstBinIndex(idx);
       idx_valid;
       idx_valid = bin_map_.GetNextDstBinIndex(idx))
  {
    queue_depth_bytes    = queue_depths_.GetBinDepthByIdx(idx,
                                                          NORMAL_LATENCY);
    queue_ls_depth_bytes = queue_depths_.GetBinDepthByIdx(idx, LOW_LATENCY);
    bin_weight_bytes     = weights_->GetBinDepthByIdx(idx, NORMAL_LATENCY);
    bin_ls_weight_bytes  = weights_->GetBinDepthByIdx(idx, LOW_LATENCY);

    LogD(kClassName, __func__,
         "Bin %s, Dest %s: Queue depth is %"
         PRIu32 "B (LS %" PRIu32 "B), weight "
         "is %" PRIu32 "B (LS %" PRIu32 "B), last computed at %" PRId64
         "usec.\n",
         bin_map_.GetIdToLog(my_bin_index_),
         bin_map_.GetIdToLog(idx).c_str(),
         queue_depth_bytes, queue_ls_depth_bytes,
         bin_weight_bytes, bin_ls_weight_bytes,
         last_weight_time_[idx]);
  }

  LogD(kClassName, __func__, "==== End Depths ====\n");
}
