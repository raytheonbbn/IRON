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

/// \file hvyball_bin_queue_mgr.cc

#include "hvyball_bin_queue_mgr.h"
#include "queue_depths.h"

#include "config_info.h"
#include "log.h"
#include "packet.h"
#include "string_utils.h"
#include "unused.h"


using ::iron::ConfigInfo;
using ::iron::HvyballBinQueueMgr;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::QueueDepths;
using ::iron::Time;

//
// Constants.
//
namespace
{
  /// Class name for logging.
  const char      kClassName[]                = "HvyballBinQueueMgr";

  /// Default beta value for weight computation.
  const double    kDefaultBeta                = 0.65;

  /// Default value for weight computation interval in usec.
  const uint32_t  kDefaultWeightCompIntvUsec  = 5000;

  /// Whether or not to use the Refactored heavy ball computation, in which
  /// smoothing is separated from latency reduction. If this is true, then
  /// the value of k should be reduced in the configuration file by 1-beta
  /// to achieve the same results as basic heavyball.
  const bool kRefactored = false;
}


//============================================================================
HvyballBinQueueMgr::HvyballBinQueueMgr(
  BinIndex bin_idx, PacketPool& packet_pool, BinMap& bin_map)
    : BinQueueMgr(bin_idx, packet_pool, bin_map),
      beta_(kDefaultBeta),
      weights_(NULL),
      current_weights_(NULL),
      last_weight_time_(0),
      weight_computation_interval_(kDefaultWeightCompIntvUsec)
{
  LogI(kClassName, __func__,
        "Creating HvyballBinQueueMgr Queue Management...\n");

  weights_ = new (std::nothrow) QueueDepths(bin_map);

  if (!weights_)
  {
    LogF(kClassName, __func__,
          "Error allocating QueueDepths object for weights.\n");
    return;
  }

  current_weights_ = new (std::nothrow) QueueDepths(bin_map);

  if (!current_weights_)
  {
    LogF(kClassName, __func__,
          "Error allocating QueueDepths object for current weights.\n");
    return;
  }
  last_weight_time_ = Time::Now().GetTimeInUsec();
}


//============================================================================
HvyballBinQueueMgr::~HvyballBinQueueMgr()
{
  LogI(kClassName, __func__,
        "Destroying HvyballBinQueueMgr...\n");

  beta_ = 0.0;

  // Get rid of weights.
  if (weights_)
  {
    delete weights_;
    weights_ = NULL;
  }

  // Get rid of current weights.
  if (current_weights_)
  {
    delete current_weights_;
    current_weights_ = NULL;
  }
}


//============================================================================
bool HvyballBinQueueMgr::Initialize(const ConfigInfo& config_info,
                                    BinIndex node_bin_idx)
{
  // Initialize the bin queue mgr in the usual manner.
  bool result   = BinQueueMgr::Initialize(config_info, node_bin_idx);
  initialized_  = false;

  // Initialize HvyballBinQueueMgr.
  LogI(kClassName, __func__,
        "Initializing HvyballBinQueueMgr...\n");


  beta_ = static_cast<double>
                  (config_info.GetFloat("Bpf.HvyBall.Beta", kDefaultBeta));

  weight_computation_interval_ = static_cast<uint32_t>
            (config_info.GetUint("Bpf.HvyBall.WeightComputationIntervalUsec",
                                  kDefaultWeightCompIntvUsec));

  // Print HvyballBinQueueMgr-specific values.
  LogC(kClassName, __func__,
        "Bpf.HvyBall.Beta              : %.2f\n", beta_);
  LogC(kClassName, __func__,
        "Bpf.HvyBall.WeightCompIntvUs  : %" PRIu32 "\n",
        weight_computation_interval_);
  LogC(kClassName, __func__,
        "Refactored Heavyball?         : %s\n",
       (kRefactored ? "true" : "false"));

  initialized_ = true;
  return result;
}

//============================================================================
QueueDepths* HvyballBinQueueMgr::GetQueueDepthsForBpf()
{
  // BPF uses weights modified with packets added/removed since last
  // computation.
  return current_weights_;
}

//============================================================================
QueueDepths* HvyballBinQueueMgr::GetDepthsForBpfQlam()
{
  // QLAMs advertised smoothed queue depths.
  return weights_;
}

//============================================================================
uint32_t HvyballBinQueueMgr::GetQueueDepthForProxies()
{
  // Admission control uses smoothed queue depths.
  // MCAST TODO: this is probably wrong.
  return weights_->GetBinDepthByIdx(my_bin_index_);
}

//============================================================================
void HvyballBinQueueMgr::OnEnqueue(
  uint32_t pkt_length_bytes, LatencyClass lat, DstVec dsts)
{
  BinQueueMgr::OnEnqueue(pkt_length_bytes, lat, dsts);

  // MCAST TODO: may need per-destination accounting here.
  current_weights_->Increment(
    my_bin_index_, pkt_length_bytes,
    (Packet::IsLatencySensitive(lat) ? pkt_length_bytes : 0));
}


//============================================================================
void HvyballBinQueueMgr::OnDequeue(const DequeuedInfo& dq_info, bool cloned)
{
  BinQueueMgr::OnDequeue(dq_info, cloned);

  if (cloned)
  {
    // Don't update accounting after a clone that doesn't remove the packet.
    return;
  }
  // MCAST TODO: may need per-destination accounting here.
  uint32_t depth  = current_weights_->GetBinDepthByIdx(my_bin_index_);
  bool     is_ls  = (dq_info.lat == iron::LOW_LATENCY ||
                     dq_info.lat == iron::HIGH_LATENCY_ZLR_LS);

  size_t  pkt_size  = dq_info.dequeued_size;
  if (pkt_size >= depth)
  {
    // This is a somewhat expected situation, since the weights are not
    // exactly the same as the queue depths. We don't want to allow
    // decrementing below zero, since queue depths are unsigned ints.
    current_weights_->Decrement(my_bin_index_, depth, is_ls ? depth : 0);
  }
  else
  {
    current_weights_->Decrement(my_bin_index_, pkt_size, is_ls ? pkt_size : 0);
  }
}

//============================================================================
void HvyballBinQueueMgr::PeriodicAdjustQueueValues()
{
  // First handle any adjustments by the super class, which includes
  // anti-starvation.
  int64_t now = Time::Now().GetTimeInUsec();
  BinQueueMgr::PeriodicAdjustQueueValues();

  if (now - last_weight_time_ > weight_computation_interval_)
  {
    last_weight_time_ = now;
    ComputeWeights();
  }
}

//============================================================================
void HvyballBinQueueMgr::ComputeWeights()
{
  uint32_t bin_weight_bytes     = 0;
  uint32_t bin_ls_weight_bytes  = 0;
  uint32_t queue_depth_bytes    = 0;
  uint32_t queue_ls_depth_bytes = 0;

  BinIndex  bin_idx = kInvalidBinIndex;

  for (bool bin_idx_valid = bin_map_.GetFirstDstBinIndex(bin_idx);
       bin_idx_valid;
       bin_idx_valid = bin_map_.GetNextDstBinIndex(bin_idx))
  {
    bin_weight_bytes    = weights_->GetBinDepthByIdx(bin_idx, NORMAL_LATENCY);
    bin_ls_weight_bytes = weights_->GetBinDepthByIdx(bin_idx, LOW_LATENCY);

    // Compute new weights: w_T+1 = w_T x beta + current queue depth.
    bin_weight_bytes     *= beta_;
    bin_ls_weight_bytes  *= beta_;
    queue_depth_bytes     = queue_depths_.GetBinDepthByIdx(bin_idx);
    queue_ls_depth_bytes  = queue_depths_.GetBinDepthByIdx(
      bin_idx, iron::LOW_LATENCY);

    if (kRefactored)
    {
      bin_weight_bytes    += (1 - beta_) * queue_depth_bytes;
      bin_ls_weight_bytes += (1 - beta_) * queue_ls_depth_bytes;
    }
    else
    {
      bin_weight_bytes    += queue_depth_bytes;
      bin_ls_weight_bytes += queue_ls_depth_bytes;
    }

    // Record the new weight for this bin.
    weights_->SetBinDepthByIdx(bin_idx, bin_weight_bytes, bin_ls_weight_bytes);

    // The current weights are the same as the weights at time of computation.
    current_weights_->SetBinDepthByIdx(bin_idx, bin_weight_bytes, bin_ls_weight_bytes);

    LogD(kClassName, __func__,
         "Bin: %s, Weight: %" PRIu32 "B (LS %" PRIu32 "B), Queue: %"
         PRIu32 "B (LS %" PRIu32 "B).\n",
         bin_map_.GetIdToLog(bin_idx).c_str(), bin_weight_bytes,
         bin_ls_weight_bytes, queue_depth_bytes, queue_ls_depth_bytes);
  }
}

//============================================================================
void HvyballBinQueueMgr::PrintDepths() const
{
  uint32_t UNUSED(queue_depth_bytes)    = 0;
  uint32_t UNUSED(queue_ls_depth_bytes) = 0;
  uint32_t UNUSED(bin_weight_bytes)     = 0;
  uint32_t UNUSED(bin_ls_weight_bytes)  = 0;
  uint32_t UNUSED(cur_weight_bytes)     = 0;
  uint32_t UNUSED(cur_ls_weight_bytes)  = 0;

  LogD(kClassName, __func__, "====== Depths ======\n");
  LogD(kClassName, __func__, "Beta = %f.\n", beta_);

  BinIndex  idx = kInvalidBinIndex;

  for (bool idx_valid = bin_map_.GetFirstDstBinIndex(idx);
       idx_valid;
       idx_valid = bin_map_.GetNextDstBinIndex(idx))
  {
    queue_depth_bytes    = queue_depths_.GetBinDepthByIdx(idx, NORMAL_LATENCY);
    queue_ls_depth_bytes = queue_depths_.GetBinDepthByIdx(idx, LOW_LATENCY);
    bin_weight_bytes     = weights_->GetBinDepthByIdx(idx, NORMAL_LATENCY);
    bin_ls_weight_bytes  = weights_->GetBinDepthByIdx(idx, LOW_LATENCY);
    cur_weight_bytes     = current_weights_->GetBinDepthByIdx(NORMAL_LATENCY);
    cur_ls_weight_bytes  = current_weights_->GetBinDepthByIdx(LOW_LATENCY);

    LogD(kClassName, __func__,
         "Bin %s, Dst %s: Queue depth is %"
         PRIu32"B (LS %" PRIu32 "B), and "
         "heavyball weight is %" PRIu32 "B (LS %" PRIu32 "B) with current weight %"
         PRIu32"B (LS %" PRIu32 "B).\n",
         bin_map_.GetIdToLog(my_bin_index_).c_str(),
         bin_map_.GetIdToLog(idx).c_str(),
         queue_depth_bytes, queue_ls_depth_bytes,
         bin_weight_bytes, bin_ls_weight_bytes,
         cur_weight_bytes, cur_ls_weight_bytes);
  }

  LogD(kClassName, __func__, "==== End Depths ====\n");
}
