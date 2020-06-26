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

/// \file queue_store.cc

#include "queue_store.h"

#include "bin_queue_mgr.h"
#include "config_info.h"
#include "ewma_bin_queue_mgr.h"
#include "hvyball_bin_queue_mgr.h"
#include "iron_constants.h"
#include "log.h"
#include "nplb_bin_queue_mgr.h"
#include "packet.h"
#include "packet_pool.h"
#include "path_controller.h"
#include "queue_depths.h"
#include "string_utils.h"

#include <map>
#include <string>

#include <inttypes.h>


using ::iron::BinQueueMgr;
using ::iron::Log;
using ::iron::EWMABinQueueMgr;
using ::iron::HvyballBinQueueMgr;
using ::iron::NPLBBinQueueMgr;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PathController;
using ::iron::QueueStore;
using ::iron::QueueDepths;
using ::iron::SharedMemoryIF;
using ::std::map;
using ::std::string;

//
// Constants.
//
namespace
{
  /// Class name for logging.
  const char       kClassName[]                = "QueueStore";

  /// The default Bpf queue management algorithm.
  const char*     kDefaultBpfQMgr              = "Base";
}

//============================================================================
QueueStore::QueueStore(PacketPool& packet_pool, BinMap& bin_map,
                       SharedMemoryIF& weight_qd_shared_memory)
    : packet_pool_(packet_pool),
      bin_map_(bin_map),
      q_mgrs_(),
      virtual_queue_depths_(bin_map),
      weight_qd_shared_memory_(weight_qd_shared_memory),
      nbr_virtual_queue_depths_(),
      proxy_depths_(bin_map),
      use_anti_starvation_zombies_(kDefaultUseAntiStarvationZombies),
      hysteresis_(kBpfAlgHysteresisBytes),
      debug_stats_(NULL),
      max_gradient_set_(),
      max_gradient_val_()
{
  LogI(kClassName, __func__,
        "Creating QueueStore...\n");
}

//============================================================================
QueueStore::~QueueStore()
{
  LogI(kClassName, __func__,
        "Destroying QueueStore...\n");

  // Destroy method checks for state of shared memory segment, so we can safely
  // call the following.
  weight_qd_shared_memory_.Destroy();
  LogD(kClassName, __func__,
       "Destroyed shared memory.\n");

  // Destroy the queue managers and neighbor virtual queue depths for all bin
  // indexes.
  BinIndex  idx = 0;

  for (bool valid = bin_map_.GetFirstBinIndex(idx);
       valid;
       valid = bin_map_.GetNextBinIndex(idx))
  {
    if (q_mgrs_[idx])
    {
      delete q_mgrs_[idx];
      q_mgrs_[idx] = NULL;
    }

    if (nbr_virtual_queue_depths_[idx])
    {
      delete nbr_virtual_queue_depths_[idx];
      nbr_virtual_queue_depths_[idx] = NULL;
    }
  }
}

//============================================================================
bool QueueStore::Initialize(const ConfigInfo& config_info,
                            BinIndex node_bin_idx)
{
  // The bin queue mgrs are allocated immediately because the constructor is
  // followed by a call to Initialize with the config info, which is not
  // retained.  The config info contains items used to initialized each queue
  // set.  In the future, we may decide to retain the config info object in
  // order to allocate bin queue mgrs on demand.
  if (!q_mgrs_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize queue managers "
         "array.\n");
    return false;
  }
  q_mgrs_.Clear(NULL);

  string  q_mgr_alg = config_info.Get("Bpf.Alg.QDMgr", kDefaultBpfQMgr);

  use_anti_starvation_zombies_ =
    config_info.GetBool("Bpf.UseAntiStarvationZombies",
                       kDefaultUseAntiStarvationZombies);

  // Test for NPLB combined with ASAP (illegal) outside the for loop.
  if (q_mgr_alg == "NPLB")
  {
    if (use_anti_starvation_zombies_)
    {
      LogF(kClassName, __func__,
           "Cannot use NPLB with Anti Starvation Zombies.\n");
      return false;
    }
  }

  // We use the hysteresis as the minimum value that needs to be overcome for
  // anti-starvation. (ProcessGradientUpdate uses this.)
  hysteresis_                  =
    config_info.GetInt("Bpf.Alg.HysteresisBytes", kBpfAlgHysteresisBytes);

  // Initialize the neighbor virtual queue depths array.
  if (!nbr_virtual_queue_depths_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize neighbor virtual queue "
         "depths array.\n");
    return false;
  }
  nbr_virtual_queue_depths_.Clear(NULL);

  q_mgrs_.Clear(NULL);

  // Create the bin queue managers for each unicast or multicast destination
  // bin index.
  BinIndex  idx = 0;

  for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
       valid;
       valid = bin_map_.GetNextDstBinIndex(idx))
  {
    if (q_mgr_alg == "HvyBall")
    {
      q_mgrs_[idx] = new (std::nothrow) HvyballBinQueueMgr(
        idx, packet_pool_, bin_map_);
    }
    else if (q_mgr_alg == "EWMA")
    {
      q_mgrs_[idx] = new (std::nothrow) EWMABinQueueMgr(
        idx, packet_pool_, bin_map_);
    }
    else if (q_mgr_alg == "NPLB")
    {
      q_mgrs_[idx] = new (std::nothrow) NPLBBinQueueMgr(
        idx, packet_pool_, bin_map_);
    }
    else
    {
      q_mgrs_[idx]  = new (std::nothrow) BinQueueMgr(
        idx, packet_pool_, bin_map_);
    }

    if (!q_mgrs_[idx])
    {
      LogF(kClassName, __func__,
           "Failed to allocate bin queue mgr object of size at least %zdB.\n",
           sizeof(BinQueueMgr));
      return false;
    }
  }

  // Create the shared memory segments, starting with queue depths for weights.
  key_t  sem_key  = config_info.GetUint("Bpf.Weight.SemKey",
                                        kDefaultWeightSemKey);
  string    name  = config_info.Get("Bpf.Weight.ShmName",
                                    kDefaultWeightShmName);

  // Find a place to store the queue depths to share, allocate
  // enough shared memory for each group, etc.
  if (!weight_qd_shared_memory_.Create(
        sem_key, name.c_str(),
        proxy_depths_.GetShmSize()))
  {
    LogF(kClassName, __func__,
         "Failed to create the shared memory segment for weights.\n");
    return false;
  }

  // Initialize the bin queue managers for each unicast or multicast
  // destination bin index.
  for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
       valid;
       valid = bin_map_.GetNextDstBinIndex(idx))
  {
    if (!q_mgrs_[idx] || !q_mgrs_[idx]->Initialize(config_info, node_bin_idx))
    {
      LogF(kClassName, __func__,
           "Failed to initialize bin queue mgr for %s bin id %" PRIBinIndex
           " at %p.\n",
           (bin_map_.IsMcastBinIndex(idx) ? "mcast" : "ucast"), idx,
           q_mgrs_[idx]);
      return false;
    }
  }
  proxy_depths_.InitializeShmStats();

  if (!max_gradient_set_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize maximum gradient set "
         "array.\n");
    return false;
  }

  if (!max_gradient_val_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize maximum gradient value "
         "array.\n");
    return false;
  }

  LogC(kClassName, __func__,
        "Bpf.Weight.SemKey             : %" PRId32 "\n",
        static_cast<int32_t>(sem_key));
  LogC(kClassName, __func__,
        "Bpf.Weight.ShmName            : %s\n", name.c_str());
  LogC(kClassName, __func__,
       "Bpf.Alg.QDMgr                  : %s\n",
       q_mgr_alg.c_str());
  LogC(kClassName, __func__,
       "Bpf.UseAntiStarvationZombies   : %s\n",
       (use_anti_starvation_zombies_ ? "Enabled" : "Disabled"));

  return true;
}

//============================================================================
void QueueStore::AddQueueMgr(const ConfigInfo& config_info,
                             BinIndex q_bin_idx, BinIndex node_bin_idx)
{
  string  q_mgr_alg = config_info.Get("Bpf.Alg.QDMgr", kDefaultBpfQMgr);

  if (q_mgr_alg == "HvyBall")
  {
    q_mgrs_[q_bin_idx] = new (std::nothrow) HvyballBinQueueMgr(
      q_bin_idx, packet_pool_, bin_map_);
  }
  else if (q_mgr_alg == "EWMA")
  {
    q_mgrs_[q_bin_idx] = new (std::nothrow) EWMABinQueueMgr(
      q_bin_idx, packet_pool_, bin_map_);
  }
  else if (q_mgr_alg == "NPLB")
  {
    q_mgrs_[q_bin_idx] = new (std::nothrow) NPLBBinQueueMgr(
      q_bin_idx, packet_pool_, bin_map_);
  }
  else
  {
    q_mgrs_[q_bin_idx]  = new (std::nothrow) BinQueueMgr(
      q_bin_idx, packet_pool_, bin_map_);
  }

  if (!q_mgrs_[q_bin_idx])
  {
    LogF(kClassName, __func__,
         "Failed to allocate bin queue mgr object of size at least %zdB.\n",
         sizeof(BinQueueMgr));
    return;
  }

  if (!q_mgrs_[q_bin_idx]->Initialize(config_info, node_bin_idx))
  {
    LogF(kClassName, __func__,
         "Failed to initialize bin queue mgr for %s bin id %" PRIBinIndex
         " at %p.\n",
         (bin_map_.IsMcastBinIndex(q_bin_idx) ? "mcast" : "ucast"), q_bin_idx,
         q_mgrs_[q_bin_idx]);
    return;
  }
}

//============================================================================
QueueDepths* QueueStore::GetWQueueDepths()
{
  // Update the queue depths for the proxies located in shared memory.  The
  // queue depth must be for all unicast and multicast destination bin
  // indexes.
  BinIndex  idx = 0;

  for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
       valid;
       valid = bin_map_.GetNextDstBinIndex(idx))
  {
    proxy_depths_.SetBinDepthByIdx(
      idx, q_mgrs_[idx]->GetQueueDepthForProxies());
  }
  return &proxy_depths_;
}

//============================================================================
bool QueueStore::PublishWQueueDepthsToShm()
{
  if (GetWQueueDepths())
  {
    return proxy_depths_.CopyToShm(weight_qd_shared_memory_);
  }
  return false;
}

//============================================================================
void QueueStore::PeriodicAdjustQueueValues()
{
  // Call the equivalent method on the bin queue managers for each unicast and
  // multicast destination bin index.
  BinIndex  idx = 0;

  for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
       valid;
       valid = bin_map_.GetNextDstBinIndex(idx))
  {
    q_mgrs_[idx]->PeriodicAdjustQueueValues();
  }
}

//============================================================================
bool QueueStore::SetNbrQueueDepths(BinIndex dst_bin_idx, BinIndex nbr_bin_idx,
  QueueDepths* qd)
{
  q_mgrs_[dst_bin_idx]->set_nbr_queue_depths(nbr_bin_idx, qd);

  return true;
}

//============================================================================
QueueDepths* QueueStore::PeekNbrQueueDepths(BinIndex dst_bin_idx,
  BinIndex nbr_bin_idx)
{
  return q_mgrs_[dst_bin_idx]->GetNbrQueueDepths(nbr_bin_idx);
}

//============================================================================
bool QueueStore::SetNbrVirtQueueDepths(BinIndex bin_idx, QueueDepths* qd)
{
  if (!qd)
  {
    LogW(kClassName, __func__, "Queue depth NULL, cannot set virtual queues "
         "for bin id %" PRIBinId ".\n", bin_map_.GetPhyBinId(bin_idx));
    return false;
  }

  if (nbr_virtual_queue_depths_[bin_idx])
  {
    LogF(kClassName, __func__, "There is a virtual QueueDepth already in for "
         "nbr bin id %" PRIBinId "!  Setting would overwrite and leak "
         "memory.\n", bin_map_.GetPhyBinId(bin_idx));
    return false;
  }

  nbr_virtual_queue_depths_[bin_idx] = qd;

  return true;
}

//============================================================================
QueueDepths* QueueStore::PeekNbrVirtQueueDepths(BinIndex bin_idx)
{
  return nbr_virtual_queue_depths_[bin_idx];
}

//============================================================================
void QueueStore::DeleteNbrVirtQueueDepths(BinIndex bin_idx)
{
  if (nbr_virtual_queue_depths_[bin_idx])
  {
    delete nbr_virtual_queue_depths_[bin_idx];
    nbr_virtual_queue_depths_[bin_idx] = NULL;
    return;
  }

  LogD(kClassName, __func__, "Did not find queue depth for pathctrl to nbr %"
       PRIBinId ".\n", bin_map_.GetPhyBinId(bin_idx));
}

//============================================================================
void QueueStore::ProcessGradientUpdate(
    OrderedList<Gradient, int64_t>& ls_gradients,
    OrderedList<Gradient, int64_t>& gradients)
{
  SetASAPCap(ls_gradients, true);
  SetASAPCap(gradients, false);
}

//============================================================================
void QueueStore::SetASAPCap(
    OrderedList<Gradient, int64_t>& gradients,
    bool is_ls)
{
  if (!use_anti_starvation_zombies_)
  {
    return;
  }

  // Compute overall max
  int64_t max_gradient     = 0;
  Gradient grad;
  if (gradients.Peek(grad))
  {
    max_gradient = grad.value;
  }
  // \todo This is here to mimic the original ASAP implementation, but it's
  // not clear why we're doing this. (And why <0, not <=0). Needs thought and
  // at least an explanatory comment.
  if (max_gradient < 0)
  {
    max_gradient = 1;
  }

  // This will skim through all the gradients and find the max value for each
  // bin (which could be the gradient to any neighbor).
  max_gradient_set_.Clear(false);
  max_gradient_val_.Clear(0);

  // Find max gradient for this bin
  OrderedList<Gradient, int64_t>::WalkState grad_ws;
  grad_ws.PrepareForWalk();
  Gradient gradient;
  while (gradients.GetNextItem(grad_ws, gradient))
  {
    if ((!max_gradient_set_[gradient.bin_idx]) ||
        (gradient.value > max_gradient_val_[gradient.bin_idx]))
    {
      max_gradient_val_[gradient.bin_idx] = gradient.value;
      max_gradient_set_[gradient.bin_idx] = true;
    }
  }

  // Note that the max gradient will remain 0 if there was no gradient from
  // the forwarding algorithm. This includes bins for which all possible
  // egress links have busy CATs as well as bins for which the gradients to
  // all neighbors are 0 or negative.
  //
  // \todo It's questionable whether this is the right thing to do in that
  // case. If the gradient is 0 or negative, perhaps we do want to add ASAP
  // zombies to build up the gradient to make it positive - because packets
  // may be starved because of a large (potentially lower priority) flow
  // entering at the neighbor node to the same bin. However, if the gradient
  // is missing because all egress links are full, adding ASAP zombies is
  // pretty clearly not the right thing to do.

  // If there's a hysteresis set, then even if the gradient is 0, we will
  // still need queue depths of at least the hysteresis to avoid starvation.
  // This must be done for all unicast and multicast bin indexes.
  BinIndex  idx = 0;

  for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(idx))
  {
    if (max_gradient_val_[idx] <= hysteresis_)
    {
      max_gradient_val_[idx] = hysteresis_ + 1;
    }
    // Now use max_gradient_val_ to hold the initial cap on ASAP additions.
    // Just use the hysteresis + 1 if the max is smaller than this. That will
    // let any bin experiencing starvation add enough zombies to overcome the
    // hysteresis, even if that means jumping past the max gradient.
    if (max_gradient >= hysteresis_)
    {
      max_gradient_val_[idx] = max_gradient - max_gradient_val_[idx];
    }
    if (max_gradient_val_[idx] < 0)
    {
      LogW(kClassName, __func__, "Inconsistency - zombie cap negative\n");
      max_gradient_val_[idx] = 0;
    }
    else if (max_gradient_val_[idx] * 1.05 > UINT32_MAX)
    {
      LogW(kClassName, __func__,
           "Difference in gradients would overflow max uint32\n.");
      max_gradient_val_[idx] = UINT32_MAX;
      q_mgrs_[idx]->SetASAPCap(UINT32_MAX, is_ls);
      return;
    }
    // \todo Why multiply by 1.05 instead of, for instance, adding 1?
    q_mgrs_[idx]->SetASAPCap(
      static_cast<uint32_t>(max_gradient_val_[idx] * 1.05), is_ls);
    LogD(kClassName, __func__, "%sZombie cap set to %" PRIu32 " for bin %s"
         ", max grad is %" PRIi64 ".\n",
         (is_ls ? "LS " : ""),
         static_cast<uint32_t>(max_gradient_val_[idx] * 1.05),
         bin_map_.GetIdToLog(idx).c_str(),
         max_gradient);
  }
}

//============================================================================
void QueueStore::PrintDepths()
{
  // Loop over all unicast or multicast destination bin indexes, printing each
  // set of queue depths.
  BinIndex  idx = 0;

  for (bool valid = bin_map_.GetFirstDstBinIndex(idx);
           valid;
           valid = bin_map_.GetNextDstBinIndex(idx))
  {
    LogD(kClassName, __func__,
         "%s", q_mgrs_[idx]->GetQueueDepths()->ToString().c_str());
  }
}
