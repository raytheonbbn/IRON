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

#include "queue_depths.h"

#include "log.h"
#include "queue_depths_shm_stats.h"
#include "shared_memory.h"

#include <sstream>

#include <arpa/inet.h>
#include <cstring>
#include <inttypes.h>
#include <limits>
#include <unistd.h>

using ::iron::QueueDepths;
using ::iron::Time;
using ::std::string;

namespace
{
  const char      kClassName[] = "QueueDepths";
  const uint16_t  kLoopSeq     = 128;
  const uint32_t  kMaxSeq      = 65535;
}

//============================================================================
QueueDepths::QueueDepths(BinMap& bin_map)
    : bin_map_(bin_map),
      access_shm_directly_(false),
      local_ls_queue_depths_(),
      local_queue_depths_(),
      shm_if_(NULL),
      shm_queue_depths_(),
      shm_stats_(NULL)
{
  // TODO: These initializations should be inside of an Initialize() method,
  // not the constructor, as they can fail.
  if (!local_ls_queue_depths_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize local latency-sensitive "
         "queue depths array.\n");
  }
  local_ls_queue_depths_.Clear(0);

  // TODO: The initialization of local_queue_depths_ is not necessary if using
  // shared memory.  However, the APIs do not allow avoiding this call (and
  // the associated memory allocations) when using shared memory, as there is
  // no "normal" initialization method.  There really should be two different
  // flavors of initialization methods, one for local memory direct access and
  // one for shared memory direct access.  Note than a complication for all of
  // this is the need to have GetShmSize() working properly before a call to
  // InitializeShmDirectAccess() can be made.
  if (!local_queue_depths_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize local queue depths "
         "array.\n");
  }
  local_queue_depths_.Clear(0);

  // Note that this initialization has to occur here in order for the
  // GetShmSize() to work properly before calls to InitializeShmDirectAccess()
  // can be made.
  if (!shm_queue_depths_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize shared memory queue "
         "depths array.\n");
  }
}

//============================================================================
QueueDepths::~QueueDepths()
{
  if (shm_stats_ != NULL)
  {
    delete shm_stats_;
    shm_stats_ = NULL;
  }
}

//============================================================================
bool QueueDepths::InitializeShmDirectAccess(SharedMemoryIF* shm)
{
  uint32_t  wait_count = 0;

  if (shm == NULL)
  {
    return false;
  }

  // Wait until the shared memory is initialized, as required by
  // SetShmDirectAccess().
  while (!shm->IsInitialized())
  {
    sleep(1);
    ++wait_count;

    if (wait_count % 10 == 0)
    {
      if (wait_count % 120 == 0)
      {
        LogW(kClassName, __func__, "... Still trying to attach to shared "
             "memory queue depths (%" PRIu32 " s).\n", wait_count);
      }
      else
      {
        LogD(kClassName, __func__, "... Waiting to attach to shared memory "
             "queue depths.\n");
      }
    }
  }

  // Set up the shared memory queue depths array to point to the shared memory
  // segment.
  if (!shm_queue_depths_.SetShmDirectAccess(*shm))
  {
    LogE(kClassName, __func__, "Unable to set shared memory direct access on "
         "queue depths array.\n");
    return false;
  }

  // Clear the shared memory queue depths.
  shm_queue_depths_.Clear(0);

  // Update to use shared memory directly.
  access_shm_directly_ = true;
  shm_if_              = shm;

  return true;
}

//============================================================================
bool QueueDepths::InitializeShmStats()
{
#ifdef SHM_STATS
  if (shm_stats_ == NULL)
  {
    shm_stats_ = new (std::nothrow) QueueDepthsShmStats(bin_map_);

    if (shm_stats_ == NULL)
    {
      LogW(kClassName, __func__, "Unable to create QueueDepthsShmStats.\n");
      return false;
    }
  }
#endif /* SHM_STATS */

  return true;
}

//============================================================================
uint32_t QueueDepths::GetBinDepthByIdx(BinIndex bin_idx,
                                       LatencyClass lat) const
{
  if (access_shm_directly_)
  {
    uint32_t  depth = 0;

    shm_if_->Lock();
    depth = shm_queue_depths_[bin_idx];
    shm_if_->Unlock();

    return depth;
  }

  if (Packet::IsLatencySensitive(lat))
  {
    return local_ls_queue_depths_[bin_idx];
  }

  return local_queue_depths_[bin_idx];
}

//============================================================================
void iron::QueueDepths::SetBinDepthByIdx(iron::BinIndex bin_idx,
                                         uint32_t depth,
                                         iron::LatencyClass lat)
{
  if (access_shm_directly_)
  {
    shm_if_->Lock();
    shm_queue_depths_[bin_idx] = depth;
    shm_if_->Unlock();
  }
  else
  {
    if (Packet::IsLatencySensitive(lat))
    {
      local_ls_queue_depths_[bin_idx] = depth;
    }
    else
    {
      local_queue_depths_[bin_idx] = depth;
    }
  }

#ifdef SHM_STATS
  if (shm_stats_ != NULL)
  {
    shm_stats_->DepthChanged(bin_idx, depth);
  }
#endif /* SHM_STATS */
}

//============================================================================
void QueueDepths::AdjustByAmt(BinIndex bin_idx, int64_t amt_bytes,
                              int64_t ls_amt_bytes)
{
  if (amt_bytes > 0)
  {
    Increment(bin_idx, amt_bytes, ls_amt_bytes);
  }
  else if (amt_bytes < 0)
  {
    Decrement(bin_idx, -amt_bytes, -ls_amt_bytes);
  }
}

//============================================================================
void QueueDepths::Increment(BinIndex bin_idx, uint32_t incr_amt_bytes,
                            uint32_t ls_incr_amt_bytes)
{
  if (ls_incr_amt_bytes > incr_amt_bytes)
  {
    LogF(kClassName, __func__, "Latency-sensitive adjustment amount %" PRIu32
         "B cannot be more than normal latency adjustment amount %" PRIu32
         "B.\n", ls_incr_amt_bytes, incr_amt_bytes);
    return;
  }

  // Note that there is no need to check the latency-sensitive (LS) queue
  // depths for overflow, because we maintain the invariant that LS queue
  // depth < NORMAL queue depth, and we already checked that we aren't
  // incrementing LS by more than we're incrementing NORMAL.

  IntLock();

#ifdef SHM_STATS
  bool  updated = false;
#endif /* SHM_STATS */

  uint32_t  curr_depth = IntGet(bin_idx);

  if ((UINT32_MAX - incr_amt_bytes) < curr_depth)
  {
    LogD(kClassName, __func__, "Unable to increment Queue depth for bin %s "
         "by %" PRIu32 " because current depth (%" PRIu32 ") is too large.\n",
         bin_map_.GetIdToLog(bin_idx).c_str(), incr_amt_bytes, curr_depth);
    IntSet(bin_idx, UINT32_MAX);
  }
  else
  {
    IntSet(bin_idx, (curr_depth + incr_amt_bytes));
    local_ls_queue_depths_[bin_idx] += ls_incr_amt_bytes;

#ifdef SHM_STATS
    updated = true;
#endif /* SHM_STATS */
  }

  IntUnlock();

#ifdef SHM_STATS
  if ((shm_stats_ != NULL) && updated)
  {
    shm_stats_->DepthChanged(bin_idx, (curr_depth + incr_amt_bytes));
  }
#endif /* SHM_STATS */
}

//============================================================================
void QueueDepths::Decrement(BinIndex bin_idx, uint32_t decr_amt_bytes,
                            uint32_t ls_decr_amt_bytes)
{
  if (ls_decr_amt_bytes > decr_amt_bytes)
  {
    LogF(kClassName, __func__, "Latency-sensitive adjustment amount %" PRIu32
         "B cannot be more than normal latency adjustment amount %" PRIu32
         "B.\n", ls_decr_amt_bytes, decr_amt_bytes);
    return;
  }

  IntLock();

  uint32_t  curr_depth = IntGet(bin_idx);

  // Since queue depths are unsigned, make sure we don't wrap.
  if (decr_amt_bytes > curr_depth)
  {
    LogW(kClassName, __func__, "Attempting to decrement queue depth for Bin "
         "%s  below 0 from %" PRIu32 "B.\n",
         bin_map_.GetIdToLog(bin_idx).c_str(), curr_depth);
    IntSet(bin_idx, 0);
    curr_depth = 0;
  }
  else
  {
    IntSet(bin_idx, (curr_depth - decr_amt_bytes));
    curr_depth -= decr_amt_bytes;
  }

  IntUnlock();

  // Need to check LS overflow separately, because LS depth is less than full
  // depth.
  uint32_t  ls_curr_depth = local_ls_queue_depths_[bin_idx];

  if (ls_decr_amt_bytes > ls_curr_depth)
  {
    LogW(kClassName, __func__, "Attempting to decrement LS queue depth for "
         "Bin %s below 0 from %" PRIu32 "B.\n",
         bin_map_.GetIdToLog(bin_idx).c_str(), ls_curr_depth);
    local_ls_queue_depths_[bin_idx] = 0;
  }
  else
  {
    local_ls_queue_depths_[bin_idx] = (ls_curr_depth - ls_decr_amt_bytes);
  }

#ifdef SHM_STATS
  if (shm_stats_ != NULL)
  {
    shm_stats_->DepthChanged(bin_idx, curr_depth);
  }
#endif /* SHM_STATS */
}

//============================================================================
void QueueDepths::ClearAllBins()
{
  BinIndex  bin_idx = 0;

  IntLock();

  for (bool more_bin_idx = bin_map_.GetFirstBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_.GetNextBinIndex(bin_idx))
  {
    IntSet(bin_idx, 0);
    local_ls_queue_depths_[bin_idx] = 0;
  }

  IntUnlock();
}

//============================================================================
uint32_t QueueDepths::GetNumNonZeroQueues() const
{
  BinIndex bin_idx  = 0;
  uint32_t depth    = 0;
  uint32_t num_bins = 0;

  IntLock();

  // Count bins that exist and are greater than 0.
  for (bool more_bin_idx = bin_map_.GetFirstUcastBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_.GetNextUcastBinIndex(bin_idx))
  {
    depth = IntGet(bin_idx);

    if (depth > 0)
    {
      ++num_bins;
    }
  }

  IntUnlock();

  return num_bins;
}

//============================================================================
size_t QueueDepths::Serialize(uint8_t* buf, size_t max_len,
                              uint8_t& num_pairs)
{
  size_t    length        = 0;
  uint32_t  bin_depth_nbo = 0;

  num_pairs = 0;

  if (access_shm_directly_)
  {
    LogF(kClassName, __func__, "Cannot call Serialize on a shared memory "
         "direct access queue depths object.\n");
    return 0;
  }

  // Check that a buffer has been specified.
  if (buf == NULL)
  {
    LogE(kClassName, __func__, "Missing buffer.\n");
    return 0;
  }

  // Add all of the (bin,depth,ls_depth) tuples.
  BinIndex  bin_idx = 0;

  for (bool more_bin_idx = bin_map_.GetFirstUcastBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_.GetNextUcastBinIndex(bin_idx))
  {
    BinId     bin_id   = bin_map_.GetPhyBinId(bin_idx);
    uint32_t  depth    = local_queue_depths_[bin_idx];
    uint32_t  ls_depth = local_ls_queue_depths_[bin_idx];

    if (depth < ls_depth)
    {
      LogD(kClassName, __func__, "LS queue depths %" PRIu32 "B is larger "
           "than all queue depths %" PRIu32 "B, wrong if not HvyBall or "
           "EWMA.\n", ls_depth, depth);
    }

    if ((depth + ls_depth) == 0)
    {
      continue;
    }

    // Verify that this addition will not go off of the end of the buffer.
    // Given the checks above, this should never happen.
    // Dest bin id: 1B, Queue Depth: 4B, LS Queue Depth: 4B.
    if ((length + sizeof(uint8_t) + (2 * sizeof(uint32_t))) > max_len)
    {
      LogW(kClassName, __func__, "Serialization of %" PRIu8 "th group would "
           "overshoot max length %zuB.  Fail.\n", (num_pairs + 1), max_len);
      return 0;
    }

    // Copy the destination bin id.
    *buf = static_cast<uint8_t>(bin_id);
    buf    += sizeof(uint8_t);
    length += sizeof(uint8_t);

    // Copy in the bin depth in bytes.
    bin_depth_nbo = htonl(depth);
    std::memcpy(buf, &bin_depth_nbo, sizeof(bin_depth_nbo));
    buf    += sizeof(bin_depth_nbo);
    length += sizeof(bin_depth_nbo);

    // Copy in the latency-sensitive-only bin depth in bytes.
    bin_depth_nbo = htonl(ls_depth);
    std::memcpy(buf, &bin_depth_nbo, sizeof(bin_depth_nbo));
    buf    += sizeof(bin_depth_nbo);
    length += sizeof(bin_depth_nbo);

    ++num_pairs;

    LogD(kClassName, __func__, "Bin ID %" PRIBinId " (Index %" PRIBinIndex
         ", translates to %s) depth: %" PRIu32 "B ls-depth: %" PRIu32
         "B added to QLAM.\n", bin_id, bin_idx,
         bin_map_.GetIdToLog(bin_idx).c_str(), depth, ls_depth);
  }

  return length;
}

//============================================================================
size_t QueueDepths::Deserialize(const uint8_t *buf, size_t len,
                                uint8_t num_pairs)
{
  uint8_t   dst_bin_id  = 0;
  BinIndex  dst_bin_idx = 0;
  uint32_t  q_depth     = 0;
  uint32_t  ls_q_depth  = 0;
  size_t    length      = 0;

  if (access_shm_directly_)
  {
    LogF(kClassName, __func__, "Cannot call Deserialize on a shared memory "
         "direct access queue depths object.\n");
    return 0;
  }

  // Check that a buffer has been specified.
  if (buf == NULL)
  {
    LogE(kClassName, __func__, "Missing buffer.\n");
    return 0;
  }

  if (num_pairs == 0)
  {
    LogD(kClassName, __func__, "Deserializing queue depth with 0 pairs.\n");
  }

  // Check that the number of pairs matches the buffer length given.
  // There are 1B dest bin id, 4B queue depth, 4B LS queue depth per pair.
  if (len < (length + (num_pairs * (sizeof(uint8_t) + sizeof(uint32_t) +
                                    sizeof(uint32_t)))))
  {
    LogE(kClassName, __func__, "%" PRIu8 " (dst bin id, depth) pairs would "
         "exceed remaining buffer length %zuB.\n", num_pairs, len);
    return 0;
  }

  // It is a new QLAM, so clear all (bin,depth,ls_depth) tuple in the object.
  local_queue_depths_.Clear(0);

  // Parse the remainder of the buffer to get the (bin,depth) pairs.
  for (uint16_t num_bins_created = 0; num_bins_created < num_pairs;
       ++num_bins_created)
  {
    // Verify that this parsing will not go off of the end of the buffer.
    // Given the checks above, this should never happen.
    if (len < (length + sizeof(uint8_t) + sizeof(uint32_t) +
               sizeof(uint32_t)))
    {
      LogF(kClassName, __func__, "Max length %zuB exceeded after %" PRIu16
           " pairs with %zuB.\n", len, num_bins_created,
           (length + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t)));
      return 0;
    }

    // Read the destination bin.  Note that these are all destination bins,
    // not multicast group bins, since Deserialize is called once we're inside
    // the portion of the QLAM for a single multicast group.
    dst_bin_id = *buf;
    buf       += sizeof(dst_bin_id);
    length    += sizeof(dst_bin_id);

    // Read the queue depth for this destination.
    std::memcpy(&q_depth, buf, sizeof(q_depth));
    q_depth = ntohl(q_depth);
    buf    += sizeof(q_depth);
    length += sizeof(q_depth);

    // Read the LS queue depth for this destination.
    std::memcpy(&ls_q_depth, buf, sizeof(ls_q_depth));
    ls_q_depth  = ntohl(ls_q_depth);
    buf        += sizeof(ls_q_depth);
    length     += sizeof(ls_q_depth);

    // Make sure the bin exists.
    dst_bin_idx = bin_map_.GetPhyBinIndex(dst_bin_id);

    if ((dst_bin_idx == kInvalidBinIndex) ||
        (!bin_map_.IsUcastBinIndex(dst_bin_idx)))
    {
      LogW(kClassName, __func__, "Invalid unicast bin_id %" PRIu32 ".\n",
           dst_bin_id);
    }
    else
    {
      if (ls_q_depth > q_depth)
      {
        LogD(kClassName, __func__, "Latency-sensitive-only depth %" PRIu32
             "B is larger than overall depth %" PRIu32 "B in QLAM for bin id "
             "%" PRIu8 ", wrong if not HvyBall or EWMA.\n", ls_q_depth,
             q_depth, dst_bin_id);
      }

      local_queue_depths_[dst_bin_idx]    = q_depth;
      local_ls_queue_depths_[dst_bin_idx] = ls_q_depth;

      LogD(kClassName, __func__, "Dest bin id %" PRIBinId ": Q Depth: %"
           PRIu32 "B | LS Q Depth: %" PRIu32 "B.\n", dst_bin_id, q_depth,
           ls_q_depth);
    }
  }

  return length;
}

//============================================================================
bool QueueDepths::CopyToShm(SharedMemoryIF& shared_memory)
{
  if (access_shm_directly_)
  {
    LogF(kClassName, __func__, "Cannot copy to shared memory on a shared "
         "memory direct access queue depths object.\n");
    return false;
  }

  if (!local_queue_depths_.CopyToShm(shared_memory))
  {
    LogW(kClassName, __func__, "Failed to copy queue depths to shared "
         "memory.\n");
    return false;
  }

  LogD(kClassName, __func__, "Copied queue depths to shared memory (%zuB).\n",
       local_queue_depths_.GetMemorySizeInBytes());

#ifdef SHM_STATS
  if (shm_stats_ != NULL)
  {
    shm_stats_->ValuesShared(this);
  }
#endif /* SHM_STATS */

  return true;
}

//============================================================================
bool QueueDepths::CopyFromShm(SharedMemoryIF& shared_memory)
{
  if (access_shm_directly_)
  {
    LogF(kClassName, __func__, "Cannot copy from shared memory on a shared "
         "memory direct access queue depths object.\n");
    return false;
  }

  if (!local_queue_depths_.CopyFromShm(shared_memory))
  {
    LogW(kClassName, __func__, "Failed to copy queue depths from shared "
         "memory.\n");
    return false;
  }

  LogD(kClassName, __func__, "Read queue depths from shared memory (%zuB).\n",
       local_queue_depths_.GetMemorySizeInBytes());

  return true;
}

//============================================================================
string QueueDepths::StatDump() const
{
  std::stringstream  ret_ss;

  IntLock();

  BinIndex  bin_idx = 0;

  // Append the bin:depth tuples in a long string.  All multicast bins should
  // be empty.
  bool add_comma = false;
  for (bool more_bin_idx = bin_map_.GetFirstUcastBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_.GetNextUcastBinIndex(bin_idx))
  {
    BinId     bin_id = bin_map_.GetPhyBinId(bin_idx);
    uint32_t  depth  = IntGet(bin_idx);

    if (add_comma)
    {
      ret_ss << ",";
    }
    add_comma = true;
    
    ret_ss << "(Bin " << static_cast<uint16_t>(bin_id) << ":" << depth
           << "B)";
  }

  IntUnlock();

  return ret_ss.str();
}

//============================================================================
string QueueDepths::ToString() const
{
  std::stringstream  ret_ss;

  ret_ss << "Printing queue depths\n";
  ret_ss << "+--------------------------------------------+\n";
  ret_ss << "| Bin Id\t|  Depth\t|  LS Depth\n";
  ret_ss << "+--------------------------------------------+\n";

  BinIndex  bin_idx = 0;

  IntLock();

  for (bool more_bin_idx = bin_map_.GetFirstUcastBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_.GetNextUcastBinIndex(bin_idx))
  {
    BinId     bin_id    = bin_map_.GetPhyBinId(bin_idx);
    uint32_t  depth     = IntGet(bin_idx);
    uint32_t  ls_depth  = local_ls_queue_depths_[bin_idx];

    ret_ss << "| " << static_cast<int>(bin_id) << "\t\t|    " << depth
           << "\t\t|      " << ls_depth << "\n";
  }

  IntUnlock();

  ret_ss << "+--------------------------------------------+\n";

#ifdef SHM_STATS
  if (shm_stats_ != NULL)
  {
    ret_ss << shm_stats_->ToString();
  }
#endif /* SHM_STATS */

  return ret_ss.str();
}

//============================================================================
string QueueDepths::ToQdDict() const
{
  std::stringstream  ret_ss;

  ret_ss << "Current QueueDepths:: {";

  IntLock();

  size_t    x           = 0;
  uint32_t  num_bin_ids = bin_map_.GetNumUcastBinIds();
  BinIndex  bin_idx     = 0;

  // All multicast bins should be empty.
  for (bool more_bin_idx = bin_map_.GetFirstUcastBinIndex(bin_idx);
       more_bin_idx;
       more_bin_idx = bin_map_.GetNextUcastBinIndex(bin_idx))
  {
    BinId     bin_id = bin_map_.GetPhyBinId(bin_idx);
    uint32_t  depth  = IntGet(bin_idx);

    ret_ss << static_cast<uint16_t>(bin_id) << ":" << depth;
    ++x;

    if (x < num_bin_ids)
    {
      ret_ss << ", ";
    }
  }

  IntUnlock();

  ret_ss << "}\n";

  return ret_ss.str();
}
