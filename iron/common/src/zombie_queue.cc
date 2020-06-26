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

#include "zombie_queue.h"

#include "debugging_stats.h"
#include "log.h"
#include "packet.h"
#include "packet_pool.h"
#include "zombie.h"

#include <cerrno>
#include <cstring>
#include <sstream>

using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Queue;
using ::iron::ZombieQueue;

namespace
{
  const char  kClassName[] = "ZombieQueue";
}

//============================================================================
ZombieQueue::ZombieQueue(PacketPool&  packet_pool,
                         BinMap&      bin_map,
                         bool         is_multicast,
                         LatencyClass lat_class,
                         BinIndex     node_bin_idx,
                         Ipv4Address  dst_addr)
    : Queue(packet_pool),
      bin_map_(bin_map),
      is_multicast_(is_multicast),
      lat_class_(lat_class),
      node_bin_index_(node_bin_idx),
      dst_addr_nbo_(static_cast<uint32_t>(dst_addr.address())),
      zombie_counts_(bin_map)
{
}

//============================================================================
ZombieQueue::~ZombieQueue()
{
}

//============================================================================
Packet* ZombieQueue::Dequeue(uint32_t max_size_bytes, DstVec dst_vec)
{
  uint32_t zombie_len    = max_size_bytes;
  if (zombie_len > kMaxZombieLenBytes)
  {
    zombie_len = kMaxZombieLenBytes;
  }

  DstVec new_dst_vec = 0;
  if (!is_multicast_)
  {
    LogD(kClassName, __func__, "Attempting to dequeue a zombie of size %"
         PRIu32 "B. Queue length is %" PRIu32 "B.\n",
         max_size_bytes, queue_size_);
    if (queue_size_ < kMinZombieLenBytes)
    {
      LogW(kClassName, __func__, "Unable to dequeue a zombie because there "
           "are only %" PRIu32 " Bytes in the queue, and the min zombie size "
           "is %zu.\n", queue_size_, kMinZombieLenBytes);
      return NULL;
    }
    if (zombie_len >= queue_size_)
    {
      // Don't dequeue more than what's left in the queue.
      zombie_len = queue_size_;
    }
  }
  else // is_multicast
  {
    LogD(kClassName, __func__, "Attempting to dequeue a zombie of size %"
         PRIu32 "B with dst vec 0x%x.\n", max_size_bytes, dst_vec);

    // Check the lengths for each destination. Find the min non-zero length
    // so that we can include all non-zero destinations in the packet.
    uint32_t  dst_depth = 0;
    BinIndex  dst_bidx  = 0;
    bool      all_zero  = true;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx))
      {
        dst_depth = zombie_counts_.GetBinDepthByIdx(dst_bidx);
        LogD(kClassName, __func__, "dst %s, depth = %" PRIu32 "\n",
             bin_map_.GetIdToLog(dst_bidx).c_str(), dst_depth);
        if (dst_depth > 0)
        {
          new_dst_vec = bin_map_.AddBinToDstVec(new_dst_vec, dst_bidx);
          all_zero = false;
          if (dst_depth <= zombie_len)
          {
            zombie_len = dst_depth;
          }
        }
      }
    }
    if (all_zero)
    {
      LogD(kClassName, __func__, "No destinations have the minimum zombie "
           "size available to dequeue.\n");
      return NULL;
    }
    LogD(kClassName, __func__, "Actually dequeuing a zombie of size %"
         PRIu32 "\n", zombie_len);
  }

  if (zombie_len < kMinZombieLenBytes)
  {
    zombie_len  = kMinZombieLenBytes;
  }

  // Encode the local node's BinId in a fake IPv4 source address.
  BinId      node_bin_id  = bin_map_.GetPhyBinId(node_bin_index_);
  in_addr_t  src_addr_nbo = htonl((static_cast<in_addr_t>(10) << 24) |
                                  static_cast<in_addr_t>(node_bin_id));

  Packet* zombie = Zombie::CreateNewZombie(
    packet_pool_,
    src_addr_nbo,
    dst_addr_nbo_,
    zombie_len,
    lat_class_);
  if (zombie != NULL)
  {
    zombie->set_dst_vec(new_dst_vec);
    if (!is_multicast_)
    {
      if (queue_size_ > zombie->virtual_length())
      {
        queue_size_ -= zombie->virtual_length();
      }
      else
      {
        queue_size_ = 0;
      }
    }
    else // is_multicast
    {
      // Decrease the counts for appropriate destinations.
      BinIndex dst_bidx = 0;
      // Multicast bins can't be in the destination bit vector.
      for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
           valid;
           valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
      {
        if (bin_map_.IsBinInDstVec(new_dst_vec, dst_bidx))
        {
          zombie_counts_.Decrement(dst_bidx, zombie_len);
          queue_size_ -= zombie_len;
        }
      }
    }
  }
  return zombie;
}

//============================================================================
bool ZombieQueue::Enqueue(Packet* pkt)
{
  if (pkt == NULL)
  {
    LogF(kClassName, __func__,
         "Attempting to enqueue a NULL zombie packet.\n");
    return false;
  }
  if (pkt->GetLatencyClass() != lat_class_)
  {
    LogE(kClassName, __func__, "Attempting to enqueue packet with latency "
         "class %s into ZombieQueue of latency class %s\n",
         LatencyClass_Name[pkt->GetLatencyClass()].c_str(),
         LatencyClass_Name[lat_class_].c_str());
  }

  uint32_t UNUSED(previous) = queue_size_;
  size_t   pkt_size         = pkt->virtual_length();
  if (!is_multicast_)
  {
    if (UINT32_MAX - pkt_size < queue_size_)
    {
      LogE(kClassName, __func__,
           "Attempting to enqueue too many zombies. Have %" PRIu32
           "B, trying to add %zu.\n", queue_size_, pkt_size);
      queue_size_ = UINT32_MAX;
    }
    else
    {
      queue_size_ += pkt_size;
    }
    LogD(kClassName, __func__, "Enqueued a zombie of size %"
         PRIu32 "B. Queue length changed from %" PRIu32 " to %" PRIu32 "B.\n",
         pkt->virtual_length(), previous, queue_size_);
  }
  else // is_multicast
  {
    DstVec  dst_vec = pkt->dst_vec();

    BinIndex dst_bidx = 0;
    // All multicast bins should be empty.
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx))
      {
        // Increment checks internally for overflow.
        zombie_counts_.Increment(dst_bidx, pkt_size);
        queue_size_ += pkt_size;
      }
    }
  }
  packet_pool_.Recycle(pkt);
  pkt = NULL;
  return true;
}

//============================================================================
void ZombieQueue::AddZombieBytes(uint32_t num_bytes, DstVec dst_vec)
{
  LogD(kClassName, __func__, "Attempting to add %" PRIu32 " zombie bytes to "
       "queue for latency class %d. "
       "Virtual queue length is %" PRIu32 "B.\n",
       num_bytes,
       lat_class_, queue_size_);
  if (!is_multicast_)
  {
    if (UINT32_MAX - num_bytes < queue_size_)
    {
      LogE(kClassName, __func__,
         "Attempting to add too many zombies. Have %" PRIu32
           "B, trying to add %" PRIu32 ".\n", queue_size_, num_bytes);
      queue_size_ = UINT32_MAX;
    }
    else
    {
      queue_size_ += num_bytes;
    }
  }
  else // is_multicast
  {
    BinIndex dst_idx = 0;
    // All multicast bins should be empty.
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_idx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_idx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, dst_idx))
      {
        // Increment checks internally for overflow.
        zombie_counts_.Increment(dst_idx, num_bytes);
        queue_size_ += num_bytes;
      }
    }
  }
}

//============================================================================
uint32_t ZombieQueue::DropPacket(uint32_t max_size_bytes, DstVec dst_vec)
{
  uint32_t dropped_bytes = max_size_bytes;
  if (!is_multicast_)
  {
    LogD(kClassName, __func__, "Attempting to drop %" PRIu32
         "B from a zombie queue. Queue length is %" PRIu32 "B.\n",
         max_size_bytes, queue_size_);
    if (queue_size_ == 0)
    {
      return 0;
    }
    if (queue_size_ < dropped_bytes)
    {
      dropped_bytes = queue_size_;
    }
    // Now decrement the overall queue size.
    queue_size_ -= dropped_bytes;
  }
  else // is_multicast
  {
    LogD(kClassName, __func__, "Attempting to dequeue a zombie of size %"
         PRIu32 "B.\n", max_size_bytes);

    // If there's only one destination in the destination bit vector, we can
    // make sure the zombie we dequeue won't leave a dribble of less than the
    // minimum zombie size in the queue. If there are multiple destinations,
    // that's much harder (and still TBD how to do it).

    // Also make sure we aren't dropping more than what exists for
    // any of the specified destinations.
    bool     one_dst  = (BinMap::GetNumBinsInDstVec(dst_vec) == 1);
    bool     all_zero = true;
    BinIndex dst_bidx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx))
      {
        uint32_t avail = zombie_counts_.GetBinDepthByIdx(dst_bidx);
        if (avail > 0)
        {
          all_zero = false;
          if (avail <= dropped_bytes)
          {
            dropped_bytes = avail;
          }
          else if (one_dst &&
                   (avail - dropped_bytes < kMinZombieLenBytes))
          {
            LogW(kClassName, __func__,
                 "Increasing zombie size so we don't leave a dribble.\n");
            // If there's only one destination, and the remaining zombies in
            // the queue after this dequeue would be too small to legally
            // drain later, we should just clear out the queue now.
            dropped_bytes = avail;
          }
        }
        else
        {
          dst_vec = bin_map_.RemoveBinFromDstVec(dst_vec, dst_bidx);
        }
      }
    }
    if (all_zero)
    {
      return 0;
    }
    LogD(kClassName, __func__, "Actually dequeuing a zombie of size %"
         PRIu32 "\n", dropped_bytes);
    // Now we know how many bytes to drop from each bin. Go ahead and drop
    // them.
    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bidx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bidx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, dst_bidx))
      {
        zombie_counts_.Decrement(dst_bidx, dropped_bytes);
        queue_size_ -= dropped_bytes;
      }
    }
  }

  return dropped_bytes;
}

//============================================================================
void ZombieQueue::Purge()
{
  queue_size_ = 0;
  zombie_counts_.ClearAllBins();
}

//============================================================================
size_t ZombieQueue::GetTotalDequeueSize()
{
  if (is_multicast_)
  {
    LogF(kClassName, __func__, "GetTotalDequeueSize MUST take a "
         "BinIndex when called on a multicast queue.\n");
    return 0;
  }
  return queue_size_;
}

//============================================================================
size_t ZombieQueue::GetTotalDequeueSize(BinIndex bin_idx)
{
  if (!is_multicast_)
  {
    LogF(kClassName, __func__, "GetTotalDequeueSize MUST NOT take a "
         "BinIndex when called on a unicast queue.\n");
    return 0;
  }
  return zombie_counts_.GetBinDepthByIdx(bin_idx);
}

//============================================================================
size_t ZombieQueue::GetNextDequeueSize()
{
  if (is_multicast_)
  {
    LogF(kClassName, __func__, "GetNextDequeueSize MUST take a "
         "BinIndex when called on a multicast queue.\n");
    return 0;
  }
  if (queue_size_ <= 0)
  {
    // If the queue size is 0, we cannot dequeue anything.
    return 0;
  }

  size_t  dequeue_size  = queue_size_;

  if (queue_size_ > kMaxZombieLenBytes)
  {
    // Cap the dequeue to maximum.
    dequeue_size = kMaxZombieLenBytes;
  }

  size_t  min_size  = sizeof(struct iphdr);

  if (dequeue_size < min_size)
  {
    // If the queue size is less than the header, we will dequeue a header size
    // worth.
    return min_size;
  }
  else
  {
    return dequeue_size;
  }
}

//============================================================================
size_t ZombieQueue::GetNextDequeueSize(BinIndex bin_idx)
{
  if (!is_multicast_)
  {
    LogF(kClassName, __func__, "GetNextDequeueSize MUST NOT take a "
         "BinIndex when called on a unicast queue.\n");
    return 0;
  }
  uint32_t depth = zombie_counts_.GetBinDepthByIdx(bin_idx);
  if (depth == 0)
  {
    // If the queue size is 0, we cannot dequeue anything.
    return 0;
  }

  size_t  dequeue_size  = depth;

  if (depth > kMaxZombieLenBytes)
  {
    // Cap the dequeue to maximum.
    dequeue_size = kMaxZombieLenBytes;
  }

  if (dequeue_size <= kMinZombieLenBytes)
  {
    // If the queue size is less than the header, we will dequeue a header size
    // worth.
    return kMinZombieLenBytes;
  }
  else
  {
    return dequeue_size;
  }
}

//============================================================================
std::string ZombieQueue::ToString()
{
  std::stringstream str;

  // Note: this doesn't print per-destination counts.
  str << queue_size_ << "B";

  return str.str();
}
