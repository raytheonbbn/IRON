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

#include "packet_queue.h"

#include "log.h"
#include "debugging_stats.h"
#include "packet.h"
#include "packet_pool.h"

#include <cerrno>
#include <cstring>
#include <sstream>

using ::iron::Queue;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketQueue;
using ::iron::Time;

namespace
{
  const char  kClassName[] = "PacketQueue";
}

//============================================================================
iron::PacketQueue::PacketQueue(iron::PacketPool& packet_pool, bool ordered)
    : Queue(packet_pool),
      queue_(), ordered_queue_(),
      queue_walk_state_(ordered),
      is_ordered_(ordered),
      elem_count_(0),
      size_limit_(DEFAULT_QUEUE_SIZE_LIMIT),
      drop_policy_(DEFAULT_DROP_POLICY)
{}

//============================================================================
iron::PacketQueue::PacketQueue(iron::PacketPool& packet_pool, uint32_t sl,
                               DropPolicy drop, bool ordered)
    : Queue(packet_pool),
      queue_(), ordered_queue_(),
      queue_walk_state_(ordered),
      is_ordered_(ordered),
      elem_count_(0),
      size_limit_(sl), drop_policy_(drop)
{}

//============================================================================
PacketQueue::~PacketQueue()
{
  // Remove all elements from the queue.
  while (elem_count_)
  {
    DropPacket(true);
  }
}

//============================================================================
void PacketQueue::PrepareQueueIterator()
{
  queue_walk_state_.PrepareForWalk();
}

//============================================================================
Packet* PacketQueue::PeekNextPacket(QueueWalkState& qws)
{
  Packet* pkt     = NULL;
  qws.is_ordered_ = is_ordered_;

  if (!is_ordered_)
  {
    queue_.GetNextItem(queue_walk_state_.ws_, pkt);
    qws.ws_ = queue_walk_state_.ws_;
  }
  else
  {
    ordered_queue_.GetNextItem(queue_walk_state_.ordered_ws_, pkt);
    qws.ordered_ws_ = queue_walk_state_.ordered_ws_;
  }

  return pkt;
}

//============================================================================
PacketQueue::QueueWalkState PacketQueue::GetFrontIterator()
{
  QueueWalkState  qws(is_ordered_);
  qws.PrepareForWalk();
  Packet* pkt = NULL;

  if (elem_count_ > 0)
  {
    if (!is_ordered_)
    {
      queue_.GetNextItem(qws.ws_, pkt);
    }
    else
    {
      ordered_queue_.GetNextItem(qws.ordered_ws_, pkt);
    }

  }

  return qws;
}

//============================================================================
PacketQueue::QueueWalkState PacketQueue::GetIterator(Packet* search_pkt)
{
  QueueWalkState  qws(is_ordered_);
  qws.PrepareForWalk();

  Packet* pkt = NULL;

  if (!is_ordered_)
  {
    while (queue_.GetNextItem(qws.ws_, pkt))
    {
      if (pkt == search_pkt)
      {
        break;
      }
    }
  }
  else
  {
    while (ordered_queue_.GetNextItem(qws.ordered_ws_, pkt))
    {
      if (pkt == search_pkt)
      {
        break;
      }
    }
  }

  return qws;
}

//============================================================================
Packet* PacketQueue::Peek()
{
  Packet* pkt = NULL;

  if (elem_count_ > 0)
  {
    if (!is_ordered_)
    {
      queue_.Peek(pkt);
    }
    else
    {
      ordered_queue_.Peek(pkt);
    }
  }

  return pkt;
}

//============================================================================
iron::Packet* iron::PacketQueue::PeekAtIterator(QueueWalkState& qws)
{
  Packet* pkt = NULL;

  if (qws.is_ordered_ != is_ordered_)
  {
    LogF(kClassName, __func__,
         "%s iterator does not match queue order %s.\n",
         qws.is_ordered_ ? "Ordered" : "Unordered",
         is_ordered_ ? "ordered" : "unordered");
    return NULL;
  }

  if (elem_count_ > 0)
  {
    if (!qws.IsNULL())
    {
      if (!is_ordered_)
      {
        queue_.PeekAt(qws.ws_, pkt);
      }
      else
      {
        ordered_queue_.PeekAt(qws.ordered_ws_, pkt);
      }
    }
    else
    {
      LogF(kClassName, __func__,
           "Saved iterator is at end of queue, cannot peek.  Possible "
           "queue corruption.\n");
      return NULL;
    }
  }

  return pkt;
}

//============================================================================
Packet* iron::PacketQueue::Dequeue(uint32_t max_size_bytes, DstVec dst_vec)
{
  if (dst_vec != 0)
  {
    LogF(kClassName, __func__, "Dequeue cannot be called with a DstVec "
         "except on Packetless Zombie queues.\n");
    return NULL;
  }
  Packet* pkt = NULL;

  if (elem_count_ > 0)
  {
    if (!is_ordered_)
    {
      queue_.Peek(pkt);
    }
    else
    {
      ordered_queue_.Peek(pkt);
    }
    if (!pkt)
    {
      LogF(kClassName, __func__,
           "Peeked failed, most likely looking at wrong ordered / reg queue.\n");
      return NULL;
    }

    if (pkt->virtual_length() > max_size_bytes)
    {
      // For now, just log this, since this is a new check that may or may not
      // pass.
      LogE(kClassName, __func__, "Attempting to dequeue a too-big packet. "
           "Max size requested is %" PRIu32 ", packet length is %zu.\n",
           max_size_bytes, pkt->virtual_length());
    }
    if (!is_ordered_)
    {
      queue_.Pop(pkt);
    }
    else
    {
      ordered_queue_.Pop(pkt);
    }

    // If there was a packet, decrease the packet counter and the size
    // recorded for the queue.
    if (pkt == NULL)
    {
      LogF(kClassName, __func__, "Dequeued packet is NULL.\n");
    }
    else
    {
      elem_count_--;
      if (pkt->virtual_length() != 0)
      {
        queue_size_ -= pkt->virtual_length();
      }
      else
      {
        queue_size_ -= pkt->GetLengthInBytes();
      }
    }
  }

  return pkt;
}

//============================================================================
iron::Packet* iron::PacketQueue::DequeueAtIterator()
{
  return DequeueAtIterator(queue_walk_state_);
}

//============================================================================
iron::Packet* iron::PacketQueue::DequeueAtIterator(QueueWalkState& qws)
{
  Packet* pkt = NULL;

  if (qws.is_ordered_ != is_ordered_)
  {
    LogF(kClassName, __func__,
         "%s iterator does not match queue order %s.\n",
         qws.is_ordered_ ? "Ordered" : "Unordered",
         is_ordered_ ? "ordered" : "unordered");
    return NULL;
  }

  if (elem_count_ > 0)
  {
    if (!qws.IsNULL())
    {
      if (!is_ordered_)
      {
        queue_.PopAt(qws.ws_, pkt);
      }
      else
      {
        ordered_queue_.PopAt(qws.ordered_ws_, pkt);
      }
    }
    else
    {
      LogF(kClassName, __func__,
           "Saved iterator is at end of queue, cannot dequeue.  Possible "
           "queue corruption.\n");
    }

    // If there was a packet, decrease the packet counter and the size
    // recorded for the queue.
    if (pkt == NULL)
    {
      LogF(kClassName, __func__, "Dequeued packet is NULL.\n");
    }
    else
    {
      elem_count_--;
      if (pkt->virtual_length() != 0)
      {
        queue_size_ -= pkt->virtual_length();
      }
      else
      {
        queue_size_ -= pkt->GetLengthInBytes();
      }
    }
  }

  return pkt;
}

//============================================================================
bool PacketQueue::Enqueue(Packet* pkt)
{
  if (pkt == NULL)
  {
    LogF(kClassName, __func__, "Attempting to enqueue a NULL packet.\n");
    return false;
  }

  // Check if the queue is full.  If it is, then attempt to drop a packet.
  if (elem_count_ >= size_limit_)
  {
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    if (DropPacket(false) == 0)
    {
      // Could not drop a packet, so the enqueue must fail.
      return false;
    }
  }

  // Add the packet to the back of the queue.
  if (is_ordered_)
  {
    ordered_queue_.Push(pkt, pkt->GetOrderTime());
  }
  else
  {
    queue_.Push(pkt);
  }

  // And increment the queued item count and queue size.
  elem_count_++;

  if (pkt->virtual_length() != 0)
  {
    queue_size_ += pkt->virtual_length();
  }
  else
  {
    queue_size_ += pkt->GetLengthInBytes();
  }

  return true;
}

//============================================================================
void PacketQueue::SetQueueLimits(uint32_t sl)
{
  // Set the size limit.  Treat a limit of zero as the default limit.
  if (sl < 1)
  {
    size_limit_ = DEFAULT_QUEUE_SIZE_LIMIT;
  }
  else
  {
    size_limit_ = sl;
  }

  // Drop packets as needed to meet the new size limit.
  while (elem_count_ >= size_limit_)
  {
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    DropPacket(true);
  }
}

//============================================================================
void PacketQueue::Purge()
{
  // Drop all packets, regardless of the current drop policy.
  while (elem_count_)
  {
    DropPacket(true);
  }
}

//============================================================================
size_t PacketQueue::GetNextDequeueSize()
{
  size_t    pkt_size  = 0;
  Packet*   pkt       = NULL;

  if (elem_count_ > 0)
  {
    if (!is_ordered_)
    {
      queue_.Peek(pkt);
    }
    else
    {
      ordered_queue_.Peek(pkt);
    }

    if (pkt->virtual_length() != 0)
    {
      pkt_size  = pkt->virtual_length();
    }
    else
    {
      pkt_size = pkt->GetLengthInBytes();
    }
  }

  return pkt_size;
}

//============================================================================
size_t PacketQueue::GetNextDequeueSize(BinIndex bin_idx)
{
  LogF(kClassName, __func__, "GetNextDequeueSize(BinIndex) is not implemented"
       " for real packet queues.\n");
  return 0;
}

//============================================================================
size_t PacketQueue::GetTotalDequeueSize(BinIndex bin_idx)
{
  LogF(kClassName, __func__, "GetTotalDequeueSize(BinIndex) is not implemented"
       " for real packet queues.\n");
  return 0;
}

//============================================================================
uint32_t PacketQueue::DropPacket(bool force_drop)
{
  Packet* pkt = NULL;

  switch (drop_policy_)
  {
    case HEAD:
      if (!is_ordered_)
      {
        queue_.Pop(pkt);
      }
      else
      {
        ordered_queue_.Pop(pkt);
      }
      break;

    case TAIL:
      if (!is_ordered_)
      {
        queue_.PopBack(pkt);
      }
      else
      {
        ordered_queue_.PopBack(pkt);
      }
      break;

    case NO_DROP:
      // Do not drop a packet unless the force_drop argument is true, in which
      // case a head drop is performed.
      if (force_drop)
      {
        if (!is_ordered_)
        {
          queue_.Pop(pkt);
        }
        else
        {
          ordered_queue_.Pop(pkt);
        }
      }
      break;

    default:
      LogF(kClassName, __func__, "Undefined drop policy: %d\n",
           static_cast<int>(drop_policy_));
  }

  uint32_t dropped_bytes = 0;
  if (pkt)
  {
    // Update the packet counter and the byte counter.
    elem_count_--;
    if (pkt->virtual_length() != 0)
    {
      dropped_bytes = pkt->virtual_length();
    }
    else
    {
      dropped_bytes = pkt->GetLengthInBytes();
    }
    queue_size_ -= dropped_bytes;

    // Delete the packet.
    packet_pool_.Recycle(pkt);
  }

  return dropped_bytes;
}

//============================================================================
void PacketQueue::Print()
{
  QueueWalkState    qws(is_ordered_);
  std::stringstream str;
  str << "Elems: ";

  LogD(kClassName, __func__,
       "Queue %p: %" PRIu32 "els, %" PRIu32 "B.\n",
       this, elem_count_, queue_size_);

  qws.PrepareForWalk();
  Packet* pkt = NULL;

  if (!is_ordered_)
  {
    while (queue_.GetNextItem(qws.ws_, pkt))
    {
      str << "[" << (void*)pkt << "]";
    }
  }
  else
  {
    while (ordered_queue_.GetNextItem(qws.ordered_ws_, pkt))
    {
      str << "[" << (void*)pkt << "(" << pkt->GetOrderTime().ToString() << ")]";
    }
  }
  LogD(kClassName, __func__,
       "%s.\n", str.str().c_str());
}

//============================================================================
std::string PacketQueue::ToString()
{
  std::stringstream str;

  str << queue_size_ << "B";

  return str.str();
}
