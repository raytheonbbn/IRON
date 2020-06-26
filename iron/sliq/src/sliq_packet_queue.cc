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

#include "sliq_packet_queue.h"

#include "log.h"

using ::sliq::DequeueRule;
using ::sliq::DropRule;
using ::sliq::PacketQueue;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;


namespace
{
  const char*  kClassName = "PacketQueue";
}


//============================================================================
PacketQueue::PacketQueue(PacketPool& packet_pool, size_t max_size_pkts,
                         DequeueRule dequeue_rule, DropRule drop_rule)
    : pkt_pool_(packet_pool), max_cnt_(max_size_pkts), cnt_(0), size_(0),
      head_(0), dequeue_rule_(dequeue_rule), drop_rule_(drop_rule),
      queue_(NULL)
{
  if (max_size_pkts == 0)
  {
    LogF(kClassName, __func__, "Invalid queue size 0.\n");
  }

  queue_ = new (std::nothrow) QueueElement[max_size_pkts];

  if (queue_ == NULL)
  {
    LogF(kClassName, __func__, "Queue allocation error.\n");
  }
}

//============================================================================
PacketQueue::~PacketQueue()
{
  Purge();

  if (queue_ != NULL)
  {
    delete [] queue_;
    queue_ = NULL;
  }
}

//============================================================================
bool PacketQueue::Reconfigure(size_t max_size_pkts, DequeueRule dequeue_rule,
                              DropRule drop_rule)
{
  if ((cnt_ > 0) || (max_size_pkts == 0))
  {
    return false;
  }

  // Reallocate the circular buffer.
  if (queue_ != NULL)
  {
    delete [] queue_;
  }

  queue_ = new (std::nothrow) QueueElement[max_size_pkts];

  if (queue_ == NULL)
  {
    return false;
  }

  // Update the state.
  max_cnt_      = max_size_pkts;
  cnt_          = 0;
  size_         = 0;
  head_         = 0;
  dequeue_rule_ = dequeue_rule;
  drop_rule_    = drop_rule;

  return true;
}

//============================================================================
bool PacketQueue::Enqueue(Packet* pkt, const Time& now)
{
  if ((pkt == NULL) || (queue_ == NULL))
  {
    return false;
  }

  // Drop a packet if needed and allowed.
  if (cnt_ == max_cnt_)
  {
    switch (drop_rule_)
    {
      case NO_DROP:
        // Enqueue must fail.
        return false;

      case HEAD_DROP:
      {
        Packet*  old_pkt  = queue_[head_].pkt;
        cnt_             -= 1;
        size_            -= (old_pkt->GetMetadataHeaderLengthInBytes() +
                             old_pkt->GetLengthInBytes());
        queue_[head_].pkt = NULL;
        head_             = ((head_ + 1) % max_cnt_);
        pkt_pool_.Recycle(old_pkt);
        // Head drops are QLAM packets from the SLIQ CAT.
        TRACK_EXPECTED_DROP(kClassName, pkt_pool_);
        break;
      }

      case TAIL_DROP:
      {
        size_t   tail    = ((head_ + cnt_ - 1) % max_cnt_);
        Packet*  old_pkt = queue_[tail].pkt;
        cnt_            -= 1;
        size_           -= (old_pkt->GetMetadataHeaderLengthInBytes() +
                            old_pkt->GetLengthInBytes());
        queue_[tail].pkt = NULL;
        pkt_pool_.Recycle(old_pkt);
        TRACK_UNEXPECTED_DROP(kClassName, pkt_pool_);
        break;
      }

      default:
        LogF(kClassName, __func__, "Invalid drop rule.\n");
        return false;
    }
  }

  // Store the new packet at the tail.
  size_t  tail              = ((head_ + cnt_) % max_cnt_);
  queue_[tail].enqueue_time = now;
  queue_[tail].pkt          = pkt;
  cnt_                     += 1;
  size_                    += (pkt->GetMetadataHeaderLengthInBytes() +
                               pkt->GetLengthInBytes());

  return true;
}

//============================================================================
Packet* PacketQueue::Dequeue()
{
  Packet*  pkt = NULL;

  // Dequeue the packet at the head.
  if ((queue_ != NULL) && (cnt_ > 0))
  {
    switch (dequeue_rule_)
    {
      case FIFO_QUEUE:
        pkt               = queue_[head_].pkt;
        cnt_             -= 1;
        size_            -= (pkt->GetMetadataHeaderLengthInBytes() +
                             pkt->GetLengthInBytes());
        queue_[head_].pkt = NULL;
        head_             = ((head_ + 1) % max_cnt_);
        break;

      case LIFO_QUEUE:
      {
        size_t  tail     = ((head_ + cnt_ - 1) % max_cnt_);
        pkt              = queue_[tail].pkt;
        cnt_            -= 1;
        size_           -= (pkt->GetMetadataHeaderLengthInBytes() +
                            pkt->GetLengthInBytes());
        queue_[tail].pkt = NULL;
        break;
      }

      default:
        LogF(kClassName, __func__, "Invalid dequeueing rule.\n");
        return NULL;
    }
  }

  return pkt;
}

//============================================================================
Packet* PacketQueue::Dequeue(const Time& now, Time& queueing_delay)
{
  Packet*  pkt = NULL;

  // Dequeue the packet at the head.
  if ((queue_ != NULL) && (cnt_ > 0))
  {
    switch (dequeue_rule_)
    {
      case FIFO_QUEUE:
        pkt               = queue_[head_].pkt;
        cnt_             -= 1;
        size_            -= (pkt->GetMetadataHeaderLengthInBytes() +
                             pkt->GetLengthInBytes());
        queueing_delay    = (now - queue_[head_].enqueue_time);
        queue_[head_].pkt = NULL;
        head_             = ((head_ + 1) % max_cnt_);
        break;

      case LIFO_QUEUE:
      {
        size_t  tail     = ((head_ + cnt_ - 1) % max_cnt_);
        pkt              = queue_[tail].pkt;
        cnt_            -= 1;
        size_           -= (pkt->GetMetadataHeaderLengthInBytes() +
                            pkt->GetLengthInBytes());
        queueing_delay   = (now - queue_[tail].enqueue_time);
        queue_[tail].pkt = NULL;
        break;
      }

      default:
        LogF(kClassName, __func__, "Invalid dequeueing rule.\n");
        return NULL;
    }
  }

  return pkt;
}

//============================================================================
void PacketQueue::Purge()
{
  if ((queue_ != NULL) && (cnt_ > 0))
  {
    Packet*  pkt = NULL;

    while (cnt_ > 0)
    {
      pkt               = queue_[head_].pkt;
      queue_[head_].pkt = NULL;
      head_             = ((head_ + 1) % max_cnt_);
      --cnt_;

      pkt_pool_.Recycle(pkt);
      // Purges are only when leaving an outage.
      TRACK_EXPECTED_DROP(kClassName, pkt_pool_);
    }

    cnt_  = 0;
    size_ = 0;
  }
}

//============================================================================
size_t PacketQueue::GetNextDequeueSizeInBytes() const
{
  size_t  size = 0;

  // Get the size of the next packet to be dequeued.
  if ((queue_ != NULL) && (cnt_ > 0))
  {
    Packet*  pkt = NULL;

    switch (dequeue_rule_)
    {
      case FIFO_QUEUE:
        pkt = queue_[head_].pkt;
        break;

      case LIFO_QUEUE:
        pkt = queue_[(head_ + cnt_ - 1) % max_cnt_].pkt;
        break;

      default:
        LogF(kClassName, __func__, "Invalid dequeueing rule.\n");
        return 0;
    }

    size = (pkt->GetMetadataHeaderLengthInBytes() + pkt->GetLengthInBytes());
  }

  return size;
}
