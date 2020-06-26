//============================================================================
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
//============================================================================

#include "out_seq_buffer.h"
#include "log.h"
#include "socket.h"

#include <netinet/tcp.h>

using ::iron::Packet;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "OutSeqBuffer";
}

//============================================================================
OutSeqBuffer::OutSeqBuffer(PktInfoPool& pkt_info_pool,
                           uint32_t max_size_bytes, Socket* socket)
    : pkt_info_pool_(pkt_info_pool),
      size_bytes_(0),
      max_size_bytes_(max_size_bytes),
      head_(NULL),
      tail_(NULL),
      last_inserted_seq_(0),
      socket_(socket)
{
  LogI(kClassName, __func__, "Creating out-of-sequence buffer with a maximum "
       "size of %zd bytes...\n", max_size_bytes_);
}

//============================================================================
OutSeqBuffer::~OutSeqBuffer()
{
  LogI(kClassName, __func__, "%s, Destroying out-of-sequence buffer...\n",
       socket_->flow_id_str());

  // If there are any packets left in the buffer, recycle them and delete the
  // PktInfo structs.
  while (head_ != NULL)
  {
    PktInfo*  cur_pkt_info = head_;
    head_                  = cur_pkt_info->next;

    pkt_info_pool_.Recycle(cur_pkt_info);
  }

  head_ = NULL;
  tail_ = NULL;
}

//============================================================================
bool OutSeqBuffer::Enqueue(PktInfo* pkt_info)
{
  LogD(kClassName, __func__, "%s, enqueuing packet into out-of-sequence "
       "buffer: seq (%" PRIu32 ") data len (%" PRIu32 ").\n",
       socket_->flow_id_str(), pkt_info->seq_num, pkt_info->data_len);

  if (pkt_info == NULL)
  {
    LogW(kClassName, __func__, "%s, Invalid argument: pkt_info is NULL.\n",
         socket_->flow_id_str());
    return false;
  }

  if (pkt_info->pkt == NULL)
  {
    LogW(kClassName, __func__, "%s, PktInfo->pkt is NULL.\n",
         socket_->flow_id_str());
    return false;
  }

  if (tail_)
  {
    if ((tail_->flags & TH_FIN) && (pkt_info->flags & TH_FIN))
    {
      LogW(kClassName, __func__, "%s, Unable to enqueue packet, TH_FIN "
           "set for buffer tail packet.\n", socket_->flow_id_str());
      return false;
    }
  }

  if ((head_ != NULL) && (tail_ == NULL))
  {
    // There is a head but no tail. Something isn't right.
    LogW(kClassName, __func__, "%s, Something is wrong. OutSeqBuffer has a "
         "head but no tail.\n", socket_->flow_id_str());
    return false;
  }

  if ((head_ == NULL) && (tail_ != NULL))
  {
    // There is a tail but no head. Something isn't right.
    LogW(kClassName, __func__, "%s, Something is wrong. OutSeqBuffer has a "
         "tail but no head.\n", socket_->flow_id_str());
    return false;
  }

  if ((head_ == tail_) && (head_ == NULL))
  {
    // Head and tail are both NULL. This is the first packet added to the
    // OutSeqBuffer.
    pkt_info->prev = NULL;
    pkt_info->next = NULL;
    head_          = pkt_info;
    tail_          = pkt_info;
  }
  else
  {
    // Append to the tail of the OutSeqBuffer.
    tail_->next    = pkt_info;
    pkt_info->prev = tail_;
    pkt_info->next = NULL;
    tail_          = pkt_info;
  }

  size_bytes_        += pkt_info->data_len;
  last_inserted_seq_  = pkt_info->seq_num;

  LogD(kClassName, __func__, "%s, out-of-sequence buffer size: %zd "
       "bytes.\n", socket_->flow_id_str(), size_bytes_);

  return true;
}

//============================================================================
PktInfo* OutSeqBuffer::Dequeue()
{
  PktInfo*  pkt_info = UnlinkHead();

  if (pkt_info != NULL)
  {
    LogD(kClassName, __func__, "%s, out-of-sequence buffer: Dequeuing "
         "packet: seq(%" PRIu32 ") data len (%" PRIu32 ")\n.",
         socket_->flow_id_str(), pkt_info->seq_num, pkt_info->data_len);

    LogD(kClassName, __func__, "%s, out-of-sequence buffer size: %zd "
         "bytes.\n", socket_->flow_id_str(), size_bytes_);
  }

  return pkt_info;
}

//============================================================================
bool OutSeqBuffer::Insert(PktInfo* pkt_info)
{
  LogD(kClassName, __func__, "%s, out-of-sequence buffer: Inserting "
       "packet: seq (%" PRIu32 ") data len (%" PRIu32 ").\n",
       socket_->flow_id_str(), pkt_info->seq_num, pkt_info->data_len);

  if (pkt_info == NULL)
  {
    LogW(kClassName, __func__, "%s, Invalid argument: pkt is NULL.\n",
         socket_->flow_id_str());
    return false;
  }

  if (pkt_info->pkt == NULL)
  {
    LogW(kClassName, __func__, "%s, PktInfo->pkt is NULL.\n",
         socket_->flow_id_str());
    return false;
  }

  if (head_ == NULL)
  {
    // There is nothing in the packet buffer, so simply enqueue the packet.
    return Enqueue(pkt_info);
  }

  // Quickly check if the packet belongs at the end of the packet buffer.
  PktInfo*  cur_pkt_info = tail_;
  if (SEQ_GT(pkt_info->seq_num, cur_pkt_info->seq_num))
  {
    // The packet to be inserted goes at the end of the packet buffer, so
    // simply enqueue the packet.
    return Enqueue(pkt_info);
  }

  // The packet to be inserted goes somewhere between head_ and tail_. Start
  // at the beginning of the packet buffer and find the correct place for the
  // insertion.
  cur_pkt_info = head_;
  while (cur_pkt_info != NULL)
  {
    if ((cur_pkt_info->seq_num == pkt_info->seq_num) &&
        (cur_pkt_info->data_len == pkt_info->data_len))
    {
      LogD(kClassName, __func__, "%s, out-of-sequence buffer: Packet is "
           "already in buffer: seq (%" PRIu32 ") data len (%" PRIu32 ").\n",
           socket_->flow_id_str(), pkt_info->seq_num, pkt_info->data_len);
      return false;
    }

    if (SEQ_GT(cur_pkt_info->seq_num, pkt_info->seq_num))
    {
      // The packet to insert goes before the current packet.

      pkt_info->prev = cur_pkt_info->prev;

      if (cur_pkt_info->prev)
      {
        cur_pkt_info->prev->next = pkt_info;
      }

      pkt_info->next     = cur_pkt_info;
      cur_pkt_info->prev = pkt_info;

      if (head_ == cur_pkt_info)
      {
        head_ = pkt_info;
      }

      size_bytes_ += pkt_info->data_len;
      break;
    }
    else
    {
      cur_pkt_info = cur_pkt_info->next;
    }
  }

  last_inserted_seq_ = pkt_info->seq_num;

  return true;
}

//============================================================================
PktInfo* OutSeqBuffer::UnlinkHead()
{
  if (size_bytes_ == 0)
  {
    LogW(kClassName, __func__, "%s, A packet is being requested from an "
         "empty out-of-sequence packet buffer.\n", socket_->flow_id_str());
    return NULL;
  }

  if (head_ == NULL)
  {
    // The OutSeqBuffer is corrupt, size_bytes_ is not zero yet head_ is NULL.
    LogW(kClassName, __func__, "%s, The packet buffer is corrupted. "
         "Resetting  head, tail, and size. A memory leak may have occurred "
         "as a result of this action.\n", socket_->flow_id_str());

    head_       = NULL;
    tail_       = NULL;
    size_bytes_ = 0;

    return NULL;
  }

  PktInfo*  pkt_info = head_;

  pkt_info->prev = NULL;
  head_          = head_->next;
  pkt_info->next = NULL;

  if (head_ != NULL)
  {
    head_->prev = NULL;
  }
  else
  {
    tail_ = NULL;
  }

  size_bytes_ -= pkt_info->data_len;

  return pkt_info;
}

//============================================================================
size_t OutSeqBuffer::GatherPlugs(PlugInfo* plugs, uint32_t max_to_find)
{
  uint32_t  lower     = 0;
  uint32_t  upper     = 0;
  uint32_t  num_found = 0;

  if (max_to_find == 0)
  {
    return num_found;
  }

  PktInfo*  pkt_info = head_;
  while (pkt_info != NULL)
  {
    lower = pkt_info->seq_num;
    upper = pkt_info->seq_num + pkt_info->data_len;

    pkt_info = pkt_info->next;
    while (pkt_info && pkt_info->seq_num == upper)
    {
      upper    += pkt_info->data_len;
      pkt_info  = pkt_info->next;
    }

    plugs[num_found].lower_seq = lower;
    plugs[num_found].upper_seq = upper;

    num_found++;
    if (num_found >= max_to_find)
    {
      break;
    }
  }

  if (num_found > 0)
  {
    LogD(kClassName, __func__, "%s, Found %" PRIu32 " plugs\n",
         socket_->flow_id_str(), num_found);
  }

  return num_found;
}

//============================================================================
bool OutSeqBuffer::GetPlugCoveringLastPkt(PlugInfo& plug)
{
  if (SEQ_LT(last_inserted_seq_, head_->seq_num))
  {
    return false;
  }

  uint32_t  lower = 0;
  uint32_t  upper = 0;

  PktInfo*  pkt_info = head_;
  while (pkt_info != NULL)
  {
    lower = pkt_info->seq_num;
    upper = pkt_info->seq_num + pkt_info->data_len;

    pkt_info = pkt_info->next;
    while (pkt_info && pkt_info->seq_num == upper)
    {
      upper    += pkt_info->data_len;
      pkt_info  = pkt_info->next;
    }

    if (SEQ_GEQ(last_inserted_seq_,lower) && SEQ_LT(last_inserted_seq_,upper))
    {
      plug.lower_seq = lower;
      plug.upper_seq = upper;

      LogD(kClassName, __func__, "%s, Found covering plug for seq %"
           PRIu32 "\n", socket_->flow_id_str(), last_inserted_seq_);

      return true;
    }
  }

  LogD(kClassName, __func__, "%s, No covering plug found for seq %"
       PRIu32 "\n", socket_->flow_id_str(), last_inserted_seq_);

  return false;
}

