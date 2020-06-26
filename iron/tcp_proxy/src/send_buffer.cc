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

#include "send_buffer.h"
#include "log.h"
#include "socket.h"

#include <netinet/tcp.h>

using ::iron::Packet;
using ::iron::Time;

namespace
{
  /// Class name for logging.
  const char*    kClassName = "SendBuffer";

  /// The minimum size for dynamic buffers.
  const uint32_t  kDefaultMinDynamicBufferSize = 20000;

  /// The maximum size for dynamic buffers.
  const uint32_t  kDefaultMaxDynamicBufferSize = 3000000;
}

//============================================================================
SendBuffer::SendBuffer(PktInfoPool& pkt_info_pool, uint32_t max_size_bytes,
                       bool adaptive_buffers, Socket* socket)
    : pkt_info_pool_(pkt_info_pool),
      max_size_bytes_(max_size_bytes),
      snd_una_(NULL),
      snd_nxt_(NULL),
      tail_(NULL),
      socket_(socket),
      una_seq_(0),
      una_seq_initialized_(false),
      nxt_seq_(0),
      rexmit_head_(NULL),
      rexmit_tail_(NULL),
      win_hwm_(una_seq_ + max_size_bytes_),
      last_size_update_time_(Time::Now()),
      xmit_bytes_since_last_size_update_(0),
      adaptive_buffers_(adaptive_buffers),
      adaptive_buffer_size_limit_(max_size_bytes),
      adaptive_buffer_min_size_(kDefaultMinDynamicBufferSize),
      adaptive_buffer_max_size_(kDefaultMaxDynamicBufferSize),
      cum_acked_bytes_(0)
{
  LogI(kClassName, __func__, "Creating send buffer with a maximum size of "
       "%zd bytes...\n", max_size_bytes);
}

//============================================================================
SendBuffer::~SendBuffer()
{
  LogI(kClassName, __func__, "%s, Destroying send buffer...\n",
       socket_->flow_id_str());

  // If there are any packets left in the packet list, recycle them and delete
  // the PktInfo structs.
  while (snd_una_ != NULL)
  {
    PktInfo*  cur_pkt_info = snd_una_;
    snd_una_ = cur_pkt_info->next;

    pkt_info_pool_.Recycle(cur_pkt_info);
  }

  snd_una_     = NULL;
  snd_nxt_     = NULL;
  tail_        = NULL;
  socket_      = NULL;
  rexmit_head_ = NULL;
  rexmit_tail_ = NULL;
}

//============================================================================
bool SendBuffer::Enqueue(PktInfo* pkt_info)
{
  LogD(kClassName, __func__, "%s, enqueuing packet into send buffer: "
       "seq (%" PRIu32 ") data len (%" PRIu32 ").\n",
       socket_->flow_id_str(), pkt_info->seq_num, pkt_info->data_len);

  if (pkt_info == NULL)
  {
    LogW(kClassName, __func__, "%s, Invalid argument: pkt_info is NULL.\n",
         socket_->flow_id_str());
    return false;
  }

  // There is always room to enqueue a zero-length packet. If non-zero length,
  // max sure it will fit. Also we need to bypass this step on SYN packets
  // since nxt_seq_ may not yet be initialized.
  if (pkt_info->data_len > 0)
  {
    if (SEQ_GT((pkt_info->seq_num + pkt_info->data_len), win_hwm_))
    {
      return false;
    }
  }

  if (tail_)
  {
    const struct tcphdr*  pkt_tcp_hdr = pkt_info->pkt->GetTcpHdr();
    if ((tail_->flags & TH_FIN) && (pkt_tcp_hdr->th_flags & TH_FIN))
    {
      LogW(kClassName, __func__, "%s, Unable to enqueue packet, TH_FIN set "
           "for buffer tail packet.\n", socket_->flow_id_str());
      return false;
    }
  }

  if ((snd_una_ != NULL) && (tail_ == NULL))
  {
    // There is a head but no tail. Something isn't right.
    LogW(kClassName, __func__, "%s, Something is wrong. Send packet buffer "
         "has a head but no tail.\n", socket_->flow_id_str());
    return false;
  }
  else if ((snd_una_ == NULL) && (tail_ != NULL))
  {
    // There is a tail but no head. Something isn't right.
    LogW(kClassName, __func__, "%s, Something is wrong. Send packet buffer "
         "has a tail but no head.\n", socket_->flow_id_str());
    return false;
  }
  else if (tail_ == NULL)
  {
    // There isn't anything in the send buffer. This is the first packet in
    // the send buffer.
    pkt_info->prev = NULL;
    pkt_info->next = NULL;
    snd_una_       = pkt_info;
    snd_nxt_       = pkt_info;
    tail_          = pkt_info;
    una_seq_       = snd_una_->seq_num;
    nxt_seq_       = tail_->seq_num + tail_->data_len;
    if (!una_seq_initialized_)
    {
      win_hwm_             = una_seq_ + max_size_bytes_;
      una_seq_initialized_ = true;
    }
  }
  else
  {
    // Append the packet to the tail of the send buffer.
    tail_->next    = pkt_info;
    pkt_info->prev = tail_;
    pkt_info->next = NULL;
    tail_          = pkt_info;

    if (SEQ_LT(nxt_seq_,tail_->seq_num + tail_->data_len))
    {
      nxt_seq_ = tail_->seq_num + tail_->data_len;
    }
  }

  if (!snd_nxt_)
  {
    snd_nxt_ = tail_;
  }

  socket_->Send(NULL, false);

  return true;
}

//============================================================================
bool SendBuffer::EnqueuePackets(PktInfo* pkt_info_list)
{
  // For now, we will simply unlink each element to be added from the provided
  // list and invoke the Enqueue() method. This will take care of adjusting
  // all of the necessary class member variables. A future optimization might
  // include investigating the appending of this list as a single operation.
  PktInfo*  pkt_to_enqueue = pkt_info_list;
  while (pkt_to_enqueue)
  {
    PktInfo*  next_pkt_info = pkt_to_enqueue->next;

    pkt_to_enqueue->next = NULL;
    if (next_pkt_info)
    {
      next_pkt_info->prev  = NULL;
    }

    if (!Enqueue(pkt_to_enqueue))
    {
      // This should never fail as we should have figured out how many packets
      // can be moved prior to moving them. If this fails something is wrong,
      // so abort.
      LogF(kClassName, __func__, "%s, Error enqueuing packets.\n",
           socket_->flow_id_str());
      return false;
    }

    pkt_to_enqueue = next_pkt_info;
  }

  socket_->Send(NULL, false);

  return true;
}

//============================================================================
PktInfo* SendBuffer::GetNextTransmission(Time& now, uint32_t sock_uwe,
                                         ProxyIfType cfg_if_id)
{
  // This method will first search for a packet to be retransmitted, a packet
  // whose rexmit time has expired. If no such packet exists, the packet at
  // snd_nxt_ is returned.
  if (rexmit_head_ &&
      (rexmit_head_->rexmit_time < now + socket_->min_burst_usec()))
    // The following additional check further limits the number of
    // retransmissions. However, there is the potential that a packet gets
    // stuck in a CAT that never recovers and we will never retransmit the
    // packet, essentially deadlocking the flow.
    // &&
    //   (rexmit_head_->pkt->ref_cnt() < 2))
  {
    if (adaptive_buffers_)
    {
      xmit_bytes_since_last_size_update_ +=
        rexmit_head_->pkt->GetLengthInBytes();
    }

    return rexmit_head_;
  }
  else
  {
    if (adaptive_buffers_ && snd_nxt_)
    {
      xmit_bytes_since_last_size_update_ += snd_nxt_->pkt->GetLengthInBytes();
    }

    if ((cfg_if_id == WAN) &&
        ((snd_nxt_ == NULL) ||
         (SEQ_GT(snd_nxt_->seq_num + snd_nxt_->data_len, sock_uwe) &&
          snd_nxt_->data_len != 0)))
    {
      // snd_nxt_ is window blocked or NULL.
      if ((rexmit_head_ != NULL) &&
          (rexmit_head_->pkt->ref_cnt() < 2))
      {
        // The proxy is the only component that has a reference to the
        // packet.
        return rexmit_head_;
      }
      else
      {
        return NULL;
      }
    }
    else
    {
      return snd_nxt_;
    }
  }
}

//============================================================================
void SendBuffer::RecordPktXmitSuccess(PktInfo* pkt_info)
{
  if (snd_nxt_ == pkt_info)
  {
    if (snd_una_ == NULL)
    {
      snd_una_ = snd_nxt_;
      una_seq_ = snd_una_->seq_num;
    }

    snd_nxt_ = snd_nxt_->next;
  }
}

//============================================================================
void SendBuffer::ProcessPlugs(OutSeqBuffer::PlugInfo* plugs,
                              uint32_t num_plugs, bool& buf_changed)
{
  if ((plugs == NULL) || (num_plugs == 0))
  {
    // Invalid parameter provided.
    return;
  }

  if (snd_una_ == NULL)
  {
    // The send buffer is empty, do nothing.
    LogD(kClassName, __func__, "%s, Cannot record any plugs, send buffer is "
         "empty.\n", socket_->flow_id_str());
    return;
  }

  bool      done         = false;
  Time      now          = Time::Now();
  PktInfo*  cur_pkt_info = snd_una_;
  uint32_t  i            = 0;
  while ((i < num_plugs) && !done)
  {
    // Mark all packets in the buffer whose sequence numbers are less than
    // the sequence number of the current plug as holes, if necessary.
    while (cur_pkt_info && SEQ_LT(cur_pkt_info->seq_num, plugs[i].lower_seq))
    {
      if (cur_pkt_info->rexmit_time.IsInfinite())
      {
        // The current packet does not have a retransmission time set yet, so
        // we mark it as a hole.
        MarkHole(cur_pkt_info, now);

        buf_changed = true;
      }

      cur_pkt_info = cur_pkt_info->next;
    }

    PktInfo*  pkt_info_at_plug_start = cur_pkt_info;

    // A data length of 0 in the following loop is meant to cover SYN and
    // FIN packets.
    bool  snd_nxt_plugged = false;
    bool  snd_una_plugged = false;
    bool  found_plugs     = false;
    while (cur_pkt_info &&
           SEQ_LT(cur_pkt_info->seq_num, plugs[i].upper_seq))
    {
      found_plugs = true;

      if (cur_pkt_info == snd_una_)
      {
        LogD(kClassName, __func__, "%s, snd_una_ is plugged. This should not "
             "happen.\n", socket_->flow_id_str());

        snd_una_plugged = true;
      }
      if (cur_pkt_info == snd_nxt_)
      {
        snd_nxt_plugged = true;
      }

      cur_pkt_info = cur_pkt_info->next;
    }

    if (found_plugs)
    {
      // If snd_una_ or snd_nxt_ has been plugged, move them.
      if (snd_una_plugged)
      {
        snd_una_ = cur_pkt_info;
      }
      if (snd_nxt_plugged)
      {
        snd_nxt_ = cur_pkt_info;
      }

      // At this point, we have a list of packets that have been plugged. We can
      // now remove this list of packets from the send buffer and recycle them.
      if (pkt_info_at_plug_start->prev)
      {
        pkt_info_at_plug_start->prev->next = cur_pkt_info;
      }

      if (cur_pkt_info != NULL)
      {
        // There are packets in the send buffer following the plug.
        cur_pkt_info->prev->next = NULL;
        cur_pkt_info->prev       = pkt_info_at_plug_start->prev;
      }
      else
      {
        // The plug is at the end of the send buffer. If and when this becomes
        // the case, we can return as we know there are no additional packets
        // that can be plugged.
        tail_ = pkt_info_at_plug_start->prev;
        done  = true;
      }
      pkt_info_at_plug_start->prev = NULL;

      ReleasePkts(pkt_info_at_plug_start);

      buf_changed = true;
    }

    ++i;
  }

  if (snd_una_ != NULL)
  {
    una_seq_ = snd_una_->seq_num;
  }
  else
  {
    una_seq_ = nxt_seq_;
  }
}

//============================================================================
void SendBuffer::MoveToHeadOfRexmitList(PktInfo* pkt_info)
{
  if (rexmit_head_ == pkt_info)
  {
    // Packet is already at the head of the retransmission list.
    return;
  }

  // If the packet to be moved is in the retransmission list, unlink it.
  if (pkt_info->rexmit_prev)
  {
    pkt_info->rexmit_prev->rexmit_next = pkt_info->rexmit_next;
  }

  if (pkt_info->rexmit_next)
  {
    pkt_info->rexmit_next->rexmit_prev = pkt_info->rexmit_prev;
  }

  if (rexmit_tail_ == pkt_info)
  {
    rexmit_tail_ = pkt_info->rexmit_prev;
  }

  // Add packet to the head of the retransmission list.
  if (rexmit_head_ == NULL)
  {
    rexmit_head_          = pkt_info;
    rexmit_tail_          = pkt_info;
    pkt_info->rexmit_next = NULL;
    pkt_info->rexmit_prev = NULL;
  }
  else
  {
    rexmit_head_->rexmit_prev = pkt_info;
    pkt_info->rexmit_prev     = NULL;
    pkt_info->rexmit_next     = rexmit_head_;
    rexmit_head_              = pkt_info;
  }
}

//============================================================================
void SendBuffer::MoveToEndOfRexmitList(PktInfo* pkt_info)
{
  if (pkt_info->rexmit_next == NULL)
  {
    // Only 1 packet in retransmission list or the packet is already at the
    // end of the retransmission list.
    return;
  }

  // Remove from head. The packet to be moved will always be at the head of
  // the retransmission list because we only move to the end of the
  // retransmission list when we reset the rexmit_time of a packet. We only do
  // this when we actually do a retransmission of a packet. Retransmissions
  // are ALWAYS pulled from the head of the retransmission list.
  rexmit_head_              = pkt_info->rexmit_next;
  pkt_info->rexmit_next     = NULL;
  rexmit_head_->rexmit_prev = NULL;

  // Append to tail.
  rexmit_tail_->rexmit_next = pkt_info;
  pkt_info->rexmit_prev     = rexmit_tail_;
  pkt_info->rexmit_next     = NULL;
  rexmit_tail_              = pkt_info;

  // The retransmission time of the new tail of the retransmission list is
  // based on the current RTT calculation and may be scheduled to occur before
  // elements in the list that are to be transmitted prior to the tail. This
  // can occur when there is a decrease in the RTT. We will adjust the time of
  // the retransmission list elements ahead of the new tail whose
  // retransmission time is greater than the retransmission time of the new
  // tail. The retransmission time of the elements for which this is the case
  // will be set to the retransmission time of the new tail. This should
  // increase the efficiency of repairing "holes".
  PktInfo*  cur_pkt_info = rexmit_tail_->rexmit_prev;
  while ((cur_pkt_info != NULL) &&
         (cur_pkt_info->rexmit_time > rexmit_tail_->rexmit_time))
  {
    LogD(kClassName, __func__, "%s, resetting retransmission time (%s) to "
         "new tail retransmission time (%s).\n", socket_->flow_id_str(),
         cur_pkt_info->rexmit_time.ToString().c_str(),
         rexmit_tail_->rexmit_time.ToString().c_str());

    cur_pkt_info->rexmit_time = rexmit_tail_->rexmit_time;
    cur_pkt_info              = cur_pkt_info->rexmit_prev;
  }
}

//============================================================================
void SendBuffer::ResendAllPkts()
{
  Time  now = Time::Now();
  PktInfo*  pkt_info = snd_una_;
  while (pkt_info && (pkt_info != snd_nxt_))
  {
    MarkHole(pkt_info, now, true);
    pkt_info = pkt_info->next;
  }
}

//============================================================================
void SendBuffer::GoBackN()
{
  snd_nxt_ = snd_una_;
  socket_->set_seq_sent(snd_nxt_->seq_num + snd_nxt_->data_len);
}

//============================================================================
void SendBuffer::Trim(uint32_t seq_num)
{
  LogD(kClassName, __func__, "%s, Trimming packets from send buffer to seq (%"
       PRIu32 ").\n", socket_->flow_id_str(), seq_num);

  // Trim the packets from the send buffer.
  if (snd_una_ && SEQ_GT(seq_num, snd_una_->seq_num))
  {
    bool      snd_nxt_trimmed = false;
    PktInfo*  cur_pkt_info    = snd_una_;
    PktInfo*  pkts_to_trim    = snd_una_;

    while (cur_pkt_info &&
           SEQ_LT(cur_pkt_info->seq_num, seq_num))
    {
      if (cur_pkt_info == snd_nxt_)
      {
        snd_nxt_trimmed = true;
      }
      una_seq_ = cur_pkt_info->seq_num + cur_pkt_info->data_len;

      cur_pkt_info = cur_pkt_info->next;
    }

    snd_una_ = cur_pkt_info;
    if (snd_una_ == NULL)
    {
      // The new snd_una_ is NULL, which means there are no more packets in
      // the send buffer. So, set tail_ to NULL also.
      tail_ = NULL;
    }
    else
    {
      if (snd_una_->prev != NULL)
      {
       snd_una_->prev->next = NULL;
       snd_una_->prev       = NULL;
      }
    }

    if (snd_nxt_trimmed)
    {
      snd_nxt_ = cur_pkt_info;
    }

    ReleasePkts(pkts_to_trim);
  }

  if (snd_una_ != NULL)
  {
    una_seq_ = snd_una_->seq_num;
  }
  else
  {
    una_seq_ = nxt_seq_;
  }
}

//============================================================================
bool SendBuffer::RexmitSanityCheck()
{
  if ((snd_una_ == NULL) && ((rexmit_head_ != NULL) || (rexmit_tail_ != NULL)))
  {
    LogF(kClassName, __func__, "%s, bug found in rexmit list: "
	 "NULL snd_una, non-NULL rexmit_head or rexmit_tail\n",
	 socket_->flow_id_str());
  }

  if ((rexmit_head_ == NULL) && (rexmit_tail_ != NULL))
  {
    LogF(kClassName, __func__, "%s, head, tail mismatch\n",
	 socket_->flow_id_str());
  }

  if ((rexmit_head_ != NULL) && (rexmit_tail_ == NULL))
  {
    LogF(kClassName, __func__, "%s, non-NULL rexmit head, NULL rexmit tail\n",
	 socket_->flow_id_str());
  }

  if (snd_una_ == NULL)
  {
    return true;
  }

  uint32_t seq_num  = snd_una_->seq_num;
  PktInfo* pkt_info = rexmit_head_;

  while (pkt_info != NULL)
  {
    if (SEQ_GT(seq_num, pkt_info->seq_num))
    {
      LogF(kClassName, __func__, "%s, bug found in rexmit list: ACK seq is %",
	   PRIu32 "; packet sequence in rexmit list is %" PRIu32 "\n",
	   socket_->flow_id_str(), seq_num, pkt_info->seq_num);
    }
    pkt_info = pkt_info->rexmit_next;
  }

  return true;
}

//============================================================================
void SendBuffer::SetPacketsPushFlag()
{
  PktInfo*  cur_pkt_info = snd_una_;
  while (cur_pkt_info)
  {
    struct tcphdr*  tcp_hdr = cur_pkt_info->pkt->GetTcpHdr();
    tcp_hdr->th_flags |= TH_PUSH;
    cur_pkt_info = cur_pkt_info->next;
  }
}

//============================================================================
void SendBuffer::UpdateBufferSize(uint32_t rtt_us, double send_rate_bps,
                                  uint32_t queue_depth)
{
  if (!adaptive_buffers_)
  {
    return;
  }

  Time  now = Time::Now();
  if ((now - last_size_update_time_) > Time::FromUsec(rtt_us))
  {
    if (queue_depth > 0)
    {
      size_t  new_size_bytes =
        static_cast<size_t>(2.0 * rtt_us * send_rate_bps / 8000000.0);

      if (new_size_bytes > 2 * max_size_bytes_)
      {
        max_size_bytes_ *= 2;
      }
      else
      {
        max_size_bytes_ = new_size_bytes;
      }

      if (max_size_bytes_ < adaptive_buffer_min_size_)
      {
       LogD(kClassName, __func__, "%s, desired max_size_bytes_ %"
            PRIu32 ", limited to %" PRIu32 " bytes.\n",
            socket_->flow_id_str(), max_size_bytes_,
            adaptive_buffer_min_size_);
        max_size_bytes_ = adaptive_buffer_min_size_;
      }

      if (max_size_bytes_ > adaptive_buffer_max_size_)
      {
       LogD(kClassName, __func__, "%s, desired max_size_bytes_ %"
            PRIu32 ", limited to %" PRIu32 " bytes.\n",
            socket_->flow_id_str(), max_size_bytes_,
            adaptive_buffer_max_size_);
        max_size_bytes_ = adaptive_buffer_max_size_;
      }

      LogD(kClassName, __func__, "%s, rtt is %" PRIu32 " us, last send rate "
           "is %f bps, queue depth is %" PRIu32 " bytes, send buffer maximum "
           "size is %zd bytes.\n", socket_->flow_id_str(), rtt_us,
           send_rate_bps, queue_depth, max_size_bytes_);
    }
    else
    {
      if ((xmit_bytes_since_last_size_update_ * 2) > max_size_bytes_)
      {
        max_size_bytes_ = xmit_bytes_since_last_size_update_ * 2;
      }

      if (max_size_bytes_ < adaptive_buffer_min_size_)
      {
       LogW(kClassName, __func__, "%s, desired max_size_bytes_ %"
            PRIu32 ", limited to %" PRIu32 " bytes.\n", socket_->flow_id_str(),
            max_size_bytes_,
            adaptive_buffer_min_size_);
        max_size_bytes_ = adaptive_buffer_min_size_;
      }

      if (max_size_bytes_ > adaptive_buffer_max_size_)
      {
       LogD(kClassName, __func__, "%s, desired max_size_bytes_ %"
            PRIu32 ", limited to %" PRIu32 " bytes.\n",
            socket_->flow_id_str(), max_size_bytes_,
            adaptive_buffer_max_size_);
        max_size_bytes_ = adaptive_buffer_max_size_;
      }

      LogD(kClassName, __func__, "%s, transmitted %zd bytes since updating "
           "buffer size, max buffer size is %zd bytes.\n",
           socket_->flow_id_str(), xmit_bytes_since_last_size_update_,
           max_size_bytes_);
    }

    last_size_update_time_             = now;
    xmit_bytes_since_last_size_update_ = 0;
  }
}

//============================================================================
size_t SendBuffer::GetUsableWindow()
{
  return uwe() - nxt_seq_;
}

//============================================================================
uint32_t SendBuffer::uwe()
{
  uint32_t  new_uwe = una_seq_ + max_size_bytes_;
  if (SEQ_GT(new_uwe, win_hwm_))
  {
    win_hwm_ = new_uwe;

    LogD(kClassName, __func__, "%s, new win_hwm_ is %" PRIu32 ".\n",
        socket_->flow_id_str());
  }

  return win_hwm_;
}

//============================================================================
void SendBuffer::MarkHole(PktInfo* pkt_info, Time& now, bool force)
{
  if (pkt_info == NULL)
  {
    return;
  }

  bool  add_to_rexmit_list = pkt_info->rexmit_time.IsInfinite();

  if (!pkt_info->rexmit_time.IsInfinite() && !force)
  {
    LogW(kClassName, __func__, "%s, packet with sequence number %" PRIu32
         " has already been marked as a hole.\n", socket_->flow_id_str(),
         pkt_info->seq_num);
    return;
  }

  if (socket_->t_srtt())
  {
    pkt_info->rexmit_time = now +
      Time::FromUsec((MIN(socket_->max_rto_us(),
                          ((MAX(0, socket_->t_srtt()) >> TCP_RTT_SHIFT) +
                           socket_->t_rttvar()))));
  }
  else
  {
    pkt_info->rexmit_time = now +
      Time::FromUsec(MIN(socket_->max_rto_us(),
                         MAX(0, socket_->initial_rto())));
  }

  if (add_to_rexmit_list)
  {
    // Add packet to the end of the retransmission list.
    if (rexmit_head_ == NULL)
    {
      rexmit_head_          = pkt_info;
      rexmit_tail_          = pkt_info;
      pkt_info->rexmit_next = NULL;
      pkt_info->rexmit_prev = NULL;
    }
    else
    {
      rexmit_tail_->rexmit_next = pkt_info;
      pkt_info->rexmit_prev     = rexmit_tail_;
      pkt_info->rexmit_next     = NULL;
      rexmit_tail_              = pkt_info;
    }
  }
}

//============================================================================
void SendBuffer::ReleasePkts(PktInfo* pkt_info)
{
  while (pkt_info)
  {
    PktInfo*  next_pkt_info = pkt_info->next;

    // Remove the packet from the retransmission list.
    if (pkt_info->rexmit_prev)
    {
      pkt_info->rexmit_prev->rexmit_next = pkt_info->rexmit_next;
    }

    if (pkt_info->rexmit_next)
    {
      pkt_info->rexmit_next->rexmit_prev = pkt_info->rexmit_prev;
    }

    if (rexmit_head_ == pkt_info)
    {
      rexmit_head_ = pkt_info->rexmit_next;
    }

    if (rexmit_tail_ == pkt_info)
    {
      rexmit_tail_ = pkt_info->rexmit_prev;
    }

    // Track the number of bytes acked.
    if (socket_->cfg_if_id() == WAN)
    {
      cum_acked_bytes_ += pkt_info->data_len;
    }

    // Now we can recycle the packet.
    pkt_info_pool_.Recycle(pkt_info);

    pkt_info = next_pkt_info;
  }
}
