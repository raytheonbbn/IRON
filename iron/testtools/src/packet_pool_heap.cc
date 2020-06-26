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

#include "packet_pool_heap.h"
#include "iron_utils.h"

#include "itime.h"
#include "log.h"

#include <cstring>
#include <inttypes.h>
#include <unistd.h>


using ::iron::Log;
using ::iron::PacketPoolHeap;
using ::iron::Packet;
using ::iron::Time;


namespace
{
  /// The class name for logging.
  const char*  kClassName = "PacketPoolHeap";
}


//============================================================================
PacketPoolHeap::PacketPoolHeap()
    : num_pkts_(0), index_(0), count_(0), pool_(NULL), pkt_buf_(NULL)
{
}

//============================================================================
PacketPoolHeap::~PacketPoolHeap()
{
  if (count_ != num_pkts_)
  {
    LogW(kClassName, __func__, "Packet pool leak detected.\n");
  }

  if (pool_ != NULL)
  {
    delete [] pool_;
    pool_ = NULL;
  }

  if (pkt_buf_ != NULL)
  {
    uint8_t*  buf = reinterpret_cast<uint8_t*>(pkt_buf_);
    delete [] buf;
    pkt_buf_ = NULL;
  }
}

//============================================================================
bool PacketPoolHeap::Create(size_t num_pkts)
{
  if (pool_ != NULL)
  {
    LogE(kClassName, __func__, "Pool already created.\n");
    return false;
  }

  if (num_pkts < 1)
  {
    LogE(kClassName, __func__, "Invalid pool size: %zu\n", num_pkts);
    return false;
  }

  // Allocate the array of packet indices.
  pool_ = new (std::nothrow) PktMemIndex[num_pkts];

  if (pool_ == NULL)
  {
    LogF(kClassName, __func__, "Pool allocation error.\n");
    return false;
  }

  // Allocate the array of Packet objects.
  size_t    packet_size = ROUND_INT(sizeof(Packet), 8);
  size_t    total_size  = (num_pkts * packet_size);
  uint8_t*  buf         = new (std::nothrow) uint8_t[total_size];

  if (buf == NULL)
  {
    delete [] pool_;
    pool_ = NULL;
    LogF(kClassName, __func__, "Packet array allocation error.\n");
    return false;
  }

  // Initialize everything.
  num_pkts_ = static_cast<PktMemIndex>(num_pkts);
  index_    = 0;
  count_    = static_cast<PktMemIndex>(num_pkts);
  pkt_buf_  = reinterpret_cast<Packet*>(buf);

  for (PktMemIndex i = 0; i < count_; ++i)
  {
    Packet*  pkt = (pkt_buf_ + i);
    pkt->Initialize(i);
    pool_[i] = i;
  }

  return true;
}

//============================================================================
Packet* PacketPoolHeap::Get(PacketRecvTimeMode timestamp)
{
  if (pool_ == NULL)
  {
    LogF(kClassName, __func__, "Packet pool not initialized.\n");
  }

  if (count_ == 0)
  {
    LogF(kClassName, __func__, "Packet pool is empty.\n");
  }

  // Get the next packet index to hand out.
  PktMemIndex  pkt_idx = 0;

  if (index_ >= count_)
  {
    pkt_idx = pool_[index_ - count_];
  }
  else
  {
    pkt_idx = pool_[num_pkts_ - count_ + index_];
  }

  --count_;

  // Convert the packet index into a Packet object pointer.
  Packet*  packet = (pkt_buf_ + pkt_idx);

  // Prepare the packet.
  packet->Reset();

  if (timestamp == PACKET_NOW_TIMESTAMP)
  {
    packet->set_recv_time(Time::Now());
  }
  else if (timestamp == PACKET_NO_TIMESTAMP)
  {
    packet->set_recv_time(Time(0));
  }
  else
  {
    LogE(kClassName, __func__, "Invalid timestamp parameter.\n");
  }

  return packet;
}

//============================================================================
void PacketPoolHeap::PacketShallowCopy(Packet* packet)
{
  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Invalid packet to copy.\n");
    return;
  }

  packet->ShallowCopy();
}

//============================================================================
Packet* PacketPoolHeap::Clone(Packet* to_clone, bool full_copy,
  PacketRecvTimeMode timestamp)
{
  if (to_clone == NULL)
  {
    LogE(kClassName, __func__, "Invalid packet to clone.\n");
    return NULL;
  }

  PacketRecvTimeMode  mode   = ((timestamp == PACKET_NOW_TIMESTAMP) ?
                                PACKET_NOW_TIMESTAMP : PACKET_NO_TIMESTAMP);
  Packet*             packet = Get(mode);

  packet->type_  = to_clone->type_;
  packet->start_ = to_clone->start_;
  memcpy((packet->buffer_ + to_clone->start_ - to_clone->metadata_length_),
         (to_clone->buffer_ + to_clone->start_ - to_clone->metadata_length_),
         (to_clone->metadata_length_ + to_clone->length_));
  packet->length_          = to_clone->length_;
  packet->metadata_length_ = to_clone->metadata_length_;

  if (full_copy)
  {
    packet->latency_               = to_clone->latency_;
    packet->virtual_length_        = to_clone->virtual_length_;
    packet->recv_late_             = to_clone->recv_late_;
    packet->origin_ts_ms_          = to_clone->origin_ts_ms_;
    packet->time_to_go_usec_       = to_clone->time_to_go_usec_;
    packet->order_time_            = to_clone->order_time_;
    packet->bin_id_                = to_clone->bin_id_;
    packet->packet_id_             = to_clone->packet_id_;
    packet->send_packet_id_        = to_clone->send_packet_id_;
    packet->track_ttg_             = to_clone->track_ttg_;
    packet->time_to_go_valid_      = to_clone->time_to_go_valid_;
    packet->send_packet_history_   = to_clone->send_packet_history_;
    packet->set_history(to_clone->history_);
    packet->send_packet_dst_vec_   = to_clone->send_packet_dst_vec_;
    packet->dst_vec_               = to_clone->dst_vec_;
  }

  if (timestamp == PACKET_COPY_TIMESTAMP)
  {
    packet->recv_time_ = to_clone->recv_time_;
  }

  return packet;
}

//============================================================================
Packet* PacketPoolHeap::CloneHeaderOnly(Packet* to_clone,
                                        PacketRecvTimeMode timestamp)
{
  if (to_clone == NULL)
  {
    LogE(kClassName, __func__, "Invalid packet to clone.\n");
    return NULL;
  }

  PacketRecvTimeMode  mode    = ((timestamp == PACKET_NOW_TIMESTAMP) ?
                                 PACKET_NOW_TIMESTAMP : PACKET_NO_TIMESTAMP);
  Packet*             packet  = Get(mode);
  uint32_t            hdr_len = to_clone->GetIpPayloadOffset();

  packet->type_   = to_clone->type_;
  packet->start_  = to_clone->start_;
  memcpy((packet->buffer_ + to_clone->start_),
         (to_clone->buffer_ + to_clone->start_), hdr_len);
  packet->SetLengthInBytes(hdr_len);

  if (timestamp == PACKET_COPY_TIMESTAMP)
  {
    packet->recv_time_ = to_clone->recv_time_;
  }

  uint8_t*       hdr_ptr = packet->GetBuffer();
  struct iphdr*  ip_hdr  = reinterpret_cast<struct iphdr*>(hdr_ptr);
  ip_hdr->tot_len        = htons(static_cast<unsigned short>(hdr_len));

  // This method currently only supports the cloning of UDP packets.
  if (ip_hdr->protocol == IPPROTO_UDP)
  {
    // Make sure the length of the packet is long enough to have a UDP header.
    if (to_clone->length_ >= (size_t)((ip_hdr->ihl * 4) +
                                      sizeof(struct udphdr)))
    {
      struct udphdr*  udp_hdr = reinterpret_cast<struct udphdr*>(
        &hdr_ptr[ip_hdr->ihl * 4]);
      udp_hdr->len            =
        htons(static_cast<unsigned short>((hdr_len - (ip_hdr->ihl * 4))));
    }
    else
    {
      Recycle(packet);
      return NULL;
    }
  }

  return packet;
}

//============================================================================
Packet* PacketPoolHeap::GetPacketFromIndex(PktMemIndex index)
{
  if (pool_ == NULL)
  {
    LogF(kClassName, __func__, "Packet pool not initialized.\n");
  }

  if (index >= num_pkts_)
  {
    LogF(kClassName, __func__, "Index %" PRIu32 " is invalid for pool size "
         PRIu32 ".\n", index, num_pkts_);
  }

  return (pkt_buf_ + index);
}

//============================================================================
void PacketPoolHeap::Recycle(Packet* packet)
{
  if (pool_ == NULL)
  {
    LogF(kClassName, __func__, "Packet pool not initialized.\n");
  }

  if (packet == NULL)
  {
    LogW(kClassName, __func__, "Attempting to recycle a NULL packet.\n");
    return;
  }

  // Get the packets memory index.
  PktMemIndex  pkt_idx = packet->mem_index();

  // First, decrement the packet's reference count.
  if (packet->DecrementRefCnt() == 0)
  {
    // The reference count has reached 0, so we can put the packet back into
    // the pool.
    if (count_ == num_pkts_)
    {
      LogE(kClassName, __func__, "Packet pool is full.\n");
      return;
    }

    pool_[index_] = pkt_idx;
    index_        = ((index_ + 1) % num_pkts_);

    ++count_;
  }
}

//============================================================================
size_t PacketPoolHeap::GetSize()
{
  return count_;
}
