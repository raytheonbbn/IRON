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

#include "iron_utils.h"
#include "packet_pool_shm.h"

#include "log.h"
#include "unused.h"

#include <sstream>

#include <cstring>
#include <inttypes.h>
#include <unistd.h>


using ::iron::Log;
using ::iron::PacketPoolShm;
using ::iron::Packet;
using ::iron::Time;
using ::std::map;
using ::std::string;


namespace
{
  const char*  UNUSED(kClassName)    = "PacketPoolShm";

  const char*  UNUSED(kClassNameCB)  = "CircularBuffer";

#ifdef PKT_LEAK_DETECT

  // How often we should run the packet tracker to log packet owner counts.
  const Time   UNUSED(kOwnerLogTime) = Time(3);

#endif // PKT_LEAK_DETECT
}

//============================================================================
bool PacketPoolShm::ShmPPCircBuf::Get(PktMemIndex& val)
{
  if (count_ == 0)
  {
    LogW(kClassNameCB, __func__, "Shared memory circular buffer is empty.\n");
    return false;
  }

  if (index_ >= count_)
  {
    val = data_[index_ - count_];
  }
  else
  {
    val = data_[kShmPPNumPkts - count_ + index_];
  }

  --count_;

  return true;
}

//============================================================================
bool PacketPoolShm::ShmPPCircBuf::Put(PktMemIndex val)
{
  if (count_ == kShmPPNumPkts)
  {
    LogW(kClassNameCB, __func__, "Shared memory circular buffer is full.\n");
    return false;
  }

  data_[index_] = val;
  index_        = ((index_ + 1) % kShmPPNumPkts);

  ++count_;

  return true;
}

//============================================================================
PacketPoolShm::LocalPPCircBuf::LocalPPCircBuf()
    : data_(), index_(0), count_(0)
{
  memset(data_, 0, sizeof(data_));
}

//============================================================================
PacketPoolShm::LocalPPCircBuf::~LocalPPCircBuf()
{
}

//============================================================================
bool PacketPoolShm::LocalPPCircBuf::Get(PktMemIndex& val)
{
  if (count_ == 0)
  {
    LogD(kClassNameCB, __func__, "Local memory circular buffer is empty.\n");
    return false;
  }

  if (index_ >= count_)
  {
    val = data_[index_ - count_];
  }
  else
  {
    val = data_[kLocalPPNumPkts - count_ + index_];
  }

  --count_;

  return true;
}

//============================================================================
bool PacketPoolShm::LocalPPCircBuf::Put(PktMemIndex val)
{
  if (count_ == kLocalPPNumPkts)
  {
    LogD(kClassNameCB, __func__, "Local memory circular buffer is full.\n");
    return false;
  }

  data_[index_] = val;
  index_        = ((index_ + 1) % kLocalPPNumPkts);

  ++count_;

  return true;
}

//============================================================================
PacketPoolShm::PacketPoolShm()
    : PacketPool(),
      packet_shared_memory_(),
      shm_packet_buffer_(NULL),
      local_packet_buffer_(),
      packet_buffer_start_(NULL),
      pool_low_water_mark_(0)
#ifdef PKT_LEAK_DETECT
    , packets_owned_(0),
      next_owner_(),
      previous_owner_(),
      last_owner_log_time_(0)
#endif // PKT_LEAK_DETECT
    , next_location_ref_(1),
      location_ref_(),
      location_deref_(),
      location_deref_expected_(),
      drop_count_()
#ifdef PACKET_TRACKING
    , location_deref_held_(),
      owned_(),
      min_owned_(0),
      max_owned_(0)
#endif // PACKET_TRACKING
{
  memset(location_deref_expected_, 0,
         (kMaxLocations * sizeof(location_deref_expected_[0])));
  memset(drop_count_, 0, (kMaxLocations * sizeof(drop_count_[0])));
#ifdef PACKET_TRACKING
  memset(location_deref_held_, 0,
         (kMaxLocations * sizeof(location_deref_held_[0])));
  memset(owned_, 0, (kShmPPNumPkts * sizeof(owned_[0])));
#endif // PACKET_TRACKING

  LogD(kClassName, __func__, "Packet pool is created.\n");
}

//============================================================================
PacketPoolShm::PacketPoolShm(PacketOwner owner)
    : PacketPool(owner),
      packet_shared_memory_(),
      shm_packet_buffer_(NULL),
      local_packet_buffer_(),
      packet_buffer_start_(NULL),
      pool_low_water_mark_(0)
#ifdef PKT_LEAK_DETECT
    , packets_owned_(0),
      next_owner_(),
      previous_owner_(),
      last_owner_log_time_(0)
#endif // PKT_LEAK_DETECT
    , next_location_ref_(1),
      location_ref_(),
      location_deref_(),
      location_deref_expected_(),
      drop_count_()
#ifdef PACKET_TRACKING
    , location_deref_held_(),
      owned_(),
      min_owned_(0),
      max_owned_(0)
#endif // PACKET_TRACKING
{
  memset(location_deref_expected_, 0,
         (kMaxLocations * sizeof(location_deref_expected_[0])));
  memset(drop_count_, 0, (kMaxLocations * sizeof(drop_count_[0])));
#ifdef PACKET_TRACKING
  memset(location_deref_held_, 0,
         (kMaxLocations * sizeof(location_deref_held_[0])));
  memset(owned_, 0, kShmPPNumPkts * sizeof(owned_[0]));
#endif // PACKET_TRACKING

  LogD(kClassName, __func__, "Packet pool is created with owner %d.\n",
       packet_owner_);
}

//============================================================================
PacketPoolShm::~PacketPoolShm()
{
  LogPacketDrops();

#ifdef PKT_LEAK_DETECT
  LogPacketsOwned(true);
#endif // PKT_LEAK_DETECT

#ifdef PACKET_TRACKING
  PacketTrackingStuckCheck();
#endif // PACKET_TRACKING

  shm_packet_buffer_ = NULL;

  LogI(kClassName, __func__, "Packet pool is removed.\n");
}

//============================================================================
bool PacketPoolShm::Create(key_t key, const char* name)
{
  if (shm_packet_buffer_ != NULL)
  {
    LogD(kClassName, __func__, "Packet pool already created.\n");
    return true;
  }

  // Get size of buffer and packets, rounded to next 8B boundary.
  size_t  shm_size    = ROUND_INT(sizeof(ShmPPCircBuf), 8);
  size_t  packet_size = ROUND_INT(sizeof(Packet), 8);
  size_t  total_size  = (shm_size + (packet_size * kShmPPNumPkts));

  if (!packet_shared_memory_.Create(key, name, total_size))
  {
    LogF(kClassName, __func__, "Failed to create the shared memory segment "
         "for packets.\n");
    return false;
  }

  LogD(kClassName, __func__, "Created the shared memory segment for "
       "packets.\n");

  packet_shared_memory_.Lock();

  shm_packet_buffer_ =
    reinterpret_cast<ShmPPCircBuf*>(packet_shared_memory_.GetShmPtr());

  if (shm_packet_buffer_ == NULL)
  {
    LogF(kClassName, __func__, " Failed to get shm_packet_buffer.\n");
  }

  packet_buffer_start_ =
    reinterpret_cast<Packet*>(packet_shared_memory_.GetShmPtr(shm_size));

  for (PktMemIndex mem_index = 0; mem_index < kShmPPNumPkts; ++mem_index)
  {
    Packet*  pkt = GetPacketFromIndex(mem_index);
    pkt->Initialize(mem_index);
    shm_packet_buffer_->Put(mem_index);
  }

  pool_low_water_mark_ = shm_packet_buffer_->GetCurrentCount();

  packet_shared_memory_.Unlock();

  LogD(kClassName, __func__, "Created shared memory segment %s for "
       "packets.\n", name);

  return true;
}

//============================================================================
bool PacketPoolShm::Attach(key_t key, const char* name)
{
  if (shm_packet_buffer_ != NULL)
  {
    LogD(kClassName, __func__, "Already attached to PacketPoolShm.\n");
    return true;
  }

  // Get size of buffer and packets, rounded to next 8B boundary.
  size_t    shm_size    = ROUND_INT(sizeof(ShmPPCircBuf), 8);
  size_t    packet_size = ROUND_INT(sizeof(Packet), 8);
  size_t    total_size  = (shm_size + (packet_size * kShmPPNumPkts));
  bool      attached    = packet_shared_memory_.Attach(key, name, total_size);
  uint32_t  wait_count  = 0;

  while (!attached)
  {
    sleep(1);

    ++wait_count;

    if ((wait_count % 10) == 0)
    {
      if ((wait_count % 120) == 0)
      {
        LogW(kClassName, __func__, "... Still trying to attach to shared "
             "memory packet pool (%" PRIu32 " s).\n", wait_count);
      }
      else
      {
        LogD(kClassName, __func__, "... Waiting to attach to shared memory "
             "packet pool.\n");
      }
    }

    if (!attached)
    {
      attached = packet_shared_memory_.Attach(key, name, total_size);
    }
  }

  shm_packet_buffer_ =
    reinterpret_cast<ShmPPCircBuf*>(packet_shared_memory_.GetShmPtr());

  packet_buffer_start_ =
    reinterpret_cast<Packet*>(packet_shared_memory_.GetShmPtr(shm_size));

  LogD(kClassName, __func__, "Attached shared memory segment %s for "
       "packets.\n", name);

  return true;
}

//============================================================================
Packet* PacketPoolShm::Get(PacketRecvTimeMode timestamp)
{
  if (shm_packet_buffer_ == NULL)
  {
    LogF(kClassName, __func__, "Not initialized.\n");
  }

  Packet*      packet         = NULL;
  PktMemIndex  next_pkt_index = 0;
  PktMemIndex  local_index    = 0;

  if (!local_packet_buffer_.Get(next_pkt_index))
  {
    // Lock the shared memory segment.
    packet_shared_memory_.Lock();

    for (local_index = 0; local_index < (kLocalPPNumPkts / 2); ++local_index)
    {
      if (!shm_packet_buffer_->Get(next_pkt_index))
      {
        LogW(kClassName, __func__, "Shared memory pool of packets is "
             "empty.\n");
        break;
      }

      if (!local_packet_buffer_.Put(next_pkt_index))
      {
        LogW(kClassName, __func__, "Could not place new packet index in "
             "local buffer.\n");
        break;
      }
    }

    size_t  num_left = shm_packet_buffer_->GetCurrentCount();

    // Unlock the shared memory segment.
    packet_shared_memory_.Unlock();

    if (num_left < pool_low_water_mark_)
    {
      pool_low_water_mark_ = num_left;
    }

    LogD(kClassName, __func__, "The local cache was empty, fetched %d new "
         "packets from shared memory. Low water mark is %zu.\n",
         static_cast<int>(local_index), pool_low_water_mark_);

    if (!local_packet_buffer_.Get(next_pkt_index))
    {
      LogF(kClassName, __func__, "Ran out of packets in local buffer.\n");
    }
  }

  packet = GetPacketFromIndex(next_pkt_index);

  if (packet == NULL)
  {
    LogF(kClassName, __func__, "Failed to get packet for index %d.\n",
         static_cast<int>(next_pkt_index));
  }

#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)
  TrackPacketClaim(packet, PACKET_OWNER_NONE);
#endif // PKT_LEAK_DETECT || PACKET_TRACKING

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
    LogE(kClassName, __func__, "Invalid timestamp mode.\n");
  }

  return packet;
}

//============================================================================
void PacketPoolShm::PacketShallowCopy(Packet* packet)
{
  if (packet == NULL)
  {
    LogE(kClassName, __func__, "Invalid packet to copy.\n");
    return;
  }

  packet->ShallowCopy();

#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)
  TrackPacketCopy(packet);
#endif // PKT_LEAK_DETECT || PACKET_TRACKING
}

//============================================================================
Packet* PacketPoolShm::Clone(Packet* to_clone, bool full_copy,
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
Packet* PacketPoolShm::CloneHeaderOnly(Packet* to_clone,
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
Packet* PacketPoolShm::GetPacketFromIndex(PktMemIndex index)
{
  if (shm_packet_buffer_ == NULL)
  {
    LogF(kClassName, __func__, "Not initialized.\n");
  }

  if (index >= kShmPPNumPkts)
  {
    LogF(kClassName, __func__, "Index %d is out of bounds of the shared "
         "memory segment.\n", static_cast<int>(index));
  }

  return reinterpret_cast<Packet*>(packet_buffer_start_ + index);
}

//============================================================================
void PacketPoolShm::Recycle(Packet* packet)
{
  if (shm_packet_buffer_ == NULL)
  {
    LogF(kClassName, __func__, "Not initialized.\n");
  }

  if (packet == NULL)
  {
    LogW(kClassName, __func__, "Attempting to recycle a NULL packet.\n");
    return;
  }

#ifdef PACKET_TRACKING
  if (owned_[packet->mem_index()] == 0)
  {
    LogW(kClassName, __func__, "Recycling packet %" PRIu32 ", which is not "
         "owned.\n", packet->mem_index());
  }
#endif // PACKET_TRACKING

#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)
  TrackPacketRelease(packet, PACKET_OWNER_NONE);
#endif // PKT_LEAK_DETECT || PACKET_TRACKING

  if (packet->DecrementRefCnt() != 0)
  {
    // The reference count has not yet reached 0, so we can not put the packet
    // back into the pool yet.
    return;
  }

  PktMemIndex  packet_index   = packet->mem_index();
  PktMemIndex  copy_count     = 0;
  PktMemIndex  next_pkt_index = 0;

  // Check the local buffer.
  if (!local_packet_buffer_.Put(packet_index))
  {
    // It is full, copy half of the indices into the shared memory circ buffer.
    // Note: we leave half for future packet needs.

    // Lock the shared memory segment.
    packet_shared_memory_.Lock();

    for (copy_count = 0; copy_count < (kLocalPPNumPkts / 2); ++copy_count)
    {
      if (!local_packet_buffer_.Get(next_pkt_index))
      {
        LogW(kClassName, __func__, "Could not get packet index from local "
             "buffer.\n");
        break;
      }

      if (!shm_packet_buffer_->Put(next_pkt_index))
      {
        LogW(kClassName, __func__, "Shared memory segment of packets is "
             "full!\n");
        break;
      }
    }

    // Unlock the shared memory segment.
    packet_shared_memory_.Unlock();

    LogD(kClassName, __func__, "The local cache was full, returned %d new "
         "packets to shared memory.\n", static_cast<int>(copy_count));

    if (!local_packet_buffer_.Put(packet_index))
    {
      LogE(kClassName, __func__, "No room in local buffer for packet.\n");
    }
  }
}

//============================================================================
size_t PacketPoolShm::GetSize()
{
  if (shm_packet_buffer_ == NULL)
  {
    return 0;
  }

  return (local_packet_buffer_.GetCurrentCount() +
          shm_packet_buffer_->GetCurrentCount());
}

//============================================================================
void PacketPoolShm::LogPacketDrops()
{
  // First log expected drops
  for (uint16_t ref = 1; ref < next_location_ref_; ref++)
  {
    if (location_deref_expected_[ref] && drop_count_[ref] > 0)
    {
      LogI(kClassName, __func__, "%" PRIu32 " packets dropped from %s.\n",
           drop_count_[ref], DerefLocation(ref).c_str());
    }
  }

  // Next log unexpected drops
  for (uint16_t ref = 1; ref < next_location_ref_; ref++)
  {
    if (!location_deref_expected_[ref] && drop_count_[ref] > 0)
    {
      string loc = DerefLocation(ref);
      LogW(kClassName, __func__, "UNEXPECTED DROP: %" PRIu32
           " packets dropped from %s.\n",
           drop_count_[ref], DerefLocation(ref).c_str());
    }
  }
}

#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)

//============================================================================
void PacketPoolShm::TrackPacketRelease(Packet* pkt, PacketOwner next_owner)
{
#ifdef PKT_LEAK_DETECT
  --packets_owned_;
  ++next_owner_[next_owner];

  DoPeriodicTracking();
#endif // PKT_LEAK_DETECT

#ifdef PACKET_TRACKING
  pkt->NewPacketLocation(packet_owner_, 0);

  if (owned_[pkt->mem_index()] > 0)
  {
    owned_[pkt->mem_index()] -= 1;
  }
  else
  {
    LogW(kClassName, __func__, "Releasing unowned packet %" PRIu32 ".\n",
         pkt->mem_index());
  }
#endif // PACKET_TRACKING
}

//============================================================================
void PacketPoolShm::TrackPacketClaim(Packet* pkt, PacketOwner previous_owner)
{
#ifdef PKT_LEAK_DETECT
  ++packets_owned_;
  ++previous_owner_[previous_owner];

  DoPeriodicTracking();
#endif // PKT_LEAK_DETECT

#ifdef PACKET_TRACKING
  pkt->NewPacketLocation(packet_owner_, GetLocationRef(__FILE__, __LINE__));
  owned_[pkt->mem_index()] += 1;

  if (pkt->mem_index() < min_owned_)
  {
    min_owned_ = pkt->mem_index();
  }
  if (pkt->mem_index() > max_owned_)
  {
    max_owned_ = pkt->mem_index();
  }
#endif // PACKET_TRACKING
}

//============================================================================
void PacketPoolShm::TrackPacketCopy(Packet* pkt)
{
  // A copy (from a tracking perspecting) is just a packet claim by this owner
  // without a correponding packet relase. (That is, we are claiming a second
  // copy of the same packet.)
  TrackPacketClaim(pkt, packet_owner_);
}

#endif // PKT_LEAK_DETECT || PACKET_TRACKING

#ifdef PKT_LEAK_DETECT

//============================================================================
void PacketPoolShm::DoPeriodicTracking()
{
  Time  now = Time::Now();

  if ((now - last_owner_log_time_) >= kOwnerLogTime)
  {
    LogPacketsOwned();
    last_owner_log_time_ = now;
  }
}

//============================================================================
void PacketPoolShm::LogPacketsOwned(bool warn_if_nonzero)
{
  if (warn_if_nonzero && (packets_owned_ > 0))
  {
    LogW(kClassName, __func__, "Packets owned = %" PRId32 "\n", packets_owned_);
  }
  else
  {
    LogA(kClassName, __func__, "Packets owned = %" PRId32 "\n", packets_owned_);
  }

  for (int i = 0; i < NUM_PACKET_OWNERS; ++i)
  {
    LogD(kClassName, __func__, "Next owner [%d] = %" PRIu32 "\n",
         i, next_owner_[i]);
    LogD(kClassName, __func__, "Previous owner [%d] = %" PRIu32 "\n",
         i, previous_owner_[i]);
  }
}

#endif // PKT_LEAK_DETECT

#ifdef PACKET_TRACKING

//============================================================================
void PacketPoolShm::PacketTrackingStuckCheck()
{
  uint32_t  stuck_count[next_location_ref_][next_location_ref_]
    [next_location_ref_];

  memset(stuck_count, 0,
         (sizeof(stuck_count[0][0][0]) * next_location_ref_ *
          next_location_ref_ * next_location_ref_));

  uint16_t  stuck_at[NUM_PACKET_OWNERS];
  memset(stuck_at, 0, (NUM_PACKET_OWNERS * sizeof(stuck_at[0])));

  Packet*      pkt   = NULL;
  PktMemIndex  total = 0;

  // Look at all packets that this component owns.
  for (PktMemIndex i = min_owned_; i <= max_owned_; ++i)
  {
    if (owned_[i] > 0)
    {
      pkt = reinterpret_cast<Packet*>(packet_buffer_start_ + i);

      if (pkt->StuckCheck(stuck_at))
      {
        ++stuck_count[stuck_at[1]][stuck_at[2]][stuck_at[3]];
        ++total;
      }

      memset(stuck_at, 0, NUM_PACKET_OWNERS * sizeof(stuck_at[0]));
    }
  }

  uint16_t  loc[NUM_PACKET_OWNERS];

  for (loc[1] = 0; loc[1] < next_location_ref_; ++loc[1])
  {
    if (location_deref_held_[loc[1]])
    {
      continue;
    }

    for (loc[2] = 0; loc[2] < next_location_ref_; ++loc[2])
    {
      if (location_deref_held_[loc[2]])
      {
        continue;
      }

      for (loc[3] = 0; loc[3] < next_location_ref_; ++loc[3])
      {
        if (location_deref_held_[loc[3]])
        {
          continue;
        }

        if (stuck_count[loc[1]][loc[2]][loc[3]] > 0 &&
            (loc[1] != 0 || loc[2] != 0 || loc[3] != 0))
        {
          LogA(kClassName, __func__, "%" PRIu32 " packets stuck at "
               "locations [%" PRIu16 ", %" PRIu16 ", %" PRIu16 "] (%s).\n",
               stuck_count[loc[1]][loc[2]][loc[3]],
               loc[1], loc[2], loc[3],
               DerefLocation(loc[packet_owner_]).c_str());
        }
      }
    }
  }
}

#endif // PACKET_TRACKING

//============================================================================
uint16_t PacketPoolShm::GetLocationRef(const char* file, int line, bool held,
                                       bool expected_drop)
{
  std::stringstream  loc_ss;

  loc_ss << file;
  loc_ss << ":";
  loc_ss << line;

  if (held)
  {
    loc_ss << " (Held)";
  }

  std::string  loc_str = loc_ss.str();
  uint16_t     loc_ref = 0;

  std::map<std::string, uint16_t>::iterator it = location_ref_.find(loc_str);

  if (it != location_ref_.end())
  {
    loc_ref = (*it).second;
  }
  else
  {
    if (next_location_ref_ == kMaxLocations)
    {
      LogW(kClassName, __func__, "Too many locations (%" PRIu16 ") include "
           "location tracking. Trying to track file %s, line %d\n",
           next_location_ref_, file, line);
      return 0;
    }

    loc_ref                       = next_location_ref_;
    ++next_location_ref_;
    location_ref_[loc_str]        = loc_ref;
    location_deref_[loc_ref]      = loc_str;
#ifdef PACKET_TRACKING
    location_deref_held_[loc_ref] = held;
#endif // PACKET_TRACKING
    location_deref_expected_[loc_ref] = expected_drop;

    LogD(kClassName, __func__, "Location ref %" PRIu16 " maps to %s.\n",
         loc_ref, loc_str.c_str());
  }

  return loc_ref;
}

//============================================================================
std::string PacketPoolShm::DerefLocation(uint16_t location)
{
  if (location == 0)
  {
    return std::string("None");
  }

  if (location >= kMaxLocations)
  {
    return std::string("Invalid");
  }

  return location_deref_[location];
}

//============================================================================
void PacketPoolShm::RecordDrop(uint16_t location)
{
  LogD(kClassName, __func__, "Location %" PRIu16 " maps to string %s.\n",
       location, location_deref_[location].c_str());
  if (drop_count_[location] < std::numeric_limits<uint32_t>::max())
  {
    drop_count_[location]++;
  }
}
