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

#include "packet_set.h"

#include "log.h"
#include "packet_pool.h"
#include "unused.h"

using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PacketSet;


namespace
{
  /// The class name string for logging.
  const char*    UNUSED(kClassName)      = "PacketSet";

  /// The minimum packet set size, in number of packets.
  const size_t   kMinPktSetSize          = 2;

  /// The number of samples to use in computing the clock offset.
  const size_t   kNumTimeSamples         = 100;

  /// The allowable range for the clock offset samples in nanoseconds.
  const int64_t  kTimeRangeThresholdNsec = 2000;
}


// The PacketSet's static members for the clock difference.
bool      PacketSet::clock_init_   = false;
timespec  PacketSet::mono_to_real_ = {0, 0};


/// The PktInfo's static member to the packet pool.
PacketPool*  PacketSet::PktInfo::packet_pool_ = NULL;


//============================================================================
PacketSet::PacketSet(PacketPool& packet_pool)
    : pkt_pool_(packet_pool), max_size_(0), cur_size_(0), ret_idx_(0),
      walk_idx_(0), pkt_info_(NULL), msg_hdr_(NULL)
{
}

//============================================================================
PacketSet::~PacketSet()
{
  // Delete the arrays.
  if (pkt_info_ != NULL)
  {
    delete [] pkt_info_;
    pkt_info_ = NULL;
  }

  if (msg_hdr_ != NULL)
  {
    delete [] msg_hdr_;
    msg_hdr_ = NULL;
  }
}

//============================================================================
void PacketSet::Initialize(size_t num_packets)
{
  // A packet set should manage a minimum number of packets.
  if (num_packets < kMinPktSetSize)
  {
    LogW(kClassName, __func__, "Number of packets specified was %zu, using "
         "%zu.\n", num_packets, kMinPktSetSize);
    num_packets = kMinPktSetSize;
  }

  if (num_packets > max_size_)
  {
    if (pkt_info_ != NULL)
    {
      delete [] pkt_info_;
    }

    if (msg_hdr_ != NULL)
    {
      delete [] msg_hdr_;
    }

    // Allocate the arrays.
    pkt_info_ = new (std::nothrow) PktInfo[num_packets];
    msg_hdr_  = new (std::nothrow) mmsghdr[num_packets];

    if ((pkt_info_ == NULL) || (msg_hdr_ == NULL))
    {
      LogF(kClassName, __func__, "Memory allocation error.\n");
    }

    // Initialize the state.
    max_size_ = num_packets;
    cur_size_ = 0;
    ret_idx_  = 0;
    walk_idx_ = 0;

    PktInfo::SetPacketPool(&pkt_pool_);

    // Set up all of the mmsghdr, msghdr, and iovec structures.
    for (size_t i = 0; i < max_size_; ++i)
    {
      pkt_info_[i].packet_ = pkt_pool_.Get();

      if (pkt_info_[i].packet_ == NULL)
      {
        LogF(kClassName, __func__, "Unable to get packet from pool.\n");
      }
#ifdef PACKET_TRACKING
      NEW_HELD_PKT_LOC(pkt_pool_, pkt_info_[i].packet_);
#endif // PACKET_TRACKING

      msg_hdr_[i].msg_len = 0;

      msg_hdr_[i].msg_hdr.msg_name    =
        static_cast<void*>(&(pkt_info_[i].src_addr_));
      msg_hdr_[i].msg_hdr.msg_namelen = sizeof(pkt_info_[i].src_addr_);

      msg_hdr_[i].msg_hdr.msg_iov    = &(pkt_info_[i].io_vec_);
      msg_hdr_[i].msg_hdr.msg_iovlen = 1;

      msg_hdr_[i].msg_hdr.msg_control    =
        static_cast<void*>(pkt_info_[i].cmsg_buf_);
      msg_hdr_[i].msg_hdr.msg_controllen = kCmsgSize;

      msg_hdr_[i].msg_hdr.msg_flags = 0;

      pkt_info_[i].io_vec_.iov_base = pkt_info_[i].packet_->GetBuffer();
      pkt_info_[i].io_vec_.iov_len  =
        pkt_info_[i].packet_->GetMaxLengthInBytes();
    }
  }

  // If the monotonic clock to real time clock offset has already been
  // computed, then return.
  if (clock_init_)
  {
    return;
  }

  // Compute the amount to adjust the real time clock values from the kernel
  // to monotonic clock values.  Retry until the delta value range is within a
  // threshold.
  int64_t  range_nsec = (kTimeRangeThresholdNsec + 1);

  while (range_nsec > kTimeRangeThresholdNsec)
  {
    bool      init          = false;
    int64_t   pedestal_nsec = 0;
    int64_t   max_nsec      = 0;
    int64_t   min_nsec      = 0;
    timespec  cgt_mono      = {0, 0};
    timespec  cgt_real      = {0, 0};
    double    sum_delta     = 0.0;

    for (size_t i = 0; i < kNumTimeSamples; i++)
    {
      timespec  sleep_time = {0, 1000000};

      nanosleep(&sleep_time, NULL);

      clock_gettime(CLOCK_MONOTONIC, &cgt_mono);
      clock_gettime(CLOCK_REALTIME, &cgt_real);

      int64_t  cgt_mono_nsec = ((static_cast<int64_t>(cgt_mono.tv_sec) *
                                 1000000000LL) +
                                static_cast<int64_t>(cgt_mono.tv_nsec));
      int64_t  cgt_real_nsec = ((static_cast<int64_t>(cgt_real.tv_sec) *
                                 1000000000LL) +
                                static_cast<int64_t>(cgt_real.tv_nsec));

      int64_t  delta_nsec = (cgt_real_nsec - cgt_mono_nsec);

      if (!init)
      {
        init          = true;
        pedestal_nsec = (delta_nsec - (delta_nsec % 1000000LL));
        max_nsec      = (delta_nsec - pedestal_nsec);
        min_nsec      = (delta_nsec - pedestal_nsec);
      }

      delta_nsec -= pedestal_nsec;

      if (delta_nsec > max_nsec)
      {
        max_nsec = delta_nsec;
      }

      if (delta_nsec < min_nsec)
      {
        min_nsec = delta_nsec;
      }

      sum_delta += static_cast<double>(delta_nsec);
    }

    double   avg_delta  = (sum_delta / static_cast<double>(kNumTimeSamples));
    int64_t  delta_nsec = (pedestal_nsec +
                           static_cast<int64_t>(avg_delta + 0.5));

    mono_to_real_.tv_sec  = static_cast<time_t>(delta_nsec / 1000000000LL);
    mono_to_real_.tv_nsec = static_cast<long>(delta_nsec % 1000000000LL);

    range_nsec = (max_nsec - min_nsec);
  }

  clock_init_ = true;
}

//============================================================================
bool PacketSet::PrepareForRecvMmsg()
{
  if (max_size_ == 0)
  {
    LogE(kClassName, __func__, "Set not initialized.\n");
    return false;
  }

  // Only prepare the elements that are missing.
  for (size_t i = 0; i < ret_idx_; ++i)
  {
    if (pkt_info_[i].packet_ == NULL)
    {
      pkt_info_[i].packet_ = pkt_pool_.Get();

      if (pkt_info_[i].packet_ == NULL)
      {
        LogF(kClassName, __func__, "Unable to get packet from pool.\n");
      }
#ifdef PACKET_TRACKING
      NEW_HELD_PKT_LOC(pkt_pool_, pkt_info_[i].packet_);
#endif // PACKET_TRACKING

      pkt_info_[i].io_vec_.iov_base = pkt_info_[i].packet_->GetBuffer();
      pkt_info_[i].io_vec_.iov_len  =
        pkt_info_[i].packet_->GetMaxLengthInBytes();
    }

    msg_hdr_[i].msg_hdr.msg_controllen = kCmsgSize;
  }

  cur_size_ = 0;
  ret_idx_  = 0;
  walk_idx_ = 0;

  return true;
}

//============================================================================
void PacketSet::FinalizeRecvMmsg(int packets_read, bool record_rcv_time)
{
  if (packets_read <= 0)
  {
    cur_size_ = 0;
    return;
  }

  // Get the current time.
  Time  now = Time::Now();

  // Loop over the received messages.
  for (int i = 0; i < packets_read; ++i)
  {
    // Get any receive timestamp that the kernel has set for the packet.  See
    // the man page cmsg(3) for details on the CMSG_*() macros that are used.
    bool      has_kernel_ts = false;
    msghdr*   msg           = &(msg_hdr_[i].msg_hdr);
    cmsghdr*  cmsg          = NULL;
    timespec  ts_rcv_real;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(msg, cmsg))
    {
      if ((cmsg->cmsg_level == SOL_SOCKET) &&
          (cmsg->cmsg_type == SO_TIMESTAMPNS))
      {
        has_kernel_ts = true;
        memcpy(&ts_rcv_real, CMSG_DATA(cmsg), sizeof(ts_rcv_real));
        break;
      }
    }

    // Set the received message length in the packet.
    pkt_info_[i].packet_->SetLengthInBytes(msg_hdr_[i].msg_len);

    // Compute the packet's receive time.
    if (has_kernel_ts)
    {
      // Adjust the kernel's real time clock value to a monotonic clock value
      // using the offset computed in Initialize().
      timespec  ts_rcv_mono;

      if (ts_rcv_real.tv_nsec < mono_to_real_.tv_nsec)
      {
        ts_rcv_mono.tv_sec  = (ts_rcv_real.tv_sec - mono_to_real_.tv_sec - 1);
        ts_rcv_mono.tv_nsec = (ts_rcv_real.tv_nsec - mono_to_real_.tv_nsec +
                               1000000000L);
      }
      else
      {
        ts_rcv_mono.tv_sec  = (ts_rcv_real.tv_sec - mono_to_real_.tv_sec);
        ts_rcv_mono.tv_nsec = (ts_rcv_real.tv_nsec - mono_to_real_.tv_nsec);
      }

      pkt_info_[i].rcv_time_ = Time(ts_rcv_mono);
    }
    else
    {
      // Simply use the current time from the monotonic clock.
      pkt_info_[i].rcv_time_ = now;
    }

    // Set the optional receive time in the packet.
    if (record_rcv_time)
    {
      pkt_info_[i].packet_->set_recv_time(pkt_info_[i].rcv_time_);
    }

    // Set the source address and port number in the IPv4 endpoint.
    pkt_info_[i].src_endpt_.set_address(
      pkt_info_[i].src_addr_.sin_addr.s_addr);
    pkt_info_[i].src_endpt_.set_port(pkt_info_[i].src_addr_.sin_port);
  }

  // Store the number of packets with data.
  cur_size_ = packets_read;
}

//============================================================================
bool PacketSet::GetNextPacket(Packet*& packet, Ipv4Endpoint& src_endpoint,
                              Time& rcv_time)
{
  if (walk_idx_ > 0)
  {
    LogE(kClassName, __func__, "Cannot return packets while walking the "
         "packet set.\n");
    return false;
  }

  if (ret_idx_ >= cur_size_)
  {
    return false;
  }

  // Return the next packet and source address to the caller.  The packet
  // ownership is transferred to the caller.
  packet                      = pkt_info_[ret_idx_].packet_;
  src_endpoint                = pkt_info_[ret_idx_].src_endpt_;
  rcv_time                    = pkt_info_[ret_idx_].rcv_time_;
  pkt_info_[ret_idx_].packet_ = NULL;
  ++ret_idx_;
#ifdef PACKET_TRACKING
  NEW_PKT_LOC(pkt_pool_, packet);
#endif // PACKET_TRACKING
  return true;
}

//============================================================================
void PacketSet::StartIteration()
{
  // Set the walk index to the start of the arrays.
  walk_idx_ = 0;
}

//============================================================================
Packet* PacketSet::GetNext()
{
  if (ret_idx_ > 0)
  {
    LogE(kClassName, __func__, "Cannot walk the packet set while returning "
         "packets.\n");
    return NULL;
  }

  if (walk_idx_ >= cur_size_)
  {
    return NULL;
  }

  // Return the next packet to the caller.  The packet remains owned by this
  // object.
  Packet*  pkt = pkt_info_[walk_idx_].packet_;
  ++walk_idx_;

  return pkt;
}

//============================================================================
void PacketSet::StopIteration()
{
  // The walk is done.
  walk_idx_ = 0;
}

//============================================================================
PacketSet::PktInfo::PktInfo()
    : packet_(NULL), src_addr_(), io_vec_(), cmsg_buf_(), src_endpt_(),
      rcv_time_()
{
}

//============================================================================
PacketSet::PktInfo::~PktInfo()
{
  // Recycle any packet.
  if ((packet_ != NULL) && (packet_pool_ != NULL))
  {
    packet_pool_->Recycle(packet_);
    packet_ = NULL;
  }
}
