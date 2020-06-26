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

/// \brief The inter-process signaling module for packet indices
///
/// Provides the IRON software with the capability to pass packet shared
/// memory indices between separate processes on a single computer. When this
/// is used to transfer a packet index, control of that packet is being
/// logically tranferred to the receiving process.

#include "packet_fifo.h"

#include "log.h"
#include "unused.h"

#include <cstring>

using ::iron::FifoIF;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketFifo;
using ::iron::PacketPool;


namespace
{
  const char*  UNUSED(kClassName) = "PacketFifo";
}


//============================================================================
PacketFifo::PacketFifo(PacketPool& packet_pool,
                       FifoIF* fifo,
                       PacketOwner remote_owner,
                       size_t max_pkts_to_recv)
    : packet_pool_(packet_pool),
      fifo_(fifo),
      remote_owner_(remote_owner),
      max_bytes_to_recv_(max_pkts_to_recv * sizeof(PktMemIndex)),
      num_viewed_pkts_(0),
      num_pkts_rcvd_(0),
      recv_pkt_index_buf_(),
      last_recv_time_(0)
{
  memset(recv_pkt_index_buf_, 0, sizeof(recv_pkt_index_buf_));
  if (max_pkts_to_recv > kRecvBufferSizePkts)
  {
    LogW(kClassName, __func__, "max_pkts_to_recv (%zd) is greater than "
         "buffer size (%zd).", max_pkts_to_recv, kRecvBufferSizePkts);
    max_bytes_to_recv_ = kRecvBufferSizePkts * sizeof(PktMemIndex);
  }
}

//============================================================================
PacketFifo::~PacketFifo()
{
}

//============================================================================
bool PacketFifo::OpenReceiver()
{
  return fifo_->OpenReceiver();
}

//============================================================================
bool PacketFifo::OpenSender()
{
  return fifo_->OpenSender();
}

//============================================================================
void PacketFifo::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
  fifo_->AddFileDescriptors(max_fd, read_fds);
}

//============================================================================
bool PacketFifo::InSet(fd_set* fds)
{
  return fifo_->InSet(fds);
}

//============================================================================
bool PacketFifo::IsOpen()
{
  return fifo_->IsOpen();
}

//============================================================================
// \todo: Create partner method for sending multiple packet indices aggregated
// into a single fifo send (to minimize the number of system calls required).
bool PacketFifo::Send(Packet* packet)
{
  if (fifo_->IsOpen() || fifo_->OpenSender())
  {
    PktMemIndex  msg = packet->mem_index();

    if (fifo_->Send(reinterpret_cast<uint8_t*>(&msg), sizeof(msg)))
    {
#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)
      packet_pool_.TrackPacketRelease(packet, remote_owner_);
#endif // PKT_LEAK_DETECT || PACKET_TRACKING
      return true;
    }
    else
    {
      LogW(kClassName, __func__, "Unable to send packet index over fifo.\n");
      return false;
    }
  }
  else
  {
    LogW(kClassName, __func__, "Unable to open fifo.\n");
    return false;
  }
  return false;
}

//============================================================================
bool PacketFifo::Recv()
{
  if (num_viewed_pkts_ < num_pkts_rcvd_)
  {
    LogW(kClassName, __func__, "%zd packets were received over the fifo from "
         "owner %d, but only %zd were viewed.\n",
         num_pkts_rcvd_, num_viewed_pkts_);
  }
  num_viewed_pkts_ = 0;
  num_pkts_rcvd_ = 0;

  // Read in packet indices from the underlying fifo.
  size_t  bytes = fifo_->Recv(reinterpret_cast<uint8_t*>(
                               &(recv_pkt_index_buf_[0])),
                             max_bytes_to_recv_);

  // Make sure that whole packet indices were read.
  if ((bytes % sizeof(PktMemIndex)) != 0)
  {
    LogW(kClassName, __func__, "Partial packet index read detected from "
         "packet owner %d.\n", remote_owner_);

    bytes += fifo_->Recv((reinterpret_cast<uint8_t*>(
                           &(recv_pkt_index_buf_[0])) + bytes),
                        (sizeof(PktMemIndex) -
                         (bytes % sizeof(PktMemIndex))));

    if ((bytes % sizeof(PktMemIndex)) != 0)
    {
      LogF(kClassName, __func__, "Error correcting for partial packet index "
           "read from packet owner %d.\n", remote_owner_);
      return false;
    }
  }

  // Process the packet indices.
  if (bytes > 0)
  {
    last_recv_time_    = Time::Now();
    num_pkts_rcvd_     = (bytes / sizeof(PktMemIndex));

    LogD(kClassName, __func__, "Read %zd packets from packet owner %d.\n",
         num_pkts_rcvd_, remote_owner_);
    return true;
  }
  return false;
}

//============================================================================
bool PacketFifo::GetNextRcvdPacket(Packet** packet)
{
  if (num_viewed_pkts_ >= num_pkts_rcvd_)
  {
    return false;
  }

  Packet* pkt = packet_pool_.GetPacketFromIndex(
    recv_pkt_index_buf_[num_viewed_pkts_]);
  num_viewed_pkts_++;
  if (pkt != NULL)
  {
#if defined(PKT_LEAK_DETECT) || defined(PACKET_TRACKING)
    packet_pool_.TrackPacketClaim(pkt, remote_owner_);
#endif // PKT_LEAK_DETECT || PACKET_TRACKING
    pkt->set_recv_time(last_recv_time_);
  }
  else
  {
    LogW(kClassName, __func__, "Invalid packet index received over fifo.\n");
  }
  *packet = pkt;
  return true;
}
