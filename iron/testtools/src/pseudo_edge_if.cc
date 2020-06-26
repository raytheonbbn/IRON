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

#include "pseudo_edge_if.h"

#include "log.h"
#include "unused.h"

#include <cstring>

using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::PseudoEdgeIf;

namespace
{
  const char* UNUSED(kClassName) = "PseudoEdgeIf";
}

int PseudoEdgeIf::last_id_ = 0;

//============================================================================
PseudoEdgeIf::PseudoEdgeIf(PacketPool&  packet_pool) :
  packets_to_recv(), sent_packets(), packet_pool_(packet_pool),
  open_(false), log_recv_empty_(true), id_(++last_id_)
{
}

//============================================================================
PseudoEdgeIf::PseudoEdgeIf(PacketPool&  packet_pool,
    bool log_recv_empty) :
  packets_to_recv(), sent_packets(), packet_pool_(packet_pool),
  open_(false), log_recv_empty_(log_recv_empty), id_(++last_id_)
{
}

//============================================================================
PseudoEdgeIf::~PseudoEdgeIf()
{
  open_ = false;
  RecyclePkts(packets_to_recv);
  RecyclePkts(sent_packets);
}

//============================================================================
bool PseudoEdgeIf::Open()
{
  open_ = true;
  return true;
}

//============================================================================
bool PseudoEdgeIf::IsOpen() const
{
  return open_;
}

//============================================================================
void PseudoEdgeIf::Close()
{
  open_ = false;
}

//============================================================================
ssize_t PseudoEdgeIf::Recv(Packet* pkt, const size_t offset)
{
  if (packets_to_recv.empty())
  {
    if (log_recv_empty_)
    {
      LogE(kClassName, __func__, "%d: No packets to recv.\n");
    }
    return -1;
  }

  size_t space_available = pkt->GetMaxLengthInBytes() - offset;
  Packet* to_recv = packets_to_recv.front();
  size_t len_bytes = to_recv->GetLengthInBytes();
  if (len_bytes > space_available)
  {
    LogW(kClassName, __func__, "%d: The entire packet does not fit in the " \
                               "receive packet.\n", id_);
    return -1;
  }

  memcpy(pkt->GetBuffer(offset), to_recv->GetBuffer(), len_bytes);
  pkt->SetLengthInBytes(len_bytes);
  packets_to_recv.pop();
  packet_pool_.Recycle(to_recv);

  return len_bytes;
}

//============================================================================
ssize_t PseudoEdgeIf::Send(const Packet* pkt)
{
  Packet* sent = packet_pool_.Get();

  memcpy(sent->GetBuffer(), pkt->GetBuffer(), pkt->GetLengthInBytes());
  sent_packets.push(sent);

  return pkt->GetLengthInBytes();
}

//============================================================================
void PseudoEdgeIf::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
}

//============================================================================
bool PseudoEdgeIf::InSet(fd_set* fds) const
{
  // We expect this to only be called after a call to Select() to check if
  // there is something ready to read, so return true if there is something to
  // read.
  return IsOpen() && !packets_to_recv.empty();
}

//============================================================================
void PseudoEdgeIf::RecyclePkts(std::queue<Packet*> pkts)
{
  while(!pkts.empty())
  {
    packet_pool_.Recycle(pkts.front());
    packets_to_recv.pop();
  }
}
