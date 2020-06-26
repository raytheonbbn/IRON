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

#include "failing_edge_if.h"

#include "log.h"
#include "unused.h"

using ::iron::Packet;
using ::iron::FailingEdgeIf;

namespace
{
  const char* UNUSED(kClassName) = "FailingEdgeIf";
}

//============================================================================
FailingEdgeIf::FailingEdgeIf(bool log_recv_send)
    : open_(false), log_recv_send_(log_recv_send)
{
}

//============================================================================
FailingEdgeIf::~FailingEdgeIf()
{
}

//============================================================================
bool FailingEdgeIf::Open()
{
  open_ = true;
  return true;
}

//============================================================================
bool FailingEdgeIf::IsOpen() const
{
  return open_;
}

//============================================================================
void FailingEdgeIf::Close()
{
  open_ = false;
}

//============================================================================
ssize_t FailingEdgeIf::Recv(Packet* pkt, const size_t offset)
{
  if (log_recv_send_)
  {
    LogE(kClassName, __func__, "Attempt to receive a packet.\n");
  }
  return -1;
}

//============================================================================
ssize_t FailingEdgeIf::Send(const Packet* pkt)
{
  if (log_recv_send_)
  {
    LogE(kClassName, __func__, "Attempt to send a packet.\n");
  }
  return -1;
}

//============================================================================
void FailingEdgeIf::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
}

//============================================================================
bool FailingEdgeIf::InSet(fd_set* fds) const
{
  return false;
}
