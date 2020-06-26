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

/// \brief The IRON inter-process communications (IPC) module.
///
/// Provides the IRON software with an efficient, flexible, message-based
/// inter-process communications capability.

#include "inter_process_comm.h"

#include "log.h"
#include "unused.h"

#include <cerrno>
#include <unistd.h>


using ::iron::InterProcessComm;
using ::iron::Log;
using ::std::string;


namespace
{
  const char*  UNUSED(CLASS_NAME) = "InterProcessComm";
}


//============================================================================
InterProcessComm::InterProcessComm()
    : socket_fd_(-1), is_connected_(false)
{
  memset(&local_addr_, 0, sizeof(local_addr_));
  memset(&remote_addr_, 0, sizeof(remote_addr_));
}

//============================================================================
InterProcessComm::~InterProcessComm()
{
  if (socket_fd_ >= 0)
  {
    Close();
  }
}

//============================================================================
bool InterProcessComm::Open(const string local_path)
{
  static const char*  UNUSED(mn)  = "Open";

  // Validate the local pathname specified.
  if ((local_path.size() < 1) ||
      (local_path.size() >= sizeof(local_addr_.sun_path)))
  {
    LogE(CLASS_NAME, mn, "Error, invalid path: \"%s\"\n", local_path.c_str());
    return false;
  }

  // Close any existing endpoint.
  if (socket_fd_ >= 0)
  {
    Close();
  }

  // Create the UNIX domain socket using datagram packets.
  if ((socket_fd_ = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
  {
    LogE(CLASS_NAME, mn, "Error opening socket: %s\n", strerror(errno));
    Close();
    return false;
  }

  // Set the socket's send buffer size.  Note that the kernel doubles these
  // values to allow for bookkeeping overhead.
  int        buf_size_bytes = (2 * 1024 * 1024);  // 2 MB
  socklen_t  opt_size       = sizeof(buf_size_bytes);

  if (setsockopt(socket_fd_, SOL_SOCKET, SO_SNDBUF, &buf_size_bytes,
                 opt_size) != 0)
  {
    LogE(CLASS_NAME, mn, "Error setting send buffer size to %d bytes: %s\n",
         buf_size_bytes, strerror(errno));
    Close();
    return false;
  }

  // Store the local pathname.
  local_path_ = local_path;

  // Create the local address from the local pathname.
  memset(&local_addr_, 0, sizeof(local_addr_));
  local_addr_.sun_family = AF_UNIX;
  // Note: the use of local_path instead of local_path_ in the following so
  // that coverity does not complain that the length of local_path_ is not
  // checked.
  strcpy(local_addr_.sun_path, local_path.c_str());

  // Delete any old pathname file.
  unlink(local_path_.c_str());

  // Bind the local address to the socket.
  if (bind(socket_fd_,
           reinterpret_cast<const struct sockaddr *>(&local_addr_),
           sizeof(local_addr_)) < 0)
  {
    LogE(CLASS_NAME, mn, "Error binding socket: %s\n", strerror(errno));
    Close();
    return false;
  }

  LogD(CLASS_NAME, mn, "Opened IPC socket %s.\n", local_path_.c_str());

  return true;
}

//============================================================================
bool InterProcessComm::Connect(const string remote_path)
{
  static const char*  UNUSED(mn)  = "Connect";

  // Validate the remote pathname specified.
  if ((remote_path.size() < 1) ||
      (remote_path.size() >= sizeof(remote_addr_.sun_path)))
  {
    LogE(CLASS_NAME, mn, "Error, invalid path: \"%s\"\n",
         remote_path.c_str());
    return false;
  }

  // The socket must already be open.
  if (socket_fd_ < 0)
  {
    LogE(CLASS_NAME, mn, "Error, socket not open for connect call.\n");
    return false;
  }

  // Store the remote pathname.
  remote_path_ = remote_path;

  // Create the remote address from the remote pathname.
  memset(&remote_addr_, 0, sizeof(remote_addr_));
  remote_addr_.sun_family = AF_UNIX;
  // Note: the use of remote_path instead of remote_path_ in the following so
  // that coverity does not complain that the length of remote_path_ is not
  // checked. 
  strcpy(remote_addr_.sun_path, remote_path.c_str());

  // The endpoint is now connnected.
  is_connected_ = true;

  LogD(CLASS_NAME, mn, "Connected IPC socket %s to %s.\n", local_path_.c_str(),
       remote_path_.c_str());

  return true;
}

//============================================================================
void InterProcessComm::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
  if (socket_fd_ >= 0)
  {
    if (socket_fd_ > max_fd)
    {
      max_fd  = socket_fd_;
    }

    FD_SET(socket_fd_, &read_fds);
  }
}

//============================================================================
bool InterProcessComm::SendMessage(uint8_t* buf, size_t len, bool blocking)
{
  static const char*  UNUSED(mn)  = "SendMessage";

  // Validate the arguments.
  if ((buf == NULL) || (len < 1))
  {
    LogE(CLASS_NAME, mn, "Error, invalid argument: buf=%p len=%zu.\n", buf,
         len);
    return false;
  }

  // The socket must already be open and connected.
  if ((socket_fd_ < 0) || (!is_connected_))
  {
    LogE(CLASS_NAME, mn, "Error, socket not open or connected for send "
         "call.\n");
    return false;
  }

  // Perform the send.
  ssize_t  bytes_sent =
    sendto(socket_fd_, static_cast<const void *>(buf), len,
           (blocking ? 0 : MSG_DONTWAIT),
           reinterpret_cast<const struct sockaddr *>(&remote_addr_),
           static_cast<socklen_t>(sizeof(remote_addr_)));

  if (bytes_sent != static_cast<ssize_t>(len))
  {
    if (bytes_sent < 0)
    {
      if (!blocking && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
      {
        LogD(CLASS_NAME, mn, "Send would block on socket to %s.\n",
             remote_path_.c_str());
      }
      else
      {
        LogE(CLASS_NAME, mn, "Error sending on socket: %s\n", strerror(errno));
      }
    }
    else
    {
      LogE(CLASS_NAME, mn,
           "Error, only sent %zd bytes of %zu byte message.\n", bytes_sent,
           len);
    }
    return false;
  }

  LogD(CLASS_NAME, mn, "SEND: IPC to %s, size: %zu bytes.\n", remote_path_.c_str(), len);

  return true;
}

//============================================================================
size_t InterProcessComm::ReceiveMessage(uint8_t* buf, size_t max_len,
                                        bool blocking)
{
  static const char*  UNUSED(mn)  = "ReceiveMessage";

  // Validate the arguments.
  if ((buf == NULL) || (max_len < 1))
  {
    LogE(CLASS_NAME, mn, "Error, invalid argument: buf=%p max_len=%zu.\n",
         buf, max_len);
    return static_cast<size_t>(0);
  }

  // The socket must already be open.
  if (socket_fd_ < 0)
  {
    LogE(CLASS_NAME, mn, "Error, socket not open for receive call.\n");
    return static_cast<size_t>(0);
  }

  // Perform the receive.
  sockaddr_un  src_addr;
  socklen_t    src_addr_len = sizeof(src_addr);
  ssize_t      bytes_received =
    recvfrom(socket_fd_, static_cast<void *>(buf), max_len,
             (blocking ? 0 : MSG_DONTWAIT),
             reinterpret_cast<struct sockaddr *>(&src_addr), &src_addr_len);

  if (bytes_received < 0)
  {
    if (!blocking && ((errno == EAGAIN) || (errno == EWOULDBLOCK)))
    {
      LogD(CLASS_NAME, mn, "No messages to receive on socket from %s.\n",
           remote_path_.c_str());
    }
    else
    {
      LogE(CLASS_NAME, mn, "Error receiving on socket: %s\n",
           strerror(errno));
    }
    return static_cast<size_t>(0);
  }

  LogD(CLASS_NAME, mn, "RECV: IPC from %s, size: %zd bytes.\n",
       src_addr.sun_path, bytes_received);

  return static_cast<size_t>(bytes_received);
}

//============================================================================
size_t InterProcessComm::ReceiveMessages(PacketSet& packet_set,
                                         bool blocking,
                                         int num_pkts)
{
  // Prepare for the recvmmsg call. To do so, we prep the PacketSet to be the
  // destination of the data that gets read from the socket.
  if (!packet_set.PrepareForRecvMmsg())
  {
    LogE(CLASS_NAME, __func__, "Error preparing PacketSet for reading "
         "packets.\n");
    return static_cast<size_t>(0);
  }

  int  packets_read = recvmmsg(socket_fd_, packet_set.GetVecPtr(),
                               packet_set.GetVecLen(),
                               (blocking ? 0 : MSG_DONTWAIT), NULL);

  if (packets_read <= 0)
  {
    LogE(CLASS_NAME, __func__, "recvmmsg error: %s\n", strerror(errno));
    return static_cast<size_t>(0);
  }

  packet_set.FinalizeRecvMmsg(packets_read, true);

  return static_cast<size_t>(packets_read);
}

//============================================================================
void InterProcessComm::Close()
{
  if (socket_fd_ >= 0)
  {
    close(socket_fd_);
    unlink(local_path_.c_str());
    socket_fd_ = -1;
  }

  is_connected_ = false;
  local_path_.clear();
  remote_path_.clear();
  memset(&local_addr_, 0, sizeof(local_addr_));
  memset(&remote_addr_, 0, sizeof(remote_addr_));
}
