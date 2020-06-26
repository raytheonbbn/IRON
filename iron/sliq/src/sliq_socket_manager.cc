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

#include "sliq_socket_manager.h"

#include "fd_event.h"
#include "log.h"
#include "unused.h"

#include <cerrno>
#include <cstring>
#include <unistd.h>

using ::sliq::SocketId;
using ::sliq::SocketManager;
using ::sliq::WriteResult;
using ::iron::FdEvent;
using ::iron::FdEventInfo;
using ::iron::Log;
using ::iron::Ipv4Endpoint;
using ::iron::Packet;
using ::iron::PacketSet;


namespace
{
  const char*  UNUSED(kClassName) = "SocketManager";
}


//============================================================================
SocketManager::SocketManager()
    : valid_socket_mask_(), socket_list_(NULL), sockets_(NULL)
{
  FD_ZERO(&valid_socket_mask_);
}

//============================================================================
SocketManager::~SocketManager()
{
  // Close the sockets and destroy the dynamically allocated memory.
  while (socket_list_ != NULL)
  {
    SockInfo*  sock_info = socket_list_;

    socket_list_ = sock_info->next;

    if (socket_list_ != NULL)
    {
      socket_list_->prev = NULL;
      sock_info->next    = NULL;
    }

    close(sock_info->fd_event_info.fd);

    delete sock_info;
  }

  if (sockets_ != NULL)
  {
    delete [] sockets_;
    sockets_ = NULL;
  }

  FD_ZERO(&valid_socket_mask_);
}

//============================================================================
bool SocketManager::Initialize()
{
  if (sockets_ == NULL)
  {
    sockets_ = new (std::nothrow) SockInfo*[FD_SETSIZE];

    if (sockets_ == NULL)
    {
      LogE(kClassName, __func__, "Error allocating socket array.\n");
      return false;
    }

    for (size_t i = 0; i < FD_SETSIZE; ++i)
    {
      sockets_[i] = NULL;
    }
  }

  return true;
}

//============================================================================
SocketId SocketManager::CreateUdpSocket(FdEvent events)
{
  int  fd;

  if ((fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP)) < 0)
  {
    LogE(kClassName, __func__, "Socket error: %s\n", strerror(errno));
    return -1;
  }

  // Make sure that we have been assigned a file descriptor that we can
  // determine is valid.
  if (fd >= FD_SETSIZE)
  {
    LogE(kClassName, __func__, "Socket Id %d exceeds maximum number of "
         "supported sockets, %d.\n", fd, (int)FD_SETSIZE);
    close(fd);
    return -1;
  }

  // Create a new socket information structure for the created socket and add
  // it to the linked list and array.
  SockInfo*  sock_info = new (std::nothrow) SockInfo;

  if (sock_info == NULL)
  {
    LogE(kClassName, __func__, "Error allocating new SockInfo.\n");
    close(fd);
    return -1;
  }

  // Add the newly created file descriptor to the valid socket mask.
  FD_SET(fd, &valid_socket_mask_);

  // Set the file descriptor event information.
  sock_info->fd_event_info.fd     = fd;
  sock_info->fd_event_info.events = events;

  // Add the socket information structure to the linked list and array.
  sock_info->next = socket_list_;
  sock_info->prev = NULL;

  if (socket_list_ != NULL)
  {
    socket_list_->prev = sock_info;
  }

  socket_list_ = sock_info;

  if (sockets_ != NULL)
  {
    sockets_[fd] = sock_info;
  }

  return fd;
}

//============================================================================
bool SocketManager::SetRecvBufferSize(SocketId socket_id, size_t size)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  if (setsockopt(socket_id, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) != 0)
  {
    LogE(kClassName, __func__, "Failed to set socket receive buffer size to "
         "%zu on socket id %" PRISocketId ": %s\n", size, socket_id,
         strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SocketManager::SetSendBufferSize(SocketId socket_id, size_t size)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  if (setsockopt(socket_id, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0)
  {
    LogE(kClassName, __func__, "Failed to set socket send buffer size to %zu "
         "on socket id %" PRISocketId ": %s\n", size, socket_id,
         strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SocketManager::EnableReceiveTimestamps(SocketId socket_id)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  int  opt_val = 1;

  if (setsockopt(socket_id, SOL_SOCKET, SO_TIMESTAMPNS, &opt_val,
                 sizeof(opt_val)) < 0)
  {
    LogE(kClassName, __func__, "Failed to enable timestamps on socket id %"
         PRISocketId ": %s\n", socket_id, strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SocketManager::EnablePortReuse(SocketId socket_id)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  int  opt_val = 1;

  if (setsockopt(socket_id, SOL_SOCKET, SO_REUSEPORT, &opt_val,
                 sizeof(opt_val)) < 0)
  {
    LogE(kClassName, __func__, "Failed to enable port number reuse on socket "
         "id %" PRISocketId ": %s\n", socket_id, strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SocketManager::Bind(SocketId socket_id, const Ipv4Endpoint& endpoint)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  struct sockaddr_in  addr;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_port        = endpoint.port();
  addr.sin_addr.s_addr = endpoint.address();

  if (bind(socket_id, reinterpret_cast<struct sockaddr*>(&addr),
           sizeof(addr)) < 0)
  {
    LogE(kClassName, __func__, "Bind error on socket id %" PRISocketId
         ": %s\n", socket_id, strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SocketManager::Connect(SocketId socket_id,
                            const Ipv4Endpoint& endpoint)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  struct sockaddr_in  addr;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_port        = endpoint.port();
  addr.sin_addr.s_addr = endpoint.address();

  if (connect(socket_id, reinterpret_cast<struct sockaddr *>(&addr),
              sizeof(addr)) < 0)
  {
    LogE(kClassName, __func__, "Connect error on socket id %" PRISocketId
         ": %s\n", socket_id, strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SocketManager::GetLocalAddress(SocketId socket_id,
                                    Ipv4Endpoint& local_addr)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  struct sockaddr_in  addr;
  socklen_t           addr_len = sizeof(addr);

  memset(&addr, 0, sizeof(addr));

  if (getsockname(socket_id, reinterpret_cast<struct sockaddr*>(&addr),
                  &addr_len) < 0)
  {
    LogE(kClassName, __func__, "Getsockname error on socket id %" PRISocketId
         ": %s\n", socket_id, strerror(errno));
    return false;
  }

  if ((addr_len != sizeof(addr)) || (addr.sin_family != AF_INET))
  {
    LogE(kClassName, __func__, "Failed to get local address on socket id %"
         PRISocketId ".\n", socket_id);
    return false;
  }

  local_addr.set_address(addr.sin_addr.s_addr);
  local_addr.set_port(addr.sin_port);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Local address is %s.\n",
       local_addr.ToString().c_str());
#endif

  return true;
}

//============================================================================
bool SocketManager::UpdateEvents(SocketId socket_id, FdEvent events)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  if (sockets_ != NULL)
  {
    SockInfo*  sock_info = sockets_[socket_id];

    if (sock_info != NULL)
    {
      sock_info->fd_event_info.events = events;
      return true;
    }
  }

  LogE(kClassName, __func__, "Socket id %" PRISocketId " not found.\n",
       socket_id);

  return false;
}

//============================================================================
size_t SocketManager::GetFileDescriptors(FdEventInfo* fd_event_array,
                                         size_t array_size) const
{
  size_t     count     = 0;
  SockInfo*  sock_info = socket_list_;

  while ((sock_info != NULL) && (count < array_size))
  {
    fd_event_array[count].fd     = sock_info->fd_event_info.fd;
    fd_event_array[count].events = sock_info->fd_event_info.events;

    ++count;
    sock_info = sock_info->next;
  }

  return count;
}

//============================================================================
int SocketManager::ReadPackets(SocketId socket_id, PacketSet& packet_set)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return 0;
  }

  // Prepare for the recvmmsg call.  To do so, we prep the PacketSet to be the
  // destination of the data that gets read from the socket.
  if (!packet_set.PrepareForRecvMmsg())
  {
    LogE(kClassName, __func__, "Error preparing PacketSet for reading "
         "packets.\n");
    return 0;
  }

  int  packets_read = recvmmsg(socket_id, packet_set.GetVecPtr(),
                               packet_set.GetVecLen(), MSG_DONTWAIT, NULL);

  if (packets_read <= 0)
  {
    // Do not log connection refused errors.  These are caused by the peer's
    // socket not being open yet, which can happen at the beginning or end of
    // a connection.
    if ((packets_read < 0) && (errno != ECONNREFUSED) && (errno != EAGAIN) &&
        (errno != EWOULDBLOCK))
    {
      LogE(kClassName, __func__, "Recvmmsg error on socket id %" PRISocketId
           ": %s\n", socket_id, strerror(errno));
    }
    return 0;
  }

  packet_set.FinalizeRecvMmsg(packets_read, true);

  return packets_read;
}

//============================================================================
WriteResult SocketManager::WritePacket(
  SocketId socket_id, Packet& packet,
  const Ipv4Endpoint& peer_address)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return WriteResult(WRITE_STATUS_ERROR, EBADF);
  }

  struct sockaddr  address;
  socklen_t        address_len = sizeof(struct sockaddr);

  peer_address.ToSockAddr(&address);

  struct iovec  iov;

  iov.iov_base = packet.GetMetadataHeaderBuffer();
  iov.iov_len  = (packet.GetMetadataHeaderLengthInBytes() +
                  packet.GetLengthInBytes());

  struct msghdr  hdr;

  hdr.msg_name        = &address;
  hdr.msg_namelen     = address_len;
  hdr.msg_iov         = &iov;
  hdr.msg_iovlen      = 1;
  hdr.msg_control     = NULL;
  hdr.msg_controllen  = 0;
  hdr.msg_flags       = 0;

  // Send the packet.
  int  rc = sendmsg(socket_id, &hdr, 0);

  if (rc >= 0)
  {
    if (static_cast<size_t>(rc) != iov.iov_len)
    {
      return WriteResult(WRITE_STATUS_ERROR, EIO);
    }

    return WriteResult(WRITE_STATUS_OK, rc);
  }

  return WriteResult(((errno == EAGAIN) || (errno == EWOULDBLOCK)) ?
                     WRITE_STATUS_BLOCKED : WRITE_STATUS_ERROR, errno);
}

//============================================================================
WriteResult SocketManager::WritePacket(
  SocketId socket_id, Packet& header, Packet& data,
  const Ipv4Endpoint& peer_address)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return WriteResult(WRITE_STATUS_ERROR, EBADF);
  }

  struct sockaddr  address;
  socklen_t        address_len = sizeof(struct sockaddr);

  peer_address.ToSockAddr(&address);

  struct iovec  iov[2];

  iov[0].iov_base = header.GetMetadataHeaderBuffer();
  iov[0].iov_len  = (header.GetMetadataHeaderLengthInBytes() +
                     header.GetLengthInBytes());

  iov[1].iov_base = data.GetMetadataHeaderBuffer();
  iov[1].iov_len  = (data.GetMetadataHeaderLengthInBytes() +
                     data.GetLengthInBytes());

  struct msghdr  hdr;

  hdr.msg_name        = &address;
  hdr.msg_namelen     = address_len;
  hdr.msg_iov         = &(iov[0]);
  hdr.msg_iovlen      = 2;
  hdr.msg_control     = NULL;
  hdr.msg_controllen  = 0;
  hdr.msg_flags       = 0;

  // Send the packet.
  int  rc = sendmsg(socket_id, &hdr, 0);

  if (rc >= 0)
  {
    if (static_cast<size_t>(rc) != (iov[0].iov_len + iov[1].iov_len))
    {
      return WriteResult(WRITE_STATUS_ERROR, EIO);
    }

    return WriteResult(WRITE_STATUS_OK, rc);
  }

  return WriteResult(((errno == EAGAIN) || (errno == EWOULDBLOCK)) ?
                     WRITE_STATUS_BLOCKED : WRITE_STATUS_ERROR, errno);
}

//============================================================================
bool SocketManager::Close(SocketId socket_id)
{
  if (!FD_ISSET(socket_id, &valid_socket_mask_))
  {
    LogE(kClassName, __func__, "Invalid socket id %" PRISocketId ".\n",
         socket_id);
    return false;
  }

  if (close(socket_id) < 0)
  {
    LogE(kClassName, __func__, "Close error on socket id %" PRISocketId
         ": %s.\n", socket_id, strerror(errno));
    return false;
  }

  // Clear the file descriptor in the valid socket mask.
  FD_CLR(socket_id, &valid_socket_mask_);

  // Remove the socket information element.
  if (sockets_ != NULL)
  {
    SockInfo*  sock_info = sockets_[socket_id];

    if (sock_info != NULL)
    {
      // Remove the pointer to the element in the socket array.
      sockets_[socket_id] = NULL;

      // Unlink and delete the element from the linked list.
      if (sock_info == socket_list_)
      {
        socket_list_ = sock_info->next;
      }

      if (sock_info->next != NULL)
      {
        sock_info->next->prev = sock_info->prev;
      }

      if (sock_info->prev != NULL)
      {
        sock_info->prev->next = sock_info->next;
      }

      sock_info->next = NULL;
      sock_info->prev = NULL;

      delete sock_info;

      return true;
    }
  }

  LogE(kClassName, __func__, "Socket id %" PRISocketId " not found.\n",
       socket_id);

  return false;
}
