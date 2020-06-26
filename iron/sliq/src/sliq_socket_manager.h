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

#ifndef IRON_SLIQ_SOCKET_MANAGER_H
#define IRON_SLIQ_SOCKET_MANAGER_H

#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_types.h"

#include "fd_event.h"
#include "ipv4_endpoint.h"
#include "packet.h"
#include "packet_set.h"

#include <sys/select.h>


namespace sliq
{

  /// Enumeration indicating the status of a write operation.
  enum WriteStatus
  {
    /// Write completed successfully.
    WRITE_STATUS_OK,

    /// The write would have blocked.
    WRITE_STATUS_BLOCKED,

    /// Error during the write.
    WRITE_STATUS_ERROR,
  };

  /// A struct used to return the result of attempting to write to a socket.
  /// This includes a status of WRITE_STATUS_OK and the number of bytes
  /// written, a status of WRITE_STATUS_BLOCKED, or a status of
  /// WRITE_STATUS_ERROR and the error code.
  struct WriteResult
  {
    WriteResult() : status(WRITE_STATUS_OK), bytes_written(0), error_code(0)
    { }
    WriteResult(WriteStatus s, int bytes_written_or_error_code)
        : status(s), bytes_written(bytes_written_or_error_code),
          error_code(bytes_written_or_error_code)
    { }

    WriteStatus  status;
    int          bytes_written;  // Only valid if status is WRITE_STATUS_OK
    int          error_code;     // Only valid if status is WRITE_STATUS_ERROR
  };

  /// Manages the SLIQ sockets.
  ///
  /// Currently, this class is capable of managing up to FD_SETSIZE sockets,
  /// which should be sufficient for virtually all applications.  The
  /// recvmmsg() system call is used for reading from the sockets, which is
  /// capable of receiving multiple packets for each system call.
  class SocketManager
  {

   public:

    /// Default no-arg constructor.
    SocketManager();

    /// Destructor.
    virtual ~SocketManager();

    /// Initialize the socket manager.
    ///
    /// \return  True if successful, false otherwise.
    bool Initialize();

    /// Create a UDP Socket.
    ///
    /// \param  events  The notification events of interest.
    ///
    /// \return  Socket identifier.
    SocketId CreateUdpSocket(iron::FdEvent events);

    /// Set the receive buffer size for a socket.
    ///
    /// \param  socket_id  The socket identifier.
    /// \param  size       The receive buffer size.
    ///
    /// \return  True if the operation is successful, false otherwise.
    bool SetRecvBufferSize(SocketId socket_id, size_t size);

    /// Set the send buffer size for a socket.
    ///
    /// \param  socket_id  The socket identifier.
    /// \param  size       The send buffer size.
    ///
    /// \return  True if the operation is successful, false otherwise.
    bool SetSendBufferSize(SocketId socket_id, size_t size);

    /// Enable receive timestamps from the kernel on a socket.
    ///
    /// \param  socket_id  The socket identifier.
    ///
    /// \return  True if the change succeeds, false otherwise.
    bool EnableReceiveTimestamps(SocketId socket_id);

    /// Enable port number reuse on a socket.
    ///
    /// \param  socket_id  The socket identifier.
    ///
    /// \return  True if the change succeeds, false otherwise.
    bool EnablePortReuse(SocketId socket_id);

    /// Bind a socket to a local address and port.
    ///
    /// \param  socket_id  The socket identifier.
    /// \param  endpoint   The local IPv4 Endpoint information.
    ///
    /// \return  True if the bind succeeds, false otherwise.
    bool Bind(SocketId socket_id, const iron::Ipv4Endpoint& endpoint);

    /// Connect a socket to a remote address and port.
    ///
    /// \param  socket_id  The socket identifier.
    /// \param  endpoint   The remote IPv4 Endpoint information.
    ///
    /// \return  True if the bind succeeds, false otherwise.
    bool Connect(SocketId socket_id, const iron::Ipv4Endpoint& endpoint);

    /// Get the local socket address and port.
    ///
    /// \param  socket_id   The socket identifier.
    /// \param  local_addr  The local address and port.
    ///
    /// \return  True if the get succeeds, false otherwise.
    bool GetLocalAddress(SocketId socket_id, iron::Ipv4Endpoint& local_addr);

    /// Update the UDP Socket events.
    ///
    /// \param  socket_id  The socket identifier.
    /// \param  events     The updated notification events of interest.
    ///
    /// \return  True if the update succeeds, false otherwise.
    bool UpdateEvents(SocketId socket_id, iron::FdEvent events);

    /// Get the file descriptor information.  For each socket, the file
    /// descriptor and the notification events of interest are returned.
    ///
    /// \param  fd_event_array  Destination for the file descriptor
    ///                         information.
    /// \param  array_size      The maximum number of file descriptors that
    ///                         can be reported on.
    ///
    /// \return  The number of returned file descriptors.
    size_t GetFileDescriptors(iron::FdEventInfo* fd_event_array,
                              size_t array_size) const;

    /// Read packets from a socket.
    ///
    /// \param  socket_id   The socket identifier.
    /// \param  packet_set  The set of Packets into which data will be placed.
    ///
    /// \return  The number of packets that were read from the socket.
    int ReadPackets(SocketId socket_id, iron::PacketSet& packet_set);

    /// Write a packet to a socket.
    ///
    /// \param  socket_id     The socket identifier.
    /// \param  packet        The packet to be written to the socket.
    /// \param  peer_address  The destination address of the packet.
    ///
    /// \return  Structure containing the result of the operation.  This
    ///          includes a status and the number of bytes written or an error
    ///          code.
    WriteResult WritePacket(SocketId socket_id, iron::Packet& packet,
                            const iron::Ipv4Endpoint& peer_address);

    /// Write a packet, consisting of a header and data, to a socket.
    ///
    /// \param  socket_id     The socket identifier.
    /// \param  header        The packet header to be written to the socket.
    /// \param  data          The packet data to be written to the socket.
    /// \param  peer_address  The destination address of the packet.
    ///
    /// \return  Structure containing the result of the operation.  This
    ///          includes a status and the number of bytes written or an error
    ///          code.
    WriteResult WritePacket(SocketId socket_id, iron::Packet& header,
                            iron::Packet& data,
                            const iron::Ipv4Endpoint& peer_address);

    /// Close a socket.
    ///
    /// \param  socket_id  The socket identifier.
    ///
    /// \return  True if the socket is closed, false otherwise.
    bool Close(SocketId socket_id);

   private:

    /// Copy constructor.
    SocketManager(const SocketManager& sm);

    /// Copy operator.
    SocketManager& operator=(const SocketManager& sm);

    /// \brief A structure for socket information.
    struct SockInfo
    {
      /// The socket's event information.
      iron::FdEventInfo  fd_event_info;

      /// The next element in the doubly-linked list.
      SockInfo*          next;

      /// The previous element in the doubly-linked list.
      SockInfo*          prev;
    };

    /// Valid socket mask.  This supports file descriptor numbers less than
    /// FD_SETSIZE.
    fd_set      valid_socket_mask_;

    /// The collection of socket information in a doubly-linked list.  This
    /// is the pointer to the head of the list, and the list owns the SockInfo
    /// objects.
    SockInfo*   socket_list_;

    /// An array of pointers to socket information indexed by the file
    /// descriptor number.  This supports file descriptor numbers less than
    /// FD_SETSIZE.
    SockInfo**  sockets_;

  }; // end class SocketManger

} // namespace sliq

#endif // IRON_SLIQ_SOCKET_MANAGER_H
