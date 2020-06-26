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

#ifndef IRON_COMMON_INTER_PROCESS_COMM_H
#define IRON_COMMON_INTER_PROCESS_COMM_H

#include "packet_set.h"

#include <string>

#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>


namespace iron
{
  /// The maximum number of packets that can be read for each recvmmsg()
  /// system call.

  static const int  kNumPktsPerRecvMmsgCall = 256;

  /// \brief A class for inter-process communications (IPC).
  ///
  /// There are two endpoints in each IPC connection, with each endpoint in a
  /// different process on the local computer system.  Each endpoint has a
  /// local pathname that must be a unique local filesystem location.  Each
  /// endpoint connects to the other endpoint specifying the other endpoint's
  /// pathname as the remote pathname.  Datagram-style messages are exchanged
  /// using send and receive calls.  Receive calls may be blocking or
  /// non-blocking.
  ///
  /// To use, an endpoint creates an InterProcessComm object, calls Open()
  /// with the local endpoint pathname, and calls Connect() with the remote
  /// endpoint pathname.  Both pathnames must be on the local filesystem.  At
  /// this point, messages may be sent and received using SendMessage() and
  /// ReceiveMessage() methods.  When finished, an endpoint closes the
  /// connection by calling Close() and deleting the InterProcessComm object.
  ///
  /// Implemented using UNIX domain datagram sockets.
  class InterProcessComm
  {

  public:

    /// \brief The default constructor.
    InterProcessComm();

    /// \brief The destructor.
    virtual ~InterProcessComm();

    /// \brief Open an endpoint.
    ///
    /// The local endpoint must be opened in order to receive messages on it.
    ///
    /// \param  local_path  The local filesystem pathname for the local
    ///                     endpoint.
    ///
    /// \return  True on success, or false otherwise.
    bool Open(const std::string local_path);

    /// \brief Connect the local, opened endpoint to a remote endpoint.
    ///
    /// The local endpoint must be connected to a remote endpoint in order to
    /// send messages to the remote endpoint.
    ///
    /// \param  remote_path  The local filesystem pathname for the remote
    ///                      endpoint.
    ///
    /// \return  True on success, or false otherwise.
    bool Connect(const std::string remote_path);

    /// \brief Add the underlying file descriptor to a mask.
    ///
    /// The receive process uses this method for adding the file to a fd_set
    /// file descriptor mask and updating the maximum file descriptor in the
    /// mask.  Typically, the called would use the maximum file descriptor and
    /// the fd_set file descriptor mask in a select() call.
    ///
    /// \param  max_fd    A reference to the maximum file descriptor value to
    ///                   be updated.
    /// \param  read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Send a message to the connected remote endpoint.
    ///
    /// The local endpoint must be connected to a remote endpoint in order to
    /// send messages to the remote endpoint.
    ///
    /// \param  buf       A pointer to the message to send.
    /// \param  len       The length, in bytes, of the message to send.
    /// \param  blocking  A flag controlling if the call is blocking or not.
    ///
    /// \return  True on success, or false otherwise.
    bool SendMessage(uint8_t* buf, size_t len, bool blocking);

    /// \brief Receive a message from the connected remote endpoint.
    ///
    /// The local endpoint must be opened in order to receive messages from a
    /// remote endpoint.
    ///
    /// \param  buf       A pointer to the buffer where the received message
    ///                   will be placed.
    /// \param  max_len   The length, in bytes, of the message buffer.
    /// \param  blocking  A flag controlling if the call is blocking or not.
    ///
    /// \return  The number of bytes received.  If zero, then no message was
    ///          received.
    size_t ReceiveMessage(uint8_t* buf, size_t max_len, bool blocking);

    /// \brief Receive a set of messages from the connected remote endpoint.
    ///
    /// The local endpoint must be opened in order to receive messages from a
    /// remote endpoint.
    ///
    /// \param  packet_set  The set of Packets into which data will be
    ///                     placed.
    /// \param  blocking    A flag controlling if the call is blocking or
    ///                     not.
    /// \param  num_pkts    The number of packets to receive per call.
    ///
    /// \return  The number of received packets. If zero, then no packets were
    ///          received.
    size_t ReceiveMessages(PacketSet& packet_set, bool blocking, 
                           int num_pkts=kNumPktsPerRecvMmsgCall);

    /// \brief Check if the endpoint is open or not.
    ///
    /// \return  True if the endpoint is open.
    inline bool IsOpen() const
    {
      return(socket_fd_ >= 0);
    }

    /// \brief Check if the endpoint is connected or not.
    ///
    /// \return  True if the endpoint is connected.
    inline bool IsConnected() const
    {
      return is_connected_;
    }

    /// \brief Get the local endpoint pathname.
    ///
    /// \return  The local endpoint pathname on the local filesystem.
    inline std::string GetLocalPath() const
    {
      return local_path_;
    }

    /// \brief Get the remote endpoint pathname.
    ///
    /// \return  The remote endpoint pathname on the local filesystem.
    inline std::string GetRemotePath() const
    {
      return remote_path_;
    }

    /// \brief Get the socket file descriptor for the local endpoint.
    ///
    /// Useful for adding the endpoint to a select() call.
    ///
    /// \return  The local endpoint's socket file descriptor, or -1 if the
    ///          endpoint is not open.
    inline int GetSocketDescriptor() const
    {
      return socket_fd_;
    }

    /// \brief Close the local endpoint.
    void Close();

  private:

    /// \brief Copy constructor.
    InterProcessComm(const InterProcessComm& other);

    /// \brief Copy operator.
    InterProcessComm& operator=(const InterProcessComm& other);

    /// The UNIX domain socket file descriptor.
    int                 socket_fd_;

    /// A flag recording if the socket is connected or not.
    bool                is_connected_;

    /// The local UNIX domain socket pathname on the local filesystem.
    std::string         local_path_;

    /// The remote UNIX domain socket pathname on the local filesystem.
    std::string         remote_path_;

    /// The local UNIX domain socket address.
    struct sockaddr_un  local_addr_;

    /// The remote UNIX domain socket address.
    struct sockaddr_un  remote_addr_;

  }; // class InterProcessComm

} // namespace iron

#endif // IRON_COMMON_INTER_PROCESS_COMM_H
