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

#ifndef IRON_COMMON_EDGE_IF_H
#define IRON_COMMON_EDGE_IF_H

/// \brief Provides the IRON software with an edge interface implementation.

#include "virtual_edge_if.h"
#include "edge_if_config.h"

namespace iron
{
  /// \brief Implementation of the abstract VirtualEdgeIf class.
  ///
  /// This class establishes a mechanism to "divert" packets from the kernel
  /// to user space for processing.
  class EdgeIf : public VirtualEdgeIf
  {
    public:

    /// \brief Constructor.
    ///
    /// \param  config  Configuration information for the edge interface.
    EdgeIf(EdgeIfConfig& config);

    /// \brief Destructor.
    virtual ~EdgeIf();

    /// \ brief Open the edge interface interface.
    ///
    /// Performs everything necessary to prepare the edge interface interface
    /// for use.
    ///
    /// \return True if the edge interface interface is opened without error,
    ///         false otherwise.
    bool Open();

    /// \brief Check if edge interface is open.
    ///
    /// \return True if the edge interface is open, false otherwise.
    bool IsOpen() const;

    /// \brief Close the edge interface interace.
    ///
    /// Performs everything necessary to clean up the edge interface
    /// interface.
    void Close();

    /// \brief Receive a packet from the edge interface.
    ///
    /// \param  pkt     Pointer to the packet that is the destination for the
    ///                 data read from the edge interface interface.
    /// \param  offset  Offset into the buffer, in bytes, where the data
    ///                 should be written.
    ///
    /// \return Number of bytes read (possibly 0), -1 on failure.
    ssize_t Recv(Packet* pkt, const size_t offset = 0);

    /// \brief Send a packet on the edge interface.
    ///
    /// \param  pkt  A pointer to the packet to send.
    ///
    /// \return Number of bytes sent, -1 on failure.
    ssize_t Send(const Packet* pkt);

    /// \brief Add the underlying file descriptor to a mask.
    ///
    /// The receive process uses this method for adding the file to a fd_set
    /// file descriptor mask and updating the maximum file descriptor in the
    /// mask. Typically, the caller would use the maximum file descriptor and
    /// the fd_set file descriptor mask in a select() call.
    ///
    /// \param max_fd    A reference to the maximum file descriptor value to
    ///                  be updated.
    /// \param read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Check if the underlying read file descriptor is in the set.
    ///
    /// \param fds Read file descriptor set to check.
    ///
    /// \return True if the edge interface interace is in the set of read file
    ///         descriptors, false otherwise. False will always be returned if
    ///         this edge interface interace is not open.
    bool InSet(fd_set* fds) const;

    protected:

    // The following are exposed for testing purposes, following the pattern
    // for existing classes that are unit tested.

    // The edge interface implementation encapsulates a raw socket (AF_INET,
    // SOCK_RAW) for transmitting packets and a packet socket (PF_PACKET,
    // SOCK_DGRAM) for receiving packets. The receive socket has an attached
    // Berkeley Packet Filter describing the pattern that must be matched for
    // incoming packets to be received. There is a separate transmit and
    // receive socket for the following reasons:
    //
    // o To transmit on a packet socket, we would have to fill in a struct
    //   sockaddr_ll structure for the sendto() call and we don't know what
    //   the required Ethernet layer address is.
    // o We had difficulty transmitting multicast packets via the packet
    //   socket (difficulty forcing the transmission out the appropriate
    //   interface).
    //
    // TODO: Further investigate using the packet socket for transmission in
    //       the future. It would simplify this class is we could use a single
    //       socket.

    /// The transmit socket (raw socket) file descriptor.
    int  xmt_sock_;

    /// The receive socket (packet socket) file descriptor.
    int  rcv_sock_;

    private:

    /// \brief Copy constructor.
    EdgeIf(const EdgeIf& ei);

    /// \brief Copy operator.
    EdgeIf& operator=(const EdgeIf& ei);

    /// \brief Close the edge interface.
    void CloseEdgeIf();

    /// \brief Close the edge interface sockets.
    void CloseSockets();

    /// \brief Execute a system command.
    ///
    /// Program termination will occur if the execution of the provided system
    /// command fails.
    ///
    /// \param  cmd  The string representation of the system command to be
    ///              executed.
    void ExeSysCmd(const std::string& cmd) const;

    /// Configuration information for the edge interface.
    EdgeIfConfig&  config_;

  }; // end class EdgeIf
} // namespace iron

#endif // IRON_COMMON_RAW_SOCKET_H
