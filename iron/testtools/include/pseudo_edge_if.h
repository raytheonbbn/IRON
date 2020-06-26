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

#ifndef IRON_TESTTOOLS_PSEUDO_EDGE_IF_H
#define IRON_TESTTOOLS_PSEUDO_EDGE_IF_H

/// Provides an edge interface implementation that can be seeded with packets
/// to receive and track packets that have been sent.

#include "packet.h"
#include "packet_pool.h"
#include "virtual_edge_if.h"

#include <queue>

namespace iron
{
  class PseudoEdgeIf: public VirtualEdgeIf
  {
    public:

    /// \brief Constructor.
    ///
    /// \param  packet_pool  Reference to the packet pool.
    PseudoEdgeIf(PacketPool& packet_pool);

    /// \brief Constructor.
    ///
    /// \param  packet_pool     Reference to the packet pool.
    /// \param  log_recv_empty  Indicates if we log when there are no packets
    ///                         to receive.
    PseudoEdgeIf(PacketPool& packet_pool, bool log_recv_empty);

    /// \brief Destructor.
    virtual ~PseudoEdgeIf();

    // Packets to return when Recv() is called.
    std::queue<Packet*>  packets_to_recv;

    // Packets that were passed to Send().
    std::queue<Packet*>  sent_packets;

    // Standard VirtualEdgeIf Interface

    /// \brief Open this edgeinterface.
    ///
    /// \return True if the edge interface was opened without error, false
    ///         otherwise.
    bool Open();

    /// \brief Check if this edge interface is open.
    ///
    /// \return True if this edge interface is open, false otherwise.
    bool IsOpen() const;

    /// \brief Close this edge interface.
    void Close();

    /// \brief Receive a packet from this edge interface.
    ///
    /// \param  pkt     Pointer to the packet that is the destination for the
    ///                 data read from the edge interface.
    /// \param  offset  Offset into the buffer, in bytes, where the data
    ///                 should be written.
    ///
    /// \return Number of bytes read, possibly 0. -1 on failure.
    virtual ssize_t Recv(Packet* pkt, const size_t offset = 0);

    /// \brief Send a packet on this edge interface.
    ///
    /// \param  pkt A pointer to the packet to send.
    ///
    /// \return Number of bytes sent, -1 on failure.
    ssize_t Send(const iron::Packet* pkt);

    /// \brief Add the underlying file descriptor to a mask.
    ///
    /// The receive process uses this method for adding the file to a fd_set
    /// file descriptor mask and updating the maximum file descriptor in the
    /// mask. Typically, the caller would use the maximum file descriptor and
    /// the fd_set file descriptor mask in a select() call.
    ///
    /// \param max_fd A reference to the maximum file descriptor value to
    ///                be updated.
    /// \param read_fds A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Check if the underlying file descriptor is in the set.
    ///
    /// \param fds File descriptor set to check.
    ///
    /// \return True if this edge interface is in the set of file descriptors,
    ///         false otherwise. False will always be returned if this edge
    ///         interface is not open.
    bool InSet(fd_set* fds) const;

  private:

    /// \brief Copy constructor.
    PseudoEdgeIf(const PseudoEdgeIf& pei);

    /// \brief Copy operator.
    PseudoEdgeIf& operator=(const PseudoEdgeIf& pei);

    /// \brief Recycle each packet in the queue.
    ///
    /// \param  pkts  Packets to recycle. Empty when method returns.
    void RecyclePkts(std::queue<Packet*> pkts);

    // Pool of packets for internal storage.
    PacketPool&  packet_pool_;

    // Is the tunnel open.
    bool         open_;

    // Should messages be logged when Recv() is called and there are no packets.
    bool         log_recv_empty_;

    // Unique id for tracking log messages.
    int          id_;

    static int   last_id_;

  }; // end class PseudoEdgeIf
} // namespace iron

#endif // IRON_TESTTOOLS_PSEUDO_EDGE_IF_H
