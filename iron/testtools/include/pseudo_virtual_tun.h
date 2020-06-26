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

/// \brief The IRON inter-process shared memory module.
///
/// Provides the IRON software with access to shared memory between separate
/// processes on a single computer.

#ifndef IRON_TESTTOOLS_PSEUDO_VIRTUAL_TUN_H
#define IRON_TESTTOOLS_PSEUDO_VIRTUAL_TUN_H

///
/// Provides a Virtual Tunnel implementation that can be seeded with packets to
/// receive and track packets that have been sent.
///

#include "virtual_edge_if.h"
#include "packet.h"
#include "packet_pool.h"

#include <queue>

namespace iron
{
  class PseudoVirtualTun: public VirtualEdgeIf
  {
  public:
    /// \brief Constructor
    PseudoVirtualTun(PacketPool& packet_pool);
    /// \brief Constructor
    PseudoVirtualTun(PacketPool& packet_pool, bool log_recv_empty);

    /// \brief Destructor.
    ~PseudoVirtualTun();

    // Packets to return when Recv() is called.
    std::queue<Packet*> packets_to_recv;

    // Packets that were passed to Send().
    std::queue<Packet*> sent_packets;

    // Standard VirtualTunIF Interface

    /// \brief Open this virtual tunnel.
    ///
    /// \return True if the virtual tunnel was opened without error, false
    ///         otherwise.
    bool Open();

    /// \brief Close this virtual tunnel
    void Close();

    /// \brief Check if this virtual tunnel is open.
    ///
    /// \return True if this virtual tunnel is open, false otherwise.
    bool IsOpen();

    /// \brief Receive a packet from this virtual tunnel.
    ///
    /// \param pkt Pointer to the packet who's buffer will contain the data
    ///            read from the interface.
    /// \param offset Offset (in bytes) into the buffer where the data should
    ///               be written.
    ///
    /// \return Number of bytes read, possibly 0. -1 on failure.
    virtual ssize_t Recv(Packet* pkt, const size_t offset = 0);

    /// \brief Send a packet on this virtual tunnel.
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
    void AddFileDescriptors(int& max_fd, fd_set& read_fds);

    /// \brief Check if the underlying file descriptor is in the set.
    ///
    /// \param fds File descriptor set to check.
    ///
    /// \return True if this virtual tunnel is in the set of file descriptors,
    ///         false otherwise. False will always be returned if this virtual
    ///         tunnel is not open.
    bool InSet(fd_set* fds);

  private:

    /// \brief Copy constructor.
    PseudoVirtualTun(const PseudoVirtualTun& tif);

    /// \brief Copy operator.
    PseudoVirtualTun& operator=(const PseudoVirtualTun& tif);

    /// \brief Recycle each packet in the queue.
    ///
    /// \param pkts Packets to recycle. Empty when method returns.
    void RecyclePkts(std::queue<Packet*> pkts);

    // Pool of packets for internal storage.
    PacketPool&  packet_pool_;

    // Is the tunnel open.
    bool open_;

    // Should messages be logged when Recv() is called and there are no packets.
    bool log_recv_empty_;

    // Unique id for tracking log messages.
    int id_;

    static int last_id_;

  }; // end class PseudoVirtualTun
}

#endif // IRON_TESTTOOLS_PSEUDO_VIRTUAL_TUN_H
