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

#ifndef IRON_COMMON_PACKET_FIFO_H
#define IRON_COMMON_PACKET_FIFO_H

#include "fifo_if.h"
#include "packet.h"
#include "packet_pool.h"

namespace iron
{

  /// \brief A fifo for passing packing indices between processes
  ///
  /// The Send function sends a single packet index over the fifo to the
  /// remote process. The Recv function receives up to max_pkts_to_recv
  /// (constructor parameter) packet indices and stores them internally. The
  /// associated packets may be viewed using GetNextRcvdPacket.
  class PacketFifo
  {

   public:

    /// \brief The default constructor.
    ///
    /// \param   packet_pool       Pool of packets to use.
    /// \param   fifo              Underlying fifo to use for data transfer.
    /// \param   remote_owner      PacketOwner at the other end of this fifo.
    /// \param   max_pkts_to_recv  If this fifo will be opened as a receiver,
    ///                            how many packet indices should we receive
    ///                            per system call?
    PacketFifo(PacketPool& packet_pool,
               FifoIF* fifo,
               PacketOwner remote_owner,
               size_t max_pkts_to_recv);

    /// \brief The destructor.
    virtual ~PacketFifo();

    /// \brief Open the receive side.
    ///
    /// Only the one process that is the receive process for the unique path
    /// name passed into the constructor must call this method.  It creates
    /// the underlying signaling channel.
    ///
    /// There is no Close() method.  The destructor handles all of the
    /// required cleanup.
    ///
    /// \return  True on success, or false on error.  If this method has
    ///          already been called, then false is returned.
    bool OpenReceiver();

    /// \brief Open the send side.
    ///
    /// Each process that is a send process for the unique path name passed
    /// into the constructor must call this method.  It attaches to the
    /// underlying signaling channel that is created by the process calling
    /// OpenReceiver().  Until a process calls OpenReceiver() on the path
    /// name, this method will fail and must be retried periodically.
    ///
    /// There is no Close() method.  The destructor handles all of the
    /// required cleanup.
    ///
    /// \return  True on success, or false on error.  If this method has
    ///          already been called, then false is returned.
    bool OpenSender();

    /// \brief Send a single packet index to the remote process.
    ///
    /// This method wraps the internal fifo call, including checking whether
    /// the fifo is open (and opening if not), pulling out and formatting the
    /// packet index, and sending the message over the fifo. Once the packet
    /// is sent, control over that packet has been transferred to the other
    /// process.
    ///
    /// \param  packet   A pointer to the packet whose index is being sent.
    ///
    /// \return  True if the index was successfully sent, or false if either
    ///          the fifo could not be opened or the packet index could not be
    ///          sent.  The packet is NOT recycled here.
    bool Send(Packet* packet);

    /// \brief Receive one or more packet indices from the remote process.
    ///
    /// The received packet indices, the number of received indices, and the
    /// time they were received are all stored locally. The associated packets
    /// can be retrieved using GetNextRcvdPacket.
    ///
    /// \return  True if any packet indices were received, or false if none
    ///          were received (including receive failure).
    bool Recv();

    /// \brief Get the next received but unviewed packet.
    ///
    /// To use this, first call Recv() to receive up to the maximum number of
    /// packet indices off the fifo. Then call this until it return false (no
    /// more packets) to skim through the buffer of received packets.
    ///
    /// \param  packet  Used to return a reference to the next packet in the
    ///                 buffer.
    ///
    /// \return  True if this was able to return the next packet, or false if
    ///          there were no more packets to return.
    bool GetNextRcvdPacket(Packet** packet);

    /// \brief Add the underlying file descriptor to a mask.
    ///
    /// The receive process uses this method for adding the file to a fd_set
    /// file descriptor mask and updating the maximum file descriptor in the
    /// mask.  Typically, the caller would use the maximum file descriptor and
    /// the fd_set file descriptor mask in a select() call.
    ///
    /// \param  max_fd    A reference to the maximum file descriptor value to
    ///                   be updated.
    /// \param  read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Check if the underlying file descriptor is in the set.
    ///
    /// \param fds File descriptor set to check.
    ///
    /// \return  True if this fifo is in the set of file descriptors, or false
    ///          otherwise.  False will always be returned if this fifo is not
    ///          open.
    bool InSet(fd_set* fds);

    /// \brief Test if the object has been successfully opened.
    ///
    /// Useful for checking if OpenSender() has succeeded yet.
    ///
    /// \return  True if the object has been successfully opened, or false
    ///          otherwise.
    bool IsOpen();

   private:

    /// \brief The default constructor.
    PacketFifo();

    /// \brief Copy constructor.
    PacketFifo(const PacketFifo& other);

    /// \brief Copy operator.
    PacketFifo& operator=(const PacketFifo& other);

    /// The size of the receive buffer. max_pkts_to_recv_ must be less than or
    /// equal to this.
    static const size_t  kRecvBufferSizePkts = 256;

    /// Packet pool used to access and return packet objects.
    PacketPool&  packet_pool_;

    /// Fifo to use to send and receive packets.
    FifoIF*      fifo_;

    /// PacketOwner for the component at the other end of this fifo.
    PacketOwner  remote_owner_;

    /// How many bytes should we receive per system call?
    size_t       max_bytes_to_recv_;

    /// How many of the received packets have we viewed since the last Recv
    /// call?
    size_t       num_viewed_pkts_;

    /// How many packets did we receive during the last Recv call?
    size_t       num_pkts_rcvd_;

    /// Packets received during a Recv call are stored here, accessible via
    /// GetNextRcvdPacket.
    PktMemIndex  recv_pkt_index_buf_[kRecvBufferSizePkts];

    /// When was the last system receive performed? This will be used to
    /// timestamp packets as they are viewed via GetNextRcvdPacket.
    Time         last_recv_time_;

  }; // class PacketFifo

} // namespace iron

#endif // IRON_COMMON_PACKET_FIFO_H
