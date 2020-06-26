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

#ifndef IRON_COMMON_VIRTUAL_EDGE_IF_H
#define IRON_COMMON_VIRTUAL_EDGE_IF_H

/// \brief Provides the IRON software with an abstract edge interface.

#include <packet.h>
#include <stdint.h>

namespace iron
{
  /// \brief Abstract base class for edge interface implementations.
  class VirtualEdgeIf
  {
    public:

    /// \brief Constructor.
    VirtualEdgeIf() {}

    /// \brief Destructor.
    virtual ~VirtualEdgeIf() {}

    /// \brief Open the edge interface.
    ///
    /// Performs everything necessary to prepare the edge interface for use.
    ///
    /// \return True if the edge interface is opened without error, false
    ///         otherwise.
    virtual bool Open() = 0;

    /// \brief Check if the edge interface is open.
    ///
    /// \return True if the edge interface is open, false otherwise.
    virtual bool IsOpen() const = 0;

    /// \brief Close the edge interace.
    ///
    /// Performs everything necessary to clean up the edge interface.
    virtual void Close() = 0;

    /// \brief Receive a packet from the edge interface.
    ///
    /// \param  pkt     Pointer to the packet that is the destination for the
    ///                 data read from the edge interface.
    /// \param  offset  Offset into the buffer, in bytes, where the data
    ///                 should be written.
    ///
    /// \return Number of bytes read (possibly 0), -1 on failure.
    virtual ssize_t Recv(Packet* pkt, const size_t offset = 0) = 0;

    /// \brief Send a packet on the edge interface.
    ///
    /// \param  pkt  A pointer to the packet to send.
    ///
    /// \return Number of bytes sent, -1 on failure.
    virtual ssize_t Send(const Packet* pkt) = 0;

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
    virtual void AddFileDescriptors(int& max_fd, fd_set& read_fds) const = 0;

    /// \brief Check if the underlying read file descriptor is in the set.
    ///
    /// \param fds Read file descriptor set to check.
    ///
    /// \return True if the edge interace is in the set of read file
    ///         descriptors, false otherwise. False will always be returned if
    ///         this edge interace is not open.
    virtual bool InSet(fd_set* fds) const = 0;

  }; // end class VirtualEdgeIf
} // namespace iron

#endif // IRON_COMMON_VIRTUAL_EDGE_IF_H
