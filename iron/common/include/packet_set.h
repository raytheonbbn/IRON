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

/// \brief The IRON PacketSet header file.
///
/// Provides the IRON software with a container to manage a set of IRON Packets.

#ifndef IRON_COMMON_PACKET_SET_H
#define IRON_COMMON_PACKET_SET_H

#include "ipv4_endpoint.h"
#include "packet.h"
#include "packet_pool.h"

#include <sys/socket.h>


namespace iron
{
  ///
  /// A utility class to manage a collection of IRON Packet objects.
  ///
  class PacketSet
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  packet_pool  A reference to the packet pool.
    PacketSet(PacketPool& packet_pool);

    /// \brief Destructor.
    virtual ~PacketSet();

    /// \brief Initialize the packet set.
    ///
    /// \param  num_packets  The number of packets to be managed by the packet
    ///                      set.  If a value less than 2 is specified, then
    ///                      this method will initialize a set of 2 packets.
    void Initialize(size_t num_packets);

    /// \brief Prepare the packet set for use with the recvmmsg() system call,
    /// which is capable of reading multiple packets from a socket.
    ///
    /// \return  Returns true if successful, or false otherwise.
    bool PrepareForRecvMmsg();

    /// \brief Get the message array pointer for the recvmmsg() call.
    ///
    /// \return  A pointer to the struct mmsghdr array.
    inline struct mmsghdr* GetVecPtr()
    {
      return msg_hdr_;
    }

    /// \brief Get the message array length for the recvmmsg() call.
    ///
    /// \return  The length of the struct mmsghdr array.
    inline size_t GetVecLen()
    {
      return max_size_;
    }

    /// \brief Finalize the packet set after successfully reading packets from
    /// the kernel with the recvmmsg() system call.
    ///
    /// This method sets the packet lengths and source addresses in the
    /// received packets.  The receive time may also be optionally set.
    ///
    /// \param  packets_read     The number of packets received during the
    ///                          recvmmsg() system call.
    /// \param  record_rcv_time  Indicates if the packet receive times should
    ///                          be set.
    void FinalizeRecvMmsg(int packets_read, bool record_rcv_time = false);

    /// \brief Retrieve the next packet that has data from the packet set.
    ///
    /// The caller assumes ownership of the returned Packet object and is
    /// responsible for recycling it.
    ///
    /// \param  packet        The received Packet.
    /// \param  src_endpoint  The source address information for the packet.
    /// \param  rcv_time      The packet's receive time.
    ///
    /// \return  Returns true if a packet with data is being returned, or
    ///          false otherwise.
    bool GetNextPacket(Packet*& packet, Ipv4Endpoint& src_endpoint,
                       Time& rcv_time);

    /// \brief Start a series of API calls to walk the packet set.
    ///
    /// Only call this method once after calling FinalizeRecvMmsgRead() and
    /// before calling GetNext() as many times as needed.  When done walking
    /// the PacketSet, call StopIteration() once.
    ///
    /// Note the the user can either retrieve the packets using
    /// GetNextPacket() or walk the packets using GetNext(), not both.
    void StartIteration();

    /// \brief Perform the next walk step in the packet set.
    ///
    /// Call StartIteration() once before calling this method as many times as
    /// needed.  When done walking the packet set, call StopIteration() once.
    ///
    /// \return  Returns a pointer to the next Packet in the packet set, or
    ///          NULL if the end of the received packets has been reached.
    ///          The packet set retains ownership of the Packet, so the caller
    ///          MUST NOT recycle the Packet.
    Packet* GetNext();

    /// \brief Stop a series of API calls to walk the packet set.
    ///
    /// Call this method once when done with all of the GetNext() calls.
    void StopIteration();

   private:

    /// Copy constructor.
    PacketSet(const PacketSet& other);

    /// Copy operator.
    PacketSet& operator=(const PacketSet& other);

    /// The control message size, in bytes.
    static const size_t  kCmsgSize = 64;

    /// Structure of information needed for each mmsghdr element.
    struct PktInfo
    {
      PktInfo();
      ~PktInfo();
      static void SetPacketPool(PacketPool* pool)
      {
        packet_pool_ = pool;
      }

      /// The common packet pool pointer for recycling packets.
      static PacketPool*  packet_pool_;

      /// The packet.
      Packet*             packet_;

      /// The source socket address.
      struct sockaddr_in  src_addr_;

      /// The input/output vector for the packet.
      struct iovec        io_vec_;

      /// The control message buffer.
      uint8_t             cmsg_buf_[kCmsgSize];

      /// The source address and port number object.
      Ipv4Endpoint        src_endpt_;

      /// The packet receive time.
      Time                rcv_time_;
    }; // end struct PktInfo

    /// The packet pool.
    PacketPool&      pkt_pool_;

    /// The maximum size of the packet set, in packets.
    size_t           max_size_;

    /// The current size of the packet set holding data, in packets.
    size_t           cur_size_;

    /// The array index for returning packets using GetNextPacket() calls.
    size_t           ret_idx_;

    /// The array index for walking the packets using GetNext() calls.
    size_t           walk_idx_;

    /// The array of packet information.
    PktInfo*         pkt_info_;

    /// The array of message headers.
    struct mmsghdr*  msg_hdr_;

    /// The flag recording if the monotonic clock to real time clock offset is
    /// initialized or not.
    static bool      clock_init_;

    /// The monotonic clock to real time clock offset.
    static timespec  mono_to_real_;

  }; // end class PacketSet

} // namespace iron

#endif // IRON_COMMON_PACKET_SET_H
