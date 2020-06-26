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

/// \brief Queue header file
///
/// Interface for representing a Queue, which may contain packets or just
/// virtual (zombie) sizes.

#ifndef IRON_COMMON_QUEUE_H
#define IRON_COMMON_QUEUE_H

#include "packet_pool.h"

#include <stdint.h>



namespace iron
{

  /// \class Queue
  /// An abstract interface representing a Queue.
  ///
  /// Captures Enqueue, Dequeue, and GetSize functions that will exist for both
  /// PacketQueue objects (containing pointers to packets) and ZombieQueue
  /// objects (containing just a big set of bytes).
  class Queue
  {
  public:

    /// /brief Constructor.
    ///
    /// \param  packet_pool  Pool containing packet to use.
    inline Queue(PacketPool& packet_pool)
      : packet_pool_(packet_pool),
        queue_size_(0)
      {
      };


    /// \brief Destructor.
    virtual inline ~Queue() {};

    /// \brief Return the next packet to be sent from the queue.
    ///
    /// If there is no data in the queue or if the next packet cannot be
    /// returned without exceeding max_size, this returns NULL.  If a packet
    /// is dequeued, the caller takes ownership of the packet.
    ///
    /// \param   max_size_bytes  The maximum size packet to be returned.
    /// \param   dst_vec         Destinations to dequeue for.
    ///
    /// \return  Returns a pointer to the packet being dequeued or NULL if
    ///          there are no packets to dequeue or if the next packet exceeds
    ///          the specified max size.
    virtual Packet* Dequeue(
      uint32_t max_size_bytes = UINT32_MAX, DstVec dst_vec = 0) = 0;

    /// \brief Enqueue an element into the queue.
    ///
    /// This places the elements at the tail end of the queue.  Once an object
    /// is enqueued, the queue takes ownership of the memory.
    ///
    /// \param  pkt  Pointer to the packet to be enqueued.  Must not be NULL.
    ///
    /// \return  Returns true if the enqueue operation succeeded and the queue
    //           has taken ownership of the memory, or false if it failed and
    //           the caller retains ownership of the memory.
    virtual bool Enqueue(Packet* pkt) = 0;

    /// \brief Drop a single packet from the queue.
    ///
    /// The packet selected to be dropped is determined by the drop policy
    /// configured with the queue.
    ///
    /// \param   max_size_bytes  The maximum size packet to be dropped.
    /// \param   dst_vec         The destinations for which we want to drop a
    ///                          packet. Ignored for unicast. For non-zombie
    ///                          queues, this function will search until it
    ///                          finds a packet that matches the given
    ///                          dst_vec.
    ///
    /// \return  Returns the number of bytes dropped (may be 0)
    virtual uint32_t DropPacket(uint32_t max_size_bytes = UINT32_MAX,
                                DstVec dst_vec = 0) = 0;

    /// \brief Empty the queue by dropping all of the packets.
    ///
    /// Deletes all packets from the queue regardless of the drop policy.
    virtual void Purge() = 0;

    /// \brief Function to return the total size of the queue in bytes.
    ///
    /// \return  Returns the queue size in bytes.
    virtual inline uint32_t GetSize() const
    {
      return queue_size_;
    }

    /// \brief Function to return the total number of packets in the queue.
    ///
    /// \return  Returns the number of packets in the queue.
    virtual uint32_t GetCount() const = 0;

    /// \brief Get the maximum of bytes available for the next dequeue.
    ///
    /// \return  Returns the max number of bytes available to be dequeued.
    virtual size_t GetTotalDequeueSize() = 0;

    /// \brief Get the total number of bytes available for dequeue.
    ///
    /// This variant (that takes a BinIndex) is implemented for multicast
    /// bins only.
    ///
    /// \param bin_idx  The bin for which to get the bytes available.
    ///
    /// \return  Returns the total number of bytes available to be dequeued.
    virtual size_t GetTotalDequeueSize(BinIndex bin_idx) = 0;

    /// \brief Get the size of the next packet to be dequeued in bytes.
    ///
    /// \return  Returns the maximum size of the next packet to be dequeued in
    /// bytes. Note that this is a maximum in the case of zombie queues, but
    /// it's a concrete packet size in the case of packet queues.
    virtual size_t GetNextDequeueSize() = 0;

    /// \brief Get the size of the next packet in bytes.
    ///
    /// This variant (that takes a BinIndex) is implemented for multicast
    /// bins only.
    ///
    /// \param bin_idx  The bin for which to get the next dequeue size.
    ///
    /// \return  Returns the maximum size of the next packet to be dequeued,
    /// which depends on the configured zombie packet size and the available
    /// zombie bytes.
    virtual size_t GetNextDequeueSize(BinIndex bin_idx) = 0;

    /// \brief  Check if a packet queue is ordered.
    ///
    /// \return true if ordered, false otherwise.
    virtual inline bool IsOrdered() const
    {
      return false;
    }

    /// \brief  Get a string summarizing the queue depth.
    ///
    /// \return The summary string.
    virtual std::string ToString() = 0;

  protected:
    /// Pool containing packets to use.
    PacketPool&         packet_pool_;

    /// The number of bytes currently in the queue.
    uint32_t            queue_size_;

  private:
    /// Disallow default constructor.
    Queue();

    /// Disallow copy constructor.
    Queue(const Queue& other);

    /// Disallow assignment.
    Queue& operator=(const Queue& other);

  }; // end class Queue

} // namespace iron

#endif  // IRON_COMMON_QUEUE_H
