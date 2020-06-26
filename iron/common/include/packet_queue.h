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

/// \brief PacketQueue header file
///
/// Implements a flexible queue class to serve as bins in the backpressure
/// queue of IRON nodes. These bins are actually queues that can be configured
/// with a drop policy. Currently, only the FIFO dequeue policy is implemented.
/// The drop policies currently implemented are drop HEAD and drop TAIL.

#ifndef IRON_COMMON_PACKET_QUEUE_H
#define IRON_COMMON_PACKET_QUEUE_H

#include "itime.h"
#include "list.h"
#include "ordered_list.h"
#include "packet_pool.h"
#include "queue.h"

#include <stdint.h>

namespace iron
{

  class Packet;

  /// Enumeration of possible drop policies.
  typedef enum
  {
    HEAD,
    TAIL,
    NO_DROP,
    UNDEFINED_DP
  } DropPolicy;

  /// The default queue size limit in number of enqueued objects. When the
  /// number of enqueued objects reaches this value, all enqueue calls will
  /// cause a packet drop.
#define DEFAULT_QUEUE_SIZE_LIMIT  500

  /// The default drop policy for a bin.
#define DEFAULT_DROP_POLICY       iron::HEAD

  /// \class PacketQueue
  ///
  /// A configurable queue that will store received packet objects as Packet
  /// pointers. It operates based on specified dequeueing and drop policies.
  ///
  /// The queue owns the objects when they are queued up. However, once
  /// dequeued, the ownership is passed to the calling object.
  ///
  /// The queue has a configurable size limit. This value will dictate when
  /// enqueues succeed or fail.
  class PacketQueue : public Queue
  {
  public:
    struct QueueWalkState
    {
      /// Default constructor, unordered.
      QueueWalkState()
        : ws_(), ordered_ws_(), is_ordered_(false)
        { }

      /// Ordered constructor.
      QueueWalkState(bool ordered)
        : ws_(), ordered_ws_(), is_ordered_(ordered)
        { }

      /// Default destructor.
      virtual ~QueueWalkState() { }

      /// Prepare for the walk.
      inline void PrepareForWalk()
      {
        ws_.PrepareForWalk();
        ordered_ws_.PrepareForWalk();
      }

      /// Check if this walk state is NULL.
      inline bool IsNULL()
      {
        if (is_ordered_)
        {
          return ordered_ws_.IsNULL();
        }
        return ws_.IsNULL();
      }

      /// Assignment operator.
      QueueWalkState& operator= (const QueueWalkState& other)
      {
        ws_         = other.ws_;
        ordered_ws_ = other.ordered_ws_;
        is_ordered_ = other.is_ordered_;
        return *this;
      }

      /// Equality operator.
      bool operator== (const QueueWalkState& other)
      {
        return is_ordered_ ? (ordered_ws_ == other.ordered_ws_) :
          (ws_ == other.ws_);
      }

      /// Internal walk state for unordered queue.
      iron::List<Packet*>::WalkState              ws_;

      /// Internal walk state for ordered queue.
      iron::OrderedList<Packet*, Time>::WalkState ordered_ws_;

      /// Indicates if this queue is ordered or not.
      bool                                        is_ordered_;
    };

    /// /brief Constructor.
    ///
    /// Uses the default dequeue and drop policies.
    ///
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  ordered      True if ordered queue, false otherwise.
    PacketQueue(iron::PacketPool& packet_pool, bool ordered=false);

    /// /brief Constructor that will initialize the queue threshold.
    ///
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  sl    The queue's size limit in number of packets.
    /// \param  drop  The drop policy for the queue.
    /// \param  ordered      True if ordered queue, false otherwise.
    PacketQueue(iron::PacketPool& packet_pool, uint32_t sl, DropPolicy drop,
                bool ordered = false);

    /// \brief Destructor.
    virtual ~PacketQueue();

    /// \brief  Prepare an iterator to the queue, starting from the back.
    ///
    /// This method MUST BE CALLED before any exploration of the queue.
    /// Sequence: PrepareQueueIterator, PeekAtIterator, SaveQueueIterator,
    ///           IncrementQueueIterator, DequeueAtIterator.
    void PrepareQueueIterator();

    /// \brief  Peek at the next packet, grab the corresponding iterator.
    /// This method advances the interval iterator_.
    ///
    /// \param  ws  The walk state returning the iterator corresponding to
    ///             the packet.
    ///
    /// \return A pointer to the peeked packet.
    Packet* PeekNextPacket(QueueWalkState& ws);

    /// \brief Peek the elements according to the configured policy.
    ///
    /// This method is non-blocking.  If there is no data in the queue, then
    /// NULL is returned as the object.  Packet ownership stays with the queue.
    ///
    /// \return  Returns a pointer to the packet being peeked or NULL if
    ///          there are no packets to peek.
    Packet* Peek();

    /// \brief  Peek the packet placed at the iterator.
    /// Memory ownership stays with the queue.
    ///
    /// \param  iterator  The iterator where to peek.
    ///
    /// \return A pointer to the peeked packet, NULL if nothing found.
    iron::Packet* PeekAtIterator(QueueWalkState& iterator);

    /// \brief  Get an iterator at the front, intended for later dequeue.
    ///
    /// \return An iterator.
    QueueWalkState GetFrontIterator();

    /// \brief  Get the iterator where a given pkt is enqueued, intended for
    ///         later dequeue.
    ///
    /// \param  pkt The pkt for which to find an iterator.
    ///
    /// \return An iterator, the NULL iterator if not found.
    QueueWalkState GetIterator(Packet* pkt);

    /// \brief  Dequeue the current packet, place iterator at element following
    ///         the one dequeued.
    /// Memory ownership quits the queue to go with the caller.
    ///
    /// \return A pointer to the dequeued packet, NULL if nothing found.
    iron::Packet* DequeueAtIterator();

    /// \brief  Dequeue the packet placed at the iterator.
    /// Memory ownership quits the queue to go with the caller.
    ///
    /// \param  iterator  The iterator from where to dequeue.
    ///
    /// \return A pointer to the dequeued packet, NULL if nothing found.
    iron::Packet* DequeueAtIterator(QueueWalkState& iterator);

    /// \brief Dequeue the elements according to the configured policy.
    ///
    /// If there is no data in the queue or if the next packet cannot be
    /// returned without exceeding max_size, this returns NULL.  If a packet
    /// is dequeued, the caller takes ownership of the packet.
    ///
    /// \param   max_size_bytes  The maximum size packet to be returned.
    /// \param   dst_vec         Destinations to dequeue for. Must be 0 for
    ///                          this subclass.
    ///
    /// \return  Returns a pointer to the packet being dequeued or NULL if
    ///          there are no packets to dequeue or if the next packet exceeds
    ///          the specified max size.
    virtual iron::Packet* Dequeue(
      uint32_t max_size_bytes = UINT32_MAX, DstVec dst_vec = 0);

    /// \brief Enqueue an element into the queue.
    ///
    /// This places the elements at the tail end of the queue.  Once an object
    /// is enqueued, the queue takes ownership of the memory.
    ///
    /// If the queue is already full when this method is called, then an
    /// existing packet in the queue is attempted to be dropped based on the
    /// current drop policy.  Any dropped packet is silently deleted.
    ///
    /// \param  pkt  Pointer to the packet to be enqueued.  Must not be NULL.
    ///
    /// \return  Returns true if the enqueue operation succeeded and the queue
    //           has taken ownership of the memory, or false if it failed and
    //           the caller retains ownership of the memory.
    virtual bool Enqueue(Packet* pkt);

    /// \brief Set the queue's size limit.
    ///
    /// If the current number of packets in the queue is larger than the
    /// specified size limit, then packets will be dropped from the queue
    /// using the configured drop policy until the new size limit is met.  If
    /// the drop policy is set to NO_DROP, then a head drop policy will be
    /// used to resize the queue.
    ///
    /// \param  sl  The queue's size limit in number of packets.  If zero is
    ///             specified, then the default queue size limit is used.
    void SetQueueLimits(uint32_t sl);

    /// \brief Drop the packet from the queue.
    ///
    /// The packet selected to be dropped is determined by the drop policy
    /// configured with the queue.
    ///
    /// \param   max_size_bytes  The maximum size to be dropped.
    ///                          Ignored for this Queue type.
    /// \param   dst_vec         Destinations to drop for. Must be 0 for
    ///                          this subclass.
    ///
    /// \return  Returns the number of bytes dropped (may be 0).
    virtual uint32_t DropPacket(uint32_t max_size_bytes = UINT32_MAX,
                                DstVec dst_vec = 0)
    {
      if (dst_vec != 0)
      {
        LogF("PacketQueue", __func__, "DropPacket with a DstVec is not yet "
             "implemented except for zombie queues.\n");
      }
      return DropPacket(false);
    }

    /// \brief Empty the queue by dropping all of the packets.
    ///
    /// Deletes all packets from the queue regardless of the drop policy.
    virtual void Purge();

    /// \brief Function to return the total number of packets in the queue.
    ///
    /// \return  Returns the number of packets in the queue.
    virtual inline uint32_t GetCount() const
    {
      return elem_count_;
    }

    /// \brief Get the maximum of bytes available for the next dequeue.
    ///
    /// \return  Returns the max number of bytes available to be dequeued.
    virtual inline size_t GetTotalDequeueSize()
    {
      return GetNextDequeueSize();
    }

    /// \brief Not implemented for this Queue subclass.
    ///
    /// \param BinIndex not used
    ///
    /// \return LogF
    virtual inline size_t GetTotalDequeueSize(BinIndex bin_idx);

    /// \brief Get the size of the next packet to be dequeued in bytes.
    ///
    /// \return  Returns the size of the next packet to be dequeued in bytes.
    virtual size_t GetNextDequeueSize();

    /// \brief Not implemented for this Queue subclass.
    ///
    /// \param BinIndex not used
    ///
    /// \return LogF
    virtual size_t GetNextDequeueSize(BinIndex bin_idx);

    /// \brief Function to set the drop policy associated with the queue.
    ///
    /// This can be changed dynamically after the object is created.
    ///
    /// \param  pol  The desired drop policy for the queue.
    inline void set_drop_policy(DropPolicy pol)
    {
      drop_policy_ = pol;
    }

    /// \brief Accessor function to get the drop policy currently configured
    /// in the queue.
    ///
    /// \return  The drop policy of the queue
    inline DropPolicy drop_policy() const
    {
      return drop_policy_;
    }

    /// \brief  Check if a packet queue is ordered.
    ///
    /// \return true if ordered, false otherwise.
    inline bool IsOrdered() const
    {
      return is_ordered_;
    }

    /// \brief  Print a quick summary of the queue and its iterators.
    void Print();

    /// \brief  Get a string summarizing the queue depth.
    ///
    /// \return The summary string.
    virtual std::string ToString();

  private:
    /// Disallow default constructor.
    PacketQueue();

    /// Disallow copy constructor.
    PacketQueue(const PacketQueue& other);

    /// Disallow assignment.
    PacketQueue& operator=(const PacketQueue& other);

    /// \brief Drop the packet from the queue, following the drop policy.
    ///
    /// The packet selected to be dropped is determined by the drop policy
    /// configured with the queue.
    ///
    /// \param  force_drop  A flag controlling what is done when the drop
    ///                     policy is set to NO_DROP.  If this flag is false,
    ///                     then no packet will be dropped.  If this flag is
    ///                     true, then a HEAD drop will be forced.  Only used
    ///                     when the drop policy is set to NO_DROP.
    ///
    /// \return  The number of bytes dropped (may be 0).
    uint32_t DropPacket(bool force_drop);

    /// A doubly-linked list which is the underlying structure of the regular
    /// queue.
    iron::List<Packet*>                         queue_;

    /// A doubly-linked list which is the underlying structure of the ordered
    /// queue.
    iron::OrderedList<Packet*, Time>            ordered_queue_;

    /// The packet queue walk state.
    QueueWalkState                              queue_walk_state_;

    /// The toggle indicating regular or ordered list.
    bool                                        is_ordered_;

    /// The number of packets currently in the queue.
    uint32_t                                    elem_count_;

    /// The maximum number of packets allowed in the queue.
    uint32_t                                    size_limit_;

    /// The drop policy for the queue.
    DropPolicy                                  drop_policy_;

  }; // end class Queue

} // namespace iron

#endif  // IRON_COMMON_PACKET_QUEUE_H
