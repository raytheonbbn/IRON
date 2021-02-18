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

#ifndef IRON_SLIQ_PACKET_QUEUE_H
#define IRON_SLIQ_PACKET_QUEUE_H

#include "sliq_types.h"

#include "itime.h"
#include "packet.h"
#include "packet_pool.h"


namespace sliq
{

  /// \brief A packet queue class.
  class PacketQueue
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  packet_pool    A reference to the common pool of packets.
    /// \param  max_size_pkts  The maximum queue size in number of packets.
    /// \param  dequeue_rule   The queue's dequeue rule.
    /// \param  drop_rule      The queue's drop rule.
    PacketQueue(iron::PacketPool& packet_pool, size_t max_size_pkts,
                DequeueRule dequeue_rule, DropRule drop_rule);

    /// \brief Destructor.
    virtual ~PacketQueue();

    /// \brief Reconfigure the packet queue.
    ///
    /// Must be called before any packets are enqueued.
    ///
    /// \param  max_size_pkts  The maximum queue size in number of packets.
    /// \param  dequeue_rule   The queue's dequeue rule.
    /// \param  drop_rule      The queue's drop rule.
    ///
    /// \return  True if successful, or false otherwise.
    bool Reconfigure(size_t max_size_pkts, DequeueRule dequeue_rule,
                     DropRule drop_rule);

    /// \brief Add a packet to the tail of the queue.
    ///
    /// Once a packet is enqueued, the queue takes ownership of the memory.
    /// If the queue is already full when this method is called, then an
    /// existing packet in the queue is attempted to be dropped based on the
    /// current drop policy.  Any dropped packet is silently recycled.
    ///
    /// \param  pkt  Pointer to the packet to be enqueued.
    /// \param  now  The current time.
    ///
    /// \return  Returns true if the enqueue operation succeeded and the queue
    //           has taken ownership of the packet, or false if it failed and
    //           the caller retains ownership of the packet.
    bool Enqueue(iron::Packet* pkt, const iron::Time& now);

    /// \brief Remove a packet from the queue.
    ///
    /// This method is non-blocking.  The packet is removed from the head of
    /// the queue if the dequeueing rule is FIFO_QUEUE, or the tail of the
    /// queue if the dequeueing rule is LIFO_QUEUE.  If there are no packets
    /// in the queue, then NULL is returned.  If a packet is dequeued, the
    /// caller takes ownership of the memory.
    ///
    /// \return  Returns a pointer to the packet being dequeued, or NULL if
    ///          there are no packets to dequeue.
    iron::Packet* Dequeue();

    /// \brief Remove a packet from the queue and compute its time enqueued.
    ///
    /// This method is non-blocking.  The packet is removed from the head of
    /// the queue if the dequeueing rule is FIFO_QUEUE, or the tail of the
    /// queue if the dequeueing rule is LIFO_QUEUE.  If there are no packets
    /// in the queue, then NULL is returned.  If a packet is dequeued, the
    /// caller takes ownership of the memory.
    ///
    /// \param  now             The current time.
    /// \param  queueing_delay  A reference to where the time that the packet
    ///                         was enqueued is placed on success.
    ///
    /// \return  Returns a pointer to the packet being dequeued, or NULL if
    ///          there are no packets to dequeue.
    iron::Packet* Dequeue(const iron::Time& now, iron::Time& queueing_delay);

    /// \brief Empty the queue by dropping all of the packets.
    ///
    /// Recycles all packets from the queue regardless of the drop policy.
    void Purge();

    /// \brief Get the size of the next packet to be dequeued in bytes.
    ///
    /// \return  Returns the number of bytes in the next packet to be
    ///          dequeued.
    size_t GetNextDequeueSizeInBytes() const;

    /// \brief Function to return the total size of the packets in the queue
    /// in bytes.
    ///
    /// \return  Returns the number of bytes in the queue.
    inline size_t GetSizeInBytes() const
    {
      return size_;
    }

    /// \brief Function to return the total number of packets in the queue.
    ///
    /// \return  Returns the number of packets in the queue.
    inline size_t GetSizeInPackets() const
    {
      return cnt_;
    }

   private:

    /// Copy constructor.
    PacketQueue(const PacketQueue& pq);

    /// Copy operator.
    PacketQueue& operator=(const PacketQueue& pq);

    /// \brief A structure for queue elements.
    struct QueueElement
    {
      QueueElement() : enqueue_time(), pkt(NULL) {}
      virtual ~QueueElement() {}

      /// The packet's enqueue time.
      iron::Time     enqueue_time;

      /// The packet.
      iron::Packet*  pkt;
    };

    /// Pool containing packets to use.
    iron::PacketPool&  pkt_pool_;

    /// The maximum packet count for the queue.
    size_t             max_cnt_;

    /// The current count of packets in the queue.
    size_t             cnt_;

    /// The current size of all of the packets in the queue, in bytes.
    size_t             size_;

    /// The index of the head element in the circular array.
    size_t             head_;

    /// The rule used when dequeueing packets.
    DequeueRule        dequeue_rule_;

    /// The rule used when the queue is full.
    DropRule           drop_rule_;

    /// The circular array of queue elements.
    QueueElement*      queue_;

  }; // end class PacketQueue

} // namespace sliq

#endif // IRON_SLIQ_PACKET_QUEUE_H
