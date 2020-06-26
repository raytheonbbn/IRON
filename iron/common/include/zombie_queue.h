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

/// \brief ZombieQueue header file
///
/// A ZombieQueue is a packet-free queue representing the set of zombies
/// currently enqueued for a destination. Internally, a zombie queue just
/// contains the total number of zombie bytes. The Dequeue function creates a
/// zombie packet that can be transmitted.

#ifndef IRON_COMMON_ZOMBIE_QUEUE_H
#define IRON_COMMON_ZOMBIE_QUEUE_H

#include "bin_map.h"
#include "ipv4_address.h"
#include "packet_pool.h"
#include "queue.h"
#include "queue_depths.h"
#include "zombie.h"

#include <stdint.h>

// If we're not using the multi-dequeue option in the BPF, then send zombies
// of at most this length.
#define kZombieSingleDequeueLenBytes 1024

namespace iron
{

  /// \class ZombieQueue
  ///
  /// A class that will maintain the number of zombie bytes enqueued for a
  /// destination. bytes. Zombie packets are created during Dequeue.
  class ZombieQueue : public Queue
  {
  public:

    /// /brief Constructor.
    ///
    /// \param  packet_pool   Pool for generating zombies during dequeue.
    /// \param  bin_map       Used within the QueueDepths for tracking counts
    /// \param  is_multicast  True if this is a queue for a multicast bin.
    /// \param  lat_class     The latency class held in this queue.
    /// \param  node_bin_idx  The local node's bin index.
    /// \param  dst_addr      Destination address for generated Zombies.
    ZombieQueue(PacketPool&  packet_pool,
                BinMap&      bin_map,
                bool         is_multicast,
                LatencyClass lat_class,
                BinIndex     node_bin_idx,
                Ipv4Address  dst_addr);

    /// \brief Destructor.
    virtual ~ZombieQueue();

    /// \brief Generates and returns a Zombie Packet of up to the specified
    /// size.
    ///
    /// If there are no enqueued zombie bytes, then NULL is returned as
    /// the object.  If a packet is generated/returned, the caller
    /// takes ownership of the memory.
    ///
    /// \param   max_size_bytes  The maximum size packet to be returned.
    /// \param   dst_vec         Destinations we'd like to dequeue for. MUST
    ///                          be 0 unless this is a packetless zombie queue.
    ///
    /// \return  Returns a pointer to the packet being generated ("dequeued")
    ///          or NULL if there are no zombie bytes to be sent.
    virtual Packet* Dequeue(uint32_t max_size_bytes = kMaxZombieLenBytes,
                            DstVec dst_vec = 0);

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

    /// \brief More efficient alternative to Enqueue for when we know the
    /// queue type is a ZombieQueue.
    ///
    /// \param   num_bytes   Number of bytes to add to the queue.
    /// \param   dst_vec     Multicast destinations, or 0 for unicast.
    void AddZombieBytes(uint32_t num_bytes, DstVec dst_vec = 0);

    /// \brief Drop the specified number of bytes (or as many as exist) from
    /// the queue.
    ///
    /// Since there are no physical packets in a zombie queue, this Drop
    /// function just subtracts bytes from the running total.
    ///
    /// \param   max_size_bytes  The maximum size to be dropped.
    /// \param   dst_vec         The destinations for which we want to drop a
    ///                          packet. 0 for unicast.
    ///
    /// \return  Returns the number of bytes dropped. May be 0.
    virtual uint32_t DropPacket(uint32_t max_size_bytes = UINT32_MAX,
                                DstVec dst_vec = 0);

    /// \brief Empty the queue by setting the count to 0.
    virtual void Purge();

    /// \brief Get the total size of Zombie bytes available for dequeue for
    /// the given destination.
    ///
    /// This variant (without passing in a BinIndex) is implemented for
    /// unicast bins only.
    ///
    /// \return  Returns the total size of Zombie bytes to be dequeued.
    virtual size_t GetTotalDequeueSize();

    /// \brief Get the total size of Zombie bytes available for dequeue.
    ///
    /// This variant (that takes a BinIndex) is implemented for multicast
    /// bins only.
    ///
    /// \param bin_idx  The bin for which to get the zombie bytes available.
    ///
    /// \return  Returns the total size of Zombie bytes to be dequeued.
    virtual size_t GetTotalDequeueSize(BinIndex bin_idx);

    /// \brief Get the size of the next packet in bytes.
    ///
    /// This variant (without passing in a BinIndex) is implemented for
    /// unicast bins only.
    ///
    /// \return  Returns the maximum size of the next packet to be dequeued,
    /// which depends on the configured zombie packet size and the available
    /// zombie bytes.
    virtual size_t GetNextDequeueSize();

    /// \brief Get the available zombie bytes for the given destination in
    /// bytes.
    ///
    /// This variant (that takes a BinIndex) is implemented for multicast
    /// bins only.
    ///
    /// \param bin_idx  The bin for which to get the next dequeue size.
    ///
    /// \return  Returns the maximum size of the next packet to be dequeued,
    /// which depends on the configured zombie packet size and the available
    /// zombie bytes.
    virtual size_t GetNextDequeueSize(BinIndex bin_idx);

    /// \brief Function to return the total number of packets in the queue.
    ///
    /// \return  Returns the number of packets in the queue.
    virtual inline uint32_t GetCount() const
    {
      if (queue_size_ > 0)
      {
        return 1;
      }
      return 0;
    }

    /// \brief  Get a string summarizing the queue depth.
    ///
    /// \return The summary string.
    virtual std::string ToString();

  private:

    /// /brief Disallow argument-free constructor.
    ZombieQueue();

    /// \brief Disallow copy constructor.
    ZombieQueue(const ZombieQueue& other);

    /// \brief Disallow assignment.
    ZombieQueue operator=(const ZombieQueue& other);

    /// \brief Bin configuration to be used to get destination info.
    BinMap&             bin_map_;

    /// True if this is a multicast packetless zombie queue (in which case we
    /// will maintain per-destination counts).
    bool                is_multicast_;

    /// The latency class (a zombie class) contained in this queue. Used
    /// to generate the right type of packet on Dequeue.
    LatencyClass        lat_class_;

    /// Zombies sent from this queue will have a source IP address based on
    /// this node's bin index.
    BinIndex            node_bin_index_;

    /// Zombies sent from this queue will have this destination IP address.
    uint32_t            dst_addr_nbo_;

    /// Zombie counts are per-destination for multicast. Not used for
    /// unicast zombie_queue objects.
    QueueDepths         zombie_counts_;

  }; // end class ZombieQueue

} // namespace iron

#endif  // IRON_COMMON_ZOMBIE_QUEUE_H
