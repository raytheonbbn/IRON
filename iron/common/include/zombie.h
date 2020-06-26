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

/// \brief Header file for zombie packet utility functions.
///
/// Provides mechanisms for creating and manipulating zombie (dummy) packets.

#ifndef IRON_COMMON_ZOMBIE_H
#define IRON_COMMON_ZOMBIE_H

#include "iron_constants.h"
#include "packet_pool.h"
#include <inttypes.h>

// TODO fix this. What's the max length supported by the CATs?
// If compression is enabled, this can be very large without causing
// transmission problems, but sending virtually huge packets could cause
// backpressure issues.
#define kMaxZombieLenBytes (iron::kDefaultZombieCompression ?      \
                            std::numeric_limits<uint32_t>::max() : \
                            1024)

#define kMinZombieLenBytes (iron::kDefaultZombieCompression ?   \
                            1 : sizeof(struct iphdr))

namespace iron
{
  class Packet;

  /// \brief Class of static utility functions for creating zombie packets.
  ///
  /// A zombie packet is a packet sent around using IRON backpressure
  /// forwarding purely as a graceful backpressure signalizing mechanism. That
  /// is, it will contribute to the gradients (and live in the queues) at the
  /// IRON nodes, but it will never be sent to an application. If zombie
  /// compression is enabled, these zombies will also not take up as much
  /// space on the links as a real packet of the same (virtual) size.
  class Zombie
  {
    public:

    /// \brief Change a data packet into a zombie packet.
    ///
    /// This function simply marks the packet as lowest forwarding priority
    /// (i.e., least restrictive latency requirement), and unsets any time to
    /// go, so that the packet can continue to be processed and forwarded in
    /// the IRON network until it reaches its destination IRON node. This will
    /// also compress the packet if zombie compression is enabled.
    ///
    /// \param pkt  The data packet that should be turned into a zombie.
    static void ZombifyExistingPacket(Packet* pkt);

    /// \brief Generate a new zombie packet from scratch.
    ///
    /// This function generates an IP packet (that is not UDP or TCP) that
    /// will function simply as a space-hog in the BPF queues and
    /// gradients. If zombie compression is enabled, it will not hog (much)
    /// space on the links.
    ///
    /// \param  pkt_pool         The packet pool, used to retrieve a new
    ///                          packet for creating the zombie.
    /// \param  src_addr_nbo     The source IP address for the zombie.
    /// \param  dst_addr_nbo     The destination IP address for the zombie.
    /// \param  zombie_len_bytes The requested length (or virtual length, if
    ///                          compression is enabled) for the new zombie
    ///                          packet.
    /// \param  lat_class        LatencyClass, used to indicate the source of
    ///                          this zombie.
    ///
    /// \return  A pointer to the newly-creawted zombie packet. Control is
    ///          turned over to the caller.
    static Packet* CreateNewZombie(PacketPool& pkt_pool,
                                   uint32_t& src_addr_nbo,
                                   uint32_t& dst_addr_nbo,
                                   size_t zombie_len_bytes,
                                   LatencyClass lat_class);

    private:

      // Constructors, destructor, assignment are all disallowed, since this
      // class contains only static utiltiy functions.
      Zombie();
      virtual ~Zombie();
      Zombie(const Zombie&);
      Zombie& operator=(const Zombie&);

  }; // class Zombie
} // namespace iron

#endif // IRON_COMMON_ZOMBIE_H
