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

///
/// Utility functions for tracking packet history.
///

#ifndef IRON_COMMON_PACKET_HISTORY_MGR_H
#define IRON_COMMON_PACKET_HISTORY_MGR_H

#include "bin_map.h"

#include <string>

#include <stdint.h>

namespace iron
{
  class Packet;

  /// \brief Utility class for managing packet history vectors.
  ///
  /// This includes functions needed for updating and reading the history
  /// vectors out of packets, which indicate whether a node bin id has been
  /// visited.
  class PacketHistoryMgr
  {
    public:

    /// \brief Constructor
    ///
    /// \param bin_map  Used to translate bin ids to indexes in the history
    ///        vector, and to set up the size allocated in the vector for each
    ///        bin.
    /// \param my_bin_id Bin ID for this node.
    PacketHistoryMgr(BinMap& bin_map, BinId my_bin_id);

    /// \brief Destructor
    virtual ~PacketHistoryMgr();

    /// \brief Determines whether the given bin has seen the packet before.
    ///
    /// \param packet  The packet about which the request is being made.
    /// \param bin_id  The bin for which the request is being made. Note: if
    ///                this is my_bin_id, then the answer will always be true
    ///                if this is called after TrackHistory.
    ///
    /// \return True if the packet has visited the given bin_id.
    bool PacketVisitedBin(Packet* packet, BinId bin_id);

    /// \brief Accessor for all visited bin ids for the given packet.
    ///
    /// \param   packet              The packet about which the request is
    ///                              being made.
    /// \param   visited_bin_array   Must be an array of length at least
    ///                              kNumNodesInHistory. This array will be
    ///                              filled in with the visited bin ids.
    /// \param   visited_bin_len     The length of the array passed in.
    ///
    /// \return  The number of visited bins, indicating how many array entries
    ///          have been filled in.
    uint32_t GetAllVisitedBins(Packet* packet,
                               BinId* visited_bin_array,
                               const uint32_t visited_bin_len);

    /// \brief Increments the packet history vector for my bin id.
    ///
    /// To be called when this node sees a packet. This increments the correct
    /// place in the packet history vector for the given packet.
    ///
    /// \param   packet        The packet in which to increment the history
    ///                        count.
    /// \param   local_packet  True if this packet is arriving locally from a
    ///                        proxy. In this case, we won't track it more
    ///                        than once, since it cannot yet be circulating
    ///                        through different enclaves (but it could be a
    ///                        retransmission of the same packet object, which
    ///                        we don't want to track a second time).
    void TrackHistory(Packet* packet, bool local_packet);

    /// \brief Prints (debug) the history of the given packet.
    ///
    /// \param packet The packet whose history should be logged.
    void LogPacketHistory(Packet* packet);

    /// \brief Prints circulation stats at this node.
    ///
    /// Prints counts and percents of packets seen multiple times as well as a
    /// sample of packet ids seen more than once by this node.
    ///
    /// Intended for debugging.
    void LogCirculationStats();

    protected:

    /// \brief Returns the number of times the packet has visited the bin.
    ///
    /// \param packet  The packet from which to get the number of visits.
    /// \param bin_id  The bin for which to get the number of vists. Note: if
    ///                this is my_bin_id, then the answer will always be >= 1
    ///                if this is called after TrackHistory.
    ///
    /// \return The number of times the packet has visited the given bin_id.
    uint8_t GetNumVisits(Packet* packet, BinId bin_id);

    private:

    /// Copy constructor.
    PacketHistoryMgr(const PacketHistoryMgr& other);

    /// Assignment operator.
    PacketHistoryMgr operator=(const PacketHistoryMgr& other);

    /// The bin map, used to translate bin ids to indexes.
    BinMap&   bin_map_;

    /// This node's bin id.
    BinId     my_bin_id_;

    /// Count the total number of packets seen
    ///
    /// Used as a denominator to compute a percent of packets that have been
    /// seen at least once (cycling).
    uint64_t  total_num_packets_;

    /// Count the number of packets seen at least once. Note: this is a
    /// best-effort count (some bin ids may fall off).
    uint64_t  cycle_count_;

  }; // class PacketHistoryMgr
} // namespace iron

#endif // IRON_COMMON_PACKET_HISTORY_MGR_H
