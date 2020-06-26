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

/// \brief Utility class for managing packet history vectors.
///
/// Includes utility function for tracking how many times a packet is seen on
/// this node and checking whether a packet has visited a bin, as well as
/// storage for tracking a sample of packet ids seen multiple times.

#include "packet_history_mgr.h"

#include "log.h"
#include "packet.h"
#include "unused.h"

#include <cstring>
#include <sstream>

#include <inttypes.h>

using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketHistoryMgr;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char* UNUSED(kClassName) = "PacketHistoryMgr";

  /// Remembers if we are tracking cycles.
  const bool  kTrackCycles = true;
}

//============================================================================
PacketHistoryMgr::PacketHistoryMgr(BinMap& bin_map, BinId my_bin_id)
    : bin_map_(bin_map),
      my_bin_id_(my_bin_id),
      total_num_packets_(0),
      cycle_count_(0)
{
  if (iron::kNumNodesInHistory == 0)
  {
    LogW(kClassName, __func__, "The history vector size cannot be 0. Will "
         "use default history vectory size of 3. Set PacketHistory "
         "configuration item to false to disable history tracking.\n");
  }

  if (bin_map_.GetNumUcastBinIds() == 0)
  {
    LogF(kClassName, __func__, "Cannot set up PacketHistoryMgr without "
         "any configured destintaion bins.\n");
    return;
  }
}

//============================================================================
PacketHistoryMgr::~PacketHistoryMgr()
{
  // Nothing to destroy.
}

//============================================================================
bool PacketHistoryMgr::PacketVisitedBin(Packet* packet, BinId bin_id)
{
  // MCAST TODO: seems like a weird use of bin id. Is this correct?
  const uint8_t*  history = packet->history();
  uint8_t         count   = 0;

  while ((*history != kHistoryEntryUnused) &&
         (count < kHistoryFieldSizeBytes))
  {
    if (*history == bin_id)
    {
      return true;
    }

    ++history;
    ++count;
  }

  return false;
}

//============================================================================
uint32_t PacketHistoryMgr::GetAllVisitedBins(Packet* packet,
                                             BinId* visited_bin_array,
                                             const uint32_t visited_bin_len)
{
  if (!packet)
  {
    return 0;
  }

  const uint8_t*  history  = packet->history();
  uint32_t        count    = 0;
  uint32_t        it_count = 0;

  // MCAST TODO: Check whether this will works with the changes to bin id.
  // TODO: Note that "(count < bin_map_.GetNumDestBinIds())" cannot be part of
  // the conditional, as it does not include interior node BinIds, but
  // interior node BinIds get recorded in the packet history.
  while ((*history != kHistoryEntryUnused) &&
         (it_count < kHistoryFieldSizeBytes))
  {
    // Figure out if we have already seen this Bin Id.
    bool  already_in = false;

    for (uint32_t i = 0; i < count; ++i)
    {
      if (static_cast<BinId>(*history) == visited_bin_array[i])
      {
        already_in = true;
        break;
      }
    }

    // First time we have seen it, add to visited array.
    if (!already_in)
    {
      if (count >= visited_bin_len)
      {
        LogE(kClassName, __func__, "Error, visited bins array size (%" PRIu32
             ") is too small.\n", visited_bin_len);
        return count;
      }

      visited_bin_array[count] = static_cast<BinId>(*history);
      ++count;
    }

    ++it_count;
    ++history;
  }

  return count;
}

//============================================================================
uint8_t PacketHistoryMgr::GetNumVisits(Packet* packet, BinId bin_id)
{
  const uint8_t*  history  = packet->history();
  uint8_t         count    = 0;
  uint8_t         it_count = 0;

  while ((*history != kHistoryEntryUnused) &&
         (it_count < kHistoryFieldSizeBytes))
  {
    if (static_cast<BinId>(*history) == bin_id)
    {
      ++count;
    }

    ++it_count;
    ++history;
  }

  return count;
}

//============================================================================
void PacketHistoryMgr::TrackHistory(Packet* packet, bool local_packet)
{
  uint8_t  num_times_visited = GetNumVisits(packet, my_bin_id_);

  if (local_packet && (num_times_visited > 0))
  {
    // Don't track a local packet more than once, since this could be a
    // retransmission (and can't possibly be a cycle, since local packets
    // haven't yet entered the network).
    return;
  }

  if (kTrackCycles)
  {
    ++total_num_packets_;
    if (num_times_visited > 0)
    {
      ++cycle_count_;
    }
  }

  packet->InsertNodeInHistory(my_bin_id_);
}


//============================================================================
void PacketHistoryMgr::LogPacketHistory(Packet* packet)
{
  if (WouldLogD(kClassName))
  {
    string  hist_str = packet->HistoryToString();
    LogD(kClassName, __func__, "%s.\n", hist_str.c_str());
  }
}

//============================================================================
void PacketHistoryMgr::LogCirculationStats()
{
  if (kTrackCycles)
  {
    if (total_num_packets_ == 0)
    {
      LogI(kClassName, __func__, "No packets observed.\n");
    }
    else
    {
      LogW(kClassName, __func__, "Observed total of %" PRIu64 " packets, "
           "including %" PRIu64 " that cycled (%.2f%%).\n",
           total_num_packets_, cycle_count_,
           (static_cast<double>(cycle_count_) /
            static_cast<double>(total_num_packets_) * 100));
    }
  }
}
