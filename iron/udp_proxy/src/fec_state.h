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

#ifndef IRON_UDP_PROXY_FEC_STATE_H
#define IRON_UDP_PROXY_FEC_STATE_H

#include "fec_defs.h"
#include "fec_state_pool.h"
#include "four_tuple.h"
#include "inter_process_comm.h"
#include "iron_types.h"
#include "itime.h"
#include "k_val.h"
#include "packet.h"
#include "packet_pool.h"
#include "queue.h"
#include "queue_depths.h"
#include "src_info.h"
#include "src_rate_estimator.h"
#include "udp_fec_trailer.h"
#include "utility_fn_if.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <ctime>
#include <string.h>
#include <sys/types.h>

class DecodingState;
class ReleaseController;


/// A FEC state object is used to aggregate packets from a FEC group and
/// reconstruct missing packets if possible.
class FecState
{
  public:

  /// \brief Constructor.
  ///
  /// \param  packet_pool  Pool containing packet to use.
  FecState(iron::PacketPool& packet_pool);

  /// \brief Destructor.
  virtual ~FecState();

  /// \brief Initialize the class members of a FecState object.
  void Initialize();

  /// \brief Insert a chunk packet into the cache.
  ///
  /// Note: The FecState object assumes ownership of the packet.
  ///
  /// \param  cacheType  The cache type into which the chunk will be inserted
  ///                    (original or repair).
  /// \param  qpkt       The chunk packet to be inserted.
  /// \param  index      The index within the cache to use when inserting the
  ///                    chunk.
  /// \param  fec_used   True if FEC encoding is used for this group.
  /// \param  bytes_srcd Byte count of the total number of bytes sent up to
  ///                    this FEC state.
  /// \param  pkts_srcd  Total number of packets sent by the source up to this
  ///                    FEC state.
  ///
  /// \return  FECSTATE_OKAY on success, error code otherwise
  int AddToCache(unsigned long cacheType, iron::Packet* qpkt, int index,
                 bool fec_used, uint64_t bytes_srcd, uint32_t pkts_srcd);

  /// \brief Retrieve a whole original packet from the cache by assembling it
  /// from chunks,stripping off any FEC trailers in the process.
  ///
  /// \param  pktID  PacketID requested to be reassemble
  ///
  /// \return Reassembled packet if successful, NULL otherwise
  iron::Packet* ReassembleFromCache(int pktID);

  /// \brief Reconstruct the original chunk packets if sufficient number of
  /// original and repair chunks have been received.
  ///
  /// \return True if a full set of original chunks has been recovered, false
  ///         otherwise.
  bool UpdateFEC();

  /// \brief Function to flush the decoding cache and reset associated control
  /// values in preparation for encoding the next group.
  ///
  /// \return FECSTATE_OKAY if successful, error codes otherwise
  int  FlushCache();

  /// \brief Get the packet ID for the first packet that has not been sent.
  ///
  /// \return The packet ID for the first packet that has not been sent.
  int getFirstUnsentPktID() const;

  /// \brief Get the next time of packets in this group.
  ///
  /// \param index The start index of the search.
  ///
  /// \return The expiration time of the subsequent packet.
  iron::Time next_pkt_exp(int index) const;

  /// \brief Set the expiration time of the FecState.
  ///
  /// \param t A time object to indicate the expiration time of the FecState.
  inline void set_expiration_time(iron::Time t)
  {
    expiration_time_ = t;
  }

  /// \brief Get the expiration time of the FecState.
  ///
  /// \return The expiration time of this FecState.
  inline iron::Time expiration_time()
  {
    return expiration_time_;
  }

  /// \brief Set the group id for the current decoding pass.
  ///
  /// \param  group_id  The group id for the current decoding pass.
  inline void set_group_id(int group_id)
  {
    group_id_  = group_id & FEC_GROUPID_MASK;
  }

  /// \brief Get the group id of this FEC group.
  ///
  /// \return The group id of this FEC group.
  inline int group_id() const
  {
    return group_id_;
  }

  /// \brief Get the number of original chunks encoded in this group.
  ///
  /// \return The number of original chunks in this group.
  inline int base_rate() const
  {
    return base_rate_;
  }

  /// \brief Determine whether a given packet has been retrieved from cache
  /// and sent to the end application.
  ///
  /// \return True if the given packet has been sent to the end application.
  inline bool pkt_sent(int index) const
  {
    if ((index >= 0) && (index < MAX_FEC_RATE))
    {
      return pkt_sent_[index];
    }
    return false;
  }

  /// \brief Set the decoding rates used for the current decoding pass.
  ///
  /// \param  base_rate  The number or original chunks.
  /// \param  fec_rate   The number of repair chunks.
  inline void setRates(int base_rate, int fec_rate)
  {
    base_rate_ = base_rate;
    fec_rate_  = fec_rate;
  }

  /// \brief Set the "has been sent" state to "true" for a given packet in the
  /// indicator array.
  ///
  /// \param  index  Index into the indicator array for the packet that has
  ///                been sent.
  inline void set_pkt_sent (int index)
  {
    if ((index >= 0) && (index < MAX_FEC_RATE))
    {
      pkt_sent_[index] = true;
    }
  }

  /// \brief Get the maximum packet ID seen up to this point for the current
  /// decoding pass.
  ///
  /// \return The maximum packet ID seen for the current decoding pass.
  inline int max_pkt_id()
  {
    return max_pkt_id_;
  }

  /// \brief Query if FEC is used for this group.
  ///
  /// \return True of FEC is used for the group, false otherwise.
  inline bool fec_used() const
  {
    return fec_used_;
  }

  /// \brief Set the expiration time of a packet in this FEC group.
  ///
  /// \param index The slotId of the packet being set.
  /// \param exp_time Teh expiration time of this packet.
  inline void set_pkt_expiration_time(int index, iron::Time exp_time)
  {
    pkt_expiration_time_[index] = exp_time;
    if ((exp_time < expiration_time_) || (expiration_time_ == iron::Time(0)))
    {
      expiration_time_ = exp_time;
    }
  }

  /// \brief Set the DecodingState for this FecState.
  ///
  /// \param  decoding_state  The DecodingState to which this FecState
  ///                         belongs.
  inline void set_decoding_state(DecodingState* decoding_state)
  {
    decoding_state_ = decoding_state;
  }

  /// \brief Get the decoding state to which this FecState belongs.
  ///
  /// \return A pointer to the decoding state.
  inline DecodingState* decoding_state() const
  {
    return decoding_state_;
  }

  /// \brief Get the total number of bytes sent by the source up to and
  /// including this FEC State.
  ///
  /// \return The total number of bytes sent by the source up to and
  /// including this FEC State.
  inline uint64_t bytes_sourced() const
  {
    return bytes_sourced_;
  }

  /// \brief Get the total number of bytes released in this FecState.
  ///
  /// \return The total number of bytes released in this FecState.
  inline uint64_t bytes_released() const
  {
    return bytes_released_;
  }

  /// \brief Get the largest packet sequence number for this FecState.
  ///
  /// \return The highest sequence number for this FecState.
  inline uint32_t max_pkt_sn() const
  {
    return max_pkt_sn_;
  }

  /// \brief Get the smallest packet sequence number for this FecState.
  ///
  /// \return The smallest packet sequence number for this FecState.
  inline uint32_t min_pkt_sn() const
  {
    return min_pkt_sn_;
  }

  protected:

  /// Current group we are encoding.
  int                group_id_;

  /// Base rate from most recent rpr pkt.
  int                base_rate_;

  /// FEC rate from most recent rpr pkt.
  int                fec_rate_;

  /// No. chunks in the orig cache.
  int                orig_count_;

  /// Indicator of chunk availability.
  bool               orig_valid_[MAX_FEC_RATE];

  /// Indicator of (possibly reconstructed) packet transmission status.
  bool               pkt_sent_[MAX_FEC_RATE];

  /// Array pointing towards first chunk containing (part of) a given pktID.
  int                pkt_lookup_[MAX_FEC_RATE];

  /// Maximum pktID seen so far.
  int                max_pkt_id_;

  /// Pool containing packets to use.
  iron::PacketPool&  packet_pool_;

  /// Original chunks seen so far.
  iron::Packet*      orig_cache_[MAX_FEC_RATE];

  /// No. chunks (pkts) in the FEC cache.
  int                fec_count_;

  // Indicator of FEC chunk (pkt) availability.
  bool               fec_valid_[MAX_FEC_RATE];

  /// FEC chunks (pkts) seen so far.
  iron::Packet*      fec_cache_[MAX_FEC_RATE];

  /// The time by which this FEC group should be sent.
  /// it is equal to min(MaxHoldTime, RecvTime + TTG).
  iron::Time         expiration_time_;

  /// The expiration time of each packet in this FEC group.
  iron::Time         pkt_expiration_time_[MAX_FEC_RATE];

  /// Indicate if FEC is acually used for this group.
  bool               fec_used_;

  /// A pointer to the DecodingState to which this belongs.
  DecodingState*     decoding_state_;

  /// Total number of bytes sent by the source up to and including
  /// this FEC State.
  uint64_t           bytes_sourced_;

  /// The total number of bytes released from this FecState.
  uint64_t           bytes_released_;

  /// The largest packet sequence number seen for this FecState.
  uint32_t           max_pkt_sn_;

  /// The starting packet sequence number for this FecState.
  uint32_t           min_pkt_sn_;

  /// The source bin ID of packets in the FecState. Since this is carried in
  /// the packet and never used other than copying it out to the coded packet,
  /// it doesn't hurt to store it as the ID (rather than converting to an
  /// index).
  iron::BinId         bin_id_;

  private:

  /// \brief No-arg constructor.
  FecState();

  /// \brief Copy constructor.
  FecState(const FecState& fs);

  /// \brief Assignment operator.
  FecState& operator=(const FecState& fs);

  /// \brief Retrieve a chunk packet from the cache: no trailers are removed.
  ///
  /// \param  cacheType  Specifies whether an original or repair chunk is
  ///                    retrieved.
  /// \param  index      The slot number within the cache.
  ///
  /// \return The chunk packet if successful, NULL if not.
  iron::Packet* FetchFromCache(unsigned long cacheType, int index);

  void UpdateLookupInfo(int index);

}; // end class FecState

#endif // IRON_UDP_PROXY_FEC_STATE_H
