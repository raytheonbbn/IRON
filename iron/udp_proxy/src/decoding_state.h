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

#ifndef IRON_UDP_PROXY_DECODING_STATE_H
#define IRON_UDP_PROXY_DECODING_STATE_H

#include "fec_state.h"
#include "fec_state_pool.h"
#include "four_tuple.h"
#include "inter_process_comm.h"
#include "itime.h"
#include "k_val.h"
#include "packet.h"
#include "packet_pool.h"
#include "queue.h"
#include "queue_depths.h"
#include "src_info.h"
#include "udp_fec_trailer.h"
#include "utility_fn_if.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <ctime>
#include <string.h>
#include <sys/types.h>

class UdpProxy;
class ReleaseController;
class FecState;

/// A decoding state is used to store per-flow state at the destination
/// UDP Proxy. The decoding state contains a map which holds the FEC
/// groups (FecState) until they are processed.
class DecodingState
{
  public:

  /// \brief Constructor.
  ///
  /// \param  udp_proxy      Reference to the UDP Proxy.
  /// \param  packet_pool    Pool containing packet to use.
  /// \param  bin_map        System-wide bin map.
  /// \param  k_val          Reference to the k value.
  /// \param  fecstate_pool  Pool containing FEC state.
  /// \param  four_tuple     The Decoding State's 4-tuple.
  /// \param  flow_tag           The Encoding State's flow tag. This uniquely
  ///                            identifies the flow.
  DecodingState(UdpProxy& udp_proxy, iron::PacketPool& packet_pool,
                iron::BinMap& bin_map,
                iron::KVal& k_val, FecStatePool& fecstate_pool,
                const iron::FourTuple& four_tuple, uint32_t flow_tag);

  /// \brief Destructor.
  virtual ~DecodingState();

  /// \brief Create the Decoding State's release controller.
  ///
  /// \param  utility_def  The utility definition string.
  ///
  /// \return True if the release controller is successfully created, false
  ///       otherwise.
  bool CreateReleaseController(const std::string utility_def);

  /// \brief Handle a received packet.
  ///
  /// The Decoding State assumes ownership of the received packet.
  ///
  /// \param  pkt  The received packet.
  void HandlePkt(iron::Packet* pkt);

  /// \brief Service the decoding state's events.
  ///
  /// \param  now  The current time.
  void SvcEvents(iron::Time& now);

  /// \brief Release a decoded packet.
  ///
  /// \param  pkt  Pointer to the packet to be released.
  ///
  /// \return The number of bytes written if the packet is successfully
  ///         released. If 0 bytes are released, the caller retains ownership
  ///         of the packet. Otherwise, this class assumes ownership of the
  ///         packet.
  ssize_t ReleasePkt(iron::Packet* pkt) const;

  /// \brief Write the collected Decoding State stats to the log file and/or
  /// the JSON writer.
  ///
  /// \param  now      The current time.
  /// \param  log_str  The string that is created for the log file.
  /// \param  writer   The JSON writer that is used to create the JSON
  ///                  message.
  void WriteStats(iron::Time& now, std::string& log_str,
                  rapidjson::Writer<rapidjson::StringBuffer>* writer = NULL);

  /// \brief Get the garbage collection timeout time.
  ///
  /// \return The last time this decoding state was used.
  inline time_t lastTime() const
  {
    return last_time_;
  }

  /// \brief Set the maximum hold time for reordering.
  ///
  /// \param  reorder_time  The maximum hold time for reordering as a Time
  ///                       object.
  inline void set_max_reorder_time(iron::Time reorder_time )
  {
    max_reorder_time_ = reorder_time;
  }

  /// \brief Get the 4-tuple associated with the Decoding State.
  ///
  /// \return The 4-tuple associated with the Decoding State.
  inline iron::FourTuple four_tuple() const
  {
    return four_tuple_;
  }

  /// \brief Get the unique tag associated with the flow.
  ///
  /// This is used as the tag in the timers of the encoding state in the UDP
  /// proxy.
  ///
  /// \return The unique tag associated with the flow.
  inline uint32_t flow_tag() const
  {
    return flow_tag_;
  }

  private:

  /// \brief No-arg constructor.
  DecodingState();

  /// \brief Copy constructor.
  DecodingState(const DecodingState& ds);

  /// \brief Assignment operator.
  DecodingState& operator=(const DecodingState& ds);

  /// \brief Send packets from the decoding state to the release controller.
  void ReleaseInOrderPackets();

  /// \brief Determine if a received chunk is "late", i.e., its groupID has
  /// already been processed or possibly skipped over.
  ///
  /// This will happen, for example, if we receive more than the number of
  /// repair packets than we need to reconstruct the original group. As soon
  /// as we get the minimum number required, we reconstruct, send, and
  /// increment the groupID. If an extra repair packet shows up for this
  /// group, it is considered late and we can safely drop it.
  ///
  /// \param  grp_id  The FEC group ID being considered.
  /// \param  cur_id  The reference point.
  ///
  /// \return True if the chunk is late, false otherwise.
  inline bool IsLate(uint32_t grp_id, uint32_t cur_id = 0)
  {
    if (cur_id == 0)
    {
      cur_id = next_grp_id_;
    }
    return ((grp_id - cur_id) > (FEC_GROUPID_ROLLOVER >> 1));
  }

  /// \brief  Get the sequentially next FEC group for which we have
  /// received packets.
  ///
  /// \param cur_group The group from which the next FEC group is needed.
  /// \return The groupId of the next non-empty FEC group.
  int GetNextFecGrp(int cur_group);

  /// \brief Get the expiration time of the next packet, relative to a
  /// specific packet in a FEC group.
  ///
  /// This is used to ensure the expiration of a packet in group X is
  /// no greater than the expiration of a packet in group Y, where X < Y.
  ///
  /// \param index The packetId of the start point for the search.
  /// \param groupId the groupID of the start point for the search.
  /// \return The expiration time of the next packet, for Time::Infinite()
  ///         if this is no packet in a subsequent group.
  iron::Time GetNextExpTime(int index, int groupId);

  /// \brief Check if there is an FecState object for a specified
  /// group id.
  ///
  /// \param  group_id  The FecState group id.
  bool HasFecState(int group_id);

  /// \brief Get a pointer an FecState in the fec_state_map.
  ///
  /// \param groupId The groupID of the FecState
  /// \param fec_state A reference to the FecState pointer, which
  /// will be set by this method.
  inline void GetFecState(int groupId, FecState*& fec_state)
  {
    fec_state = fec_state_map_[groupId];
  }

  /// \brief Delete a FecState.
  ///
  /// \param The group_id of the FecState being deleted.
  void DeleteFecState(int group_id);

  /// \brief Get the expiration time of a group.
  ///
  /// \param  group_id  The group ID.
  ///
  /// \return The expiration time of the specified group.
  inline iron::Time grp_exp_time(int group_id)
  {
    if (fec_state_map_.find(group_id) != fec_state_map_.end())
    {
      return fec_state_map_[group_id]->expiration_time();
    }
    else
    {
      return iron::Time::Infinite();
    }
  }

  /// \brief  Accumulates packet information into the state for stats
  /// reporting.
  ///
  /// This information is for flows whose packets were admitted to the network
  /// or sent to the BPF.
  ///
  /// \param  length_bytes  The packet size that needs to be accumulated.
  /// \param  delay         The packet delay.
  void AccumulatePacketInfo(uint64_t length_bytes, const iron::Time& delay);

  /// \brief Process a FEC group ready timer timeout.
  ///
  /// \param  now  The current time.
  void FecGrpReadyTimeout(iron::Time& now);

  /// \brief Send packet to the release controller.
  ///
  /// \param  fec_state  A pointer to the FecState object for the group
  ///                    from which packets are to be sent.
  /// \param  next_exp   The expiration time of the next FecState.
  ///
  /// \return True if all packets have been sent from this FecState.
  bool SendToReleaseController(FecState* fec_state, iron::Time& next_exp);

  /// Reference to the UDP Proxy.
  UdpProxy&                 udp_proxy_;

  /// The packet release controller.
  ReleaseController*        release_controller_;

  /// Reference to the packet pool.
  iron::PacketPool&         packet_pool_;

  /// Reference to the system-wide bin map.
  iron::BinMap&             bin_map_;

  /// Pool of fec states to use.
  FecStatePool&             fecstate_pool_;

  /// A collection of groups of packets being decoded.
  std::map<int, FecState*>  fec_state_map_;

  /// The time that the next FEC group should be provided to the release
  /// controller.
  iron::Time                fec_grp_ready_time_;

  /// The group that is expected to be sent next
  int                       next_grp_id_;

  /// Last time this was accessed.
  time_t                    last_time_;

  /// The maximum hold time for reordering.
  iron::Time                max_reorder_time_;

  /// The Decoding State's bin index (mcast or unicast).
  iron::BinIndex            bin_idx_;

  /// The Decoding State's four tuple.
  iron::FourTuple           four_tuple_;

  /// The Decoding State's flow identifier.
  uint32_t                  flow_tag_;

  /// The number of packets sent or received since the last dump.
  uint64_t                  dump_byte_number_;

  /// The number of bytes sent or received since the last dump.
  uint64_t                  dump_pkt_number_;

  /// The number of packets sent or received since proxy start.
  uint64_t                  total_byte_number_;

  /// The number of bytes sent or received since proxy start.
  uint64_t                  total_pkt_number_;

  /// The largest packet delay.
  iron::Time                max_pkt_delay_;

  /// The cumulative packet delay.
  iron::Time                cum_pkt_delay_;

  /// The last statistics report time.
  iron::Time                last_report_time_;

  /// The priority of the flow, as reported by the source. This should be
  /// in the range 0-255. If the priority of the flow is greater than 255
  /// it would be rounded down to 255.
  uint8_t                   priority_;

  /// The loss threshold for the flow, as reported by the source, as a
  /// percentage. This should be in the range 0-100.
  uint8_t                   loss_thresh_pct_;

  /// The highest packet sequence number seen.
  uint32_t                  pkt_seq_num_;

}; // end class DecodingState


#endif // IRON_UDP_PROXY_DECODING_STATE_H
