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

#ifndef IRON_UTIL_MGMS_H
#define IRON_UTIL_MGMS_H

#include "config_info.h"
#include "ipv4_address.h"
#include "list.h"
#include "mash_table.h"
#include "packet_pool.h"
#include "remote_control.h"
#include "virtual_edge_if.h"

#include <string>

/// \brief The GNAT Multicast Group Management Sniffer (mgms).
///
/// mgms runs on each GNAT node and "sniffs" multicast group management
/// messages (currently only IGMP messages are received and processed). mgms
/// also notifies AMP of multicast group joins/leaves, if required.
class Mgms
{
  public:

  /// \brief Constructor.
  ///
  /// \param  edge_if      Edge interface used to receive Group Management
  ///                      messages (IGMP and PIM) from the LAN-facing
  ///                      interface.
  /// \param  packet_pool  Pool of packets to use.
  Mgms(iron::VirtualEdgeIf& edge_if, iron::PacketPool& packet_pool);

  /// \brief Destructor.
  virtual ~Mgms();

  /// \brief   Initialize Amp with connections and configurations
  ///          for the specific node it is running on.
  /// \param   ci A config info object for the IRON node for this AMP.
  /// \return  True if successful.
  bool Initialize(const iron::ConfigInfo& ci);

  /// \brief Start the Multicast Group Management Sniffer.
  ///
  /// The Multicast Group Management Sniffer runs until a Ctrl-c signal is
  /// caught.
  void Start();

  /// \brief Shutdown the Multicast Group Management Sniffer.
  inline void Stop()
  {
    running_ = false;
  }

  private:

  /// \brief Contains the information for a multicast group member.
  struct MbrInfo
  {
    /// The multicast group member address.
    iron::Ipv4Address  mbr_addr;

    /// The expiration time of the group member. This is updated as group
    /// management messages are received and if used to remove the group
    /// member when we no longer receive group management messages from the
    /// member.
    iron::Time         exp_time;
  };

  /// \brief Contains the information for a multicast group.
  struct GrpInfo
  {
    /// The multicast group address.
    iron::Ipv4Address     mcast_addr;

    /// The multicast group members.
    iron::List<MbrInfo*>  mbrs;
  };

  /// \brief Contains the information for an expired multicast group member.
  struct ExpMbrInfo
  {
    /// The multicast group address.
    iron::Ipv4Address  mcast_addr;

    /// The multicast group member address.
    iron::Ipv4Address  mbr_addr;
  };

  /// \brief  Default no-arg constructor.
  Mgms();

  /// \brief Copy constructor.
  Mgms(const Mgms& m);

  /// \brief Copy operator.
  Mgms& operator=(const Mgms& m);

  /// \brief Process a received packet.
  ///
  /// \param  pkt  The received packet to process.
  void ProcessPkt(iron::Packet* pkt);

  /// \brief Process a received IGMP packet.
  ///
  /// \param  igmp_pkt  The received IGMP packet.
  void ProcessIgmpPkt(iron::Packet* igmp_pkt);

  /// \brief Process a received PIM packet.
  ///
  /// \param  pim_pkt  The received PIM packet.
  void ProcessPimPkt(iron::Packet* pim_pkt);

  /// \brief Parse the PIM Join/Prune message address family.
  ///
  /// \param  buf     The PIM message buffer.
  /// \param  offset  The current offset into the message buffer. This will be
  ///                 updated as the address family is parsed.
  ///
  /// \return True if successful, false otherwise.
  bool ParsePimAddrFamily(uint8_t* buf, size_t& offset) const;

  /// \brief Add a group member to a multicast group.
  ///
  /// In addition to modifying the multicast group cache, this notifies AMP of
  /// the change in membership, if required.
  ///
  /// \param  mcast_addr  The multicast group address.
  /// \param  mbr_addr    The multicast group member address.
  /// \param  now         The group management message received time.
  void AddToMcastGrpCache(const iron::Ipv4Address& mcast_addr,
                          const iron::Ipv4Address& mbr_addr,
                          const iron::Time& now);

  /// \brief Remove a group member from a multicast group.
  ///
  /// In addition to modifying the multicast group cache, this notifies AMP of
  /// the change in membership, if required.
  ///
  /// \param  mcast_addr  The multicast group address.
  /// \param  mbr_addr    The multicast group member address.
  void RemoveFromMcastGrpCache(const iron::Ipv4Address& mcast_addr,
                               const iron::Ipv4Address& mbr_addr);

  /// \brief Remove expired multicast group members.
  ///
  /// This removes multicast group members for which group management messages
  /// are no longer being received.
  void RemoveExpMembers();

  /// \brief Send a Set message to AMP.
  ///
  /// \param  amp_msg  The message to send to AMP.
  void SendSetMsgToAmp(std::string amp_msg);

  /// Edge interface for the UDP Proxy's LAN side.
  iron::VirtualEdgeIf&                          edge_if_;

  /// Pool containing packets to use.
  iron::PacketPool&                             packet_pool_;

  /// Mash table to store the mapping of multicast group to application node
  /// IP addresses.
  iron::MashTable<iron::Ipv4Address, GrpInfo*>  mcast_grp_cache_;

  /// Remote control client to maintain connection state to AMP.
  iron::RemoteControlClient                     rc_client_;

  /// The AMP endpoint id.
  uint32_t                                      amp_ep_id_;

  /// The multicast group membership expiration interval, in seconds.
  uint16_t                                      exp_interval_secs_;

  /// The next multicast group member cleanup time.
  iron::Time                                    next_exp_time_;

  /// Remembers if we are running or not.
  bool                                          running_;

}; // end class Mgms

#endif // IRON_UTIL_MGMS_H
