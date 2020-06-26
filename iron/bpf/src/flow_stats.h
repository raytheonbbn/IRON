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

#ifndef IRON_BPF_FLOW_STATS_H
#define IRON_BPF_FLOW_STATS_H

#include "four_tuple.h"
#include "packet.h"

namespace iron
{
  /// \brief A flow filter.
  ///
  /// Flow filters are used to determine if received packets match a set of
  /// user specified criteria of interest.
  class FlowFilter
  {
    public:

    /// \brief Default no-arg constructor.
    FlowFilter();

    /// \brief Destructor.
    virtual ~FlowFilter();

    /// \brief Configure the flow filter.
    ///
    /// \param  filter_spec  The filter specification.
    ///
    /// \return True if the filter specification is properly formatted and
    ///         supported, false otherwise.
    bool Configure(const std::string& filter_spec);

    /// \brief Determines if a received Packet matches the filter.
    ///
    /// \param  packet  The received packet.
    ///
    /// \return True if the received Packet matches the filter, false
    ///         otherwise.
    bool Matches(const Packet* packet) const;

    private:

    /// \brief Copy constructor.
    FlowFilter(const FlowFilter& other);

    /// \brief Set the filter's source address value, in Network Byte Order.
    ///
    /// \param  saddr  The filter's source address value, in Network Byte
    ///                Order.
    inline void set_saddr(uint32_t saddr)
    {
      saddr_set_ = true;
      saddr_     = saddr;
    }

    /// \brief Set the filter's source port value, in Network Byte Order.
    ///
    /// \param  sport  The filter's source port value, in Network Byte Order.
    inline void set_sport(uint16_t sport)
    {
      sport_set_ = true;
      sport_     = sport;
    }

    /// \brief Set the filter's destination address value, in Network Byte
    /// Order.
    ///
    /// \param  daddr  The filter's destination address value, in Network Byte
    ///                Order.
    inline void set_daddr(uint32_t daddr)
    {
      daddr_set_ = true;
      daddr_     = daddr;
    }

    /// \brief Set the filter's destination port value, in Network Byte
    /// Order.
    ///
    /// \param  dport  The filter's destination port value, in Network Byte
    ///                Order.
    inline void set_dport(uint16_t dport)
    {
      dport_set_ = true;
      dport_     = dport;
    }

    /// \brief Set the filter's protocol value.
    ///
    /// \param  proto  The filter's protocol value.
    inline void set_proto(uint8_t proto)
    {
      proto_set_ = true;
      proto_     = proto;
    }

    /// \brief Set the filter's dscp value.
    ///
    /// \param  dscp  The filter's dscp value.
    inline void set_dscp(uint8_t dscp)
    {
      dscp_set_ = true;
      dscp_     = dscp;
    }

    /// Indicates if the source address is part of the filter.
    bool      saddr_set_;

    /// The filter's source address, in Network Byte Order.
    uint32_t  saddr_;

    /// Indicates if the source port is part of the filter.
    bool      sport_set_;

    /// The filter's source port, in Network Byte Order.
    uint16_t  sport_;

    /// Indicates if the destination address is part of the filter.
    bool      daddr_set_;

    /// The filter's destination address, in Network Byte Order.
    uint32_t  daddr_;

    /// Indicates if the destination port is part of the filter.
    bool      dport_set_;

    /// The filter's destination port, in Network Byte Order.
    uint16_t  dport_;

    /// Indicates if the protocol is part of the filter.
    bool      proto_set_;

    /// The filter's protocol.
    uint8_t   proto_;

    /// Indicates if the DSCP value is part of the filter.
    bool      dscp_set_;

    /// The filter's DSCP value.
    uint8_t   dscp_;

  }; // end class FlowFilter


  /// \brief Collects and reports flow statistics.
  ///
  /// Stastistics are accumulated for packets that match a user configurable
  /// flow filter.
  class FlowStats
  {
    public:

    /// \brief Constructor.
    FlowStats();

    /// \brief Destructor.
    virtual ~FlowStats();

    /// \brief Set the filter used to match packets.
    ///
    /// \param  flow_filter  The flow statistic's filter specification.
    inline void SetFilter(const FlowFilter& flow_filter)
    {
      flow_filter_ = flow_filter;
    }

    /// \brief Record flow statistics.
    ///
    /// If the packet matches the desired flow characteristics, add the number
    /// of bytes in the packet to the cumulative number of bytes.
    ///
    /// \param  packet  The received packet.
    void Record(const Packet* packet);

    /// \brief Get the number of bytes that match the filter.
    ///
    /// Reports the nymber of bytes matching the desired flow filter and
    /// resets the bytes accumulator.
    ///
    /// \return The number of bytes matching the desired flow filter.
    uint32_t Report();

    private:

    /// \brief Copy constructor.
    FlowStats(const FlowStats& other);

    /// \brief Copy operator.
    FlowStats& operator=(const FlowStats& other);

    /// The flow filter.
    FlowFilter  flow_filter_;

    /// The cumulative number of bytes that match the flow filter.
    uint32_t    byte_count_;

  }; // end class FlowStats

} // namespace iron

#endif // IRON_BPF_FLOW_STATS_H
