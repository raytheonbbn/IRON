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

/// \brief Header file for Receiver Report Message (RRM) packet utility
/// functions.
///
/// Provides mechanisms for creating and manipulating RRM packets.


#ifndef IRON_UDP_PROXY_RRM_H
#define IRON_UDP_PROXY_RRM_H

#include "four_tuple.h"
#include "packet.h"
#include "packet_pool.h"

namespace iron
{
  class Rrm
  {
    public:
    static const uint16_t  kDefaultRrmPort = 48900;

    /// \brief  Create a new RRM message.
    /// Ownership of the packet is passed to the caller.
    ///
    /// \param  pkt_pool  The packet pool to use for creating the packet.
    /// \param  four_tuple  The four-tuple identifying the flow for which the 
    ///                     report is to be created.
    ///
    /// \return A pointer to the RRM packet, NULL if failed. 
    static Packet* CreateNewRrm(iron::PacketPool& pkt_pool,
                                iron::FourTuple& four_tuple);

    /// \brief  Fill the report in the RRM message.
    ///
    /// \param  rrm The RRM message to fill.
    /// \param  tot_bytes The total number of bytes sent.
    /// \param  tot_pkts  The total number of packets sent.
    /// \param  rel_bytes The number of bytes released.
    /// \param  rel_pkts  The number of packets released.
    /// \param  loss_rate The flow loss rate.
    static void FillReport(Packet* rrm,
                           uint64_t tot_bytes, uint32_t tot_pkts,
                           uint64_t rel_bytes, uint32_t rel_pkts,
                           uint32_t loss_rate);

    /// \brief  Get the flow four tuple from an RRM packet.
    ///
    /// \param  rrm The RRM packet.
    /// \param  four_tuple  The four tuple for which the RRM is intended.
    static void GetFlowFourTuple(Packet* rrm, iron::FourTuple& four_tuple);

    /// \brief  Get the report from an RRM packet.
    ///
    /// \param  rrm The RRM packet.
    /// \param  tot_bytes The total number of bytes sent.
    /// \param  tot_pkts  The total number of packets sent.
    /// \param  rel_bytes The number of bytes released.
    /// \param  rel_pkts  The number of packets released.
    /// \param  loss_rate The flow loss rate.
    static void GetReport(Packet* rrm,
                          uint64_t& tot_bytes, uint32_t& tot_pkts,
                          uint64_t& rel_bytes, uint32_t& rel_pkts,
                          uint32_t& loss_rate);

    /// \brief  Get the flow's destination port (not the RRM specific port).
    ///
    /// \param  rrm The RRM packet.
    ///
    /// \return The destination port.
    static uint16_t GetFlowDstPort(iron::Packet* rrm);

    /// \brief  Print the contents of the RRM.
    ///
    /// \param  rrm The RRM message to print.
    static void PrintRrm(iron::Packet* rrm);

    private:
    /// Disallow constructor.
    Rrm();

    /// Disallow destructor.
    virtual ~Rrm();

    /// Disallow the copy constructor.
    Rrm(const Rrm&);

    /// Disallow the assignment operator.
    Rrm& operator=(const Rrm&);

    /// \brief  Get the location of the buffer where the report starts (after 
    ///         the flow destination port).
    ///
    /// \param  rrm The RRM message to fill.
    ///
    /// \return The location of the report in the RRM packet.
    static inline uint8_t* GetReportBuffer(iron::Packet* rrm)
    {
      return rrm->GetBuffer(rrm->GetIpPayloadOffset() + sizeof(uint16_t)
        + sizeof(uint16_t));
    }

  };  // Class Rrm
} // namespace iron

#endif  // IRON_UDP_PROXY_RRM_H
