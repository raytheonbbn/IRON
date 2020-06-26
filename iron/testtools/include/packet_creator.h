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
/// Provides static functions for generating filled packets for the sake of
/// unit tests.
///

#ifndef IRON_TESTTOOLS_PACKET_CREATOR_H
#define IRON_TESTTOOLS_PACKET_CREATOR_H

#include "four_tuple.h"
#include "packet.h"
#include "packet_pool.h"

namespace iron
{

  /// \brief Container class for static methods for creating dummy packets.
  ///
  /// For use in unit tests that need semi-filled packets.
  class PacketCreator
  {
    public:

    virtual ~PacketCreator() {};

    /// \brief Create a UDP packet with the given fields.
    ///
    /// \param pkt_pool   Packet pool to get a new packet from.
    /// \param four_tuple IP addresses and ports to use for this packet. MAY
    ///                   BE NULL. If null, default dummy values will be used.
    /// \param data_len_bytes How long to make the UDP payload.
    ///
    /// \return Packet The new packet (control goes to the caller) or NULL if
    ///                none could be created.
    static Packet* CreateUdpPacket(PacketPool& pkt_pool,
                                   FourTuple* four_tuple,
                                   uint32_t data_len_bytes);


    private:

    /// Disable constructor
    PacketCreator();

    /// Disable copy constructor
    PacketCreator(const PacketCreator&);

    /// Disable assignment
    PacketCreator& operator=(const PacketCreator&);
  }; // end class PacketCreator
} // end namespace iron

#endif // IRON_TESTTOOLS_PACKET_CREATOR_H
