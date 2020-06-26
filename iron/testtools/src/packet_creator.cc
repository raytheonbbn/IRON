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

#include "packet_creator.h"

#include "log.h"
#include "unused.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

using ::iron::FourTuple;
using ::iron::Packet;
using ::iron::PacketCreator;

namespace
{
  const char* UNUSED(kClassName) = "PacketCreator";
}

//============================================================================
Packet* PacketCreator::CreateUdpPacket(
  PacketPool& pkt_pool,
  FourTuple* four_tuple,
  uint32_t data_len_bytes)
{
  LogD(kClassName, __func__, "Creating UDP packet with length %"
       PRIu32 "\n", data_len_bytes);
  struct iphdr  iphdr;
  struct udphdr udphdr;
  memset(&iphdr, 0, sizeof(iphdr));
  memset(&udphdr, 0, sizeof(udphdr));

  Packet* pkt = pkt_pool.Get();
  if (!pkt)
  {
    LogE(kClassName, __func__, "Failed to get packet from pool.\n");
    return NULL;
  }

  FourTuple ft;
  if (!four_tuple)
  {
    four_tuple = &ft;
    ft.Set(1, 2, 3, 4);
  }

  iphdr.version  = 4;
  iphdr.ihl      = 5;
  iphdr.protocol = IPPROTO_UDP;
  iphdr.saddr    = four_tuple->src_addr_nbo();
  iphdr.daddr    = four_tuple->dst_addr_nbo();
  iphdr.tos      = 0; // 0 out this field so we don't accidentally think this
                      // packet is a zombie.
  iphdr.check    = 0;
  iphdr.tot_len  = htons(sizeof(iphdr));

  udphdr.source = four_tuple->src_port_nbo();
  udphdr.dest   = four_tuple->dst_port_nbo();

  size_t length = 0;
  memcpy(pkt->GetBuffer(), reinterpret_cast<void*>(&iphdr),
         sizeof(iphdr));
  length += sizeof(iphdr);
  pkt->SetLengthInBytes(length);
  pkt->SetIpDscp(DSCP_DEFAULT);

  // Append the UDP header to the Packet.
  if (!pkt->AppendBlockToEnd(reinterpret_cast<uint8_t*>(&udphdr),
                             sizeof(udphdr)))
  {
    LogE(kClassName, __func__, "Failed to add udp header to packet.\n");
    pkt_pool.Recycle(pkt);
    return NULL;
  }
  length += sizeof(udphdr);
  pkt->SetLengthInBytes(length);

  // Setting data to all 5s in case a unit test wants to verify anything to do
  // with actual data lengths or data content.
  memset(pkt->GetBuffer(length), 5, data_len_bytes);
  length += data_len_bytes;
  pkt->SetLengthInBytes(length);
  if (!pkt->UpdateIpLen() || !pkt->UpdateChecksums())
  {
    LogE(kClassName, __func__, "Failed to update IP length and checksum.\n");
    pkt_pool.Recycle(pkt);
    return NULL;
  }
  return pkt;
}
