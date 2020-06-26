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

/// \brief Implementation of the Receiver Report Message (RRM) packet utility
/// functions.
///
/// Provides static functions for creating RRMs.

#include "rrm.h"

#include "unused.h"

using ::iron::Packet;
using ::iron::Rrm;

namespace
{
  const char* UNUSED(kClassName)  = "RRM";
}

//============================================================================
Packet* Rrm::CreateNewRrm(PacketPool& pkt_pool, iron::FourTuple& four_tuple)
{
  // RRM packets have the following headers and format:
  // 20B: IP header (no IP option).
  // 8B: UDP header with the destination port set to special RRM port.
  // 2B: Flow dest port.
  // 2B: Padding.
  // --- Report buffer starts here ---
  // 8B: bytes sourced.
  // 8B: bytes released.
  // 4B: packets sourced.
  // 4B: packets released.
  // 4B: average loss rate.
  Packet* rrm = pkt_pool.Get(PACKET_NOW_TIMESTAMP);
  rrm->InitIpPacket();
  struct iphdr* iphdr = rrm->GetIpHdr();

  if (!iphdr)
  {
    LogF(kClassName, __func__,
         "Failed to get IP header in new packet.\n");
    return NULL; 
  }

  iphdr->id       = htons(pkt_pool.GetNextIpId());
  iphdr->protocol = IPPROTO_UDP;
  // In RRM, saddr is address of destination in flow four tuple, and vice versa.
  iphdr->saddr    = four_tuple.dst_addr_nbo();
  iphdr->daddr    = four_tuple.src_addr_nbo();

  rrm->SetIpDscp(DSCP_DEFAULT);
  rrm->SetTimeToGo(
    Time::FromUsec(static_cast<int64_t>(iron::kUnsetTimeToGo)));
  // Length is 20B.
  size_t  length          = rrm->GetLengthInBytes();

  length                 +=  sizeof(struct udphdr);
  // Length is 28B.
  rrm->SetLengthInBytes(length);

  rrm->SetSrcPort(four_tuple.src_port_nbo());
  rrm->SetDstPort(htons(kDefaultRrmPort));

  uint8_t*  buf           = rrm->GetBuffer(rrm->GetIpPayloadOffset());
  uint16_t  dst_port_nbo  = four_tuple.dst_port_nbo();
  
  // Length is expected to be 32B.
  length += sizeof(uint16_t) + sizeof(uint16_t);

  if (length > kMaxPacketSizeBytes)
  {
    LogF(kClassName, __func__,
         "RRM length %zd is larger than max packet size.\n",
         length);
    return NULL;
  }

  memcpy(buf, &dst_port_nbo, sizeof(dst_port_nbo));
  
  buf += sizeof(dst_port_nbo);
  memset(buf, 0, sizeof(uint16_t));

  rrm->SetLengthInBytes(length);
  rrm->UpdateIpLen();
  rrm->UpdateIpChecksum();

  LogD(kClassName, __func__,
       "Created RRM with length %zuB.\n", length);
  rrm->DumpIpHdr();
  return rrm;
}

//============================================================================
void Rrm::FillReport(Packet* rrm,
                     uint64_t tot_bytes, uint32_t tot_pkts,
                     uint64_t rel_bytes, uint32_t rel_pkts,
                     uint32_t loss_rate)
{
  size_t  length  = rrm->GetLengthInBytes();
  length         += sizeof(tot_bytes);
  length         += sizeof(rel_bytes);
  length         += sizeof(tot_pkts);
  length         += sizeof(rel_pkts);
  length         += sizeof(loss_rate);

  if (length > kMaxPacketSizeBytes)
  {
    LogF(kClassName, __func__,
         "RRM Length exceeds max packet size.\n");
    return;
  }

  // 2B: dest port.
  // 2B: Padding.
  // --- Report buffer starts here ---
  // 8B: bytes sourced.
  // 8B: bytes released.
  // 4B: packets sourced.
  // 4B: packets released.
  // 4B: average loss rate.
  uint8_t* buf  = iron::Rrm::GetReportBuffer(rrm);

  tot_bytes = htonl(tot_bytes);
  memcpy(buf, &tot_bytes, sizeof(tot_bytes));
  buf += sizeof(tot_bytes);
  
  rel_bytes = htonl(rel_bytes);
  memcpy(buf, &rel_bytes, sizeof(rel_bytes));
  buf += sizeof(rel_bytes);

  tot_pkts  = htonl(tot_pkts);
  memcpy(buf, &tot_pkts, sizeof(tot_pkts));
  buf += sizeof(tot_pkts);

  rel_pkts  = htonl(rel_pkts);
  memcpy(buf, &rel_pkts, sizeof(rel_pkts));
  buf += sizeof(rel_pkts);

  loss_rate = htonl(loss_rate);
  memcpy(buf, &loss_rate, sizeof(loss_rate));
  buf += sizeof(loss_rate);

  rrm->SetLengthInBytes(length);
  rrm->UpdateIpLen();
  rrm->UpdateIpChecksum();
}

//============================================================================
void Rrm::GetFlowFourTuple(Packet* rrm, iron::FourTuple& four_tuple)
{
  uint32_t  saddr_nbo;
  uint32_t  daddr_nbo;
  uint16_t  sport_nbo;
  uint16_t  dport_nbo;
  uint32_t  proto_nbo;

  rrm->GetFiveTuple(saddr_nbo, daddr_nbo, sport_nbo, dport_nbo, proto_nbo);

  if (ntohs(dport_nbo) != Rrm::kDefaultRrmPort)
  {
    LogF(kClassName, __func__,
         "RRM packet does not have port destination %" PRIu16 ".\n",
         kDefaultRrmPort);

    four_tuple.Set(0, 0, 0, 0);
    return;
  }

  dport_nbo  = GetFlowDstPort(rrm);
  four_tuple.Set(daddr_nbo, sport_nbo, saddr_nbo, dport_nbo);
}

//============================================================================
void Rrm::GetReport(Packet* rrm,
                    uint64_t& tot_bytes, uint32_t& tot_pkts,
                    uint64_t& rel_bytes, uint32_t& rel_pkts,
                    uint32_t& loss_rate)
{
  // 2B: dest port.
  // 2B: Padding.
  // --- Report buffer starts here ---
  // 8B: bytes sourced.
  // 8B: bytes released.
  // 4B: packets sourced.
  // 4B: packets released.
  // 4B: average loss rate.

  size_t  pkt_length  = rrm->GetLengthInBytes();

  if (pkt_length < sizeof(struct iphdr) + sizeof(struct udphdr) +
    sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint32_t) +
    sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint32_t))

  {
    LogF(kClassName, __func__,
         "Packet of size %zd is too short.\n",
         pkt_length);
    return;
  }

  uint8_t* buf  = iron::Rrm::GetReportBuffer(rrm);

  memcpy(&tot_bytes, buf, sizeof(tot_bytes));
  tot_bytes = ntohl(tot_bytes);
  buf += sizeof(tot_bytes);
  
  memcpy(&rel_bytes, buf, sizeof(rel_bytes));
  rel_bytes = ntohl(rel_bytes);
  buf += sizeof(rel_bytes);

  memcpy(&tot_pkts, buf, sizeof(tot_pkts));
  tot_pkts  = ntohl(tot_pkts);
  buf += sizeof(tot_pkts);

  memcpy(&rel_pkts, buf, sizeof(rel_pkts));
  rel_pkts  = ntohl(rel_pkts);
  buf += sizeof(rel_pkts);

  memcpy(&loss_rate, buf, sizeof(loss_rate));
  loss_rate = ntohl(loss_rate);
  buf += sizeof(loss_rate);
}

//============================================================================
uint16_t Rrm::GetFlowDstPort(Packet* rrm)
{
  uint32_t  dst_port_nbo  = 0;
  uint8_t*  buf           = rrm->GetBuffer(rrm->GetIpPayloadOffset());
  memcpy(&dst_port_nbo, buf, sizeof(dst_port_nbo));
  return dst_port_nbo;
}


//============================================================================
void Rrm::PrintRrm(Packet* rrm)
{
  iron::FourTuple four_tuple;

  GetFlowFourTuple(rrm, four_tuple);

  uint64_t  tot_bytes;
  uint64_t  rel_bytes;
  uint32_t  tot_pkts;
  uint32_t  rel_pkts;
  uint32_t  rate;

  GetReport(rrm, tot_bytes, tot_pkts, rel_bytes, rel_pkts, rate);

  LogD(kClassName, __func__,
       "RRM: Flow %s reports: %" PRIu64 "B released out of %" PRIu64 "B, %" PRIu32 
       " pkts released out of %" PRIu32 ", rate %" PRIu32 ".\n",
       four_tuple.ToString().c_str(),
       rel_bytes, tot_bytes,
       rel_pkts, tot_pkts,
       rate);
}

