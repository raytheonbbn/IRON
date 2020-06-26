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

/// \brief Implementation of the IRON Zombie packet utility functions.
///
/// Provides static functions for creating Zombies and for turning existing
/// packets into Zombies.

#include "zombie.h"

#include "iron_constants.h"
#include "itime.h"
#include "log.h"
#include "packet.h"
#include "unused.h"

#include <cstring>
#include <netinet/ip.h>

using ::iron::Log;
using ::iron::Packet;
using ::iron::Zombie;

namespace
{
  // Class name for logging.
  const char* UNUSED(kClassName) = "Zombie";

  // IANA assigned protocol number for "any local network." Used in the IP
  // header's protocol field for a new zombie packet, since we don't need a
  // transport protocol.
  const uint8_t kZombieProtocolNum             = 63;
}

//============================================================================
void Zombie::ZombifyExistingPacket(Packet* pkt)
{
  pkt->MakeZombie(HIGH_LATENCY_EXP);

  if (kDefaultZombieCompression)
  {
    LogD(kClassName, __func__,
         "Creating compressed zombie with virtual length %zu\n",
         pkt->GetLengthInBytes());
    size_t    virtual_length  = pkt->GetLengthInBytes();
    uint32_t  virtual_size    = htonl(static_cast<uint32_t>(virtual_length));
    // Set the virtual length to the current real length.
    pkt->set_virtual_length(virtual_length);
    // Add it to the data portion.
    uint8_t*  buf             = pkt->GetBuffer();

    size_t    new_length      = pkt->GetIpPayloadOffset();
    memcpy(buf + new_length, &virtual_size, sizeof(virtual_size));
    new_length               += sizeof(virtual_size);

    pkt->SetLengthInBytes(new_length);
    pkt->UpdateIpLen();

    // NOTE: We do not move the FEC trailer since the packet will not be
    // passed up to the UDP proxy.
  }
}

//============================================================================
Packet* Zombie::CreateNewZombie(PacketPool& pkt_pool,
                                uint32_t& src_addr_nbo,
                                uint32_t& dst_addr_nbo,
                                size_t zombie_len_bytes,
                                LatencyClass lat_class)
{
  if (zombie_len_bytes > kMaxZombieLenBytes
      || zombie_len_bytes < kMinZombieLenBytes)
  {
    LogF(kClassName, __func__,
         "CreateNewZombie must be called with zombie_len_bytes (%zu) between "
         "kMinZombieLenBytes (%zu) and kMaxZombieLenBytes (%zu). "
         "LatencyClass is %s, dst_addr is %s.\n",
         zombie_len_bytes, kMinZombieLenBytes, kMaxZombieLenBytes,
         Ipv4Address(dst_addr_nbo).ToString().c_str());
    return NULL;
  }
  Packet* zombie = pkt_pool.Get(PACKET_NOW_TIMESTAMP);
  zombie->InitIpPacket();
  // MakeZombie encapsulates setting up the DSCP value, TTG, and packet type.
  zombie->MakeZombie(lat_class);
  struct iphdr* iphdr = zombie->GetIpHdr();
  iphdr->id       = htons(pkt_pool.GetNextIpId());
  iphdr->protocol = kZombieProtocolNum;
  iphdr->saddr    = src_addr_nbo;
  iphdr->daddr    = dst_addr_nbo;

  size_t length = zombie->GetLengthInBytes();

  if (kDefaultZombieCompression)
  {
    uint32_t virtual_size = htonl(static_cast<uint32_t>(zombie_len_bytes));
    zombie->set_virtual_length(zombie_len_bytes);

    // Add the virtual length to the packet data
    memcpy(zombie->GetBuffer(length), &virtual_size, sizeof(virtual_size));
    length += sizeof(virtual_size);
  }
  else if (zombie_len_bytes >= length)
  {
    // Set data to 0s to avoid any vulnerabilities from re-transmitting
    // leftover data from the last time this packet was used.
    // We know this will fit because zombie_len_bytes < kMaxZombieLenBytes.
    memset(zombie->GetBuffer(length), 0, zombie_len_bytes - length);
    length = zombie_len_bytes;
    zombie->set_virtual_length(zombie_len_bytes);
  }
  else
  {
    // We are trying to send a zombie smaller than the minimum size of a
    // packet when compression is disabled. This is going to cause accounting
    // issues, because we'll look at the size of the packet (length), which
    // may be smaller than the size of the zombie queue.
    LogE(kClassName, __func__, "Attempted to create a zombie of size %zu, "
         "which is smaller than the minimum packet size %zu. Returning NULL.\n",
         zombie_len_bytes, length);
    pkt_pool.Recycle(zombie);
    zombie = NULL;
    return zombie;
  }
  zombie->SetLengthInBytes(length);
  zombie->UpdateIpLen();
  zombie->UpdateIpChecksum();
  LogD(kClassName, __func__,
       "Created zombie with length %zu.\n", zombie->GetLengthInBytes());
  zombie->DumpIpHdr();
  return zombie;
}
