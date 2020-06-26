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

#include "packet.h"
#include "log.h"
#include "udp_fec_trailer.h"
#include "unused.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>

#include <inttypes.h>
#include <netinet/udp.h>

using ::iron::LatencyClass;
using ::iron::Log;
using ::iron::Packet;
using ::iron::PacketOwner;
using ::iron::PacketType;
using ::iron::Time;
using ::std::string;

namespace
{
  const char* UNUSED(kClassName)       = "Packet";

  /// After how long with the same last seen location should we report a
  /// packet as "stuck"?
  const uint64_t kPacketStuckTimeUsecs = 20000000;
}

//============================================================================
Packet& Packet::operator=(const Packet& packet)
{
  type_                  = packet.type_;
  latency_               = packet.latency_;
  start_                 = packet.start_;
  length_                = packet.length_;
  virtual_length_        = packet.virtual_length_;
  metadata_length_       = packet.metadata_length_;
  recv_time_             = packet.recv_time_;
  recv_late_             = packet.recv_late_;
  origin_ts_ms_          = packet.origin_ts_ms_;
  time_to_go_usec_       = packet.time_to_go_usec_;
  order_time_            = packet.order_time_;
  bin_id_                = packet.bin_id_;
  send_packet_id_        = packet.send_packet_id_;
  track_ttg_             = packet.track_ttg_;
  time_to_go_valid_      = packet.time_to_go_valid_;
  send_packet_history_   = packet.send_packet_history_;
  memcpy(history_, packet.history_, sizeof(history_));
  send_packet_dst_vec_   = packet.send_packet_dst_vec_;
  dst_vec_               = packet.dst_vec_;
  memcpy((buffer_ + start_ - metadata_length_),
         (packet.buffer_ + packet.start_ - packet.metadata_length_),
         (metadata_length_ + length_));

  return *this;
}

//============================================================================
size_t Packet::ref_cnt()
{
  size_t  rv;

  // Normally, we would lock the mutex here. However, ref_cnt_ will ALWAYS be
  // either 1 or 2. Reading the single octet will be an atomic operation, so
  // we'll remove the mutex locks on the read here.
  // pthread_mutex_lock(&mutex_);
  rv = ref_cnt_;
  // pthread_mutex_unlock(&mutex_);

  return rv;
}

//============================================================================
void Packet::ShallowCopy()
{
  pthread_mutex_lock(&mutex_);
  ++ref_cnt_;
  pthread_mutex_unlock(&mutex_);
}

//============================================================================
bool Packet::SetLengthInBytes(size_t length)
{
  if (start_ + length > kMaxPacketSizeBytes)
  {
    LogW(kClassName, __func__, "Length of %zu bytes from the packet start "
         "(%zu) is greater than maximum length of %zu bytes.\n", length,
         start_, kMaxPacketSizeBytes);
    return false;
  }

  length_ = length;

  return true;
}

//============================================================================
bool Packet::SetMetadataHeaderLengthInBytes(size_t md_length)
{
  if (md_length > start_)
  {
    LogW(kClassName, __func__, "Metadata header length of %zu bytes is "
         "greater than the number of bytes available at the packet start "
         "(%zu).\n", md_length, start_);
    return false;
  }

  metadata_length_ = md_length;

  return true;
}

//============================================================================
size_t Packet::ParseVirtualLength() const
{
  if (type_ != ZOMBIE_PACKET || !kDefaultZombieCompression)
  {
    virtual_length_ = length_;
  }
  else
  {
    const uint8_t*  buf             = GetBuffer();
    uint32_t        virtual_length  = 0;
    memcpy(&virtual_length, buf + GetIpPayloadOffset(), sizeof(virtual_length));
    virtual_length_ = static_cast<size_t>(ntohl(virtual_length));
  }
  return virtual_length_;
}

//============================================================================
bool Packet::RemoveBytesFromBeginning(size_t length)
{
  // As an optimization, the requested number of bytes are NOT actually
  // removed from the internal buffer. Rather, the start_ and length_ class
  // variables are adjusted to reflect the requested smaller packet. This
  // enables us to efficiently "strip off" outer encapsulating headers
  // (without having to copy the buffer data).

  // If there are any metdata headers, then bytes cannot be removed from the
  // beginning of the internal buffer.
  if (metadata_length_ > 0)
  {
    LogW(kClassName, __func__, "Request to remove %zu bytes from a packet "
         "with metadata headers (%zu bytes).\n", length, metadata_length_);
    return false;
  }

  // Ensure that there are enough bytes in the internal buffer to support the
  // requested reduction.
  if (length > length_)
  {
    LogW(kClassName, __func__, "Request to remove %zu bytes from a packet "
         "with a length of %zu bytes.\n", length, length_);
    return false;
  }

  // Adjust the "start of" the packet and its length and set its type to
  // unknown as we don't know the type of the packet after removing bytes.
  start_  += length;
  length_ -= length;
  type_    = UNKNOWN_PACKET;
  latency_ = UNSET_LATENCY;

  return true;
}

//============================================================================
bool Packet::AddBytesToBeginning(size_t length)
{
  // As an optimization, the requested number of bytes are NOT actually added
  // to the internal buffer. Rather, the start_ and length_ class variables
  // are adjusted to reflect the requested larger packet.

  // If there are any metdata headers, then bytes cannot be added to the
  // beginning of the internal buffer.
  if (metadata_length_ > 0)
  {
    LogW(kClassName, __func__, "Request to add %zu bytes to a packet with "
         "metadata headers (%zu bytes).\n", length, metadata_length_);
    return false;
  }

  // Ensure that there are enough bytes in the internal buffer to support the
  // requested addition.
  if (start_ < length)
  {
    LogW(kClassName, __func__, "Request to add %zu bytes to a packet that "
         "has %zu bytes available.\n", length, start_);
    return false;
  }

  // Adjust the "start of" the packet and its length and set its type to
  // unknown as we don't know the type of the packet after adding bytes.
  start_  -= length;
  length_ += length;
  type_    = UNKNOWN_PACKET;
  latency_ = UNSET_LATENCY;

  return true;
}

//============================================================================
bool Packet::AppendBlockToEnd(uint8_t* data, size_t len)
{
  // Must have enough room.
  if ((start_ + length_ + len) > kMaxPacketSizeBytes)
  {
    LogW(kClassName, __func__, "Unable to append %zu bytes to packet with "
         "current size of %zu bytes, a start at offset %zu, and a maximum "
         "size of %zu bytes.\n", len, length_, start_, kMaxPacketSizeBytes);
    return false;
  }

  memcpy(buffer_+ start_ + length_, data, len);
  length_ += len;

  if (type_ == UNKNOWN_PACKET)
  {
    ParseType();
  }

  // Make sure to adjust the various embedded lengths for IPv4 packets.
  if (type_ == IPV4_PACKET)
  {
    struct iphdr*  ip = GetIpHdr();
    ip->tot_len = htons(ntohs(ip->tot_len) + len);

    uint8_t  protocol;
    if (!GetIpProtocol(protocol))
    {
      return false;
    }

    if (protocol == IPPROTO_UDP)
    {
      // Make sure the length of the packet is long enough to have an UDP
      // header.
      if (length_ >= (size_t)((ip->ihl * 4) + sizeof(struct udphdr)))
      {
        struct udphdr*  udp = reinterpret_cast<struct udphdr*>(
          buffer_ + start_ + (ip->ihl * 4));
        udp->len = htons(ntohs(udp->len) + len);
      }
      else
      {
        return false;
      }
    }
  }

  return true;
}

//============================================================================
bool Packet::RemoveBlockFromEnd(uint8_t* data, size_t len)
{
  // Must have enough data.
  if (length_ < len)
  {
    return false;
  }

  length_ -= len;
  memcpy(data, buffer_ + start_ + length_, len);

  // Make sure to adjust the various embedded lengths for IPv4 packets.
  if (type_ == UNKNOWN_PACKET)
  {
    ParseType();
  }

  if (type_ == IPV4_PACKET)
  {
    struct iphdr*  ip = GetIpHdr();
    if (!ip)
    {
      return false;
    }

    ip->tot_len       = htons(ntohs(ip->tot_len) - len);

    uint8_t  protocol;
    if (!GetIpProtocol(protocol))
    {
      return false;
    }

    if (protocol == IPPROTO_UDP)
    {
      // Make sure the length of the packet is long enough to have an UDP
      // header.
      if (length_ >= (size_t)((ip->ihl * 4) + sizeof(struct udphdr)))
      {
        struct udphdr*  udp = reinterpret_cast<struct udphdr*>(
          buffer_ + start_ + (ip->ihl * 4));
        udp->len = htons(ntohs(udp->len) - len);
      }
    }
  }

  return true;
}

//============================================================================
bool Packet::CopyBlockFromEnd(uint8_t* data, size_t len)
{
  // Must have enough data.
  if (length_ < len)
  {
    return false;
  }

  memcpy(data, buffer_ + start_ + length_ - len, len);

  return true;
}

//============================================================================
PacketType Packet::GetType() const
{
  if (type_ == UNKNOWN_PACKET)
  {
    ParseType();
  }

  return type_;
}

//============================================================================
int Packet::GetRawType() const
{
  int  raw_type = -1;

  if (length_ > 0)
  {
    uint8_t  first_byte = buffer_[start_];

    if ((first_byte >> 4) == 4)
    {
      raw_type = IPV4_PACKET;
    }
    else
    {
      raw_type = static_cast<int>(first_byte);
    }
  }

  return raw_type;
}

//============================================================================
int Packet::GetRawType(size_t offset) const
{
  int  raw_type = -1;

  if (length_ > offset)
  {
    uint8_t  first_byte = buffer_[start_ + offset];

    if ((first_byte >> 4) == 4)
    {
      raw_type = IPV4_PACKET;
    }
    else
    {
      raw_type = static_cast<int>(first_byte);
    }
  }

  return raw_type;
}

//============================================================================
int Packet::GetMetadataHeaderRawType() const
{
  int  raw_type = -1;

  if ((metadata_length_ + length_) > 0)
  {
    uint8_t  first_byte = buffer_[start_ - metadata_length_];

    if ((first_byte >> 4) == 4)
    {
      raw_type = IPV4_PACKET;
    }
    else
    {
      raw_type = static_cast<int>(first_byte);
    }
  }

  return raw_type;
}

//============================================================================
int Packet::GetMetadataHeaderRawType(size_t offset) const
{
  int  raw_type = -1;

  if ((metadata_length_ + length_) > offset)
  {
    uint8_t  first_byte = buffer_[start_ - metadata_length_ + offset];

    if ((first_byte >> 4) == 4)
    {
      raw_type = IPV4_PACKET;
    }
    else
    {
      raw_type = static_cast<int>(first_byte);
    }
  }

  return raw_type;
}

//============================================================================
struct udphdr* iron::Packet::GetUdpHdr()
{
  struct iphdr* ip_hdr  = GetIpHdr();

  if (!ip_hdr)
  {
    return NULL;
  }

  if (ip_hdr->protocol == IPPROTO_UDP)
  {
    return reinterpret_cast<struct udphdr*>(reinterpret_cast<uint8_t *>(ip_hdr)
                                            + ip_hdr->ihl * 4);
  }

  return NULL;
}

//============================================================================
const struct udphdr* iron::Packet::GetUdpHdr() const
{
  const struct iphdr* ip_hdr  = GetIpHdr();

  if (!ip_hdr)
  {
    return NULL;
  }

  if (ip_hdr->protocol == IPPROTO_UDP)
  {
    return reinterpret_cast<const struct udphdr*>(
      reinterpret_cast<const uint8_t *>(ip_hdr) + ip_hdr->ihl * 4);
  }

  return NULL;
}

//============================================================================
bool Packet::GetIpProtocol(uint8_t& protocol) const
{
  const struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  protocol = ip_hdr->protocol;

  return true;
}

//============================================================================
void Packet::SetIpSrcAddr(uint32_t saddr)
{
  struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    LogF(kClassName, __func__, "No IP header in packet, cannot set source "
         "address.\n");
  }

  ip_hdr->saddr = saddr;
}

//============================================================================
bool Packet::GetIpSrcAddr(uint32_t& saddr) const
{
  const struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  saddr = ip_hdr->saddr;

  return true;
}

//============================================================================
void Packet::SetIpDstAddr(uint32_t daddr)
{
  struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    LogF(kClassName, __func__, "No IP header in packet, cannot set "
         "destination address.\n");
  }

  ip_hdr->daddr = daddr;
}

//============================================================================
bool Packet::GetIpDstAddr(uint32_t& daddr) const
{
  const struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  daddr = ip_hdr->daddr;

  return true;
}

//============================================================================
bool Packet::SetIpDscp(uint8_t dscp)
{
  struct iphdr* ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  if (dscp >= (1 << 6))
  {
    LogI(kClassName, __func__, "Cannot set DSCP value %" PRIu8 " (exceeds "
         "6-bit field).\n", dscp);
    return false;
  }

  // Clear only the DSCP field (leave ECN intact).
  //
  // TOS field:
  // ---------------------------------
  // | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
  // ---------------------------------
  // |          DSCP         |  ECN  |
  // ---------------------------------
  ip_hdr->tos &= 0x03;

  ip_hdr->tos |= (dscp << 2);

  if (ip_hdr->check != 0)
  {
    if (UpdateIpChecksum() == 0)
    {
      return false;
    }
  }
  latency_  = UNSET_LATENCY;
  return true;
}

//============================================================================
bool Packet::GetIpDscp(uint8_t& dscp) const
{
  const struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  // Grab the DSCP bits (shift to remove ECN).
  // TOS field:
  // ---------------------------------
  // | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
  // ---------------------------------
  // |          DSCP         |  ECN  |
  // ---------------------------------
  dscp = ((ip_hdr->tos >> 2) & 0x3F);

  return true;
}

//============================================================================
LatencyClass Packet::GetLatencyClass() const
{
  if (latency_ != UNSET_LATENCY)
  {
    return latency_;
  }

  if (type_ == UNKNOWN_PACKET)
  {
    ParseType();
  }

  uint8_t  dscp = 0;

  // Use the packet's type to help determine the latency class.
  switch (type_)
  {
    case IPV4_PACKET:
      // For IPv4 packets, use the DSCP value to determine the latency class.
      if (!GetIpDscp(dscp))
      {
        LogE(kClassName, __func__, "Error: Could not get DSCP value out of "
             "packet, treat as normal latency.\n");
        latency_ = NORMAL_LATENCY;
        return latency_;
      }

      if (dscp == DSCP_EF)
      {
        latency_ = LOW_LATENCY;
      }
      else if (dscp == DSCP_TOLERANT)
      {
        latency_ = HIGH_LATENCY_RCVD;
      }
      else
      {
        latency_ = NORMAL_LATENCY;
      }
      break;

    case LSA_PACKET:
      // These are all system-level control packets with their own latency
      // class.
      latency_ = CONTROL_TRAFFIC_LATENCY;
      break;

    case ZOMBIE_PACKET:
      latency_ = HIGH_LATENCY_RCVD;
      break;

    case QLAM_PACKET:
      // Qlam packets should not be assigned a latency class.  They are sent
      // and processed outside of backpressure forwarding.  This falls through
      // to the default case.
    default:
      LogE(kClassName, __func__, "Error: Unexpected packet type 0x%02x, "
           "treating as normal latency.\n", type_);
      latency_ = NORMAL_LATENCY;
  }

  return latency_;
}

//============================================================================
bool Packet::GetIpLen(size_t& ip_len) const
{
  const struct iphdr*  ip = GetIpHdr();

  if (!ip)
  {
    return false;
  }

  ip_len = ntohs(ip->tot_len);

  return true;
}

//============================================================================
bool Packet::UpdateIpLen()
{
  struct iphdr*   ip_hdr = GetIpHdr();
  struct udphdr*  udp_hdr;

  // Must at least long enough for an IP header for this to make sense
  if ((length_ < (int)sizeof(struct iphdr)) || !ip_hdr)
  {
    return false;
  }

  ip_hdr->tot_len = htons((unsigned short)length_);

  if (ip_hdr->protocol == IPPROTO_UDP)
  {
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct udphdr)))
    {
      udp_hdr = reinterpret_cast<struct udphdr*>(buffer_ + start_ +
                                                 (ip_hdr->ihl * 4));
      udp_hdr->len = htons((unsigned short)(length_ - (ip_hdr->ihl * 4)));
    }
  }

  return true;
}

//============================================================================
bool Packet::UpdateIpLen(const size_t len)
{
  if (len < sizeof(struct iphdr))
  {
    return false;
  }

  length_ = len;

  return UpdateIpLen();
}

//============================================================================
bool Packet::TrimIpLen(const size_t len)
{
  // Need at least "len" bytes
  if (length_ < len)
  {
    return false;
  }

  length_ -= len;

  return UpdateIpLen();
}

//============================================================================
size_t Packet::GetIpPayloadOffset() const
{
  // Need at least an IP header to go further.
  if (length_ < sizeof(struct iphdr))
  {
    return length_;
  }

  const struct iphdr*  ip_hdr =
    reinterpret_cast<const struct iphdr*>(buffer_ + start_);

  uint8_t  protocol = 0;
  if (!GetIpProtocol(protocol))
  {
    return length_;
  }

  if (protocol == IPPROTO_TCP)
  {
    // Need at least a TCP header to go further.
    if (length_ < (size_t)((ip_hdr->ihl * 4) + sizeof(struct tcphdr)))
    {
      return length_;
    }

    const struct tcphdr*  tcp_hdr =
      reinterpret_cast<const struct tcphdr*>(buffer_ + start_ +
                                             (ip_hdr->ihl * 4));
    return ((ip_hdr->ihl * 4) + (tcp_hdr->doff * 4));
  }
  else if (protocol == IPPROTO_UDP)
  {
    // Need at least a UDP header to go further.
    if (length_ < (size_t)((ip_hdr->ihl * 4) + sizeof(struct udphdr)))
    {
      return length_;
    }

    return ((ip_hdr->ihl * 4) + sizeof(struct udphdr));
  }
  else if (protocol == IPPROTO_ESP)
  {
    // For ESP packets, everything beyond the IP header is considered data.
    return (ip_hdr->ihl * 4);
  }
  else
  {
    // We have an IP packet with no transport layer header. Payload starts
    // after the header.
    return (ip_hdr->ihl * 4);
  }
}

//============================================================================
size_t Packet::GetIpPayloadLengthInBytes() const
{
  return length_ - GetIpPayloadOffset();
}

//============================================================================
struct tcphdr* iron::Packet::GetTcpHdr()
{
  struct iphdr*  ip_hdr = GetIpHdr();

  if ((ip_hdr == NULL) || (ip_hdr->protocol != IPPROTO_TCP))
  {
    return NULL;
  }

  return reinterpret_cast<struct tcphdr*>(buffer_ + start_ +
                                          (ip_hdr->ihl * 4));
}

//============================================================================
const struct tcphdr* iron::Packet::GetTcpHdr() const
{
  const struct iphdr*  ip_hdr = GetIpHdr();

  if ((ip_hdr == NULL) || (ip_hdr->protocol != IPPROTO_TCP))
  {
    return NULL;
  }

  return reinterpret_cast<const struct tcphdr*>(buffer_ + start_ +
                                                (ip_hdr->ihl * 4));
}

//============================================================================
bool Packet::GetSrcPort(uint16_t& sport) const
{
  const struct iphdr*   ip_hdr = GetIpHdr();
  const struct tcphdr*  tcp_hdr;
  const struct udphdr*  udp_hdr;

  // Need at least an IP header.
  if (!ip_hdr)
  {
    return false;
  }

  if (ip_hdr->protocol == IPPROTO_TCP)
  {
    // Make sure the length of the packet is long enough to have an TCP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct tcphdr)))
    {
      tcp_hdr = reinterpret_cast<const struct tcphdr*>(buffer_ + start_ +
                                                       (ip_hdr->ihl * 4));
      sport = tcp_hdr->source;
    }
    else
    {
      return false;
    }
  }
  else if (ip_hdr->protocol == IPPROTO_UDP)
  {
    // Make sure the length of the packet is long enough to have an UDP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct udphdr)))
    {
      udp_hdr = reinterpret_cast<const struct udphdr*>(buffer_ + start_ +
                                                       (ip_hdr->ihl * 4));
      sport = udp_hdr->source;
    }
    else
    {
      return false;
    }
  }
  else if (ip_hdr->protocol == IPPROTO_ESP)
  {
    // ESP packets do not have ports, 0 is assigned.
    sport = 0;
  }
  else
  {
    return false;
  }

  return true;
}

//============================================================================
bool Packet::SetSrcPort(uint16_t sport_nbo)
{
  struct iphdr*  ip_hdr = GetIpHdr();

  // Need at least an IP header to continue.
  if (!ip_hdr)
  {
    return false;
  }

  if (ip_hdr->protocol == IPPROTO_TCP)
  {
    // Make sure the length of the packet is long enough to have an TCP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct tcphdr)))
    {
      struct tcphdr*  tcp_hdr =
        reinterpret_cast<struct tcphdr*>(buffer_ + start_ +
                                         (ip_hdr->ihl * 4));

      tcp_hdr->source = sport_nbo;
    }
    else
    {
      return false;
    }
  }
  else if (ip_hdr->protocol == IPPROTO_UDP)
  {
    // Make sure the length of the packet is long enough to have an UDP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct udphdr)))
    {
      struct udphdr*  udp_hdr =
        reinterpret_cast<struct udphdr*>(buffer_ + start_ +
                                         (ip_hdr->ihl * 4));

      udp_hdr->source = sport_nbo;
    }
    else
    {
      return false;
    }
  }
  else
  {
    LogF(kClassName, __func__, "Protocol %d is not supported.\n",
         (int)(ip_hdr->protocol));

    return false;
  }

  return true;
}

//============================================================================
bool Packet::GetDstPort(uint16_t& dport_nbo) const
{
  const struct iphdr*  ip_hdr = GetIpHdr();

  // Need at least an IP header to continue.
  if (!ip_hdr)
  {
    return false;
  }

  if (ip_hdr->protocol == IPPROTO_TCP)
  {
    // Make sure the length of the packet is long enough to have an TCP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct tcphdr)))
    {
      const struct tcphdr*  tcp_hdr =
        reinterpret_cast<const struct tcphdr*>(buffer_ + start_ +
                                               (ip_hdr->ihl * 4));

      dport_nbo = tcp_hdr->dest;
    }
    else
    {
      return false;
    }
  }
  else if (ip_hdr->protocol == IPPROTO_UDP)
  {
    // Make sure the length of the packet is long enough to have an UDP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct udphdr)))
    {
      const struct udphdr*  udp_hdr =
        reinterpret_cast<const struct udphdr*>(buffer_ + start_ +
                                               (ip_hdr->ihl * 4));

      dport_nbo = udp_hdr->dest;
    }
    else
    {
      return false;
    }
  }
  else if (ip_hdr->protocol == IPPROTO_ESP)
  {
    // ESP packets do not have ports, 0 is assigned.
    dport_nbo = 0;
  }
  else
  {
    // Not a TCP, UDP or ESP packet.
    return false;
  }

  return true;
}

//============================================================================
bool Packet::SetDstPort(uint16_t dport_nbo)
{
  struct iphdr*   ip_hdr = GetIpHdr();

  // Need at least an IP header to continue.
  if (!ip_hdr)
  {
    return false;
  }

  if (ip_hdr->protocol == IPPROTO_TCP)
  {
    // Make sure the length of the packet is long enough to have an TCP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct tcphdr)))
    {
      struct tcphdr*  tcp_hdr =
        reinterpret_cast<struct tcphdr*>(buffer_ + start_ +
                                         (ip_hdr->ihl * 4));

      tcp_hdr->dest = dport_nbo;
    }
    else
    {
      return false;
    }
  }
  else if (ip_hdr->protocol == IPPROTO_UDP)
  {
    // Make sure the length of the packet is long enough to have an UDP
    // header.
    if (length_ >= (size_t)((ip_hdr->ihl * 4) + sizeof(struct udphdr)))
    {
      struct udphdr*  udp_hdr =
        reinterpret_cast<struct udphdr*>(buffer_ + start_ +
                                         (ip_hdr->ihl * 4));

      udp_hdr->dest = dport_nbo;
    }
    else
    {
      return false;
    }
  }
  else
  {
    // Not a TCP or UDP packet.
    return false;
  }

  return true;
}

//============================================================================
bool Packet::UpdateChecksums()
{
  if (UpdateTransportChecksum() == 0)
  {
    return false;
  }

  if (UpdateIpChecksum() == 0)
  {
    return false;
  }

  return true;
}

//============================================================================
bool Packet::ZeroChecksums()
{
  unsigned  char*     hdr;
  struct    udphdr*   udp_hdr;
  struct    tcphdr*   tcp_hdr;

  struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  ip_hdr->check = 0;

  uint8_t  protocol;
  if (!GetIpProtocol(protocol))
  {
    return false;
  }

  hdr = (unsigned char *)(buffer_ + start_ + (ip_hdr->ihl * 4));

  if (protocol == IPPROTO_TCP)
  {
    tcp_hdr = reinterpret_cast<struct tcphdr*>(hdr);
    tcp_hdr->check = 0;
  }
  else if (protocol == IPPROTO_UDP)
  {
    udp_hdr = reinterpret_cast<struct udphdr*>(hdr);
    udp_hdr->check = 0;
  }
  else
  {
    return false;
  }

  return true;
}

//============================================================================
bool Packet::UpdateIpChecksum()
{
  struct iphdr*  ip_hdr = GetIpHdr();

  int sum   = 0;
  int nleft = sizeof(struct iphdr);

  unsigned short* w = (unsigned short *)ip_hdr;
  unsigned short odd_byte = 0;

  // Need at least an IP header.
  if (!ip_hdr)
  {
    return false;
  }

  // We absolutely must clear the checksum.
  ip_hdr->check = 0;

  // Our algorithm is simple. Using a 32 bit accumulator (sum), we add
  // sequential 16 bit words to it, and at the end, fold back all the carry
  // bits from the top 16 bits into the lower 16 bits.
  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }

  // Mop up an odd byte, if necessary.
  if (nleft == 1)
  {
    *(unsigned char *)(&odd_byte) = *(unsigned char *)w;
    sum += odd_byte;
  }

  // Add back carry outs from top 16 bits to low 16 bits.
  sum  = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
  sum += (sum >> 16);                  // add carry

  ip_hdr->check = (unsigned short)~sum;

  return true;
}

//============================================================================
bool Packet::UpdateTransportChecksum()
{
  struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  uint8_t  protocol;
  if (!GetIpProtocol(protocol))
  {
    return false;
  }

  size_t    len  = length_ - (ip_hdr->ihl * 4);
  uint16_t  csum = 0;
  if (!ComputeTransportChecksum(len, csum))
  {
    return false;
  }

  // Insert the csum into the header. Note: csum is already 1s complement.
  if (protocol == IPPROTO_TCP)
  {
    struct tcphdr*  tcp_hdr = reinterpret_cast<struct tcphdr*>(
      (buffer_ + start_ + (ip_hdr->ihl * 4)));
    tcp_hdr->check = ((unsigned short)(csum));
  }
  else if (protocol == IPPROTO_UDP)
  {
    struct udphdr*  udp_hdr = reinterpret_cast<struct udphdr*>(
      (buffer_ + start_ + (ip_hdr->ihl * 4)));
    udp_hdr->check = ((unsigned short)(csum));
  }
  else
  {
    return false;
  }

  return true;
}

//============================================================================
bool Packet::ComputeTransportChecksum(size_t len, uint16_t& csum)
{
  struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  unsigned char*  hdr;
  struct udphdr*  udp_hdr;
  struct tcphdr*  tcp_hdr;

  uint32_t  src_addr;
  uint32_t  dst_addr;

  if (!GetIpSrcAddr(src_addr))
  {
    return false;
  }

  if (!GetIpDstAddr(dst_addr))
  {
    return false;
  }

  uint8_t  protocol;
  if (!GetIpProtocol(protocol))
  {
    return false;
  }

  hdr = (unsigned char *)(buffer_ + start_ + (ip_hdr->ihl * 4));

  if (protocol == IPPROTO_TCP)
  {
    tcp_hdr = reinterpret_cast<struct tcphdr*>(hdr);
    tcp_hdr->check = 0;
  }
  else if (protocol == IPPROTO_UDP)
  {
    udp_hdr = reinterpret_cast<struct udphdr*>(hdr);
    udp_hdr->check = 0;
  }
  else if (protocol == IPPROTO_ESP)
  {
    // There are no transport checksums for ESP packets.
    return true;
  }
  else
  {
    return false;
  }

  // Compute the transport psuedo header checksum. Do not actually assemble
  // the psuedo header in memory, just add in the fields required. These are:
  //
  //    0      7 8     15 16    23 24    31
  //   +--------+--------+--------+--------+
  //   |          source address           |
  //   +--------+--------+--------+--------+
  //   |        destination address        |
  //   +--------+--------+--------+--------+
  //   |  zero  |protocol|     length      |
  //   +--------+--------+--------+--------+

  uint64_t  sum = 0;

  // The following four quantities will not generate an overflow so no
  // roll-over handling is required.
  sum += src_addr;
  sum += dst_addr;
  sum += htons((unsigned short)protocol);
  sum += htons((unsigned short)len);

  uint64_t*  b    = reinterpret_cast<uint64_t *>(hdr);
  uint32_t   size = len;

  // Main loop - 8 bytes at a time
  while (size >= sizeof(uint64_t))
  {
    uint64_t  s = *b++;
    sum += s;
    if (sum < s)
    {
      sum++;
    }
    size -= sizeof(uint64_t);
  }

  // Handle tails less than 8-bytes long
  uint8_t*  bb = (uint8_t*) b;

  if (size & 4)
  {
    uint32_t  s = *reinterpret_cast<uint32_t *>(bb);
    sum += s;
    if (sum < s)
    {
      sum++;
    }
    bb += 4;
  }

  if (size & 2)
  {
    uint16_t  s = *reinterpret_cast<int16_t *>(bb);
    sum += s;
    if (sum < s)
    {
      sum++;
    }
    bb += 2;
  }

  if (size & 1)
  {
    uint8_t  s = *(uint8_t *)bb;
    sum += s;
    if (sum < s)
    {
      sum++;
    }
  }

  // Fold down to 16 bits.
  uint32_t  t1;
  uint32_t  t2;

  t1  = sum;
  t2  = sum >> 32;
  t1 += t2;

  if (t1 < t2)
  {
    t1++;
  }

  uint16_t  t3;

  t3    = t1;
  csum  = t1 >> 16;
  csum += t3;

  if (csum < t3)
  {
    csum++;
  }

  csum = ~csum;

  return true;
}

//============================================================================
bool Packet::GetFiveTuple(uint32_t& saddr, uint32_t& daddr,
                          uint16_t& sport, uint16_t& dport,
                          uint32_t& proto) const
{
  // Need at least an IP header to continue.
  if (length_ < sizeof(struct iphdr))
  {
    return false;
  }

  // Get the IP header.
  const struct iphdr*  ip_hdr = GetIpHdr();

  if (!ip_hdr)
  {
    return false;
  }

  if (ip_hdr->protocol == IPPROTO_TCP)
  {
    if (length_ < (ip_hdr->ihl * 4) + sizeof(struct tcphdr))
    {
      return false;
    }

    const struct tcphdr*  tcp_hdr =
      reinterpret_cast<const struct tcphdr*>(&buffer_[start_ +
                                                      (ip_hdr->ihl * 4)]);

    sport = tcp_hdr->source;
    dport = tcp_hdr->dest;
  }
  else if (ip_hdr->protocol == IPPROTO_UDP)
  {
    if (length_ < (ip_hdr->ihl * 4) + sizeof(struct udphdr))
    {
      return false;
    }

    const struct udphdr*  udp_hdr =
      reinterpret_cast<const struct udphdr*>(&buffer_[start_ +
                                                      (ip_hdr->ihl * 4)]);

    sport = udp_hdr->source;
    dport = udp_hdr->dest;
  }
  else if (ip_hdr->protocol == IPPROTO_ESP)
  {
    // There are no port numbers for ESP traffic so they are assigned 0s.
    sport = 0;
    dport = 0;
  }
  else
  {
    // Not TCP, UDP or ESP.
    return false;
  }

  saddr = ip_hdr->saddr;
  daddr = ip_hdr->daddr;
  proto = ip_hdr->protocol;

  return true;
}

//============================================================================
Time Packet::GetTimeToGo() const
{
  return Time::FromUsec(static_cast<int64_t>(time_to_go_usec_));
}

//============================================================================
void Packet::SetTimeToGo(const Time& ttg, bool ttg_valid)
{
  int64_t ttg_us = ttg.GetTimeInUsec();
  if (ttg_us >= std::numeric_limits<int32_t>::max())
  {
    time_to_go_usec_ = kUnsetTimeToGo;
    time_to_go_valid_ = false;
  }
  else
  {
    time_to_go_usec_ = ttg_us;
    time_to_go_valid_ = ttg_valid;
  }
}

//============================================================================
void Packet::UpdateTimeToGo()
{
  SetTimeToGo(GetTimeToGo() - (Time::Now() - recv_time_), time_to_go_valid_);
}

//============================================================================
bool Packet::HasExpired() const
{
  if (!time_to_go_valid_)
  {
    return false;
  }
  return (GetTimeToGo() - (Time::Now() - recv_time_) < Time(0));
}

//============================================================================
bool Packet::CanBeDeliveredInTime(Time ttr) const
{
  if (!time_to_go_valid_)
  {
    return true;
  }

  Time  ttg = GetTimeToGo();

  Time now       = Time::Now();
  Time hold_time = (now - recv_time_);
  Time remaining = ttg - hold_time;
  if (remaining < Time(0))
  {
    LogD(kClassName, __func__,
         "Packet held too long: original ttg %s, hold time %s.\n",
         ttg.ToString().c_str(), hold_time.ToString().c_str());
    return false;
  }

  if (remaining >= ttr)
  {
    return true;
  }

  LogD(kClassName, __func__,
       "Insufficient time remaining: original ttg %s, remaining %s,"
       " path ttr %s.\n",
       ttg.ToString().c_str(), remaining.ToString().c_str(),
       ttr.ToString().c_str());

  return false;
}

//============================================================================
bool Packet::GetGroupId(uint32_t& group_id) const
{
  uint8_t  proto;
  if (!GetIpProtocol(proto))
  {
    return false;
  }

  // The group_id is in the FecTrailer, which is attached to UDP and ESP
  // packets only.
  if ((proto == IPPROTO_UDP) || (proto == IPPROTO_ESP))
  {
    const FECControlTrailer*  fec_trlr =
      reinterpret_cast<const FECControlTrailer*>
      (GetBuffer(GetLengthInBytes() - sizeof(FECControlTrailer)));

    group_id = fec_trlr->get_group_id();

    return true;
  }

  group_id = 0;

  return false;
}

//============================================================================
bool Packet::GetSlotId(uint32_t& slot_id) const
{
  uint8_t  proto;
  if (!GetIpProtocol(proto))
  {
    return false;
  }

  // The SlotId is in the FecTrailer, which is attached to UDP and ESP
  // packets only.
  if ((proto == IPPROTO_UDP) || (proto == IPPROTO_ESP))
  {
    const FECControlTrailer*  fec_trlr =
      reinterpret_cast<const FECControlTrailer*>
      (GetBuffer(GetLengthInBytes() - sizeof(FECControlTrailer)));

    slot_id = fec_trlr->get_slot_id();

    return true;
  }

  slot_id = 0;

  return false;
}

//============================================================================
bool Packet::GetFecSeqNum(uint32_t& seq_num) const
{
  uint8_t  proto;
  if (!GetIpProtocol(proto))
  {
    return false;
  }

  // The Sequence Number is in the FecTrailer, which is attached to UDP and ESP
  // packets only.
  if ((proto == IPPROTO_UDP) || (proto == IPPROTO_ESP))
  {
    const FECControlTrailer*  fec_trlr =
      reinterpret_cast<const FECControlTrailer*>
      (GetBuffer(GetLengthInBytes() - sizeof(FECControlTrailer)));

    seq_num = fec_trlr->seq_number;

    return true;
  }

  seq_num = 0;

  return false;
}

//============================================================================
uint32_t Packet::GetMgenSeqNum() const
{
  size_t size = GetIpPayloadOffset();

  const struct MgenHdr*  mgen_hdr =
    reinterpret_cast<const struct MgenHdr*>(buffer_ + start_ + size);

  return ntohl(mgen_hdr->sequenceNumber);
}

//============================================================================
bool Packet::PopulateBroadcastPacket(PacketType type,
                                     BinId src_bin,
                                     uint16_t seq_num_hbo)
{
  if (length_ > 0)
  {
    LogF(kClassName, __func__,
         "Attempting to overwrite an existing packet.\n");
  }

  // Broadcast packet looks like:
  // 1 byte type
  // 1 byte source bin id
  // 2 bytes sequence number
  // control data (type dependent, filled in elsewhere)
  size_t needed_len = 1 + sizeof(src_bin) + sizeof(seq_num_hbo);

  // Must have enough room.
  if (start_ + needed_len > kMaxPacketSizeBytes)
  {
    LogW(kClassName, __func__, "Unable to append %zu bytes to packet with "
         "start offset %zu and a maximum size of %zu bytes.\n",
         needed_len, start_, kMaxPacketSizeBytes);
    return false;
  }

  size_t idx = 0;
  buffer_[start_ + idx] = static_cast<uint8_t>(type);
  ++idx;
  buffer_[start_ + idx] = src_bin;
  ++idx;
  uint16_t seq_num_nbo = htons(seq_num_hbo);
  memcpy(buffer_ + start_ + idx, &seq_num_nbo, sizeof(seq_num_nbo));
  length_ += needed_len;

  // We've now written the type. Set it up in the packet object.
  ParseType();
  return true;
}

//============================================================================
bool Packet::ParseBroadcastPacket(BinId& src_bin,
                                  uint16_t& seq_num_hbo,
                                  const uint8_t** data,
                                  size_t& data_len)
{
  size_t expected_len = sizeof(uint8_t) + sizeof(BinId) + sizeof(seq_num_hbo);

  if (length_ < expected_len)
  {
    LogW(kClassName, __func__,
         "Packet isn't long enough for a broadcast packet. (Length is %zu).",
         length_);
    return false;
  }

  // Broadcast packet looks like:
  // 1 byte type
  // 1 byte source bin id
  // 2 bytes sequence number
  // control data (type dependent)

  ParseType();
  size_t idx = 1; // start after type
  src_bin = buffer_[start_ + idx];
  ++idx;
  uint16_t seq_num_nbo = 0;
  memcpy(&seq_num_nbo, buffer_ + start_ + idx, sizeof(seq_num_nbo));
  seq_num_hbo = ntohs(seq_num_nbo);

  // data starts after the type, src_bin and seq num
  *data = buffer_ + start_ + expected_len;
  data_len = length_ - expected_len;
  return true;
}

//============================================================================
void Packet::DumpIpHdr() const
{
  const struct iphdr* ip_hdr  = GetIpHdr();

  if (!ip_hdr)
  {
    LogD(kClassName, __func__, "Not an IP packet.\n");
    return;
  }

  LogD(kClassName, __func__,
       "IP: ver=%d ihl=%d tos=%d len=%d id=%d off=%d "
       "ttl=%d proto=%d chk=%x saddr=%x daddr=%x\n",
       static_cast<int>(ip_hdr->version),
       static_cast<int>(ip_hdr->ihl),
       static_cast<int>(ip_hdr->tos),
       static_cast<int>(ntohs(ip_hdr->tot_len)),
       static_cast<int>(ntohs(ip_hdr->id)),
       static_cast<int>(ntohs(ip_hdr->frag_off)),
       static_cast<int>(ip_hdr->ttl),
       static_cast<int>(ip_hdr->protocol),
       static_cast<unsigned int>(ntohs(ip_hdr->check)),
       static_cast<unsigned int>(ntohl(ip_hdr->saddr)),
       static_cast<unsigned int>(ntohl(ip_hdr->daddr)));
}

//============================================================================
void Packet::DumpUdpHdr() const
{
  const struct udphdr*  udp_hdr = GetUdpHdr();

  if (!udp_hdr)
  {
    LogD(kClassName, __func__, "Not a UDP packet.\n");
    return;
  }

  LogD(kClassName, __func__,
       "UDP: sport=%d dport=%d len=%d chk=%x\n",
       static_cast<int>(ntohs(udp_hdr->source)),
       static_cast<int>(ntohs(udp_hdr->dest)),
       static_cast<int>(ntohs(udp_hdr->len)),
       static_cast<unsigned int>(ntohs(udp_hdr->check)));
}

//============================================================================
string Packet::ToString() const
{
  char  str[150];

  snprintf(str, sizeof(str) - 1, "Packet length: (phy: %zuB, virt: %zuB) "
           "maximum length: %zuB, TTG = %" PRIu32 "us time of reception = %s",
           length_, virtual_length_, kMaxPacketSizeBytes,
           time_to_go_usec_, recv_time_.ToString().c_str());

  return str;
}

//============================================================================
Packet::~Packet()
{
  pthread_mutex_destroy(&mutex_);
}

//============================================================================
void Packet::Initialize(PktMemIndex index)
{
  type_                     = UNKNOWN_PACKET;
  latency_                  = UNSET_LATENCY;
  start_                    = kDefaultPacketStartBytes;
  length_                   = 0;
  virtual_length_           = 0;
  metadata_length_          = 0;
  mem_index_                = index;
  ref_cnt_                  = 1;
  recv_time_.Zero();
  recv_late_                = false;
  bin_id_                   = 0;
  packet_id_                = 0;
  send_packet_id_           = false;
  origin_ts_ms_             = kUnsetOriginTs;
  time_to_go_usec_          = kUnsetTimeToGo;
  order_time_               = Time(0);
  time_to_go_valid_         = false;
  track_ttg_                = false;
  send_packet_history_      = false;
  send_packet_dst_vec_      = false;
  dst_vec_                  = 0;
  memset(history_, 0, sizeof(history_));
#ifdef PACKET_TRACKING
  last_movement_time_usecs_ = 0;
  memset(last_location_, 0, 4 * sizeof(last_location_[0]));
#endif // PACKET_TRACKING
  memset(buffer_, 0, sizeof(buffer_));

  // Initialize the mutex.
  pthread_mutexattr_init(&mutex_attr_);
  pthread_mutexattr_setpshared(&mutex_attr_, PTHREAD_PROCESS_SHARED);
  if (pthread_mutex_init(&mutex_, &mutex_attr_) != 0)
  {
    LogF(kClassName, __func__, "pthread_mutex_init error: %s.\n",
         strerror(errno));
  }
}

//============================================================================
void Packet::Reset()
{
  type_                  = UNKNOWN_PACKET;
  latency_               = UNSET_LATENCY;
  start_                 = kDefaultPacketStartBytes;
  length_                = 0;
  virtual_length_        = 0;
  metadata_length_       = 0;
  ref_cnt_               = 1;
  recv_late_             = false;
  bin_id_                = 0;
  packet_id_             = 0;
  send_packet_id_        = false;
  origin_ts_ms_          = kUnsetOriginTs;
  time_to_go_usec_       = kUnsetTimeToGo;
  order_time_            = Time(0);
  track_ttg_             = false;
  time_to_go_valid_      = false;
  send_packet_history_   = false;
  send_packet_dst_vec_   = false;
  dst_vec_               = 0;
  ClearPacketHistory();

  // Do not zero the shared memory index.
}

//============================================================================
size_t Packet::DecrementRefCnt()
{
  size_t  rv;

  pthread_mutex_lock(&mutex_);
  --ref_cnt_;
  rv = ref_cnt_;
  pthread_mutex_unlock(&mutex_);

  return rv;
}

//============================================================================
void Packet::ParseType() const
{
  if (length_ == 0)
  {
    return;
  }

  // First, we'll check if this is an IPv4 packet. To do this we'll only
  // examine the 4 high order bits of the first byte, as these are the bits
  // that are set in the IP header structure.
  //
  // If not an IPv4 packet, we'll check the value of the entire first byte,
  // searching for a known packet type.
  if ((buffer_[start_] >> 4) == 4)
  {
    type_ = IPV4_PACKET;

    uint8_t dscp  = 0;
    GetIpDscp(dscp);

    if (dscp == DSCP_TOLERANT)
    {
      type_ = ZOMBIE_PACKET;
      ParseVirtualLength();
    }
  }
  else if (buffer_[start_] == QLAM_PACKET)
  {
    type_ = QLAM_PACKET;
  }
  else if (buffer_[start_] == LSA_PACKET)
  {
    type_ = LSA_PACKET;
  }
}

//============================================================================
void Packet::MakeZombie(LatencyClass lat_class)
{
  SetIpDscp(DSCP_TOLERANT);
  SetTimeToGo(Time::FromUsec(static_cast<int64_t>(iron::kUnsetTimeToGo)));
  type_ = ZOMBIE_PACKET;
  latency_ = lat_class;
  send_packet_history_  = false;
  memset(history_, 0, sizeof(history_));
}

//============================================================================
string Packet::GetPacketMetadataString()
{
  std::stringstream str;
  str << "BinId: <" << static_cast<unsigned int>(bin_id_)
      << ">, PacketId: <" << packet_id_ << ">";
  return str.str();
}

//============================================================================
std::string iron::Packet::ToHexString() const
{
  return ToHexString(length_);
}

//============================================================================
std::string iron::Packet::ToHexString(uint32_t limit) const
{
  std::stringstream str;

  char tmpstr[1024];
  char buff[17];

  const uint8_t *pc = buffer_ + start_;
  size_t i;

  if (limit > length_)
  {
    limit = length_;
  }

  // Process every byte in the data.
  for (i = 0; i < limit; i++)
  {
    // Multiple of 16 means new line (with line offset).

    if ((i % 16) == 0)
    {
      // Just don't print ASCII for the zeroth line.
      if (i != 0)
      {
	sprintf (&tmpstr[0],"  %s\n", buff);
	str << tmpstr;
      }

      // Output the offset.
      sprintf (&tmpstr[0],"  %04x ", (uint32_t)i);
      str << tmpstr;
    }

    // Now the hex code for the specific character.
    sprintf (&tmpstr[0]," %02x", pc[i]);
    str << tmpstr;

    // And store a printable ASCII character for later.
    if ((pc[i] < 0x20) || (pc[i] > 0x7e))
    {
      buff[i % 16] = '.';
    }
    else
    {
      buff[i % 16] = pc[i];
    }
    buff[(i % 16) + 1] = '\0';
  }

  // Pad out last line if not exactly 16 characters.
  while ((i % 16) != 0)
  {
    sprintf (&tmpstr[0],"   ");
    str <<tmpstr;
    i++;
  }

  // And print the final ASCII bit.
  sprintf (&tmpstr[0],"  %s", buff);
  str << tmpstr;

  return str.str();
}

#ifdef PACKET_TRACKING
//============================================================================
void Packet::NewPacketLocation(PacketOwner owner,
                               uint16_t new_location)
{
  LogD(kClassName, __func__, "Packet %" PRIu32 " was at locations: [%"
       PRIu16 ", %" PRIu16 ", %" PRIu16 "]. Owner %d moving to location %"
       PRIu16 ".\n", mem_index_, last_location_[1], last_location_[2],
       last_location_[3], owner, new_location);
  last_location_[owner] = new_location;
  last_movement_time_usecs_ = static_cast<uint64_t>(Time::GetNowInUsec());
}

//============================================================================
bool Packet::StuckCheck(uint16_t* stuck_at)
{
  uint64_t time_diff = (static_cast<uint64_t>(Time::GetNowInUsec()) -
                        last_movement_time_usecs_);
  if ((last_location_[1] != 0 ||
       last_location_[2] != 0 ||
       last_location_[3] != 0) &&
      time_diff > kPacketStuckTimeUsecs)
  {
    LogD(kClassName, __func__, "Packet id -%" PRIu32 "- owned by [%d, %d, "
         "%d] for %" PRIu64 " usec.\n", mem_index_, last_location_[1],
         last_location_[2], last_location_[3], time_diff);
    memcpy(stuck_at, last_location_, 4 * sizeof(uint16_t));
    return true;
  }
  return false;
}
#endif // PACKET_TRACKING

//============================================================================
bool Packet::IsGram() const
{
 uint16_t dport_nbo;
 if (!GetDstPort(dport_nbo))
 {
   return false;
 }
 uint32_t daddr_nbo;
 if (!GetIpDstAddr(daddr_nbo))
 {
   return false;
 }

 return ((dport_nbo == htons(kDefaultGramPort)) &&
         (daddr_nbo == kDefaultGramGrpAddr.address()));
}
