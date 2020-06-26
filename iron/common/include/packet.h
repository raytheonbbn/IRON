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
/// Provides the IRON software with a packet class.
///


#ifndef IRON_COMMON_PACKET_H
#define IRON_COMMON_PACKET_H

#include "iron_constants.h"
#include "iron_types.h"
#include "itime.h"
#include "log.h"
#include "string_utils.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string>

#include <cstring>
#include <sstream>

namespace iron
{
  /// The type stored in the array of memory indices.
  typedef uint32_t PktMemIndex;

  // The number of nodes to keep in the history vector.
  // This number should be a multiple of 4 - 1 and should be greater than 0.
  const uint8_t kNumNodesInHistory  = 11;

  /// The number of 4B words used to represent the history vector.
  ///     1,2,3 -> 1 x 4B
  ///   4,5,6,7 -> 2 x 4B
  /// 8,9,10,11 -> 3 x 4B
  const uint8_t kNumHistoryFields = (kNumNodesInHistory + 4) / 4;

  /// How big is the history field in bytes?
  ///     1,2,3 -> 3B
  ///   4,5,6,7 -> 7B
  /// 8,9,10,11 -> 11B
  const uint8_t kHistoryFieldSizeBytes  =
    (((kNumNodesInHistory / 4) + 1) * 4) - 1;

  /// Value of a history vector entry that is unused.
  const uint8_t  kHistoryEntryUnused = 255;

  /// Enumeration of the supported packet types.  Determined by the first byte
  /// in the buffer.
  ///
  /// All backpressure forwarder packet type values are one byte long, and are
  /// within the following hexadecimal range:
  ///
  ///   Range 0x10-0x1f (decimal 16-31)
  ///
  /// This leaves the following ranges for other components:
  ///
  ///   Range 0x00-0x0f (decimal 0-15) for SLIQ headers.
  ///   Range 0x20-0x2f (decimal 32-47) for SLIQ headers.
  ///   Range 0x30-0x3f (decimal 48-63) for CAT packets and headers.
  ///   Range 0x40-0x4f (decimal 64-79) for IPv4 packets.
  ///
  /// WARNING: Any changes to these header types must not conflict with the
  /// HeaderType definition in iron/sliq/src/sliq_framer.h and the
  /// CatHeaderType definition in iron/bpf/src/path_controller.h.
  enum PacketType
  {
    // BPF Queue Length Advertisement Message (QLAM) packets.
    QLAM_PACKET = 0x10,

    // TODO: The following two types cannot be forwarded by the BPF over
    // multiple hops like regular IPV4_PACKETs.

    // BPF Link State Advertisement (LSA) packets.
    LSA_PACKET = 0x13,

    // BPF Zombie packets.  Note that this value is NOT stored at the start of
    // the buffer.  These packets have a value of 0x4 in the most significant
    // 4-bits at the start of the buffer (since they have valid IPv4 headers),
    // and have a DSCP value of DSCP_TOLERANT.
    ZOMBIE_PACKET = 0x15,

    // IPv4 packets.  This value is merely a placeholder.  A value of 0x4 in
    // the most significant 4-bits at the start of the buffer indicates the
    // packet is an IPv4 packet.
    IPV4_PACKET = 0x40,

    UNKNOWN_PACKET = 0
  };

  /// Enumeration of IPv4 packet DSCP values we care about for IRON
  /// processing.
  typedef enum
  {
    DSCP_EF       = 46,
    DSCP_DEFAULT  = 0,
    DSCP_TOLERANT = 1,
  } DSCPSupportEnum;

  /// Enumeration of the packet latency classes for IRON processing.  Note
  /// that the order of the members controls the order that the BinQueueMgr
  /// dequeues packets for backpressure forwarding.
  enum LatencyClass
  {
    // NOTE: A change in this enum should be reflected in LatencyClass_Name
    //       below, IsZombie() and IsLatencySensitive().
    //       It may also need to be reflected in BinQueueMgr, IS_ZOMBIE_QUEUE.
    CRITICAL_LATENCY        = 0,
    CONTROL_TRAFFIC_LATENCY,
    LOW_LATENCY,
    HIGH_LATENCY_EXP,      // Zombies created from expired low latency pkts.
    HIGH_LATENCY_NPLB_LS,  // Zombies created by the LS NPLB algorithm.
    HIGH_LATENCY_ZLR_LS,   // ZLR-created zombies for latency sensitive packets.
    NORMAL_LATENCY,
    HIGH_LATENCY_RCVD,     // Received zombies.
    HIGH_LATENCY_NPLB,     // Zombies created by the NPLB algorithm.
    HIGH_LATENCY_ZLR,      // Zombies created by the ZLR algorithm.
    NUM_LATENCY_DEF,       // The number of latency classes supported.
    UNSET_LATENCY          // Used to indicate that we haven't yet determined
                           // and set the cached latency class for this
                           // packet.
  };

  /// The name of the traffic type.
  const ::std::string LatencyClass_Name[]  =
    {"critical", "control", "low-latency", "ZombieExp", "Zombie-NPLB-LS",
      "Zombie-ZLR-LS", "normal-latency", "ZombieRcvd",
     "ZombieNPLB", "ZombieZLR", "in-error", "unset latency"};

  /// Enumeration to indicate how the receive time in a packet should be set,
  /// if at all. This is used in the PacketPool::Get() method and the
  /// PacketPool::Clone() methods. PACKET_COPY_TIMESTAMP is only used when
  /// cloning packets.
  enum PacketRecvTimeMode
  {
    PACKET_NO_TIMESTAMP = 0,
    PACKET_NOW_TIMESTAMP = 1,
    PACKET_COPY_TIMESTAMP = 2
  };

  /// Enumeration used to store the current and previous owners of the packet
  /// to use for tracking packets through the system. Currently, these are at
  /// a process level.
  ///
  /// If additional values are added to this enum, then the last_location_
  /// variable must be updated to allow tracking location across more
  /// components.
  enum PacketOwner
  {
    PACKET_OWNER_NONE      = 0,
    PACKET_OWNER_UDP_PROXY = 1,
    PACKET_OWNER_TCP_PROXY = 2,
    PACKET_OWNER_BPF       = 3,
    NUM_PACKET_OWNERS      = 4
  };

  /// A class for the creation and manipulation of IRON packets. Currently, this
  /// class supports all of the packet types defined in the PacketType
  /// enumeration.
  class Packet
  {
    friend class PacketPoolHeap;
    friend class PacketPoolShm;

    public:

    struct MgenHdr
    {
      // This is the Mgen header for versions 0-4 (to best of documentation).
      // Set GetMgenMaxDecodableVersion() accordingly.
      //
      //   0                   1                   2                   3
      //   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //  |          messageSize          |    version    |    flags      |
      //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //  |                          mgenFlowId                           |
      //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //  |                        sequenceNumber                         |
      //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //  |                         txTimeSeconds                         |
      //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      //  |                      txTimeMicroseconds                       |
      //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      uint16_t  messageSize;
      uint8_t   version;
      uint8_t   flags;
      uint32_t  mgenFlowId;
      uint32_t  sequenceNumber;
      uint32_t  txTimeSeconds;
      uint32_t  txTimeMicroseconds;
    };

    /// \brief Assignment operator.
    ///
    /// \param  packet  The Packet to assign to this Packet.
    ///
    /// \return The Packet.
    Packet& operator=(const Packet& packet);

    /// \brief Get the reference count.
    ///
    /// \return The Packet's reference count.
    size_t ref_cnt();

    /// \brief Get a pointer to the internal Packet buffer.
    ///
    /// \return Pointer to the start of the internal Packet buffer.
    inline uint8_t* GetBuffer()
    {
      return (buffer_ + start_);
    }

    /// \brief Get a pointer to the internal Packet buffer.
    ///
    /// \return Pointer to the start of the internal Packet buffer.
    inline const uint8_t* GetBuffer() const
    {
      return (buffer_ + start_);
    }

    /// \brief Get a pointer to the Packet buffer at the specified offset.
    ///
    /// \param  offset  Offset at which to return the Packet buffer.
    ///
    /// \return Pointer to the internal Packet buffer at the specified
    ///         offset.
    inline uint8_t* GetBuffer(size_t offset)
    {
      return (buffer_ + start_ + offset);
    }

    /// \brief Get a pointer to the Packet buffer at the specified offset.
    ///
    /// \param  offset  Offset at which to return the Packet buffer.
    ///
    /// \return Pointer to the internal Packet buffer at the specified
    ///         offset.
    inline const uint8_t* GetBuffer(size_t offset) const
    {
      return (buffer_ + start_ + offset);
    }

    /// \brief Get a pointer to the internal Packet buffer starting at the
    /// metadata headers.
    ///
    /// \return Pointer to the start of the metadata headers in the internal
    ///         Packet buffer.
    inline uint8_t* GetMetadataHeaderBuffer()
    {
      return (buffer_ + (start_ - metadata_length_));
    }

    /// \brief Get a pointer to the internal Packet buffer starting at the
    /// metadata headers.
    ///
    /// \return Pointer to the start of the metadata headers in the internal
    ///         Packet buffer.
    inline const uint8_t* GetMetadataHeaderBuffer() const
    {
      return (buffer_ + (start_ - metadata_length_));
    }

    /// \brief Get a pointer to the Packet buffer at the specified offset
    /// starting at the metadata headers.
    ///
    /// \param  offset  Offset at which to return the Packet buffer.
    ///
    /// \return Pointer to the internal Packet buffer at the specified
    ///         offset starting at the metadata headers.
    inline uint8_t* GetMetadataHeaderBuffer(size_t offset)
    {
      return (buffer_ + (start_ - metadata_length_) + offset);
    }

    /// \brief Get a pointer to the Packet buffer at the specified offset
    /// starting at the metadata headers.
    ///
    /// \param  offset  Offset at which to return the Packet buffer.
    ///
    /// \return Pointer to the internal Packet buffer at the specified
    ///         offset starting at the metadata headers.
    inline const uint8_t* GetMetadataHeaderBuffer(size_t offset) const
    {
      return (buffer_ + (start_ - metadata_length_) + offset);
    }

    /// \brief Set the length of the Packet buffer, in bytes.
    ///
    /// \param  length  Length of the Packet buffer, in bytes.
    ///
    /// \return True if length of the Packet buffer is successfully set, false
    ///         otherwise.
    bool SetLengthInBytes(size_t length);

    /// \brief Sets the number of bytes in Packet metadata headers prepended
    /// to the beginning of the Packet's internal buffer.
    ///
    /// Note that this does not move the data that is already in the internal
    /// buffer or alter the internal start of the Packet data. Instead, it
    /// simply records that metadata headers were prepended to the start of
    /// the Packet.
    ///
    /// Once Packet metadata headers are recorded using this method, calls to
    /// RemoveBytesFromBeginning() or AddBytesToBeginning() will fail.
    ///
    /// \param  md_length  The number of bytes of metadata headers at the
    ///                    beginning of the Packet's buffer.
    ///
    /// \return True if the metadata header bytes are recorded successfully,
    ///         false otherwise.
    bool SetMetadataHeaderLengthInBytes(size_t md_length);

    /// \brief Set the virtual length of the Packet buffer, in bytes.
    ///
    /// \param  v_length  Virtual length of the packet buffer in bytes.
    inline void set_virtual_length(size_t v_length)
    {
      virtual_length_ = v_length;
    }

    /// \brief Get the length of the Packet, in bytes.
    ///
    /// Note that for packetless or compressed zombies, this is NOT the
    /// size represented by the zombie in the queues. This is the physical
    /// packet length, which could be much smaller.
    ///
    /// \return Length of the Packet buffer, in bytes.
    inline size_t GetLengthInBytes() const
    {
      return length_;
    }

    /// \brief Get length of the metadata headers prepended to the packet, in
    /// bytes.
    ///
    /// \return Length of the metadata headers, in bytes.
    inline size_t GetMetadataHeaderLengthInBytes() const
    {
      return metadata_length_;
    }

    /// Get the virtual length of the buffer, in bytes.
    ///
    /// return The virtual length of the packet buffer in bytes.
    inline size_t virtual_length() const
    {
      if (virtual_length_ == 0)
      {
        ParseVirtualLength();
      }
      return virtual_length_;
    }

    /// \brief Get the maximum theoretical size of a Packet, in bytes.
    ///
    /// This function is static because the maximum theoretical size of a
    /// packet may be useful to compute certain rates, sizes, etc. without
    /// having to allocate a packet.
    ///
    /// WARNING: The length returned does not take into account any internal
    /// buffer start offset for the Packet.  If the packet has a non-zero
    /// start offset and this number of bytes is written into the Packet, then
    /// the write will go off the end of the Packet's internal buffer!  Use
    /// GetMaxLengthInBytes() instead, which takes into account the start
    /// offset.
    ///
    /// \return The maximum theoretical size of a Packet in bytes.
    static inline size_t MaxPacketSizeInBytes()
    {
      return kMaxPacketSizeBytes;
    }

    /// \brief Get the current maximium Packet length, in bytes.
    ///
    /// This method takes into account the size of the internal buffer and the
    /// current start offset into the buffer.  The length returned is valid
    /// until the Packet object is modified by a call to
    /// RemoveBytesFromBeginning() or AddBytesToBeginning().
    ///
    /// \return The current maximum length for the Packet object.
    inline size_t GetMaxLengthInBytes() const
    {
      return (kMaxPacketSizeBytes - start_);
    }

    /// \brief Remove the specified number of bytes from the start of the
    /// Packet's internal buffer.
    ///
    /// Note that this does not move the data that is already in the internal
    /// buffer. Instead, it simply adjusts the start of the Packet and the
    /// length of the Packet, in bytes. This is generally used to remove
    /// encapsulating headers from the Packet.
    ///
    /// If the Packet has a non-zero metadata header length, then this method
    /// will fail.
    ///
    /// \param  length  The number of bytes to remove from the beginning of
    ///                 the Packet's buffer.
    ///
    /// \return True if the bytes are removed, false otherwise.
    bool RemoveBytesFromBeginning(size_t length);

    /// \brief Add the specified number of bytes to the start of the Packet's
    /// internal buffer.
    ///
    /// Note that this does not move the data that is already in the internal
    /// buffer. Instead, it simply adjusts the start of the Packet and the
    /// length of the Packet, in bytes.
    ///
    /// If the Packet has a non-zero metadata header length, then this method
    /// will fail.
    ///
    /// \param  length  The number of bytes to add to the beginning of the
    ///                 Packet's buffer.
    ///
    /// \return True if the bytes are added, false otherwise.
    bool AddBytesToBeginning(size_t length);

    /// \brief Append a block of data to the end of a Packet.
    ///
    /// \param  data  Buffer holding the data to append to the end of the
    ///               Packet.
    /// \param  len   Length of the data block to append.
    ///
    /// \return True if the block of data is successfully appended, false
    ///         otherwise.
    bool AppendBlockToEnd(uint8_t* data, size_t len);

    /// \brief Copy and remove a block of data from the end of the Packet.
    ///
    /// \param  data  Buffer to hold the data to be copied from the end of
    ///               the Packet.
    /// \param  len   Length of the data block to be copied.
    ///
    /// \return True if the block of data is copied and removed, false
    ///         otherwise.
    bool RemoveBlockFromEnd(uint8_t* data, size_t len);

    /// \brief Copy a block of data from the end of the Packet.
    ///
    /// \param  data  Buffer to hold the data to be copied from the end of
    ///               the Packet.
    /// \param  len   Length of the data block to be copied.
    ///
    /// \return True if the block of data is successfully copied, false
    ///         otherwise.
    bool CopyBlockFromEnd(uint8_t* data, size_t len);

    /// \brief Get the Packet's type.
    ///
    /// \return The Packet's type.
    PacketType GetType() const;

    /// \brief Get the Packet's raw type value.
    ///
    /// If the type value is for an IPv4 packet, then this method correctly
    /// returns IPV4_PACKET.  Otherwise, the raw value of the first byte is
    /// returned.
    ///
    /// \return The Packet's raw type value, or -1 if the packet is empty.
    int GetRawType() const;

    /// \brief Get the Packet's raw type value at a specified offset.
    ///
    /// If the type value is for an IPv4 packet, then this method correctly
    /// returns IPV4_PACKET.  Otherwise, the raw value of the first byte at
    /// the specified offset is returned.
    ///
    /// \param  offset  Offset at which to get the raw type value.
    ///
    /// \return The Packet's raw type value, or -1 if the packet is empty.
    int GetRawType(size_t offset) const;

    /// \brief Get the Packet's raw type value starting at the metadata
    /// headers.
    ///
    /// If the type value is for an IPv4 packet, then this method correctly
    /// returns IPV4_PACKET.  Otherwise, the raw value of the first byte is
    /// returned.
    ///
    /// \return The Packet's raw type value, or -1 if the packet is empty.
    int GetMetadataHeaderRawType() const;

    /// \brief Get the Packet's raw type value at a specified offset starting
    /// at the metadata headers.
    ///
    /// If the type value is for an IPv4 packet, then this method correctly
    /// returns IPV4_PACKET.  Otherwise, the raw value of the first byte at
    /// the specified offset is returned.
    ///
    /// \param  offset  Offset at which to get the raw type value.
    ///
    /// \return The Packet's raw type value, or -1 if the packet is empty.
    int GetMetadataHeaderRawType(size_t offset) const;

    /// \brief Returns true if and only if this packet has an IPv4 header.
    ///
    /// Determined based on the packet type.
    ///
    /// \return True if this packet has an IPv4 header.
    inline bool HasIpHeader() const
    {
      if (type_ == UNKNOWN_PACKET)
      {
        ParseType();
      }

      return ((type_ == IPV4_PACKET) || (type_ == ZOMBIE_PACKET));
    }

    /// Get a pointer to the Packet's IP header.
    ///
    /// \return Pointer to the Packet's IP header, or NULL if the Packet does
    ///         not have an IP header.
    inline struct iphdr* GetIpHdr()
    {
      if (type_ == UNKNOWN_PACKET)
      {
        ParseType();
      }

      if ((type_ == IPV4_PACKET) || (type_ == ZOMBIE_PACKET))
      {
        return reinterpret_cast<struct iphdr*>(buffer_ + start_);
      }

      return NULL;
    }

    /// Get a pointer to the Packet's IP header.
    ///
    /// \return Pointer to the Packet's IP header, or NULL if the Packet does
    ///         not have an IP header.
    inline const struct iphdr* GetIpHdr() const
    {
      if (type_ == UNKNOWN_PACKET)
      {
        ParseType();
      }

      if ((type_ == IPV4_PACKET) || (type_ == ZOMBIE_PACKET))
      {
        return reinterpret_cast<const struct iphdr*>(buffer_ + start_);
      }

      return NULL;
    }

    /// \brief  Get a pointer to the packet's UDP header.
    ///
    /// \return The pointer to the packet's UDP header, or NULL if the packet
    ///         does not have a UDP header.
    struct udphdr* GetUdpHdr();

    /// \brief  Get a pointer to the packet's UDP header.
    ///
    /// \return The pointer to the packet's UDP header, or NULL if the packet
    ///         does not have a UDP header.
    const struct udphdr* GetUdpHdr() const;

    /// \brief Get the Packet's IP Protocol.
    ///
    /// \param  protocol  The Packet's IP Protocol.
    ///
    /// \return True if the Packet has an IP Protocol field, false otherwise.
    bool GetIpProtocol(uint8_t& protocol) const;

    /// \brief Set the source IP Address, in Network Byte Order.
    ///
    /// \param  saddr  The source IP Address.
    void SetIpSrcAddr(uint32_t saddr);

    /// \brief Get the source IP Address, in Network Byte Order, from the
    /// Packet's IP header.
    ///
    /// \param  saddr  The retrieved source IP Address.
    ///
    /// \return True if the Packet has a source IP address, false otherwise.
    bool GetIpSrcAddr(uint32_t& saddr) const;

    /// \brief Set the destination IP Address, in Network Byte Order.
    ///
    /// \param  daddr  The destination address.
    void SetIpDstAddr(uint32_t daddr);

    /// \brief Get the destination IP Address, in Network Byte Order, from the
    /// Packet's IP header.
    ///
    /// \param  daddr  The retrieved destination IP Address.
    ///
    /// \return True if the Packet has a destination IP address, false
    ///         otherwise.
    bool GetIpDstAddr(uint32_t& daddr) const;

    /// \brief Set the DSCP value in the IP header.
    ///
    /// \param  dscp  The DSCP value to be set in the IP header.
    ///
    /// \return True if the IP header DSCP value is set, false otherwise.
    bool SetIpDscp(uint8_t dscp);

    /// \brief Get the DSCP value from the packet's IP header.
    ///
    /// \param  dscp  The DSCP value.
    ///
    /// \return True if the Packet has an IP header DSCP value, false
    ///         otherwise.
    bool GetIpDscp(uint8_t& dscp) const;

    /// \brief Get the latency class for this packet.
    ///
    /// This is dynamically determined (based on packet type and DSCP value)
    /// and then cached for future calls to this function.
    ///
    /// \return The latency class for intra-IRON treatment of this packet.
    LatencyClass GetLatencyClass() const;

    /// \brief Set the latency class for this packet.
    ///
    /// This is supposed to be dynamically determined (based on packet type
    /// and DSCP value) and then cached, but sometimes it must be set to
    /// CRITICAL.
    inline void SetLatencyClass(LatencyClass lat)
    {
      latency_  = lat;
    }

    /// \brief Get the length field from the Packet's IP header.
    ///
    /// \param  ip_len  The retrieved length field from the Packet's IP
    ///                 header.
    ///
    /// \return True if the Packet has an IP header length field, false
    ///         otherwise.
    bool GetIpLen(size_t& ip_len) const;

    /// \brief Set the length field in the Packet's IP header.
    ///
    /// \return True if the Packet's IP header length field is successfully
    ///         updated, false otherwise.
    bool UpdateIpLen();

    /// \brief Set the length field in the Packet's IP header and modify the
    /// internal value of the Packet buffer length.
    ///
    /// \param  len  The length of the Packet, in bytes.
    ///
    /// \return True if the Packet's IP header length field is successfully
    ///         updated, false otherwise.
    bool UpdateIpLen(const size_t len);

    /// \brief Trim the Packet by "len" bytes.
    ///
    /// \param  len  The number of bytes to remove from the end of the
    ///              Packet.
    ///
    /// \return True if the Packet is trimmed, false otherwise.
    bool TrimIpLen(const size_t len);

    /// \brief Get the position of the payload within the Packet.
    ///
    /// \return The position of the payload within the Packet.
    size_t GetIpPayloadOffset() const;

    /// \brief Get the length of the payload of the Packet.
    ///
    /// \return The length of the payload of the Packet.
    size_t GetIpPayloadLengthInBytes() const;

    /// \brief Get a pointer to the Packet's TCP header.
    ///
    /// \return Pointer to the Packet's TCP header, or NULL if the Packet does
    /// not have a TCP header.
    struct tcphdr* GetTcpHdr();

    /// \brief Get a pointer to the Packet's TCP header.
    ///
    /// \return Pointer to the Packet's TCP header, or NULL if the Packet does
    /// not have a TCP header.
    const struct tcphdr* GetTcpHdr() const;

    /// \brief Get the source port, in Network Byte Order, from the Packet's
    /// TCP or UDP header.
    ///
    /// \param  sport_nbo  The retrieved source port, in Network Byte
    ///                    Order.
    ///
    /// \return True if the Packet has a source port, false otherwise.
    bool GetSrcPort(uint16_t& sport_nbo) const;

    /// \brief Set the source port in the Packet's TCP or UDP header.
    ///
    /// \param  sport_nbo  The Packet's source port, in Network Byte Order.
    ///
    /// \return True if the Packet has a TCP or UDP header, false otherwise.
    bool SetSrcPort(uint16_t sport_nbo);

    /// \brief Get the destination port, in Network Byte Order, from the
    /// Packet's TCP or UDP header.
    ///
    /// \param  dport_nbo  The retrieved destination port, in Network Byte
    ///                    Order.
    ///
    /// \return True if the Packet has a destination port, false otherwise.
    bool GetDstPort(uint16_t& dport_nbo) const;

    /// \brief Set the destination port in the Packet's TCP or UDP header.
    ///
    /// \param  dport_nbo  The Packet's destination port, in Network Byte
    ///                    Order .
    ///
    /// \return True if the Packet has a TCP or UDP header, false otherwise.
    bool SetDstPort(uint16_t dport_nbo);

    /// \brief Update the network and transport layer checksums.
    ///
    /// \return True if the Packet has header checksums and they are
    ///         successfully updated, false otherwise.
    bool UpdateChecksums();

    /// \brief Set the checksums to a zero.
    ///
    /// \return True if the Packet has header checksums and they are
    ///         successfully cleared, false otherwise.
    bool ZeroChecksums();

    /// \brief Update the network layer checksum.
    ///
    /// \return True if the Packet has an IP header checksum and it is
    ///         successfully updated, false otherwise.
    bool UpdateIpChecksum();

    /// \brief Update the transport layer checksum.
    ///
    /// \return True if the Packet has a transport header checksum and it is
    ///         successfully updated, false otherwise.
    bool UpdateTransportChecksum();

    /// \brief Compute the transport layer checksum.
    ///
    /// \param  len    The number of bytes to utilize in the checksum
    ///                computation.
    /// \param  cksum  The computed transport layer checksum.
    ///
    /// \return True if the Packet has a transport header checksum and it is
    ///         successfully updated, false otherwise.
    bool ComputeTransportChecksum(size_t len, uint16_t& cksum);

    /// \brief Get the five tuple from the Packet's headers.
    ///
    /// The returned values are in Network Byte Order.
    ///
    /// \param  saddr  The source address of the packet, in Network Byte
    ///                Order.
    /// \param  daddr  The destination address of the packet, in Network
    ///                Byte Order.
    /// \param  sport  The source port of the packet, in Network Byte
    ///                Order.
    /// \param  dport  The destination port of the packet, in Network Byte
    ///                Order.
    /// \param  proto  The protocol type of the packet, generally TCP or
    ///                UDP.
    ///
    /// \return True if the Packet has a 5-tuple, false otherwise.
    bool GetFiveTuple(uint32_t& saddr, uint32_t& daddr,
                      uint16_t& sport, uint16_t& dport,
                      uint32_t& proto) const;

    /// Get the packet receive time.
    ///
    /// \return The time the packet was received.
    inline Time recv_time() const
    {
      return recv_time_;
    }

    /// Set the packet receive time.
    ///
    /// \param  recv_time  The time that the packet was received.
    inline void set_recv_time(const Time& recv_time)
    {
      recv_time_ = recv_time;
    }

    /// Check if the packet was received late.
    ///
    /// \return True if the packet was received late.
    inline bool recv_late() const
    {
      return recv_late_;
    }

    /// Set the packet received late flag.
    ///
    /// \param  recv_late  True if the packet was received late.
    inline void set_recv_late(bool recv_late)
    {
      recv_late_ = recv_late;
    }

    /// Get the origin timestamp for the packet.
    ///
    /// return The origin timestamp for the packet, in milliseconds.
    inline uint16_t origin_ts_ms()
    {
      return origin_ts_ms_;
    }

    /// Set the origin timestamp for the packet.
    ///
    /// \param ts  The timestamp of the packet, in milliseconds.
    inline void set_origin_ts_ms(uint16_t ts)
    {
      origin_ts_ms_ = ts;
    }

    /// Get the packet time-to-go time.
    ///
    /// \return The packet time-to-go.
    Time GetTimeToGo() const;

    /// Set the packet time-to-go time.
    ///
    /// \param  ttg    The packet time-to-go time.
    /// \param  valid  True if the TTG was set for this flow. False
    ///                otherwise.
    void SetTimeToGo(const Time& ttg, bool valid=true);

    /// Update the packet time-to-go time. This subtracts the difference
    /// between the current time and the packet receive time from the
    /// time-to-go time.
    void UpdateTimeToGo();

    /// \brief  Get the packet time value for ordering from smallest to largest.
    ///
    /// \return Return the order time.
    inline Time GetOrderTime() const
    {
      return order_time_;
    }

    /// \brief  Set the packet time value for ordering from smallest to largest.
    /// NOTE: time_to_go_valid must be true to set the order time.
    ///
    /// \param achievable_ttg The achievable time-to-go used to order packets.
    inline void SetOrderTime(const Time& achievable_ttg)
    {
      if (time_to_go_valid_)
      {
        order_time_ = achievable_ttg;
      }
    }

    /// \brief Determines whether a packet has already expired.
    ///
    /// This is accomplished using the following calculation:
    ///   ttg - (now - time_recv)
    ///
    /// This operation is currently only supported for UDP Packets.
    ///
    /// \return True if the Packet is a UDP packet that has expired, false
    ///         otherwise (either the Packet has not expired or the Packet is
    ///         not a UDP packet).
    bool HasExpired() const;

    /// \brief Determines whether a packet can make it over a link with a
    /// given time-to-reach (ttr).
    ///
    /// \param  ttr  The time to reach.
    ///
    /// \return True if the packet can make it in time or there is no ttg
    ///         info, false otherwise.
    bool CanBeDeliveredInTime(Time ttr) const;

    /// \brief Get the group id from the Packet's UDP FEC trailer.
    ///
    /// \param  group_id  The retrieved group id.
    ///
    /// \return True if the Packet has a UDP FEC trailer, false otherwise.
    bool GetGroupId(uint32_t& group_id) const;

    /// \brief Get the slot id from the Packet's UDP FEC trailer.
    ///
    /// \param  slot_id  The retrieved slot id.
    ///
    /// \return True if the Packet has a UDP FEC trailer, false otherwise.
    bool GetSlotId(uint32_t& slot_id) const;

    /// \brief Get the sequence number from the Packet's UDP FEC trailer.
    ///
    /// \param  seq_num  The retrieved sequence number.
    ///
    /// \return True if the Packet has a UDP FEC trailer, false otherwise.
    bool GetFecSeqNum(uint32_t& seq_num) const;

    /// Get the maximum MGEN version that is decodable.
    ///
    /// \return The maximum MGEN version that is decodable.
    static inline uint8_t GetMgenMaxDecodableVersion()
    {
      return 4;
    }

    /// \brief  Get the MGEN sequence number for non-aggregated non-split
    ///         packets.
    ///
    /// This method does not check whether this packet is an MGEN packet, but
    /// simply finds the seq num IF it is known this packet is an MGEN packet.
    ///
    /// \return  The mgen sequence number in the packet.
    uint32_t GetMgenSeqNum() const;

    /// \brief Get the shared memory packet index.
    ///
    /// \return The packet's memory index.
    inline PktMemIndex mem_index()
    {
      return mem_index_;
    }

    /// \brief Set up an IP header on a new packet.
    ///
    /// Most packet functions, such as GetIpHdr, assume that the IP version is
    /// already in place on the packet, and will fail if not. This function
    /// therefore sets up the basic, standard values in an IP header to get a
    /// base Packet on which other functions can be called. This does NOT set
    /// up the DSCP value, Id, or IP addresses.
    inline void InitIpPacket()
    {
      memset(buffer_ + start_, 0, sizeof(struct iphdr));
      struct iphdr* iphdr = reinterpret_cast<struct iphdr*>(buffer_ + start_);
      iphdr->version = 4;
      iphdr->ihl = 5; // IP header with no options.
      iphdr->frag_off = 0;
      iphdr->ttl = 64;
      length_ = sizeof(struct iphdr);
    };

    /// \brief Populate this packet as a broadcast control packet with
    /// necessary header information.
    ///
    /// These broadcast packets use 16 bit sequence numbers, and two sequence
    /// numbers that are more than 2^15 apart will be judged as out of
    /// order. This means if packets are sent at 2^4 packets per second (a
    /// reasonable maximum supported rate for system level control packets),
    /// then we could comfortably support a disconnected network for 214
    /// minutes without having broadcast packets rejected when the network is
    /// reconnected. We can support longer outages if packets are generated
    /// less frequently.
    ///
    /// \param  type         The specific packet type for this type of control
    ///                      packet.
    /// \param  src_bin      The source bin id.
    /// \param  seq_num_hbo  The sequence number in host byte order.
    ///
    /// \return True if the packet was successfully populated. False
    /// otherwise.
    bool PopulateBroadcastPacket(PacketType type,
                                 BinId src_bin,
                                 uint16_t seq_num_hbo);

    /// \brief Parse this packet as an IRON broadcast control packet.
    ///
    /// \param  src_bin  Source bin id will be parsed into here.
    /// \param  seq_num_hbo  The broadcast sequence number will be parsed
    ///                  into here (in host byte order).
    /// \param  data     Pointer to the start of the data in the packet.
    /// \param  data_len The length of the data in the packet (not including
    ///                  type, bin id, sequence number).
    ///
    /// \return True if the packet was successfully parsed. False otherwise.
    bool ParseBroadcastPacket(BinId& src_bin,
                              uint16_t& seq_num_hbo,
                              const uint8_t** data,
                              size_t& data_len);

    /// \brief  Dump the IP header.
    void DumpIpHdr() const;

    /// \brief  Dump the UDP header.
    void DumpUdpHdr() const;

    /// \brief Generate a string representation of the Packet.
    ///
    /// \return String representation of the Packet.
    std::string ToString() const;

    /// \brief Get the time to go in microseconds.
    ///
    /// For most purposes, use GetTimeToGo instead, which will convert the raw
    /// value into a Time object. However, this is useful for including the
    /// value in the packet sent over the wire.
    ///
    /// \return The raw time to go value.
    inline int32_t  time_to_go_usec()  const
    {
      return time_to_go_usec_;
    }

    /// \brief Set the time to go in microseconds.
    ///
    /// For most purposes, use SetTimeToGo instead, which will convert a Time
    /// object into an int32_t. However, this is useful for getting the raw
    /// value out of the packet sent over the wire.
    ///
    /// \param ttg  The raw time to go value.
    inline void set_time_to_go_usec(int32_t ttg)
    {
      time_to_go_usec_ = ttg;
    }

    /// \brief Get the source bin id (part of the unique packet id)
    ///
    /// \return The source bin id.
    inline BinId bin_id() const
    {
      return bin_id_;
    }

    /// Set the source bin id (part of the unique packet id).
    ///
    /// \param  bin_id  The source bin id.
    inline void set_bin_id(BinId bin_id)
    {
      bin_id_ = bin_id;
    }

    /// \brief Get the unique packet id (unique when combined with bin id)
    ///
    /// \return The packet id.
    inline uint32_t packet_id() const
    {
      return packet_id_;
    }

    /// \brief Set the packet id.
    ///
    /// \param  packet_id  The packet id
    inline void set_packet_id(uint32_t packet_id)
    {
      packet_id_ = packet_id;
    }

    /// \brief Get the flag for whether to send the packet id.
    ///
    /// \return the flag for whether to send the packet id.
    inline bool  send_packet_id() const
    {
      return send_packet_id_;
    }

    /// \brief Set the flag for whether to send packet id information.
    ///
    /// \param  new_val   Whether or not to send the packet id.
    inline void set_send_packet_id(bool new_val)
    {
      send_packet_id_ = new_val;
    }

    /// \brief Get the time to go validity flag
    ///
    /// \return the time to go validity flag
    inline bool time_to_go_valid() const
    {
      return time_to_go_valid_;
    }

    /// \brief Set the time to go validity flag
    ///
    /// \param time_to_go_valid the time to go validity flag
    inline void set_time_to_go_valid(bool time_to_go_valid)
    {
      time_to_go_valid_ = time_to_go_valid;
    }

    /// \brief Get the flag for whether to track time-to-go/
    ///
    /// \return the track ttg flag value
    inline bool track_ttg() const
    {
      return track_ttg_;
    }

    /// \brief Set the track time-to-go flag
    ///
    /// \param track  True if we want to track ttg based on this
    /// packet.
    inline void set_track_ttg(bool track)
    {
      track_ttg_ = track;
    }

    /// \brief Get the flag for whether to send packet history
    ///
    /// \return the send packet history flag value
    inline bool send_packet_history() const
    {
      return send_packet_history_;
    }

    /// \brief Set the send packet history flag
    ///
    /// \param send True if we want to track packet history for this packet.
    inline void set_send_packet_history(bool send)
    {
      send_packet_history_ = send;
    }

    /// \brief Get the flag for whether to send packet destination bit vector.
    ///
    /// \return the send packet destination bit vector flag value
    inline bool send_packet_dst_vec() const
    {
      return send_packet_dst_vec_;
    }

    /// \brief Set the send packet destination bit vector flag
    ///
    /// \param send True if we want to track packet destination bit vector
    ///        for this packet.
    inline void set_send_packet_dst_vec(bool send)
    {
      send_packet_dst_vec_ = send;
    }

    /// \brief Return the Packet's internal metadata as a string.
    ///
    /// \return An std string with the bin id and packet id.
    std::string GetPacketMetadataString();

    /// \brief Return the packet contents as a 'tcpdump style' formatted string.
    ///
    /// \return A std string with the packet contents in hex format
    std::string ToHexString() const;

    /// \brief Return the packet contents as a 'tcpdump style' formatted string.
    ///
    /// \param  limit  The maximum number of bytes from the packet to dump
    ///
    /// \return A std string with the packet contents in hex format
    std::string ToHexString(uint32_t limit) const;

    /// \brief Set up the necessary fields to declare this packet a zombie.
    ///
    /// \param lat_class The latency class for this zombie (indicates the
    /// source of the zombie, which is useful for tracking stats).
    void MakeZombie(LatencyClass lat_class);

    /// \brief Return true if this packet is a Zombie (EF zombie or other).
    ///
    /// \return True if latency class is a zombie class.
    inline bool IsZombie()
    {
      // Call GetLatencyClass in case latency hasn't been set.
      GetLatencyClass();
      return ((latency_ >= HIGH_LATENCY_EXP) && (latency_ != NORMAL_LATENCY));
    }

    /// \brief Return true if this latency class represents a zombie.
    ///
    /// \param  lat  The latency class to be checked for the packet.
    ///
    /// \return True if latency class is a zombie class.
    static inline bool IsZombie(LatencyClass lat)
    {
      return ((lat >= HIGH_LATENCY_EXP) && (lat != NORMAL_LATENCY) &&
        (lat != UNSET_LATENCY));
    }

    /// \brief Return true if this latency class counts towards the latency
    /// sensitive byte counts for hierarchical forwarding.
    ///
    /// \param  lat  The latency class to be checked for the packet.
    ///
    /// \return True if latency class is latency sensitive.
    static inline bool IsLatencySensitive(LatencyClass lat)
    {
      return (lat < NORMAL_LATENCY);
    }

    /// \brief  Return true if this latency class represents a latency-sensitive
    ///         packet.
    ///
    /// \return True if latency class is Latency-Sensitive, including LS-Zombies.
    inline bool IsLatencySensitive()
    {
      // Call GetLatencyClass in case latency hasn't been set.
      GetLatencyClass();
      return IsLatencySensitive(latency_);
    }

    /// \brief  Check whether this packet is non-Zombie Latency-Sensitive and
    ///         is being tracked for TTG.
    ///
    /// \return Return true if this packet has queuing delay, false otherwise.
    inline bool HasQueuingDelay()
    {
      return !IsZombie() && IsLatencySensitive() && track_ttg();
    }

    /// \brief Return the packet history vector.
    ///
    /// This should ONLY be called by the PacketHistoryMgr.
    ///
    /// \return The packet history bit vector (understood by PacketHistoryMgr).
    inline const uint8_t* history()
    {
      return history_;
    }

    /// \brief Set the packet history vector.
    ///
    /// This should ONLY be called by the PacketHistoryMgr.
    ///
    /// \param  history  The new packet history bit vector (understood by
    ///         PacketHistoryMgr).
    inline void set_history(uint8_t *history)
    {
      memcpy(history_, history, sizeof(history_));
    }

    /// \brief  Insert a node bin id into the packet's history vector.
    ///
    /// \param  bin_id  The node bin id to insert.
    inline void InsertNodeInHistory(BinId bin_id)
    {
      // Shift the history vector to the right.  Make a copy into tmp, then
      // shift then recopy inside packet's history.
      uint8_t tmp[sizeof(history_) - 1];
      memcpy(tmp, history_, sizeof(history_) - 1);

      memcpy(&(history_[1]), tmp, sizeof(history_) - 1);
      history_[0] = static_cast<uint8_t>(bin_id);
    }

    /// \brief  Get the string of the history vector.
    ///
    /// \return The string of the history vector.
    inline std::string HistoryToString()
    {
      std::stringstream ss;
      ss.str("");
      ss << "History: ";

      uint8_t it_count  = 0;
      while ((history_[it_count] > 0) && (it_count < kHistoryFieldSizeBytes))
      {
        ss << StringUtils::ToString(history_[it_count]) << ", ";
        ++it_count;
      }
      return ss.str();
    }

    /// \brief  Clear the whole packet history.
    inline void ClearPacketHistory()
    {
      memset(history_, kHistoryEntryUnused, sizeof(history_));
    }

    /// \brief Return the destination bit vector for the packet.
    ///
    /// \return The packet destination bit vector.
    inline DstVec dst_vec()
    {
      return dst_vec_;
    }

    /// \brief Set the packet destination bit vector.
    ///
    /// \param  dst_vec  The new destination bit vector.
    inline void set_dst_vec(DstVec dst_vec)
    {
      dst_vec_             = dst_vec;
      send_packet_dst_vec_ = true;
    }

#ifdef PACKET_TRACKING
    /// \brief  Keep track of when a packet moves through the system.
    ///
    /// Used to track when packets move through the system. This happens when
    /// (a) a process gets a fresh packet out of the pool, (b) a process
    /// retrieves the packet by index (owner transfer), (c) a process returns
    /// the packet to the pool, or (d) we explicitly pass the packet to a place
    /// within a component that we want to track.
    ///
    /// Note: to avoiding needing to know the packet owner, call this via the
    /// NEW_PKT_LOC macro in packet_pool.h.
    ///
    /// \param  owner        Which component owns this packet?
    /// \param  new_location Where is this packet going? This is a location
    ///                      reference that can be learned by using
    ///                      GetLocationRef(file, line) in PacketPool.
    void NewPacketLocation(PacketOwner owner, uint16_t new_location);
#endif // PACKET_TRACKING

    /// Check if a packet is a Group Advertisement Message (GRAM).
    bool IsGram() const;

    private:

    /// \brief Default no-arg constructor.
    Packet();

    /// \brief Copy constructor.
    Packet(const Packet& packet);

    /// \brief Destructor.
    ///
    /// This cannot be virtual because Packets live in shared memory, and the
    /// existence of a v_table makes the layout unpredictable.
    ~Packet();

    /// \brief Initialize the internal state of the packet, including clearing
    ///        the buffer.
    ///
    /// \param  index The index in the shared memory segment where the packet
    ///               is located.
    void Initialize(PktMemIndex index);

    /// \brief Reset the internal state of the Packet.
    void Reset();

    /// \brief Make a shallow copy of the Packet.
    ///
    /// This is generally utilized when one thread/process needs to keep a
    /// reference to the Packet and pass the Packet to another thread/process
    /// for processing. The result of this is an increase in the reference
    /// count.
    ///
    /// Note that if it is the case that more than one thread/process has a
    /// reference to the Packet, modifications to the contents of the Packet
    /// are not protected. Modifications to the reference counts are the only
    /// protected operations.
    void ShallowCopy();

    /// \brief Decrement the reference count.
    ///
    /// This method will be called by the PacketPool each time that a Packet
    /// is recycled.
    ///
    /// \return The remaining reference count.
    size_t DecrementRefCnt();

    /// \brief Parse the Packet type from the internal Packet buffer.
    void ParseType() const;

    /// \brief  Parse the virtual length of a Zombie packet.
    ///
    /// \return The length of the packet is not a Zombie packet, the
    ///         virtual lenght otherwise (as grabbed from payload).
    size_t ParseVirtualLength() const;

#ifdef PACKET_TRACKING
    /// \brief Determines whether this is a candidate for a leaked packet
    ///
    /// Checks whether this packet has had the same owner for a long time.
    /// If so, prints the packet and owner information.
    ///
    /// \param stuck_at An array of 4 location references, into which this
    ///        function will put the marker from the latest time this packet
    ///        was seen by each component. stuck_at is indexed by the values
    ///        of the PacketOwner enum, with each array entry representing the
    ///        last place this packet was seen by one component. This is only
    ///        filled in if StuckCheck returns true. The locations can be
    ///        dereferenced using DerefLocation() in PacketPool.
    ///
    /// \return true if the packet is stuck, false otherwise.
    bool StuckCheck(uint16_t* stuck_at);
#endif // PACKET_TRACKING

    // The following depicts a Packet buffer that is partially populated:
    //
    //     |<------------------ kMaxPacketSizeBytes ------------------>|
    //
    //     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //     | D | D | D | D | D | D | D | D | D | D | D |   |   |   |   |
    //     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //       ^
    //       |
    //     start_
    //
    //     |<---------------- length_ ---------------->|
    //
    // The bytes that have data in them are marked with a "D" in the figure,
    // the start of the packet is set to the first byte, and the length is
    // set to the bytes that have data in them.
    //
    // One method of modifying the Packet is to remove bytes from the
    // beginning of the buffer, accomplished via the
    // RemoveBytesFromBeginning() method. When this action is taken, the
    // buffer is modified as follows:
    //
    //     |<------------------ kMaxPacketSizeBytes ------------------>|
    //
    //     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //     | X | X | X | D | D | D | D | D | D | D | D |   |   |   |   |
    //     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //                   ^
    //                   |
    //                 start_
    //
    //                 |<---------- length_ ---------->|
    //
    // The start of the packet is moved forward by the number of bytes that
    // are removed (the bytes that are no longer part of the packet are marked
    // with an "X" in the figure) and the length of the packet is
    // appropriately adjusted.
    //
    // The Packet can also be modified by removing bytes from the end of the
    // buffer, accomplished via the RemoveBlockFromEnd() method. When this
    // action is taken, the buffer is modified as follows:
    //
    //     |<------------------ kMaxPacketSizeBytes ------------------>|
    //
    //     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //     | X | X | X | D | D | D | D | D | X | X | X |   |   |   |   |
    //     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    //                   ^
    //                   |
    //                 start_
    //
    //                 |<---- length_ ---->|
    //
    // The start of the packet does not change when bytes are removed from the
    // end. However, the length is adjusted by the number of bytes that have
    // been removed (marked with an "X" at the end of the buffer in the
    // figure).
    //
    // It is important to note that all methods to get the internal buffer or
    // get the internal buffer at a user specified offset are relative to the
    // start of the packet, start_.
    //

    /// The Packet type. This is a piece of metadata that is remembered as an
    /// optimization. Once the type of packet is determined we will remember
    /// it so we don't have to keep figuring out what type it is. It is a
    /// mutable so that can be modified in const methods.
    mutable PacketType   type_;

    /// The LatencyClass, used to determine intra-IRON latency treatment.
    /// Like type_, this is a piece of metadata that is remembered as an
    /// optimization. It is mutable so that it can be modified in const
    /// methods.
    mutable LatencyClass latency_;

    /// The start of the packet. This value may change as encapsulating
    /// headers are "stripped from" the packet via the
    /// RemoveBytesFromBeginning() method call.
    size_t               start_;

    /// The Packet buffer.
    uint8_t              buffer_[kMaxPacketSizeBytes];

    /// The physical length of the Packet buffer. Note that this represents the
    /// length of the buffer after the internal start_ offset.
    size_t               length_;

    /// The virtual length of the Packet buffer. Note that this represents the
    /// pretend length of the buffer after the internal start_ offset.
    /// In bytes.
    mutable size_t       virtual_length_;

    /// The length of any Packet metadata headers prepended to the buffer
    /// before the internal start_ offset.  This length does not affect the
    /// start_ or length_ members.
    size_t               metadata_length_;

    /// The receive time of the packet.
    Time                 recv_time_;

    /// True if this packet was received outside the target amount of time.
    bool                 recv_late_;

    /// The packet's index inside memory.
    PktMemIndex          mem_index_;

    /// A reference count that tracks the number of references to the Packet
    /// that currently exist.
    size_t               ref_cnt_;

    /// Mutex lock that ensures that reference count modifications are
    /// atomic. Note that not all Packet methods are protected by this
    /// mutex. If multiple threads/processes reference the same Packet,
    /// modifications to the contents of the Packet are not protected.
    pthread_mutex_t      mutex_;

    /// Mutex attributes.
    pthread_mutexattr_t  mutex_attr_;

    /// The time the packet was received at the source.
    uint16_t             origin_ts_ms_;

    /// The time-to-go time for the packet, in microseconds.
    int32_t              time_to_go_usec_;

    /// The time value used for ordering packets from smallest time value to
    /// largest time value.
    Time                 order_time_;

    /// The source bin id, used to disambiguate packet ids.
    BinId                bin_id_;

    /// The packet id.
    uint32_t             packet_id_;

    /// Indicates whether or not this packet should be sent with packet
    /// identification metadata.
    bool                 send_packet_id_;

    /// True if we want to use this packet to track time-to-go information.
    bool                 track_ttg_;

    /// True if this flow has a time to go. False otherwise.
    bool                 time_to_go_valid_;

    /// True if we want to send/track packet history with this packet.
    bool                 send_packet_history_;

    /// Vector tracking the bin ids of the nodes previously visited by the
    /// packet.  The bin ids are represented by bytes and are in order of last
    /// visited first.  The oldest nodes are dropped to enter the latest visited
    /// ones.  A byte value of kHistoryEntryUnused means no node visited.
    ///
    /// Note: This array does not include a type.
    ///
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Node 0    |     Node 1    |     Node 2    |     Node 3    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |     Node 4    |       ...     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ///
    uint8_t             history_[kHistoryFieldSizeBytes];

    /// True if we want to send the packet destination bit vector with this
    /// packet.
    bool                 send_packet_dst_vec_;

    /// A bit vector of destinations for which the packet is to be sent.
    DstVec               dst_vec_;

#ifdef PACKET_TRACKING
    /// Stores a hint of the most recent non-0 packet location references for
    /// each component.
    ///
    /// We track the last location for each component because we don't hold a
    /// lock while updating the location. By giving each component its own
    /// value to update, we avoid overwriting the actual location where the
    /// packet is stuck (otherwise, another copy of the packet could overwrite
    /// the location as the packet moves through a different component, and we
    /// could record the wrong "stuck" location if the other component
    /// eventually recycles the packet). The packet is most likely "stuck" in
    /// only one of these locations, so this is just a hint, not a definitive
    /// answer.
    uint16_t             last_location_[NUM_PACKET_OWNERS];

    /// Keeps track of the most recent time when the owner of this packet
    /// changed to a non-zero owner. This is useful for skimming through the
    /// in use packets to find the most recent time when the ownership of the
    /// packet changed, so identify any packets that have been claimed by the
    /// same owner for a long time.
    uint64_t             last_movement_time_usecs_;
#endif // PACKET_TRACKING
  }; // end class Packet

} // namespace iron

#endif // IRON_COMMON_PACKET_H
