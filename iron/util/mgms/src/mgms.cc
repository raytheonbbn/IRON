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

#include "mgms.h"
#include "ipv4_address.h"
#include "itime.h"
#include "string_utils.h"
#include "virtual_edge_if.h"

#include <cerrno>
#include <linux/igmp.h>
#include <unistd.h>

using ::iron::ConfigInfo;
using ::iron::Ipv4Address;
using ::iron::List;
using ::iron::MashTable;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::StringUtils;
using ::iron::Time;
using ::iron::VirtualEdgeIf;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "Mgms";

  /// The IGMP Query Interval (observed to be 15 seconds on Ubuntu which
  /// differs from the 125 second default as specified in RFC 3376).
  const uint16_t kIgmpQueryIntervalSecs = 15;

  /// The PIM Join/Prune Interval (observed to be 30 seconds on Ubuntu which
  /// differs from the 60 second default as specified in RFC 4601).
  const uint16_t  kPimJoinPruneIntervalSecs = 30;

  /// The PIM Join/Prune packet type.
  const uint8_t  kPimJoinPruneType = 3;

  /// The IPv4 address family identifier, as assigned by IANA.
  const uint8_t  kIpv4AddrFamily = 1;

  /// The number of buckets in the multicast group membership cache. This
  /// constant seems to be a bit large given that the configured number of
  /// multicast addresses is much smaller (see iron_constants.h for the
  /// configured number of multicast addresses).
  const uint16_t  kMcastGrpCacheNumBuckets = 2048;

  /// The maximum number of expired members that will be processed.
  const uint16_t  kMaxExpMbrCnt = 128;

  /// The default AMP remote control port number.
  const uint16_t  kDefaultAmpCtrlPort = 3140;

  /// The maximum number of times a connection to AMP will be retried on
  /// initialization.
  const uint32_t  kMaxNumConnectRetries = 15;

  /// Template for a multicast group join message to be sent to AMP.
  //
  // %s : String representation of multicast group address.
  const char*  kAmpMcastGrpJoinStr =
    "parameter;mcast_group;action;join;mcast_addr;%s";

  /// Template for a multicast group join message to be sent to AMP.
  //
  // %s : String representation of multicast group address.
  const char*  kAmpMcastGrpLeaveStr =
    "parameter;mcast_group;action;leave;mcast_addr;%s";

  /// The upper range of the multicast addresses that will be excluded (all
  /// non-routable multicast addresses, 224.0.0.0 - 224.0.0.255, will be
  /// excluded).
  const Ipv4Address  kMcastExcHiAddr("224.0.0.255");
}

//============================================================================
Mgms::Mgms(VirtualEdgeIf& edge_if, PacketPool& packet_pool)
    : edge_if_(edge_if),
      packet_pool_(packet_pool),
      mcast_grp_cache_(),
      rc_client_(),
      amp_ep_id_(0),
      exp_interval_secs_(kIgmpQueryIntervalSecs),
      next_exp_time_(Time::Infinite()),
      running_(false)
{
}

//============================================================================
Mgms::~Mgms()
{
  // Close the edge interface.
  edge_if_.Close();

  // Clean up the group membership cache.
  GrpInfo*                                     grp_info = NULL;
  MashTable<Ipv4Address, GrpInfo*>::WalkState  grp_ws;
  while (mcast_grp_cache_.GetNextItem(grp_ws, grp_info))
  {
    MbrInfo*                   mbr_info = NULL;
    List<MbrInfo*>::WalkState  mbr_ws;
    while (grp_info->mbrs.GetNextItem(mbr_ws, mbr_info))
    {
      delete mbr_info;
    }
    grp_info->mbrs.Clear();

    delete grp_info;
  }

  mcast_grp_cache_.Clear();
}

//============================================================================
bool Mgms::Initialize(const ConfigInfo& config_info)
{
  LogI(kClassName, __func__, "Configuring Multicast Group Management "
       "Sniffer...\n");

  // Create the edge interface and attach the Berkeley Packet Filter that will
  // divert packets into the Multicast Group Management Sniffer.
  if (!edge_if_.Open())
  {
    LogE(kClassName, __func__, "Error creating edge interface.\n");
    return false;
  }

  // Initialize the multicast group membership mash table.
  if (!mcast_grp_cache_.Initialize(kMcastGrpCacheNumBuckets))
  {
    LogF(kClassName, __func__, "Initialize multicast group cache to %" PRIu16
         " buckets failed.\n", kMcastGrpCacheNumBuckets);
    return false;
  }

  exp_interval_secs_ = kIgmpQueryIntervalSecs > kPimJoinPruneIntervalSecs ?
    kIgmpQueryIntervalSecs : kPimJoinPruneIntervalSecs;

  // Connect to AMP.
  struct sockaddr_in  amp_addr;
  memset(&amp_addr, 0, sizeof(amp_addr));
  amp_addr.sin_family      = AF_INET;
  amp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  amp_addr.sin_port        = htons(kDefaultAmpCtrlPort);

  uint32_t  retry_cnt = 0;
  while ((amp_ep_id_ = rc_client_.Connect(amp_addr)) == 0)
  {
    // Sleep for 1 second and retry.
    sleep(1);
    if (++retry_cnt > kMaxNumConnectRetries)
    {
      LogE(kClassName, __func__, "Unable to connect to AMP after %"
           PRIu32 " attempts...\n", kMaxNumConnectRetries);
      return false;
    }
  }

  next_exp_time_ = Time::Now().Add(Time(exp_interval_secs_).Multiply(2));

  return true;
}

//============================================================================
void Mgms::Start()
{
  LogI(kClassName, __func__, "Starting main Multicast Group Management "
       "Sniffer service loop...\n");

  running_ = true;

  struct timeval  tv;
  tv.tv_sec  = exp_interval_secs_ * 2;
  tv.tv_usec = 0;

  while (running_)
  {
    fd_set  read_fds;
    int     max_fd = 0;

    FD_ZERO(&read_fds);
    edge_if_.AddFileDescriptors(max_fd, read_fds);

    LogD(kClassName, __func__, "select() backstop time tv.{tv_sec, "
         "tv.tv_usec}: {%d, %d}\n", tv.tv_sec, tv.tv_usec);

    int   num_fds = select(max_fd + 1, &read_fds, NULL, NULL, &tv);

    Time  now     = Time::Now();

    if (num_fds < 0)
    {
      LogE(kClassName, __func__, "select() error %s.\n", strerror(errno));
    }
    else if (num_fds > 0)
    {
      if (edge_if_.InSet(&read_fds))
      {
        // Process all available edge interface packets.
        while (true)
        {
          // Read a packet from the edge interface and process it.
          Packet*  pkt = packet_pool_.Get();
          if (pkt == NULL)
          {
            LogF(kClassName, __func__, "Unable to retrieve Packet from "
                 "Packet Pool.\n");
            break;
          }

          if (edge_if_.Recv(pkt) <= 0)
          {
            // There are no more packets available on the edge interface.
            packet_pool_.Recycle(pkt);
            break;
          }
          else
          {
            LogD(kClassName, __func__, "Rcvd. packet of length %d "
                 "bytes...\n", pkt->GetLengthInBytes());

            ProcessPkt(pkt);
            packet_pool_.Recycle(pkt);
          }
        }
      }
    }

    if (next_exp_time_ <= now)
    {
      // Backstop time has expired and reset the backstop timer.
      RemoveExpMembers();

      next_exp_time_ = now.Add(Time(exp_interval_secs_).Multiply(2));
      tv.tv_sec      = exp_interval_secs_ * 2;
      tv.tv_usec     = 0;
    }
    else
    {
      // Recompute next backstop time.
      tv = next_exp_time_.Subtract(now).ToTval();
    }
  }
}

//============================================================================
void Mgms::ProcessPkt(Packet* pkt)
{
  uint8_t  protocol;
  if (!pkt->GetIpProtocol(protocol))
  {
    LogW(kClassName, __func__, "Unable to determine protocol from received "
         "packet.\n");
    return;
  }

  switch (protocol)
  {
    case IPPROTO_IGMP:
      ProcessIgmpPkt(pkt);
      break;
    case IPPROTO_PIM:
      ProcessPimPkt(pkt);
      break;
    default:
      break;
  }
}

//============================================================================
void Mgms::ProcessIgmpPkt(Packet* igmp_pkt)
{
  struct iphdr*  ip_hdr =
    reinterpret_cast<struct iphdr*>(igmp_pkt->GetBuffer());

  Ipv4Address  mbr_addr(ip_hdr->saddr);
  uint32_t     hdr_len = ip_hdr->ihl * 4;

  LogD(kClassName, __func__, "Rcvd. IGMP packet IP header length: %" PRIu32
       " bytes.\n", hdr_len);

  struct igmphdr*  igmp_hdr = reinterpret_cast<struct igmphdr*>
    (igmp_pkt->GetBuffer(hdr_len));

  // TODO: Figure out if we should process IGMPv2 messages also.
  if (igmp_hdr->type != IGMPV3_HOST_MEMBERSHIP_REPORT)
  {
    // Don't process, we only care about IGMP messages with type
    // IGMPV3_HOST_MEMBERSHIP_REPORT.
    return;
  }

  LogD(kClassName, __func__, "Rcvd. IGMPv3 Membership Report...\n");

  struct igmpv3_report*  mem_report =
    reinterpret_cast<struct igmpv3_report*>(igmp_hdr);

  uint16_t  num_grp_records = ntohs(mem_report->ngrec);
  LogD(kClassName, __func__, "IGMP membership report contains %" PRIu16
       " group records.\n", num_grp_records);

  Time  now = Time::Now();
  for (uint16_t i = 0; i < num_grp_records; ++i)
  {
    struct igmpv3_grec*  grec = &mem_report->grec[i];
    uint8_t  grec_type = grec->grec_type;

    string       amp_msg     = "";
    Ipv4Address  mcast_addr(grec->grec_mca);

    if (!mcast_addr.IsMulticast())
    {
      LogE(kClassName, __func__, "Address %s is not a multicast address.\n",
           mcast_addr.ToString().c_str());
      return;
    }

    LogD(kClassName, __func__, "Group record type: %" PRIu8 ".\n", grec_type);
    switch (grec_type)
    {
      case IGMPV3_CHANGE_TO_EXCLUDE:
      case IGMPV3_MODE_IS_EXCLUDE:
        // When there are no unicast addresses in the report it is interpreted
        // as a "join all sources". If there are addresses it is interpreted
        // as a "join but ignore provided sources". In either case for us, it
        // is interpreted as a "join".
        AddToMcastGrpCache(mcast_addr, mbr_addr, now);
        break;

      case IGMPV3_CHANGE_TO_INCLUDE:
        // When there are no unicast addresses in the report it is interpreted
        // as a "leave all sources". If there are addresses it is interpreted
        // as a "leave provided sources". In either case for us, it
        // is interpreted as a "leave".
        //
        // This turns into a leave message ONLY if there are no unicast
        // addresses in the report.
        if (grec->grec_nsrcs == 0)
        {
          RemoveFromMcastGrpCache(mcast_addr, mbr_addr);
        }
        else
        {
          LogW(kClassName, __func__, "Received IGMPV3_CHANGE_TO_INCLUDE "
               "report, not currently handled.\n");
        }
        break;

      default:
        // We currently don't handle the following IGMP group record types:
        //
        // - IGMPV3_MODE_IS_INCLUDE
        // - IGMPV3_ALLOW_NEW_SOURCES
        // - IGMPV3_BLOCK_OLD_SOURCES
        break;
    }
  }
}

//============================================================================
void Mgms::ProcessPimPkt(Packet* pim_pkt)
{
  // Following is the format of the PIM Join/Prune message (as defined in RFC
  // 4601):
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |PIM Ver| Type  |   Reserved    |           Checksum            |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Upstream Neighbor Address (Encoded-Unicast format)     |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Reserved     | Num groups    |          Holdtime             |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         Multicast Group Address 1 (Encoded-Group format)      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |   Number of Joined Sources    |   Number of Pruned Sources    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Joined Source Address 1 (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                             .                                 |
  // |                             .                                 |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Joined Source Address n (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Pruned Source Address 1 (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                             .                                 |
  // |                             .                                 |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Pruned Source Address n (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                           .                                   |
  // |                           .                                   |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         Multicast Group Address m (Encoded-Group format)      |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |   Number of Joined Sources    |   Number of Pruned Sources    |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Joined Source Address 1 (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                             .                                 |
  // |                             .                                 |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Joined Source Address n (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Pruned Source Address 1 (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                             .                                 |
  // |                             .                                 |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |        Pruned Source Address n (Encoded-Source format)        |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //
  // The size of the address fields in the Join/Prune message depend on the
  // address family. NOTE: We will only process Join/Prune messages belonging
  // to the IPv4 address family.
  //
  //
  // Following is the format of the Encoded-Unicast Address (as defined in RFC
  // 4601):
  //
  // 0                   1                   2                   3
  // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Addr Family  | Encoding Type |     Unicast Address
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
  //
  //
  // Following is the format of the Encoded-Group Address (as defined in RFC
  // 4601):
  //
  // 0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  Addr Family  | Encoding Type |B| Reserved  |Z|  Mask Len     |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                Group multicast Address
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+...
  //
  //
  // Following is the format of the Encoded-Source Address (as defined in RFC
  // 4601):
  //
  // 0                   1                   2                   3
  // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // | Addr Family   | Encoding Type | Rsrvd   |S|W|R|  Mask Len     |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                        Source Address
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-...

  Time  now = Time::Now();

  // Verify that the received PIM packet is a PIM Join/Prune type. The PIM
  // packet begins after the IP header.
  uint8_t*  pim_pkt_buf = pim_pkt->GetBuffer(sizeof(struct iphdr));
  size_t    offset      = 0;

  uint8_t   pim_type    = *(pim_pkt_buf) & 0xF;
  if (pim_type != kPimJoinPruneType)
  {
    LogW(kClassName, __func__, "Received unexpected PIM packet type: %" PRIu8
         ".\n", pim_type);
    return;
  }
  offset += sizeof(pim_type);

  // Skip the Reserved and Checksum fields.
  offset += sizeof(uint8_t);
  offset += sizeof(uint16_t);

  // Skip the Upstream Neighbor Address field. The size of this field depends
  // on the address family of the neighbor address.
  if (!ParsePimAddrFamily(pim_pkt_buf, offset))
  {
    return;
  }

  // Skip over the contents of the Upstream Neighbor Address.
  offset += sizeof(uint8_t);
  offset += sizeof(uint32_t);

  // Skip the Reserved field.
  offset += sizeof(uint8_t);

  // Get the number of multicast group sets.
  uint8_t  num_mcast_grps = *(pim_pkt_buf + offset);
  offset += sizeof(num_mcast_grps);

  // Skip the Holdtime field.
  offset += sizeof(uint16_t);

  // Iterate over the number of multicast group sets contained in the PIM
  // Join/Prune packet.
  for (uint8_t i = 0; i < num_mcast_grps; ++i)
  {
    // Get the multicast address. First, we must verify that the address is an
    // IPv4 address.
    if (!ParsePimAddrFamily(pim_pkt_buf, offset))
    {
      LogW(kClassName, __func__, "Mixed address family fields in PIM "
           "Join/Prune message.\n ");

      return;
    }

    // Skip the following Encoded-Group Address fields (3 bytes):
    //
    // - Encoding Type, B, Reserved, Z, Mask Len
    offset += sizeof(uint8_t) * 3;

    // Now, we can get the multicast address.
    uint32_t  addr;
    memcpy(&addr, (pim_pkt_buf + offset), sizeof(addr));
    offset += sizeof(addr);

    Ipv4Address  mcast_addr(addr);
    if (!mcast_addr.IsMulticast())
    {
      LogE(kClassName, __func__, "Address %s is not a multicast address.\n",
           mcast_addr.ToString().c_str());
      return;
    }

    // Get the number of joined sources.
    uint16_t  num_join_srcs_nbo;
    memcpy(&num_join_srcs_nbo, (pim_pkt_buf + offset),
           sizeof(num_join_srcs_nbo));
    offset += sizeof(num_join_srcs_nbo);

    uint16_t  num_join_srcs = ntohs(num_join_srcs_nbo);

    // Get the number of pruned sources.
    uint16_t  num_pruned_srcs_nbo;
    memcpy(&num_pruned_srcs_nbo, (pim_pkt_buf + offset),
           sizeof(num_pruned_srcs_nbo));
    offset += sizeof(num_pruned_srcs_nbo);

    uint16_t  num_pruned_srcs = ntohs(num_pruned_srcs_nbo);

    // Iterate over the Joined Source Addresses.
    for (uint16_t  j = 0; j < num_join_srcs; ++j)
    {
      // Get the join source address. First, we must verify that the address
      // is an IPv4 address.
      if (!ParsePimAddrFamily(pim_pkt_buf, offset))
      {
        LogW(kClassName, __func__, "Mixed address family fields in PIM "
             "Join/Prune message.\n ");

        return;
      }

      // Skip the following Encoded-Source Address fields (3 bytes):
      //
      // - Encoding Type, Rsvrd, S, W, R, Mask Len
      offset += sizeof(uint8_t) * 3;

      // Now, we can get the source address.
      memcpy(&addr, (pim_pkt_buf + offset), sizeof(addr));
      offset += sizeof(addr);

      Ipv4Address  join_addr(addr);

      AddToMcastGrpCache(mcast_addr, join_addr, now);
    }

    // Iterate over the Pruned Source Addresses.
    for (uint16_t  j = 0; j < num_pruned_srcs; ++j)
    {
      // Get the join source address. First, we must verify that the address
      // is an IPv4 address.
      if (!ParsePimAddrFamily(pim_pkt_buf, offset))
      {
        LogW(kClassName, __func__, "Mixed address family fields in PIM "
             "Join/Prune message.\n ");

        return;
      }

      // Skip the following Encoded-Source Address fields (3 bytes):
      //
      // - Encoding Type, Rsvrd, S, W, R, Mask Len
      offset += sizeof(uint8_t) * 3;

      // Now, we can get the source address.
      memcpy(&addr, (pim_pkt_buf + offset), sizeof(addr));
      offset += sizeof(addr);

      Ipv4Address  prune_addr(addr);

      RemoveFromMcastGrpCache(mcast_addr, prune_addr);
    }
  }
}

//============================================================================
bool Mgms::ParsePimAddrFamily(uint8_t* buf, size_t& offset) const
{
  uint8_t  addr_family = *(buf + offset);
  offset += sizeof(addr_family);

  if (addr_family != kIpv4AddrFamily)
  {
    LogW(kClassName, __func__, "Unsupported address family: %" PRIu8 ".\n",
         addr_family);
    return false;
  }

  return true;
}

//============================================================================
void Mgms::AddToMcastGrpCache(const Ipv4Address& mcast_addr,
                              const Ipv4Address& mbr_addr,
                              const Time& now)
{
  // Don't include any non-routable multicast addresses (addresses in the
  // range 224.0.0.0-224.0.0.255).
  if (mcast_addr <= kMcastExcHiAddr)
  {
    return;
  }

  Time      mbr_next_exp_time =
    now.Add(Time(exp_interval_secs_).Multiply(2));
  GrpInfo*  grp_info          = NULL;

  if (mcast_grp_cache_.Find(mcast_addr, grp_info))
  {
    // The multicast group is already part of the group cache. If we know
    // about the member already, update the expiration time. If not, add the
    // member to the member list.

    bool                       mbr_found = false;
    MbrInfo*                   mbr_info = NULL;
    List<MbrInfo*>::WalkState  ws;
    while (grp_info->mbrs.GetNextItem(ws, mbr_info))
    {
      if (mbr_info->mbr_addr == mbr_addr)
      {
        // Update the multicast group member's expiration time and terminate
        // our search.
        mbr_info->exp_time = mbr_next_exp_time;
        mbr_found          = true;
        break;
      }
    }

    if (!mbr_found)
    {
      // Add the member to the multicast group's list of members.
      mbr_info = new (std::nothrow) MbrInfo();
      if (mbr_info == NULL)
      {
        LogF(kClassName, __func__, "Error allocating new MbrInfo "
             "structure.\n");
        return;
      }

      LogI(kClassName, __func__, "Added member %s to multicast group %s.\n",
           mbr_addr.ToString().c_str(), mcast_addr.ToString().c_str());

      mbr_info->mbr_addr = mbr_addr;
      mbr_info->exp_time = mbr_next_exp_time;
      grp_info->mbrs.Push(mbr_info);
    }
  }
  else
  {
    // The multicast group is not in the group cache yet, so we will add it.
    grp_info = new (std::nothrow) GrpInfo();
    if (grp_info == NULL)
    {
      LogF(kClassName, __func__, "Error allocating new group info for "
           "multicast address %s.\n", mcast_addr.ToString().c_str());
      return;
    }

    MbrInfo*  mbr_info = new (std::nothrow) MbrInfo();
    if (mbr_info == NULL)
    {
      LogF(kClassName, __func__, "Error allocating new MbrInfo structure.\n");
      return;
    }

    mbr_info->mbr_addr = mbr_addr;
    mbr_info->exp_time = mbr_next_exp_time;

    grp_info->mcast_addr = mcast_addr;
    grp_info->mbrs.Push(mbr_info);

    if (!mcast_grp_cache_.Insert(mcast_addr, grp_info))
    {
      LogW(kClassName, __func__, "Insertion in the multicast group "
           "membership cache failed for multicast group %s.\n",
           mcast_addr.ToString().c_str());

      grp_info->mbrs.Clear();
      delete mbr_info;
      delete grp_info;

      return;
    }

    LogI(kClassName, __func__, "Added multicast group %s to cache.\n",
         mcast_addr.ToString().c_str());

    LogI(kClassName, __func__, "Added member %s to multicast group %s.\n",
         mbr_addr.ToString().c_str(), mcast_addr.ToString().c_str());

    // We have successfully added a new group and group member to the
    // multicast group cache, so notify AMP of the change.
    string  amp_msg =
      StringUtils::FormatString(256, kAmpMcastGrpJoinStr,
                                mcast_addr.ToString().c_str());

    LogI(kClassName, __func__, "Amp msg: %s\n", amp_msg.c_str());
    SendSetMsgToAmp(amp_msg);
  }
}

//============================================================================
void Mgms::RemoveFromMcastGrpCache(const Ipv4Address& mcast_addr,
                                   const Ipv4Address& mbr_addr)
{
  GrpInfo*  grp_info     = NULL;
  if (!mcast_grp_cache_.Find(mcast_addr, grp_info))
  {
    LogI(kClassName, __func__, "Multicast group %s is not in the multicast "
         "group cache.\n", mcast_addr.ToString().c_str());
    return;
  }

  MbrInfo*                   mbr_info = NULL;
  List<MbrInfo*>::WalkState  ws;
  while (grp_info->mbrs.GetNextItem(ws, mbr_info))
  {
    if (mbr_info->mbr_addr == mbr_addr)
    {
      LogI(kClassName, __func__, "Removed member %s from multicast group "
           "%s.\n", mbr_addr.ToString().c_str(),
           mcast_addr.ToString().c_str());

      if (!grp_info->mbrs.PopAt(ws, mbr_info))
      {
        LogW(kClassName, __func__, "Error removing member %s from multicast "
             "group %s.\n", mbr_addr.ToString().c_str(),
             mcast_addr.ToString().c_str());

        return;
      }

      // Delete the MbrInfo structure and terminate the search.
      delete mbr_info;
      break;
    }
  }

  if (grp_info->mbrs.size() == 0)
  {
    // There are no remaining members that have reported interest in the
    // multicast group. We will now:
    //
    // - Remove the multicast group from the MashTable
    // - Notify AMP to "leave" the multicast group.
    mcast_grp_cache_.FindAndRemove(mcast_addr, grp_info);
    delete grp_info;

    LogI(kClassName, __func__, "Removed multicast group %s from cache.\n",
         mcast_addr.ToString().c_str());

    string amp_msg = StringUtils::FormatString(256, kAmpMcastGrpLeaveStr,
                                               mcast_addr.ToString().c_str());
    LogI(kClassName, __func__, "Amp msg: %s\n", amp_msg.c_str());
    SendSetMsgToAmp(amp_msg);
  }
}

//============================================================================
void Mgms::RemoveExpMembers()
{
  LogD(kClassName, __func__, "Removing expired members...\n");

  Time  now = Time::Now();

  size_t      exp_mbr_cnt = 0;
  ExpMbrInfo  exp_mbr_list[kMaxExpMbrCnt];

  // There are expired members. Find them and remove them from the multicast
  // group cache.
  GrpInfo*                                     grp_info = NULL;
  MashTable<Ipv4Address, GrpInfo*>::WalkState  mg_ws;

  while (mcast_grp_cache_.GetNextItem(mg_ws, grp_info))
  {
    MbrInfo*                   mbr_info = NULL;
    List<MbrInfo*>::WalkState  mbr_info_ws;
    while (grp_info->mbrs.GetNextItem(mbr_info_ws, mbr_info))
    {
      if (mbr_info->exp_time <= now)
      {
        exp_mbr_list[exp_mbr_cnt].mcast_addr = grp_info->mcast_addr;
        exp_mbr_list[exp_mbr_cnt++].mbr_addr = mbr_info->mbr_addr;

        if (exp_mbr_cnt == kMaxExpMbrCnt)
        {
          break;
        }
      }
    }
  }

  for (size_t idx = 0; idx < exp_mbr_cnt; ++idx)
  {
    RemoveFromMcastGrpCache(exp_mbr_list[idx].mcast_addr,
                            exp_mbr_list[idx].mbr_addr);
  }
}

//============================================================================
void Mgms::SendSetMsgToAmp(string amp_msg)
{
  rc_client_.SendSetMessage(amp_ep_id_, "bpf", amp_msg.c_str());
}
