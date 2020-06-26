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

#ifndef IRON_COMMON_IRON_CONSTANTS_H
#define IRON_COMMON_IRON_CONSTANTS_H

#include "ipv4_address.h"
#include "iron_types.h"
#include "itime.h"
#include "unused.h"

#include <limits>
#include <sys/types.h>
#include <stdint.h>
#include <string>

/// The default BPF to UDP Proxy FIFO path for passing packets.
#define kDefaultBpfToUdpPktFifoPath    "/tmp/BPF_UDP_PKT_FIFO"

/// The default BPF to TCP Proxy FIFO path for passing packets.
#define kDefaultBpfToTcpPktFifoPath    "/tmp/BPF_TCP_PKT_FIFO"

/// The default UDP Proxy to BPF FIFO path for passing packets.
#define kDefaultUdpToBpfPktFifoPath    "/tmp/UDP_BPF_PKT_FIFO"

/// The default TCP Proxy to BPF FIFO path for passing packets.
#define kDefaultTcpToBpfPktFifoPath    "/tmp/TCP_BPF_PKT_FIFO"

/// The default name of the shared memory segment for queue depth weights.
#define kDefaultWeightShmName          "/weights"

/// The default name of the shared memory segment for the bin map.
#define kDefaultBinMapShmName          "/binmap"

/// The name of the shared memory segment for the packet pool.
#define kPacketPoolShmName             "/packetpool"

/// The default name of the shared memory segment for the latency_cache.
#define kDefaultLatencyCacheShmName    "/latencycache"

/// The default anti-circulation technique.
#define kDefaultAntiCirculation        "HeuristicDAG"

/// The default Bpf forwarding algorithm.
#define kDefaultBpfwderAlg             "LatencyAware"

namespace iron
{
  /// The size of the DstVec, in bits.
  const uint8_t   kDstVecSizeBits       = sizeof(iron::DstVec) * 8;

  /// Of the bits in the DstVec, this is the maximum number of bits to be used
  /// to record destinations BinIds. This constant is necessary in order to
  /// use a specific number of bits for which we don't have a standard integer
  /// type.
  const uint8_t   kDstVecBitsUsed       = 24;

  /// The maximum number of supported IRON node unicast destinations. These
  /// are IRON edge nodes only, not IRON interior nodes.  Each destination is
  /// uniquely identified via a BinId. Statically initialized arrays to hold
  /// per-IRON-edge-node values (i.e., per-unicast-BinIndex) can be allocated
  /// using this size.
  ///
  /// See also iron_types.h typedef BinIndex. The BinIndex type must be able
  /// to hold the value of this constant plus kMaxNumIntNodes and
  /// kMaxNumMcastGroups.
  const uint32_t  kMaxNumDsts           = kDstVecBitsUsed;

  /// The maximum number of supported IRON interior nodes. Each interior node
  /// is uniquely identified via a BinId.
  ///
  /// See also iron_types.h typedef BinIndex. The BinIndex type must be able
  /// to hold the value of this constant plus kMaxNumDsts and
  /// kMaxNumMcastGroups.
  const uint32_t  kMaxNumIntNodes       = 24;

  /// The maximum number of supported multicast groups, each of which can be
  /// uniquely identified via a McastId. Statically initialized arrays to hold
  /// per-multicast-group values (i.e., per-mcast-BinIndex) can be allocated
  /// using this size.
  ///
  /// See also iron_types.h typedef BinIndex. The BinIndex type must be able
  /// to hold the value of this constant plus kMaxNumDsts and
  /// kMaxNumIntNodes.
  const uint32_t  kMaxNumMcastGroups    = 16;

  /// The maximum value of a BinId for a unicast destination (IRON edge
  /// node). Valid BinIds for unicast destinations are 0 to kMaxUcastBinId.
  ///
  /// This is also limited, and checked during BinMap initialization, by the
  /// size kDstVecBitsUsed, since we currently use the BinId as the bit
  /// position in the DstVec bit vector.
  const uint32_t  kMaxUcastBinId        = kDstVecBitsUsed - 1;

  /// The maximum value of a BinId. Except for unicast destinations (IRON edge
  /// nodes), valid BinIds are 0 to kMaxBinId.
  ///
  /// See also iron_types.h typedef BinId. The BinId type must be able to hold
  /// the value of this constant.
  ///
  /// This is also limited, and checked during BinMap initialization, by the
  /// value of kInvalidBinId.
  const uint32_t  kMaxBinId             = UINT8_MAX - 1;

  /// The maximum value of a McastId. Valid McastIds are 0 to kMaxMcastId.
  ///
  /// See also iron_types.h typedef McastId. The McastId type must be able to
  /// hold the value of this constant.
  const uint32_t  kMaxMcastId           = UINT32_MAX;

  /// The BinId value that represents an invalid value.
  const BinId     kInvalidBinId         = UINT8_MAX;

  /// The McastId value that represents an invalid value.
  const McastId   kInvalidMcastId       = 0;

  /// The BinIndex value that represents an invalid value.
  const BinIndex  kInvalidBinIndex      = UINT16_MAX;

  /// The default queue normalizer.
  const double    kDefaultK = 1e12;

  /// The maximum number of path controllers supported
  const size_t    kMaxPathCtrls = 32;

  /// True if we want to access queue depths directly in shared memory. False
  /// if we want to periodically copy to local memory and access from there.
  const bool      kDirectAccessQueueDepths = false;

  // The default flag for whether to do track packet history.
  const bool      kDefaultPacketHistory = true;

  // The default flag for whether to do packet tracing.
  const bool      kDefaultPacketTrace = true;

  /// The default flag for whether to track per-packet time-to-go.
  const bool      kDefaultTtgTracking = true;

  /// The default flag for whether to do LSA-based latency collection.
  const bool      kDefaultLinkStateLatency  = true;

  /// The default semaphore key for queue depth weights in shared memory.
  const key_t     kDefaultWeightSemKey  = 101;

  /// The semaphore key for the packet pool segment in shared memory.
  const key_t     kPacketPoolSemKey     = 103;

  /// The semaphore key for the latency cache segment in shared memory.
  const key_t     kLatencyCacheSemKey = 105;

  /// The semaphore key for the bin map segment in shared memory.
  const key_t     kDefaultBinMapSemKey = 107;

  /// Default for the minimum time window between admission control timers.
  const uint32_t  kDefaultBpfMinBurstUsec = 2000;

  /// The maximum length of the Packet buffer.
  const size_t    kMaxPacketSizeBytes   = 2048;

  /// The default length reserved at the start of each Packet buffer.  Used
  /// for prepending headers to packets (such as CAT headers to IPv4 packets).
  const size_t    kDefaultPacketStartBytes = 32;

  /// The number of bits to represent the packet id.
  const uint32_t  kPacketIdSizeBits     = 20;

  const uint32_t  kMaxPacketId          = (1 << kPacketIdSizeBits) - 1;

  /// The default setting to perform multiple dequeues.
  const bool      kDefaultMultiDeq      = true;

  /// The default xmit queue threshold for the BPF.
  const uint32_t  kDefaultBpfXmitQueueThreshBytes  = 6000;

  /// Magic number for unspecified TTG.
  const int32_t   UNUSED(kUnsetTimeToGo) = std::numeric_limits<int32_t>::max();

  /// Magic number for unspecified origin timestamp.
  const uint16_t  UNUSED(kUnsetOriginTs) = std::numeric_limits<uint16_t>::max();

  /// Drop expired packets rather than turn them into Zombies.
  const bool      kDefaultDropExpired   = false;

  /// Disable Zombie compression by default.  Not config tunable because there
  /// is no obvious advantage not to enable compression.
  const bool      kDefaultZombieCompression  = false;

  /// \brief Default value for whether to use anti-starvation zombies
  /// as opposed to NPLB
  const bool      kDefaultUseAntiStarvationZombies = true;

  /// \brief The UDP destination port for VXLAN tunneled packets.
  ///
  /// Note that Linux uses destination port 8472 for VXLAN tunnels instead of
  /// the IANA-assigned port of 4789.
  const uint16_t  kVxlanTunnelDstPort = 8472;  // 4789

  /// \brief The length of the VXLAN tunnel headers.
  ///
  /// The VXLAN tunnel headers include the following:
  ///   - Outer IPv4 Header (20 bytes)
  ///   - UDP Header (8 bytes)
  ///   - VXLAN Header (8 bytes)
  ///   - Inner Ethernet Header (14 bytes)
  const uint16_t  kVxlanTunnelHdrLen = 50;

  /// The state of flows, as seen by the proxies.
  typedef enum
  {
    // If you change this portion, make sure to change the flowStateString below.
    FLOW_TRIAGED = 0,
    FLOW_OFF,
    FLOW_ON,
    UNREACHABLE,
    LOSS_TRIAGED,
    UNDEFINED
  } FlowState;

  const ::std::string flowStateString[] = {"TRIAGED", "OFF", "ON", "UNREACHABLE", "LOSS_TRIAGED", "UNDEFINED"};

  /// The EF Ordering enum.  Modify the array of strings below if you modify
  /// the enum here.
  /// EF_ORDERING_NONE is same as receive time (no ordering)
  /// EF_ORDERING_DELIVERY_MARGIN, for ttg - ttr (default).
  /// EF_ORDERING_TTG for ttg of the packet.
  enum EFOrdering
  {
    EF_ORDERING_NONE            = 0,
    EF_ORDERING_DELIVERY_MARGIN,
    EF_ORDERING_TTG
  };

  const EFOrdering kDefaultEFOrdering = EF_ORDERING_DELIVERY_MARGIN;

  /// \brief The backpressure gradient queue-delay weight for NPLB.
  ///
  /// Ignored unless QueueDepthManager = NPLB.
  ///
  /// This is how much weight to place on the queue-delay term in the
  /// backpressure gradients. This will be equally weighted to the queue depth
  /// term when set to [drain-rate / 1x10^6], since the delay term reflects
  /// how long a packet has been sitting first in the queue in micro seconds,
  /// and the queue depths are in bytes.
  const double        kDefaultQueueDelayWeight               = 0.1;

  /// \brief Threshold queue delay before adding a stickiness term for NPLB.
  ///
  /// This is parameter d_{max} in the paper "No Packet Left Behind". (In
  /// usec rather than time slots, since we are essentially using a usec as a
  /// time slot). If the difference between the queue delay on the first
  /// packet dequeued and the first packet remaining in the queue is greater
  /// than this value, then some stickiness will be added to the
  /// gradient, meaning later packets will sit in the queue for less
  /// time. Increasing threshold this means we get less stickiness, so higher
  /// latency for packets facing potential starvation. Decreasing this will
  /// decrease latency for these packets at the expense of latency for packets
  /// for more heavily utilized bins.
  const double        kDefaultQueueDelayStickinessThreshSecs = 0.2;

  /// \brief The default maximum loss threshold for an inelastic flow.
  ///
  /// This is used in the UDP proxy and AMP in utility functions where a
  /// delta value is not specified. An inelastic flow can lose at most
  /// this fraction of the nominal rate for it to be considered
  /// to be properly serviced.
  const double        kDefaultMaxLossThreshold               = 0.2;

  /// The default algorithm hysteresis, or minimal queue differential,
  /// in bytes, with a neighbor required before transmitting a packet
  /// to that neighbor.
  const uint32_t      kBpfAlgHysteresisBytes                 = 150;

  /// \brief Approximate system start time, to be used for drawing graphs.
  ///
  /// Used to normalize times when logging values to be graphed.
  const uint64_t  UNUSED(kStartTime)              = Time::GetNowInUsec();

  /// The default port used for GRoup Advertisement Messages.
  const uint16_t  kDefaultGramPort                = 48901;

  /// The default multicast group used for GRoup Advertisement Messages.
  const Ipv4Address kDefaultGramGrpAddr           = Ipv4Address("224.77.77.77");

  /// The default maximum number of subnet masks allowed per bin id.
  const uint8_t kDefaultNumHostMasks              = 8;

  /// A flag indicating whether or not to send group advertisement messages.
  const bool      kDefaultSendGrams               = true;

  /// The default LOG utility function parameters for the UDP proxy.
  const ::std::string kDefaultUdpLogUtilityDefn   =
    "1/1;1500;0;0;120;0;type=LOG:a=20:m=10000000:p=1:label=default_service";

  /// The default LOG utility function parameters for the TCP proxy.
  const ::std::string kDefaultTcpLogUtilityDefn   =
    "1/1;1500;0;0;120;0;type=LOG:a=20:m=10000000:p=1:label=default_service";

  /// The default STRAP utility function parameters.
  const ::std::string kDefaultStrapUtilityDefn    =
    "1/1;1500;0;0;120;0;type=STRAP:p=5:label=mgen_flow_1";
} // namespace iron

#endif // IRON_COMMON_IRON_CONSTANTS_H
