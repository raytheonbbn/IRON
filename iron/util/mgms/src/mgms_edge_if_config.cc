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

#include "mgms_edge_if_config.h"

#include "log.h"

using ::iron::ConfigInfo;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "MgmsEdgeIfConfig";

  /// Default iptables flush mangle table directive.
  const bool  kDefaultFlushIpMangleTables = false;

  /// External plumbing directive.
  const bool  kExternalPlumbing = false;

  // The following Berkeley Packet Filter is meant to limit packets sent to
  // the raw socket used by the Multicast Group Management Sniffer so that the
  // packets are:
  // 1) Any IGMP packets
  //    igmp
  // OR
  // 2) Any pim join/prune packets -- pim packets with with a PIM
  //    Type (offset of 20 bytes from start of the IP header) of 3.
  //    (pim and ip[20]&0xF==3)
  //
  /// The Multicast Group Management Sniffer Berkeley Packet Filter (BPF)
  /// string.
  const char*  kBpfStr = "igmp or (pim and ip[20]&0xF==3)";
}

//============================================================================
MgmsEdgeIfConfig::MgmsEdgeIfConfig()
    : EdgeIfConfig(IPPROTO_IGMP, kDefaultFlushIpMangleTables,
                   kExternalPlumbing)
{
}

//============================================================================
MgmsEdgeIfConfig::~MgmsEdgeIfConfig()
{
  // Nothing to destroy.
}

//============================================================================
bool MgmsEdgeIfConfig::Initialize(ConfigInfo& ci)
{
  if (!EdgeIfConfig::Initialize(ci))
  {
    return false;
  }

  // Finalize the BPF string.
  bpf_str_ = kBpfStr;

  LogC(kClassName, __func__, "BPF string: %s\n", bpf_str_.c_str());

  // "Compile" the BPF string into the required micro-code program for the
  // edge interface implementation.
  InitializeBpf();

  // Since the Multicast Group Management Sniffer is just "sniffing" IGMP
  // packets, we won't create any iptables rules (add and delete) for dropping
  // packets (as we do in the TCP Proxy and the UDP Proxy) as we want the
  // kernel to still process received IGMP packets.

  return true;
}
