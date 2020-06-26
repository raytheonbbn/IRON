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

#include "tcp_edge_if_config.h"

#include "log.h"
#include "string_utils.h"

using ::iron::ConfigInfo;
using ::iron::StringUtils;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "TcpEdgeIfConfig";

  /// Default iptables flush mangle table directive.
  const bool  kDefaultFlushIpMangleTables = false;

  /// External plumbing directive.
  const bool  kExternalPlumbing = false;

  // The following Berkeley Packet Filter is meant to limit packets sent to the raw
  // socket used by the TCP proxy so that the packets are:
  // 1) tcp packets that are not being sent to the local interface and not marked
  //    with a TOS value of 4 (which we use to bypass IRON/GNAT for demos)
  //    -- tcp and ip[1] != 4 and not dst if_addr
  // OR
  // 2) the packets are VXLAN packets encapsulating tcp packets
  //    udp dst port 8472 are VXLAN packets; udp[39]==6 means they contain TCP pkts

  /// The TCP Proxy Berkeley Packet Filter (BPF) string.
  //
  //  %s : String representation of the LAN-facing interface identified by
  //       the configuration item InboundDevName.
  //  %s : Bypass string portion of BPF string.
  const char*  kBpfStr =
    "(tcp and  ip[1] != 0x4 and not dst %s%s) or (udp dst port 8472 and udp[39]==6)";
//    "(tcp and  ip[1] != 0x4 not dst %s%s) or (udp dst port 8472 and udp[39]==6)";

  /// TCP Proxy edge interface iptables rule-specification: this will
  /// instruct the kernel to drop all TCP packets that have a destination
  /// address that is NOT the LAN-facing IP Address.
  //
  //  %s : iptables command
  //  %s : 'A' or 'D'
  //  %s : InboundDevName
  //  %s : String representation of IP Address of InboundDevName
  const char*  iptables_rule_spec1 =
    "%s -%s PREROUTING -t mangle -i %s -p tcp ! -d %s -j DROP";

  /// TCP Proxy edge interface iptables rule-specification: this will instruct
  /// the kernel to drop all VXLAN tunneled TCP packets.
  //
  //  %s : iptables command
  //  %s : 'A' or 'D'
  //  %s : InboundDevName
  const char*  iptables_rule_spec2 =
    "%s -%s PREROUTING -t mangle -i %s -p udp --dport 8472 -m u32 "
    "--u32 \"56 & 0xFF = 0x6\" -j DROP";
}

//============================================================================
TcpEdgeIfConfig::TcpEdgeIfConfig()
    : EdgeIfConfig(IPPROTO_TCP, kDefaultFlushIpMangleTables,
                   kExternalPlumbing)
{
}

//============================================================================
TcpEdgeIfConfig::~TcpEdgeIfConfig()
{
  // Nothing to destroy.
}

//============================================================================
bool TcpEdgeIfConfig::Initialize(ConfigInfo& ci)
{
  if (!EdgeIfConfig::Initialize(ci))
  {
    return false;
  }

  // Finalize the BPF string.
  bpf_str_ = StringUtils::FormatString(256, kBpfStr,
                                       inbound_dev_ip_str_.c_str(),
                                       bpf_bypass_str_.c_str());

  LogC(kClassName, __func__, "BPF string: %s\n", bpf_str_.c_str());

  // "Compile" the BPF string into the required micro-code program for the
  // edge interface implementation.
  InitializeBpf();

  // Populate the iptables add and delete rules lists.
  iptables_add_rule_list_.Push(
    StringUtils::FormatString(256, iptables_rule_spec1, iptables_cmd_.c_str(),
                              "A", inbound_dev_name_.c_str(),
                              inbound_dev_ip_str_.c_str()));
  iptables_add_rule_list_.Push(
    StringUtils::FormatString(256, iptables_rule_spec2, iptables_cmd_.c_str(),
                              "A", inbound_dev_name_.c_str()));

  iptables_del_rule_list_.Push(
    StringUtils::FormatString(256, iptables_rule_spec1, iptables_cmd_.c_str(),
                              "D", inbound_dev_name_.c_str(),
                              inbound_dev_ip_str_.c_str()));
  iptables_del_rule_list_.Push(
    StringUtils::FormatString(256, iptables_rule_spec2, iptables_cmd_.c_str(),
                              "D", inbound_dev_name_.c_str()));

  return true;
}
