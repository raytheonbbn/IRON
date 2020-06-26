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

#include "edge_if_config.h"

#include "log.h"
#include "string_utils.h"

#include <cstring>
#include <net/if.h>
#include <pcap/pcap.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace
{
  /// Class name for logging.
  const char*  kClassName = "EdgeIfConfig";

  /// The default inbound dev name.
  const char*  kDefaultInboundDevName= "em2";

  /// Default iptables command.
  const char*  kDefaultIptablesCmd = "/sbin/iptables";

  /// Default ESP support indicator.
  const bool   kDefaultEspSupport = false;

  /// Edge interface iptables bypass rule-specification: this will
  /// instruct the kernel to mark packets that are to bypass IRON.
  //
  //  %s : iptables command
  //  %s : 'A' or 'D'
  //  %s : protocol (tcp, udp)
  //  %s : bypass information
  const char*  iptables_bypass_rule_spec1 = "%s -%s PREROUTING "
    "-t mangle -p %s %s -j TOS --set-tos 0x4";

  /// Edge interface iptables bypas rule-specfication: this will instruct the
  /// kernel to ACCEPT all packets that have been marked to bypass IRON.
  ///
  // %s : iptables command
  // %s : 'A' or 'D'
  const char*  iptables_bypass_rule_spec2 = "%s -%s PREROUTING -t mangle "
    "-m tos --tos=0x4 -j ACCEPT";
}

using ::iron::EdgeIfConfig;
using ::std::string;

//============================================================================
EdgeIfConfig::EdgeIfConfig(int protocol, bool flush_iptables_mangle_table,
                           bool external_plumbing)
    : bpf_str_(),
      bpf_bypass_str_(),
      bpf_(NULL),
      inbound_dev_name_(),
      inbound_dev_ip_(0),
      inbound_dev_ip_str_(),
      iptables_cmd_(kDefaultIptablesCmd),
      iptables_add_rule_list_(),
      iptables_del_rule_list_(),
      protocol_(protocol),
      flush_iptables_mangle_table_(flush_iptables_mangle_table),
      external_plumbing_(external_plumbing)
{
}

//============================================================================
EdgeIfConfig::~EdgeIfConfig()
{
  // Destroy the Berkeley Packet Filter.
  if (bpf_ != NULL)
  {
    delete bpf_;
    bpf_ = NULL;
  }
}

//============================================================================
bool EdgeIfConfig::Initialize(ConfigInfo& ci)
{
  inbound_dev_name_ = ci.Get("InboundDevName", kDefaultInboundDevName);
  iptables_cmd_     = ci.Get("IptablesCmd", kDefaultIptablesCmd);

  if (!GetInboundDevInfo())
  {
    LogE(kClassName, "Error getting device info for %s.\n",
         inbound_dev_name_.c_str());
    return false;
  }

  // Extract the information for the bypass flows, if any.
  uint32_t  num_bypass_tuples = ci.GetUint("NumBypassTuples", 0, false);

  for (uint32_t i = 0; i < num_bypass_tuples; i++)
  {
    string  config_prefix("BypassTuple.");
    config_prefix.append(StringUtils::ToString(static_cast<int>(i)));

    string  bypass_tuple = ci.Get(config_prefix, "");
    if (bypass_tuple != "")
    {
      ParseBypassTuple(bypass_tuple);
    }
  }

  GenerateBypassIptablesRulesAndBpfStr();

  LogC(kClassName, __func__, "Edge interface configuration:\n");
  LogC(kClassName, __func__, "InboundDevName : %s\n",
       inbound_dev_name_.c_str());
  LogC(kClassName, __func__, "IptablesCmd    : %s\n", iptables_cmd_.c_str());

  uint8_t                      cnt = 0;
  BypassInfo                   bi;
  List<BypassInfo>::WalkState  bi_ws;
  bi_ws.PrepareForWalk();
  while (bypass_info_list_.GetNextItem(bi_ws, bi))
  {
    LogC(kClassName, __func__, "BypassTuple.%" PRIu8  "  : %s\n", cnt,
         bi.bypass_tuple_str.c_str());
    cnt++;
  }

  LogC(kClassName, __func__, "Edge interface configuration complete.\n");

  return true;
}

//============================================================================
bool EdgeIfConfig::InitializeBpf()
{
  pcap_t*             handle;
  struct bpf_program  fp;
  int                 snaplen = 2048;

  handle = pcap_open_dead(DLT_RAW, snaplen);
  if (handle == NULL)
  {
    LogE(kClassName, __func__, "Error opening pcap handle.\n");
    return false;
  }

  int optimize = 1;
  if (pcap_compile(handle, &fp, bpf_str_.c_str(), optimize,
                   PCAP_NETMASK_UNKNOWN) == -1)
  {
    LogE(kClassName, __func__, "Error: %s\n", pcap_geterr(handle));
    pcap_close(handle);
    return false;
  }

  pcap_close(handle);

  // Convert the struct bpf_program to a struct sock_fprog.
  int     len       = fp.bf_len;
  size_t  prog_size = sizeof(fp.bf_insns) * len;

  bpf_ = (struct sock_fprog*)
    new (std::nothrow) char[sizeof(struct sock_fprog) +
                            (sizeof(struct sock_filter) * len)];

  if (bpf_ == NULL)
  {
    LogF(kClassName, __func__, "Error allocating new struct sock_fprog.\n");
    return false;
  }

  bpf_->len    = len;
  bpf_->filter = (struct sock_filter*)(((char *)bpf_) +
                                       sizeof(struct sock_fprog));

  memcpy(bpf_->filter, fp.bf_insns, prog_size);

  return true;
}

//============================================================================
bool EdgeIfConfig::GetInboundDevInfo()
{
  int  temp_fd = -1;

  // Make sure that the provided device name isn't too large.
  if (inbound_dev_name_.length() > IFNAMSIZ)
  {
    LogE(kClassName, __func__, "inbound_dev_name_ must be less than %d "
         "characters.\n", IFNAMSIZ);
    return false;
  }

  // Get the local interfaces.
  if ((temp_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
  {
    LogW(kClassName, __func__, "Error creating socket.\n");
    return false;
  }

  struct ifreq  if_str;
  memset(&if_str, 0, sizeof(struct ifreq));
  strncpy(if_str.ifr_name, inbound_dev_name_.c_str(), IFNAMSIZ - 1);
  if_str.ifr_name[IFNAMSIZ - 1] = '\0';

  int rv = ioctl(temp_fd, SIOCGIFADDR, &if_str);
  if (rv != 0)
  {
    LogE(kClassName, __func__, "FATAL ERROR: ioctl returned %d for specified "
         "device %s. \n", rv, inbound_dev_name_.c_str());
    close(temp_fd);
    return false;
  }

  inbound_dev_ip_ = htonl(
    ((struct sockaddr_in*)&(if_str.ifr_addr))->sin_addr.s_addr);

  char    if_addr_str[64];
  size_t  if_addr_str_size = 64;
  if (!inet_ntop(AF_INET,
                 &((struct sockaddr_in*)&(if_str.ifr_addr))->sin_addr,
                 if_addr_str, if_addr_str_size))
  {
    LogE(kClassName, __func__, "Error getting device %s IP Address as a "
         "string.\n", inbound_dev_name_.c_str());
    close(temp_fd);
    return false;
  }

  inbound_dev_ip_str_ = if_addr_str;

  close(temp_fd);
  return true;
}

//============================================================================
void EdgeIfConfig::ParseBypassTuple(string bypass_tuple)
{
  // The bypass tuples have the following format:
  //
  //   protocol;saddr:[sport|sport_low,sport_high]->
  //     daddr:[dport|dport_low,dport_high]

  List<string>  tokens;
  StringUtils::Tokenize(bypass_tuple, ";", tokens);

  if (tokens.size() != 2)
  {
    LogW(kClassName, __func__, "Incorrectly formatted bypass tuple: %s\n",
         bypass_tuple.c_str());
    return;
  }

  BypassInfo  bi;

  bi.bypass_tuple_str = bypass_tuple;
  tokens.Pop(bi.protocol);

  string  four_tuple;
  tokens.Pop(four_tuple);

  if ((bi.protocol != "tcp") && (bi.protocol != "udp"))
  {
    LogW(kClassName, __func__, "Invalid protocol: %s\n", bi.protocol.c_str());
    return;
  }

  if (((protocol_ == IPPROTO_TCP) && (bi.protocol != "tcp")) ||
      ((protocol_ == IPPROTO_UDP) && (bi.protocol != "udp")))
  {
    return;
  }

  List<string>  endpt_tokens;
  StringUtils::Tokenize(four_tuple, "->", endpt_tokens);

  if (endpt_tokens.size() != 2)
  {
    LogW(kClassName, __func__, "Incorrectly formatted 4-tuple: %s\n",
         four_tuple.c_str());
    return;
  }

  string  src_endpt;
  string  dst_endpt;
  endpt_tokens.Pop(src_endpt);
  endpt_tokens.Pop(dst_endpt);

  List<string>  src_tokens;
  StringUtils::Tokenize(src_endpt, ":", src_tokens);

  if (src_tokens.size() != 2)
  {
    LogW(kClassName, __func__, "Incorrectly formatted source endpoint: %s\n",
         src_endpt.c_str());
    return;
  }

  src_tokens.Pop(bi.saddr);
  src_tokens.Pop(bi.sport);
  if (bi.sport.find(",") != string::npos)
  {
    bi.sport_range = true;
    List<string>  sport_tokens;
    StringUtils::Tokenize(bi.sport, ",", sport_tokens);

    sport_tokens.Pop(bi.sport_low);
    sport_tokens.Pop(bi.sport_high);
  }

  List<string>  dst_tokens;
  StringUtils::Tokenize(dst_endpt, ":", dst_tokens);

  if (dst_tokens.size() != 2)
  {
    LogW(kClassName, __func__, "Incorrectly formatted destination endpoint: "
         "%s\n", dst_endpt.c_str());
    return;
  }

  dst_tokens.Pop(bi.daddr);
  dst_tokens.Pop(bi.dport);
  if (bi.dport.find(",") != string::npos)
  {
    bi.dport_range = true;
    List<string>  dport_tokens;
    StringUtils::Tokenize(bi.dport, ",", dport_tokens);

    dport_tokens.Pop(bi.dport_low);
    dport_tokens.Pop(bi.dport_high);
  }

  bypass_info_list_.Push(bi);
}

//============================================================================
void EdgeIfConfig::GenerateBypassIptablesRulesAndBpfStr()
{
  // Create the bypass portion of the BPF string and create the iptables rules
  // for the flows that are to bypass IRON.
  //
  // The format for the bypass portion of the BPF string is:
  //
  //   and not ((expression1) or (expression2) or ... or (expressionN))

  BypassInfo                   bi;
  List<BypassInfo>::WalkState  bi_ws;
  bi_ws.PrepareForWalk();

  bool    first_item = true;
  string  and_str = "";
  string  iptables_bypass_str;

  if (bypass_info_list_.size() == 0)
  {
    return;
  }

  bpf_bypass_str_ = " and not (";
  while (bypass_info_list_.GetNextItem(bi_ws, bi))
  {
    and_str = "";
    iptables_bypass_str = "";

    if (!first_item)
    {
      bpf_bypass_str_ += " or ";
    }
    else
    {
      first_item = false;
    }

    bpf_bypass_str_ += "(";

    if (bi.saddr != "*")
    {
      iptables_bypass_str += StringUtils::FormatString(
        256, " --saddr %s", bi.saddr.c_str());
      bpf_bypass_str_ += StringUtils::FormatString(
        256, "src %s", bi.saddr.c_str());
      and_str = " and";
    }

    if (bi.sport_range)
    {
      iptables_bypass_str += StringUtils::FormatString(
        256, " --sport %s:%s", bi.sport_low.c_str(), bi.sport_high.c_str());
      bpf_bypass_str_ += StringUtils::FormatString(
        256, "%s src portrange %s-%s", and_str.c_str(), bi.sport_low.c_str(),
        bi.sport_high.c_str());
      and_str = " and";
    }
    else if (bi.sport != "*")
    {
      iptables_bypass_str += StringUtils::FormatString(
        256, " --sport %s", bi.sport.c_str());
      bpf_bypass_str_ += StringUtils::FormatString(
        256, "%s src port %s", and_str.c_str(), bi.sport.c_str());
      and_str = " and";
    }

    if (bi.daddr != "*")
    {
      iptables_bypass_str += StringUtils::FormatString(
        256, " --daddr %s", bi.daddr.c_str());
      bpf_bypass_str_ += StringUtils::FormatString(
        256, "%s dst %s", and_str.c_str(), bi.daddr.c_str());
      and_str = " and";
    }

    if (bi.dport_range)
    {
      iptables_bypass_str += StringUtils::FormatString(
        256," --dport %s:%s", bi.dport_low.c_str(), bi.dport_high.c_str());
      bpf_bypass_str_ += StringUtils::FormatString(
        256, "%s dst portrange %s-%s", and_str.c_str(), bi.dport_low.c_str(),
        bi.dport_high.c_str());
      and_str = " and";
    }
    else if (bi.dport != "*")
    {
      iptables_bypass_str += StringUtils::FormatString(
        256, " --dport %s", bi.dport.c_str());
      bpf_bypass_str_ += StringUtils::FormatString(
        256, "%s dst port %s", and_str.c_str(), bi.dport.c_str());
    }

    iptables_add_rule_list_.Push(
      StringUtils::FormatString(256, iptables_bypass_rule_spec1,
                                iptables_cmd_.c_str(), "A",
                                bi.protocol.c_str(),
                                iptables_bypass_str.c_str()));
    iptables_del_rule_list_.Push(
      StringUtils::FormatString(256, iptables_bypass_rule_spec1,
                                iptables_cmd_.c_str(), "D",
                                bi.protocol.c_str(),
                                iptables_bypass_str.c_str()));

    bpf_bypass_str_ += ")";
  }

  bpf_bypass_str_ += ")";

  iptables_add_rule_list_.Push(
    StringUtils::FormatString(256, iptables_bypass_rule_spec2,
                              iptables_cmd_.c_str(), "A"));
  iptables_del_rule_list_.Push(
    StringUtils::FormatString(256, iptables_bypass_rule_spec2,
                              iptables_cmd_.c_str(), "D"));
}
