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

#include "nftp_gnat_net_if.h"

#include <string>

#include <cstdio>
#include <unistd.h>

using ::std::string;

namespace
{
  /// The default remote control AMP port number.
  const uint16_t  kDefaultAmpCtlPort = 3140;
}

//============================================================================
NftpGnatNetIf::NftpGnatNetIf()
    : NftpNetIf(),
      rc_client_(),
      amp_addr_str_(),
      flow_tuple_str_(),
      dst_list_str_()
{
}

//============================================================================
NftpGnatNetIf::~NftpGnatNetIf()
{
  // Nothing to destroy.
}

//============================================================================
bool NftpGnatNetIf::Initialize(const ConfigInfo& config_info)
{
  // Get the AMP IP address string.
  amp_addr_str_ = config_info.Get("AmpIpAddr", "");
  if (amp_addr_str_.length() ==0)
  {
    fprintf(stderr, "[NftpGnatNetIf::Initialize] Configuration information "
            "missing AmpIpAddr.\n");
    return false;
  }

  fprintf(stdout, "[NftpGnatNetIf::Initialize] AmpIpAddr: %s\n",
          amp_addr_str_.c_str());

  // Get the flow tuple information for the file transfer.
  string  saddr = config_info.Get("FileXfer.Saddr", "");
  string  sport = config_info.Get("FileXfer.Sport", "");
  string  daddr = config_info.Get("FileXfer.Daddr", "");
  string  dport = config_info.Get("FileXfer.Dport", "");

  if ((saddr.length() == 0) || (sport.length() == 0) ||
      (daddr.length() == 0) || (dport.length() == 0))
  {
    fprintf(stderr, "[NftpGnatNetIf::Initialize] Flow tuple error.\n");
    return false;
  }

  flow_tuple_str_ = saddr + ":" + sport + "->" + daddr + ":" + dport;
  fprintf(stdout, "[NftpGnatNetIf::Initialize] Flow Tuple: %s\n",
          flow_tuple_str_.c_str());

  // Get the destination list.
  dst_list_str_ = config_info.Get("FileXfer.DstList", "");
  if (dst_list_str_.length() == 0)
  {
    fprintf(stderr, "[NftpGnatNetIf::Initialize] Configuration information "
            "missing DstList.\n");
    return false;
  }
  fprintf(stdout, "[NftpGnatNetIf::Information] Destination list: %s\n",
          dst_list_str_.c_str());

  return true;
}

//============================================================================
bool NftpGnatNetIf::CoordinateWithNetwork()
{
  // Connect to the AMP.
  struct sockaddr_in  amp_sock_addr;
  memset(&amp_sock_addr, 0, sizeof(amp_sock_addr));
  amp_sock_addr.sin_family      = AF_INET;
  amp_sock_addr.sin_addr.s_addr = inet_addr(amp_addr_str_.c_str());
  amp_sock_addr.sin_port        = htons(kDefaultAmpCtlPort);
  uint32_t amp_ep               = 0;
  while (amp_ep ==0)
  {
    fprintf(stdout, "[NftpGnatNetIf::CoordinateWithNetwork] Connecting to "
            "AMP\n");
    amp_ep = rc_client_.Connect(amp_sock_addr);
    if (amp_ep != 0)
    {
      fprintf(stdout, "[NftpGnatNetIf::CoordinateWithNetwork] Connected to "
              "AMP\n");
      break;
    }
    sleep(2);
  }

  fprintf(stdout, "[NftpGnatNetIf::CoordinateWithNetwork] Sending message to "
          "AMP: flow tuple is %s, destination list is %s\n", flow_tuple_str_.c_str(),
          dst_list_str_.c_str());

  rc_client_.SendSetMessage(amp_ep, "udp_proxy",
                            "parameter;mcast_dst_list;flow_tuple;" +
                            flow_tuple_str_ + ";dst_list;" + dst_list_str_);

  // XXX Do we wait for a response here?

  return true;
}
