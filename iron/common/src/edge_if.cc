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

#include "edge_if.h"

#include <cerrno>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace
{
  /// Class name for logging.
  const char*  kClassName = "EdgeIf";

  /// Identifier for an unopened socket file descriptor.
  const int kNoFd = -1;
}

using ::iron::EdgeIf;
using ::std::string;

//============================================================================
EdgeIf::EdgeIf(EdgeIfConfig& config)
    : xmt_sock_(kNoFd), rcv_sock_(kNoFd), config_(config)
{
}

//============================================================================
EdgeIf::~EdgeIf()
{
  CloseEdgeIf();
}

//============================================================================
bool EdgeIf::Open()
{
  // Open the transmit socket.
  if ((xmt_sock_ = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
  {
    LogE(kClassName, __func__, "socket error: %s\n", strerror(errno));
    return false;
  }

  // Tell the kernel that we will provide the headers for the transmit
  // socket.
  int  on = 1;
  if (setsockopt(xmt_sock_, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
  {
    LogE(kClassName, __func__, "setsockopt IP_HDRINCL error: %s\n",
         strerror(errno));
    CloseSockets();
    return false;
  }

  // Set the multicast interface for the transmit socket.
  struct in_addr  if_addr;
  if (inet_aton(config_.inbound_dev_ip_str().c_str(), &if_addr) == 0)
  {
    LogE(kClassName, __func__, "Error getting inbound dev IP Address.\n");
    CloseSockets();
    return false;
  }

  if (setsockopt(xmt_sock_, IPPROTO_IP, IP_MULTICAST_IF,
                 (const void*)&if_addr, sizeof(if_addr)) < 0)
  {
    LogE(kClassName, __func__, "setsockopt IP_MULTICAST_IF error: %s\n",
                 strerror(errno));
    CloseSockets();
    return false;
  }

  // Open the receive socket, a packet socket for receiving packets from the
  // kernel. Use SOCK_DGRAM for the type so we don't receive Ethernet
  // headers. Use ETH_P_IP, instead of ETH_P_ALL, for the protocol so that we
  // are only notified of incoming packets. Otherwise, we hear echos of the
  // packets that we transmit.
  if ((rcv_sock_ = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
  {
    LogE(kClassName, __func__, "socket error: %s\n", strerror(errno));
    CloseSockets();
    return false;
  }

  // Bind the receive socket to the identified interface.
  struct sockaddr_ll  bind_addr;
  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sll_family   = PF_PACKET;
  bind_addr.sll_ifindex  = if_nametoindex(config_.inbound_dev_name().c_str());
  bind_addr.sll_protocol = htons(ETH_P_IP);

  if (bind(rcv_sock_, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0)
  {
    LogE(kClassName, __func__, "bind error: %s\n", strerror(errno));
    CloseSockets();
    return false;
  }

  // Attach the Berkeley Packet Filter to the receive socket.
  struct sock_fprog*  bpf = config_.bpf();
  if (setsockopt(rcv_sock_, SOL_SOCKET, SO_ATTACH_FILTER, bpf, sizeof(*bpf))
      < 0)
  {
    LogE(kClassName, __func__, "setsockopt SO_ATTACH_FILTER error: %s\n",
         strerror(errno));
    CloseSockets();
    return false;
  }

  // Set the receive socket to non-blocking mode.
  if (fcntl(rcv_sock_, F_SETFL, fcntl(rcv_sock_, F_GETFL, 0) | O_NONBLOCK)
      < 0)
  {
    LogE(kClassName, __func__, "fcntl error: %s\n", strerror(errno));
    CloseSockets();
    return false;
  }

  if (!config_.external_plumbing())
  {
    List<string>&            add_rule_list = config_.iptables_add_rule_list();
    List<string>::WalkState  rule_ws;
    rule_ws.PrepareForWalk();

    string  rule;
    while (add_rule_list.GetNextItem(rule_ws, rule))
    {
      LogD(kClassName, __func__, "iptables rule: %s\n", rule.c_str());
      ExeSysCmd(rule.c_str());
    }
  }

  return true;
}

//============================================================================
bool EdgeIf::IsOpen() const
{
  return ((xmt_sock_ != kNoFd) && (rcv_sock_ != kNoFd));
}

//============================================================================
void EdgeIf::Close()
{
  CloseEdgeIf();
}

//============================================================================
ssize_t EdgeIf::Recv(Packet* pkt, const size_t offset)
{
  if (pkt == NULL)
  {
    LogF(kClassName, __func__, "Error: pkt was NULL\n");
    return -1;
  }

  ssize_t num_read = recvfrom(rcv_sock_, pkt->GetBuffer(offset),
                              pkt->GetMaxLengthInBytes() - offset, 0,
                              NULL, NULL);

  if (num_read < 0)
  {
    // Multiple Recv() calls are expected after a single indication from
    // select() that there is data to read, so don't log EAGAIN.
    if (errno != EAGAIN)
    {
      LogE(kClassName, __func__, "Failed to receive with error: %s\n",
	   strerror(errno));
    }
    pkt->SetLengthInBytes(0);
    return -1;
  }

  // Set the tentative packet length
  pkt->SetLengthInBytes(num_read);

  // Because of ethernet minimum size rules, the number read
  // may be bigger that the actual ipv4 packet. Adjust
  // accordingly
  
  size_t real_len;
  if (pkt->GetIpLen(real_len))
  {
    if (num_read != (ssize_t)real_len)
    {
      num_read = real_len;
      pkt->SetLengthInBytes(num_read);
    }
  }

  LogD(kClassName, __func__, "%zd bytes read.\n", num_read);
  return num_read;
}

//============================================================================
ssize_t EdgeIf::Send(const Packet* pkt)
{
  if (pkt == NULL)
  {
    LogF(kClassName, __func__, "Error: pkt was NULL\n");
    return -1;
  }

  uint16_t  dport;
  if (!pkt->GetDstPort(dport))
  {
    LogE(kClassName, __func__, "Error getting destination port.\n");
    return -1;
  }

  uint32_t  daddr;
  if (!pkt->GetIpDstAddr(daddr))
  {
    LogE(kClassName, __func__, "Error getting packet's destination "
         "address.\n");
    return -1;
  }

  struct sockaddr_in  addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_port        = dport;
  addr.sin_addr.s_addr = daddr;

  ssize_t  num_written;
  if ((num_written = sendto(xmt_sock_, pkt->GetBuffer(),
                            pkt->GetLengthInBytes(), 0,
                            (struct sockaddr*)&addr, sizeof(addr)))
      != static_cast<ssize_t>(pkt->GetLengthInBytes()))
  {
    LogE(kClassName, __func__, "sendto error: %s, wrote=%zd, expected=%zd\n",
         strerror(errno), num_written, pkt->GetLengthInBytes());
    return -1;
  }

  LogD(kClassName, __func__, "%zd bytes written to edge interface.\n",
       num_written);

  return num_written;
}

//============================================================================
void EdgeIf::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
  if (IsOpen())
  {
    if (rcv_sock_ > max_fd)
    {
      max_fd  = rcv_sock_;
    }

    FD_SET(rcv_sock_, &read_fds);
  }
}

//============================================================================
bool EdgeIf::InSet(fd_set* read_fds) const
{
  if (IsOpen())
  {
    return FD_ISSET(rcv_sock_, read_fds);
  }

  return false;
}

//============================================================================
void EdgeIf::CloseEdgeIf()
{
  if (IsOpen())
  {
    CloseSockets();

    if (!config_.external_plumbing())
    {
      List<string>&            del_rule_list = config_.iptables_del_rule_list();
      List<string>::WalkState  rule_ws;
      rule_ws.PrepareForWalk();

      string  rule;
      while (del_rule_list.GetNextItem(rule_ws, rule))
      {
        LogD(kClassName, __func__, "iptables rule: %s\n", rule.c_str());
        ExeSysCmd(rule.c_str());
      }
    }
  }
}

//============================================================================
void EdgeIf::CloseSockets()
{
  // Close the transmit socket.
  if (xmt_sock_ != kNoFd)
  {
    if (close(xmt_sock_) < 0)
    {
      LogE(kClassName, __func__, "Error closing transmit socket: %s.\n",
           strerror(errno));
    }
    xmt_sock_ = kNoFd;
  }

  // Close the receive socket.
  if (rcv_sock_ != kNoFd)
  {
    if (close(rcv_sock_) < 0)
    {
      LogE(kClassName, __func__, "Error closing receive socket: %s.\n",
           strerror(errno));
    }
    rcv_sock_ = kNoFd;
  }
}

//============================================================================
void EdgeIf::ExeSysCmd(const string& cmd) const
{
  LogD(kClassName, __func__, "Executing ==> %s\n", cmd.c_str());

  if (system(cmd.c_str()) == -1)
  {
    LogF(kClassName, __func__, "Error executing system cmd: %s\n",
         cmd.c_str());
    exit(-1);
  }
}
