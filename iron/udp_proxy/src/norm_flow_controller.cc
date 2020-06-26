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

#include "norm_flow_controller.h"
#include "udp_proxy.h"

#include <cerrno>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>

using ::iron::ConfigInfo;
using ::iron::FourTuple;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Time;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "NormFlowController";

  /// The default inbound dev name.
  const char*  kDefaultInboundDevName= "em2";

  /// The default periodic window update period, in milliseconds.
  const uint16_t  kWinUpdatePeriodMs = 100;

  /// The length of the IP and UDP headers, in bytes.
  const int  kCommonHdrLen = sizeof(struct iphdr) + sizeof(struct udphdr);

  /// The length of the NORM Common message header, in bytes.
  const int  kNormCommonHdrLen = 8;

  /// The payload length of Window Size packets, in bytes.
  const int  kWinSizeLen = 12;

  /// The payload length of Window Update packets, in bytes.
  const int  kWinUpdateLen = 16;

  /// The maximum shift for periodic window updates.
  const uint8_t  kMaxPerWinUpdateShift = 5;
}

uint32_t NormFlowController::inbound_dev_ip_ = 0;
bool     NormFlowController::initialized_    = false;

//============================================================================
NormFlowController::NormFlowController(UdpProxy& udp_proxy,
                                       PacketPool& packet_pool,
                                       const FourTuple& four_tuple,
                                       uint32_t max_queue_depth)
    : udp_proxy_(udp_proxy),
      packet_pool_(packet_pool),
      four_tuple_(four_tuple),
      max_queue_depth_(max_queue_depth),
      win_size_(max_queue_depth),
      first_pkt(true),
      win_update_time_(),
      tx_seq_num_(0),
      rcv_seq_num_nbo_(0),
      sent_seq_num_nbo_(0),
      per_win_update_shift_(0)
{
  win_update_time_.SetInfinite();
}

//============================================================================
NormFlowController::~NormFlowController()
{
  // Nothing to destroy.
}

//============================================================================
bool NormFlowController::Initialize(ConfigInfo& ci)
{
  if (!initialized_)
  {
    // Get the inbound device IP Address.
    string  inbound_dev_name = ci.Get("InboundDevName", kDefaultInboundDevName);

    int  temp_fd = -1;

    // Make sure that the provided device name isn't too large.
    if (inbound_dev_name.length() > IFNAMSIZ)
    {
      LogE(kClassName, __func__, "InboundDevName must be less than %d "
           "characters.\n", IFNAMSIZ);
      return false;
    }

    if ((temp_fd = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
    {
      LogW(kClassName, __func__, "Error creating socket.\n");
      return false;
    }

    struct ifreq  if_str;
    memset(&if_str, 0, sizeof(struct ifreq));
    strncpy(if_str.ifr_name, inbound_dev_name.c_str(), IFNAMSIZ - 1);
    if_str.ifr_name[IFNAMSIZ - 1] = '\0';

    int rv = ioctl(temp_fd, SIOCGIFADDR, &if_str);
    if (rv != 0)
    {
      LogE(kClassName, __func__, "FATAL ERROR: ioctl returned %d for specified "
           "device %s. \n", rv, inbound_dev_name.c_str());
      close(temp_fd);
      return false;
    }

    inbound_dev_ip_ =
      ((struct sockaddr_in*)&(if_str.ifr_addr))->sin_addr.s_addr;

    close(temp_fd);

    initialized_ = true;
  }

  return true;
}

//============================================================================
void NormFlowController::HandleRcvdPkt(const Packet* pkt)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "NORM flow controller for flow %s not "
         "initialized.\n", four_tuple_.ToString().c_str());
    return;
  }

  rcv_seq_num_nbo_ = ExtractNormSeqNum(pkt);

  if (first_pkt)
  {
    // This is the first packet that we have received for the NORM
    // flow. Initialize the headers that will be used for transmissions to the
    // NORM application, generate the window size packet, and send it to the
    // NORM application.
    SendWindowSizePkt();
    first_pkt = false;
  }
}

//============================================================================
void NormFlowController::HandleSentPkt(const Packet* pkt)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "NORM flow controller for flow %s not "
         "initialized.\n", four_tuple_.ToString().c_str());
    return;
  }

  // Extract the sequence number of the packet sent to the BPF,
  sent_seq_num_nbo_ = ExtractNormSeqNum(pkt);

  // generate and send a window information update message to the NORM
  // application, and
  SendWindowUpdatePkt();

  // Reset the periodic window update shift.
  per_win_update_shift_ = 0;

  // reset the time for the next periodic window information message.
  win_update_time_ = Time::Now() +
    Time::FromMsec(kWinUpdatePeriodMs);
}

//============================================================================
void NormFlowController::SvcEvents(Time& now)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "NORM flow controller for flow %s not "
         "initialized.\n", four_tuple_.ToString().c_str());
    return;
  }

  if (win_update_time_ < now)
  {
    WinUpdateTimeout();
  }
}

//============================================================================
void NormFlowController::UpdateEncodingRate(float encoding_rate)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "NORM flow controller for flow %s not "
         "initialized.\n", four_tuple_.ToString().c_str());
    return;
  }

  win_size_ = (max_queue_depth_ - 10) / encoding_rate;

  SendWindowSizePkt();
}

//============================================================================
uint16_t NormFlowController::ExtractNormSeqNum(const Packet* pkt)
{
  // The NORM sequence number is in the NORM Common Message Header (documented
  // in RFC 5740), as depicted below:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |version|  type |    hdr_len |             sequence             |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                           source_id                           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  // The NORM sequence number is 2 bytes offset from the start of the received
  // Packet's payload.
  uint16_t  seq_num;
  size_t    offset = pkt->GetIpPayloadOffset() + 2;
  memcpy(&seq_num, (void*)(pkt->GetBuffer(offset)), sizeof(seq_num));

  return seq_num;
}

//============================================================================
void NormFlowController::WinUpdateTimeout()
{
  SendWindowUpdatePkt();

  per_win_update_shift_++;
  if (per_win_update_shift_ > kMaxPerWinUpdateShift)
  {
    per_win_update_shift_ = kMaxPerWinUpdateShift;
  }

  // Reset the time for the next periodic window update message.
  win_update_time_ = Time::Now() +
    Time::FromMsec(kWinUpdatePeriodMs << per_win_update_shift_);
}

//============================================================================
void NormFlowController::AddPktHdrs(Packet* pkt, size_t& offset,
                                    size_t pyld_len)
{
  // Fill in the IP Header.
  struct iphdr  ip_hdr;
  memset((void*)&ip_hdr, 0, sizeof(struct iphdr));
  ip_hdr.ihl      = 5;
  ip_hdr.version  = 4;
  ip_hdr.tos      = 0;
  ip_hdr.tot_len  = htons(sizeof(struct iphdr) + sizeof(struct udphdr) +
                           pyld_len);
  ip_hdr.id       = 0;
  ip_hdr.frag_off = 0;
  ip_hdr.ttl      = 255;
  ip_hdr.protocol = IPPROTO_UDP;
  ip_hdr.check    = 0;
  ip_hdr.saddr    = inbound_dev_ip_;
  ip_hdr.daddr    = four_tuple_.dst_addr_nbo();

  // Fill in the UDP Header.
  struct udphdr  udp_hdr;
  memset((void*)&udp_hdr, 0, sizeof(struct udphdr));
  udp_hdr.source = four_tuple_.src_port_nbo();
  udp_hdr.dest   = four_tuple_.dst_port_nbo();
  udp_hdr.len    = htons(sizeof(struct udphdr) + pyld_len);
  udp_hdr.check  = 0;

  // Add the IP Header to the packet.
  uint8_t*  buf = pkt->GetBuffer(offset);

  memcpy(buf, (void*)&ip_hdr, sizeof(struct iphdr));
  buf    += sizeof(struct iphdr);
  offset += sizeof(struct iphdr);

  // Add the UDP Header to the packet.
  memcpy(buf, (void*)&udp_hdr, sizeof(struct udphdr));
  buf    += sizeof(struct udphdr);
  offset += sizeof(struct udphdr);
}

//============================================================================
void NormFlowController::SendWindowSizePkt()
{
  // Window Size packet payloads have the following format:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |version|type=7 |    hdr_len    |          sequence             |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                           source_id                           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  subtype=1    |   reserved    |        window size            |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //  8 bytes : NORM Common Message Header (includes version, type, header
  //            length, sequence number, and source id as described in RFC
  //            5740).
  //  1 byte  : Flow control subtype
  //  1 byte  : Reserved
  //  2 bytes : Window size, in packets
  // ---------
  // 12 bytes

  // Get a packet from the packet pool.
  Packet*  pkt    = packet_pool_.Get();
  size_t  offset = 0;

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Error retrieving packet from packet pool.\n");
    return;
  }

  // Add the IP and UDP Headers to the packet.
  AddPktHdrs(pkt, offset, kNormCommonHdrLen + kWinSizeLen);

  // Add the NORM Common Message Header data to the send buffer.
  AddNormCommonMsgHdrData(pkt, offset);

  // Get pointer to the packet payload.
  uint8_t*  buf = pkt->GetBuffer(offset);

  // Add the subtype field.
  uint8_t  subtype = 1;
  memcpy(buf, &subtype, sizeof(subtype));
  buf    += sizeof(subtype);
  offset += sizeof(subtype);

  // Skip over reserved byte.
  buf    += sizeof(uint8_t);
  offset += sizeof(uint8_t);

  // Add the Window Size fields.
  uint16_t  win_size_nbo = htons(win_size_);
  memcpy(buf, &win_size_nbo, sizeof(win_size_nbo));

  // Update the checksums in the newly created packet,
  pkt->UpdateChecksums();

  // set the length of the packet, and
  pkt->SetLengthInBytes(kCommonHdrLen + kNormCommonHdrLen + kWinSizeLen);

  // instruct the UDP Proxy to transmit the packet out the LAN-facing
  // interface.
  ssize_t  bytes_sent = udp_proxy_.SendToLan(pkt);
  if (bytes_sent == 0)
  {
    // Transmission failed, recycle packet.
    LogE(kClassName, __func__, "Error sending Window Size packet.\n");
    packet_pool_.Recycle(pkt);
  }

  LogD(kClassName, __func__, "Sent Window Size packet with a length of "
       "%zu bytes to NORM application.\n", bytes_sent);
}

//============================================================================
void NormFlowController::SendWindowUpdatePkt()
{
  // Window Update packet payloads have the following format:
  //
  //  0                   1                   2                   3
  //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |version|type=7 |    hdr_len    |          sequence             |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |                           source_id                           |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |  subtype=2    |   reserved    |        window size            |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  // |         rcv seq num           |      sent seq num             |
  // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  //
  //  8 bytes : NORM Common Message Header (includes version, type, header
  //            length, sequence number, and source id as described in RFC
  //            5740).
  //  1 byte  : Flow control subtype
  //  1 byte  : Reserved
  //  2 bytes : Window size, in packets
  //  2 bytes : rcv seq num - the NORM sequence number from the last
  //            received NORM packet
  //  2 bytes : sent seq num - the NORM sequence number of the NORM packet
  //            that has been sent to the BPF
  // ---------
  // 16 bytes

  // Get a packet from the packet pool.
  Packet*  pkt    = packet_pool_.Get();
  size_t  offset = 0;

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Error retrieving packet from packet pool.\n");
    return;
  }

  // Add the IP and UDP Headers to the packet.
  AddPktHdrs(pkt, offset, kNormCommonHdrLen + kWinUpdateLen);

  // Add the NORM Common Message Header data to the send buffer.
  AddNormCommonMsgHdrData(pkt, offset);

  // Get pointer to the packet payload.
  uint8_t*  buf = pkt->GetBuffer(offset);

  // Add the subtype field.
  uint8_t  subtype = 2;
  memcpy(buf, &subtype, sizeof(subtype));
  buf    += sizeof(subtype);
  offset += sizeof(subtype);

  // Skip over reserved byte.
  buf    += sizeof(uint8_t);
  offset += sizeof(uint8_t);

  // Add the Window Update fields.
  uint16_t  win_size_nbo = htons(win_size_);
  memcpy(buf, &win_size_nbo, sizeof(win_size_nbo));
  buf    += sizeof(win_size_);
  offset += sizeof(win_size_);

  memcpy(buf, &rcv_seq_num_nbo_, sizeof(rcv_seq_num_nbo_));
  buf    += sizeof(rcv_seq_num_nbo_);
  offset += sizeof(rcv_seq_num_nbo_);

  memcpy(buf, &sent_seq_num_nbo_, sizeof(sent_seq_num_nbo_));

  // Update the checksums in the newly created packet,
  pkt->UpdateChecksums();

  // set the length of the packet, and
  pkt->SetLengthInBytes(kCommonHdrLen + kNormCommonHdrLen + kWinUpdateLen);

  // instruct the UDP Proxy to transmit the packet out the LAN-facing
  // interface.
  ssize_t  bytes_sent = udp_proxy_.SendToLan(pkt);
  if (bytes_sent == 0)
  {
    // Transmission failed, recycle packet.
    LogE(kClassName, __func__, "Error sending Window Update packet.\n");
    packet_pool_.Recycle(pkt);
  }

  LogD(kClassName, __func__, "Sent Window Update packet with a length of "
       "%zu bytes to NORM application.\n", bytes_sent);
}

//============================================================================
void NormFlowController::AddNormCommonMsgHdrData(Packet* pkt, size_t& offset)
{
  uint8_t*  buf = pkt->GetBuffer(offset);

  // Add the NORM version and type.
  uint8_t  norm_vt = (1 << 4) | 7;
  memcpy(buf, &norm_vt, sizeof(uint8_t));
  buf    += sizeof(uint8_t);
  offset += sizeof(uint8_t);

  // Add the header length.
  uint8_t  hdr_len = 2;
  memcpy(buf, &hdr_len, sizeof(uint8_t));
  buf    += sizeof(uint8_t);
  offset += sizeof(uint8_t);

  // Add the sequence number.
  uint16_t  seq_nbo = htons(tx_seq_num_++);
  memcpy(buf, &seq_nbo, sizeof(uint16_t));
  buf    += sizeof(uint16_t);
  offset += sizeof(uint16_t);

  // Add the source id. We will use the inbound_dev_ip_ for this.
  memcpy(buf, &inbound_dev_ip_, sizeof(inbound_dev_ip_));
  buf    += sizeof(inbound_dev_ip_);
  offset += sizeof(inbound_dev_ip_);
}
