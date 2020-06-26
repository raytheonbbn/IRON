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

#ifndef IRON_UDP_PROXY_NORM_FLOW_CONTROLLER_H
#define IRON_UDP_PROXY_NORM_FLOW_CONTROLLER_H

#include "config_info.h"
#include "four_tuple.h"
#include "itime.h"
#include "packet.h"
#include "packet_pool.h"

#include <netinet/ip.h>
#include <netinet/udp.h>

class UdpProxy;

/// \brief A flow controller for NORM multicast flows.
///
/// The NORM flow controller advertises a window size, in units of packets,
/// back to the NORM application when the first packet for the flow is
/// received. Each time that the UDP Proxy admits a packet to the BPF, a window
/// update packet is transmitted to the NORM application indicating the most
/// recently received NORM packet sequence number and the NORM packet sequence
/// number that was just admitted to the BPF. This information enables the
/// NORM application to compute the flow control window available.
class NormFlowController
{
  public:

  /// \brief Default constructor.
  ///
  /// \param  udp_proxy        Reference to the UDP Proxy.
  /// \param  packet_pool      Reference to the UDP Proxy packet pool.
  /// \param  four_tuple       The 4-tuple associated with the NORM flow.
  /// \param  max_queue_depth  The maximum depth of the encoded packets queue,
  ///                          in packets.
  NormFlowController(UdpProxy& udp_proxy,
                     iron::PacketPool& packet_pool,
                     const iron::FourTuple& four_tuple,
                     uint32_t max_queue_depth);

  /// \brief Destructor.
  virtual ~NormFlowController();

  /// \brief Initialize the state shared by the NORM flow controllers.
  ///
  /// \param  ci  The configuration information.
  ///
  /// \return True if the initialization is successful, false otherwise.
  static bool Initialize(iron::ConfigInfo& ci);

  /// \brief Extract the NORM sequence number from the received packet.
  ///
  /// \param  pkt  The received packet.
  void HandleRcvdPkt(const iron::Packet* pkt);

  /// \brief Extract the NORM sequence number from the packet to be sent to
  ///        the BPF.
  ///
  /// \param  pkt  The received packet.
  void HandleSentPkt(const iron::Packet* pkt);

  /// \brief Service the NORM flow controller events.
  ///
  /// \param  now  The current time.
  void SvcEvents(iron::Time& now);

  /// \brief Update the flow's FEC encoding rate.
  ///
  /// The flow control window advertised back to the NORM application is a
  /// function of the encoding rate for the flow, as the encoding queue
  /// contains both original and repair packets.
  ///
  /// \param  encoding_rate  The flow's encoding rate.
  void UpdateEncodingRate(float encoding_rate);

  /// The UDP socket use to transmit flow control packets to the NORM
  /// application. There will be a single socket shared amongst all NORM flow
  /// controllers.
  static int       sock_;

  /// The IP Address, in network byte order, of the inbound device. This will
  /// be used for the source id field of the NORM Common Message Header field.
  static uint32_t  inbound_dev_ip_;

  /// Remembers if the shared NORM flow controller information (sock_,
  /// inbound_dev_ip_) has been initialized.
  static bool      initialized_;

  private:

  /// \brief Default constructor.
  NormFlowController();

  /// \brief Copy constructor.
  NormFlowController(const NormFlowController& nfc);

  /// \brief Assignment operator.
  NormFlowController& operator=(const NormFlowController& nfc);

  /// \brief Extract the NORM sequence number from the packet.
  ///
  /// \brief  pkt  The packet containing the NORM sequence number.
  ///
  /// \return The NORM sequence number, extracted from the packet.
  uint16_t ExtractNormSeqNum(const iron::Packet* pkt);

  /// \brief Generates and transmits a Window Update packet to the NORM
  ///        application if the periodic timer expires.
  void WinUpdateTimeout();

  /// \brief Add the headers (IP and UDP) to the packet.
  ///
  /// \param  pkt       The packet that is being generated.
  /// \param  offset    Offset into the packet buffer.
  /// \param  pyld_len  The packet's payload length.
  void AddPktHdrs(iron::Packet* pkt, size_t& offset, size_t pyld_len);

  /// \brief Generate a window size packet and send it to the NORM
  ///        application.
  ///
  /// The window size packet is used to convey the flow's receive window size,
  /// in packets, to the NORM application.
  void SendWindowSizePkt();

  /// \brief Generate a window update packet and send it to the NORM
  ///        application.
  ///
  /// The NORM window update packet includes the sequence number of the most
  /// recently received NORM packet and the sequence number of the NORM packet
  /// most recently sent to the BPF.
  void SendWindowUpdatePkt();

  /// \brief Add the NORM Common Message Header data to the packet.
  ///
  /// \param  pkt     The packet that is being generated.
  /// \param  offset  Offset into the packet buffer.
  void AddNormCommonMsgHdrData(iron::Packet* pkt, size_t& offset);

  /// Reference to the UDP Proxy.
  UdpProxy&          udp_proxy_;

  /// Reference to the packet pool.
  iron::PacketPool&  packet_pool_;

  /// The 4-tuple associated with the NORM flow.
  iron::FourTuple    four_tuple_;

  /// The maximum size of the encoded packets queue, in packets.
  uint32_t           max_queue_depth_;

  /// The size of the flow control window, in packets.
  uint16_t           win_size_;

  /// The encoding rate for the flow.
  float              encoding_rate_;

  /// Remembers if the received packet is the first packet received.
  bool               first_pkt;

  /// The next time that a periodic window information update message will be
  /// sent to the NORM application. This time is rescheduled each time that a
  /// packet is sent to the BPF.
  iron::Time         win_update_time_;

  /// The monotonically increasing sequence number included in messages sent
  /// to the NORM application.
  uint16_t           tx_seq_num_;

  /// The sequence number of the NORM packet most recently received, in
  /// network byte order.
  uint16_t           rcv_seq_num_nbo_;

  /// The sequence number of the NORM packet most recently sent to the BPF, in
  /// network byte order.
  uint16_t           sent_seq_num_nbo_;

  /// The periodic window update message shift. This increases the time
  /// between successive periodic window updates.
  uint8_t            per_win_update_shift_;

};  // end class NormFlowController

#endif  // IRON_UDP_PROXY_NORM_FLOW_CONTROLLER_H
