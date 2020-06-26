//============================================================================
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
//============================================================================

#ifndef IRON_TCP_PROXY_SOCKET_H
#define IRON_TCP_PROXY_SOCKET_H

#include "bin_map.h"
#include "inter_process_comm.h"
#include "ipv4_endpoint.h"
#include "iron_types.h"
#include "itime.h"
#include "out_seq_buffer.h"
#include "packet_fifo.h"
#include "pkt_info_pool.h"
#include "send_buffer.h"
#include "tcp_proxy_config.h"
#include "utility_fn_if.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <string>

#include <netinet/ip.h>
#include <netinet/in.h>

class CongCtrlAlg;
class TcpProxy;
class SocketMgr;

// The minimum RTT variance.
#define MIN_RTTVAR 0

// Macros for packet sequence number comparisons.
#define SEQ_LT(a,b)   ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)  ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)   ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)  ((int)((a)-(b)) >= 0)

// Max and min macros.
#ifndef MAX
#define MAX(a,b) ((((int) ((a)-(b)))>0) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b) ((((int)((a) - (b))) < 0) ? (a) : (b))
#endif

// TCP states not defined in tcp.h.
#define TCP_NASCENT           0	// socket just created

// sock_flags_ values.
#define SOCK_NDELAY      0x0001  // flag to indicate whether to delay before coalese
#define SOCK_DELACK      0x0010  // flag to indicate that delayed ack is used
#define TF_RCVD_SCALE    0x0020  // flag to indicate that we received window scale
#define TF_RCVD_TSTMP    0x0040  // flag to indicate that we received timestamp
#define TF_RCVD_SACK     0x0080  // flag to indicate that we received SACK request
#define TF_REQ_SCALE     0x0100  // have/will request window scaling
#define TF_REQ_TSTMP     0x0200  // have/will request timestamps
#define TF_REQ_SACK      0x0400  // have/will request SACK
#define TF_CC_LINEAR     0x0800  // 1 = linear cong. ctl, 0 = exponential
#define TF_TSTMPING      0x0140L // TF_REQ_TSTMP | TF_RCFD_TSTMP
#define SOCK_ACKNOW      0x10000 // 1 = ACK immediately
#define SOCK_CANACK      0x20000 // 1 = ACK if input queue has been drained

// Macro to compute the header length of a data packet at run-time. Note
// that this assumes that the only option accompanying a data packet is a
// timestamp, and that a timestamp will accompany ALL data packets.
#define TP_HDR_LEN (((sock_flags_ & (TF_TSTMPING)) == (TF_TSTMPING)) ? (12) : (0))

/// Proxy Protocol Capabilities.
#define CAP_TIMESTAMP    1
#define CAP_SACK         2
#define CAP_CONGEST      4

#define FUNCT_HIGH_CONGESTION_SEQ  0x0001
#define FUNCT_HIGH_SEQ             0x0002
#define FUNCT_REL_SEQ_NUM_URG_PTR  0x0004

/// The smoothed round-trip time and estimated variance are stored as fixed
/// point numbers scaled by the values below. For convenience, these scales are
/// also used in smoothing the average (smoothed = (1/scale)sample +
/// ((scale-1)/scale)smoothed). With these scales, srtt has 3 bits to the right
/// of the binary point, and thus an "ALPHA" of 0.875. rttvar has 2 bits to the
/// right of the binary point, and is smoothed with an ALPHA of 0.75.
#define TCP_RTT_SHIFT     3        /* shift for srtt; 3 bits frac. */
#define TCP_RTTVAR_SHIFT  2        /* multiplier for rttvar; 2 bits */

/// TCP VJ congestion control constants.
#define DUPACK_THRESH        3

// Congestion control algorithms.
#define NO_CONGESTION_CONTROL  0
#define VJ_CONGESTION_CONTROL  1
#define MAX_CC_ALG_CNT         2

#define PROXY_SEND_SYN         1
#define PROXY_SEND_FIN         2

#define PROXY_MAX_BURST        50

#define MSS_DEFAULT            512
#define MSS_MIN                32

/// The minimum send rate, in bps.
#define kMinSendRate 10000.0

namespace
{
  /// The maximum TCP option length.
  const size_t  kMaxTcpOptLen = 40;
}

/// \brief Encapsulates the state for one of the TCP Proxy's sockets.
///
/// For each TCP flow, a pair of Socket objects are created. One Socket faces
/// the LAN side and the other faces the WAN side. This occurs in both the
/// local and remote TCP Proxy. So a single TCP flow is implemented by a total
/// of 4 Socket objects in the TCP Proxies. The following example illustrates
/// the addresses and ports that are utilized for an example TCP flow.
///
/// Consider the following example:
///   an ssh session from 172.24.1.1:29778 to 172.24.2.1:22
///
/// for the following topology:
///
///   node0 --- node3 --- node4 --- node1
///
/// where node0 is the host from which the ssh command is executed and node1
/// is the target for the ssh command. node3 and node4 are running the TCP
/// Proxy.
///
/// The state of the Sockets on node3 and node4 for the example ssh
/// connection are as follows:
///
///                        node3                             node4
///            Passive Socket  Active Socket     Passive Socket  Active Socket
///            --------------  -------------     --------------  -------------
///   myAddr     172.24.2.1      172.24.1.1        172.24.2.1      172.24.1.1
///   hisAddr    172.24.1.1      172.24.2.1        172.24.1.1      172.24.2.1
///   myPort     22              29778             22              29778
///   hisPort    29778           22                29778           22
///   cfgIfId    LAN             WAN               WAN             LAN
///
/// The Passive Socket and Active Socket on node3 are peers of each other (as
/// are the sockets on node4).
///
/// Note that the IRON utility function definitions are stored in the WAN
/// facing sockets, the Active Socket on node3 and the Passive Socket on node4
/// in the above example. The commands received from the IRON Admission
/// Planner MUST match the LAN facing socket 4-tuples. This means that when
/// searching for a socket that matches an Admission Planner flow
/// modification, the found socket (if it exists) must be on the LAN
/// side. Once found, the LAN side socket's peer (the WAN side socket) is the
/// socket that gets modified.
class Socket
{
  public:

  /// TCP Pseudo Header structure.
  struct PseudoHeader
  {
    struct in_addr  src;
    struct in_addr  dst;
    uint8_t         mbz;
    uint8_t         protocol;
    uint16_t        length;
    uint16_t        checksum;
    uint16_t        upper_seq_num; // For compression
  };

  /// \brief Constructor.
  ///
  /// \param  tcp_proxy      TCP Proxy instance.
  /// \param  packet_pool    Pool containing packets to use.
  /// \param  bin_map        Bin Map used to determine mcast vs unicast
  /// \param  pkt_info_pool  The PktInfo pool.
  /// \param  proxy_config   TCP Proxy configuration information.
  /// \param  socket_mgr     Manager of TCP Proxy sockets.
  Socket(TcpProxy& tcp_proxy, iron::PacketPool& packet_pool,
         iron::BinMap& bin_map,
         PktInfoPool& pkt_info_pool, TcpProxyConfig& proxy_config,
         SocketMgr& socket_mgr);

  /// \brief Destructor.
  virtual ~Socket();

  /// \brief Process a received TCP packet.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  /// \param  ip_hdr    The received IP header.
  ///
  /// \return
  int ProcessPkt(PktInfo* pkt_info, const struct tcphdr* tcp_hdr,
                 const struct iphdr* ip_hdr);

  /// \brief Construct the packet headers in an IRON Packet object.
  ///
  /// \param  pkt_info      The PktInfo into which to place the constructed IP
  ///                       and TCP headers. If NULL, one will be retrieved
  ///                       from the PktInfo pool.
  /// \param  push          If the value is 1, TH_PUSH will be set in the TCP
  ///                       header's flags field. If the value is 0, TH_PUSH
  ///                       will not be set in the TCP header's flags field.
  /// \param  use_seq_sent  If true the sequence number is adjusted according
  ///                       to SYN and FIN rules. Otherwise the seq number is
  ///                       the usual sequence number -- i.e., the sequence
  ///                       number for the next sequence number.
  ///
  /// \return The PktInfo that contains the constructed packet headers.
  PktInfo* BuildHdr(PktInfo* pkt_info, int push, bool use_seq_sent);

  /// \brief Send a TCP packet.
  ///
  /// \param  arg_pkt_info  The provided packet to send.
  /// \param  force         Flag that controls if the packet is immediately
  ///                       sent.
  ///
  /// \return The number of bytes that are sent.
  uint32_t Send(PktInfo* arg_pkt_info, bool force);

  /// \brief Construct an ACK and send it.
  void BuildAndSendAck();

  /// \brief Service the socket's events.
  ///
  /// \param  now  The current time.
  void SvcEvents(iron::Time& now);

  /// \brief Cancel the delayed ack event.
  void CancelDelayedAckEvent();

  /// \brief Actively open a connection to a particular destination.
  ///
  /// \return True if successful, false if an error occurs.
  bool Connect();

  /// \brief Close the Socket.
  ///
  /// Send a FIN on a particular port. Only works if the Socket is open.
  ///
  /// \return True if the close is successful, false if an error occurs.
  bool Close();

  /// \brief Abort a connection.
  int Abort();

  /// \brief Configure the socket's utility function.
  ///
  /// This initializes and configures the specific utility function
  /// based on a string of colon-separated key:value pairs.
  ///
  /// \param  utility_def  The utility function definition.
  /// \param  queue_depths  Reference to the QueueDepths object.
  void ConfigureUtilityFn(std::string utility_def,
                          iron::QueueDepths& queue_depths);

  /// \brief Reset the socket's utility function.
  ///
  /// This happens when a remote control message is received to update the
  /// flow/service definition that affects this socket.
  ///
  /// \param  utility_def   The utility function definition.
  /// \param  queue_depths  Reference to the QueueDepths object.
  void ResetUtilityFn(std::string utility_def,
                      iron::QueueDepths& queue_depths);

  /// \brief Update the priority of the utility function for this socket.
  ///
  /// \param priority The new priority for this flow..
  inline void UpdatePriority(double priority)
  {
    if (flow_utility_fn_)
    {
      flow_utility_fn_->set_priority(priority);
    }
  }

  /// \brief Stop admitting packets for a flow.
  ///
  /// This happens when a remote control message is received with an
  /// off_flow command.
  void TurnFlowOff();

  /// \brief Ask the Socket's Admission Controller if a packet can be
  /// admitted.
  ///
  /// \param  now  The current time.
  ///
  /// \return True if a packet can be admitted, false otherwise.
  bool CanAdmitPacket(iron::Time& now);

  /// \brief Send the Packet on the Socket.
  ///
  /// \param  pkt_info  The Packet (and associated metadata) containing the
  ///                   bytes to be written.
  ///
  /// \return The number of bytes written.
  int Write(PktInfo* pkt_info);

  /// \brief Adjust tcp header as needed by peer socket and insert the options
  void UpdateHeaderForMoveToPeer(PktInfo* pkt_info);

  /// \brief Close the peer socket if its time to do so.
  void CheckAndClosePeerIfWarranted();

  /// \brief Send any pending data.
  void Flush();

  /// \brief Reset the state of the Socket.
  ///
  /// \param  tcp_hdr  The received TCP header.
  void Reset(const struct tcphdr* tcp_hdr);

  /// \brief Configure the Proxy options for the Socket.
  void SetProxyOptions();

  /// \brief Perform the provisional MSS setup for the Socket.
  ///
  /// \param  offer  The remote side's offered MSS.
  void SetMss(uint32_t offer);

  /// \brief Compute the header length of a data packet at run-time.
  ///
  /// Note that this assumes that the only option accompanying a data packet
  /// is a timestamp, and that the timestamp will accompany ALL data packets.
  ///
  /// \return The header length of a data packet at run-time.
  int GetTcpHdrLen();

  /// \brief Update the Socket's scheduled admission event.
  ///
  /// \param  now  The current time.
  void UpdateScheduledAdmissionEvent(iron::Time& now);

  /// Set the IRON Bin Index associated with the socket.
  ///
  /// \param  bin_idx  The IRON Bin Index associated with the socket.
  inline void set_bin_idx(iron::BinIndex bin_idx)
  {
    bin_idx_ = bin_idx;
  }

  /// Get the IRON Bin Index associated with the socket.
  ///
  /// \return The IRON Bin Index associated with the socket.
  inline iron::BinIndex bin_idx() const
  {
    return bin_idx_;
  }

  /// \brief Set the tag used to uniquely identify the flow.
  ///
  /// \param  tag  The tag used for the flow.
  inline void set_flow_tag(uint32_t tag)
  {
    flow_tag_ = tag;
  }

  /// \brief Get the socket's configuration interface id.
  ///
  /// \return The socket's configuration interface id.
  inline void set_cfg_if_id(ProxyIfType cfg_if_id)
  {
    cfg_if_id_ = cfg_if_id;
    if (cfg_if_id_ == WAN)
    {
      snprintf(flow_id_str_, 63, "fid: %" PRIu32 " IF: WAN", flow_tag_);
    }
    else
    {
      snprintf(flow_id_str_, 63, "fid: %" PRIu32 " IF: LAN", flow_tag_);
    }
  }

  /// \brief Get the socket's configuration interface id.
  ///
  /// \return The socket's configuration interface id.
  ProxyIfType cfg_if_id() const
  {
    return cfg_if_id_;
  }

  /// \brief Get a reference to the socket flags.
  ///
  /// \return A reference to the socket flags.
  inline uint32_t& sock_flags()
  {
    return sock_flags_;
  }

  /// \brief Set the active state of the socket.
  ///
  /// \param  is_active  True if the socket is active, false otherwise.
  inline void set_is_active(bool is_active)
  {
    is_active_ = is_active;
  }

  /// \brief Query the active state of the socket.
  ///
  /// \return True if the socket is active, false otherwise.
  inline bool is_active() const
  {
    return is_active_;
  }

  /// \brief Get a reference to the socket's local address for the
  /// connection.
  ///
  /// \return A reference to the socket's local address for the connection.
  struct in_addr& my_addr()
  {
    return my_addr_;
  }

  /// \brief Get a reference to the socket's remote address for the
  /// connection.
  ///
  /// \return A reference to the socket's remote address for the connection.
  struct in_addr& his_addr()
  {
    return his_addr_;
  }

  /// \brief Set the socket's local port for the connection.
  ///
  /// \param  port  The socket's local port for the connection.
  void set_my_port(uint16_t port)
  {
    my_port_ = port;
  }

  /// \brief Get the socket's local port for the connection.
  ///
  /// \return The socket's local port for the connection.
  uint16_t my_port() const
  {
    return my_port_;
  }

  /// \brief Set the socket's remote port for the connection.
  ///
  /// \param  port  The socket's remote port for the connection.
  void set_his_port(uint16_t port)
  {
    his_port_ = port;
  }

  /// \brief Get the socket's remote port for the connection.
  ///
  /// \return The socket's remote port for the connection.
  uint16_t his_port() const
  {
    return his_port_;
  }

  /// \brief Get a reference to the IP header template.
  ///
  /// \return A reference to the IP header template.
  inline struct iphdr& t_template()
  {
    return t_template_;
  }

  /// \brief Set the flag that indicates seamless server handoff is active for
  /// the socket.
  inline void set_do_seamless_handoff()
  {
    do_seamless_handoff_ = true;
  }

  /// \brief Set the seamless handoff endpoint.
  ///
  /// \param  endpoint  The seamless handoff endpoint.
  inline void set_seamless_handoff_endpoint(iron::Ipv4Endpoint endpoint)
  {
    seamless_handoff_endpoint_ = endpoint;
  }

  /// \brief Set the client configured server endpoint.
  ///
  /// \param  endpoint  The client configured server endpoint.
  inline void set_client_configured_server_endpoint(iron::Ipv4Endpoint endpoint)
  {
    client_configured_server_endpoint_ = endpoint;
  }

  /// \brief Set the flag that remembers that the socket supports a tunneled
  /// flow.
  inline void set_is_tunneled()
  {
    is_tunneled_ = true;
  }

  /// \brief Query if the socket is supporting a tunneled flow.
  ///
  /// \return True if the socket is supporting a tunneled flow, false
  ///         otherwise.
  inline bool is_tunneled() const
  {
    return is_tunneled_;
  }

  /// \brief Get the tunnel headers.
  ///
  /// \return A pointer to the tunnel headers.
  uint8_t* tunnel_hdrs()
  {
    return tunnel_hdrs_;
  }

  /// \brief Invert the tunnel headers.
  ///
  /// IRON currently only supports VXLAN tunnels. This will swap:
  ///   - the source and destination addresses in the outer IPv4 header
  ///   - the destination and source MAC addresses in the inner Ethernet
  ///     header
  void InvertTunnelHdrs();

  /// \brief Get a pointer to the socket's send buffer.
  ///
  /// \return A pointer to the socket's send buffer.
  inline SendBuffer* send_buf()
  {
    return send_buf_;
  }

  /// \brief Set the socket's peer.
  ///
  /// \param  peer  The socket's peer.
  inline void set_peer(Socket* peer)
  {
    peer_ = peer;
  }

  /// \brief Get the socket's peer.
  ///
  /// \return A pointer to the socket's peer.
  inline Socket* peer()
  {
    return peer_;
  }

  /// \brief Get a reference to the gateway flags.
  ///
  /// \return A reference to the gateway flags.
  inline int& gw_flags()
  {
    return gw_flags_;
  }

  /// \brief Set the socket's TOS value.
  ///
  /// \param  tos  The socket's TOS value.
  inline void set_tos(uint8_t tos)
  {
    tos_ = tos;
  }

  /// \brief Get the socket's TOS value.
  ///
  /// \return The socket's TOS value.
  inline uint8_t tos() const
  {
    return tos_;
  }

  /// \brief Set the socket's desired DSCP value.
  ///
  /// \param  desired_dscp  The socket's desired DSCP value.
  inline void set_desired_dscp(int8_t desired_dscp)
  {
    desired_dscp_ = desired_dscp;
  }

  /// \brief Get the socket's desired DSCP value.
  ///
  /// \return The socket's desired DSCP value.
  inline int8_t desired_dscp() const
  {
    return desired_dscp_;
  }

  /// \brief Set the socket's state.
  ///
  /// \param  state  The socket's state.
  inline void set_state(int16_t state)
  {
    state_ = state;
  }

  /// \brief Get the socket's state.
  ///
  /// \return The socket's state.
  inline int16_t state() const
  {
    return state_;
  }

  /// \brief Set the socket's previous state.
  ///
  /// \param  prev_state  The socket's previous state.
  inline void set_prev_state(int16_t prev_state)
  {
    prev_state_ = prev_state;
  }

  /// \brief Set the socket's initial sequence number.
  ///
  /// \param  initial_seq_num  The socket's initial sequence number.
  inline void set_initial_seq_num(uint32_t initial_seq_num)
  {
    initial_seq_num_ = initial_seq_num;
  }

  /// \brief Get the socket's initial sequence number.
  ///
  /// \return The socket's initial sequence number.
  inline uint32_t initial_seq_num() const
  {
    return initial_seq_num_;
  }

  /// \brief Set the socket's sequence number.
  ///
  /// \param  seq_num  The socket's sequence number.
  inline void set_seq_num(uint32_t seq_num)
  {
    seq_num_ = seq_num;
  }

  /// \brief Set the socket's send una sequence number.
  ///
  /// \param  snd_una  The socket's send una sequence number.
  inline void set_snd_una(uint32_t snd_una)
  {
    snd_una_ = snd_una;
  }

  /// \brief Get the socket's send una sequence number.
  ///
  /// \return The socket's send una sequence number.
  inline uint32_t snd_una() const
  {
    return snd_una_;
  }

  /// \brief Set the socket's sequence sent sequence number.
  ///
  /// \param  seq_sent  The socket's sequence sent sequence number.
  inline void set_seq_sent(uint32_t seq_sent)
  {
    seq_sent_ = seq_sent;
  }

  /// \brief Get the socket's sequence sent sequence number.
  ///
  /// \return The socket's sequence sent sequence number.
  inline uint32_t seq_sent() const
  {
    return seq_sent_;
  }

  /// \brief Set the socket's maximum sequence sent sequence number.
  ///
  /// \param  snd_max  The socket's maximum sequence sent sequence number.
  inline void set_snd_max(uint32_t snd_max)
  {
    snd_max_ = snd_max;
  }

  /// \brief Get the socket's maximum sequence sent sequence number.
  ///
  /// \return The socket's maximum sequence sent sequence number.
  inline uint32_t snd_max() const
  {
    return snd_max_;
  }

  /// \brief Set the socket's high sequence number.
  ///
  /// \param  high_seq  The socket's high sequence number.
  inline void set_high_seq(uint32_t high_seq)
  {
    high_seq_ = high_seq;
  }

  /// \brief Get the socket's high sequence number.
  ///
  /// \return The socket's high sequence number.
  inline uint32_t high_seq() const
  {
    return high_seq_;
  }

  /// \brief Set the socket's high congestion sequence number.
  ///
  /// \param  high_cong_seq  The socket's high congestion sequence number.
  inline void set_high_cong_seq(uint32_t high_cong_seq)
  {
    high_cong_seq_ = high_cong_seq;
  }

  /// \brief Get the socket's high congestion sequence number.
  ///
  /// \return The socket's high congestion sequence number.
  inline uint32_t high_cong_seq() const
  {
    return high_cong_seq_;
  }

  /// \brief Set the socket's packets ACKed in epoch.
  ///
  /// \param  pkts_ack_in_epoch  The socket's packets ACKed in epoch.
  inline void set_pkts_ack_in_epoch(uint32_t pkts_ack_in_epoch)
  {
    pkts_ack_in_epoch_ = pkts_ack_in_epoch;
  }

  /// \brief Get a reference to the socket's packets ACKed in epoch.
  ///
  /// \return A reference to the socket's packets ACKed in epoch.
  inline uint32_t& pkts_ack_in_epoch()
  {
    return pkts_ack_in_epoch_;
  }

  /// \brief Set the socket's functional flags.
  ///
  /// \param  funct_flags  The socket's functional flags.
  inline void set_funct_flags(uint32_t funct_flags)
  {
    funct_flags_ = funct_flags;
  }

  /// \brief Get a reference to the socket's functional flags.
  ///
  /// \return A reference to the socket's functional flags.
  inline uint32_t& funct_flags()
  {
    return funct_flags_;
  }

  /// \brief Set the socket's last upper window edge sent.
  ///
  /// \param  last_uwe  The socket's last upper window edge sent.
  inline void set_last_uwe(uint32_t last_uwe)
  {
    last_uwe_ = last_uwe;
  }

  /// \brief Set the socket's last upper window edge received.
  ///
  /// \param  last_uwe_in  The socket's last upper window edge received.
  inline void set_last_uwe_in(uint32_t last_uwe_in)
  {
    last_uwe_in_ = last_uwe_in;
  }

  /// \brief Get the socket's last upper window edge received.
  ///
  /// \return The socket's last upper window edge received.
  inline uint32_t last_uwe_in() const
  {
    return last_uwe_in_;
  }

  /// \brief Get the socket's pseudo header.
  ///
  /// \return The socket's pseudo header.
  inline PseudoHeader& ph()
  {
    return ph_;
  }

  /// \brief Set the socket's timeout.
  ///
  /// \param  timeout  The socket's timeout.
  inline void set_timeout(int timeout)
  {
    timeout_ = timeout;
  }

  /// \brief Get the socket's send scale.
  ///
  /// \return The socket's send scale.
  inline int16_t snd_scale() const
  {
    return snd_scale_;
  }

  /// \brief Get the socket's maximum data size for transmits.
  ///
  /// \return The socket's maximum data size for transmits.
  inline int16_t max_data() const
  {
    return max_data_;
  }

  /// \brief Set the socket's send side congestion window.
  ///
  /// \param  snd_cwnd  The socket's send side congestion window.
  inline void set_snd_cwnd(uint32_t snd_cwnd)
  {
    snd_cwnd_ = snd_cwnd;
  }

  /// \brief Get a reference to the socket's send side congestion window.
  ///
  /// \return A reference to the socket's send side congestion window.
  inline uint32_t& snd_cwnd()
  {
    return snd_cwnd_;
  }

  /// \brief Set the socket's previous send side congestion window.
  ///
  /// \param  snd_prev_cwnd  The socket's previous send side congestion
  ///                        window.
  inline void set_snd_prev_cwnd(uint32_t snd_prev_cwnd)
  {
    snd_prev_cwnd_ = snd_prev_cwnd;
  }

  /// \brief Get a reference to the socket's previous send side congestion
  /// window.
  ///
  /// \return A reference to the socket's previous send side congestion
  ///         window.
  inline uint32_t& snd_prev_cwnd()
  {
    return snd_prev_cwnd_;
  }

  /// \brief Set the socket's slow start threshold.
  ///
  /// \param  snd_ssthresh  The socket's slow start threshold.
  inline void set_snd_ssthresh(uint32_t snd_ssthresh)
  {
    snd_ssthresh_ = snd_ssthresh;
  }

  /// \brief Get the socket's slow start threshold.
  ///
  /// \return The socket's slow start threshold.
  inline uint32_t snd_ssthresh() const
  {
    return snd_ssthresh_;
  }

  /// \brief Get the socket's smoothed round trip time.
  ///
  /// \return The socket's smoothed round trip time.
  inline int32_t t_srtt() const
  {
    return t_srtt_;
  }

  /// \brief Get the socket's smoothed mean difference in RTT.
  ///
  /// \return The socket's smoothed mean difference in RTT.
  inline int t_rttvar() const
  {
    return t_rttvar_;
  }

  /// \brief Get the socket's starting RTO value.
  ///
  /// \return The socket's starting RTO value.
  inline uint32_t initial_rto() const
  {
    return initial_rto_;
  }

  /// \brief Get the socket's duplicate ACK count.
  ///
  /// \return The socket's duplicate ACK count.
  inline int t_dupacks() const
  {
    return t_dupacks_;
  }

  /// \brief Get the socket's maximum RTO, in microseconds.
  ///
  /// \return The socket's maximum RTO, in microseconds.
  inline uint32_t max_rto_us() const
  {
    return max_rto_us_;
  }

  /// \brief Get the last advertised window size.
  ///
  /// \return The socket's last advertised window size.
  inline uint32_t last_adv_wnd() const
  {
    return last_adv_wnd_;
  }

  /// \brief Set the next socket.
  ///
  /// \param  next  The next socket.
  void set_next(Socket* next)
  {
    next_ = next;
  }

  /// \brief Get the next socket.
  ///
  /// \return The next socket.
  Socket* next()
  {
    return next_;
  }

  /// \brief Set the previous socket.
  ///
  /// \param  prev  The previous socket.
  void set_prev(Socket* prev)
  {
    prev_ = prev;
  }

  /// \brief Get the previous socket.
  ///
  /// \return The previous socket.
  Socket* prev()
  {
    return prev_;
  }

  /// \brief Get a reference to the source endpoint for the flow for
  /// statistics reporting.
  ///
  /// \return A reference to the source endpoint for the flow for statistics
  ///         reporting.
  iron::Ipv4Endpoint& stats_src_endpt()
  {
    return stats_src_endpt_;
  }

  /// \brief Get a reference to the destination endpoint for the flow for
  /// statistics reporting.
  ///
  /// \return A reference to the destination endpoint for the flow for
  ///         statistics reporting.
  iron::Ipv4Endpoint& stats_dst_endpt()
  {
    return stats_dst_endpt_;
  }

  /// \brief Increment the number of bytes sent.
  ///
  /// In addition to incrementing the number of bytes sent, the sent packet
  /// count will be incremented by 1.
  ///
  /// \param  bytes_sent  The number of bytes sent by the Socket.
  void IncrementSentBytes(uint32_t bytes_sent);

  /// \brief Increment the number of bytes received.
  ///
  /// In addition to incrementing the number of bytes received, the received
  /// packet count will be incremented by 1.
  ///
  /// \param  bytes_rcvd  The number of bytes received by the Socket.
  void IncrementRcvdBytes(uint32_t bytes_rcvd);

  /// \brief Write the collected TCP Proxy stats to the log file and/or the
  /// JSON writer.
  ///
  /// \param  log_str  The string that is created for the log file.
  /// \param  writer   The JSON writer that is used to create the JSON
  ///                  message.
  void WriteStats(std::string& log_str,
                  rapidjson::Writer<rapidjson::StringBuffer>* writer = NULL);

  /// \brief Get the cumulative utility for the flow.
  ///
  /// \return The cumulative utility for the flow.
  inline double cumulative_utility() const
  {
    return cumulative_utility_;
  }

  /// \brief Get the average utility during the last statistics collection
  /// interval.
  ///
  /// \return The average utility during the last statistics collection
  ///         interval.
  inline double ave_utility() const
  {
    return ave_utility_;
  }

  /// \brief Get a reference to the PktInfo pool.
  ///
  /// \return A reference to the PktInfo pool.
  inline PktInfoPool& pkt_info_pool() const
  {
    return pkt_info_pool_;
  }

  /// \brief Get the socket's burst interval, in microseconds.
  ///
  /// \return The socket's burst interval, in microseconds.
  inline const iron::Time& min_burst_usec() const
  {
    return min_burst_usec_;
  }

  /// \brief Get the flow's identification string.
  ///
  /// \return The flow's identification string.
  inline const char* flow_id_str() const
  {
    return flow_id_str_;
  }

  private:

  /// \brief Copy constructor.
  Socket(const Socket& s);

  /// \brief Copy operator.
  Socket& operator=(const Socket& s);

  /// \brief Perform a "silent abort".
  ///
  /// A silent abort only applies to sockets that have done a seamless handoff
  /// to an alternate server. This will search the proxy's server lists for
  /// another suitable server to use for the connection.
  void SilentAbort();

  /// \brief Acknowledge a received TCP FIN packet.
  ///
  /// When a FIN packet is received, the proxy does not immediately ACK the
  /// received FIN. Instead, the FIN packet is sent by the peer socket. Only
  /// when the peer socket receives an ACK for the FIN packet does this socket
  /// send an ACK for the FIN. This method accomplishes ACKing the FIN
  /// received once the peer has sent it and received an ACK for it.
  void AckFin();

  /// \brief Time a packet transmission.
  ///
  /// \param  pkt_info  Pointer to the PktInfo containing the packet to
  ///                   transmit.
  void TimePkt(PktInfo* pkt_info);

  /// \brief Send a packet.
  ///
  /// \param  pkt_info  Pointer to the PktInfo containing the packet to send
  ///                   and its metadata.
  ///
  /// \return The number of bytes that were sent.
  uint32_t SendPkt(PktInfo* pkt_info);

  /// \brief Process a packet received on a socket that is in the TCP_LISTEN
  /// state.
  ///
  /// \param  ip_hdr   The received IP header.
  /// \param  tcp_hdr  The received TCP header.
  void ProcessPktListenState(const struct iphdr* ip_hdr,
                             const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the TCP_LISTEN
  /// state.
  ///
  void ProcessPktListenState();

  /// \brief Process a packet received on a Socket that has a state value of
  /// TCP_SYN_SENT.
  ///
  /// \param  tcp_hdr  The received TCP header.
  ///
  /// \return 1 if successful, -2 if not.
  int ProcessPktSynSentState(const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the TCP_SYN_REC
  /// state.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TP header.
  /// \param  ip_hdr    The received IP header.
  ///
  /// \return 1 if successful
  int ProcessPktSynRecState(PktInfo* pkt_info, const struct tcphdr* tcp_hdr,
                            const struct iphdr* ip_hdr);

  /// \brief Process a packet received on a Socket that is in one of the
  /// following states:
  ///
  /// - TCP_ESTAB
  /// - TCP_CLOSE_WAIT
  /// - TCP_FIN_WAIT1_PEND
  /// - TCP_FIN_WAIT_DETOUR
  /// - TCP_LAST_ACK_PEND
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  ///
  /// \return 1 if successful.
  int ProcessPktEstablishedState(PktInfo* pkt_info,
                                 const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the
  /// TCP_FIN_WAIT1 state.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  ///
  /// \return 1 if successful, -1 if an error occurs.
  int ProcessPktFinWait1State(PktInfo* pkt_info,
                              const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the
  /// TCP_FIN_WAIT2 state.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  void ProcessPktFinWait2State(PktInfo* pkt_info,
                               const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the TCP_CLOSING
  /// state.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  void ProcessPktClosingState(PktInfo* pkt_info,
                              const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the TCP_LAST_ACK
  /// state.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  ///
  /// \return 1 if successful, -1 if an error occurs.
  int ProcessPktLastAckState(PktInfo* pkt_info,
                             const struct tcphdr* tcp_hdr);

  /// \brief Process a packet received on a Socket that is in the
  /// TCP_TIME_WAIT state.
  ///
  /// \param  tcp_hdr  The received TCP header.
  /// \param  ip_hdr   The received IP header.
  void ProcessPktTimeWaitState(const struct tcphdr* tpHdr,
                               const struct iphdr* ipHdr);

  /// \brief Create a new connection.
  ///
  /// \param  ip_hdr   The received IP header.
  /// \param  tcp_hdr  The received TCP header.
  void HandleNewConnection(const struct iphdr* ip_hdr,
                           const struct tcphdr* tcp_hdr);

  /// \brief Process an acknowledgement received in an incoming packet.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  void ProcessAck(PktInfo* pkt_info, const struct tcphdr* tcp_hdr);

  /// \brief Process the data in an incoming packet.
  ///
  /// Called from all states where incoming data can be received: established,
  /// FinWait1, FinWait2.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  void ProcessRcvdData(PktInfo* pkt_info, const struct tcphdr* tcp_hdr);

  /// \brief Process out-of-sequence data.
  ///
  /// \param  pkt_info  The received packet and its metadata.
  /// \param  tcp_hdr   The received TCP header.
  void ProcessOutOfSequenceData(PktInfo* pkt_info,
                                const struct tcphdr* tcp_hdr);

  /// \brief Updates RTT values when TCP packets are received.
  ///
  /// \param  rtt_sample  The RTT sample, in microseconds
  void UpdateRttEstimate(uint32_t rtt_sample);

  /// \brief Set options on a Socket.
  ///
  /// \param  cnt                  Count of TCP header options.
  /// \param  tcp_hdr              The TCP header.
  /// \param  ts_present           Is the TPOPT_TIMESTAMP option set?
  /// \param  ts_val               The timestamp value.
  /// \param  ts_ecr               Timestamp echo reply.
  /// \param  pkt_changed_snd_buf  Set to true if there are SACK plugs that
  ///                              change the state of the send buffer.
  void DoOptions(int cnt, const struct tcphdr* tcp_hdr, int* ts_present,
                 uint32_t* ts_val, uint32_t* ts_ecr,
                 bool& pkt_changed_snd_buf);

  /// \brief Get the TCP options.
  ///
  /// \param  opt_buf           The buffer that contains the TCP options for
  ///                           the Socket.
  /// \param  opt_buf_max_size  The maximum size of the options buffer.
  ///
  /// \return The size of the TCP options for the Socket.
  size_t GetOptions(uint8_t* opt_buf, size_t opt_buf_max_size);

  /// \brief Update the window size and ack number fields in the TCP header.
  ///
  /// \param  tcp_hdr  The TCP packet header.
  void UpdateWinSizeAndAckNum(struct tcphdr* tcp_hdr);

  /// \brief Determine if the flow is transitioning out of a flow control
  /// blocked state.
  ///
  /// \return True if the flow is leaving a flow control blocked state, false
  ///         otherwise.
  bool IsLeavingFlowCtrlBlockedState();

  /// \brief Process a delayed ack timer timeout.
  void DelayedAckTimeout();

  /// \brief Process a keepalive timer timeout.
  void KeepAliveTimeout();

  /// \brief Process a persist timer timeout.
  void PersistTimeout();

  /// \brief Process a RTO timer timeout.
  void RtoTimeout();

  /// \brief Process a time wait timer callback.
  void TimeWaitTimeout();

  /// \brief Clear out the currently selected Congestion Control Algorithm.
  ///
  /// This is normally called when we are making changes to the selection.
  void ClearCcAlgSelection();

  /// \brief Schedule a delayed ack event.
  ///
  /// \param  time_delta  The time delta from now when the event is to occur.
  void ScheduleDelayedAckEvent(iron::Time& time_delta);

  /// \brief Schedule a keep alive event.
  ///
  /// \param  time_delta  The time delta from now when the event is to occur.
  void ScheduleKeepAliveEvent(iron::Time& time_delta);

  /// \brief Schedule a persist event.
  ///
  /// \param  time_delta  The time delta from now when the event is to occur.
  void SchedulePersistEvent(iron::Time& time_delta);

  /// \brief Schedule an RTO event.
  ///
  /// \param  time_delta  The time delta from now when the event is to occur.
  void ScheduleRtoEvent(iron::Time& time_delta);

  /// \brief Schedule a time wait event.
  ///
  /// \param  time_delta  The time delta from now when the event is to occur.
  void ScheduleTimeWaitEvent(iron::Time& time_delta);

  /// \brief Cancel all scheduled events.
  void CancelAllScheduledEvents();

  /// \brief Cancel a scheduled event.
  ///
  /// \param  time  A reference to the time for the scheduled event.
  void CancelScheduledEvent(iron::Time& time);

  // Where applicable, the names of the member variables match those found in
  // Stevens' TCP/IP Illustrated, Volume 2 (c) 1995.

  //--------------------------------------------------------------------------
  // Other TCP Proxy components.

  /// The TCP Proxy configuration information.
  TcpProxyConfig&           proxy_config_;

  /// The TCP Proxy instance.
  TcpProxy&                 tcp_proxy_;

  /// Reference to the IRON packet pool.
  iron::PacketPool&         packet_pool_;

  /// Bin info: used to identify multicast vs unicast bins.
  iron::BinMap&             bin_map_;

  /// The TCP socket manager.
  SocketMgr&                socket_mgr_;

  /// Reference to the PktInfo pool.
  PktInfoPool&              pkt_info_pool_;

  //--------------------------------------------------------------------------
  // Socket identification.

  /// Bin Index of the flow.
  iron::BinIndex            bin_idx_;

  /// The socket's unique flow identifier.
  uint32_t                  flow_tag_;

  /// The interface that the originating SYN packet was received on.
  ProxyIfType               cfg_if_id_;

  /// A string to identify each flow, used in the Socket log statements.
  char                      flow_id_str_[64];

  /// The local address for the connection.
  struct in_addr            my_addr_;

  /// The remote address for the connection.
  struct in_addr            his_addr_;

  /// My port for the connection.
  uint16_t                  my_port_;

  /// The remote port for the connection.
  uint16_t                  his_port_;

  /// IP header template, a skeletal packet for transmission.
  struct iphdr              t_template_;

  /// Socket flags.
  uint32_t                  sock_flags_;

  /// Remembers if the socket is active or passive. An active socket is the
  /// socket that sends the initial SYN packet.
  bool                      is_active_;

  /// The original received SYN packet.
  PktInfo*                  orig_syn_pkt_info_;

  /// Remembers if the socket has done a seamless handoff to an alternate
  /// server.
  bool                      do_seamless_handoff_;

  /// The IPv4 endpoint of the alternate server.
  iron::Ipv4Endpoint        seamless_handoff_endpoint_;

  /// The IPv4 endpoint of the client configured server.
  iron::Ipv4Endpoint        client_configured_server_endpoint_;

  //--------------------------------------------------------------------------
  // Encapsulated packet information.

  /// Remembers if the socket's packets are encapsulated.
  bool                      is_tunneled_;

  /// The outer headers for the encapsulated packets.
  uint8_t                   tunnel_hdrs_[iron::kVxlanTunnelHdrLen];

  //--------------------------------------------------------------------------
  // Packet buffers.

  /// Remembers if adaptive buffers are being used.
  bool                      adaptive_buffers_;

  /// The send buffer.
  SendBuffer*               send_buf_;

  /// The out-of-sequence buffer.
  OutSeqBuffer*             out_seq_buf_;


  //--------------------------------------------------------------------------
  // Peer information.

  /// Pointer to peer Socket.
  Socket*                   peer_;

  /// Max size of the peer's send buffer
  uint32_t                  peer_send_buf_max_bytes_;

  /// What should the peer do.
  int                       gw_flags_;

  //--------------------------------------------------------------------------
  // IRON admission control information.

  /// Socket's utility function.
  iron::UtilityFn*          flow_utility_fn_;

  //--------------------------------------------------------------------------
  // Socket state variables.

  /// TOS value for the socket.
  uint8_t                   tos_;

  /// The desired DSCP value for the flow on this socket.
  int8_t                    desired_dscp_;

  /// Connection state.
  int16_t                   state_;

  /// Connection state prior to current connection state.
  int16_t                   prev_state_;

  /// The capabilities of this socket.
  int16_t                   capabilities_;

  /// For passing urgent ptrs in the gateway.
  uint32_t                  initial_seq_num_;

  /// For passing urgent ptrs in the gateway.
  uint32_t                  initial_seq_num_rec_;

  /// Offet from init_seq_num of urg data.
  uint32_t                  rel_seq_num_urg_ptr_;

  /// Data acknowledged.
  uint32_t                  ack_num_;

  /// Sequence number.
  uint32_t                  seq_num_;

  /// The sequence number of the sent TCP SYN.
  uint32_t                  syn_seq_num_;

  /// Remembers if we have sent a SYN packet.
  bool                      syn_seq_num_set_;

  /// The sequence number of the sent TCP FIN.
  uint32_t                  fin_seq_num_;

  /// Remembers if we have sent a FIN packet.
  bool                      fin_seq_num_set_;

  /// First octet of data sent but unacknowledged.
  uint32_t                  snd_una_;

  /// Sequence number that has been sent.
  uint32_t                  seq_sent_;

  /// Max sequence number sent excluding RTOs.
  uint32_t                  snd_max_;

  /// Highest sequence number sent when we transition into fast
  /// retransmit. NewReno.
  uint32_t                  high_seq_;

  /// The highest sequence number sent during a congestion epoch. On leaving a
  /// congestion epoch, we don't get sndCwnd credit for ACKs from packets sent
  /// during the epoch.
  uint32_t                  high_cong_seq_;

  /// This is the number of packets that were acked during a congestion
  /// epoch.
  uint32_t                  pkts_ack_in_epoch_;

  ///
  uint32_t                  funct_flags_;

  /// Connection send window.
  uint32_t                  snd_wnd_;

  /// Last ack sent from this socket.
  uint32_t                  last_ack_;

  /// Last upper window edge sent.
  uint32_t                  last_uwe_;

  /// Last upper window edge received.
  uint32_t                  last_uwe_in_;

  /// The socket's pseudo-header storage.
  PseudoHeader              ph_;

  /// Timeout, in milliseconds.
  int                       timeout_;

  /// Shift counter for exponential values.
  int                       persist_shift_;

  /// TCP flags word for last packet sent.
  uint8_t                   flags_;

  /// Number of segments since last ack sent.
  int16_t                   ack_delay_;

  /// Ack frequency: 0 = delayed only, 1 = every segment, 2 = every 2nd
  /// segment.
  int16_t                   ack_freq_;

  /// Maximum segment size to send.
  int16_t                   t_maxseg_;

  /// maxSeg - TP_HDR_LEN.
  uint16_t                  max_data_;

  /// MSS offered by other side.
  int16_t                   remote_mss_offer_;

  /// MSS offered to the other side.
  uint16_t                  my_mss_offer_;

  /// Window other side advertised to us.
  uint32_t                  snd_awnd_;

  /// Send side congestion window.
  uint32_t                  snd_cwnd_;

  /// Previous send side congestion window.
  uint32_t                  snd_prev_cwnd_;

  /// Send side slow start threshold.
  uint32_t                  snd_ssthresh_;

  /// Maximum transmission unit.
  uint32_t                  mtu_;

  /// Count of duplicate acks, 3 = rexmit now.
  int                       t_dupacks_;

  /// Processed but unacked segments.
  int                       unacked_segs_;

  /// Array of pointers to the Congestion Control objects.
  CongCtrlAlg*              cc_algs_[MAX_CC_ALG_CNT];

  /// The last advertised window.
  uint32_t                  last_adv_wnd_;

  uint32_t                  total_sent_;

  /// Remembers if the socket is carrying data.
  bool                      is_carrying_data_;

  /// A unique identifier that is updated each time that the flow is
  /// serviced. This will be used to ensure that we don't retransmit a packet
  /// more than once each time a flow is serviced.
  uint32_t                  flow_svc_id_;

  //--------------------------------------------------------------------------
  // TCP Window Scale Option.

  /// Remote requested window scale.
  int16_t                   requested_s_scale_;

  /// Pending window scaling.
  int16_t                   request_r_scale_;

  /// Window scaling for send window.
  int16_t                   snd_scale_;

  /// Window scaling for receive window.
  int16_t                   rcv_scale_;


  //--------------------------------------------------------------------------
  // TCP Timestamp Option.

  /// Recent timestamp.
  uint32_t                  ts_recent_;

  /// Time that the recent Timestamp came in.
  uint32_t                  ts_recent_age_;

  /// Most recent Timestamp echo reply.
  uint32_t                  ts_ecr_recent_;


  //--------------------------------------------------------------------------
  // TCP Selective ACK (SACK) Option.

  /// Size of plug in bytes.
  uint32_t                  plug_send_size_;

  /// Sequence number of plug.
  uint32_t                  plug_send_seq_;

  /// A cache of the last SACK block set.
  OutSeqBuffer::PlugInfo    sack_plug_cache_[4];

  //--------------------------------------------------------------------------
  // Retransmission Timer Calculations.

  /// Current rtt on this connection.
  uint32_t                  rtt_cur_;

  /// Starting RTT value.
  uint32_t                  initial_rtt_;

  /// Starting RTT variance value.
  uint32_t                  initial_rtt_var_;

  /// Starting RTO value.
  uint32_t                  initial_rto_;

  /// Smoothed round trip time (int for signed compare).
  int32_t                   t_srtt_;

  /// Smoothed mean difference in rtt (int for signed compare).
  int                       t_rttvar_;

  /// Current retransmission timeout, RTO.
  uint32_t                  t_rxtcur_;

  /// Shift value for rtt if congested.
  uint32_t                  t_rxtshift_;

  /// Maximum shift value for rtt, if congested.
  uint32_t                  t_rxtmaxshift_;

  /// Are we timing a transmission? This is only used if TCP timestamp options
  /// are not being used.
  bool                      t_rtt;

  /// The transmission that is being timed. This is only used if TCP timestamp
  /// options are not being used.
  uint32_t                  t_rtseq;

  /// Timestamp of immediately prior segment.
  iron::Time                rtseq_ts_val_;


  //--------------------------------------------------------------------------
  // Timer related.

  /// The ACK delay, in microseconds.
  uint32_t                  ack_delay_us_;

  /// The minimum RTO, in microseconds.
  uint32_t                  min_rto_us_;

  /// The maximum RTO, in microseconds.
  uint32_t                  max_rto_us_;

  /// Set to 1 if pkt send failed in RTO rexmit.
  int                       rto_failed_;

  /// The Keep Alive timeout.
  uint32_t                  ka_timeout_;

  /// The next time that a packet can be admitted to the BPF.
  iron::Time                next_admission_time_;

  /// The minimum burst window in which to admit packets.
  iron::Time                min_burst_usec_;

  /// The last send rate for the Socket.
  double                    last_send_rate_;

  /// The delayed ack timer expiration time.
  iron::Time                delayed_ack_time_;

  /// The keep alive timer expiration time.
  iron::Time                keep_alive_time_;

  /// The persist timer expiration time.
  iron::Time                persist_time_;

  /// The rto timer expiration time.
  iron::Time                rto_time_;

  /// The time wait timer expiration time.
  iron::Time                time_wait_time_;

  /// Flag that remembers if the flow is idle or not.
  bool                      flow_is_idle_;

  /// Flag that remembers if the flow is flow control blocked or not.
  bool                      flow_ctrl_blocked_;

  /// The sequence number of the packet that would have been sent if not flow
  /// control blocked.
  uint32_t                  flow_ctrl_blocked_seq_num_;

  /// The data length of the packet that would have been sent if not flow
  /// control blocked.
  uint16_t                  flow_ctrl_blocked_data_len_;


  //--------------------------------------------------------------------------
  // IRON statistics collection.

  /// The source IPv4 endpoint used for statistics reporting.
  iron::Ipv4Endpoint        stats_src_endpt_;

  /// The destination IPv4 endpoint used for statistics reporting.
  iron::Ipv4Endpoint        stats_dst_endpt_;

  /// The total number of packets sent by the flow during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint32_t                  sent_pkt_cnt_;

  /// The total number of bytes sent by the flow during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint32_t                  sent_bytes_cnt_;

  /// The total number of packets sent by the flow since its inception.
  uint64_t                  cumulative_sent_pkt_cnt_;

  /// The total number of bytes sent by the flow since its inception.
  uint64_t                  cumulative_sent_bytes_cnt_;

  /// The total number of packets received by the flow during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint32_t                  rcvd_pkt_cnt_;

  /// The total number of bytess received by the flow during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint32_t                  rcvd_bytes_cnt_;

  /// The total number of packets received by the flow since its inception.
  uint64_t                  cumulative_rcvd_pkt_cnt_;

  /// The total number of bytes received by the flow since its inception.
  uint64_t                  cumulative_rcvd_bytes_cnt_;

  /// The cumulative utility of the flow since its inception.
  double                    cumulative_utility_;

  /// The cumulative utility during the statistics collection interval. This
  /// value is reset each time the statistics interval expires.
  double                    utility_;

  /// The number of utility samples during the statistics collection
  /// interval. This value is reset each time the statistic interval expires.
  uint16_t                  utility_sample_cnt_;

  /// The average utility during the statistics collection interval. This
  /// value is recomputed each time the statistics interval expires.
  double                    ave_utility_;

  /// The cumulative packet delay, in milliseconds, during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint32_t                  cumulative_pkt_delay_ms_;

  /// The number of packet delay samples captured during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint16_t                  pkt_delay_sample_cnt_;

  /// The average packet delay, in milliseconds, during the statistics
  /// collection interval. This value is reset each time the statistics
  /// interval expires.
  uint32_t                  ave_pkt_delay_ms_;

  /// The last statistics report time.
  iron::Time                last_report_time_;


  //--------------------------------------------------------------------------
  // List manipulation.

  /// Pointer to the next socket.
  Socket*                   next_;

  /// Pointer to the previous socket.
  Socket*                   prev_;

}; // end class Socket

#endif // IRON_TCP_PROXY_SOCKET_H
