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

#ifndef IRON_TCP_PROXY_TCP_PROXY_H
#define IRON_TCP_PROXY_TCP_PROXY_H

#include "fifo_if.h"
#include "four_tuple.h"
#include "hash_table.h"
#include "ipv4_address.h"
#include "k_val.h"
#include "packet.h"
#include "packet_fifo.h"
#include "packet_pool.h"
#include "pkt_info_pool.h"
#include "queue_depths.h"
#include "remote_control.h"
#include "server_list.h"
#include "shared_memory_if.h"
#include "socket_mgr.h"
#include "tcp_proxy_config.h"
#include "tcp_proxy_opts.h"
#include "tcp_context.h"
#include "timer.h"
#include "virtual_edge_if.h"


/// Enum type definitions for modifying or deleting TCP contexts
enum TcpActionType
{
  TcpModAction,
  TcpDelAction
};

/// Main class for the IRON TCP Proxy.
class TcpProxy
{
  public:

  /// \brief Constructor.
  ///
  /// \param  proxy_config             The TCP Proxy configuration
  ///                                  information.
  /// \param  packet_pool              Pool of packets to use.
  /// \param  edge_if                  Edge interface for the TCP Proxy's
  ///                                  LAN side.
  /// \param  bin_map                  A reference to the bin map in shared
  ///                                  memory.
  /// \param  weight_qd_shared_memory  Memory to share weight queue depths
  //                                   with proxies.
  /// \param  bpf_to_tcp_pkt_fifo      Unopened-fifo for receiving packets
  ///                                  from BPF. This instance takes ownership
  ///                                  of the memory.
  /// \param  tcp_to_bpf_pkt_fifo      Unopened-fifo for sending packets to
  ///                                  BPF. This instance takes ownership of
  ///                                  the memory.
  TcpProxy(TcpProxyConfig& proxy_config, iron::PacketPool& packet_pool,
           iron::VirtualEdgeIf& edge_if,
           iron::BinMap& bin_map,
           iron::SharedMemoryIF& weight_qd_shared_memory,
           iron::FifoIF* bpf_to_tcp_pkt_fifo,
           iron::FifoIF* tcp_to_bpf_pkt_fifo);

  /// \brief Constructor that also takes a remote control server.
  ///
  /// \param  proxy_config             The TCP Proxy configuration
  ///                                  information.
  /// \param  packet_pool              Pool of packets to use.
  /// \param  edge_if                  Edge interface for the TCP Proxy's
  ///                                  LAN side.
  /// \param  bin_map                  A reference to the bin map in shared
  ///                                  memory.
  /// \param  weight_qd_shared_memory  Memory to share weight queue depths
  //                                   with proxies.
  /// \param  bpf_to_tcp_pkt_fifo      Unopened-fifo for receiving packets
  ///                                  from BPF. This instance takes ownership
  ///                                  of the memory.
  /// \param  tcp_to_bpf_pkt_fifo      Unopened-fifo for sending packets to
  ///                                  BPF. This instance takes ownership of
  ///                                  the memory.
  /// \param  remote_control_server    Remote control server to use.
  TcpProxy(TcpProxyConfig& proxy_config, iron::PacketPool& packet_pool,
           iron::VirtualEdgeIf& edge_if,
           iron::BinMap& bin_map,
           iron::SharedMemoryIF& weight_qd_shared_memory,
           iron::FifoIF* bpf_to_tcp_pkt_fifo,
           iron::FifoIF* tcp_to_bpf_pkt_fifo,
           iron::RemoteControlServer& remote_control_server);

  /// \brief Destructor.
  virtual ~TcpProxy();

  /// \brief Initialize the TCP Proxy.
  ///
  /// \param  config_info  The configuration information.
  ///
  /// \return True if successful, false otherwise.
  bool Initialize(const iron::ConfigInfo& config_info);

  /// \brief Main service loop for the TCP Proxy.
  void Start();

  /// \brief Send a Packet to the LAN side interface.
  ///
  /// \param  pkt  Pointer to the Packet to be written to the LAN side
  ///              interface.
  ///
  /// \return The number of bytes written to the LAN side interface.
  ssize_t SendToLan(const iron::Packet* pkt);

  /// \brief Send a Packet to the LAN side interface.
  ///
  /// \param  pkt  Pointer to the Packet to be written to the WAN side
  ///              interface.
  ///
  /// \return True if the Packet is written to the WAN side interface, false
  ///         otherwise.
  bool SendToWan(iron::Packet* pkt);

  /// \brief Mark a server as unreachable.
  ///
  /// \param  server  The server that is unreachable.
  void MarkServerAsUnreachable(iron::Ipv4Endpoint& server);

  /// \brief Add the packet to the reconnect list.
  ///
  /// Reconnection requests only apply to client configured servers that have
  /// a corresponding alternate server list.
  ///
  /// \param  pkt  Contains the originally received SYN packet.
  void Reconnect(iron::Packet* pkt);

  /// \brief Write a control packet to the network.
  ///
  /// Use only if data_len == 0. This method is responsible for recycling the
  /// provided PktInfo object.
  ///
  /// \param  out_if    The interface to use to send the packet, WAN or LAN.
  /// \param  pkt_info  Pointer to the PktInfo containing the packet to send
  ///                   and its metadata.
  ///
  /// \return The number of bytes that were sent.
  uint32_t SimpleSendPkt(ProxyIfType out_if, PktInfo* pkt_info);

  /// \brief The service sockets timeout callback.
  void SvcSocketsTimeout();

  /// \brief Get the bin index for a destination IP address.
  ///
  /// \param  ip_addr  The IP address for which we want a bin index.
  /// \param  ret_index The BinIndex is returned here if found.
  ///
  /// \return True if there was a valid mapping, false otherwise.
  bool GetBinIndex(
    const iron::Ipv4Address& ip_addr, iron::BinIndex& ret_index) const;

  /// \brief Get the current bin depth for the provide bin index.
  ///
  /// \param  bin_idx  The bin index of interest.
  ///
  /// \return The current bin depth for the provided bin index.
  uint32_t GetBinDepth(iron::BinIndex bin_idx) const;

  /// \brief  Get the queue depths object.
  ///
  /// \return A reference to the queue depths object.
  inline iron::QueueDepths& GetQueueDepths()
  {
    return local_queue_depths_;
  }

  /// \brief Get the previous bin depth for the provide bin index.
  ///
  /// \param  bin_idx  The bin index of interest.
  ///
  /// \return The previous bin depth for the provided bin index.
  uint32_t GetPreviousBinDepth(iron::BinIndex bin_idx) const;

  /// \brief Get the IRON utility function definition for the provided
  /// destination port.
  ///
  /// This lookup will search the Service definitions for a match. If there is
  /// no Service defined for the provided port, the default utility function
  /// definition is returned.
  ///
  /// \param  port  The target port for the lookup.
  ///
  /// \return The utility function definition string, which contains the
  ///         parameters for the utility function. The default utility
  ///         function definition is returned if there is no Service defined
  ///         for the provided port.
  std::string GetUtilityFnDef(uint16_t port);

  /// \brief  Get the DSCP value for the provided destination port.
  ///
  /// This lookup will search the Service definitions for a match.  If there is
  /// no Service defined for the provided port, the default -1 value (do not
  /// change whatever DSCP value is in the packets) is returned.

  /// \param  port_hbo  The target port for the lookup.
  ///
  /// \return The DSCP value.  The value -1 (do not change whatever DSCP value
  ///         is in the packets) is returned if there is no Service defined for
  ///         the provided port.
  int8_t GetContextDscp(uint16_t port_hbo);

  /// \brief Inquire if there is a Flow Utility function definition that
  /// matches the provided 4-tuple.
  ///
  /// Flow Utility function definitions take precedence over Service Utility
  /// function definitions.
  ///
  /// \param  four_tuple  The 4-tuple to use for the lookup.
  ///
  /// \return True if the Flow definition cache has a Utility function
  ///         definition entry for the provided 4-tuple, false otherwise.
  inline bool HasFlowUtilityFnDef(const iron::FourTuple& four_tuple) const
  {
    return (flow_utility_def_cache_.Count(four_tuple) > 0);
  }

  /// \brief Get the Flow Utility function definition that matches the
  /// provided 4-tuple.
  ///
  /// Flow Utility function definitions take precedence over Service Utility
  /// function definitions.
  ///
  /// \param  four_tuple      The 4-tuple to use for the lookup.
  /// \param  utility_fn_def  The returned utility function definition.
  ///
  /// \return True if the Flow definition cache has a Utility function
  ///         definition entry for the provided 4-tuple, false otherwise.
  inline bool GetFlowUtilityFnDef(const iron::FourTuple& four_tuple,
                                  std::string& utility_fn_def) const
  {
    return flow_utility_def_cache_.Find(four_tuple, utility_fn_def);
  }

  /// \brief  Get the Flow Dscp value that matches the provided 4-tuple.
  ///
  /// This Dscp definition takes precedence over Service definitions.
  ///
  /// \param  four_tuple  The 4-tuple to use for the lookup.
  /// \param  dscp        The returned DSCP value to apply (-1 means do not
  ///                     change whatever value is in the packet already).
  /// \return True if the Dscp cache has an entry for the provided 4-tuple,
  ///         false otherwise.
  inline bool GetFlowDscpDef(const iron::FourTuple& four_tuple,
                             int8_t& dscp) const
  {
    return context_dscp_cache_.Find(four_tuple, dscp);
  }

  /// \brief  The method invoked when the statistics timer expires.
  void PushStats();

  /// \brief Get the statistics collection interval, in milliseconds.
  ///
  /// \return The statistics collection interval, in milliseconds.
  inline uint32_t stats_interval_ms() const
  {
    return stats_interval_ms_;
  }

  /// \brief Inquire if the statistics are to be logged.
  ///
  /// \return True if the statistics are to be logged, false otherwise.
  inline bool log_stats() const
  {
    return log_stats_;
  }

  /// \brief Get access to the queue normalizer, K.
  ///
  /// K will be maintained here, so this just returns a reference.
  ///
  /// \return A reference to the queue normalizer, K.
  inline iron::KVal& k_val()
  {
    return k_val_;
  }

  /// \brief Get the next scheduled time for servicing the sockets.
  ///
  /// \return The next scheduled time for servicing the sockets.
  inline const iron::Time& next_sched_socket_svc_time() const
  {
    return next_sched_socket_svc_time_;
  }

  protected:

  /// The maximum number of seamless handoff server lists supported.
  static const uint8_t  kMaxServerLists = 8;

  /// The maximum number of reconnects requests supported.
  static const uint8_t  kMaxReconnects = 16;

  /// \brief Information for pushing TCP Proxy statistics to a client
  /// periodically.
  struct TcpStatsPushInfo
  {
    TcpStatsPushInfo()
        : is_active(false), client_id(0), msg_id(0), interval_sec(0.0),
          timer_handle()
    { }

    bool                 is_active;
    uint32_t             client_id;
    uint32_t             msg_id;
    double               interval_sec;
    iron::Timer::Handle  timer_handle;
  };

  /// \brief Copy constructor.
  TcpProxy(const TcpProxy& tp);

  /// \brief Copy operator.
  TcpProxy& operator=(const TcpProxy& tp);

  /// \brief Wrapper for system select()
  ///
  /// Allows test cases to operate when not using system resources to back
  /// data sources. The contract matches select(), with unused arguments
  /// removed.
  ///
  /// \param nfds    Highest-numbered file descriptor in the read set, plus 1
  /// \param readfs  Set of file descriptors that will be watched to see if
  ///                characters become available for reading.
  /// \param timeout Interval that the call should block waiting for a file
  ///                descriptor to become ready.
  ///
  /// \return Number of file descriptors that are ready to read. May be
  ///         zero if the timeout expired. On error, -1 is returned, and errno
  ///         will be set to indicate the error.
  virtual int Select(int nfds, fd_set* readfs, struct timeval* timeout);

  /// \brief  Attach the shared memory for queue weights.
  ///
  /// \param  config_info A reference to the configuration information.
  ///
  /// \return True if successful, false otherwise.
  virtual bool AttachSharedMemory(const iron::ConfigInfo& config_info);

  /// \brief Body of the loop the performs tcp proxy forwarding.
  virtual void MainLoop();

  /// \brief Stop the main loop from running.
  void Stop();

  /// \brief Receive packets from the IRON Backpressure Forwarder.
  void ReceivePktsFromBpf();

  /// \brief Process a received Packet.
  ///
  /// \param  packet  The received Packet.
  /// \param  in_if   The interface the packet was received on.
  void ProcessRcvdPkt(iron::Packet* packet, ProxyIfType in_if);

  /// \brief Generate a RST packet and transmit it out the interface the
  /// packet was received on.
  ///
  /// \param  rst_pkt_info  The RST packet.
  /// \param  rcv_if        Interface the packet was received on.
  /// \param  is_tunnel     Indicates if the socket pair is for a TCP
  ///                       connection that is encapsulated in a tunnel.
  void SimpleReset(PktInfo* rst_pkt_info, ProxyIfType rcv_if,
                   bool is_tunnel);

  /// \brief Create a pair of peer Sockets.
  ///
  /// Creates a passive Socket and an active Socket and makes them peers of
  /// each other.
  ///
  /// \param  packet     The received Packet.
  /// \param  in_if      The interface the packet was received on.
  /// \param  is_tunnel  Indicates if the socket pair is for a TCP connection
  ///                    that is encapsulated in a tunnel.
  ///
  /// \return The created passive socket.
  Socket* CreateSocketPair(iron::Packet* packet, ProxyIfType in_if,
                           bool is_tunnel);

  /// \brief Create a passive Socket.
  ///
  /// \param  tcp_hdr  The received TCP header.
  /// \param  ip_hdr   The received IP header.
  ///
  /// \return New Socket, or NULL if an error occurs.
  Socket* CreatePassiveSocket(const struct tcphdr* tcp_hdr,
                              const struct iphdr* ip_hdr);

  /// \brief Create an active Socket.
  ///
  /// \param  tcp_hdr  The received TCP header.
  /// \param  ip_hdr   The received IP header.
  ///
  /// \return New Socket, or NULL if an error occurs.
  Socket* CreateActiveSocket(const struct tcphdr* tcp_hdr,
                             const struct iphdr* ip_hdr);

  /// \brief Generate and send a TCP RST out the LAN-facing interface.
  ///
  /// This is only invoked when a TCP SYN packet is received for which
  /// seamless server handoff is being done for the destination and there are
  /// no reachable destinations in the list of alternate servers.
  ///
  /// \param  tcp_hdr  The received TCP header.
  /// \param  ip_hdr   The received IP header.
  void GenerateAndSendReset(const struct tcphdr* tcp_hdr,
                            const struct iphdr* ip_hdr);

  /// \brief Process a received remote control message.
  void ProcessRemoteControlMessage();

  /// \brief Process a received remote control SET message.
  ///
  /// Currently, the remote control messages that are supported are:
  ///
  /// - Service add
  /// - Flow add
  /// - Flow del
  ///
  /// messages that are received from the Admission Planner.
  void ProcessSetMessage();

  /// \brief Process a received remote control GET message.
  void ProcessGetMessage();

  /// Process a received remote control PUSHREQ message.
  void ProcessPushReqMessage();

  /// Process a received remote control PUSHSTOP message.
  void ProcessPushStopMessage();

  /// \brief Process a received Service Definition update message.
  ///
  /// \param  key       The json message key.
  /// \param  val_obj   The json message value object.
  /// \param  err_msg   The reference where the error string is to be
  ///                   written. An empty string indicates that no error
  ///                   occurred.
  ///
  /// \return True if the message is successfully processed, false otherwise.
  bool ProcessSvcDefUpdateMsg(const std::string& key,
                              const rapidjson::Value& val_obj,
                              std::string& err_msg);

  /// \brief Process a received Flow Definition update message.
  ///
  /// \param  key       The json message key.
  /// \param  key_vals  The json message value object.
  /// \param  err_msg   The reference where the error string is to be
  ///                   written. An empty string indicates that no error
  ///                   occurred.
  ///
  /// \return True if the message is successfully processed, false otherwise.
  bool ProcessFlowDefUpdateMsg(const std::string& key,
                               const rapidjson::Value& key_vals,
                               std::string& err_msg);
  /// \brief Parse a TCP service context.
  ///
  /// \param  command  The service command.
  /// \param  action   The action to take for the service command.
  ///
  /// \return The TcpContext for the service command.
  TcpContext* ParseService(char* command, TcpActionType action);

  /// \brief Modify a TCP service context.
  ///
  /// If the service is not in the collection of TCP service context's, it
  /// will be added to the collection. Otherwise, the existing service context
  /// is modified.
  ///
  /// \param  ref_context  The TCP context.
  ///
  /// \return True if the modification is successful, false otherwise.
  bool ModService(TcpContext* ref_context);

  /// \brief Delete a TCP service context.
  ///
  /// \param  ref_context  The TCP context.
  ///
  /// \return True if the deletion is successful, false otherwise.
  bool DelService(TcpContext* ref_context);

  /// \brief Get a unique tag for a flow.
  ///
  /// \return An integer tag to identify the flow.
  inline uint32_t flow_tag()
  {
    return ++flow_tag_;
  }

  /// Controls if main loop should continue running or not.
  bool                                           running_;

  /// Raw socket interface for the TCP Proxy's LAN side.
  iron::VirtualEdgeIf&                           edge_if_;

  /// The IRON bin mapping.
  iron::BinMap&                                  bin_map_shm_;

  /// Pool containing packets to use.
  iron::PacketPool&                              packet_pool_;

  /// FIFO object for BPF to TCP Proxy packet passing.
  iron::PacketFifo                               bpf_to_tcp_pkt_fifo_;

  /// FIFO object for TCP Proxy to BPF packet passing.
  iron::PacketFifo                               tcp_to_bpf_pkt_fifo_;

  /// The shared memory segment for weight queue depths.
  iron::SharedMemoryIF&                          weight_qd_shared_memory_;

  /// The TCP Proxy configuration information.
  TcpProxyConfig&                                proxy_config_;

  /// The socket manager.
  SocketMgr                                      socket_mgr_;

  /// The PktInfo pool.
  PktInfoPool                                    pkt_info_pool_;

  /// The IRON timer.
  iron::Timer                                    timer_;

  /// Backpressure queue normalization parameter (bits^2/sec).
  iron::KVal                                     k_val_;

  /// QueueDepths object to store deserialized local QLAM.
  iron::QueueDepths                              local_queue_depths_;

  /// Collection of Service context information.
  std::map<int, TcpContext*>                     svc_configs_;

  /// The flow utility function definition cache. This stores the utility
  /// function definition as a string for a 4-tuple (src_addr, dst_addr,
  /// src_port, dst_port). The entires in this collection take precedence over
  /// the utility function definitions that are part of the Service contexts.
  iron::HashTable<iron::FourTuple, std::string>  flow_utility_def_cache_;

  /// The DSCP cache.  This stores the DSCP value as an int (-1 indicating that
  /// we do not want to change the DSCP value of the packet, whatever it is) for
  /// a 4-tuple (src_add, dst_addr, src_port, dst_port).  The entries in this
  /// collection take precedence over the utility function definitions that are
  /// part of the Service contexts.
  iron::HashTable<iron::FourTuple, int8_t>       context_dscp_cache_;

  /// The default Utility Function Definition.
  std::string                                    default_utility_def_;

  /// The number of seamless server handoff lists.
  uint8_t                                        num_server_lists_;

  /// The seamless server handoff lists.
  ServerList*                                  server_lists_[kMaxServerLists];

  /// The number of existing outstanding reconnects. Reconnects are attempted
  /// when the chosen seamless handoff server is unreachable. Reconnects are
  /// only attempted for client configured servers that have an alternate
  /// server list in the proxy's configuration.
  uint8_t                                        num_recon_reqs_;

  /// Array of existing outstanding reconnections. This array stores the
  /// original SYN packets received for which the connection has failed due to
  /// an unreachable server. Reconnects are only attempted for client
  /// configured servers that have an alternate server list in the proxy's
  /// configuration.
  iron::Packet*                                  recon_reqs_[kMaxReconnects];

  /// The service sockets timer handle.
  iron::Timer::Handle                            svc_sockets_timer_;

  /// The next scheduled socket service time.
  iron::Time                                     next_sched_socket_svc_time_;

  /// The IRON Remote Control interface.
  iron::RemoteControlServer&                     remote_control_;

  /// Information on any active statistics pushing to a remote control
  /// client. Can only push to a single client at a time due to statistics
  /// resetting on each push.
  TcpStatsPushInfo                               tcp_stats_push_;

  /// The statistics collection interval, in milliseconds.
  uint32_t                                       stats_interval_ms_;

  /// Remembers if we are logging statistics.
  bool                                           log_stats_;

  /// True if we want to access queue depth information directly from shared
  /// memory, rather than periodically copying to local memory and accessing
  /// from there.
  bool                                           qd_direct_access_;

  /// Flow specific tag used to identify the flow.
  uint32_t                                       flow_tag_;

}; // end class TcpProxy

#endif // IRON_TCP_PROXY_TCP_PROXY_H
