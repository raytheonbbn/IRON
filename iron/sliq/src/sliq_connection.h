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
//
// This code is derived in part from the stablebits libquic code available at:
// https://github.com/stablebits/libquic.
//
// The stablebits code was forked from the devsisters libquic code available
// at:  https://github.com/devsisters/libquic
//
// The devsisters code was extracted from Google Chromium's QUIC
// implementation available at:
// https://chromium.googlesource.com/chromium/src.git/+/master/net/quic/
//
// The original source code file markings are preserved below.

// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#ifndef IRON_SLIQ_CONNECTION_H
#define IRON_SLIQ_CONNECTION_H

#include "sliq_app.h"
#include "sliq_capacity_estimator.h"
#include "sliq_framer.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_socket_manager.h"
#include "sliq_stream.h"
#include "sliq_types.h"

#include "fd_event.h"
#include "ipv4_endpoint.h"
#include "packet_pool.h"
#include "packet_set.h"
#include "rng.h"
#include "timer.h"


namespace sliq
{

  class ConnectionManager;
  class Stream;

  /// \brief Structure for a storing information for a single congestion
  /// control algorithm.
  struct CcAlg
  {
    CcAlg();
    ~CcAlg();

    /// The congestion control algorithm object.
    CongCtrlInterface*   cc_alg;

    /// The send timer.
    iron::Timer::Handle  send_timer;

    /// The next send time.
    iron::Time           next_send_time;

    /// The flag recording if ACK packet processing has been started.
    bool                 in_ack_proc;

    /// The setting for pacing retransmissions.
    bool                 use_rexmit_pacing;

    /// The setting for unacknowledged packet reporting.
    bool                 use_una_pkt_reporting;
  };

  /// \brief Structure for a storing information for multiple congestion
  /// control algorithms.
  struct CcAlgs
  {
    CcAlgs();
    ~CcAlgs();

    /// The overall setting for unacknowledged packet reporting.  Set to true
    /// if at least one congestion control algorithm requires this reporting.
    bool               use_una_pkt_reporting;

    /// The capacity estimator object.
    CapacityEstimator  cap_est;

    /// The current channel capacity estimate in bits per second.
    double             chan_cap_est_bps;

    /// The current transport capacity estimate in bits per second.
    double             trans_cap_est_bps;

    /// The amount of time, in seconds, since a congestion control limit event
    /// caused a capacity estimate update.
    double             ccl_time_sec;

    /// The number of congestion control algorithms currently in use.
    size_t             num_cc_alg;

    /// The array of congestion control algorithm settings.  Indexed by
    /// congestion control identifier (CCID).
    CongCtrl           cc_settings[SliqApp::kMaxCcAlgPerConn];

    /// The array of congestion control algorithm information.  Indexed by
    /// congestion control identifier (CCID).
    CcAlg              cc_alg[SliqApp::kMaxCcAlgPerConn];
  };

  /// \brief Class implementing the SLIQ connections.
  ///
  /// Each connection may be one of the following endpoints:
  ///   - server listen endpoint, waiting for connection requests from clients
  ///   - client data endpoint
  ///   - server data endpoint
  ///
  /// Note that this class is not thread-safe.
  class Connection
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  app             A reference to the common SLIQ application.
    /// \param  socket_mgr      A reference to the common socket manager.
    /// \param  connection_mgr  A reference to the common connection manager.
    /// \param  rng             A reference to the common random number
    ///                         generator.
    /// \param  packet_pool     A reference to the common pool of packets.
    /// \param  timer           A reference to the common timer.
    Connection(SliqApp& app, SocketManager& socket_mgr,
               ConnectionManager& connection_mgr, iron::RNG& rng,
               iron::PacketPool& packet_pool, iron::Timer& timer);

    /// \brief Destructor.
    virtual ~Connection();

    /// \brief Initialize a client connection that will attempt to connect to
    /// a server.
    ///
    /// The specified client address may either be 0.0.0.0:0 (for a TCP-like
    /// connection procedure) or a local IP address and specific port number
    /// (for a direct connection procedure).  Once connected, it can also send
    /// and receive data.  Returns the assigned endpoint ID.
    ///
    /// \param  client_address  A reference to the local IP address and port
    ///                         number to use.
    /// \param  server_address  A reference to the remote IP address and port
    ///                         number to use.
    /// \param  cc_alg          The congestion control algorithms and settings
    ///                         in an array.
    /// \param  num_cc_alg      The number of congestion control algorithms
    ///                         and settings in the specified array.
    /// \param  direct_conn     A flag specifying if this endpoint is part of
    ///                         a direct connection or not.
    /// \param  endpt_id        A reference to where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool InitClient(const iron::Ipv4Endpoint& client_address,
                    const iron::Ipv4Endpoint& server_address,
                    const CongCtrl* cc_alg, size_t num_cc_alg,
                    bool direct_conn, EndptId& endpt_id);

    /// \brief Initialize a server connection that only listens for connection
    /// requests from clients.
    ///
    /// Returns the assigned endpoint ID.
    ///
    /// \param  server_address  A reference to the local IP address and port
    ///                         number to use.
    /// \param  endpt_id        A reference to where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool InitServerListen(const iron::Ipv4Endpoint& server_address,
                          EndptId& endpt_id);

    /// \brief Initialize a server connection that only listens for connection
    /// requests from clients.
    ///
    /// Returns the assigned endpoint ID.
    ///
    /// \param  server_address  A reference to the local IP address and port
    ///                         number to use.
    /// \param  client_address  A reference to the remote IP address and port
    ///                         number to use.
    /// \param  endpt_id        A reference to where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool InitServerDirectData(const iron::Ipv4Endpoint& server_address,
                              const iron::Ipv4Endpoint& client_address,
                              EndptId& endpt_id);

    /// \brief Initiate a connection attempt to a server.
    ///
    /// Called on a client connection.  Does not block while the connection is
    /// being established.
    ///
    /// \param  server_address  A reference to the server's IP address and
    ///                         port number.
    ///
    /// \return  True on success, or false otherwise.
    bool ConnectToServer(const iron::Ipv4Endpoint& server_address);

    /// \brief Add a new stream.
    ///
    /// The stream IDs must be between 1 and 32 (inclusive), must be odd on
    /// the client side, and must be even on the server side.
    ///
    /// \param  stream_id  The new stream ID to create.  The stream ID must be
    ///                    odd on the client side, even on the server side,
    ///                    and between 1 and 32 (inclusive).
    /// \param  prio       The priority of the stream.  The highest priority
    ///                    is 0, and the lowest priority is 7.
    /// \param  rel        The reliability settings for the stream.
    /// \param  del_mode   The delivery mode for the stream.
    ///
    /// \return  True on success, or false otherwise.
    bool AddStream(StreamId stream_id, Priority prio, const Reliability& rel,
                   DeliveryMode del_mode);

    /// \brief Configure the connection's TCP friendliness/aggressiveness.
    ///
    /// \param  num_flows  The number of TCP flows to emulate in terms of
    ///                    TCP friendliness/aggressiveness.  The higher the
    ///                    number, the more aggressive.  Must be greater than
    ///                    or equal to one.
    ///
    /// \return  Returns true on success, or false if this setting is not
    ///          supported by the algorithm.
    bool ConfigureTcpFriendliness(uint32_t num_flows);

    /// \brief Configure a stream's transmit queue.
    ///
    /// \param  stream_id      The stream ID.
    /// \param  max_size_pkts  The queue's maximum size, in packets.
    /// \param  dequeue_rule   The queue's dequeue rule.
    /// \param  drop_rule      The queue's drop rule.
    ///
    /// \return  True on success, or false otherwise.
    bool ConfigureTransmitQueue(StreamId stream_id, size_t max_size_pkts,
                                DequeueRule dequeue_rule, DropRule drop_rule);

    /// \brief Configure a stream's semi-reliable packet delivery
    /// retransmission limit.
    ///
    /// \param  stream_id     The stream ID.
    /// \param  rexmit_limit  The packet delivery retransmission limit.
    ///
    /// \return  True on success, or false otherwise.
    bool ConfigureRexmitLimit(StreamId stream_id, RexmitLimit rexmit_limit);

    /// \brief Check if a stream is fully established or not.
    ///
    /// \param  stream_id  The stream ID to be queried.
    ///
    /// \return  True if the stream is fully established, or false otherwise.
    bool IsStreamEstablished(StreamId stream_id) const;

    /// \brief Send data on a stream.
    ///
    /// The connection takes ownership of the packet on success.
    ///
    /// \param  stream_id  The stream ID to send the data on.
    /// \param  data       A pointer to a packet containing the data to be
    ///                    sent.
    ///
    /// \return  True on success, or false otherwise.
    bool Send(StreamId stream_id, iron::Packet* data);

    /// \brief Called when data to be sent is dropped.
    ///
    /// This callback can only occur for best-effort or semi-reliable
    /// streams.  Ownership of the packet remains with SLIQ.
    ///
    /// \param  stream_id  The stream that is dropping the data.
    /// \param  data       A pointer to a packet containing the dropped data.
    inline void DropCallback(StreamId stream_id, iron::Packet* data)
    {
      // Pass the drop information up to the application.
      app_.ProcessPacketDrop(socket_id_, stream_id, data);
    }

    /// \brief Called when the connection's file descriptor has an event that
    /// is of interest.
    ///
    /// \param  fd     The file descriptor that needs servicing.
    /// \param  event  The events to process on the file descriptor.
    void ServiceFileDescriptor(int fd, iron::FdEvent event);

    /// \brief Called when new data is available on a stream.
    ///
    /// Ownership of the packet is transferred to the application.
    ///
    /// \param  stream_id  The stream that received the data.
    /// \param  data       A pointer to a packet containing the received data.
    inline void RecvCallback(StreamId stream_id, iron::Packet* data)
    {
      app_.Recv(socket_id_, stream_id, data);
    }

    /// \brief Get the current size of the stream's transmit queue, in
    /// bytes.
    ///
    /// \param  stream_id  The stream ID of interest.
    /// \param  size       A reference to where the current size, in bytes, is
    ///                    returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool GetTransmitQueueSizeInBytes(StreamId stream_id, size_t& size);

    /// \brief Get the current size of the stream's transmit queue, in
    /// packets.
    ///
    /// \param  stream_id  The stream ID of interest.
    /// \param  size       A reference to where the current size, in packets,
    ///                    is returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool GetTransmitQueueSizeInPackets(StreamId stream_id, size_t& size);

    /// \brief Called when a stream's transmit queue size changes.
    ///
    /// \param  stream_id  The stream ID of the transmit queue.
    /// \param  bytes      The updated number of bytes in the stream's
    ///                    transmit queue.
    inline void TransmitQueueSizeCallback(StreamId stream_id, size_t bytes)
    {
      // Pass the updated queue size up to the application.
      app_.ProcessTransmitQueueSize(socket_id_, stream_id, bytes);
    }

    /// \brief Initiate the closing of the stream as directed by the local
    /// application.
    ///
    /// \param  stream_id     The stream ID of the stream to be closed.
    /// \param  fully_closed  A reference to where a flag indicating if the
    ///                       stream is fully closed or not will be returned.
    ///
    /// \return  True on success, or false otherwise.
    bool InitiateCloseStream(StreamId stream_id, bool& fully_closed);

    /// \brief Initiate the closing of the connection as directed by the local
    /// application.
    ///
    /// \param  reason        The reason for the close.
    /// \param  fully_closed  A reference to where a flag indicating if the
    ///                       connection is fully closed or not will be
    ///                       returned.
    ///
    /// \return  True on success, or false otherwise.
    bool InitiateClose(ConnCloseCode reason, bool& fully_closed);

    /// \brief Called when a packet has been ACKed and there are RTT and
    /// packet delivery delay (PDD) samples to report to the application.
    ///
    /// \param  stream_id  The stream ID.
    /// \param  rtt_usec   The measured RTT in usec.
    /// \param  pdd_usec   The estimated packet delivery delay in usec.
    void PktAcked(StreamId stream_id, uint32_t rtt_usec, uint32_t pdd_usec);

    /// \brief Called when a stream is closed.
    ///
    /// \param  stream_id     The stream ID.
    /// \param  fully_closed  Indicates if the stream is fully closed.
    void CloseStreamCallback(StreamId stream_id, bool fully_closed);

    /// \brief Check if one of the congestion control algorithms will allow a
    /// data packet to be sent right now.
    ///
    /// This method includes the send pacing check and the congestion control
    /// CanSend() method check.  If a congestion control algorithm passes both
    /// of the specified checks, then "cc_id" is set and true is returned.
    ///
    /// \param  now    The current time.
    /// \param  bytes  The data packet size in bytes.
    /// \param  cc_id  A reference to a location where the congestion control
    ///                identifier of the algorithm that allows the send is
    ///                placed on success.
    ///
    /// \return  True if the data packet can be sent right now, or false if
    ///          not.
    bool CanSend(const iron::Time& now, size_t bytes, CcId& cc_id);

    /// \brief Check if one of the congestion control algorithms will allow a
    /// data packet to be resent right now.
    ///
    /// This method includes the send pacing check (if the congestion control
    /// algorithm requires pacing of retransmissions) and the congestion
    /// control CanResend() method check.  If a congestion control algorithm
    /// passes both of the specified checks, then "cc_id" is set and true is
    /// returned.
    ///
    /// \param  now         The current time.
    /// \param  bytes       The data packet size in bytes.
    /// \param  orig_cc_id  The data packet's associated congestion control
    ///                     identifier.  This is the congestion control
    ///                     algorithm that allowed the original transmission
    ///                     of the data packet.
    /// \param  cc_id       A reference to a location where the congestion
    ///                     control identifier of the algorithm that allows
    ///                     the send is placed on success.
    ///
    /// \return  True if the data packet can be sent right now, or false if
    ///          not.
    bool CanResend(const iron::Time& now, size_t bytes, CcId orig_cc_id,
                   CcId& cc_id);

    /// \brief Send a create stream packet to the peer.
    ///
    /// \param  ack        The ACK flag.
    /// \param  del_mode   The delivery mode.
    /// \param  rel        The reliability settings.
    /// \param  stream_id  The stream ID.
    /// \param  prio       The priority.
    /// \param  win_size   The initial window size in packets.
    /// \param  seq_num    The initial sequence number.
    ///
    /// \return  True on success, or false otherwise.
    bool SendCreateStreamPkt(bool ack, DeliveryMode del_mode,
                             const Reliability& rel, StreamId stream_id,
                             Priority prio, WindowSize win_size,
                             PktSeqNumber seq_num);

    /// \brief Send a reset stream packet to the peer.
    ///
    /// \param  stream_id  The stream ID.
    /// \param  error      The error code.
    /// \param  seq_num    The final sequence number.
    ///
    /// \return  True on success, or false otherwise.
    bool SendResetStreamPkt(StreamId stream_id, StreamErrorCode error,
                            PktSeqNumber seq_num);

    /// \brief Send a data packet to the peer.
    ///
    /// Attempts to also opportunistically send ACK and CC sync packets with
    /// the data packet.
    ///
    /// \param  now       The current time.
    /// \param  data_hdr  A reference to the data header to use.
    /// \param  data      A pointer to the payload data in a packet object.
    ///                   May be NULL if no payload is to be sent.
    /// \param  bytes     A reference to a variable where the total number of
    ///                   bytes, including SLIQ headers but excluding IP and
    ///                   UDP headers, attempted to be sent is placed.  Only
    ///                   useful if the write result is either WRITE_STATUS_OK
    ///                   or WRITE_STATUS_BLOCKED.
    ///
    /// \return  The write result from the send.
    WriteResult SendDataPkt(const iron::Time& now, DataHeader& data_hdr,
                            iron::Packet* data, size_t& bytes);

    /// \brief Send one or more congestion control packet train packets.
    ///
    /// \param  id           The congestion control identifier.
    /// \param  type         The packet traing packet type.
    /// \param  seq          The initial packet train sequence number.
    /// \param  irt          The packet train inter-receive time in usec.
    /// \param  payload_len  The payload length in bytes.
    /// \param  pkt_cnt      The number of packet train packets to send.
    ///
    /// \return  True on success, or false otherwise.
    bool SendCcPktTrainPkts(CcId id, uint8_t type, uint8_t seq, uint32_t irt,
                            size_t payload_len, size_t pkt_cnt);

    /// \brief Update the capacity estimate after a packet has been ACKed.
    ///
    /// \param  now                The current time.
    /// \param  cc_id              The identifier of the congestion control
    ///                            algorithm that allowed the packet to be
    ///                            sent.
    /// \param  app_payload_bytes  The number of application payload bytes in
    ///                            the packet.
    /// \param  bytes_sent         The size of the SLIQ headers and payload
    ///                            sent, in bytes.
    void UpdateCapacityEstimate(const iron::Time& now, CcId cc_id,
                                size_t app_payload_bytes, size_t bytes_sent);

    /// \brief Get the timestamp corresponding to the current local time.
    ///
    /// \return  The current local timestamp.
    PktTimestamp GetCurrentLocalTimestamp();

    /// \brief Get the current one-way delay estimate for a packet.
    ///
    /// \param  send_ts    The sender's timestamp from the packet header.
    /// \param  recv_time  A reference to the packet receive time.
    ///
    /// \return  The current one-way delay estimate, in seconds.
    double GetOneWayDelayEst(PktTimestamp send_ts,
                             const iron::Time& recv_time);

    /// \brief Perform any pending callbacks.
    ///
    /// This must only be called when the SLIQ API is reentrant.
    void DoReentrantCallbacks();

    /// \brief Disable application callbacks in the destructor.
    ///
    /// This is necessary to avoid the Connection from calling back into the
    /// Application when it is already in its destructor.
    inline void DisableCallbacks()
    {
      do_callbacks_ = false;
    }

    /// \brief Get the endpoint type for the connection.
    ///
    /// \return  The connection object's endpoint type.
    inline EndptType endpt_type() const
    {
      return type_;
    }

    /// \brief Get the connected status.
    ///
    /// \return  True if the connection object is fully connected, or false
    ///          otherwise.
    inline bool connected() const
    {
      return(state_ == CONNECTED);
    }

    /// \brief Check if the connection is currently write blocked.
    ///
    /// \return  True if the connection is currently write blocked.
    inline bool IsWriteBlocked() const
    {
      return is_write_blocked_;
    }

    /// \brief Check if the connection is currently in an outage.
    ///
    /// \return  True if the connection is currently in an outage.
    inline bool IsInOutage() const
    {
      return is_in_outage_;
    }

    /// \brief Get the connection's peer address and port number.
    ///
    /// \return  The connection's peer address and port number.
    inline const iron::Ipv4Endpoint& GetPeerEndpoint()
    {
      return peer_addr_;
    }

    /// \brief Get the local timestamp clock correction value.
    ///
    /// \return  The local timestamp clock correction value.
    inline PktTimestamp GetLocalTimestampCorrection()
    {
      return ts_corr_;
    }

    /// \brief Get the next connection sequence number for a sent data packet.
    ///
    /// \return  The connection sequence number.
    inline PktSeqNumber GetConnSeqNum()
    {
      return next_conn_seq_num_++;
    }

    /// \brief Get the sent data packet count after sending a data packet.
    ///
    /// \return  The sent data packet count.
    inline PktCount GetSentPktCnt()
    {
      return stats_snd_data_pkts_sent_;
    }

    /// \brief Get the current packet error rate (PER) estimate for packets
    /// sent by the connection.
    ///
    /// \return  The current local PER estimate.
    inline double StatsGetLocalPer() const
    {
      return stats_local_per_;
    }

   private:

    /// \brief Copy constructor.
    Connection(const Connection& sc);

    /// \brief Assignment operator.
    Connection& operator=(const Connection& sc);

    /// \brief Initialize the connection state.
    ///
    /// \param  type  The endpoint type.
    ///
    /// \return  True on success, or false otherwise.
    bool InitState(EndptType type);

    /// \brief Initialize a server connection that will send and receive data
    /// with a connected client.
    ///
    /// This is called by the ProcessClientHello() method.  Returns the
    /// assigned endpoint ID.
    ///
    /// \param  server_port     The local server port number to use.
    /// \param  client_address  A reference to the client's IP address and
    ///                         port number.
    /// \param  id              The client ID from the connection handshake.
    /// \param  cc_alg          The congestion control algorithms and settings
    ///                         in an array.
    /// \param  num_cc_alg      The number of congestion control algorithms
    ///                         and settings in the specified array.
    /// \param  endpt_id        A reference to where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool InitServerData(uint16_t server_port,
                        const iron::Ipv4Endpoint& client_address, ClientId id,
                        const CongCtrl* cc_alg, size_t num_cc_alg,
                        EndptId& endpt_id);

    /// \brief Continue with a connection attempt to a client that has already
    /// been started.
    ///
    /// Called after calling InitServerData() and having the application
    /// accept the connection request.  Called on a server data connection.
    /// Does not block while the connection is being established.
    ///
    /// \param  echo_ts  The echo timestamp.
    /// \param  id       The client ID from the connection handshake.
    ///
    /// \return  True on success, or false otherwise.
    bool ContinueConnectToClient(PktTimestamp echo_ts, ClientId id);

    /// \brief Create the necessary congestion control objects for the
    /// connection.
    ///
    /// \param  is_client  The flag determining if this is the client or
    ///                    server side of the connection.
    ///
    /// \return  True on success, or false otherwise.
    bool CreateCongCtrlObjects(bool is_client);

    /// \brief Send a connection handshake packet to the specified
    /// destination.
    ///
    /// \param  dst      A reference to the packet's destination.
    /// \param  tag      The message tag.
    /// \param  echo_ts  The echo timestamp.
    /// \param  id       The client ID.
    ///
    /// \return  True on success, or false otherwise.
    bool SendConnHndshkPkt(const iron::Ipv4Endpoint& dst, MsgTag tag,
                           PktTimestamp echo_ts, ClientId id);

    /// \brief Send a reset connection packet to the peer.
    ///
    /// \param  error  The error code.
    ///
    /// \return  True on success, or false otherwise.
    bool SendResetConnPkt(ConnErrorCode error);

    /// \brief Send a close connection packet to the peer.
    ///
    /// \param  ack     The ACK flag.
    /// \param  reason  The reason code.
    ///
    /// \return  True on success, or false otherwise.
    bool SendCloseConnPkt(bool ack, ConnCloseCode reason);

    /// \brief Send an ACK packet to the peer.
    ///
    /// The packet remains owned by the caller.
    ///
    /// \param  now    The current time.
    /// \param  cc_id  The congestion control identifier for use in updating
    ///                the capacity estimate.
    /// \param  pkt    A pointer to the ACK packet to send.
    ///
    /// \return  True on success, or false otherwise.
    void SendAckPkt(const iron::Time& now, CcId cc_id, iron::Packet* pkt);

    /// \brief Send a congestion control synchronization packet to the peer.
    ///
    /// \param  cc_id            The congestion control identifier.
    /// \param  cc_sync_seq_num  The sequence number to be sent.
    /// \param  cc_sync_params   The parameters to be sent.
    ///
    /// \return  True on success, or false otherwise.
    bool SendCcSyncPkt(CcId cc_id, uint16_t cc_sync_seq_num,
                       uint32_t cc_sync_params);

    /// \brief Send a received packet count packet to the peer.
    ///
    /// \return  True on success, or false otherwise.
    bool SendRcvdPktCnt();

    /// \brief Receive packets and process them.
    void ReceivePackets();

    /// \brief Process a received connection handshake header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessConnHandshake(ConnHndshkHeader& hdr,
                              const iron::Ipv4Endpoint& src);

    /// \brief Process a received client hello connection handshake header
    /// when the connection is a server data connection.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessDataClientHello(ConnHndshkHeader& hdr,
                                const iron::Ipv4Endpoint& src);

    /// \brief Process a received client hello connection handshake header
    /// when the connection is a server listen connection.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessClientHello(ConnHndshkHeader& hdr,
                            const iron::Ipv4Endpoint& src);

    /// \brief Process a received server hello connection handshake header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessServerHello(ConnHndshkHeader& hdr,
                            const iron::Ipv4Endpoint& src);

    /// \brief Process a received client confirm connection handshake header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessClientConfirm(ConnHndshkHeader& hdr,
                              const iron::Ipv4Endpoint& src);

    /// \brief Process a received reject connection handshake header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessReject(ConnHndshkHeader& hdr, const iron::Ipv4Endpoint& src);

    /// \brief Process a received reset connection header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessResetConn(ResetConnHeader& hdr,
                          const iron::Ipv4Endpoint& src);

    /// \brief Process a received close connection header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessCloseConn(CloseConnHeader& hdr,
                          const iron::Ipv4Endpoint& src);

    /// \brief Process a received create stream header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessCreateStream(CreateStreamHeader& hdr,
                             const iron::Ipv4Endpoint& src);

    /// \brief Process a received reset stream header.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    void ProcessResetStream(ResetStreamHeader& hdr,
                            const iron::Ipv4Endpoint& src);

    /// \brief Check that received data header is good before processing it.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    ///
    /// \return  Returns true if the data header is for this connection and
    ///          not a duplicate, or false otherwise.
    bool IsGoodDataPacket(DataHeader& hdr, const iron::Ipv4Endpoint& src);

    /// \brief Process a received data header.
    ///
    /// \param  hdr       The received header.
    /// \param  src       The source address of the received header.
    /// \param  rcv_time  The receive time.
    /// \param  pkt_size  The size of the packet, including all SLIQ headers,
    ///                   in bytes.
    ///
    /// \return  Returns true if ownership of the the payload packet object is
    ///          passed to the stream, or false if not.
    bool ProcessData(DataHeader& hdr, const iron::Ipv4Endpoint& src,
                     const iron::Time& rcv_time, size_t pkt_size);

    /// \brief Check that received ACK header is good before processing it.
    ///
    /// \param  hdr  The received header.
    /// \param  src  The source address of the received header.
    ///
    /// \return  Returns true if the ACK header is for this connection and
    ///          not a duplicate, or false otherwise.
    bool IsGoodAckPacket(AckHeader& hdr, const iron::Ipv4Endpoint& src);

    /// \brief Process a received ACK header.
    ///
    /// \param  hdr       The received header.
    /// \param  src       The source address of the received header.
    /// \param  rcv_time  The receive time.
    void ProcessAck(AckHeader& hdr, const iron::Ipv4Endpoint& src,
                    const iron::Time& rcv_time);

    /// \brief Process an implicit ACK.
    ///
    /// \param  ack_stream_mask  A mask of stream IDs that have received an
    ///                          ACK header.
    void ProcessImplicitAcks(uint64_t ack_stream_mask);

    /// \brief Process a received received packet count header.
    ///
    /// \param  hdr       The received received packet count header.
    /// \param  rcv_time  The receive time.
    void ProcessRcvdPktCntInfo(RcvdPktCntHeader& hdr,
                               const iron::Time& rcv_time);

    /// \brief Immediately send an ACK packet and record that it was sent.
    ///
    /// \param  now        The current time.
    /// \param  cc_id      The identifier of the congestion control algorithm
    ///                    for updating the capacity estimate.
    /// \param  stream_id  The stream ID of the stream initiating the ACK.
    void ForceAck(const iron::Time& now, CcId cc_id, StreamId stream_id);

    /// \brief Maybe send an ACK packet.
    ///
    /// This method is only called when a data packet is received, and only if
    /// an ACK packet is not required to be sent immediately.
    ///
    /// \param  now        The current time.
    /// \param  cc_id      The identifier of the congestion control algorithm
    ///                    for updating the capacity estimate.
    /// \param  stream_id  The stream ID of the stream initiating the ACK.
    void MaybeAck(const iron::Time& now, CcId cc_id, StreamId stream_id);

    /// \brief Attempt to add the available ACKs to a single packet.
    ///
    /// \param  now              The current time.
    /// \param  rsvd_len         The reserved packet length in bytes.
    /// \param  pkt              A reference to a pointer to the packet where
    ///                          the ACK headers will be appended.  If NULL,
    ///                          then a packet will be generated and placed in
    ///                          this pointer.
    /// \param cancel_ack_timer  A reference to a flag that is set to true if
    ///                          the ACK timer should be canceled after the
    ///                          packet has been sent.
    ///
    /// \return  True on success, or false on error.
    bool GetAcks(const iron::Time& now, size_t rsvd_len, iron::Packet*& pkt,
                 bool& cancel_ack_timer);

    /// \brief Send an ACK packet.
    ///
    /// \param  now                The current time.
    /// \param  cc_id              The identifier of the congestion control
    ///                            algorithm for updating the capacity
    ///                            estimate.
    /// \param  trigger_stream_id  The stream ID of the stream that received a
    ///                            data packet and is initiating the ACK.
    void SendAck(const iron::Time& now, CcId cc_id,
                 StreamId trigger_stream_id);

    /// \brief Attempt to add a received packet count header to a packet.
    ///
    /// \param  rsvd_len  The reserved packet length in bytes.
    /// \param  pkt       A reference to a pointer to the packet where the
    ///                   received packet count header will be appended.  If
    ///                   NULL, then a packet will be generated and placed in
    ///                   this pointer.
    void AddRcvdPktCnt(size_t rsvd_len, iron::Packet*& pkt);

    /// \brief Check if all of the stream data being sent is currently ACKed.
    ///
    /// \return  True if all of the stream data is currently ACKed, or false
    ///          otherwise.
    bool IsAllDataAcked();

    /// \brief Force all of the unACKed packets in each stream to be
    /// considered lost.
    ///
    /// \param  now  The current time.
    void ForceUnackedPacketsLost(const iron::Time& now);

    /// \brief Check if the peer has been heard from recently.
    ///
    /// \param  now  The current time.
    ///
    /// \return  True if the peer has been heard from recently, or false
    ///          otherwise.
    bool IsPeerResponsive(const iron::Time& now);

    /// \brief Cause the connection to enter a mode for handling an outage.
    ///
    /// \param  now        The current time.
    /// \param  stream_id  The stream ID of the stream that detected the
    ///                    outage.
    void EnterOutage(const iron::Time& now, StreamId stream_id);

    /// \brief Cause the connection to leave the mode for handling outages.
    ///
    /// \param  full_proc  Controls if full processing should be performed or
    ///                    not.
    void LeaveOutage(bool full_proc);

    /// \brief Set the socket as write blocked.
    ///
    /// \param  stream_id  The stream ID of the stream that was sending on the
    ///                    socket when the write blocked.
    void SetWriteBlocked(StreamId stream_id);

    /// \brief Unset the socket as write blocked.
    ///
    /// \param  reblocked_stream_id  The stream ID of the stream that is now
    ///                              blocked when this method returns false.
    ///
    /// \return  Returns true if the socket is unblocked after allowing the
    ///          blocked stream to send its blocked packet, or false if the
    ///          socket is blocked again.
    bool ClearWriteBlocked(StreamId& reblocked_stream_id);

    /// \brief Give all of the streams a chance to send data.
    ///
    /// Before returning, this method makes sure that a send pacing timer is
    /// active for each congestion control algorithm that returns a non-zero
    /// time from TimeUntilSend().
    void OnCanWrite();

    /// \brief Force a stream to retransmit one data packet, or at least send
    /// a persist packet.
    ///
    /// The resent data packet will be the lowest unACKed packet, if
    /// available.  Otherwise, a persist packet is sent instead.
    ///
    /// \param  now  The current time.
    ///
    /// \return  Returns the number of packets sent, either 0 or 1.
    int RexmitOneDataPkt(const iron::Time& now);

    /// \brief Force all streams to each retransmit one data packet, or at
    /// least send a persist packet.
    ///
    /// The resent data packet will be the highest unACKed packet, if
    /// available.  Otherwise, a persist packet is sent instead.
    void RexmitDataPkts();

    /// \brief Process a client hello packet timer callback.
    void ClientHelloTimeout();

    /// \brief Process a client hello packet timer callback.
    void ServerHelloTimeout();

    /// \brief Process a send timer callback for a congestion control
    /// algorithm.
    ///
    /// \param  cc_id  The identifier of the congestion control algorithm.
    void SendTimeout(CcId cc_id);

    /// \brief Process an ACK timer callback.
    ///
    /// \param  cc_id  The identifier of the congestion control algorithm for
    ///                updating the capacity estimate.
    void AckTimeout(CcId cc_id);

    /// \brief Process a close connection timer callback.
    void CloseConnTimeout();

    /// \brief Process an RTO timer callback.
    void RtoCallback();

    /// \brief Process a retransmission timeout.
    ///
    /// \param  now  The current time.
    void RexmitTimeout(const iron::Time& now);

    /// \brief Start the client hello timer.
    ///
    /// \return  True if the timer is started successfully.
    bool StartClientHelloTimer();

    /// \brief Start the server hello timer.
    ///
    /// \return  True if the timer is started successfully.
    bool StartServerHelloTimer();

    /// \brief Start the pacing timer.
    ///
    /// \param  now       The current time.
    /// \param  cc_id     The congestion control identifier.
    /// \param  duration  The timer duration.
    void StartSendTimer(const iron::Time& now, CcId cc_id,
                        const iron::Time& duration);

    /// \brief Start the underlying RTO timer that runs constantly.
    ///
    /// \param  now       The current time.
    /// \param  duration  The timer duration.
    ///
    /// \return  True if the timer is started successfully.
    bool StartRtoTimer();

    /// \brief Set the connection-level retransmission timer expiration time.
    ///
    /// \param  now       The current time.
    /// \param  duration  The timer duration.
    void SetRexmitTime(const iron::Time& now, const iron::Time& duration);

    /// \brief Set the connection-level outage retransmission timer expiration
    /// time.
    ///
    /// \param  now  The current time.
    void SetOutageRexmitTime(const iron::Time& now);

    /// \brief Check if any congestion control algorithm currently requires a
    /// fast RTO.
    ///
    /// \return  True if at least one congestion control algorithm requires a
    ///          fast RTO.
    bool SetFastRto();

    /// \brief Start the close connection timer.
    ///
    /// \return  True if the timer is started successfully.
    bool StartCloseConnTimer();

    /// \brief Cancel all timers.
    void CancelAllTimers();

    /// \brief Update the connection's timestamp state based on a received
    /// packet's receive time and timestamp fields.
    ///
    /// \param  recv_time      The packet's receive time.
    /// \param  send_ts        The packet header's timestamp field.
    /// \param  send_ts_delta  The packet header's timestamp delta field.
    void UpdateTimestampState(iron::Time& recv_time, PktTimestamp send_ts,
                              PktTimestamp send_ts_delta);

    /// \brief Record a new Stream.
    ///
    /// \param  stream     A pointer to the new Stream object.
    /// \param  stream_id  The stream ID.
    /// \param  prio       The stream's priority.
    void RecordNewStream(Stream* stream, StreamId stream_id, Priority prio);

    /// \brief Get the Stream pointer for a stream ID.
    ///
    /// \param  stream_id  The stream ID.
    ///
    /// \return  A pointer to the Stream object if it is found, or NULL if
    ///          it is not found.
    Stream* GetStream(StreamId stream_id) const;

    /// \brief Check if the specified stream ID is valid.
    ///
    /// \param  stream_id  The stream ID.
    ///
    /// \return  True if the stream ID is valid.
    bool StreamIdIsValid(StreamId stream_id) const;

    /// \brief Check if the specified priority value is valid.
    ///
    /// \param  prio  The priority value.
    ///
    /// \return  True if the priority value is valid.
    bool PriorityIsValid(Priority prio) const;

    /// \brief Check if the specified reliability settings are valid.
    ///
    /// \param  rel       The reliability settings to be checked.
    /// \param  del_mode  The delivery mode.
    ///
    /// \return  True if the reliability settings are valid.
    bool ReliabilityIsValid(const Reliability& rel,
                            DeliveryMode del_mode) const;

    /// \brief Check if the object's congestion control algorithm and settings
    /// are valid, and possible update them.
    ///
    /// This method will update the congestion control algorithm and settings
    /// if allow_updates is true, including setting all fields if congestion
    /// control algorithm is DEFAULT_CC.
    ///
    /// \param  alg            The congestion control algorithm and settings.
    /// \param  allow_updates  A flag controlling if the settings may be
    ///                        updated.
    ///
    /// \return  True if the congestion control algorithm and settings are
    ///          valid.
    bool CongCtrlSettingIsValid(CongCtrl& alg, bool allow_updates) const;

    /// \brief Convert a congestion control algorithm and settings to a
    /// string.
    ///
    /// \param  alg  The congestion control algorithm and settings.
    ///
    /// \return  The resulting string.
    const char* CongCtrlAlgToString(const CongCtrl& alg) const;

    /// The possible connection states.
    ///
    /// During connection establishment, the client goes through the states
    /// UNCONNECTED, SENT_CHLO (when the client hello has been sent), and
    /// CONNECTED (when the server hello has been received).  The server goes
    /// through the states UNCONNECTED, SENT_SHLO (when the client hello has
    /// been received and the server hello has been sent), and CONNECTED (when
    /// the client confirmation has been received).
    ///
    /// During connection teardown, the endpoint that calls Close() first goes
    /// through the states CONNECTED, CONN_CLOSE_WAIT (when Close() is called
    /// and the close connection packet is sent to the peer), and CLOSED (when
    /// the close connection packet is received from the peer).  The endpoint
    /// that does not call Close() first goes through the states CONNECTED,
    /// APP_CLOSE_WAIT (when the close connection packet is received), and
    /// CLOSED (when Close() is called and the close connection packet is sent
    /// to the peer).
    enum ConnState
    {
      UNCONNECTED,
      SENT_CHLO,
      SENT_SHLO,
      CONNECTED,
      CONN_CLOSE_WAIT,
      APP_CLOSE_WAIT,
      CLOSED
    };

    /// \brief Helper structure for stream information.
    ///
    /// The structure is in use when stream is non-NULL.
    struct StreamInfo
    {
      StreamInfo();
      ~StreamInfo();

      Stream*   stream;
      Priority  priority;
      uint8_t   extra_acks;
      bool      delayed_ack;
      bool      is_write_blocked;
    };

    /// The size of the array for accessing streams.
    static const size_t  kStreamArraySize = (kMaxStreamId + 1);

    /// \brief Helper structure for a band of streams with the same priority.
    struct BandInfo
    {
      Priority  prio;
      size_t    start;
      size_t    size;
      size_t    next;
    };

    /// \brief Helper structure for prioritized round-robin OnCanWrite() calls
    /// into streams.
    ///
    /// There is a band for all of the streams having the same priority level.
    /// The bands are stored from highest priority to lowest priority.  Each
    /// band references a common array of the stream IDs.  Each band remembers
    /// the next stream to check to guarantee fairness.
    struct PrioRndRbnInfo
    {
      PrioRndRbnInfo() : num_streams(0), num_bands(0), band(), stream_id() {}
      ~PrioRndRbnInfo() {}

      size_t    num_streams;
      size_t    num_bands;

      BandInfo  band[kNumPriorities];

      StreamId  stream_id[kStreamArraySize];
    };

    /// \brief The structure of state information for tracking the estimated
    /// one-way delay (OWD) for packets sent from the remote endpoint to this
    /// (the local) endpoint.
    ///
    /// GOAL: To adjust each packet's time-to-go (TTG) value by the OWD for
    /// that packet.  This includes the transmission, propagation, and
    /// queueing delays from the sending endpoint to this endpoint.
    ///
    /// ASSUMPTIONS: The network links used to connect the endpoints may be
    /// asymmetric, but are assumed to be symmetric for this estimation
    /// approach.  Both endpoints have a monotonic clock available.  The two
    /// clocks are not synchronized, and there may be clock skew (slightly
    /// different frequencies between the two clocks).
    ///
    /// APPROACH: The idea for adjusting the TTG for the one-way delay is to
    /// send local clock timestamps and local-to-remote clock difference
    /// values in packets exchanged by the two endpoints.  These values are
    /// used by the receiving endpoint, along with its local clock timestamp
    /// when the packet was received, to estimate the one-way delay.  The
    /// minimum RTT and minimum timestamp difference values (both local and
    /// remote) are collected over a OWD sampling period and used by the
    /// computations in the next sampling period.
    ///
    /// DETAILS: At start up, one endpoint computes a local clock timestamp
    /// correction value from an early packet received from the other
    /// endpoint, which will bring the local clock timestamp values used in
    /// the following computations close to the remote clock timestamp values.
    /// This prevents issues due to timestamp wrap-around in the 32-bit
    /// timestamp field computations that follow.  This correction value is
    /// assumed to have already been applied to one endpoint's clock timestamp
    /// values in the following computations.
    ///
    /// The equations use the following time values for two packets exchanged
    /// between the two endpoints.
    ///
    ///           Local              Remote
    ///           =====              ======
    ///            Tl0 -------_
    ///                        ------> Tr1
    ///                       _------- Tr2
    ///            Tl3 <------
    ///
    /// During a sampling period, the sender timestamp and clock difference
    /// values from each received packet are used along with the local clock's
    /// timestamp.  These will be called:
    ///
    ///   Tl3 = local clock timestamp at packet receive time (local)
    ///   Tr2 = remote clock timestamp at packet send time (from packet)
    ///   Dr  = remote clock difference value (from packet) = (Tr1 - Tl0)
    ///   Dl  = local clock difference value = (Tl3 - Tr2)
    ///
    /// The network RTT estimate from this packet exchange is then:
    ///
    ///   rtt = (Time From Send to Receive) - (Processing Time at Receiver)
    ///       = (Tl3 - Tl0) - (Tr2 - Tr1)
    ///       = (Tl3 - Tr2) + (Tr1 - Tl0)
    ///       = Dl + Dr
    ///
    /// Thus, if the minimum values of Dl and Dr are tracked over a time
    /// interval (the OWD sampling period), the minimum network RTT estimate
    /// at the end of that interval is:
    ///
    ///   min_rtt = MIN(Dl) + MIN(Dr)
    ///
    /// Given the min_rtt and min_Dl = MIN(Dl) values from the previous
    /// sampling period, the OWD estimate for a received packet in the current
    /// sampling period is then:
    ///
    ///   Dl  = local clock difference value for packet
    ///       = (Tl3 - Tr2)
    ///
    ///   owd = (One Half the Minimum Network RTT) + (Packet Queueing Delay)
    ///       = (0.5 * min_rtt) + MAX((Dl - min_Dl), 0)
    ///
    /// The TTG adjustment for the received packet is then:
    ///
    ///   ttg' = ttg - owd
    ///
    struct OwdInfo
    {
      OwdInfo()
          : cur_ready_(false), cur_min_rtt_(), cur_min_local_delta_(0),
            next_end_time_(), next_delta_cnt_(0), next_min_local_delta_(0),
            next_min_remote_delta_(0), prev_pkt_delta_(0)
      {}

      ~OwdInfo()
      {}

      /// A flag recording if the current state is ready or not.
      bool        cur_ready_;

      /// The current minimum RTT.
      iron::Time  cur_min_rtt_;

      /// The current minimum local timestamp delta in microseconds.  Computed
      /// as (local_timestamp - remote_timestamp).
      int64_t     cur_min_local_delta_;

      /// The one-way delay sampling period end time.
      iron::Time  next_end_time_;

      /// The number of samples in the one-way delay sampling period.
      uint32_t    next_delta_cnt_;

      /// The current period's minimum observed local timestamp delta in
      /// microseconds.
      int64_t     next_min_local_delta_;

      /// The current period's minimum observed remote timestamp delta in
      /// microseconds.
      int64_t     next_min_remote_delta_;

      /// The previous timestamp delta value computed, in microseconds.  Used
      /// when the received data packet is missing the send timestamp.
      int64_t     prev_pkt_delta_;
    };

    // ---------- Components Used By Connections ----------

    /// The SLIQ application.
    SliqApp&             app_;

    /// The socket manager.
    SocketManager&       socket_mgr_;

    /// The connection manager.
    ConnectionManager&   conn_mgr_;

    /// The random number generator.
    iron::RNG&           rng_;

    /// Pool containing packets to use.
    iron::PacketPool&    packet_pool_;

    /// Timer manager to use.
    iron::Timer&         timer_;

    /// The RTT manager.
    RttManager           rtt_mgr_;

    /// The packet framer.
    Framer               framer_;

    // ---------- Connection State Information ----------

    /// The endpoint type.
    EndptType            type_;

    /// The initialized flag.
    bool                 initialized_;

    /// The current connection state.
    ConnState            state_;

    /// The local address and port number.
    iron::Ipv4Endpoint   self_addr_;

    /// The peer's address and port number.
    iron::Ipv4Endpoint   peer_addr_;

    /// The client's unique ID for the connection.
    ClientId             client_id_;

    /// The UDP socket file descriptor.  Also used as the endpoint ID.
    SocketId             socket_id_;

    /// A flag to record if writing to the UDP socket is blocked.
    bool                 is_write_blocked_;

    /// A flag to record if the connection is in a retransmission timeout.
    bool                 is_in_rto_;

    /// A flag to record if the connection is in an outage.
    bool                 is_in_outage_;

    /// The stream ID for the stream that retransmits during an outage.
    StreamId             outage_stream_id_;

    /// The outage start time.
    iron::Time           outage_start_time_;

    // ---------- Congestion Control ----------

    /// The congestion control algorithms.
    CcAlgs               cc_algs_;

    // ---------- Queues and Buffers ----------

    /// The packet set for receiving packets from the UDP socket.
    iron::PacketSet      pkt_set_;

    /// An ACK header for parsing and processing received packets.
    AckHeader            ack_hdr_;

    // ---------- ACK Generation ----------

    /// The number of data packets received since the last ACK packet was
    /// sent.
    size_t               pkts_since_last_ack_;

    // ---------- Timers ----------

    /// The tolerance used for timers.
    iron::Time           timer_tolerance_;

    /// The number of hellos sent for connection establishment.
    int                  num_hellos_;

    /// The hello timer handle.
    iron::Timer::Handle  hello_timer_;

    /// The last client hello timestamp.
    PktTimestamp         client_hello_timestamp_;

    /// The last client hello receive time.
    iron::Time           client_hello_recv_time_;

    /// The ACK timer handle.
    iron::Timer::Handle  ack_timer_;

    /// The number of close connections sent for connection teardown.
    int                  num_closes_;

    /// The close connection timer handle.
    iron::Timer::Handle  close_timer_;

    /// The retransmission timer duration.
    iron::Time           rto_duration_;

    /// The retransmission timer expiration time.
    iron::Time           rto_time_;

    /// The retransmission timer handle.
    iron::Timer::Handle  rto_timer_;

    /// The number of retransmission timeouts.
    int                  rto_timeout_cnt_;

    // ---------- Packet Send and Receive Times ----------

    /// The time that a data packet that would generate an ACK packet was sent
    /// on the connection since an ACK was received.
    iron::Time           data_pkt_send_time_;

    /// The time that the last ACK or data packet was received on the
    /// connection.
    iron::Time           ack_or_data_pkt_recv_time_;

    /// The time that the last data packet was received on the connection.
    iron::Time           data_pkt_recv_time_;

    /// The expected data packet inter-receive time, in seconds.
    double               data_pkt_irt_sec_;

    // ---------- Capacity Estimate Callbacks ----------

    /// Perform the capacity estimate callback.
    bool                 do_cap_est_callback_;

    // ---------- Packet Timestamp Clock Differences ----------

    /// The local timestamp clock correction value to be added to the local
    /// clock.
    PktTimestamp         ts_corr_;

    /// The local timestamp clock difference.
    PktTimestamp         ts_delta_;

    /// The remote timestamp clock difference.
    PktTimestamp         rmt_ts_delta_;

    // ---------- RTT and PDD Estimates ----------

    /// The number of RTT and Packet Delivery Delay (PDD) estimates awaiting a
    /// callback.
    uint32_t             num_rtt_pdd_samples_;

    /// The RTT and PDD estimates to report in the callback.
    RttPdd*              rtt_pdd_samples_;

    // ---------- OWD Estimates ----------

    /// The One-Way Delay (OWD) estimate information for adjusting TTG values.
    OwdInfo              owd_;

    // ---------- Close Connection Callbacks ----------

    /// Perform the close connection callback.
    bool                 do_close_conn_callback_;

    // ---------- Statistics ----------

    /// The received packet count header information at the receive side.
    RcvdPktCntHeader     stats_rcv_rpc_hdr_;

    /// The number of data packet receptions since the last received packet
    /// count header was sent at the receive side.
    uint32_t             stats_rcv_rpc_trigger_cnt_;

    /// The number of data packet transmissions at the send side.
    PktCount             stats_snd_data_pkts_sent_;

    /// The starting number of data packet transmissions for the next packet
    /// error rate (PER) update at the send side.
    PktCount             stats_snd_start_pkts_sent_;

    /// The starting number of data packet receptions for the next packet
    /// error rate (PER) update at the send side.
    PktCount             stats_snd_start_pkts_rcvd_;

    /// The time for the next packet error rate (PER) update at the send side.
    iron::Time           stats_snd_per_update_time_;

    /// The estimated packet error rate (PER) for data packets sent.
    double               stats_local_per_;

    /// The last received packet count to be received.
    PktCount             stats_last_rpc_;

    // ---------- Specialized Members ----------

    /// Perform callbacks to the application in the destructor.
    bool                 do_callbacks_;

    /// The reason that the connection is being closed.
    ConnCloseCode        close_reason_;

    // ---------- Stream Information ----------

    /// The next connection sequence number to be assigned to a sent packet.
    PktSeqNumber         next_conn_seq_num_;

    /// The largest observed connection sequence number across all streams.
    PktSeqNumber         largest_observed_conn_seq_num_;

    /// The prioritized, round-robin stream information.
    PrioRndRbnInfo       prio_info_;

    /// An array of information about each stream within the connection.
    StreamInfo           stream_info_[kStreamArraySize];

  }; // class Connection

} // namespace sliq

#endif // IRON_SLIQ_CONNECTION_H
