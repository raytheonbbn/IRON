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

#include "sliq_connection.h"

#include "sliq_cc_copa.h"
#include "sliq_cc_interface.h"
#include "sliq_cc_pacing_sender.h"
#include "sliq_connection_manager.h"
#include "sliq_private_types.h"
#include "sliq_socket_manager.h"
#include "sliq_stream.h"
#include "sliq_types.h"

#include "callback.h"
#include "itime.h"
#include "log.h"
#include "packet_pool.h"
#include "timer.h"
#include "unused.h"

#include <cerrno>
#include <cstring>
#include <inttypes.h>


using ::sliq::CcAlg;
using ::sliq::CcAlgs;
using ::sliq::Connection;
using ::sliq::EndptId;
using ::sliq::MsgTag;
using ::sliq::PktTimestamp;
using ::sliq::Stream;
using ::sliq::WriteResult;
using ::iron::CallbackNoArg;
using ::iron::CallbackOneArg;
using ::iron::FdEvent;
using ::iron::Ipv4Endpoint;
using ::iron::kFdEventRead;
using ::iron::kFdEventReadWrite;
using ::iron::kFdEventWrite;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::RNG;
using ::iron::Time;
using ::iron::Timer;


namespace
{

  /// The class name string for logging.
  const char*         UNUSED(kClassName) = "Connection";

  /// The UDP socket send and receive buffer sizes.
  const size_t        kSocketBufferSize = (32 * 1024 * 1024);

  /// The maximum number of times that we'll send a client hello.
  const int           kMaxClientHellos = 32;

  /// The maximum number of times that we'll send a server hello.
  const int           kMaxServerHellos = 32;

  /// The maximum number of times that we'll send a close connection.
  const int           kMaxCloseConns = 32;

  /// The number of times that a FIN packet is sent.
  const int           kFinPktSends = 32;

  /// The wait time for connection establishment packets, in seconds.
  const double        kConnEstabTimerSec = 0.333;

  /// The wait time for close connection packets, in seconds.
  const double        kCloseConnTimerSec = 0.333;

  /// The retransmission timer interval, in milliseconds.
  const int           kRtoTimerMsec = 100;

  /// The fast retransmission timer minimum interval, in milliseconds.
  const int           kMinFastRtoTimerMsec = 1;

  /// The ACK timer minimum interval, in milliseconds.
  const int           kMinAckTimerMsec = 1;

  /// The maximum connection establishment RTT estimate value, in
  /// microseconds.
  const PktTimestamp  kConnEstabMaxRttUsec = 1500000;

  /// The maximum number of CC packet train packets that can be sent in the
  /// SendCcPktTrainPkts() method.
  const size_t        kMaxCcPktTrainPkts = 2;

  /// The number of unpaced packets to send after quiescence when pacing is
  /// used.
  const size_t        kInitialUnpacedBurst = 10;

  /// The maximum number of RTT and packet delivery delay (PDD) samples that
  /// can be stored for a single callback.
  const uint32_t      kMaxRttPddSamples = 256;

  /// The OWD sampling period maximum time period, in seconds.
  const double        kOwdPeriodSec = 10.0;

  /// The OWD sampling period minimum number of samples.
  const uint32_t      kOwdPeriodMinSamples = 1000;

  /// The minimum number of data packet receptions required for a packet error
  /// rate (PER) update.
  const uint32_t      kPerMinDataPktXmits = 200;

  /// The minimum amount of time between packet error rate (PER) updates, in
  /// milliseconds.
  const int           kPerMinTimeMsec = 2000;

  /// The minimum Copa constant delta value.
  const double        kMinCopaConstDelta = 0.004;

  /// The maximum Copa constant delta value.
  const double        kMaxCopaConstDelta = 1.0;

  /// Connection handshake header message tag for "CH" (client hello).
  const MsgTag        kClientHelloTag = 0x4843;

  /// Connection handshake header message tag for "SH" (server hello).
  const MsgTag        kServerHelloTag = 0x4853;

  /// Connection handshake header message tag for "CC" (client confirm).
  const MsgTag        kClientConfirmTag = 0x4343;

  /// Connection handshake header message tag for "RJ" (reject).
  const MsgTag        kRejectTag = 0x4A52;

} // namespace


//============================================================================
CcAlg::CcAlg()
    : cc_alg(NULL),
      send_timer(),
      next_send_time(),
      in_ack_proc(false),
      use_rexmit_pacing(false),
      use_una_pkt_reporting(false)
{}

//============================================================================
CcAlg::~CcAlg()
{
  if (cc_alg != NULL)
  {
    cc_alg->Close();
    delete cc_alg;
    cc_alg = NULL;
  }
}

//============================================================================
CcAlgs::CcAlgs()
    : use_una_pkt_reporting(false),
      cap_est(),
      chan_cap_est_bps(0.0),
      trans_cap_est_bps(0.0),
      ccl_time_sec(0.0),
      num_cc_alg(0),
      cc_settings(),
      cc_alg()
{}

//============================================================================
CcAlgs::~CcAlgs()
{
  num_cc_alg = 0;
}

//============================================================================
Connection::Connection(SliqApp& app, SocketManager& socket_mgr,
                       ConnectionManager& connection_mgr, RNG& rng,
                       PacketPool& packet_pool, Timer& timer)
    : app_(app),
      socket_mgr_(socket_mgr),
      conn_mgr_(connection_mgr),
      rng_(rng),
      packet_pool_(packet_pool),
      timer_(timer),
      rtt_mgr_(),
      framer_(packet_pool),
      type_(UNKNOWN_ENDPOINT),
      initialized_(false),
      state_(UNCONNECTED),
      self_addr_(),
      peer_addr_(),
      socket_id_(-1),
      is_write_blocked_(false),
      is_in_rto_(false),
      is_in_outage_(false),
      outage_stream_id_(0),
      outage_start_time_(),
      cc_algs_(),
      pkt_set_(packet_pool),
      ack_hdr_(),
      pkts_since_last_ack_(0),
      timer_tolerance_(Time::FromMsec(1)),
      num_hellos_(0),
      hello_timer_(),
      client_hello_timestamp_(0),
      client_hello_recv_time_(),
      ack_timer_(),
      num_closes_(0),
      close_timer_(),
      rto_duration_(),
      rto_time_(),
      rto_timer_(),
      rto_timeout_cnt_(0),
      data_pkt_send_time_(),
      ack_or_data_pkt_recv_time_(),
      data_pkt_recv_time_(),
      data_pkt_irt_sec_(-1.0),
      do_cap_est_callback_(false),
      ts_corr_(0),
      ts_delta_(0),
      rmt_ts_delta_(0),
      num_rtt_pdd_samples_(0),
      rtt_pdd_samples_(NULL),
      owd_(),
      do_close_conn_callback_(false),
      stats_rcv_rpc_hdr_(),
      stats_rcv_rpc_trigger_cnt_(0),
      stats_snd_data_pkts_sent_(0),
      stats_snd_start_pkts_sent_(0),
      stats_snd_start_pkts_rcvd_(0),
      stats_snd_per_update_time_(),
      stats_local_per_(0.0),
      stats_last_rpc_(0),
      do_callbacks_(true),
      close_reason_(SLIQ_CONN_NORMAL_CLOSE),
      next_conn_seq_num_(1),
      largest_observed_conn_seq_num_(0),
      prio_info_(),
      stream_info_()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Creating connection object %p.\n", this);
#endif

  // Initialize the packet set.
  pkt_set_.Initialize(kNumPktsPerRecvMmsgCall);
}

//============================================================================
Connection::~Connection()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Destroying connection object %p.\n", this);
#endif

  // Close any open socket.
  if (socket_id_ >= 0)
  {
    if (!socket_mgr_.Close(socket_id_))
    {
      LogE(kClassName, __func__, "Error closing socket.\n");
    }
    socket_id_ = -1;

    if (do_callbacks_)
    {
      // Notify the application.
      app_.ProcessFileDescriptorChange();
    }
  }

  // Delete the streams.
  for (size_t i = 0; i < kStreamArraySize; ++i)
  {
    Stream*  stream = stream_info_[i].stream;

    if (stream != NULL)
    {
      delete stream;
      stream_info_[i].stream = NULL;
    }
  }

  // Delete the arrays for PDD estimate callbacks.
  if (rtt_pdd_samples_ != NULL)
  {
    num_rtt_pdd_samples_ = 0;
    delete [] rtt_pdd_samples_;
    rtt_pdd_samples_ = NULL;
  }

  // Cancel all of the timers.
  CancelAllTimers();

  // Clean up the timer callback object pools.
  CallbackNoArg<Connection>::EmptyPool();
  CallbackOneArg<Connection, CcId>::EmptyPool();
}

//============================================================================
bool Connection::InitClient(const Ipv4Endpoint& client_address,
                            const Ipv4Endpoint& server_address,
                            const CongCtrl* cc_alg, size_t num_cc_alg,
                            bool direct_conn, EndptId& endpt_id)
{
  // Check if the object has already been initialized.
  if (initialized_)
  {
    LogE(kClassName, __func__, "Error, connection already initialized.\n");
    return false;
  }

  // Initialize the state information.
  if (!InitState(CLIENT_DATA))
  {
    return false;
  }

  // Open a UDP socket.
  socket_id_ = socket_mgr_.CreateUdpSocket(kFdEventRead
#ifdef SLIQ_NS3
                                           , this
#endif // SLIQ_NS3
                                           );

  if (socket_id_ < 0)
  {
    LogE(kClassName, __func__, "Error opening client UDP socket.\n");
    return false;
  }

  // Set the necessary socket options.
  if ((!socket_mgr_.SetRecvBufferSize(socket_id_, kSocketBufferSize)) ||
      (!socket_mgr_.SetSendBufferSize(socket_id_, kSocketBufferSize)) ||
      (!socket_mgr_.EnableReceiveTimestamps(socket_id_)))
  {
    LogE(kClassName, __func__, "Error setting options on client UDP "
         "socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Enable port number reuse on the socket.
  if (direct_conn)
  {
    if (!socket_mgr_.EnablePortReuse(socket_id_))
    {
      LogE(kClassName, __func__, "Error enabling port number reuse on client "
           "UDP socket.\n");
      socket_mgr_.Close(socket_id_);
      socket_id_ = -1;
      return false;
    }
  }

  // Bind the socket to the specified address and port number.
  if (!socket_mgr_.Bind(socket_id_, client_address))
  {
    LogE(kClassName, __func__, "Error binding client UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Connect the socket to the server.
  if (direct_conn)
  {
    if (!socket_mgr_.Connect(socket_id_, server_address))
    {
      LogE(kClassName, __func__, "Error connecting client UDP socket.\n");
      socket_mgr_.Close(socket_id_);
      socket_id_ = -1;
      return false;
    }
  }

  // Get the local socket address.
  if (!socket_mgr_.GetLocalAddress(socket_id_, self_addr_))
  {
    LogE(kClassName, __func__, "Error getting local socket address.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Walk the array of congestion control settings, storing and validating
  // each one.
  for (size_t i = 0; i < num_cc_alg; ++i)
  {
    cc_algs_.cc_settings[i] = cc_alg[i];

    if (!CongCtrlSettingIsValid(cc_algs_.cc_settings[i], true))
    {
      LogE(kClassName, __func__, "Error, invalid congestion control "
           "settings: %s\n", CongCtrlAlgToString(cc_alg[i]));
      socket_mgr_.Close(socket_id_);
      socket_id_ = -1;
      return false;
    }
  }

  cc_algs_.num_cc_alg = num_cc_alg;

  // Create the congestion control objects.
  if (!CreateCongCtrlObjects(true))
  {
    LogE(kClassName, __func__, "Error creating congestion control "
         "objects.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Start the RTO timer running.
  if (!StartRtoTimer())
  {
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // The initialization was successful.  Map the socket ID to the endpoint
  // ID, which are equal for simplicity.  Note that the SliqApp adds the
  // connection object to the connection manager.
  initialized_ = true;
  endpt_id     = socket_id_;

  // Notify the application.
  app_.ProcessFileDescriptorChange();

  if (direct_conn)
  {
    LogA(kClassName, __func__, "Conn %" PRISocketId ": Client direct "
         "connection from %s to server %s.\n", socket_id_,
         self_addr_.ToString().c_str(), server_address.ToString().c_str());
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Connection object %p assigned endpoint ID "
       "%" PRIEndptId ".\n", this, endpt_id);
#endif

  return true;
}

//============================================================================
bool Connection::InitServerListen(const Ipv4Endpoint& server_address,
                                  EndptId& endpt_id)
{
  // Check if the object has already been initialized.
  if (initialized_)
  {
    LogE(kClassName, __func__, "Error, connection already initialized.\n");
    return false;
  }

  // Initialize the state information.
  if (!InitState(SERVER_LISTEN))
  {
    return false;
  }

  // Open a UDP socket.
  socket_id_ = socket_mgr_.CreateUdpSocket(kFdEventRead
#ifdef SLIQ_NS3
                                           , this
#endif // SLIQ_NS3
                                           );
  if (socket_id_ < 0)
  {
    LogE(kClassName, __func__, "Error opening server listen UDP socket.\n");
    return false;
  }

  // Set the necessary socket options.
  if (!socket_mgr_.EnableReceiveTimestamps(socket_id_))
  {
    LogE(kClassName, __func__, "Error setting options on server listen UDP "
         "socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Enable port number reuse on the socket.
  if (!socket_mgr_.EnablePortReuse(socket_id_))
  {
    LogE(kClassName, __func__, "Error enabling port number reuse on server "
         "listen UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Bind the socket to the specified address and well known port number.
  if (!socket_mgr_.Bind(socket_id_, server_address))
  {
    LogE(kClassName, __func__, "Error binding server listen UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Store the server's address and well known port number.
  self_addr_ = server_address;

  // The initialization was successful.  Map the socket ID to the endpoint
  // ID, which are equal for simplicity.  Note that the SliqApp adds the
  // connection object to the connection manager.
  initialized_ = true;
  endpt_id     = socket_id_;

  // Notify the application.
  app_.ProcessFileDescriptorChange();

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Server listening on "
       "%s.\n", socket_id_, self_addr_.ToString().c_str());

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Connection object %p assigned endpoint ID "
       "%" PRIEndptId ".\n", this, endpt_id);
#endif

  return true;
}

//============================================================================
bool Connection::InitServerDirectData(const Ipv4Endpoint& server_address,
                                      const Ipv4Endpoint& client_address,
                                      EndptId& endpt_id)
{
  // Check if the object has already been initialized.
  if (initialized_)
  {
    LogE(kClassName, __func__, "Error, connection already initialized.\n");
    return false;
  }

  // Initialize the state information.
  if (!InitState(SERVER_DATA))
  {
    return false;
  }

  // Store the client address.
  peer_addr_ = client_address;

  // Open a UDP socket.
  socket_id_ = socket_mgr_.CreateUdpSocket(kFdEventRead
#ifdef SLIQ_NS3
                                           , this
#endif // SLIQ_NS3
                                           );
  if (socket_id_ < 0)
  {
    LogE(kClassName, __func__, "Error opening server data UDP socket.\n");
    return false;
  }

  // Set the necessary socket options.
  if ((!socket_mgr_.SetRecvBufferSize(socket_id_, kSocketBufferSize)) ||
      (!socket_mgr_.SetSendBufferSize(socket_id_, kSocketBufferSize)) ||
      (!socket_mgr_.EnableReceiveTimestamps(socket_id_)))
  {
    LogE(kClassName, __func__, "Error setting options on server data UDP "
         "socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Enable port number reuse on the socket.
  if (!socket_mgr_.EnablePortReuse(socket_id_))
  {
    LogE(kClassName, __func__, "Error enabling port number reuse on server "
         "data UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Bind the socket to the specified address and port number.
  if (!socket_mgr_.Bind(socket_id_, server_address))
  {
    LogE(kClassName, __func__, "Error binding server data UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Connect the socket to the client.
  if (!socket_mgr_.Connect(socket_id_, client_address))
  {
    LogE(kClassName, __func__, "Error connecting server data UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Get the local socket address.
  if (!socket_mgr_.GetLocalAddress(socket_id_, self_addr_))
  {
    LogE(kClassName, __func__, "Error getting local socket address.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Start the RTO timer running.
  if (!StartRtoTimer())
  {
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // The initialization was successful.  Map the socket ID to the endpoint ID,
  // which are equal for simplicity.  Note that the SliqApp adds the
  // connection object to the connection manager.
  initialized_ = true;
  endpt_id     = socket_id_;

  // Notify the application.
  app_.ProcessFileDescriptorChange();

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Server direct "
       "connection from %s to client %s.\n", socket_id_,
       self_addr_.ToString().c_str(), client_address.ToString().c_str());

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Connection object %p assigned endpoint ID "
       "%" PRIEndptId".\n", this, endpt_id);
#endif

  return true;
}

//============================================================================
bool Connection::ConnectToServer(const Ipv4Endpoint& server_address)
{
  // Check if this connection object can connect to a server.
  if ((type_ != CLIENT_DATA) || (!initialized_) || (state_ != UNCONNECTED))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, cannot connect "
         "to server in current connection state.\n", socket_id_);
    return false;
  }

  // Update the connection state.
  state_      = UNCONNECTED;
  peer_addr_  = server_address;
  num_hellos_ = 0;
  hello_timer_.Clear();

  // Set a timer for how long to wait for a response from the server.
  if (!StartClientHelloTimer())
  {
    return false;
  }

  // Initiate the connection establishment process by sending a client hello
  // message to the server.
  if (!SendConnHndshkPkt(kClientHelloTag, 0))
  {
    timer_.CancelTimer(hello_timer_);
    return false;
  }

  // Record the transmission.
  num_hellos_++;

  // Update the connection state.
  state_ = SENT_CHLO;

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Client %s connecting to "
       "server %s.\n", socket_id_, self_addr_.ToString().c_str(),
       peer_addr_.ToString().c_str());

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();

  return true;
}

//============================================================================
bool Connection::AddStream(StreamId stream_id, Priority prio,
                           const Reliability& rel, DeliveryMode del_mode)
{
  // Make sure a stream can be added to this connection.
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED) || (cc_algs_.num_cc_alg < 1))
  {
    return false;
  }

  // Validate the stream ID.  It must be odd on the client side, and even on
  // the server side.
  if (!StreamIdIsValid(stream_id) ||
      ((type_ == CLIENT_DATA) && ((stream_id % 2) != 1)) ||
      ((type_ == SERVER_DATA) && ((stream_id % 2) != 0)))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid stream ID %"
         PRIStreamId ".\n", socket_id_, stream_id);
    return false;
  }

  // Validate the priority.
  if (!PriorityIsValid(prio))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid stream "
         "priority %" PRIPriority ".\n", socket_id_, prio);
    return false;
  }

  // Validate the reliability settings.
  if (!ReliabilityIsValid(rel, del_mode))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid stream "
         "reliability settings: reliability %d rexmit_limit %" PRIRexmitLimit
         " tgt_prob %f del_time %d tgt_rnds %" PRIRexmitRounds " tgt_time %f "
         "delivery %d.\n", socket_id_, rel.mode, rel.rexmit_limit,
         rel.fec_target_pkt_recv_prob,
         static_cast<int>(rel.fec_del_time_flag),
         rel.fec_target_pkt_del_rounds, rel.fec_target_pkt_del_time_sec,
         del_mode);
    return false;
  }

  // Make sure that the stream ID is not already in use.
  if (GetStream(stream_id) != NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Stream ID %"
         PRIStreamId " is already in use.\n", socket_id_, stream_id);
    return false;
  }

  // Create a new stream.
  Stream*  stream = new (std::nothrow)
    Stream(*this, rtt_mgr_, cc_algs_, rng_, packet_pool_, timer_,
           socket_id_, stream_id, prio);

  // Initialize it.  This will cause the stream to send a create stream
  // packet, but it does not wait for a create stream ACK packet.
  if ((stream == NULL) ||
      (!stream->InitializeLocalStream(rel, del_mode)))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating a new "
         "stream.\n", socket_id_);
    if (stream != NULL)
    {
      delete stream;
    }
    return false;
  }

  // Store the stream using the stream ID as the index.
  RecordNewStream(stream, stream_id, prio);

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Directly created stream "
       "ID %" PRIStreamId " with: delivery %d reliability %d rexmit_limit %"
       PRIRexmitLimit " tgt_prob %f del_time %d tgt_rnds %" PRIRexmitRounds
       " tgt_time %f prio %" PRIPriority "\n", socket_id_, stream_id,
       del_mode, rel.mode, rel.rexmit_limit, rel.fec_target_pkt_recv_prob,
       static_cast<int>(rel.fec_del_time_flag), rel.fec_target_pkt_del_rounds,
       rel.fec_target_pkt_del_time_sec, prio);

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();

  return true;
}

//============================================================================
bool Connection::ConfigureTcpFriendliness(uint32_t num_flows)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED) || (cc_algs_.num_cc_alg < 1))
  {
    return false;
  }

  // Change the setting in the congestion control algorithms.
  bool  rv = true;

  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if ((cc_alg == NULL) || (!cc_alg->SetTcpFriendliness(num_flows)))
    {
      rv = false;
    }
  }

  return rv;
}

//============================================================================
bool Connection::ConfigureTransmitQueue(StreamId stream_id,
                                        size_t max_size_pkts,
                                        DequeueRule dequeue_rule,
                                        DropRule drop_rule)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_))
  {
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream.
  return stream->ConfigureTransmitQueue(max_size_pkts, dequeue_rule,
                                        drop_rule);
}

//============================================================================
bool Connection::ConfigureRexmitLimit(StreamId stream_id,
                                      RexmitLimit rexmit_limit)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_))
  {
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream.
  return stream->ConfigureRexmitLimit(rexmit_limit);
}

//============================================================================
bool Connection::IsStreamEstablished(StreamId stream_id) const
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_))
  {
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream.
  return stream->IsEstablished();
}

//============================================================================
bool Connection::Send(StreamId stream_id, Packet* data)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) ||
      (!initialized_) ||
      ((state_ != CONNECTED) && (state_ != APP_CLOSE_WAIT)))
  {
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Allow any queued packets to be sent before attempting to send this
  // packet.
  OnCanWrite();

  // Call into the stream.
  bool  rv = stream->Send(data, false);

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();

  return rv;
}

//============================================================================
void Connection::ServiceFileDescriptor(int fd, FdEvent event)
{
  // Verify the file descriptor.
  if (fd != socket_id_)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": File descriptor %d "
         "does not match socket ID %" PRISocketId ".\n", socket_id_, fd,
         socket_id_);
    return;
  }

  // Handle the write event first.  This event is due to a socket write being
  // blocked, and it is best to complete that transmission before processing
  // received packets.
  if ((event == kFdEventWrite) || (event == kFdEventReadWrite))
  {
    if (!is_write_blocked_)
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Connection is not "
           "write blocked on write ready event.\n", socket_id_);
    }

    // The socket is no longer write blocked.
    StreamId  reblocked_stream_id = 0;

    if (ClearWriteBlocked(reblocked_stream_id))
    {
      // The socket is now unblocked.  Allow the streams to send again.
      OnCanWrite();
    }
    else
    {
      // The socket is blocked again.
      SetWriteBlocked(reblocked_stream_id);
    }
  }

  // Handle the read event.
  if ((event == kFdEventRead) || (event == kFdEventReadWrite))
  {
    ReceivePackets();
  }

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();
}

//============================================================================
bool Connection::GetTransmitQueueSizeInBytes(StreamId stream_id,
                                             size_t& size)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED))
  {
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream.
  size = stream->GetTransmitQueueSizeInBytes();

  return true;
}

//============================================================================
bool Connection::GetTransmitQueueSizeInPackets(StreamId stream_id,
                                               size_t& size)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED))
  {
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream.
  size = stream->GetTransmitQueueSizeInPackets();

  return true;
}

//============================================================================
bool Connection::InitiateCloseStream(StreamId stream_id, bool& fully_closed)
{
  if (((type_ != SERVER_DATA) && (type_ != CLIENT_DATA)) || (!initialized_) ||
      (state_ != CONNECTED))
  {
    return false;
  }

  Stream*  stream = GetStream(stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Make sure that a FIN is not already queued or sent for the stream.
  if (stream->HasQueuedOrSentFin())
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, FIN already "
         "queued/sent on stream %" PRIStreamId ".\n", socket_id_, stream_id);
    return false;
  }

  // Send a FIN to the peer on the stream.  This initiates the close of the
  // send side of the stream.
  bool  rv  = true;

  if (!stream->Send(NULL, true))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending FIN on "
         "stream %" PRIStreamId ".\n", socket_id_, stream_id);
    rv = false;
  }

  // The write side is now closed.  If the read side is also closed, then the
  // stream is fully closed.
  fully_closed = stream->IsFullyClosed();

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();

  return rv;
}

//============================================================================
bool Connection::InitiateClose(ConnCloseCode reason, bool& fully_closed)
{
  if (((type_ != SERVER_DATA) && (type_ != CLIENT_DATA) &&
       (type_ != SERVER_LISTEN)) || (!initialized_))
  {
    return false;
  }

  // For server listen endpoints, simply set the state to CLOSED and schedule
  // the connection for deletion.
  if (type_ == SERVER_LISTEN)
  {
    state_ = CLOSED;
    conn_mgr_.DeleteConnection(socket_id_);

    fully_closed = true;

    // Do any pending reentrant callbacks.
    DoReentrantCallbacks();

    return true;
  }

  // For client or server data endpoints, the processing depends on the
  // current state.
  if (state_ == UNCONNECTED)
  {
    state_ = CLOSED;
    return true;
  }

  // If the connection is still being established, then send a reset
  // connection packet and immediately schedule the connection for deletion.
  if ((state_ == SENT_CHLO) || (state_ == SENT_SHLO))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Connection is still "
         "being established, sending a reset connection packet and "
         "immediately closing.\n", socket_id_);
#endif

    SendResetConnPkt(SLIQ_CONN_RECV_CLOSE_ERROR);
    state_ = CLOSED;
    conn_mgr_.DeleteConnection(socket_id_);

    fully_closed = true;

    // Do any pending reentrant callbacks.
    DoReentrantCallbacks();

    return true;
  }

  if ((state_ == CONN_CLOSE_WAIT) || (state_ == CLOSED))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Connection is already "
         "closed.\n", socket_id_);
    return false;
  }

  // The state is either CONNECTED or APP_CLOSE_WAIT from this point on.  Set
  // a timer for how long to wait for a close connection ACK packet.
  if (!StartCloseConnTimer())
  {
    return false;
  }

  // Send a connection close packet with the specified reason.
  close_reason_ = reason;

  if (!SendCloseConnPkt(false, close_reason_))
  {
    timer_.CancelTimer(close_timer_);
    return false;
  }

  // Record the transmission.
  num_closes_ = 1;

  // Close all of the streams.
  for (size_t i = 0; i < kStreamArraySize; ++i)
  {
    Stream*  stream = stream_info_[i].stream;

    if (stream != NULL)
    {
      if (state_ == CONNECTED)
      {
        // The stream can no longer send, but can still receive.
        stream->ImmediateHalfCloseNoSend();
      }
      else
      {
        // The stream can no longer send or receive.
        stream->ImmediateFullClose();
      }
    }
  }

  // Update the state as needed given the current state.
  if (state_ == CONNECTED)
  {
    // The connection is now waiting on a connection close packet from the
    // remote peer.
    state_       = CONN_CLOSE_WAIT;
    fully_closed = false;
  }

  if (state_ == APP_CLOSE_WAIT)
  {
    // The connection is now fully closed.
    state_       = CLOSED;
    fully_closed = true;

    // The connection can be scheduled for deletion.
    conn_mgr_.DeleteConnection(socket_id_);
  }

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();

  return true;
}

//============================================================================
void Connection::PktAcked(StreamId stream_id, uint32_t rtt_usec,
                          uint32_t pdd_usec)
{
  if (num_rtt_pdd_samples_ < kMaxRttPddSamples)
  {
    rtt_pdd_samples_[num_rtt_pdd_samples_].stream_id = stream_id;
    rtt_pdd_samples_[num_rtt_pdd_samples_].rtt_usec  = rtt_usec;
    rtt_pdd_samples_[num_rtt_pdd_samples_].pdd_usec  = pdd_usec;
    ++num_rtt_pdd_samples_;
  }
  else
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Warning, too many "
         "RTT/PDD measurements, some will be lost.\n", socket_id_);
  }
}

//============================================================================
void Connection::CloseStreamCallback(StreamId stream_id, bool fully_closed)
{
  app_.ProcessCloseStream(socket_id_, stream_id, fully_closed);
}

//============================================================================
bool Connection::CanSend(const Time& now, size_t bytes, CcId& cc_id)
{
  // If currently in an outage, then the send should not happen.
  if (is_in_outage_)
  {
    return false;
  }

  // Check each of the congestion control algorithms.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CcAlg&              cc_info = cc_algs_.cc_alg[i];
    CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

    if (cc_alg == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRISocketId ": Congestion control "
           "object for cc_id %zu is NULL.\n", socket_id_, i);
      continue;
    }

    // Get the amount of delay before a send can occur for this congestion
    // control algorithm.
    Time  delay(cc_alg->TimeUntilSend(now));

    // The returned delay should never be infinite.
    if (delay.IsInfinite())
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Time until send is "
           "infinite for cc_id %zu.\n", socket_id_, i);
      timer_.CancelTimer(cc_info.send_timer);
      continue;
    }

    // If the congestion control algorithm requires a delay, then we cannot
    // send this packet now.
    if (!delay.IsZero())
    {
      // Use the send pacing timer to wake up when a packet can be sent, and
      // continue the search.
      StartSendTimer(now, i, delay);
      continue;
    }

    // If the congestion control algorithm blocks the send, then we cannot
    // send this packet right now.
    if (!cc_alg->CanSend(now, bytes))
    {
      // Continue the search.
      continue;
    }

    // This congestion control algorithm will allow the send right now.
    // Cancel any pacing timer before returning the CCID and true.
#ifdef SLIQ_DEBUG
    if (timer_.IsTimerSet(cc_info.send_timer))
    {
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Send immediately, "
           "cancel send timer cc_id %zu handle %" PRIu64 ".\n", socket_id_, i,
           cc_info.send_timer.id());
    }
#endif

    timer_.CancelTimer(cc_info.send_timer);

    cc_id = static_cast<CcId>(i);
    return true;
  }

  return false;
}

//============================================================================
bool Connection::CanResend(const Time& now, size_t bytes, CcId orig_cc_id,
                           CcId& cc_id)
{
  // If currently in an outage, then the send should not happen.
  if (is_in_outage_)
  {
    return false;
  }

  // Check each of the congestion control algorithms.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CcAlg&              cc_info = cc_algs_.cc_alg[i];
    CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

    if (cc_alg == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRISocketId ": Congestion control "
           "object for cc_id %zu is NULL.\n", socket_id_, i);
      continue;
    }

    if (cc_info.use_rexmit_pacing)
    {
      // Get the amount of delay before a resend can occur for this congestion
      // control algorithm.
      Time  delay(cc_alg->TimeUntilSend(now));

      // The returned delay should never be infinite.
      if (delay.IsInfinite())
      {
        LogE(kClassName, __func__, "Conn %" PRISocketId ": Time until resend "
             "is infinite for cc_id %zu.\n", socket_id_, i);
        timer_.CancelTimer(cc_info.send_timer);
        continue;
      }

      // If the congestion control algorithm requires a delay, then we cannot
      // resend this packet now.
      if (!delay.IsZero())
      {
        // Use the send pacing timer to wake up when a packet can be sent, and
        // continue the search.
        StartSendTimer(now, i, delay);
        continue;
      }
    }

    // If the congestion control algorithm blocks the resend, then we cannot
    // send this packet right now.
    if (!cc_alg->CanResend(now, bytes, (orig_cc_id == i)))
    {
      // Continue the search.
      continue;
    }

    // This congestion control algorithm will allow the resend right now.
    // Cancel any pacing timer before returning the CCID and true.
#ifdef SLIQ_DEBUG
    if (timer_.IsTimerSet(cc_info.send_timer))
    {
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Resend immediately, "
           "cancel send timer cc_id %zu handle %" PRIu64 ".\n", socket_id_, i,
           cc_info.send_timer.id());
    }
#endif

    timer_.CancelTimer(cc_info.send_timer);

    cc_id = static_cast<CcId>(i);
    return true;
  }

  return false;
}

//============================================================================
bool Connection::SendCreateStreamPkt(
  bool ack, DeliveryMode del_mode, const Reliability& rel, StreamId stream_id,
  Priority prio, WindowSize win_size, PktSeqNumber seq_num)
{
  bool  rv = false;

  // Create the create stream packet.
  CreateStreamHeader  cs_hdr(rel.fec_del_time_flag, ack, stream_id, prio,
                             win_size, seq_num, del_mode, rel.mode,
                             rel.rexmit_limit, rel.fec_target_pkt_del_rounds,
                             rel.fec_target_pkt_del_time_sec,
                             rel.fec_target_pkt_recv_prob);
  Packet*             pkt = framer_.GenerateCreateStream(cs_hdr);

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating "
         "packet.\n", socket_id_);
    return rv;
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent create stream "
         "packet: del_time %s ACK %s stream %" PRIStreamId " prio %"
         PRIPriority " init_win %" PRIWindowSize " init_seq %" PRIPktSeqNumber
         " del %d rel %d rexmit_lim %" PRIRexmitLimit " tgt_rnds %"
         PRIRexmitRounds " tgt_time %f tgt_prob %f\n", socket_id_,
         (cs_hdr.del_time_flag ? "true" : "false"),
         (cs_hdr.ack_flag ? "true" : "false"), cs_hdr.stream_id,
         cs_hdr.priority, cs_hdr.initial_win_size_pkts,
         cs_hdr.initial_seq_num, cs_hdr.delivery_mode,
         cs_hdr.reliability_mode, cs_hdr.rexmit_limit,
         cs_hdr.fec_target_pkt_del_rounds, cs_hdr.fec_target_pkt_del_time_sec,
         cs_hdr.fec_target_pkt_recv_prob);
#endif

    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending "
         "create stream packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending create "
         "stream packet: %s.\n", socket_id_, strerror(wr.error_code));
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
bool Connection::SendResetStreamPkt(StreamId stream_id, StreamErrorCode error,
                                    PktSeqNumber seq_num)
{
  bool  rv = false;

  // Create the reset stream packet.
  ResetStreamHeader  rs_hdr(stream_id, error, seq_num);
  Packet*            pkt = framer_.GenerateResetStream(rs_hdr);

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating "
         "packet.\n", socket_id_);
    return rv;
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent reset stream "
         "packet: stream %" PRIStreamId " error %d final_seq %"
         PRIPktSeqNumber "\n", socket_id_, stream_id, error, seq_num);
#endif

    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending reset "
         "stream packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending reset "
         "stream packet: %s.\n", socket_id_, strerror(wr.error_code));
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
WriteResult Connection::SendDataPkt(const Time& now, DataHeader& data_hdr,
                                    Packet* data, size_t& bytes)
{
  size_t   data_len         = 0;
  size_t   rsvd_len         = Framer::ComputeDataHeaderSize(data_hdr);
  bool     cancel_ack_timer = false;

  // Send a data packet, possibly including other SLIQ headers, in the
  // following order:
  //
  //   1. CC Sync Header (opportunistic as space allows)
  //   2. ACK Header(s) (opportunistic as space allows)
  //   3. Received Packet Count Header (opportunistic as space allows)
  //   4. Data Header (required)
  //   5. Payload (if "data" Packet object contains data)

  // Record the payload length.
  if (data != NULL)
  {
    data_len  = (data->GetMetadataHeaderLengthInBytes() +
                 data->GetLengthInBytes());
    rsvd_len += data_len;
  }

  // Warn if this packet will be fragmented by IP.
  size_t  curr_len = rsvd_len;

  if (curr_len > kMaxPacketSize)
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId " Stream %" PRIStreamId
         ": Warning, payload length %zu with required headers (total length "
         "%zu) will be fragmented by IP.\n", socket_id_, data_hdr.stream_id,
         data_len, curr_len);
  }

  // Decide if any congestion control synchronization headers can be
  // opportunistically included or not.
  Packet*   hdrs            = NULL;
  uint16_t  cc_sync_seq_num = 0;
  uint32_t  cc_sync_params  = 0;

  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if ((cc_alg != NULL) && ((curr_len + kCcSyncHdrSize) <= kMaxPacketSize) &&
        (cc_alg->GetSyncParams(cc_sync_seq_num, cc_sync_params)))
    {
      CcSyncHeader  ccs_hdr(i, cc_sync_seq_num, cc_sync_params);

      if (!framer_.AppendCcSyncHeader(hdrs, ccs_hdr))
      {
        LogE(kClassName, __func__, "Conn %" PRISocketId ": Error appending "
             "CC sync header for cc_id %zu.\n", socket_id_, i);
        bytes = (data_len + ((hdrs != NULL) ? hdrs->GetLengthInBytes() : 0));
        if (hdrs != NULL)
        {
          packet_pool_.Recycle(hdrs);
        }
        return WriteResult(WRITE_STATUS_ERROR, ENOMEM);
      }
#ifdef SLIQ_DEBUG
      else
      {
        LogD(kClassName, __func__, "Conn %" PRISocketId ": Add opportunistic "
             "CC sync: stream %" PRIStreamId " cc_id %" PRICcId " seq_num %"
             PRIu16 " cc_params %" PRIu32 "\n", socket_id_,
             data_hdr.stream_id, ccs_hdr.cc_id, ccs_hdr.seq_num,
             ccs_hdr.cc_params);
      }
#endif

      curr_len += kCcSyncHdrSize;
    }
  }

  // Decide if ACK headers can be opportunistically included or not.
  if (!GetAcks(now, rsvd_len, hdrs, cancel_ack_timer))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error appending ACK "
         "headers.\n", socket_id_);
    bytes = (data_len + ((hdrs != NULL) ? hdrs->GetLengthInBytes() : 0));
    if (hdrs != NULL)
    {
      packet_pool_.Recycle(hdrs);
    }
    return WriteResult(WRITE_STATUS_ERROR, ENOMEM);
  }

  // Decide if a received packet count header can be opportunistically
  // included or not.
  if (stats_rcv_rpc_trigger_cnt_ >= kRcvdPktCntIntPkts)
  {
    AddRcvdPktCnt(rsvd_len, hdrs);
  }

  // Get the timestamp and timestamp delta values for the data header.
  data_hdr.timestamp       = GetCurrentLocalTimestamp();
  data_hdr.timestamp_delta = ts_delta_;

  // Finally, add the data header last.
  if (!framer_.AppendDataHeader(hdrs, data_hdr, data_len))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error appending data "
         "header for stream %" PRIStreamId ".\n", socket_id_,
         data_hdr.stream_id);
    bytes = (data_len + ((hdrs != NULL) ? hdrs->GetLengthInBytes() : 0));
    if (hdrs != NULL)
    {
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(hdrs);
    }
    return WriteResult(WRITE_STATUS_ERROR, ENOMEM);
  }

#ifdef TTG_TRACKING
  if ((data != NULL) && (data->track_ttg()) && (data_hdr.num_ttg == 1))
  {
    // Log the TTG values before the packet is sent.
    // Format:  PLT_SND <seq_num> <full_ttg> <sent_ttg>
    LogC(kClassName, __func__, "Conn %" PRISocketId ": PLT_SND %"
         PRIPktSeqNumber " %f %f\n", socket_id_, data_hdr.sequence_number,
         data->GetTimeToGo().ToDouble(), data_hdr.ttg[0]);
  }
#endif // TTG_TRACKING

  // Send the packet to the peer.  If this packet is a FIN packet, then send
  // it multiple times to improve the chance of reception.
  WriteResult  wr;
  int          send_cnt = (data_hdr.fin_flag ? kFinPktSends : 1);

  for (int i = 0; i < send_cnt; ++i)
  {
    if ((data == NULL) || (data_len == 0))
    {
      wr = socket_mgr_.WritePacket(socket_id_, *hdrs, peer_addr_);
    }
    else
    {
      wr = socket_mgr_.WritePacket(socket_id_, *hdrs, *data, peer_addr_);
    }
  }

  // Record the total number of bytes sent.  This includes SLIQ headers, but
  // not IP or UDP headers.
  bytes = (data_len + hdrs->GetLengthInBytes());

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent data packet: "
         "epl %s fec %s move_fwd %s persist %s fin %s stream %" PRIStreamId
         " num_ttg %" PRITtgCount " cc_id %" PRICcId " rexmit_cnt %"
         PRIRetransCount " pld_len %zu seq %" PRIPktSeqNumber " ts %"
         PRIPktTimestamp " ts_delta %" PRIPktTimestamp "\n", socket_id_,
         (data_hdr.enc_pkt_len_flag ? "true" : "false"),
         (data_hdr.fec_flag ? "true" : "false"),
         (data_hdr.move_fwd_flag ? "true" : "false"),
         (data_hdr.persist_flag ? "true" : "false"),
         (data_hdr.fin_flag ? "true" : "false"), data_hdr.stream_id,
         data_hdr.num_ttg, data_hdr.cc_id, data_hdr.retransmission_count,
         data_len, data_hdr.sequence_number, data_hdr.timestamp,
         data_hdr.timestamp_delta);
    if (data_hdr.move_fwd_flag)
    {
      LogD(kClassName, __func__, "  move_fwd: seq %" PRIPktSeqNumber "\n",
           data_hdr.move_fwd_seq_num);
    }
    if (data_hdr.fec_flag)
    {
      LogD(kClassName, __func__, "  fec: pkt_type %s grp %" PRIFecGroupId
           " idx %" PRIFecBlock " src %" PRIFecBlock " rnd %" PRIFecRound
           "\n", ((data_hdr.fec_pkt_type == FEC_SRC_PKT) ? "SRC" : "ENC"),
           data_hdr.fec_group_id, data_hdr.fec_block_index,
           data_hdr.fec_num_src, data_hdr.fec_round);
    }
    if (data_hdr.enc_pkt_len_flag)
    {
      LogD(kClassName, __func__, "  enc_pkt_len: %" PRIFecEncPktLen "\n",
           data_hdr.encoded_pkt_length);
    }
    for (TtgCount i = 0; i < data_hdr.num_ttg; ++i)
    {
      LogD(kClassName, __func__, "  ttg[%" PRITtgTime "]: %f seconds\n", i,
           data_hdr.ttg[i]);
    }
#endif

    // If all of the delayed ACKs were sent, then cancel the ACK timer.
    if (cancel_ack_timer)
    {
      pkts_since_last_ack_ = 0;
      timer_.CancelTimer(ack_timer_);
    }

    // If an ACK or data packet has been received since the last data packet
    // was sent to the peer, then update the data packet send time.
    if (ack_or_data_pkt_recv_time_ >= data_pkt_send_time_)
    {
      data_pkt_send_time_ = now;
    }

    // If there is not currently an outage and this is not called from a
    // retransmission timeout and the retransmission timer expiration time is
    // not currently set, then set it.  This is done only for data packets
    // that generate a response (ACK) packet, be they original or
    // retransmitted data packets.
    //
    // \todo RFC 6675, section 6, optionally allows a more conservative RTO
    // management algorithm.  This would re-arm the RTO timer on each
    // retransmission that is sent during fast recovery.  Possibly add this.
    if ((!is_in_outage_) && (!is_in_rto_) && (rto_time_.IsZero()))
    {
      SetRexmitTime(now, rtt_mgr_.GetRtoTime());
    }

    // Update the sent data packet statistics.
    ++stats_snd_data_pkts_sent_;
  }
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    // Writes are now blocked on the socket.
    SetWriteBlocked(data_hdr.stream_id);
  }
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending data "
         "packet: %s\n", socket_id_, strerror(wr.error_code));

    // Initiate a close of the connection.
    do_close_conn_callback_ = true;
  }

  // Release the packet used for the headers.
  packet_pool_.Recycle(hdrs);

  return wr;
}

//============================================================================
bool Connection::SendCcPktTrainPkts(CcId id, uint8_t type, uint8_t seq,
                                    uint32_t irt, size_t payload_len,
                                    size_t pkt_cnt)
{
  bool          rv       = true;
  size_t        send_cnt = ((pkt_cnt > kMaxCcPktTrainPkts) ?
                            kMaxCcPktTrainPkts : pkt_cnt);
  Time          now      = Time::Now();
  PktTimestamp  ts       = (static_cast<PktTimestamp>(now.GetTimeInUsec()) +
                            ts_corr_);
  Packet*       pkt[kMaxCcPktTrainPkts];

  // Clear the packet pointer array.
  memset(pkt, 0, sizeof(pkt));

  // Create the packets to send.
  uint8_t  hdr_seq = seq;

  for (size_t i = 0; i < send_cnt; ++i)
  {
    CcPktTrainHeader  hdr(id, type, hdr_seq, irt, ts, ts_delta_);

    pkt[i] = framer_.GenerateCcPktTrain(hdr, payload_len);
    ++hdr_seq;
  }

  // Send the packets to the peer as fast as possible.
  for (size_t i = 0; i < send_cnt; ++i)
  {
    if (pkt[i] != NULL)
    {
      WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *(pkt[i]),
                                                peer_addr_);

      if (wr.status == WRITE_STATUS_BLOCKED)
      {
        rv = false;

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending "
             "CC packet train packet.\n", socket_id_);
#endif
      }
      else if (wr.status == WRITE_STATUS_ERROR)
      {
        rv = false;

        LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending CC "
             "packet train packet: %s.\n", socket_id_,
             strerror(wr.error_code));
      }
    }
    else
    {
      rv = false;

      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error generating CC "
           "packet train packet.\n", socket_id_);
    }
  }

  // The packet train packets are not saved.
  for (size_t i = 0; i < send_cnt; ++i)
  {
    if (pkt[i] != NULL)
    {
      packet_pool_.Recycle(pkt[i]);
      pkt[i] = NULL;
    }
  }

  return rv;
}

//============================================================================
void Connection::UpdateCapacityEstimate(const Time& now, CcId cc_id,
                                        size_t app_payload_bytes,
                                        size_t bytes_sent)
{
  if (cc_id >= cc_algs_.num_cc_alg)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid congestion "
         "control ID %" PRICcId ".\n", socket_id_, cc_id);
    return;
  }

  CcAlg&              cc_info = cc_algs_.cc_alg[cc_id];
  CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

  if (cc_alg == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Congestion control "
         "object is NULL for ID %" PRICcId ".\n", socket_id_, cc_id);
    return;
  }

  size_t  cwnd         = cc_alg->GetCongestionWindow();
  double  rate_est_bps = static_cast<double>(cc_alg->CapacityEstimate());
  double  chan_ce_bps  = 0.0;
  double  trans_ce_bps = 0.0;
  double  ccl_time_sec = 0.0;

  // Inform the capacity estimator that data was ACKed on the connection.
  if (cc_algs_.cap_est.UpdateCapacityEstimate(
        cc_id, now, app_payload_bytes, bytes_sent, cwnd, rate_est_bps,
        is_in_outage_, chan_ce_bps, trans_ce_bps, ccl_time_sec))
  {
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": PLT_CAPEST %f %f\n",
         socket_id_, cc_algs_.chan_cap_est_bps, cc_algs_.trans_cap_est_bps);
#endif

    // Record the capacity estimate callback information to perform when SLIQ
    // is reentrant.
    do_cap_est_callback_       = true;
    cc_algs_.chan_cap_est_bps  = chan_ce_bps;
    cc_algs_.trans_cap_est_bps = trans_ce_bps;
    cc_algs_.ccl_time_sec      = ccl_time_sec;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": PLT_CAPEST %f %f\n",
         socket_id_, cc_algs_.chan_cap_est_bps, cc_algs_.trans_cap_est_bps);
#endif
  }
}

//============================================================================
PktTimestamp Connection::GetCurrentLocalTimestamp()
{
  // Get the timestamp for the current local time.  Include the timestamp
  // correction.
  Time          ts_now = Time::Now();
  PktTimestamp  ts     = (static_cast<PktTimestamp>(ts_now.GetTimeInUsec()) +
                          ts_corr_);

  // Valid timestamps cannot be zero.
  if (ts == 0)
  {
    ts = 1;
  }

  return ts;
}

//============================================================================
double Connection::GetOneWayDelayEst(PktTimestamp send_ts,
                                     const Time& recv_time)
{
  double  owd_est_sec = 0.0;

  // If the one-way delay estimate is not ready yet, then use one-half of the
  // current smoothed RTT estimate.
  if (!owd_.cur_ready_)
  {
    Time    srtt     = rtt_mgr_.smoothed_rtt();
    double  srtt_sec = srtt.ToDouble();

    owd_est_sec = (0.5 * srtt_sec);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": OWD est %f "
         "(srtt=%f).\n", socket_id_, owd_est_sec, srtt_sec);
#endif

    return owd_est_sec;
  }

  // Convert the receive time into a receive timestamp.
  PktTimestamp  recv_ts =
    (static_cast<PktTimestamp>(recv_time.GetTimeInUsec()) + ts_corr_);

  // Compute the local timestamp delta value for the packet.  If there is no
  // send timestamp, then use the last local timestamp delta value computed.
  int64_t  local_delta = 0;

  if (send_ts != 0)
  {
    local_delta          = (static_cast<int32_t>(recv_ts) -
                            static_cast<int32_t>(send_ts));
    owd_.prev_pkt_delta_ = local_delta;
  }
  else
  {
    local_delta = owd_.prev_pkt_delta_;
  }

  // The one-way delay estimate is:
  //   OWD = (0.5 * MinRTT) + MAX((local_delta - min_local_delta), 0)
  Time     owd_est = owd_.cur_min_rtt_.Multiply(0.5);
  int64_t  add_del = (local_delta - owd_.cur_min_local_delta_);

  if (add_del > 0)
  {
    owd_est = (owd_est + Time::FromUsec(add_del));
  }

  owd_est_sec = owd_est.ToDouble();

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": OWD est %f (recv_ts=%"
       PRIu32 " send_ts=%" PRIu32 " delta=%" PRId64 " min_rtt=%f "
       "min_delta=%" PRId64 ").\n", socket_id_, owd_est_sec, recv_ts, send_ts,
       local_delta, owd_.cur_min_rtt_.ToDouble(), owd_.cur_min_local_delta_);
#endif

  return owd_est_sec;
}

//============================================================================
void Connection::DoReentrantCallbacks()
{
  if (do_cap_est_callback_)
  {
    do_cap_est_callback_ = false;

    // Pass the updated total capacity estimate for the connection to the
    // application.
    app_.ProcessCapacityEstimate(socket_id_, cc_algs_.chan_cap_est_bps,
                                 cc_algs_.trans_cap_est_bps,
                                 cc_algs_.ccl_time_sec);
  }

  if (num_rtt_pdd_samples_ > 0)
  {
    if (rtt_pdd_samples_ == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, RTT/PDD "
           "array missing.\n", socket_id_);
    }
    else
    {
      // Pass the RTT/PDD samples for the connection to the application.
      app_.ProcessRttPddSamples(socket_id_, num_rtt_pdd_samples_,
                                rtt_pdd_samples_);
    }

    num_rtt_pdd_samples_ = 0;
  }

  if (do_close_conn_callback_)
  {
    // Send a reset connection packet.
    SendResetConnPkt(SLIQ_CONN_SOCKET_WRITE_ERROR);

    // Close all of the streams.
    for (size_t i = 0; i < kStreamArraySize; ++i)
    {
      Stream*  stream = stream_info_[i].stream;

      if (stream != NULL)
      {
        // The stream can no longer send or receive.
        stream->ImmediateFullClose();
      }
    }

    // The connection is now fully closed.
    state_ = CLOSED;

    // Notify the application of the close.
    app_.ProcessClose(socket_id_, true);

    // Cancel all of the timers.
    CancelAllTimers();

    // The connection can be scheduled for deletion.
    conn_mgr_.DeleteConnection(socket_id_);

    do_close_conn_callback_ = false;
  }
}

//============================================================================
bool Connection::InitState(EndptType type)
{
  type_             = type;
  initialized_      = false;
  state_            = UNCONNECTED;
  self_addr_.set_address(0);
  self_addr_.set_port(0);
  peer_addr_.set_address(0);
  peer_addr_.set_port(0);
  socket_id_        = -1;
  is_write_blocked_ = false;
  num_hellos_       = 0;
  hello_timer_.Clear();

  // Allocate an array of objects for RTT/PDD estimate callbacks if needed.
  if (rtt_pdd_samples_ == NULL)
  {
    rtt_pdd_samples_ = new (std::nothrow) RttPdd[kMaxRttPddSamples];

    if (rtt_pdd_samples_ == NULL)
    {
      LogE(kClassName, __func__, "Error allocating RTT/PDD callback "
           "array.\n");
      return false;
    }
  }

  return true;
}

//============================================================================
bool Connection::InitServerData(uint16_t server_port,
                                const Ipv4Endpoint& client_address,
                                const CongCtrl* cc_alg, size_t num_cc_alg,
                                EndptId& endpt_id)
{
  // Check if the object has already been initialized.
  if (initialized_)
  {
    LogE(kClassName, __func__, "Error, connection already initialized.\n");
    return false;
  }

  // Initialize the state information.
  if (!InitState(SERVER_DATA))
  {
    return false;
  }

  // Store the client address.
  peer_addr_ = client_address;

  // Open a UDP socket.
  socket_id_ = socket_mgr_.CreateUdpSocket(kFdEventRead
#ifdef SLIQ_NS3
                                           , this
#endif // SLIQ_NS3
                                           );
  if (socket_id_ < 0)
  {
    LogE(kClassName, __func__, "Error opening server data UDP socket.\n");
    return false;
  }

  // Set the necessary socket options.
  if ((!socket_mgr_.SetRecvBufferSize(socket_id_, kSocketBufferSize)) ||
      (!socket_mgr_.SetSendBufferSize(socket_id_, kSocketBufferSize)) ||
      (!socket_mgr_.EnableReceiveTimestamps(socket_id_)))
  {
    LogE(kClassName, __func__, "Error setting options on server data UDP "
         "socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Enable port number reuse on the socket.
  if (!socket_mgr_.EnablePortReuse(socket_id_))
  {
    LogE(kClassName, __func__, "Error enabling port number reuse on server "
         "data UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Bind the socket to any address and the server's well known port number.
  Ipv4Endpoint  endpoint("0.0.0.0", server_port);

  if (!socket_mgr_.Bind(socket_id_, endpoint))
  {
    LogE(kClassName, __func__, "Error binding server data UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Connect the socket to the client.
  if (!socket_mgr_.Connect(socket_id_, client_address))
  {
    LogE(kClassName, __func__, "Error connecting server data UDP socket.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Get the local socket address.
  if (!socket_mgr_.GetLocalAddress(socket_id_, self_addr_))
  {
    LogE(kClassName, __func__, "Error getting local socket address.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Walk the array of congestion control settings, storing each one.
  for (size_t i = 0; i < num_cc_alg; ++i)
  {
    cc_algs_.cc_settings[i] = cc_alg[i];
  }

  cc_algs_.num_cc_alg = num_cc_alg;

  // Create the congestion control objects.
  if (!CreateCongCtrlObjects(false))
  {
    LogE(kClassName, __func__, "Error creating congestion control "
         "objects.\n");
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // Start the RTO timer running.
  if (!StartRtoTimer())
  {
    socket_mgr_.Close(socket_id_);
    socket_id_ = -1;
    return false;
  }

  // The initialization was successful.  Map the socket ID to the endpoint ID,
  // which are equal for simplicity.  Note that the ProcessClientHello()
  // method adds the connection object to the connection manager.
  initialized_ = true;
  endpt_id     = socket_id_;

  // Notify the application.
  app_.ProcessFileDescriptorChange();

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Server %s accepted "
       "connection from client %s.\n", socket_id_,
       self_addr_.ToString().c_str(), peer_addr_.ToString().c_str());

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Connection object %p assigned endpoint ID %"
       PRIEndptId ".\n", this, endpt_id);
#endif

  return true;
}

//============================================================================
bool Connection::ContinueConnectToClient(PktTimestamp echo_ts)
{
  // Check if this connection object can continue to connect to a client.
  if ((type_ != SERVER_DATA) || (!initialized_) || (state_ != UNCONNECTED))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, cannot connect "
         "to client in current connection state.\n", socket_id_);
    return false;
  }

  // Update the connection state.
  state_      = UNCONNECTED;
  num_hellos_ = 0;
  hello_timer_.Clear();

  // Set a timer for how long to wait for a response from the client.
  if (!StartServerHelloTimer())
  {
    return false;
  }

  // Store the timestamp information to use in the server hello timer
  // callback while ignoring duplicates.
  if (echo_ts != client_hello_timestamp_)
  {
    client_hello_timestamp_ = echo_ts;
    client_hello_recv_time_ = Time::Now();
  }

  // Send a server hello message back to the client.
  if (!SendConnHndshkPkt(kServerHelloTag, echo_ts))
  {
    timer_.CancelTimer(hello_timer_);
    return false;
  }

  // Record the transmission.
  num_hellos_++;

  // Update the connection state.
  state_ = SENT_SHLO;

  return true;
}

//============================================================================
bool Connection::CreateCongCtrlObjects(bool is_client)
{
  if ((cc_algs_.num_cc_alg < 1) ||
      (cc_algs_.num_cc_alg > SliqApp::kMaxCcAlgPerConn))
  {
    return false;
  }

  // Initialize the capacity estimator.
  cc_algs_.cap_est.Initialize(socket_id_);

  // Loop over all of the congestion control settings, creating and
  // initializing the necessary congestion control objects.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    if (cc_algs_.cc_alg[i].cc_alg != NULL)
    {
      return false;
    }

    cc_algs_.cc_alg[i].cc_alg = CongCtrlInterface::Create(
      socket_id_, is_client, static_cast<CcId>(i), *this, framer_, rtt_mgr_,
      rng_, packet_pool_, timer_, cc_algs_.cc_settings[i]);

    if (cc_algs_.cc_alg[i].cc_alg == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Congestion control "
           "allocation error.\n", socket_id_);
      return false;
    }

    // Check if a PacingSender object must wrap the real object.
    if (((cc_algs_.cc_settings[i].algorithm == TCP_CUBIC_BYTES_CC) ||
         (cc_algs_.cc_settings[i].algorithm == TCP_RENO_BYTES_CC)) &&
        (cc_algs_.cc_settings[i].cubic_reno_pacing))
    {
      CongCtrlInterface*  tail_cc_alg = cc_algs_.cc_alg[i].cc_alg;

      cc_algs_.cc_alg[i].cc_alg =
        new (std::nothrow) PacingSender(socket_id_, is_client, tail_cc_alg,
                                        timer_tolerance_,
                                        kInitialUnpacedBurst);

      if (cc_algs_.cc_alg[i].cc_alg == NULL)
      {
        delete tail_cc_alg;
        LogE(kClassName, __func__, "Conn %" PRISocketId ": Congestion "
             "control pacing allocation error.\n", socket_id_);
        return false;
      }

      LogD(kClassName, __func__, "Conn %" PRISocketId ": Added pacing sender "
           "to congestion control.\n", socket_id_);
    }

    // Get the congestion control requirements.
    cc_algs_.cc_alg[i].use_rexmit_pacing     =
      cc_algs_.cc_alg[i].cc_alg->UseRexmitPacing();
    cc_algs_.cc_alg[i].use_una_pkt_reporting =
      cc_algs_.cc_alg[i].cc_alg->UseUnaPktReporting();

    if (cc_algs_.cc_alg[i].use_una_pkt_reporting)
    {
      cc_algs_.use_una_pkt_reporting = true;
    }

    // Initialize the congestion control algorithm with the capacity estimator
    // specifying the initial congestion window size.
    if (!cc_algs_.cap_est.InitCcAlg(
          i, cc_algs_.cc_alg[i].cc_alg->UseCongWinForCapEst(),
          cc_algs_.cc_alg[i].cc_alg->GetCongestionWindow()))
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Congestion control "
           "capacity estimator initialization error.\n", socket_id_);
      return false;
    }
  }

  return true;
}

//============================================================================
bool Connection::SendConnHndshkPkt(MsgTag tag, PktTimestamp echo_ts)
{
  bool  rv = false;

  // Compute the timestamp for the connection handshake header.
  Time          now = Time::Now();
  PktTimestamp  ts  = static_cast<PktTimestamp>(now.GetTimeInUsec());

  if (ts == 0)
  {
    ts = 1;
  }

  // Create the connection handshake packet.
  ConnHndshkHeader  ch_hdr(cc_algs_.num_cc_alg, tag, ts, echo_ts,
                           cc_algs_.cc_settings);
  Packet*           pkt = framer_.GenerateConnHndshk(ch_hdr);

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating "
         "packet.\n", socket_id_);
    return rv;
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent connection "
         "handshake packet: tag %c%c ts %" PRIPktTimestamp " echo_ts %"
         PRIPktTimestamp "\n", socket_id_,
         static_cast<int>(ch_hdr.message_tag & 0xFF),
         static_cast<int>((ch_hdr.message_tag >> 8) & 0xFF), ts, echo_ts);
    for (uint8_t i = 0; i < ch_hdr.num_cc_algs; ++i)
    {
      LogD(kClassName, __func__, "  id %" PRIu8 " type %d det %s pacing %s "
           "params %" PRIu32 "\n", i, ch_hdr.cc_alg[i].congestion_control_alg,
           (ch_hdr.cc_alg[i].deterministic_flag ? "true" : "false"),
           (ch_hdr.cc_alg[i].pacing_flag ? "true" : "false"),
           ch_hdr.cc_alg[i].congestion_control_params);
    }
#endif

    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending "
         "connection handshake packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending "
         "connection handshake packet: %s.\n", socket_id_,
         strerror(wr.error_code));
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
bool Connection::SendResetConnPkt(ConnErrorCode error)
{
  bool  rv = false;

  // Create the reset connection packet.
  ResetConnHeader  rc_hdr(error);
  Packet*          pkt = framer_.GenerateResetConn(rc_hdr);

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating "
         "packet.\n", socket_id_);
    return rv;
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent reset connection "
         "packet: error %d\n", socket_id_, error);
#endif

    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending reset "
         "connection packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending reset "
         "connection packet: %s.\n", socket_id_, strerror(wr.error_code));
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
bool Connection::SendCloseConnPkt(bool ack, ConnCloseCode reason)
{
  bool  rv = false;

  // Create the close connection packet.
  CloseConnHeader  cc_hdr(ack, reason);
  Packet*          pkt = framer_.GenerateCloseConn(cc_hdr);

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating "
         "packet.\n", socket_id_);
    return rv;
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent close connection "
         "packet: ACK %s reason %d\n", socket_id_, (ack ? "true" : "false"),
         reason);
#endif

    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending close "
         "connection packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending close "
         "connection packet: %s.\n", socket_id_, strerror(wr.error_code));
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
void Connection::SendAckPkt(const Time& now, CcId cc_id, Packet* pkt)
{
  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent consolidated ACK "
         "packet for cc_id %" PRICcId " size %zu bytes.\n", socket_id_, cc_id,
         pkt->GetLengthInBytes());
#endif
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending ACK "
         "packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending ACK "
         "packet: %s.\n", socket_id_, strerror(wr.error_code));

    // Initiate a close of the connection.
    do_close_conn_callback_ = true;
  }
}

//============================================================================
bool Connection::SendCcSyncPkt(CcId cc_id, uint16_t cc_sync_seq_num,
                               uint32_t cc_sync_params)
{
  bool     rv               = false;
  bool     cancel_ack_timer = false;
  Packet*  pkt              = NULL;

  // Send a CC Sync packet, possibly including other SLIQ headers, in the
  // following order:
  //
  //   1. CC Sync Header (required)
  //   2. ACK Header(s) (opportunistic as space allows)
  //   3. Received Packet Count Header (opportunistic as space allows)

  // Add the congestion control synchronization header.
  CcSyncHeader  ccs_hdr(cc_id, cc_sync_seq_num, cc_sync_params);

  if (!framer_.AppendCcSyncHeader(pkt, ccs_hdr))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating "
         "packet.\n", socket_id_);
    if (pkt != NULL)
    {
      packet_pool_.Recycle(pkt);
    }
    return rv;
  }

  // Get the current time.
  Time  now = Time::Now();

  // Decide if ACK headers can be opportunistically included or not.
  if (!GetAcks(now, 0, pkt, cancel_ack_timer))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error appending ACK "
         "headers.\n", socket_id_);
    if (pkt != NULL)
    {
      packet_pool_.Recycle(pkt);
    }
    return rv;
  }

  // Decide if a received packet count header can be opportunistically
  // included or not.
  if (stats_rcv_rpc_trigger_cnt_ >= kRcvdPktCntIntPkts)
  {
    AddRcvdPktCnt(0, pkt);
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent CC sync packet: "
         "cc_id %" PRICcId " seq_num %" PRIu16 " cc_params %" PRIu32 "\n",
         socket_id_, ccs_hdr.cc_id, ccs_hdr.seq_num, ccs_hdr.cc_params);
#endif

    // If all of the delayed ACKs were sent, then cancel the ACK timer.
    if (cancel_ack_timer)
    {
      pkts_since_last_ack_ = 0;
      timer_.CancelTimer(ack_timer_);
    }

    // The send was successful.
    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending CC "
         "sync packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending CC sync "
         "packet: %s.\n", socket_id_, strerror(wr.error_code));

    // Initiate a close of the connection.
    do_close_conn_callback_ = true;
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
bool Connection::SendRcvdPktCnt()
{
  bool     rv  = false;
  Packet*  pkt = NULL;

  // Add the received packet count header.
  if (!framer_.AppendRcvdPktCntHeader(pkt, stats_rcv_rpc_hdr_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error appending "
         "received packet count header.\n", socket_id_);
    if (pkt != NULL)
    {
      packet_pool_.Recycle(pkt);
    }
    return rv;
  }

  // Send the packet to the peer.
  WriteResult  wr = socket_mgr_.WritePacket(socket_id_, *pkt, peer_addr_);

  if (wr.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Sent received packet "
         "count: stream %" PRIStreamId " rexmit_cnt %" PRIRetransCount
         " seq %" PRIPktSeqNumber " rcvd_pkt_cnt %" PRIPktCount "\n",
         socket_id_, stats_rcv_rpc_hdr_.stream_id,
         stats_rcv_rpc_hdr_.retransmission_count,
         stats_rcv_rpc_hdr_.sequence_number,
         stats_rcv_rpc_hdr_.rcvd_data_pkt_count);
#endif

    // Reset the trigger counter.
    stats_rcv_rpc_trigger_cnt_ = 0;

    // The send was successful.
    rv = true;
  }
#ifdef SLIQ_DEBUG
  else if (wr.status == WRITE_STATUS_BLOCKED)
  {
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Blocked sending "
         "received packet count packet.\n", socket_id_);
  }
#endif
  else if (wr.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending "
         "received packet count packet: %s.\n", socket_id_,
         strerror(wr.error_code));

    // Initiate a close of the connection.
    do_close_conn_callback_ = true;
  }

  // Release the packet.
  packet_pool_.Recycle(pkt);

  return rv;
}

//============================================================================
void Connection::ReceivePackets()
{
  Ipv4Endpoint  src;
  Time          rcv_time;
  Packet*       pkt      = NULL;
  int           num_pkts = 1;

  // Loop until all of the packets are read from the socket.
  while (num_pkts > 0)
  {
    // Read the next set of packets.
    num_pkts = socket_mgr_.ReadPackets(socket_id_, pkt_set_);

    // Process each of the packets.
    for (int i = 0; i < num_pkts; ++i)
    {
      // Get the next packet.
      if ((!pkt_set_.GetNextPacket(pkt, src, rcv_time)) || (pkt == NULL))
      {
        LogW(kClassName, __func__, "Conn %" PRISocketId ": GetNextPacket "
             "returned NULL.\n", socket_id_);
        continue;
      }

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Processing received "
           "packet, %zu bytes, from %s.\n", socket_id_,
           pkt->GetLengthInBytes(), src.ToString().c_str());
#endif

      // Parse the SLIQ headers within the received packet.  Note that the ACK
      // stream mask must be sized to have at least kStreamArraySize bits.
      int       ack_cnt         = 0;
      uint64_t  ack_stream_mask = 0;
      size_t    offset          = 0;

      while ((pkt != NULL) && (offset < pkt->GetLengthInBytes()))
      {
        HeaderType  hdr_type = framer_.GetHeaderType(pkt, offset);

        // Only data, ACK, CC sync, and received packet count headers may be
        // consolidated.
        if ((offset > 0) && ((hdr_type < DATA_HEADER) ||
                             (hdr_type > RCVD_PKT_CNT_HEADER)))
        {
          LogE(kClassName, __func__, "Conn %" PRISocketId ": Cannot "
               "consolidate header type %d.\n", socket_id_, hdr_type);
          break;
        }

        switch (hdr_type)
        {
          case CONNECTION_HANDSHAKE_HEADER:
          {
            ConnHndshkHeader  ch_hdr;

            if (framer_.ParseConnHndshkHeader(pkt, offset, ch_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "connection handshake packet: tag %c%c\n", socket_id_,
                   static_cast<int>(ch_hdr.message_tag & 0xFF),
                   static_cast<int>((ch_hdr.message_tag >> 8) & 0xFF));
              for (uint8_t j = 0; j < ch_hdr.num_cc_algs; ++j)
              {
                LogD(kClassName, __func__, "  id %" PRIu8 " type %d det %s "
                     "pacing %s params %" PRIu32 "\n", j,
                     ch_hdr.cc_alg[i].congestion_control_alg,
                     (ch_hdr.cc_alg[i].deterministic_flag ? "true" : "false"),
                     (ch_hdr.cc_alg[i].pacing_flag ? "true" : "false"),
                     ch_hdr.cc_alg[i].congestion_control_params);
              }
#endif

              ProcessConnHandshake(ch_hdr, src);
            }

            offset = pkt->GetLengthInBytes();
            break;
          }

          case RESET_CONNECTION_HEADER:
          {
            ResetConnHeader  rc_hdr;

            if (framer_.ParseResetConnHeader(pkt, offset, rc_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "reset connection packet: error %d\n", socket_id_,
                   rc_hdr.error_code);
#endif

              ProcessResetConn(rc_hdr, src);
            }

            offset = pkt->GetLengthInBytes();
            break;
          }

          case CLOSE_CONNECTION_HEADER:
          {
            CloseConnHeader  cc_hdr;

            if (framer_.ParseCloseConnHeader(pkt, offset, cc_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "close connection packet: ACK %s reason %d\n", socket_id_,
                   (cc_hdr.ack_flag ? "true" : "false"), cc_hdr.reason_code);
#endif

              ProcessCloseConn(cc_hdr, src);
            }

            offset = pkt->GetLengthInBytes();
            break;
          }

          case CREATE_STREAM_HEADER:
          {
            CreateStreamHeader  cs_hdr;

            if (framer_.ParseCreateStreamHeader(pkt, offset, cs_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "create stream packet: del_time %s ACK %s stream %"
                   PRIStreamId " prio %" PRIPriority " init_win %"
                   PRIWindowSize " init_seq %" PRIPktSeqNumber " del %d rel "
                   "%d rexmit_lim %" PRIRexmitLimit " tgt_rnds %"
                   PRIRexmitRounds " tgt_time %f tgt_prob %f\n", socket_id_,
                   (cs_hdr.del_time_flag ? "true" : "false"),
                   (cs_hdr.ack_flag ? "true" : "false"), cs_hdr.stream_id,
                   cs_hdr.priority, cs_hdr.initial_win_size_pkts,
                   cs_hdr.initial_seq_num, cs_hdr.delivery_mode,
                   cs_hdr.reliability_mode, cs_hdr.rexmit_limit,
                   cs_hdr.fec_target_pkt_del_rounds,
                   cs_hdr.fec_target_pkt_del_time_sec,
                   cs_hdr.fec_target_pkt_recv_prob);
#endif

              ProcessCreateStream(cs_hdr, src);
            }

            offset = pkt->GetLengthInBytes();
            break;
          }

          case RESET_STREAM_HEADER:
          {
            ResetStreamHeader  rs_hdr;

            if (framer_.ParseResetStreamHeader(pkt, offset, rs_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "reset stream packet: stream %" PRIStreamId " error %d "
                   "final_seq %" PRIPktSeqNumber "\n", socket_id_,
                   rs_hdr.stream_id, rs_hdr.error_code, rs_hdr.final_seq_num);
#endif

              ProcessResetStream(rs_hdr, src);
            }

            offset = pkt->GetLengthInBytes();
            break;
          }

          case DATA_HEADER:
          {
            DataHeader  data_hdr;

            if (framer_.ParseDataHeader(pkt, offset, data_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "data packet: epl %s fec %s move_fwd %s persist %s fin %s "
                   "stream %" PRIStreamId " num_ttg %" PRITtgCount " cc_id %"
                   PRICcId " rexmit_cnt %" PRIRetransCount " pld_len %zu seq "
                   "%" PRIPktSeqNumber " ts %" PRIPktTimestamp " ts_delta %"
                   PRIPktTimestamp "\n", socket_id_,
                   (data_hdr.enc_pkt_len_flag ? "true" : "false"),
                   (data_hdr.fec_flag ? "true" : "false"),
                   (data_hdr.move_fwd_flag ? "true" : "false"),
                   (data_hdr.persist_flag ? "true" : "false"),
                   (data_hdr.fin_flag ? "true" : "false"),
                   data_hdr.stream_id, data_hdr.num_ttg, data_hdr.cc_id,
                   data_hdr.retransmission_count, data_hdr.payload_length,
                   data_hdr.sequence_number, data_hdr.timestamp,
                   data_hdr.timestamp_delta);
              if (data_hdr.move_fwd_flag)
              {
                LogD(kClassName, __func__, "  move_fwd: seq %" PRIPktSeqNumber
                     "\n", data_hdr.move_fwd_seq_num);
              }
              if (data_hdr.fec_flag)
              {
                LogD(kClassName, __func__, "  fec: pkt_type %s grp %"
                     PRIFecGroupId " idx %" PRIFecBlock " src %" PRIFecBlock
                     " rnd %" PRIFecRound "\n",
                     ((data_hdr.fec_pkt_type == FEC_SRC_PKT) ? "SRC" : "ENC"),
                     data_hdr.fec_group_id, data_hdr.fec_block_index,
                     data_hdr.fec_num_src, data_hdr.fec_round);
              }
              if (data_hdr.enc_pkt_len_flag)
              {
                LogD(kClassName, __func__, "  enc_pkt_len: %" PRIFecEncPktLen
                     "\n", data_hdr.encoded_pkt_length);
              }
              for (TtgCount i = 0; i < data_hdr.num_ttg; ++i)
              {
                LogD(kClassName, __func__, "  ttg[%" PRITtgCount "]: %f "
                     "seconds\n", i, data_hdr.ttg[i]);
              }
#endif

              // Before processing the data packet, make sure that it is for
              // this connection and not a duplicate.
              if (IsGoodDataPacket(data_hdr, src))
              {
                // Update the differences in the two packet timestamp clocks.
                UpdateTimestampState(rcv_time, data_hdr.timestamp,
                                     data_hdr.timestamp_delta);

#ifdef TTG_TRACKING
                if (data_hdr.num_ttg == 1)
                {
                  // Log the received TTG value before it is processed.
                  // Format:  PLT_RCV <seq_num> <recv_ttg>
                  LogC(kClassName, __func__, "Conn %" PRISocketId
                       ": PLT_RCV %" PRIPktSeqNumber " %f\n", socket_id_,
                       data_hdr.sequence_number, data_hdr.ttg[0]);
                }
#endif // TTG_TRACKING

                // Update the received data packet statistics.
                stats_rcv_rpc_hdr_.stream_id            = data_hdr.stream_id;
                stats_rcv_rpc_hdr_.retransmission_count =
                  data_hdr.retransmission_count;
                stats_rcv_rpc_hdr_.sequence_number      =
                  data_hdr.sequence_number;
                ++stats_rcv_rpc_hdr_.rcvd_data_pkt_count;
                ++stats_rcv_rpc_trigger_cnt_;

                if (ProcessData(data_hdr, src, rcv_time,
                                pkt->GetLengthInBytes()))
                {
                  // The ProcessData() method took ownership of the packet.
                  pkt = NULL;
                }
              }
            }

            break;
          }

          case ACK_HEADER:
          {
            // Use the ACK packet class member, since this structure is large.
            if (framer_.ParseAckHeader(pkt, offset, ack_hdr_))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "ACK packet: stream %" PRIStreamId " num_times %" PRIu8
                   " num_blocks %" PRIu8 " next_seq %" PRIPktSeqNumber " ts %"
                   PRIPktTimestamp " ts_delta %" PRIPktTimestamp "\n",
                   socket_id_, ack_hdr_.stream_id,
                   ack_hdr_.num_observed_times,
                   ack_hdr_.num_ack_block_offsets,
                   ack_hdr_.next_expected_seq_num, ack_hdr_.timestamp,
                   ack_hdr_.timestamp_delta);

              for (uint8_t j = 0; j < ack_hdr_.num_observed_times; ++j)
              {
                LogD(kClassName, __func__, "  Observed time %" PRIu8 ": seq %"
                     PRIPktSeqNumber " ts %" PRIPktTimestamp "\n", j,
                     ack_hdr_.observed_time[j].seq_num,
                     ack_hdr_.observed_time[j].timestamp);
              }

              for (uint8_t k = 0; k < ack_hdr_.num_ack_block_offsets; ++k)
              {
                LogD(kClassName, __func__, "  ACK block %" PRIu8 ": type %d "
                     "offset %" PRIu16 " (seq %" PRIPktSeqNumber ")\n", k,
                     ack_hdr_.ack_block_offset[k].type,
                     ack_hdr_.ack_block_offset[k].offset,
                     (ack_hdr_.next_expected_seq_num +
                      static_cast<PktSeqNumber>(
                        ack_hdr_.ack_block_offset[k].offset)));
              }
#endif

              // Before processing the ACK packet, make sure that it is for
              // this connection and not a duplicate.
              if (IsGoodAckPacket(ack_hdr_, src))
              {
                // Update the differences in the two packet timestamp clocks.
                UpdateTimestampState(rcv_time, ack_hdr_.timestamp,
                                     ack_hdr_.timestamp_delta);

                ProcessAck(ack_hdr_, src, rcv_time);

                ack_cnt++;
                ack_stream_mask |= (static_cast<uint64_t>(0x1) <<
                                    ack_hdr_.stream_id);
              }
            }

            break;
          }

          case CC_SYNC_HEADER:
          {
            CcSyncHeader  ccs_hdr;

            if (framer_.ParseCcSyncHeader(pkt, offset, ccs_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received CC "
                   "sync packet: cc_id %" PRICcId " seq_num %" PRIu16
                   " cc_params %" PRIu32 "\n", socket_id_, ccs_hdr.cc_id,
                   ccs_hdr.seq_num, ccs_hdr.cc_params);
#endif

              // Pass the parameters into the correct congestion control
              // object.
              if (ccs_hdr.cc_id < cc_algs_.num_cc_alg)
              {
                CongCtrlInterface*  cc_alg =
                  cc_algs_.cc_alg[ccs_hdr.cc_id].cc_alg;

                if (cc_alg != NULL)
                {
                  Time  cc_now = Time::Now();
                  cc_alg->ProcessSyncParams(cc_now, ccs_hdr.seq_num,
                                            ccs_hdr.cc_params);
                }
              }
            }

            break;
          }

          case RCVD_PKT_CNT_HEADER:
          {
            RcvdPktCntHeader  rpc_hdr;

            if (framer_.ParseRcvdPktCntHeader(pkt, offset, rpc_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received "
                   "received packet count packet: stream %" PRIStreamId
                   " rexmit_cnt %" PRIRetransCount " seq %" PRIPktSeqNumber
                   " rcvd_pkt_cnt %" PRIPktCount "\n", socket_id_,
                   rpc_hdr.stream_id, rpc_hdr.retransmission_count,
                   rpc_hdr.sequence_number, rpc_hdr.rcvd_data_pkt_count);
#endif

              ProcessRcvdPktCntInfo(rpc_hdr, rcv_time);
            }

            break;
          }

          case CC_PKT_TRAIN_HEADER:
          {
            CcPktTrainHeader  ccpt_hdr;

            if (framer_.ParseCcPktTrainHeader(pkt, offset, ccpt_hdr))
            {
#ifdef SLIQ_DEBUG
              LogD(kClassName, __func__, "Conn %" PRISocketId ": Received CC "
                   "packet train packet: cc_id %" PRICcId " pt_type %" PRIu8
                   " pt_seq %" PRIu8 " inter_recv_time %" PRIu32 " ts %"
                   PRIPktTimestamp " ts_delta %" PRIPktTimestamp "\n",
                   socket_id_, ccpt_hdr.cc_id, ccpt_hdr.pt_pkt_type,
                   ccpt_hdr.pt_seq_num, ccpt_hdr.pt_inter_recv_time,
                   ccpt_hdr.pt_timestamp, ccpt_hdr.pt_timestamp_delta);
#endif

              // Update the differences in the two packet timestamp clocks.
              UpdateTimestampState(rcv_time, ccpt_hdr.pt_timestamp,
                                   ccpt_hdr.pt_timestamp_delta);

              // Notify the correct congestion control object about the packet
              // train packet just received.
              if (ccpt_hdr.cc_id < cc_algs_.num_cc_alg)
              {
                CongCtrlInterface*  cc_alg =
                  cc_algs_.cc_alg[ccpt_hdr.cc_id].cc_alg;

                if (cc_alg != NULL)
                {
                  Time  cc_now = Time::Now();
                  cc_alg->ProcessCcPktTrain(cc_now, ccpt_hdr);
                }
              }
            }

            offset = pkt->GetLengthInBytes();
            break;
          }

          case UNKNOWN_HEADER:
          default:
            LogE(kClassName, __func__, "Conn %" PRISocketId ": "
                 "Identification of SLIQ header type %d failed.\n",
                 socket_id_, hdr_type);
            offset = pkt->GetLengthInBytes();
        } // switch (hdr_type)
      } // while ((pkt != NULL) && (offset < pkt->GetLengthInBytes()))

      // Release the packet if ownership has not been transferred.
      if (pkt != NULL)
      {
        packet_pool_.Recycle(pkt);
        pkt = NULL;
      }

      // Update congestion control.
      if (ack_cnt > 0)
      {
        // Process any implicit ACKs for streams other than those that
        // received ACKs above.
        ProcessImplicitAcks(ack_stream_mask);

        // Get the current time.
        Time  now = Time::Now();

        // Stop ACK packet processing on the congestion control algorithms
        // where it has been started.
        for (size_t l = 0; l < cc_algs_.num_cc_alg; ++l)
        {
          CcAlg&  cc_info = cc_algs_.cc_alg[l];

          if (cc_info.in_ack_proc)
          {
            if (cc_info.cc_alg != NULL)
            {
              cc_info.cc_alg->OnAckPktProcessingDone(now);
            }

            cc_info.in_ack_proc = false;
          }
        }

        // Now that all of the ACKs have been processed, attempt to send as
        // many packets as possible.
        OnCanWrite();
      }
    } // for (int i = 0; i < num_pkts; ++i)
  } // while (num_pkts > 0)
}

//============================================================================
void Connection::ProcessConnHandshake(ConnHndshkHeader& hdr,
                                      const Ipv4Endpoint&src)
{
  if (hdr.message_tag == kClientHelloTag)
  {
    if (type_ == SERVER_DATA)
    {
      ProcessDataClientHello(hdr, src);
    }
    else
    {
      ProcessClientHello(hdr, src);
    }
  }
  else if (hdr.message_tag == kServerHelloTag)
  {
    ProcessServerHello(hdr, src);
  }
  else if (hdr.message_tag == kClientConfirmTag)
  {
    ProcessClientConfirm(hdr, src);
  }
  else if (hdr.message_tag == kRejectTag)
  {
    ProcessReject(src);
  }
  else
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Unknown connection "
         "handshake packet %c%c.\n", socket_id_,
         static_cast<int>(hdr.message_tag & 0xFF),
         static_cast<int>((hdr.message_tag >> 8) & 0xFF));
  }
}

//============================================================================
void Connection::ProcessDataClientHello(ConnHndshkHeader& hdr,
                                        const Ipv4Endpoint& src)
{
  if (state_ == SENT_SHLO)
  {
    // Update the timestamp information for use in the server hello timer
    // callback while ignoring duplicate packets.
    if (hdr.timestamp != client_hello_timestamp_)
    {
      client_hello_timestamp_ = hdr.timestamp;
      client_hello_recv_time_ = Time::Now();
    }
  }

  // The connection must be initialized and UNCONNECTED.
  if ((!initialized_) || (state_ != UNCONNECTED))
  {
    return;
  }

  // Validate the client hello packet and store the congestion control
  // settings.
  CongCtrl  alg[SliqApp::kMaxCcAlgPerConn];
  size_t    num_alg = hdr.ConvertToCongCtrl(alg, SliqApp::kMaxCcAlgPerConn);

  for (size_t i = 0; i < num_alg; ++i)
  {
    cc_algs_.cc_settings[i] = alg[i];

    if (!CongCtrlSettingIsValid(alg[i], false))
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, invalid "
           "client hello packet congestion control settings: %s\n",
           socket_id_, CongCtrlAlgToString(alg[i]));
      return;
    }
  }

  cc_algs_.num_cc_alg = num_alg;

  // Create the congestion control objects.
  if (!CreateCongCtrlObjects(false))
  {
    LogE(kClassName, __func__, "Error creating congestion control "
         "objects.\n");
    return;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Received request for "
       "connection from client %s.\n", socket_id_, src.ToString().c_str());
#endif

  // Attempt to continue the connection establishment.
  if (!ContinueConnectToClient(hdr.timestamp))
  {
    SendConnHndshkPkt(kRejectTag, hdr.timestamp);
    state_ = CLOSED;
    app_.ProcessConnectionResult(socket_id_, false);
    conn_mgr_.DeleteConnection(socket_id_);
    timer_.CancelTimer(hello_timer_);
    return;
  }

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Server %s connected to "
       "client %s.\n", socket_id_, self_addr_.ToString().c_str(),
       peer_addr_.ToString().c_str());
}

//============================================================================
void Connection::ProcessClientHello(ConnHndshkHeader& hdr,
                                    const Ipv4Endpoint& src)
{
  // The connection must be a server listen endpoint.
  if ((type_ != SERVER_LISTEN) || (!initialized_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, non-server "
         "listen endpoint got client hello packet.\n", socket_id_);
    return;
  }

  // A server listen endpoint is only in either the UNCONNECTED or CLOSED
  // states.  If the server listen endpoint is CLOSED, then ignore the client
  // hello packet.
  if (state_ != UNCONNECTED)
  {
    return;
  }

  // Validate the client hello packet.
  CongCtrl  alg[SliqApp::kMaxCcAlgPerConn];
  size_t    num_alg = hdr.ConvertToCongCtrl(alg, SliqApp::kMaxCcAlgPerConn);

  if (num_alg != cc_algs_.num_cc_alg)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, invalid client "
         "hello number of congestion control algorithms: %zu\n", socket_id_,
         num_alg);
    return;
  }

  for (size_t i = 0; i < num_alg; ++i)
  {
    if (!CongCtrlSettingIsValid(alg[i], false))
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, invalid "
           "client hello congestion control settings: %s\n", socket_id_,
           CongCtrlAlgToString(alg[i]));
      return;
    }
  }

  // Check if this is a duplicate client hello packet.  If the connection
  // object for the peer already exists, then ignore the client hello packet.
  // The connection object takes responsibility for sending server hello
  // packets.
  Connection*  conn = conn_mgr_.GetConnectionByPeer(src);

  if (conn != NULL)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Duplicate client "
         "hello packet from %s, ignoring.\n", socket_id_,
         src.ToString().c_str());
#endif

    // Update the timestamp information for use in the connection's server
    // hello timer callback while ignoring duplicates.
    if (hdr.timestamp != client_hello_timestamp_)
    {
      conn->client_hello_timestamp_ = hdr.timestamp;
      conn->client_hello_recv_time_ = Time::Now();
    }

    return;
  }

  // This client is the current peer for the server listen endpoint.
  peer_addr_ = src;

  // Create a new connection and initialize it as a server data endpoint.
  EndptId  endpt_id = 0;

  conn = new (std::nothrow) Connection(app_, socket_mgr_, conn_mgr_, rng_,
                                       packet_pool_, timer_);

  if ((conn == NULL) ||
      (!conn->InitServerData(ntohs(self_addr_.port()), src, alg, num_alg,
                             endpt_id)))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating a new "
         "server data connection for client %s.\n", socket_id_,
         src.ToString().c_str());
    if (conn != NULL)
    {
      delete conn;
    }
    return;
  }

  // Allow the application to accept or reject the connection request.
  if (!app_.ProcessConnectionRequest(socket_id_, endpt_id, src))
  {
    // Rejected.
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Application rejected "
         "request for connection from client %s.\n", socket_id_,
         src.ToString().c_str());
#endif

    SendConnHndshkPkt(kRejectTag, hdr.timestamp);
    delete conn;
    return;
  }

  // Accepted.
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Application accepted "
       "request for connection from client %s.\n", socket_id_,
       src.ToString().c_str());
#endif

  // Attempt to continue the connection establishment.
  if (!conn->ContinueConnectToClient(hdr.timestamp))
  {
    SendConnHndshkPkt(kRejectTag, hdr.timestamp);
    app_.ProcessConnectionResult(endpt_id, false);
    delete conn;
    return;
  }

  // Store the connection.
  if (!conn_mgr_.AddConnection(endpt_id, conn))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error storing new "
         "connection.\n", socket_id_);
    // A server hello packet was already sent above.  Thus, a reset connection
    // packet must be sent.
    SendResetConnPkt(SLIQ_CONN_INTERNAL_ERROR);
    app_.ProcessConnectionResult(endpt_id, false);
    delete conn;
    return;
  }
}

//============================================================================
void Connection::ProcessServerHello(ConnHndshkHeader& hdr,
                                    const Ipv4Endpoint& src)
{
  // The connection must be a client data endpoint.
  if ((type_ != CLIENT_DATA) || (!initialized_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, non-client "
         "data endpoint got server hello packet.\n", socket_id_);
    return;
  }

  // The connection must be in the SENT_CHLO or CONNECTED state.
  if ((state_ != SENT_CHLO) && (state_ != CONNECTED))
  {
    return;
  }

  // The congestion control parameters must match.
  CongCtrl  alg[SliqApp::kMaxCcAlgPerConn];
  size_t    num_alg = hdr.ConvertToCongCtrl(alg, SliqApp::kMaxCcAlgPerConn);

  if (num_alg != cc_algs_.num_cc_alg)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, invalid server "
         "hello number of congestion control algorithms: %zu\n", socket_id_,
         num_alg);
    return;
  }

  for (size_t i = 0; i < num_alg; ++i)
  {
    if (alg[i] != cc_algs_.cc_settings[i])
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, server hello "
           "congestion control parameters do not match local settings.\n",
           socket_id_);
      return;
    }
  }

  // If this is the first server hello (currently in the SENT_CHLO state),
  // then the source address has the port number that the server will use, and
  // this is our peer address.  If this is not the first server hello
  // (currently in the CONNECTED state), then we should already have the
  // correct peer address.
  if (state_ == SENT_CHLO)
  {
    peer_addr_ = src;
  }
  else if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, server hello "
         "source %s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return;
  }

  // Send a client confirmation packet back to the server.
  if (!SendConnHndshkPkt(kClientConfirmTag, hdr.timestamp))
  {
    return;
  }

  // If this is the first server hello (currently in the SENT_CHLO state),
  // then update the connection state, notify the client application that the
  // connection was successful, compute the local timestamp clock correction
  // value to use, and compute an RTT estimate.
  if (state_ == SENT_CHLO)
  {
    LogA(kClassName, __func__, "Conn %" PRISocketId ": Client %s connected "
         "to server %s.\n", socket_id_, self_addr_.ToString().c_str(),
         peer_addr_.ToString().c_str());

    state_ = CONNECTED;

    // Notify the server application that the connection was successful.
    app_.ProcessConnectionResult(socket_id_, true);

    // Compute the local timestamp clock correction value to be used.  Find
    // the (remote_ts - local_ts) in order to be able to add the correction
    // value to the actual local timestamp clock.
    ts_corr_ = (hdr.timestamp - hdr.echo_timestamp);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Client timestamp "
         "correction is %" PRIPktTimestamp " usec (rmt=%" PRIPktTimestamp
         " - loc=%" PRIPktTimestamp ").\n", socket_id_, ts_corr_,
         hdr.timestamp, hdr.echo_timestamp);
#endif

    // Calculate an RTT estimate for the RTT manager, the application, and the
    // congestion control algorithms.
    Time          now    = Time::Now();
    PktTimestamp  now_ts = static_cast<PktTimestamp>(now.GetTimeInUsec());

    PktTimestamp  delta  = ((hdr.echo_timestamp != 0) ?
                            (now_ts - hdr.echo_timestamp) :
                            kConnEstabMaxRttUsec);

    if (hdr.echo_timestamp == 0)
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid connection "
           "handshake echo timestamp received.\n", socket_id_);
    }

    if (delta > kConnEstabMaxRttUsec)
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid connection "
           "handshake RTT estimate %" PRIPktTimestamp " usec.\n", socket_id_,
           delta);

      delta = kConnEstabMaxRttUsec;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Connection handshake "
         "RTT estimate is %" PRIPktTimestamp " usec at client.\n", socket_id_,
         delta);
#endif

    Time  rtt = Time::FromUsec(delta);

    rtt_mgr_.UpdateRtt(socket_id_, rtt);

    if (num_rtt_pdd_samples_ < kMaxRttPddSamples)
    {
      rtt_pdd_samples_[num_rtt_pdd_samples_].stream_id = 0;
      rtt_pdd_samples_[num_rtt_pdd_samples_].rtt_usec  = delta;
      rtt_pdd_samples_[num_rtt_pdd_samples_].pdd_usec  = 0;
      ++num_rtt_pdd_samples_;
    }

    for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
    {
      CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

      if (cc_alg != NULL)
      {
        cc_alg->Connected(now, rtt);
      }
    }
  }

  // Cancel any hello timer.
  timer_.CancelTimer(hello_timer_);
}

//============================================================================
void Connection::ProcessClientConfirm(ConnHndshkHeader& hdr,
                                      const Ipv4Endpoint& src)
{
  // The connection must be a server data endpoint.
  if ((type_ != SERVER_DATA) || (!initialized_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, non-server "
         "data endpoint got client confirm packet.\n", socket_id_);
    return;
  }

  // The connection must be in the SENT_SHLO state.
  if (state_ != SENT_SHLO)
  {
    return;
  }

  // The congestion control parameters must match.
  CongCtrl  alg[SliqApp::kMaxCcAlgPerConn];
  size_t    num_alg = hdr.ConvertToCongCtrl(alg, SliqApp::kMaxCcAlgPerConn);

  if (num_alg != cc_algs_.num_cc_alg)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, invalid client "
         "confirm number of congestion control algorithms: %zu\n", socket_id_,
         num_alg);
    return;
  }

  for (size_t i = 0; i < num_alg; ++i)
  {
    if (alg[i] != cc_algs_.cc_settings[i])
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, client "
           "confirm congestion control parameters do not match local "
           "settings.\n", socket_id_);
      return;
    }
  }

  // We should already have the correct peer address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, client confirm "
         "source %s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return;
  }

  // Update the connection state.
  state_ = CONNECTED;

  // Notify the server application that the connection was successful.
  app_.ProcessConnectionResult(socket_id_, true);

  // Calculate an RTT estimate for the RTT manager, the application, and the
  // congestion control algorithms.
  Time          now    = Time::Now();
  PktTimestamp  now_ts = static_cast<PktTimestamp>(now.GetTimeInUsec());
  PktTimestamp  delta  = ((hdr.echo_timestamp != 0) ?
                          (now_ts - hdr.echo_timestamp) :
                          kConnEstabMaxRttUsec);

  if (hdr.echo_timestamp == 0)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid connection "
         "handshake echo timestamp received.\n", socket_id_);
  }

  if (delta > kConnEstabMaxRttUsec)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid connection "
         "handshake RTT estimate %" PRIPktTimestamp " usec.\n", socket_id_,
         delta);

    delta = kConnEstabMaxRttUsec;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Connection handshake "
       "RTT estimate is %" PRIPktTimestamp " usec at server.\n", socket_id_,
       delta);
#endif

  Time  rtt = Time::FromUsec(delta);

  rtt_mgr_.UpdateRtt(socket_id_, rtt);

  if (num_rtt_pdd_samples_ < kMaxRttPddSamples)
  {
    rtt_pdd_samples_[num_rtt_pdd_samples_].stream_id = 0;
    rtt_pdd_samples_[num_rtt_pdd_samples_].rtt_usec  = delta;
    rtt_pdd_samples_[num_rtt_pdd_samples_].pdd_usec  = 0;
    ++num_rtt_pdd_samples_;
  }

  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if (cc_alg != NULL)
    {
      cc_alg->Connected(now, rtt);
    }
  }

  // Cancel any hello timer.
  timer_.CancelTimer(hello_timer_);
}

//============================================================================
void Connection::ProcessReject(const Ipv4Endpoint& src)
{
  // The connection must be a client data endpoint.
  if ((type_ != CLIENT_DATA) || (!initialized_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, non-client "
         "data endpoint got reject packet.\n", socket_id_);
    return;
  }

  // The connection must be in the SENT_CHLO state.
  if (state_ != SENT_CHLO)
  {
    return;
  }

  // The source address has the server's new port number, and is our peer
  // address.  This is because the server switches to an ephemeral port number
  // before sending the reject packet, and the connection must use this new
  // port number.
  peer_addr_ = src;

  // The server rejected the connection.  Schedule the connection for
  // deletion.
  state_ = CLOSED;
  app_.ProcessConnectionResult(socket_id_, false);
  conn_mgr_.DeleteConnection(socket_id_);

  // Cancel any hello timer.
  timer_.CancelTimer(hello_timer_);
}

//============================================================================
void Connection::ProcessResetConn(ResetConnHeader& hdr,
                                  const Ipv4Endpoint& src)
{
  if (((type_ != SERVER_DATA) && (type_ != CLIENT_DATA)) || (!initialized_))
  {
    return;
  }

  // Validate the source address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, source address "
         "%s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return;
  }

  // Only server data and client data endpoints handle reset connection
  // packets.  This depends on the current state.
  if ((state_ == UNCONNECTED) || (state_ == CLOSED))
  {
    return;
  }

  // Log any error codes.
  if (hdr.error_code != SLIQ_CONN_NO_ERROR)
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Received reset "
         "connection, error code %d.\n", hdr.error_code);
  }

  if ((state_ == SENT_CHLO) || (state_ == SENT_SHLO))
  {
    // The connection is still being established.  Immediately close the
    // connection.  There are no streams to be closed.
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Connection is still "
         "being established, immediately closing.\n", socket_id_);
#endif

    state_ = CLOSED;
    app_.ProcessConnectionResult(socket_id_, false);
    conn_mgr_.DeleteConnection(socket_id_);

    // Cancel any hello timer.
    timer_.CancelTimer(hello_timer_);

    return;
  }

  // At this point, the state may be either CONNECTED, CONN_CLOSE_WAIT, or
  // APP_CLOSE_WAIT.  Close all of the streams.
  for (size_t i = 0; i < kStreamArraySize; ++i)
  {
    Stream*  stream = stream_info_[i].stream;

    if (stream != NULL)
    {
      // The stream can no longer send or receive.
      stream->ImmediateFullClose();
    }
  }

  // The connection is now fully closed.
  state_ = CLOSED;

  // Notify the application of the close.
  app_.ProcessClose(socket_id_, true);

  // Cancel all of the timers.
  CancelAllTimers();

  // The connection can be scheduled for deletion.
  conn_mgr_.DeleteConnection(socket_id_);
}

//============================================================================
void Connection::ProcessCloseConn(CloseConnHeader& hdr,
                                  const Ipv4Endpoint& src)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_))
  {
    return;
  }

  // Validate the source address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, source address "
         "%s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return;
  }

  // Check if this is a close connection ACK packet.
  if (hdr.ack_flag)
  {
    // If a close connection packet has been sent, then cancel the close
    // connection timer.
    if ((state_ == CONN_CLOSE_WAIT) || (state_ == CLOSED))
    {
      timer_.CancelTimer(close_timer_);
    }

    return;
  }

  // For client or server data endpoints receiving a close connection packet,
  // the processing depends on the current state.
  if (state_ == UNCONNECTED)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": No connection "
         "initiated.\n", socket_id_);
    return;
  }

  // If the connection is still being established, then send a reset
  // connection packet and immediately schedule the connection for deletion.
  if ((state_ == SENT_CHLO) || (state_ == SENT_SHLO))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Connection is still "
         "being established, sending a reset connection packet and "
         "immediately closing.\n", socket_id_);
#endif

    SendResetConnPkt(SLIQ_CONN_RECV_CLOSE_ERROR);
    state_ = CLOSED;
    conn_mgr_.DeleteConnection(socket_id_);

    return;
  }

  if ((state_ == APP_CLOSE_WAIT) || (state_ == CLOSED))
  {
    // This is a close connection packet retransmission.  Send another
    // connection close ACK packet.
    SendCloseConnPkt(true, hdr.reason_code);
    return;
  }

  // The state is either CONNECTED or CONN_CLOSE_WAIT from this point on.
  // Send a number of connection close ACK packets.
  for (int cnt = 0; cnt < kMaxCloseConns; ++cnt)
  {
    if ((!SendCloseConnPkt(true, hdr.reason_code)) && (cnt == 0))
    {
      return;
    }
  }

  // Close all of the streams.
  for (size_t i = 0; i < kStreamArraySize; ++i)
  {
    Stream*  stream = stream_info_[i].stream;

    if (stream != NULL)
    {
      if (state_ == CONNECTED)
      {
        // The stream can no longer receive, but can still send.
        stream->ImmediateHalfCloseNoRecv();
      }
      else
      {
        // The stream can no longer send or receive.
        stream->ImmediateFullClose();
      }
    }
  }

  // Update the state as needed given the current state.
  if (state_ == CONNECTED)
  {
    // The connection is now waiting on the local application calling Close().
    state_ = APP_CLOSE_WAIT;

    // Perform a callback to the application.
    app_.ProcessClose(socket_id_, false);

    return;
  }

  if (state_ == CONN_CLOSE_WAIT)
  {
    // The connection is now fully closed.
    state_ = CLOSED;

    // Perform a callback to the application.
    app_.ProcessClose(socket_id_, true);

    // The connection can be scheduled for deletion.
    conn_mgr_.DeleteConnection(socket_id_);

    return;
  }
}

//============================================================================
void Connection::ProcessCreateStream(CreateStreamHeader& hdr,
                                     const Ipv4Endpoint& src)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED) || (cc_algs_.num_cc_alg < 1))
  {
    return;
  }

  // Validate the source address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, source address "
         "%s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return;
  }

  // Look up the stream object.
  StreamId  stream_id = hdr.stream_id;
  Stream*   stream    = GetStream(stream_id);

  // The stream must handle any create stream ACK packet.
  if (hdr.ack_flag)
  {
    if (stream != NULL)
    {
      stream->ProcessCreateStreamAck(hdr);
    }
    return;
  }

  // This is a non-ACK create stream packet.  If the stream already exists,
  // then let the stream handle it.
  if (stream != NULL)
  {
    stream->ProcessCreateStream(hdr);
    return;
  }

  // The stream has not been created yet on this side of the connection.
  // Attempt to create it now.
  Reliability  rel;

  hdr.GetReliability(rel);

  if ((StreamIdIsValid(stream_id)) &&
      (((type_ == CLIENT_DATA) && ((stream_id % 2) == 0)) ||
       ((type_ == SERVER_DATA) && ((stream_id % 2) == 1))) &&
      (PriorityIsValid(hdr.priority)) &&
      (ReliabilityIsValid(rel, hdr.delivery_mode)))
  {
    // Create a new stream and initialize it.
    Stream*  stream = new (std::nothrow)
      Stream(*this, rtt_mgr_, cc_algs_, rng_, packet_pool_, timer_,
             socket_id_, stream_id, hdr.priority);

    if ((stream == NULL) ||
        (!stream->InitializeRemoteStream(hdr)))
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error creating a "
           "new stream.\n", socket_id_);
      if (stream != NULL)
      {
        delete stream;
      }
    }
    else
    {
      // Store the stream using the stream ID as the index.
      RecordNewStream(stream, stream_id, hdr.priority);

      LogA(kClassName, __func__, "Conn %" PRISocketId ": Implicitly created "
           "stream ID %" PRIStreamId " with: delivery %d reliable %d prio %"
           PRIPriority " win %" PRIWindowSize " seq %" PRIPktSeqNumber
           " rexmit_lim %" PRIRexmitLimit " del_time %d tgt_rnds %"
           PRIRexmitRounds " tgt_time %f tgt_p %f\n", socket_id_, stream_id,
           hdr.delivery_mode, hdr.reliability_mode, hdr.priority,
           hdr.initial_win_size_pkts, hdr.initial_seq_num, hdr.rexmit_limit,
           static_cast<int>(hdr.del_time_flag), hdr.fec_target_pkt_del_rounds,
           hdr.fec_target_pkt_del_time_sec, hdr.fec_target_pkt_recv_prob);

      // Inform the application of the new stream.
      app_.ProcessNewStream(socket_id_, stream_id, hdr.priority, rel,
                            hdr.delivery_mode);
    }
  }
  else
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, cannot "
         "implicitly create a stream due to invalid stream ID %" PRIStreamId
         " or priority %" PRIPriority " or reliability settings.\n",
         socket_id_, stream_id, hdr.priority);
  }
}

//============================================================================
void Connection::ProcessResetStream(ResetStreamHeader& hdr,
                                    const Ipv4Endpoint& src)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED))
  {
    return;
  }

  // Validate the source address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, source address "
         "%s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return;
  }

  // Log any error codes.
  if (hdr.error_code != SLIQ_STREAM_NO_ERROR)
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId " Stream %" PRIStreamId
         ": Received reset stream, error code %d.\n", socket_id_,
         hdr.stream_id, hdr.error_code);
  }

  // Find the stream.
  Stream*  stream = GetStream(hdr.stream_id);

  if (stream == NULL)
  {
    return;
  }

  // Call into the stream.
  stream->ProcessResetStream();
}

//============================================================================
bool Connection::IsGoodDataPacket(DataHeader& hdr, const Ipv4Endpoint& src)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED))
  {
    return false;
  }

  // Validate the source address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, source address "
         "%s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return false;
  }

  // Validate the congestion control identifier.
  if (hdr.cc_id >= cc_algs_.num_cc_alg)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, cc_id %" PRICcId
         " is invalid.\n", socket_id_, hdr.cc_id);
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(hdr.stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream to check the data packet further.
  return stream->IsGoodDataPacket(hdr);
}

//============================================================================
bool Connection::ProcessData(DataHeader& hdr, const Ipv4Endpoint& src,
                             const Time& rcv_time, size_t pkt_size)
{
  // Find the stream.
  Stream*  stream = GetStream(hdr.stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // If the connection is currently in an outage, then switch back to normal
  // mode.  Since this method does not reset the retransmission timer or force
  // packets to be sent, have the LeaveOutage() method do those things as
  // needed.
  if (is_in_outage_)
  {
    LeaveOutage(true);

    // Attempt to send as many packets as possible from all of the stream
    // transmit queues.
    OnCanWrite();
  }

  // Update the expected data packet inter-receive time as needed.
  //
  // \todo What if the network were to slow down?  If the receive network
  // capacity drops, then the inter-receive time here needs to increase.
  // Should we assume a symmetric channel rate-wise (which might allow us to
  // use the local capacity estimate)?
  if (!data_pkt_recv_time_.IsZero())
  {
    double  irt = ((kMaxPacketSize / pkt_size) *
                   (rcv_time.Subtract(data_pkt_recv_time_).ToDouble()));

    if ((data_pkt_irt_sec_ < 0.0) || (irt < data_pkt_irt_sec_))
    {
      data_pkt_irt_sec_ = irt;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Update data packet "
           "inter-receive time: %f sec.\n", socket_id_, data_pkt_irt_sec_);
#endif
    }
  }

  // Record the time that a data packet was received from the peer.
  ack_or_data_pkt_recv_time_ = rcv_time;
  data_pkt_recv_time_        = rcv_time;

  // Call into the stream to process the data packet.
  bool  ack_now = false;
  bool  missing = stream->IsDataMissing();
  bool  rv      = stream->ProcessData(hdr, rcv_time, ack_now);

  // If this completes the missing data, then send post-recovery ACKs.
  if (missing && !stream->IsDataMissing())
  {
    if (stream_info_[hdr.stream_id].extra_acks < kPostRecoveryAckCnt)
    {
      stream_info_[hdr.stream_id].extra_acks = kPostRecoveryAckCnt;
    }
  }

  // If this is a semi-reliable ARQ+FEC stream, then ACK the latency-sensitive
  // data now and send additional ACKs to allow the logic that detects the end
  // of each FEC group round to function in the presence of packet loss.
  if (stream->IsUsingArqFec())
  {
    ack_now = true;

    // Compute:  ceil(3 + (20 * PER))
    uint8_t  ls_acks = static_cast<uint8_t>(3.0 + (20.0 * stats_local_per_) +
                                            0.999999);

    if (stream_info_[hdr.stream_id].extra_acks < ls_acks)
    {
      stream_info_[hdr.stream_id].extra_acks = ls_acks;
    }
  }

  // Send an ACK packet as directed.
  Time  now = Time::Now();

  if (ack_now)
  {
    ForceAck(now, hdr.cc_id, hdr.stream_id);
  }
  else
  {
    MaybeAck(now, hdr.cc_id, hdr.stream_id);
  }

  return rv;
}

//============================================================================
bool Connection::IsGoodAckPacket(AckHeader& hdr, const Ipv4Endpoint& src)
{
  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) || (!initialized_) ||
      (state_ != CONNECTED))
  {
    return false;
  }

  // Validate the source address.
  if (peer_addr_ != src)
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error, source address "
         "%s does not match peer address %s.\n", socket_id_,
         src.ToString().c_str(), peer_addr_.ToString().c_str());
    return false;
  }

  // Find the stream.
  Stream*  stream = GetStream(hdr.stream_id);

  if (stream == NULL)
  {
    return false;
  }

  // Call into the stream to check the ACK packet further.
  return stream->IsGoodAckPacket(hdr);
}

//============================================================================
void Connection::ProcessAck(AckHeader& hdr, const Ipv4Endpoint& src,
                            const Time& rcv_time)
{
  // Find the stream.
  Stream*  stream = GetStream(hdr.stream_id);

  if (stream == NULL)
  {
    return;
  }

  // If the connection is currently in an outage, then switch back to normal
  // mode.  Note that the retransmission timer will be reset below if needed.
  // Also, any required data packets will be sent below.
  bool  leaving_outage = false;

  if (is_in_outage_)
  {
    LeaveOutage(false);
    leaving_outage = true;
  }

  // Get the current time.
  Time  now = Time::Now();

  // Record the time that an ACK packet was received from the peer.
  ack_or_data_pkt_recv_time_ = rcv_time;

  // Call into the stream to process the ACK.  The stream returns if all data
  // has been ACKed after processing the ACK, and if new data was ACKed in the
  // processing of the ACK.  It also returns the largest observed connection
  // sequence number on success.
  bool          new_data_acked = false;
  bool          all_data_acked = false;
  PktSeqNumber  lo_conn_seq    = 0;

  if (stream->ProcessAck(hdr, rcv_time, now, leaving_outage, new_data_acked,
                         all_data_acked, lo_conn_seq))
  {
    if (SEQ_GT(lo_conn_seq, largest_observed_conn_seq_num_))
    {
      largest_observed_conn_seq_num_ = lo_conn_seq;
    }
  }

  // If this is the first ACK packet since an RTO timeout, then reset state
  // for a fast recovery.
  if (rto_timeout_cnt_ > 0)
  {
    // Have each stream consider any unACKed packets to be lost.  This can
    // help speed up the necessary packet retransmissions.
    ForceUnackedPacketsLost(now);

    // Reset the RTO timeout counter.
    rto_timeout_cnt_ = 0;
  }

  // If leaving an outage, then allow each stream to retransmit one data
  // packet now that the ACK packet has been processed.  This should help get
  // the ACK clocking restarted.  Set the RTO flag during retransmissions.
  // This prevents setting timers that will just be canceled and reset.
  if (leaving_outage)
  {
    is_in_rto_ = true;
    RexmitDataPkts();
    is_in_rto_ = false;
  }

  // If all of the data on this and the other streams has been ACKed, then
  // stop the retransmission timer.
  if ((all_data_acked) && (IsAllDataAcked()))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": All data ACKed, "
         "cancel retransmit timer.\n", socket_id_);
#endif

    rto_time_.Zero();
  }
  else
  {
    // If new data was ACKed in the ACK or this call is leaving an outage,
    // then set the retransmission timer expiration time.
    if ((new_data_acked) || (leaving_outage))
    {
      SetRexmitTime(now, rtt_mgr_.GetRtoTime());
    }
  }
}

//============================================================================
void Connection::ProcessImplicitAcks(uint64_t ack_stream_mask)
{
  bool  have_now = false;
  Time  now;

  // Call into each stream that did not receive an ACK header in this packet
  // and still has unACKed data to process an implicit ACK in the form of a
  // (possibly updated) largest observed connection sequence number.
  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    StreamId  stream_id = prio_info_.stream_id[index];

    if ((ack_stream_mask & (static_cast<uint64_t>(0x1) << stream_id)) == 0)
    {
      Stream*  stream = GetStream(stream_id);

      if ((stream != NULL) && (!stream->IsAllDataAcked()))
      {
        // Get the current time.
        if (!have_now)
        {
          now      = Time::Now();
          have_now = true;
        }

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRISocketId ": Processing "
             "implicit ACK for stream %" PRIStreamId " lo_conn_seq %"
             PRIPktSeqNumber  "\n", socket_id_, stream_id,
             largest_observed_conn_seq_num_);
#endif

        stream->ProcessImplicitAck(now, largest_observed_conn_seq_num_);
      }
    }
  }
}

//============================================================================
void Connection::ProcessRcvdPktCntInfo(RcvdPktCntHeader& hdr,
                                       const Time& rcv_time)
{
  // Ignore duplicates.  If the received data packet count is not greater than
  // the last one received, then this must be a duplicate.
  if ((!stats_snd_per_update_time_.IsZero()) &&
      (CNT_LEQ(hdr.rcvd_data_pkt_count, stats_last_rpc_)))
  {
    return;
  }

  stats_last_rpc_ = hdr.rcvd_data_pkt_count;

  // Find the stream.
  Stream*  stream = GetStream(hdr.stream_id);

  if (stream == NULL)
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Warning, no stream ID "
         "%" PRIStreamId ".\n", socket_id_, hdr.stream_id);
    return;
  }

  // Look up the sent packet count for the referenced data packet that we sent
  // earlier.
  PktCount  sent_pkt_cnt = 0;

  if (!stream->GetSentPktCnt(hdr.sequence_number, hdr.retransmission_count,
                             sent_pkt_cnt))
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Warning, no stream ID "
         "%" PRIStreamId " packet for seq %" PRIPktSeqNumber " rexmit_cnt %"
         PRIRetransCount ".\n", socket_id_, hdr.stream_id,
         hdr.sequence_number, hdr.retransmission_count);
    return;
  }

  // On the first received packet count header received, initialize the PER
  // state.
  if (stats_snd_per_update_time_.IsZero())
  {
    stats_snd_start_pkts_sent_ = sent_pkt_cnt;
    stats_snd_start_pkts_rcvd_ = hdr.rcvd_data_pkt_count;
    stats_snd_per_update_time_ = (rcv_time + Time::FromMsec(kPerMinTimeMsec));

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Init PER state, sent %"
         PRIPktCount " rcvd %" PRIPktCount ".\n", socket_id_,
         stats_snd_start_pkts_sent_, stats_snd_start_pkts_rcvd_);
#endif

    return;
  }

  // Compute the number of data packet receptions in this update interval thus
  // far.
  PktCount  delta_rcvd = (hdr.rcvd_data_pkt_count -
                          stats_snd_start_pkts_rcvd_);

  // Update the PER if it is the end of the current udpate interval.
  if ((delta_rcvd >= kPerMinDataPktXmits) &&
      (rcv_time >= stats_snd_per_update_time_))
  {
    PktCount  delta_sent = (sent_pkt_cnt - stats_snd_start_pkts_sent_);

    if (delta_sent >= delta_rcvd)
    {
      stats_local_per_ = (static_cast<double>(delta_sent - delta_rcvd) /
                          static_cast<double>(delta_sent));

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Updated PER %f\n",
           socket_id_, stats_local_per_);
#endif
    }
    else
    {
      LogW(kClassName, __func__, "Conn %" PRISocketId ": Warning, ignoring "
           "PER update with sent %" PRIPktCount " rcvd %" PRIPktCount ".\n",
           socket_id_, delta_sent, delta_rcvd);
    }

    // Reset the PER state for the next update interval.
    stats_snd_start_pkts_sent_ = sent_pkt_cnt;
    stats_snd_start_pkts_rcvd_ = hdr.rcvd_data_pkt_count;
    stats_snd_per_update_time_ = (rcv_time + Time::FromMsec(kPerMinTimeMsec));

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Start of PER "
         "interval, sent %" PRIPktCount " rcvd %" PRIPktCount ".\n",
         socket_id_, stats_snd_start_pkts_sent_, stats_snd_start_pkts_rcvd_);
#endif
  }
}

//============================================================================
void Connection::ForceAck(const Time& now, CcId cc_id, StreamId stream_id)
{
  // Clear the number of data packets received since the last ACK was sent.
  pkts_since_last_ack_ = 0;

  // Cancel any ACK timer.
  timer_.CancelTimer(ack_timer_);

  // Send an ACK packet.
  SendAck(now, cc_id, stream_id);
}

//============================================================================
void Connection::MaybeAck(const Time& now, CcId cc_id, StreamId stream_id)
{
  // This is only called when a data packet is received.

  // Increment the counter of the number of data packets received since the
  // last ACK packet was sent.
  pkts_since_last_ack_++;

  // If enough data packets have been received since the last ACK packet was
  // sent, then send the ACK packet immediately.  Otherwise, use the ACK
  // timer.
  if (pkts_since_last_ack_ >= kAckAfterDataPktCnt)
  {
    // Reset the packet counter.
    pkts_since_last_ack_ = 0;

    // Cancel any ACK timer.
    timer_.CancelTimer(ack_timer_);

    // Send an ACK packet.
    SendAck(now, cc_id, stream_id);
  }
  else
  {
    // Record that this stream has a delayed ACK waiting.
    stream_info_[stream_id].delayed_ack = true;

    if (!timer_.IsTimerSet(ack_timer_))
    {
      // Start an ACK timer.
      Time                              duration(0, kAckTimerUsec);
      CallbackOneArg<Connection, CcId>  callback(this,
                                                 &Connection::AckTimeout,
                                                 cc_id);

      if (!timer_.StartTimer(duration, &callback, ack_timer_))
      {
        LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting "
             "ACK timer.\n", socket_id_);
      }
    }
  }
}

//============================================================================
bool Connection::GetAcks(const Time& now, size_t rsvd_len, Packet*& pkt,
                         bool& cancel_ack_timer)
{
  // Cancel the ACK timer unless a stream is found that still needs it in the
  // loop below.
  cancel_ack_timer = true;

  // Get ACK packet information from each of the streams.
  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    StreamId  stream_id = prio_info_.stream_id[index];
    Stream*   stream    = GetStream(stream_id);

    // Only include the stream in the ACK information if it has missing data,
    // it has a delayed ACK waiting, or it has additional ACKs to send.
    if ((stream != NULL) &&
        ((stream->IsDataMissing()) ||
         (stream_info_[stream_id].delayed_ack) ||
         (stream_info_[stream_id].extra_acks > 0)))
    {
      // Add the ACK header for the stream if it will fit.
      size_t  ack_len = stream->PrepareNextAckHdr();
      size_t  tot_len = (((pkt != NULL) ? pkt->GetLengthInBytes() : 0) +
                         rsvd_len + ack_len);

      if (tot_len <= kMaxPacketSize)
      {
        // Get the ACK header for the stream.
        if (stream->BuildNextAckHdr(ack_hdr_, now))
        {
          // Double check the ACK header length.
          if (Framer::ComputeAckHeaderSize(ack_hdr_) != ack_len)
          {
            LogF(kClassName, __func__, "Conn %" PRISocketId ": ACK size "
                 "estimate %zu != ACK size %zu.\n", socket_id_, ack_len,
                 Framer::ComputeAckHeaderSize(ack_hdr_));
          }

          // Get the timestamp and timestamp delta values for the ACK header.
          ack_hdr_.timestamp       = GetCurrentLocalTimestamp();
          ack_hdr_.timestamp_delta = ts_delta_;

          if (!framer_.AppendAckHeader(pkt, ack_hdr_))
          {
            LogE(kClassName, __func__, "Conn %" PRISocketId ": Error adding "
                 "ACK header for stream %" PRIStreamId ".\n", socket_id_,
                 stream_id);
            if (pkt != NULL)
            {
              TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
              packet_pool_.Recycle(pkt);
              pkt = NULL;
            }
            return false;
          }

          // Clear the delayed ACK flag for the stream.
          stream_info_[stream_id].delayed_ack = false;

          // Update the extra ACK count.
          if (stream_info_[stream_id].extra_acks > 0)
          {
            stream_info_[stream_id].extra_acks -= 1;
          }

#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRISocketId ": Add "
               "opportunistic ACK: stream %" PRIStreamId " num_times %" PRIu8
               " num_blocks %" PRIu8 " next_seq %" PRIPktSeqNumber " ts %"
               PRIPktTimestamp " ts_delta %" PRIPktTimestamp "\n", socket_id_,
               ack_hdr_.stream_id, ack_hdr_.num_observed_times,
               ack_hdr_.num_ack_block_offsets, ack_hdr_.next_expected_seq_num,
               ack_hdr_.timestamp, ack_hdr_.timestamp_delta);

          for (uint8_t i = 0; i < ack_hdr_.num_observed_times; ++i)
          {
            LogD(kClassName, __func__, "  Observed time %" PRIu8 ": seq %"
                 PRIPktSeqNumber " ts %" PRIPktTimestamp "\n", i,
                 ack_hdr_.observed_time[i].seq_num,
                 ack_hdr_.observed_time[i].timestamp);
          }

          for (uint8_t j = 0; j < ack_hdr_.num_ack_block_offsets; ++j)
          {
            LogD(kClassName, __func__, "  ACK block %" PRIu8 ": type %d "
                 "offset %" PRIu16 " (seq %" PRIPktSeqNumber ")\n", j,
                 ack_hdr_.ack_block_offset[j].type,
                 ack_hdr_.ack_block_offset[j].offset,
                 (ack_hdr_.next_expected_seq_num +
                  static_cast<PktSeqNumber>(
                    ack_hdr_.ack_block_offset[j].offset)));
          }
#endif
        }
        else
        {
          LogE(kClassName, __func__, "Conn %" PRISocketId ": Error getting "
               "ACK header for stream %" PRIStreamId ".\n", socket_id_,
               stream_id);
          continue;
        }
      }

      // If the stream still has a delayed ACK waiting or at least one extra
      // ACK waiting, then do not cancel the ACK timer.
      if ((stream_info_[stream_id].delayed_ack) ||
          (stream_info_[stream_id].extra_acks > 0))
      {
        cancel_ack_timer = false;
      }
    }
  }

  return true;
}

//============================================================================
void Connection::SendAck(const Time& now, CcId cc_id,
                         StreamId trigger_stream_id)
{
  Packet*  pkt             = NULL;
  bool     start_ack_timer = false;
  bool     fast_ack_timer  = false;

  // Send an ACK packet, possibly including other SLIQ headers, in the
  // following order:
  //
  //   1. ACK Header(s) (required)
  //   2. Received Packet Count Header (opportunistic as space allows)

  // Get ACK packet information from each of the streams.
  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    StreamId  stream_id = prio_info_.stream_id[index];
    Stream*   stream    = GetStream(stream_id);

    // Only include the stream in the ACK packet if it directly caused the
    // ACK, it has missing data, it has a delayed ACK waiting, or it has
    // additional ACKs to send.
    if ((stream != NULL) &&
        ((stream_id == trigger_stream_id) ||
         (stream->IsDataMissing()) ||
         (stream_info_[stream_id].delayed_ack) ||
         (stream_info_[stream_id].extra_acks > 0)))
    {
      // Get the ACK packet information for the stream.
      size_t  ack_len = stream->PrepareNextAckHdr();

      if (stream->BuildNextAckHdr(ack_hdr_, now))
      {
        // Get the timestamp and timestamp delta values for the ACK header.
        ack_hdr_.timestamp       = GetCurrentLocalTimestamp();
        ack_hdr_.timestamp_delta = ts_delta_;

        // Clear the delayed ACK flag for the stream.
        stream_info_[stream_id].delayed_ack = false;

        // Update the extra ACK count.
        if (stream_info_[stream_id].extra_acks > 0)
        {
          stream_info_[stream_id].extra_acks -= 1;
        }

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRISocketId ": Building ACK "
             "packet: stream %" PRIStreamId " num_times %" PRIu8
             " num_blocks %" PRIu8 " next_seq %" PRIPktSeqNumber " ts %"
             PRIPktTimestamp " ts_delta %" PRIPktTimestamp "\n", socket_id_,
             ack_hdr_.stream_id, ack_hdr_.num_observed_times,
             ack_hdr_.num_ack_block_offsets, ack_hdr_.next_expected_seq_num,
             ack_hdr_.timestamp, ack_hdr_.timestamp_delta);

        for (uint8_t i = 0; i < ack_hdr_.num_observed_times; ++i)
        {
          LogD(kClassName, __func__, "  Observed time %" PRIu8 ": seq %"
               PRIPktSeqNumber " ts %" PRIPktTimestamp "\n", i,
               ack_hdr_.observed_time[i].seq_num,
               ack_hdr_.observed_time[i].timestamp);
        }

        for (uint8_t j = 0; j < ack_hdr_.num_ack_block_offsets; ++j)
        {
          LogD(kClassName, __func__, "  ACK block %" PRIu8 ": type %d offset "
               "%" PRIu16 " (seq %" PRIPktSeqNumber ")\n", j,
               ack_hdr_.ack_block_offset[j].type,
               ack_hdr_.ack_block_offset[j].offset,
               (ack_hdr_.next_expected_seq_num +
                static_cast<PktSeqNumber>(
                  ack_hdr_.ack_block_offset[j].offset)));
        }
#endif

        // Add the ACK packet information to an ACK packet.
        if (pkt != NULL)
        {
          if ((pkt->GetLengthInBytes() + ack_len) <= kMaxPacketSize)
          {
            // Append the stream's ACK packet information to the existing ACK
            // packet.
            if (!framer_.AppendAckHeader(pkt, ack_hdr_))
            {
              LogE(kClassName, __func__, "Conn %" PRISocketId ": Error "
                   "appending to ACK packet for stream %" PRIStreamId ".\n",
                   socket_id_, stream_id);
            }
          }
          else
          {
            // The current ACK packet is full.  Send it and start another ACK
            // packet.
            SendAckPkt(now, cc_id, pkt);
            packet_pool_.Recycle(pkt);
            pkt = NULL;
          }
        }

        if (pkt == NULL)
        {
          // Create a new ACK packet with the stream's ACK packet information.
          if (!framer_.AppendAckHeader(pkt, ack_hdr_))
          {
            LogE(kClassName, __func__, "Conn %" PRISocketId ": Error "
                 "creating ACK packet for stream %" PRIStreamId ".\n",
                 socket_id_, stream_id);
          }
        }
      }

      // If the stream still has a delayed ACK waiting or at least one extra
      // ACK waiting, then the ACK timer will need to be started.
      if ((stream_info_[stream_id].delayed_ack) ||
          (stream_info_[stream_id].extra_acks > 0))
      {
        start_ack_timer = true;

        if (stream_info_[stream_id].extra_acks > 0)
        {
          fast_ack_timer = true;
        }
      }
    }
  }

  // Decide if a received packet count header can be opportunistically
  // included or not.
  if (stats_rcv_rpc_trigger_cnt_ >= kRcvdPktCntIntPkts)
  {
    AddRcvdPktCnt(0, pkt);
  }

  // Send the ACK packet.
  if (pkt != NULL)
  {
    SendAckPkt(now, cc_id, pkt);
    packet_pool_.Recycle(pkt);
    pkt = NULL;
  }

  // The ACK timer is always canceled before entering this method.  Start the
  // next ACK timer if needed.
  if (start_ack_timer)
  {
    Time                              duration(0, kAckTimerUsec);
    CallbackOneArg<Connection, CcId>  callback(this,
                                               &Connection::AckTimeout,
                                               cc_id);

    // If a fast ACK timer is needed for additional ACKs, then use the
    // expected data packet inter-receive time as the ACK timer duration.
    if (fast_ack_timer)
    {
      double  dur_sec = (data_pkt_irt_sec_ * 1.5);
      double  dur_min = (kMinAckTimerMsec * 0.001);

      if (dur_sec < dur_min)
      {
        dur_sec = dur_min;
      }

      duration = Time(dur_sec);
    }

    if (!timer_.StartTimer(duration, &callback, ack_timer_))
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting "
           "ACK timer.\n", socket_id_);
    }
  }
}

//============================================================================
void Connection::AddRcvdPktCnt(size_t rsvd_len, Packet*& pkt)
{
  // Check if a received packet count header will fit, and if so, add it.
  size_t  curr_len = (rsvd_len +
                      ((pkt != NULL) ? pkt->GetLengthInBytes() : 0));

  if ((curr_len + kRcvdPktCntHdrSize) <= kMaxPacketSize)
  {
    if (!framer_.AppendRcvdPktCntHeader(pkt, stats_rcv_rpc_hdr_))
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error appending "
           "received packet count header.\n", socket_id_);
      return;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Add opportunistic "
         "received packet count: stream %" PRIStreamId " rexmit_cnt %"
         PRIRetransCount " seq %" PRIPktSeqNumber " rcvd_pkt_cnt %"
         PRIPktCount "\n", socket_id_, stats_rcv_rpc_hdr_.stream_id,
         stats_rcv_rpc_hdr_.retransmission_count,
         stats_rcv_rpc_hdr_.sequence_number,
         stats_rcv_rpc_hdr_.rcvd_data_pkt_count);
#endif

    // Reset the trigger counter.
    stats_rcv_rpc_trigger_cnt_ = 0;
  }
}

//============================================================================
bool Connection::IsAllDataAcked()
{
  // Check each of the streams.  If any stream has data that is unACKed, then
  // return false.
  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    StreamId  stream_id = prio_info_.stream_id[index];
    Stream*   stream    = GetStream(stream_id);

    if ((stream != NULL) && (!stream->IsAllDataAcked()))
    {
      return false;
    }
  }

  return true;
}

//============================================================================
void Connection::ForceUnackedPacketsLost(const Time& now)
{
  // Update each of the streams.
  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    StreamId  stream_id = prio_info_.stream_id[index];
    Stream*   stream    = GetStream(stream_id);

    if (stream != NULL)
    {
      stream->ForceUnackedPacketsLost(now);
    }
  }
}

//============================================================================
bool Connection::IsPeerResponsive(const Time& now)
{
  // First, determine if the data packet send time is greater than the last
  // ACK or data packet receive time.
  if (data_pkt_send_time_ > ack_or_data_pkt_recv_time_)
  {
    // Compute a correction factor based on the current PER.  Assume that the
    // PER is in both directions.
    double  per      = ((stats_local_per_ < 0.9) ? stats_local_per_ : 0.9);
    double  per_corr = (1.0 / ((1.0 - per) * (1.0 - per)));

    // Compute how long it has been since the data packet was sent.
    Time  current_ack_wait = (now - data_pkt_send_time_);

    // Compute how long until an ACK packet is expected, being conservative.
    Time  expected_ack_wait = rtt_mgr_.GetRtoTime().Multiply(2.0 * per_corr);

    // If we have waited too long for the ACK packet, then the peer is
    // considered unresponsive.
    if (current_ack_wait > expected_ack_wait)
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRISocketId ": ACK should have "
           "arrived in %s, have waited %s, peer is unresponsive.\n",
           socket_id_, expected_ack_wait.ToString().c_str(),
           current_ack_wait.ToString().c_str());
#endif

      return false;
    }
  }

  return true;
}

//============================================================================
void Connection::EnterOutage(const Time& now, StreamId stream_id)
{
  if (is_in_outage_)
  {
    LogF(kClassName, __func__, "Conn %" PRISocketId ": Attempting to enter "
         "outage when already in one.\n", socket_id_);
    return;
  }

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Entering outage, "
       "detected by stream %" PRIStreamId ".\n", socket_id_, stream_id);

  // Mark the connection as being in an outage.
  is_in_outage_      = true;
  outage_stream_id_  = stream_id;
  outage_start_time_ = now;

  // Inform all of the capacity estimators that an outage has started.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    UpdateCapacityEstimate(now, i, 0, 0);
  }

  // Set the outage retransmission timer expiration time.
  SetOutageRexmitTime(now);
}

//============================================================================
void Connection::LeaveOutage(bool full_proc)
{
  if (!is_in_outage_)
  {
    LogF(kClassName, __func__, "Conn %" PRISocketId ": Attempting to leave "
         "outage when not already in one.\n", socket_id_);
    return;
  }

  LogA(kClassName, __func__, "Conn %" PRISocketId ": Leaving outage, "
       "originally detected by stream %" PRIStreamId ".\n", socket_id_,
       outage_stream_id_);

  // Reset the packet error rate (PER) statistics counts.
  stats_snd_per_update_time_.Zero();

  // Allow the streams to handle the end of the outage.  This might end up
  // dropping data packets, so do this before having congestion control end
  // the outage.
  Time  now             = Time::Now();
  Time  outage_duration = (now - outage_start_time_);

  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    Stream*  stream = GetStream(prio_info_.stream_id[index]);

    if (stream != NULL)
    {
      stream->LeaveOutage(outage_duration);
    }
  }

  // Update congestion control.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if (cc_alg != NULL)
    {
      cc_alg->OnOutageEnd();
    }
  }

  // Mark the connection as not being in an outage.
  is_in_outage_ = false;

  // Stop the current outage retransmission timer.
  rto_time_.Zero();

  // Reset the RTO timeout counter.
  rto_timeout_cnt_ = 0;

  // If requested, then allow each stream to retransmit one data packet.  This
  // should help get the ACK clocking restarted.  Set the RTO flag during
  // retransmissions.  This prevents setting timers that will just be canceled
  // and reset.
  if (full_proc)
  {
    is_in_rto_ = true;
    RexmitDataPkts();
    is_in_rto_ = false;
  }

  // If requested, then start the retransmission timer here.  Note that the
  // retransmission timer is not started if all stream data has been ACKed.
  if ((full_proc) && (!IsAllDataAcked()))
  {
    // Start over with the RTO as the duration.
    SetRexmitTime(now, rtt_mgr_.GetRtoTime());
  }
}

//============================================================================
void Connection::SetWriteBlocked(StreamId stream_id)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Socket is now "
       "blocked.\n", socket_id_);
#endif

  // The socket is now write blocked.
  is_write_blocked_ = true;
  socket_mgr_.UpdateEvents(socket_id_, kFdEventReadWrite);
  app_.ProcessFileDescriptorChange();

  // Mark the stream as blocked.
  if (StreamIdIsValid(stream_id))
  {
    stream_info_[stream_id].is_write_blocked = true;
  }
}

//============================================================================
bool Connection::ClearWriteBlocked(StreamId& reblocked_stream_id)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Socket is now "
       "unblocked.\n", socket_id_);
#endif

  // The socket is no longer write blocked.
  is_write_blocked_ = false;
  socket_mgr_.UpdateEvents(socket_id_, kFdEventRead);
  app_.ProcessFileDescriptorChange();

  // Find the stream that is blocked and complete the send that was
  // interrupted.
  for (size_t index = 0; index < prio_info_.num_streams; ++index)
  {
    StreamId  stream_id = prio_info_.stream_id[index];
    Stream*   stream    = GetStream(stream_id);

    if ((stream != NULL) && stream_info_[stream_id].is_write_blocked)
    {
      // This stream was blocked.  Allow it to send any blocked packets.
      if (stream->SendAnyBlockedPackets())
      {
        stream_info_[stream_id].is_write_blocked = false;
      }
      else
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRISocketId ": Sending of "
             "blocked packets on stream %" PRIStreamId " was blocked.\n",
             socket_id_, stream_id);
#endif

        reblocked_stream_id = stream_id;
        return false;
      }
    }
  }

  return true;
}

//============================================================================
void Connection::OnCanWrite()
{
  if (is_write_blocked_)
  {
    return;
  }

  // Note: The code in this method has been optimized using a profiler.  While
  // it is no longer very easy to read, it is much faster.  Do not make any
  // changes unless checking the before/after results with a profiler.

  // In the spirit of the NextSeg() scoreboard function found in RFC 6675,
  // section 4, all retransmissions (rule (1)) need to occur before any new
  // transmissions (rule (2)) across all streams.  Rules (3) (early
  // retransmit) and (4) (rescue retransmit) do not really apply to SLIQ since
  // SLIQ uses selective ACKs to provide certainty as to which packets must be
  // retransmitted and has a persist packet that can be sent as a last resort.
  // Since this connection contains one or more streams with different
  // priorities, all streams are first checked for retransmissions in
  // round-robin priority order (pass = 0), and then all streams are then
  // checked for new transmissions in round-robin priority order (pass = 1).
  bool  stop_flag = false;

  for (size_t pass = 0; ((pass < 2) && !stop_flag); ++pass)
  {
    size_t  band = 0;

    while (band < prio_info_.num_bands)
    {
      size_t     sends = 0;
      BandInfo*  bp    = &(prio_info_.band[band]);
      size_t     index = bp->next;

      for (size_t band_cnt = bp->size; band_cnt; --band_cnt)
      {
        Stream*  stream = stream_info_[prio_info_.stream_id[index]].stream;

        if (stream != NULL)
        {
          if (pass == 0)
          {
            // Check if this stream has fast retransmissions waiting to be
            // sent.
            if (stream->HasFastRexmit())
            {
              // Attempt to send one fast retransmission.  This method returns
              // false if congestion control or send pacing prevented the
              // retransmission.
              if (!stream->OnCanFastRexmit(sends))
              {
                stop_flag = true;
                break;
              }
            }
          }
          else
          {
            // Attempt to send one new data packet.  This method returns false
            // if congestion control prevented a packet from being sent.
            if (!stream->OnCanSend(sends))
            {
              stop_flag = true;
              break;
            }
          }
        }
        else
        {
          LogF(kClassName, __func__, "Conn %" PRISocketId ": Prioritized "
               "round-robin stream state error, stream ID %" PRIStreamId
               " is missing.\n", socket_id_, prio_info_.stream_id[index]);
        }

        // Move to the next stream in the band.
        ++index;

        if (index >= (bp->start + bp->size))
        {
          index = bp->start;
        }

        // If the socket becomes write blocked, then stop.
        if (is_write_blocked_)
        {
          stop_flag = true;
          break;
        }
      }

      // Record the stopping index for the band.
      bp->next = index;

      // Stop the band loop if needed.
      if (stop_flag)
      {
        break;
      }

      // Retry the same band if something was sent.  Otherwise, move on to the
      // next band.
      if (sends == 0)
      {
        ++band;
      }
    }
  }

  // If there is a congestion control synchronization packet still waiting to
  // be sent, then send it now.
  uint16_t  cc_sync_seq_num = 0;
  uint32_t  cc_sync_params  = 0;

  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if ((!is_write_blocked_) && (cc_alg != NULL) &&
        (cc_alg->GetSyncParams(cc_sync_seq_num, cc_sync_params)))
    {
      if (!SendCcSyncPkt(static_cast<CcId>(i), cc_sync_seq_num,
                         cc_sync_params))
      {
        LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending CC "
             "sync packet for cc_id %zu.\n", socket_id_, i);
      }
    }
  }

  // If there has been a received packet count header waiting to be added for
  // twice the normal amount of time, then send one now by itself.
  if (stats_rcv_rpc_trigger_cnt_ >= (kRcvdPktCntIntPkts * 2))
  {
    if (!SendRcvdPktCnt())
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error sending "
           "received packet count header.\n", socket_id_);
    }
  }

  // Make sure that a send timer is active for each congestion control
  // algorithm that returns a non-zero time from TimeUntilSend().
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CcAlg&              cc_info = cc_algs_.cc_alg[i];
    CongCtrlInterface*  cc_alg  = cc_info.cc_alg;

    if (cc_alg == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRISocketId ": Congestion control "
           "object for cc_id %zu is NULL.\n", socket_id_, i);
      continue;
    }

    // If a send pacing timer is active for this congestion control algorithm,
    // then continue the search.
    if (timer_.IsTimerSet(cc_info.send_timer))
    {
      continue;
    }

    // Get the current time.
    Time  now = Time::Now();

    // Get the amount of delay before a send can occur for this congestion
    // control algorithm.
    Time  delay(cc_alg->TimeUntilSend(now));

    // The returned delay should never be infinite.
    if (delay.IsInfinite())
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Time until send is "
           "infinite for cc_id %zu.\n", socket_id_, i);
      timer_.CancelTimer(cc_info.send_timer);
      continue;
    }

    // If the congestion control algorithm requires a delay, then start a send
    // pacing timer.
    if (!delay.IsZero())
    {
      StartSendTimer(now, i, delay);
    }
  }
}

//============================================================================
int Connection::RexmitOneDataPkt(const Time& now)
{
  if (is_write_blocked_)
  {
    return 0;
  }

  // Allow a stream to retransmit one data packet, using priority order.
  for (size_t band = 0; band < prio_info_.num_bands; ++band)
  {
    BandInfo*  bp    = &(prio_info_.band[band]);
    size_t     index = bp->next;

    for (size_t band_cnt = bp->size; band_cnt; --band_cnt)
    {
      Stream*  stream = stream_info_[prio_info_.stream_id[index]].stream;

      if (stream != NULL)
      {
        // Attempt to send one retransmission of the lowest unACKed packet
        // with checks disabled.
        if (stream->RexmitPkt(now, true, true))
        {
          return 1;
        }
      }
      else
      {
        LogF(kClassName, __func__, "Conn %" PRISocketId ": Prioritized "
             "round-robin stream state error, stream ID %" PRIStreamId
             " is missing.\n", socket_id_, prio_info_.stream_id[index]);
      }

      // Move to the next stream in the band.
      ++index;

      if (index >= (bp->start + bp->size))
      {
        index = bp->start;
      }
    }
  }

  // No retransmission occurred.  Send a persist packet on the first,
  // highest-priority stream.
  Stream*  stream = stream_info_[prio_info_.stream_id[0]].stream;

  if (stream != NULL)
  {
    // Send one persist packet associated with the first congestion control
    // algorithm.
    if (stream->SendPersist(now, 0))
    {
      return 1;
    }
  }

  LogE(kClassName, __func__, "Conn %" PRISocketId ": Unable to resend packet "
       "on stream ID %" PRIStreamId ".\n", socket_id_,
       prio_info_.stream_id[0]);

  return 0;
}

//============================================================================
void Connection::RexmitDataPkts()
{
  if (is_write_blocked_)
  {
    return;
  }

  // Allow each stream to either retransmit one data packet or send a persist
  // packet.
  for (size_t band = 0; band < prio_info_.num_bands; ++band)
  {
    BandInfo*  bp    = &(prio_info_.band[band]);
    size_t     index = bp->next;

    for (size_t band_cnt = bp->size; band_cnt; --band_cnt)
    {
      Stream*  stream = stream_info_[prio_info_.stream_id[index]].stream;

      if (stream != NULL)
      {
        // Get the current time.
        Time  now = Time::Now();

        // Attempt to send one retransmission of the highest unACKed packet
        // with checks disabled.
        if (!stream->RexmitPkt(now, false, true))
        {
          // Send a persist packet instead.  Associate it with the first
          // congestion control algorithm.
          if (!stream->SendPersist(now, 0))
          {
            LogE(kClassName, __func__, "Conn %" PRISocketId ": Unable to "
                 "resend packet on stream ID %" PRIStreamId ".\n", socket_id_,
                 prio_info_.stream_id[index]);
          }
        }
      }
      else
      {
        LogF(kClassName, __func__, "Conn %" PRISocketId ": Prioritized "
             "round-robin stream state error, stream ID %" PRIStreamId
             " is missing.\n", socket_id_, prio_info_.stream_id[index]);
      }

      // Move to the next stream in the band.
      ++index;

      if (index >= (bp->start + bp->size))
      {
        index = bp->start;
      }
    }
  }
}

//============================================================================
void Connection::ClientHelloTimeout()
{
  // Check if the connection has been established.  If so, then there is
  // nothing more to do in this timer callback.
  if (state_ != SENT_CHLO)
  {
    return;
  }

  // Limit the number of client hellos that can be sent.
  if (num_hellos_ >= kMaxClientHellos)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Too many client "
         "hellos sent, closing connection.\n", socket_id_);
#endif
  }
  else
  {
    // Perform another wait.
    if (StartClientHelloTimer())
    {
      // Send another client hello message to the server.
      if (SendConnHndshkPkt(kClientHelloTag, 0))
      {
        // Record the transmission.
        num_hellos_++;

        return;
      }

      timer_.CancelTimer(hello_timer_);
    }
    else
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting "
           "client hello timer.\n", socket_id_);
    }
  }

  // There was a problem.  Schedule the connection for deletion.
  state_ = CLOSED;
  app_.ProcessConnectionResult(socket_id_, false);
  conn_mgr_.DeleteConnection(socket_id_);
}

//============================================================================
void Connection::ServerHelloTimeout()
{
  // Check if the connection has been established.  If so, then there is
  // nothing more to do in this timer callback.
  if (state_ != SENT_SHLO)
  {
    return;
  }

  // Limit the number of server hellos that can be sent.
  if (num_hellos_ >= kMaxServerHellos)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Too many server "
         "hellos sent, closing connection.\n", socket_id_);
#endif
  }
  else
  {
    // Perform another wait.
    if (StartServerHelloTimer())
    {
      // Send another server hello message to the server.
      PktTimestamp  echo_ts = 0;

      if (client_hello_timestamp_ != 0)
      {
        Time  delta = (Time::Now() - client_hello_recv_time_);

        echo_ts = (client_hello_timestamp_ +
                   static_cast<PktTimestamp>(delta.GetTimeInUsec()));
      }

      if (SendConnHndshkPkt(kServerHelloTag, echo_ts))
      {
        // Record the transmission.
        num_hellos_++;

        return;
      }

      timer_.CancelTimer(hello_timer_);
    }
    else
    {
      LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting "
           "server hello timer.\n", socket_id_);
    }
  }

  // There was a problem.  Schedule the connection for deletion.
  state_ = CLOSED;
  app_.ProcessConnectionResult(socket_id_, false);
  conn_mgr_.DeleteConnection(socket_id_);
}

//============================================================================
void Connection::SendTimeout(CcId cc_id)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Send timeout for cc_id %"
       PRICcId ".\n", socket_id_, cc_id);
#endif

  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) ||
      (!initialized_) ||
      ((state_ != CONNECTED) && (state_ != APP_CLOSE_WAIT) &&
       (state_ != CONN_CLOSE_WAIT)))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Stopping send "
         "timeouts for cc_id %" PRICcId ", type %d initialized %d state %d\n",
         socket_id_, cc_id, (int)type_, (int)initialized_, (int)state_);
#endif
    return;
  }

  // If the socket is not write blocked, then attempt to send packets.
  if (!is_write_blocked_)
  {
    // Send as many packets as possible.  This will handle resetting the send
    // timer if needed.
    OnCanWrite();

    // Do any pending reentrant callbacks.
    DoReentrantCallbacks();
  }
}

//============================================================================
void Connection::AckTimeout(CcId cc_id)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": ACK timeout with cc_id %"
       PRICcId ".\n", socket_id_, cc_id);
#endif

  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) ||
      (!initialized_) ||
      ((state_ != CONNECTED) && (state_ != CONN_CLOSE_WAIT)))
  {
    return;
  }

  // Get the current time.
  Time  now = Time::Now();

  // Reset the packet counter.
  pkts_since_last_ack_ = 0;

  // Send an ACK packet.
  SendAck(now, cc_id, 0);

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();
}

//============================================================================
void Connection::CloseConnTimeout()
{
  // Check if a close connection packet should be retransmitted.
  if ((state_ == CONN_CLOSE_WAIT) || (state_ == CLOSED))
  {
    // Limit the number of close connection packets that can be sent.
    if (num_closes_ >= kMaxCloseConns)
    {
      LogW(kClassName, __func__, "Conn %" PRISocketId ": Too many close "
           "connection packets sent.\n", socket_id_);
    }
    else
    {
      // Perform another wait.
      if (StartCloseConnTimer())
      {
        // Send another close connection message to the server.
        if (SendCloseConnPkt(false, close_reason_))
        {
          // Record the transmission.
          num_closes_ += 1;
        }
        else
        {
          timer_.CancelTimer(close_timer_);
        }
      }
      else
      {
        LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting "
             "close connection timer.\n", socket_id_);
      }
    }
  }
}

//============================================================================
void Connection::RtoCallback()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": RTO timeout, handle %"
       PRIu64 ".\n", socket_id_, rto_timer_.id());
#endif

  // Get the current time.
  Time  now = Time::Now();

  // Check if the connection-level retransmission timer has expired.
  if ((!rto_time_.IsZero()) && (now >= rto_time_))
  {
    RexmitTimeout(now);
  }
  else if (!is_in_outage_)
  {
    // There is no connection-level RTO event, and the connection is not in an
    // outage.  Allow the streams to perform any single retransmissions that
    // are needed based on their own stream-level RTO periods.
    for (size_t index = 0; index < prio_info_.num_streams; ++index)
    {
      StreamId  stream_id = prio_info_.stream_id[index];
      Stream*   stream    = GetStream(stream_id);

      if (stream != NULL)
      {
        stream->RtoCheck(now);
      }
    }
  }

  // Start the RTO timer again.
  StartRtoTimer();
}

//============================================================================
void Connection::RexmitTimeout(const Time& now)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Rexmit timeout.\n",
       socket_id_);
#endif

  // Clear the retransmission timer expiration time.
  rto_time_.Zero();

  if (((type_ != CLIENT_DATA) && (type_ != SERVER_DATA)) ||
      (!initialized_) ||
      ((state_ != CONNECTED) && (state_ != APP_CLOSE_WAIT)))
  {
    return;
  }

  // If currently in an outage, then allow the stream that detected the outage
  // to send a persist packet associated with the first congestion control
  // algorithm.
  if (is_in_outage_)
  {
    Stream*  outage_stream = GetStream(outage_stream_id_);

    if (outage_stream != NULL)
    {
      outage_stream->SendPersist(now, 0);
    }
    else
    {
      LogF(kClassName, __func__, "Conn %" PRISocketId ": Missing outage "
           "stream ID %" PRIStreamId ".\n", socket_id_, outage_stream_id_);
    }

    // Set the next outage retransmission timer expiration time.
    SetOutageRexmitTime(now);

    // Do any pending reentrant callbacks.
    DoReentrantCallbacks();

    return;
  }

  // Detect if the connection is in an outage.  Start by determining if the
  // peer is being responsive.
  if (!IsPeerResponsive(now))
  {
    // The peer is not being responsive.  Check each of the streams to see if
    // an outage has been detected or not.
    for (size_t index = 0; index < prio_info_.num_streams; ++index)
    {
      StreamId  stream_id = prio_info_.stream_id[index];
      Stream*   stream    = GetStream(stream_id);

      if ((stream != NULL) && (stream->IsInOutage()))
      {
        // This stream has detected an outage.  Enter outage mode.
        EnterOutage(now, stream_id);
        return;
      }
    }
  }

  // Increment the RTO timeout count.
  ++rto_timeout_cnt_;

  // Allow a stream to retransmit one data packet.  Set the RTO flag during
  // retransmissions.  This prevents setting timers that will just be canceled
  // and set again.
  is_in_rto_ = true;
  int  num_sent = RexmitOneDataPkt(now);
  is_in_rto_ = false;

  // Update congestion control.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if (cc_alg != NULL)
    {
      cc_alg->OnRto((num_sent > 0));
    }
  }

  // Do any pending reentrant callbacks.
  DoReentrantCallbacks();

  // Set the next retransmission timer expiration time with double the
  // previous duration.
  SetRexmitTime(now, rto_duration_.Multiply(2));
}

//============================================================================
bool Connection::StartClientHelloTimer()
{
  // First, check if the client hello timer is currently set.
  if (timer_.IsTimerSet(hello_timer_))
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Canceling existing "
         "hello timer handle %" PRIu64 ".\n", socket_id_, hello_timer_.id());

    timer_.CancelTimer(hello_timer_);
  }

  // Set a timer for how long to wait for a response from the server.
  Time                       duration(kConnEstabTimerSec);
  CallbackNoArg<Connection>  callback(this, &Connection::ClientHelloTimeout);

  if (!timer_.StartTimer(duration,  &callback, hello_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting client "
         "hello timer.\n", socket_id_);
    return false;
  }

  return true;
}

//============================================================================
bool Connection::StartServerHelloTimer()
{
  // First, check if the server hello timer is currently set.
  if (timer_.IsTimerSet(hello_timer_))
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Canceling existing "
         "hello timer handle %" PRIu64 ".\n", socket_id_, hello_timer_.id());

    timer_.CancelTimer(hello_timer_);
  }

  // Set a timer for how long to wait for a response from the client.
  Time                       duration(kConnEstabTimerSec);
  CallbackNoArg<Connection>  callback(this, &Connection::ServerHelloTimeout);

  if (!timer_.StartTimer(duration, &callback, hello_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting client "
         "hello timer.\n", socket_id_);
    return false;
  }

  return true;
}

//============================================================================
void Connection::StartSendTimer(const Time& now, CcId cc_id,
                                const Time& duration)
{
  // First, check if the send timer is currently set.  We might not need to
  // restart it.
  if (timer_.IsTimerSet(cc_algs_.cc_alg[cc_id].send_timer))
  {
    // Check if the new expiration time matches the current expiration time
    // within the timer tolerance.  If it does, then just return.
    Time  new_send_time = (now + duration);

    if (cc_algs_.cc_alg[cc_id].next_send_time >= new_send_time)
    {
      if ((cc_algs_.cc_alg[cc_id].next_send_time - new_send_time) <=
          timer_tolerance_)
      {
        return;
      }
    }
    else
    {
      if ((new_send_time - cc_algs_.cc_alg[cc_id].next_send_time) <=
          timer_tolerance_)
      {
        return;
      }
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Scheduling next send "
         "for cc_id %" PRICcId ", cancel send timer handle %" PRIu64 ".\n",
         socket_id_, cc_id, cc_algs_.cc_alg[cc_id].send_timer.id());
#endif

    timer_.CancelTimer(cc_algs_.cc_alg[cc_id].send_timer);
  }

  // Start the new send timer.
  CallbackOneArg<Connection, CcId>  callback(this, &Connection::SendTimeout,
                                             cc_id);

  if (!timer_.StartTimer(duration, &callback,
                         cc_algs_.cc_alg[cc_id].send_timer))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting send "
         "timer for cc_id %" PRICcId ".\n", socket_id_, cc_id);
  }
  else
  {
    cc_algs_.cc_alg[cc_id].next_send_time = (now + duration);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Started send timer "
         "for cc_id %" PRICcId " with duration %s handle %" PRIu64 ".\n",
         socket_id_, cc_id, duration.ToString().c_str(),
         cc_algs_.cc_alg[cc_id].send_timer.id());
#endif
  }
}

//============================================================================
bool Connection::StartRtoTimer()
{
  if (timer_.IsTimerSet(rto_timer_))
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Canceling existing "
         "RTO timer handle %" PRIu64 ".\n", socket_id_, rto_timer_.id());

    timer_.CancelTimer(rto_timer_);
  }

  // Determine the RTO timer duration to use.
  Time                       duration = Time::FromMsec(kRtoTimerMsec);
  CallbackNoArg<Connection>  callback(this, &Connection::RtoCallback);

  // If any of the congestion control algorithms require fast RTOs, then have
  // the RTO timer use a much shorter period.
  if (SetFastRto())
  {
    duration = Time::Max(rtt_mgr_.smoothed_rtt().Multiply(0.5),
                         Time::FromMsec(kMinFastRtoTimerMsec));
  }

  // Start the new RTO timer.
  if (!timer_.StartTimer(duration, &callback, rto_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting RTO "
         "timer.\n", socket_id_);
    return false;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Started RTO timer with "
       "duration %s handle %" PRIu64 ".\n", socket_id_,
       duration.ToString().c_str(), rto_timer_.id());
#endif

  return true;
}

//============================================================================
void Connection::SetRexmitTime(const Time& now, const Time& duration)
{
  // Limit the retransmission timer duration.
  Time  new_duration = Time::Min(Time::FromSec(kMaxRexmitWaitTimeSec),
                                 duration);

  // If any of the congestion control algorithms require fast RTOs, then use
  // the current retransmission time as the duration.
  if (SetFastRto())
  {
    new_duration = Time::Max(rtt_mgr_.GetRexmitTime(5),
                             Time::FromMsec(kMinFastRtoTimerMsec));
  }

  // Store the duration.
  rto_duration_ = new_duration;

  // Set the retransmission timer expiration time.
  rto_time_ = (now + new_duration);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Set rexmit duration "
       "%s.\n", socket_id_, new_duration.ToString().c_str());
#endif
}

//============================================================================
void Connection::SetOutageRexmitTime(const Time& now)
{
  // Set the outage retransmission timer using the RTO as the duration.  Do
  // not overwrite rto_duration_, as we will use it restore the retransmission
  // timer when exiting outage mode.
  Time  duration = rtt_mgr_.GetRtoTime();

  // Set the outage retransmission timer expiration time.
  rto_time_ = (now + duration);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRISocketId ": Set outage rexmit "
       "duration %s.\n", socket_id_, duration.ToString().c_str());
#endif
}

//============================================================================
bool Connection::SetFastRto()
{
  // If currently in an outage, then do not use any fast RTOs.
  if (is_in_outage_)
  {
    return false;
  }

  // Check if any of the congestion control algorithms currently require fast
  // RTOs.
  //
  // These are needed when a congestion control algorithm that has a
  // congestion window and is designed to operate with non-congestion packet
  // losses (e.g. Copa2 or Copa3) has a small congestion window size, which
  // can lead to send blockages when not enough ACK packets are being received
  // to send the necessary retransmissions.  The only way out of these send
  // blockages is using the RTO timer, and making these occur quicker helps
  // speed recovery.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if ((cc_alg != NULL) && (cc_alg->RequireFastRto()))
    {
      return true;
    }
  }

  return false;
}

//============================================================================
bool Connection::StartCloseConnTimer()
{
  // First, check if the close connection timer is currently set.
  if (timer_.IsTimerSet(close_timer_))
  {
    LogW(kClassName, __func__, "Conn %" PRISocketId ": Canceling existing "
         "close connection timer handle %" PRIu64 ".\n", socket_id_,
         close_timer_.id());

    timer_.CancelTimer(close_timer_);
  }

  Time                       duration(kCloseConnTimerSec);
  CallbackNoArg<Connection>  callback(this, &Connection::CloseConnTimeout);

  if (!timer_.StartTimer(duration, &callback, close_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Error starting close "
         "connection timer.\n", socket_id_);
    return false;
  }

  return true;
}

//============================================================================
void Connection::CancelAllTimers()
{
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    timer_.CancelTimer(cc_algs_.cc_alg[i].send_timer);
  }

  timer_.CancelTimer(hello_timer_);
  timer_.CancelTimer(ack_timer_);
  timer_.CancelTimer(close_timer_);
  timer_.CancelTimer(rto_timer_);
}

//============================================================================
void Connection::UpdateTimestampState(Time& recv_time, PktTimestamp send_ts,
                                      PktTimestamp send_ts_delta)
{
  // Update the differences in the two packet timestamp clocks.
  PktTimestamp  recv_ts =
    (static_cast<PktTimestamp>(recv_time.GetTimeInUsec()) + ts_corr_);

  ts_delta_     = (recv_ts - send_ts);
  rmt_ts_delta_ = send_ts_delta;

  // Valid timestamp delta values are never zero.
  if (ts_delta_ == 0)
  {
    ts_delta_ = 1;
  }

  // Update the one-way delay estimate based on the two timestamps and the
  // sender's timestamp delta value.
  //
  // For details, see the documentation for the OwdInfo structure in this
  // class's header file.
  if ((send_ts != 0) && (send_ts_delta != 0))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ": Input recv_ts=%"
         PRIPktTimestamp " send_ts=%" PRIPktTimestamp " send_ts_delta=%"
         PRIPktTimestamp "\n", socket_id_, recv_ts, send_ts, send_ts_delta);
#endif

    // Have from above:
    //   ts_delta_     = (recv_ts - send_ts);
    //   rmt_ts_delta_ = send_ts_delta;

    // Update the current sampling period.
    int64_t  local_delta  = static_cast<int32_t>(ts_delta_);
    int64_t  remote_delta = static_cast<int32_t>(rmt_ts_delta_);

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRISocketId ":       recv_ts_delta=%"
         PRIPktTimestamp " local_delta=%" PRId64 " remote_delta=%" PRId64
         "\n", socket_id_, ts_delta_, local_delta, remote_delta);
#endif

    if (owd_.next_delta_cnt_ == 0)
    {
      // Start of a new sampling period.
      owd_.next_delta_cnt_        = 1;
      owd_.next_min_local_delta_  = local_delta;
      owd_.next_min_remote_delta_ = remote_delta;

      // Compute the end time for this period.
      owd_.next_end_time_ = (Time::Now() + Time(kOwdPeriodSec));

      // If this is the first period, then set initial values for the
      // parameters used for adjusting the TTG values.
      if (!owd_.cur_ready_)
      {
        owd_.cur_ready_           = true;
        owd_.cur_min_rtt_         = Time::FromUsec(local_delta +
                                                   remote_delta);
        owd_.cur_min_local_delta_ = local_delta;
      }

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Sampling period "
           "start local_delta=%" PRId64 " remote_delta=%" PRId64
           " cur_min_rtt=%f cur_min_local_delta=%" PRId64 "\n", socket_id_,
           local_delta, remote_delta, 0, owd_.cur_min_rtt_.ToDouble(),
           owd_.cur_min_local_delta_);
#endif
    }
    else
    {
      // Update the minimum delta values observed.
      owd_.next_delta_cnt_++;

      if (local_delta < owd_.next_min_local_delta_)
      {
        owd_.next_min_local_delta_ = local_delta;
      }

      if (remote_delta < owd_.next_min_remote_delta_)
      {
        owd_.next_min_remote_delta_ = remote_delta;
      }

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRISocketId ": Sample local_delta=%"
           PRId64 " remote_delta=%" PRId64 " next_min_local_delta=%" PRId64
           " next_min_remote_delta=%" PRId64 "\n", socket_id_, local_delta,
           remote_delta, owd_.next_min_local_delta_,
           owd_.next_min_remote_delta_);
#endif

      // Check if it is the end of the current period.
      if ((owd_.next_delta_cnt_ >= kOwdPeriodMinSamples) &&
          (Time::Now() >= owd_.next_end_time_))
      {
        // The current period is over.  Update the parameters used for
        // adjusting the TTG values.
        int64_t min_rtt = (owd_.next_min_local_delta_ +
                           owd_.next_min_remote_delta_);

        if (min_rtt < 0)
        {
          min_rtt = -min_rtt;
        }

        owd_.cur_ready_           = true;
        owd_.cur_min_rtt_         = Time::FromUsec(min_rtt);
        owd_.cur_min_local_delta_ = owd_.next_min_local_delta_;

        // Reset to start another sampling period.
        owd_.next_delta_cnt_ = 0;

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRISocketId ": Sampling period "
             "end cur_min_rtt %f cur_min_local_delta %" PRId64 "\n",
             socket_id_, owd_.cur_min_rtt_.ToDouble(),
             owd_.cur_min_local_delta_);
#endif
      }
    }
  }
}

//============================================================================
void Connection::RecordNewStream(Stream* stream, StreamId stream_id,
                                 Priority prio)
{
  // Store the stream using the stream ID as the index.
  stream_info_[stream_id].stream           = stream;
  stream_info_[stream_id].priority         = prio;
  stream_info_[stream_id].extra_acks       = 0;
  stream_info_[stream_id].delayed_ack      = false;
  stream_info_[stream_id].is_write_blocked = false;

  // Regenerate the prioritized round-robin stream information.
  size_t  offset     = 0;
  size_t  band       = 0;
  size_t  band_size  = 0;

  for (Priority p = kHighestPriority; p <= kLowestPriority; ++p)
  {
    band_size = 0;

    for (size_t i = 0; i < kStreamArraySize; ++i)
    {
      if ((stream_info_[i].stream != NULL) && (stream_info_[i].priority == p))
      {
        prio_info_.stream_id[offset] = static_cast<StreamId>(i);
        offset++;
        band_size++;
      }
    }

    if (band_size > 0)
    {
      prio_info_.band[band].prio  = p;
      prio_info_.band[band].start = (offset - band_size);
      prio_info_.band[band].size  = band_size;
      prio_info_.band[band].next  = (offset - band_size);
      band++;
    }
  }

  prio_info_.num_streams = offset;
  prio_info_.num_bands   = band;
}

//============================================================================
Stream* Connection::GetStream(StreamId stream_id) const
{
  // Validate the stream ID.
  if ((stream_id < kMinStreamId) || (stream_id > kMaxStreamId) ||
      (stream_id >= kStreamArraySize))
  {
    LogE(kClassName, __func__, "Conn %" PRISocketId ": Invalid stream ID %"
         PRIStreamId ".\n", socket_id_, stream_id);
    return NULL;
  }

  // Return the stream pointer for the stream ID.
  return stream_info_[stream_id].stream;
}

//============================================================================
bool Connection::StreamIdIsValid(StreamId stream_id) const
{
  if ((stream_id < kMinStreamId) || (stream_id > kMaxStreamId) ||
      (stream_id >= kStreamArraySize))
  {
    return false;
  }

  return true;
}

//============================================================================
bool Connection::PriorityIsValid(Priority prio) const
{
  // This appears backward, but it is because the highest priority value has
  // the lowest numerical value.
  if ((prio < kHighestPriority) || (prio > kLowestPriority))
  {
    return false;
  }

  return true;
}

//============================================================================
bool Connection::ReliabilityIsValid(
  const Reliability& rel, DeliveryMode del_mode) const
{
  switch (rel.mode)
  {
    case BEST_EFFORT:
      return (del_mode == UNORDERED_DELIVERY);

    case SEMI_RELIABLE_ARQ:
      return ((del_mode == UNORDERED_DELIVERY) && (rel.rexmit_limit >= 1));

    case SEMI_RELIABLE_ARQ_FEC:
      return ((del_mode == UNORDERED_DELIVERY) &&
              (rel.fec_target_pkt_recv_prob > 0.0) &&
              (rel.fec_target_pkt_recv_prob <= kMaxTgtPktRcvProb) &&
              ((rel.fec_del_time_flag) ||
               ((rel.fec_target_pkt_del_rounds >= 1) &&
                (rel.fec_target_pkt_del_rounds <= (rel.rexmit_limit + 1)) &&
                (rel.fec_target_pkt_del_rounds <= kMaxTgtPktDelRnds))) &&
              ((!rel.fec_del_time_flag) ||
               ((rel.fec_target_pkt_del_time_sec >= 0.001) &&
                (rel.fec_target_pkt_del_time_sec <= 64.0))));

    case RELIABLE_ARQ:
      return true;

    default:
      break;
  }

  return false;
}

//============================================================================
bool Connection::CongCtrlSettingIsValid(CongCtrl& alg,
                                        bool allow_updates) const
{
  switch (alg.algorithm)
  {
    case NO_CC:
      // \todo If no congestion control is to be supported, then a class must
      // be created to provide the necessary interfaces.
      return false;

    case TCP_CUBIC_BYTES_CC:
      if (allow_updates)
      {
        alg.deterministic_copa = false;
        alg.copa_delta         = 0.0;
        alg.copa3_anti_jitter  = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: Cubic Bytes%s\n", socket_id_,
           (alg.cubic_reno_pacing ? " With Pacing" : ""));
      return true;

    case TCP_RENO_BYTES_CC:
      if (allow_updates)
      {
        alg.deterministic_copa = false;
        alg.copa_delta         = 0.0;
        alg.copa3_anti_jitter  = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: Reno Bytes%s\n", socket_id_,
           (alg.cubic_reno_pacing ? " With Pacing" : ""));
      return true;

    case TCP_CUBIC_CC:
      if (allow_updates)
      {
        alg.cubic_reno_pacing  = false;
        alg.deterministic_copa = false;
        alg.copa_delta         = 0.0;
        alg.copa3_anti_jitter  = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: Cubic\n", socket_id_);
      return true;

    case COPA_CONST_DELTA_CC:
      if ((alg.copa_delta < kMinCopaConstDelta) ||
          (alg.copa_delta > kMaxCopaConstDelta))
      {
        return false;
      }
      if (allow_updates)
      {
        alg.cubic_reno_pacing = false;
        alg.copa3_anti_jitter = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: %sCopa %0.3f\n", socket_id_,
           (alg.deterministic_copa ? "Deterministic " : ""), alg.copa_delta);
      return true;

    case COPA_M_CC:
      if (allow_updates)
      {
        alg.cubic_reno_pacing = false;
        alg.copa_delta        = 0.0;
        alg.copa3_anti_jitter = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: %sCopa M\n", socket_id_,
           (alg.deterministic_copa ? "Deterministic " : ""));
      return true;

    case COPA2_CC:
      if (allow_updates)
      {
        alg.cubic_reno_pacing  = false;
        alg.deterministic_copa = false;
        alg.copa_delta         = 0.0;
        alg.copa3_anti_jitter  = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: Copa2\n", socket_id_);
      return true;

    case COPA3_CC:
      if (allow_updates)
      {
        alg.cubic_reno_pacing  = false;
        alg.deterministic_copa = false;
        alg.copa_delta         = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: Copa3\n", socket_id_);
      return true;

    case FIXED_RATE_TEST_CC:
      // The connection handshake header only has a 32-bit field for
      // congestion control parameters.
      if ((alg.fixed_send_rate < 1) || (alg.fixed_send_rate > UINT32_MAX))
      {
        return false;
      }

      if (allow_updates)
      {
        alg.cubic_reno_pacing  = false;
        alg.deterministic_copa = false;
        alg.copa_delta         = 0.0;
        alg.copa3_anti_jitter  = 0.0;
      }

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using congestion "
           "control: Fixed Rate %" PRICapacity " bps\n", socket_id_,
           alg.fixed_send_rate);
      return true;

    case DEFAULT_CC:
      if (!allow_updates)
      {
        return false;
      }

      // Set the default congestion control to use.
      alg.algorithm          = COPA3_CC;
      alg.cubic_reno_pacing  = false;
      alg.deterministic_copa = false;
      alg.copa_delta         = 0.0;
      alg.copa3_anti_jitter  = 0.0;

      LogI(kClassName, __func__, "Conn %" PRISocketId ": Using default "
           "congestion control: Copa3\n", socket_id_);
      return true;

    default:
      break;
  }

  return false;
}

//============================================================================
const char* Connection::CongCtrlAlgToString(const CongCtrl& alg) const
{
  static char  tmp_str[64];

  switch (alg.algorithm)
  {
    case NO_CC:
      return "None";

    case TCP_CUBIC_BYTES_CC:
      if (alg.cubic_reno_pacing)
      {
        return "TCP CUBIC Bytes With Pacing";
      }
      return "TCP CUBIC Bytes";

    case TCP_RENO_BYTES_CC:
      if (alg.cubic_reno_pacing)
      {
        return "TCP Reno Bytes With Pacing";
      }
      return "TCP Reno Bytes";

    case TCP_CUBIC_CC:
      return "TCP CUBIC";

    case COPA_CONST_DELTA_CC:
      if (alg.deterministic_copa)
      {
        snprintf(tmp_str, sizeof(tmp_str), "Deterministic Copa %0.3f",
                 alg.copa_delta);
      }
      else
      {
        snprintf(tmp_str, sizeof(tmp_str), "Copa %0.3f", alg.copa_delta);
      }
      return tmp_str;

    case COPA_M_CC:
      if (alg.deterministic_copa)
      {
        return "Deterministic Copa M";
      }
      return "Copa M";

    case COPA2_CC:
      return "Copa2";

    case COPA3_CC:
      return "Copa3";

    case FIXED_RATE_TEST_CC:
      snprintf(tmp_str, sizeof(tmp_str), "Fixed Rate %" PRICapacity " bps",
               alg.fixed_send_rate);
      return tmp_str;

    case DEFAULT_CC:
      return "Default";

    default:
      break;
  }

  return "????";
}

//============================================================================
Connection::StreamInfo::StreamInfo()
    : stream(NULL), priority(kLowestPriority), extra_acks(0),
      delayed_ack(false), is_write_blocked(false)
{
}

//============================================================================
Connection::StreamInfo::~StreamInfo()
{
  if (stream != NULL)
  {
    delete stream;
    stream = NULL;
  }
}
