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

#ifndef IRON_BPF_SLIQ_CAT_H
#define IRON_BPF_SLIQ_CAT_H

/// \file sliq_cat.h
///
/// The Simple Lightweight IPv4 QUIC (SLIQ) Capacity Adaptive Tunnel (CAT)
/// header file.

#include "packet_pool.h"
#include "path_controller.h"

#include "sliq_app.h"

#include "ipv4_address.h"


namespace iron
{
  class BPFwder;
  class ConfigInfo;
  class Packet;
  class PacketPool;
  class Timer;

  /// \brief Simple Lightweight IPv4 QUIC (SLIQ) Capacity Adaptive Tunnel
  /// (CAT) implementation.
  ///
  /// Backpressure forwarders in IRON nodes use path controllers to
  /// communicate with each other.  This class is a path controller
  /// implementation that uses the SLIQ protocol for IRON node communications.
  /// Outgoing packets are transmitted through the SLIQ CATs and incoming
  /// packets are received from the SLIQ CATs and sent to the backpressure
  /// forwarder.  Each SLIQ CAT endpoint has a network capacity estimator
  /// which provides link capacity estimates to its backpressure forwarder.
  ///
  /// IRON packets are prioritized as follows:
  ///
  /// - QLAM packets have the highest priority.
  /// - Expedited forwarding (EF) IPv4 data packets (those with LatencyClass\n
  ///     set to LOW_LATENCY) have the next highest priority.
  /// - System-level control packets (LSA and K update packets) have\n
  ///     the next highest priority.
  /// - Other IPv4 data packets and flow-level control packets (RRM packets)\n
  ///     have the lowest priority.
  ///
  /// SLIQ CATs use the following prioritized streams for packets to be sent:
  ///
  /// - Uses stream ID 1 with priority 2 (highest priority) for QLAM packets.
  /// - Uses stream ID 3 with priority 3 for EF data packets.
  /// - Uses stream ID 5 with priority 4 for system-level control packets.
  /// - Uses stream ID 7 with priority 5 (lowest priority) for other data\n
  ///     and flow-level control packets.
  ///
  /// SLIQ CATs also use the following low priority stream for maintaining
  /// accurate capacity estimates:
  ///
  /// - Uses stream ID 9 with priority 7 (lowest priority) for sending dummy
  ///     data to get an accurate capacity estimate when needed.
  ///
  /// SLIQ CAT streams use the following transmit queue settings:
  ///
  /// - The QLAM packet transmit queue size is set to 1 packet with a head\n
  ///     drop rule (discarding any old QLAM packet for the new one).
  /// - The EF data packet transmit queue size is automatically computed\n
  ///     from the BPF transmit queue threshold with no drop rule.
  /// - The system-level control packet transmit queue size is 100 packets\n
  ///     with no drop rule.
  /// - The other data and flow-level control packet transmit queue size is\n
  ///     automatically computed from the BPF transmit queue threshold with\n
  ///     no drop rule.
  /// - The capacity estimate packet transmit queue size is 250 packets with\n
  ///     no drop rule.
  ///
  /// Following are the configurable parameters for a SLIQ CAT.  The format of
  /// the entries is PathController.x.configurable_parameter_name, where x
  /// is a number from 0 to (NumPathControllers - 1).  Note that
  /// NumPathControllers is a BPF configuration parameter.
  ///
  /// - PathController.x.Type
  /// - PathController.x.Label
  /// - PathController.x.Endpoints
  /// - PathController.x.EfDataRel
  /// - PathController.x.CongCtrl
  /// - PathController.x.Aggr
  /// - PathController.x.RttOutRej
  /// - PathController.x.AntiJitter
  /// - PathController.x.ActiveCapEst
  ///
  /// Each of these parameters are to be used as follows.
  ///
  /// - Type      : The path controller type.  Must be "SliqCat" for\n
  ///               creating a SLIQ CAT.
  /// - Label     : The optional SLIQ CAT label string.
  /// - Endpoints : The IPv4 addresses and optional port numbers for the\n
  ///               local and remote endpoints of the tunnel.\n
  ///               Must use the format\n
  ///               "LOCAL_IP[:LOCAL_PORT]->REMOTE_IP[:REMOTE_PORT]"\n
  ///               (for example "192.168.3.4->192.168.3.5" or\n
  ///               "1.2.3.4:5100->6.7.8.9:5100").  Note that the SLIQ CAT\n
  ///               automatically determines which end is the client and\n
  ///               which is the server (the higher IP address will be the\n
  ///               server).  The port numbers default to 30300.  Required.
  /// - EfDataRel : The optional reliability mode for expedited forwarding\n
  ///               data packets.  May be "ARQ" (semi-reliable ARQ), or\n
  ///               "ARQFEC(<l>,<p>)" (semi-reliable ARQ and FEC).  For\n
  ///               ARQFEC, "<p>" is the target packet delivery probability\n
  ///               for delivering the packets within the limit "<l>".  The\n
  ///               limit "<l>" may be a floating point time in seconds or\n
  ///               an integer number of rounds.  To determine which limit\n
  ///               type is being specified, a time must have an "s" at the\n
  ///               end (short for "seconds").  Note that "<p>" must be\n
  ///               specified as a floating point number between 0.95 and\n
  ///               0.999 (inclusive), while "<l>" must be either a time in\n
  ///               seconds between "0.001s" and "64.0s" (inclusive) or a\n
  ///               number of rounds between "1" and "7" (inclusive).\n
  ///               Defaults to "ARQ".
  /// - CongCtrl  : The optional congestion control algorithms to use,\n
  ///               separated by commas.  Only the client side sets the
  ///               congestion control algorithms for both ends of the
  ///               connection.  May be:\n
  ///               "Cubic" (TCP's CUBIC using Bytes with Pacing),\n
  ///               "Copa" (Copa),\n
  ///               "CopaBeta2" (Copa Beta 2),\n
  ///               "CopaBeta1M" (Copa Beta 1, Maximize Throughput),\n
  ///               "DetCopaBeta1M" (Deterministic Copa Beta 1, Maximize\n
  ///                 Throughput),\n
  ///               "CopaBeta1_<delta>" (Copa Beta 1, Constant Delta),\n
  ///               "DetCopaBeta1_<delta>" (Deterministic Copa Beta 1,\n
  ///                 Constant Delta), or\n
  ///               "FixedRate_<bps>" (Fixed Send Rate, For Testing Only).\n
  ///               Note that "<delta>" must be a floating-point number in\n
  ///               the range 0.004 to 1.0 inclusive.  Defaults to\n
  ///               "Cubic,Copa".
  /// - Aggr      : The optional congestion control algorithm aggressiveness\n
  ///               factor in number of TCP flows.  Must be an integer\n
  ///               >= 1.  Defaults to 1.
  /// - RttOutRej : The optional RTT outlier rejection setting.  When\n
  ///               enabled, all RTT samples are passed through a median\n
  ///               filter to eliminate those from the maximum RTT estimate.\n
  ///               Defaults to false (disabled).
  /// - AntiJitter : The optional Copa congestion control algorithm\n
  ///               anti-jitter value in seconds.  Must be between 0.0 and\n
  ///               1.0.  Defaults to 0.0 (disabled).
  /// - ActiveCapEst : The optional active capacity estimation setting.\n
  ///               When enabled, the SLIQ CAT will fill the channel with\n
  ///               dummy data periodically as needed to keep an accurate\n
  ///               channel capacity estimate.  Defaults to false (disabled).
  class SliqCat : public PathController, public sliq::SliqApp
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  bpf  Pointer to backpressure forwarder.
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  timer  Manager of all timers.
    SliqCat(BPFwder* bpf, PacketPool& packet_pool, Timer& timer);

    /// \brief Destructor.
    virtual ~SliqCat();

    /// \brief Initialize the Path Controller.
    ///
    /// \param  config_info  The configuration information.
    /// \param  config_id    The ID used to construct the parameter names to
    ///                      extract from the configuration information.  This
    ///                      becomes the path controller integer identifier
    ///                      returned by path_controller_number().
    ///
    /// \return  True if the initialization is successful, false otherwise.
    virtual bool Initialize(const ConfigInfo& config_info,
                            uint32_t config_id);

    /// \brief Configure the reporting of estimated packet delivery delay
    /// (PDD) values for low-latency (aka expedited forwarding, or EF)
    /// packets.
    ///
    /// \param  thresh      The amount of change, as a decimal, to trigger a
    ///                     PDD report.  A threshold of +/- 10% would be
    ///                     specified as 0.10.
    /// \param  min_period  The minimum time between PDD reports, in seconds.
    ///                     Reports are guaranteed not to occur with less than
    ///                     this period between them.
    /// \param  max_period  The maximum time between PDD reports, in seconds.
    ///                     Reports will occur with no more than this period
    ///                     (plus some small error) between them.
    ///
    /// \return  True if the configuration is successful, false otherwise.
    virtual bool ConfigurePddReporting(double thresh, double min_period,
                                       double max_period);

    /// \brief Send a packet.
    ///
    /// If the packet is enqueued or sent successfully, the Path Controller
    /// assumes ownership of the packet.  If the insertion fails, the caller
    /// keeps ownership of the packet.
    ///
    /// \param  pkt  Pointer to the packet to be sent.
    ///
    /// \return  True if the packet was enqueued or sent successfully, false
    ///          otherwise (i.e., if the transmit queue was at its capacity).
    virtual bool SendPacket(Packet* pkt);

    /// \brief Called when a file descriptor has an event that is of interest
    /// to the Path Controller.
    ///
    /// \param  fd     The file descriptor.
    /// \param  event  The event(s) for the file descriptor.
    virtual void ServiceFileDescriptor(int fd, FdEvent event);

    /// \brief Get the Path Controller's file descriptor information.
    ///
    /// Used for including the file descriptors in a read and/or write mask
    /// for a select() call within the main processing loop.
    ///
    /// \param  fd_event_array  A pointer to an array of fd event information
    ///                         structures.
    /// \param  array_size      The number of elements in the event
    ///                         information structure array.
    ///
    /// \return  The number of Path Controller file descriptor information
    ///          elements returned.
    virtual size_t GetFileDescriptors(FdEventInfo* fd_event_array,
                                      size_t array_size) const;

    /// \brief Get the current size of the Path Controller's transmit queue in
    /// bytes.
    ///
    /// This includes all queued QLAM, control, and data packets.
    ///
    /// \param  size  A reference where the current transmit queue size, in
    ///               bytes, is placed on success.
    ///
    /// \return  True if the connection is established and there are active
    ///          transmit queues, or false otherwise.
    virtual inline bool GetXmitQueueSize(size_t& size) const
    {
      size = (qlam_xq_bytes_ + ef_data_xq_bytes_ + control_xq_bytes_ +
              data_xq_bytes_);
      return (is_connected_ && (!IsInOutage(endpt_id_)));
    }

    /// \brief Set a configurable parameter value.
    ///
    /// \param  name   The parameter name.
    /// \param  value  The parameter value.
    ///
    /// \return  True on success, false otherwise.
    virtual bool SetParameter(const char* name, const char* value);

    /// \brief Get a configurable parameter value.
    ///
    /// \param  name   The parameter name.
    /// \param  value  A reference to where the parameter value will be
    ///                returned on success.
    ///
    /// \return  True on success, false otherwise.
    virtual bool GetParameter(const char* name, std::string& value) const;

    /// \brief  Get the per-QLAM header overhead in bytes.
    ///
    /// 26 - Ethernet Framing (8 start of frame, 14 header, 4 CRC trailer)
    /// 20 - IPv4 Header (no options)
    ///  8 - UDP Header
    /// 20 - SLIQ Data Header (with the move forward sequence number option)
    ///
    /// \return The number of bytes added to each QLAM.
    virtual uint32_t GetPerQlamOverhead() const
    {
      return 74;
    }

    /// \brief A callback method for processing a connection request received
    /// by a server listen endpoint from a client.
    ///
    /// Only used if the server is using a TCP-like connection procedure as
    /// initiated by calling Listen().
    ///
    /// The SLIQ server listen endpoint, as created by Listen(), is specified
    /// in server_endpt_id.  The new server endpoint to the client is
    /// specified in data_endpt_id.  If this method returns true, then the
    /// data_endpt_id will be accepted and a ProcessConnectionResult() call
    /// specifying data_endpt_id as the endpt_id will be made later with the
    /// result of the connection establishment process.  If this method
    /// returns false, then the client connection request will be rejected
    /// immediately, and the data_endpt_id will be automatically closed.
    ///
    /// \param  server_endpt_id  The server listen endpoint ID.
    /// \param  data_endpt_id    The new server data endpoint ID.
    /// \param  client_address   The client's address and port number.
    ///
    /// \return  True if the connection is to be accepted, or false if the
    ///          connection is to be rejected.
    virtual bool ProcessConnectionRequest(
      sliq::EndptId server_endpt_id, sliq::EndptId data_endpt_id,
      const iron::Ipv4Endpoint& client_address);

    /// \brief A callback method for processing a client or server endpoint
    /// connection result.
    ///
    /// The endpoint ID specified is:
    /// - the client data endpoint that was returned by a call to Connect()\n
    ///   or SetupClientDataEndpoint() earlier, or
    /// - the server data endpoint passed by ProcessConnectionRequest() in\n
    ///   the data_endpt_id argument when the connection request was\n
    ///   accepted, or
    /// - the server data endpoint that was returned by a call to\n
    ///   SetupServerDataEndpoint() earlier.
    ///
    /// If success is true, then the connection has been set up with the
    /// remote peer and is ready to send and receive data over streams.  If
    /// success is false, then the connection failed and the specified data
    /// endpoint has been automatically closed.
    ///
    /// \param  endpt_id  The data endpoint ID for the connection.
    /// \param  success   The result of the connection establishment.  Set to
    ///                   true if the connection establishment succeeded, or
    ///                   false if it failed.
    virtual void ProcessConnectionResult(sliq::EndptId endpt_id,
                                         bool success);

    /// \brief A callback method indicating that a new stream has been created
    /// by the remote peer.
    ///
    /// \param  endpt_id   The endpoint ID containing the stream.
    /// \param  stream_id  The new stream ID.
    /// \param  prio       The priority of the stream.  The highest priority
    ///                    is 0, and the lowest priority is 7.
    /// \param  rel        The reliability mode and settings for the stream.
    /// \param  del_mode   The delivery mode for the stream.
    virtual void ProcessNewStream(sliq::EndptId endpt_id,
                                  sliq::StreamId stream_id,
                                  sliq::Priority prio,
                                  const sliq::Reliability& rel,
                                  sliq::DeliveryMode del_mode);

    /// \brief A callback method for processing data received from the remote
    /// peer over the specified connected endpoint and stream.
    ///
    /// Called for a SLIQ client or server with a connected endpoint.
    /// Ownership of the packet is transferred to the application.
    ///
    /// \param  endpt_id   The endpoint ID that received the data.
    /// \param  stream_id  The stream ID that received the data.
    /// \param  data       A pointer to a packet containing the received data.
    virtual void Recv(sliq::EndptId endpt_id, sliq::StreamId stream_id,
                      iron::Packet* data);

    /// \brief A callback method for processing data passed to SLIQ for
    /// transmission on a best-effort or semi-reliable stream that cannot be
    /// delivered to the remote peer.
    ///
    /// This method occurs while SLIQ is not re-entrant.  No calls into the
    /// SLIQ API should occur during this callback.
    ///
    /// Ownership of the packet remains with SLIQ.  The SLIQ application must
    /// not modify or release the packet.
    ///
    /// \param  endpt_id   The endpoint ID that is dropping the packet.
    /// \param  stream_id  The stream ID that is dropping the packet.
    /// \param  data       A pointer to the packet being dropped.  Remains
    ///                    owned by SLIQ.
    virtual void ProcessPacketDrop(
      sliq::EndptId endpt_id, sliq::StreamId stream_id, iron::Packet* data);

    /// \brief A callback method for processing an update to the number of
    /// bytes in a stream's transmit queue.
    ///
    /// \param  endpt_id   The endpoint ID for the transmit queue.
    /// \param  stream_id  The stream ID for the transmit queue.
    /// \param  bytes      The updated number of bytes in the stream's
    ///                    transmit queue.
    virtual void ProcessTransmitQueueSize(
      sliq::EndptId endpt_id, sliq::StreamId stream_id, size_t bytes);

    /// \brief A callback method for processing a connection capacity
    /// estimate.
    ///
    /// \param  endpt_id           The endpoint ID for the connection.
    /// \param  chan_cap_est_bps   The channel capacity estimate, in bps.
    /// \param  trans_cap_est_bps  The transport capacity estimate, in bps.
    /// \param  ccl_time_sec       The time, in seconds, since the last
    ///                            congestion control limit event.
    virtual void ProcessCapacityEstimate(sliq::EndptId endpt_id,
                                         double chan_cap_est_bps,
                                         double trans_cap_est_bps,
                                         double ccl_time_sec);

    /// \brief A callback method for processing RTT and packet delivery delay
    /// (PDD) samples.
    ///
    /// \param  endpt_id     The endpoint ID for the measurements.
    /// \param  num_samples  The number of estimates in the array.
    /// \param  samples      The stream ID, RTT (in usec), and PDD (in usec)
    ///                      for each sample in an array of structures.
    virtual void ProcessRttPddSamples(sliq::EndptId endpt_id,
                                      uint32_t num_samples,
                                      const sliq::RttPdd* samples);

    /// \brief A callback method for processing a stream close from the remote
    /// peer.
    ///
    /// When this method is called, all of the remote peer's data for the
    /// stream has already been delivered via Recv().  The local application
    /// may still send data to the remote peer on the stream if it has not
    /// called CloseStream() yet, in which case fully_closed will be set to
    /// false.  If the local application has already called CloseStream() on
    /// the stream, then fully_closed will be set to true.
    ///
    /// \param  endpt_id      The endpoint ID for the connection containing
    ///                       the stream.
    /// \param  stream_id     The stream ID that the remote peer has closed.
    /// \param  fully_closed  A boolean that is true if the stream is fully
    ///                       closed, or false if the stream is in a
    ///                       half-closed state and the local application can
    ///                       still send data on the stream to the remote
    ///                       peer.
    virtual void ProcessCloseStream(sliq::EndptId endpt_id,
                                    sliq::StreamId stream_id,
                                    bool fully_closed);

    /// \brief A callback method for processing a connection close from the
    /// remote peer.
    ///
    /// When this method is called, all of the remote peer's data has already
    /// been delivered via Recv().  The local application may still send data
    /// to the remote peer on any existing streams if it has not called
    /// Close() yet, in which case fully_closed will be set to false.  If the
    /// local application has already called Close(), then fully_closed will
    /// be set to true.
    ///
    /// \param  endpt_id      The endpoint ID that the remote peer has closed.
    /// \param  fully_closed  A boolean that is true if the endpoint is fully
    ///                       closed, or false if the endpoint is in a
    ///                       half-closed state and the local application can
    ///                       still send data on existing streams to the
    ///                       remote peer.
    virtual void ProcessClose(sliq::EndptId endpt_id, bool fully_closed);

    /// \brief Process a change to the file descriptors and their events due
    /// to some state change in SLIQ.
    virtual void ProcessFileDescriptorChange();

   private:

    /// \brief Copy constructor.
    SliqCat(const SliqCat& cat);

    /// \brief Assignment operator.
    SliqCat& operator=(const SliqCat& cat);

    /// \brief Parse the endpoints string.
    ///
    /// \param  ep_str  A reference to the string to be parsed.
    ///
    /// \return  True if the string is parsed successfully, or false
    ///          otherwise.
    bool ParseEndpointsString(const std::string& ep_str);

    /// \brief Parse the EF data reliability mode string.
    ///
    /// \param  ef_rel_str  A reference to the string to be parsed.
    ///
    /// \return  True if the string is parsed successfully, or false
    ///          otherwise.
    bool ParseEfDataRelString(const std::string& ef_rel_str);

    /// \brief Parse the congestion control string.
    ///
    /// \param  cc_alg_str   A reference to the string to be parsed.
    /// \param  anti_jitter  The Copa anti-jitter value in seconds.
    ///
    /// \return  True if the string is parsed successfully, or false
    ///          otherwise.
    bool ParseCongCtrlString(const std::string& cc_alg_str,
                             double anti_jitter);

    /// \brief Create the required streams.
    ///
    /// \return  True if the streams are created successfully, or false
    ///          otherwise.
    bool CreateStreams();

    /// \brief Start a connection retry timer.
    void StartConnectionRetryTimer();

    /// \brief The connection retry timer callback method.
    void ConnectionRetryTimeout();

    /// \brief Start a capacity estimate send timer.
    ///
    /// \param  start_flag  A flag controlling if the method is starting the
    ///                     first capacity estimate send timer or not.
    ///                     Defaults to true.
    void StartCapEstSendTimer(bool start_flag = true);

    /// \brief The capacity estimate send timer callback method.
    void CapEstSendCallback();

    /// \brief Send the necessary number of dummy capacity estimate packets.
    void SendCapEstDummyPkts();

    /// \brief Send a CAT Capacity Estimate (CCE) packet to the remote CAT.
    void SendCatCapEstPkt();

    /// \brief Process a received CAT Capacity Estimate (CCE) packet from the
    /// remote CAT.
    ///
    /// \param  pkt  The received CCE packet.
    void ProcessCatCapEstPkt(Packet* pkt);

    /// \brief Possibly report a capacity estimate and a packet delivery delay
    /// (PDD) estimate to the BPF.
    void ReportCapEstPddToBpf();

    /// \brief The structure of state information for tracking the estimated
    /// round trip time (RTT) for packets sent from this CAT to the remote
    /// CAT.
    ///
    struct RttInfo
    {
      RttInfo()
          : srtt_(-1.0), rtt_variation_(0.0), rtt_bound_(-1.0)
      {}

      ~RttInfo()
      {}

      /// The smoothed RTT, in seconds.
      double  srtt_;

      /// The RTT variation, in seconds.
      double  rtt_variation_;

      /// The RTT bound, in seconds.
      double  rtt_bound_;
    };

    /// \brief The structure of state information for tracking the estimated
    /// packet delivery delay (PDD) for packets sent from this CAT to the
    /// remote CAT.
    ///
    struct PddInfo
    {
      PddInfo();

      ~PddInfo()
      {}

      /// The number of initial measurements to ignore.
      size_t      ignore_cnt_;

      /// The current mean of the EF data PDD, in seconds.
      double      ef_pdd_mean_;

      /// The current variance of the EF data PDD, in seconds squared.
      double      ef_pdd_variance_;

      /// The time of the last EF data PDD update.
      iron::Time  ef_pdd_update_time_;

      /// The current mean of the QLAM and normal data PDD, in seconds.
      double      norm_pdd_mean_;

      /// The current variance of the QLAM and normal data PDD, in seconds
      /// squared.
      double      norm_pdd_variance_;

      /// The PDD callback threshold for reporting.
      double      cb_change_thresh_;

      /// The PDD callback minimum time between updates, in seconds.
      double      cb_min_period_;

      /// The PDD callback maximum time between updates, in seconds.
      double      cb_max_period_;

      /// The PDD mean reported in the previous PDD callback, in seconds.
      double      cb_pdd_mean_;

      /// The time of the previous PDD callback.
      iron::Time  cb_prev_time_;
    };

    /// Manager of all timers.
    iron::Timer&         timer_;

    /// A flag recording if this is the SLIQ client or server.
    bool                 is_server_;

    /// A flag recording if the SLIQ connection is established.
    bool                 is_connected_;

    /// A flag recording if currently in the destructor.
    bool                 in_destructor_;

    /// A flag recording if the active capacity estimation is enabled or not.
    bool                 active_cap_est_;

    /// The EF data reliability mode and settings.
    sliq::Reliability    ef_rel_;

    /// The number of SLIQ congestion control algorithms.
    size_t               num_cc_alg_;

    /// The SLIQ congestion control algorithms and settings.
    sliq::CongCtrl       cc_alg_[kMaxCcAlgPerConn];

    /// The SLIQ congestion control algorithm aggressiveness setting.
    uint32_t             cc_aggr_;

    /// The SLIQ RTT outlier rejection setting.
    bool                 rtt_outlier_rejection_;

    /// The data packet transmit queue size in packets.  Used for both the EF
    /// data and non-EF data streams.
    size_t               data_xmit_queue_size_;

    /// The SLIQ QLAM/control/data connection endpoint identifier.  Set to -1
    /// when not available.
    sliq::EndptId        endpt_id_;

    /// The SLIQ QLAM packet stream identifier.  Set to 0 when there is no
    /// stream.
    sliq::StreamId       qlam_stream_id_;

    /// The SLIQ EF data packet stream identifier.  Set to 0 when there is no
    /// stream.
    sliq::StreamId       ef_data_stream_id_;

    /// The SLIQ system-level control packet stream identifier.  Set to 0 when
    /// there is no stream.
    sliq::StreamId       control_stream_id_;

    /// The SLIQ non-EF data packet and flow-level control packet stream
    /// identifier.  Set to 0 when there is no stream.
    sliq::StreamId       data_stream_id_;

    /// The SLIQ capacity estimate packet stream identifier.  Set to 0 when
    /// there is no stream.
    sliq::StreamId       cap_est_stream_id_;

    /// The connection retry timer handle.
    iron::Timer::Handle  conn_retry_handle_;

    /// The number of client connection attempts.
    int                  client_conn_attempts_;

    /// The current QLAM packet transmit queue size in bytes.
    size_t               qlam_xq_bytes_;

    /// The current EF data packet transmit queue size in bytes.
    size_t               ef_data_xq_bytes_;

    /// The current system-level control packet transmit queue size in bytes.
    size_t               control_xq_bytes_;

    /// The current non-EF data packet and flow-level control packet transmit
    /// queue size in bytes.
    size_t               data_xq_bytes_;

    /// The current capacity estimate packet transmit queue size in bytes.
    size_t               cap_est_xq_bytes_;

    /// The capacity estimate send timer handle.
    iron::Timer::Handle  cap_est_send_handle_;

    /// The capacity estimate send end time.
    iron::Time           cap_est_send_end_time_;

    /// The capacity estimate send ready flag.  Set to true when the capacity
    /// estimate packet stream is fully established.
    bool                 cap_est_send_ready_;

    /// The capacity estimate send initialized flag.  Set to true when the
    /// parameters for sending capacity estimate packets are all set.
    bool                 cap_est_send_init_;

    /// The target number of capacity estimate packets to keep enqueued.
    size_t               cap_est_send_pkts_;

    /// The target capacity estimate packet inter-send time, in seconds.
    double               cap_est_send_ist_;

    /// The local channel capacity estimate, in bits per second.
    double               local_chan_cap_est_bps_;

    /// The local transport capacity estimate, in bits per second.
    double               local_trans_cap_est_bps_;

    /// The remote channel capacity estimate, in bits per second.
    double               remote_chan_cap_est_bps_;

    /// The last reported channel capacity estimate, in bits per second.
    double               last_chan_cap_est_bps_;

    /// The last reported transport capacity estimate, in bits per second.
    double               last_trans_cap_est_bps_;

    /// A flag recording if CCE packets are allowed to be sent by
    /// SendPacket() or not.
    bool                 cce_lock_;

    /// The CCE packet send timer handle.
    iron::Timer::Handle  cce_send_handle_;

    /// The RTT estimate information.
    RttInfo              rtt_;

    /// The packet delivery delay (PDD) estimate information.
    PddInfo              pdd_;

  }; // end class SliqCat

} // namespace iron

#endif // IRON_BPF_SLIQ_CAT_H
