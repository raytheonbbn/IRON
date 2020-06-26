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

#ifndef IRON_SLIC_APP_H
#define IRON_SLIC_APP_H

#include "sliq_types.h"

#include "fd_event.h"
#include "ipv4_endpoint.h"
#include "itime.h"
#include "packet_pool.h"
#include "rng.h"
#include "timer.h"


namespace sliq
{

  class ConnectionManager;
  class SocketManager;

  /// \brief The base class for all SLIQ applications.
  ///
  /// A SLIQ application should inherit from this class and implement the
  /// following methods:
  /// - ProcessConnectionRequest()
  /// - ProcessConnectionResult()
  /// - ProcessNewStream()
  /// - Recv()
  /// - ProcessPacketDrop() (optional)
  /// - ProcessTransmitQueueSize() (optional)
  /// - ProcessCapacityEstimate()
  /// - ProcessRttPddSamples() (optional)
  /// - ProcessCloseStream()
  /// - ProcessClose()
  /// - ProcessFileDescriptorChange()
  ///
  /// The implementation of a SLIQ server application would consist of the
  /// following calls and callbacks:
  /// - Call InitializeSliqApp().
  /// - Use a TCP-like connection procedure or a direct connection procedure\n
  ///   for creating a connection.  If using a TCP-like connection procedure:
  ///   - Call Listen() with a server address, storing the new listen server\n
  ///     endpoint ID.
  ///   - The ProcessConnectionRequest() callback occurs when a client\n
  ///     requests a connection to the server.  The return value controls if\n
  ///     the connection is accepted or not.  If accepted, the new server\n
  ///     data endpoint ID should be stored.
  /// - If using a direct connection procedure:
  ///   - Call SetupServerDataEndpoint() with both server and client\n
  ///     addresses to attempt to accept the connection to a SLIQ client\n
  ///     application, storing the new server data endpoint ID.
  /// - The ProcessConnectionResult() callback occurs when the connection\n
  ///   attempt has either been successful or has failed.
  /// - Call AddStream() as necessary to create new streams.  The SLIQ\n
  ///   server can only create even stream IDs.  The stream ID should be\n
  ///   stored.
  /// - The ProcessNewStream() callback occurs for each stream created by\n
  ///   the client.  These have odd stream IDs, and should be stored.
  /// - Call ConfigureTcpFriendliness() on the connection to change the TCP\n
  ///   friendliness/aggressiveness behavior of local transmissions.
  /// - Call ConfigureTransmitQueue() on any stream that requires the\n
  ///   transmit queue to be configured.
  /// - Call ConfigureRetransmissionLimit() on any semi-reliable ARQ stream\n
  ///   to change the delivery retransmission limit for local transmissions.
  /// - Call Send() to send data on the endpoint/stream.
  /// - The Recv() callback occurs when data is received on the\n
  ///   endpoint/stream.
  /// - The optional ProcessPacketDrop() callback occurs when a data packet\n
  ///   to be sent is dropped.  This only occurs for best-effort or\n
  ///   semi-reliable streams.
  /// - The optional ProcessTransmitQueueSize() callback occurs when there\n
  ///   is an update to an endpoint/stream's transmit queue size.
  /// - The ProcessCapacityEstimate() callback occurs when there is an\n
  ///   update to the capacity estimates for the connection.
  /// - The optional ProcessRttPddSamples() callback occurs every time there\n
  ///   are new RTT and packet-delivery-delay estimates available.
  /// - The ProcessCloseStream() callback occurs when the client closes a\n
  ///   stream.
  /// - Call CloseStream() to close a stream.
  /// - The ProcessClose() callback occurs when the client closes the\n
  ///   connection.
  /// - Call Close() to close the connection.
  ///
  /// The implementation of a SLIQ client application would consist of the
  /// following calls and callbacks:
  /// - Call InitializeSliqApp().
  /// - Use a TCP-like connection procedure or a direct connection procedure\n
  ///   for creating a connection.  If using a TCP-like connection procedure:
  ///   - Call Connect() with a server address to attempt to connect to a\n
  ///     SLIQ server application, storing the new client data endpoint ID.
  /// - If using a direct connection procedure:
  ///   - Call SetupClientDataEndpoint() with both client and server\n
  ///     addresses to attempt to connect to the SLIQ server application,\n
  ///     storing the new client data endpoint ID.
  /// - The ProcessConnectionResult() callback occurs when the connection\n
  ///   attempt has either been successful or has failed.
  /// - Call AddStream() as necessary to create new streams.  The SLIQ\n
  ///   client can only create odd stream IDs.  The stream ID should be\n
  ///   stored.
  /// - The ProcessNewStream() callback occurs for each stream created by\n
  ///   the server.  These have even stream IDs, and should be stored.
  /// - Call ConfigureTcpFriendliness() on the connection to change the TCP\n
  ///   friendliness/aggressiveness behavior of local transmissions.
  /// - Call ConfigureTransmitQueue() on any stream that requires the\n
  ///   transmit queue to be configured.
  /// - Call ConfigureRetransmissionLimit() on any semi-reliable ARQ stream\n
  ///   to change the delivery retransmission limit for local transmissions.
  /// - Call Send() to send data on the endpoint/stream.
  /// - The Recv() callback occurs when data is received on the\n
  ///   endpoint/stream.
  /// - The optional ProcessPacketDrop() callback occurs when a data packet\n
  ///   to be sent is dropped.  This only occurs for best-effort or\n
  ///   semi-reliable streams.
  /// - The optional ProcessTransmitQueueSize() callback occurs when there\n
  ///   is an update to an endpoint/stream's transmit queue size.
  /// - The ProcessCapacityEstimate() callback occurs when there is an\n
  ///   update to the capacity estimates for the connection.
  /// - The optional ProcessRttPddSamples() callback occurs every time there\n
  ///   are new RTT and packet-delivery-delay estimates available.
  /// - The ProcessCloseStream() callback occurs when the server closes a\n
  ///   stream.
  /// - Call CloseStream() to close a stream.
  /// - The ProcessClose() callback occurs when the server closes the\n
  ///   connection.
  /// - Call Close() to close the connection.
  ///
  /// Each stream's packet transmit queue defaults to a size of 64 packets, a
  /// FIFO_QUEUE dequeueing rule, and a NO_DROP drop rule.  In order to change
  /// these settings on a stream, call the ConfigureTransmitQueue() method
  /// before sending any packets on the stream.
  ///
  /// Finally, the application's main processing loop must include the IRON
  /// Timer class API calls as well as the following SLIQ calls, and the
  /// application will receive the following callbacks:
  /// - Call GetFileDescriptorList() to get a list of all of the file\n
  ///   descriptors that must be monitored in the main processing loop.
  /// - When one of these file descriptors has an event occur, call\n
  ///   SvcFileDescriptor() on the file descriptor.
  /// - The ProcessFileDescriptorChange() callback occurs when the list of\n
  ///   SLIQ file descriptors to be monitored changes.
  ///
  /// This class is not thread-safe.
  class SliqApp
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  packet_pool  Pool containing packet to use.
    /// \param  timer        Manager of all timers.
    SliqApp(iron::PacketPool& packet_pool, iron::Timer& timer);

    /// \brief Destructor.
    virtual ~SliqApp();

    /// \brief Initialize the object.
    ///
    /// \return  True on success, or false otherwise.
    bool InitializeSliqApp();

    /// \brief Initiate a TCP-like connection to the specified server.
    ///
    /// Called by a SLIQ client when using a TCP-like connection procedure.
    /// On success, the endpoint ID for the client data endpoint is returned
    /// in endpt_id and the ProcessConnectionResult() method is called later
    /// when the connection is either completed successfully or has failed.
    /// This method does not block while the connection is being established.
    ///
    /// \param  server_address  The server address and well known port number.
    /// \param  cc_alg          A pointer to an array of congestion control
    ///                         algorithm and settings to use in parallel for
    ///                         the connection to the server.
    /// \param  num_cc_alg      The number of congestion control algorithms
    ///                         in the specified array.  Must be between 1 and
    ///                         kMaxCcAlgPerConn.
    /// \param  endpt_id        A reference where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool Connect(const iron::Ipv4Endpoint& server_address,
                 const CongCtrl* cc_alg, size_t num_cc_alg,
                 EndptId& endpt_id);

    /// \brief Initiate a TCP-like connection that listens for connection
    /// requests on the specified IP address and well known port number.
    ///
    /// Called by a SLIQ server when using a TCP-like connection procedure.
    /// If the IP address in server_address is zero, then all interfaces are
    /// listened on.  Does not block.  The endpoint ID for the server listen
    /// endpoint is returned in endpt_id on success.  The
    /// ProcessConnectionRequest() method is called when a request for a new
    /// connection is received from a client.  Note that the server listen
    /// endpoint can never be connected (i.e., it can never create streams, or
    /// send and receive data).
    ///
    /// \param  server_address  The server address and well known port number.
    /// \param  endpt_id        A reference where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool Listen(const iron::Ipv4Endpoint& server_address, EndptId& endpt_id);

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
      EndptId server_endpt_id, EndptId data_endpt_id,
      const iron::Ipv4Endpoint& client_address) = 0;

    /// \brief Initiate the client side of a direct connection to the
    /// specified server.
    ///
    /// Called by a SLIQ client when using a direct connection procedure.
    /// Requires specifying the complete addresses and port numbers for both
    /// endpoints of the connection.  On success, the endpoint ID for the
    /// client data endpoint is returned in endpt_id and the
    /// ProcessConnectionResult() method is called later when the connection
    /// is either completed successfully or has failed.  This method does not
    /// block while the connection is being established.
    ///
    /// \param  client_address  The local address and port number.
    /// \param  server_address  The remote address and port number.
    /// \param  cc_alg          A pointer to an array of congestion control
    ///                         algorithm and settings to use in parallel for
    ///                         the connection to the server.
    /// \param  num_cc_alg      The number of congestion control algorithms
    ///                         in the specified array.  Must be between 1 and
    ///                         kMaxCcAlgPerConn.
    /// \param  endpt_id        A reference where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool SetupClientDataEndpoint(
      const iron::Ipv4Endpoint& client_address,
      const iron::Ipv4Endpoint& server_address, const CongCtrl* cc_alg,
      size_t num_cc_alg, EndptId& endpt_id);

    /// \brief Initialize the server side of a direct connection to the
    /// specified client.
    ///
    /// Called by a SLIQ server when using a direct connection procedure.
    /// Requires specifying the complete addresses and port numbers for both
    /// endpoints of the connection.  On success, the endpoint ID for the
    /// server data endpoint is returned in endpt_id and the
    /// ProcessConnectionResult() method is called later when the connection
    /// is either completed successfully or has failed.  This method does not
    /// block while the connection is being established.
    ///
    /// \param  server_address  The local address and port number.
    /// \param  client_address  The remote address and port number.
    /// \param  endpt_id        A reference where the assigned endpoint ID
    ///                         will be returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool SetupServerDataEndpoint(
      const iron::Ipv4Endpoint& server_address,
      const iron::Ipv4Endpoint& client_address, EndptId& endpt_id);

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
    virtual void ProcessConnectionResult(EndptId endpt_id, bool success) = 0;

    /// \brief Add a new stream to a connected client or server endpoint.
    ///
    /// A new stream can only be added when the connection is fully connected
    /// (IsConnected() returns true).
    ///
    /// To avoid stream ID collisions, client initiated stream IDs must be odd
    /// numbers, and server initiated stream IDs must be even numbers.  Stream
    /// ID 0 is not a valid stream ID.  The maximum stream ID allowed is 32
    /// for efficiency.  Thus, the stream ID specified must be between 1 and
    /// 32 (inclusive).
    ///
    /// If the reliability mode is RELIABLE_ARQ, then the delivery mode may
    /// be either ORDERED_DELIVERY or UNORDERED_DELIVERY.  If the reliability
    /// mode is either SEMI_RELIABLE_* or BEST_EFFORT, then the delivery
    /// mode must be UNORDERED_DELIVERY.
    ///
    /// \param  endpt_id   The endpoint ID to which the stream will be added.
    /// \param  stream_id  The new stream ID.  Must be between 1 and 32
    ///                    (inclusive), with odd numbers for the client
    ///                    (1, 3, 5, 7, ..., 31) and even numbers for the
    ///                    server (2, 4, 6, 8, ..., 32).
    /// \param  prio       The priority of the stream.  The highest priority
    ///                    is 0, and the lowest priority is 7.
    /// \param  rel        The reliability mode and settings for the stream.
    /// \param  del_mode   The delivery mode for the stream.
    ///
    /// \return  True on success, or false otherwise.
    bool AddStream(EndptId endpt_id, StreamId stream_id, Priority prio,
                   const Reliability& rel, DeliveryMode del_mode);

    /// \brief A callback method indicating that a new stream has been created
    /// by the remote peer.
    ///
    /// \param  endpt_id   The endpoint ID containing the stream.
    /// \param  stream_id  The new stream ID.
    /// \param  prio       The priority of the stream.  The highest priority
    ///                    is 0, and the lowest priority is 7.
    /// \param  rel        The reliability mode and settings for the stream.
    /// \param  del_mode   The delivery mode for the stream.
    virtual void ProcessNewStream(EndptId endpt_id, StreamId stream_id,
                                  Priority prio, const Reliability& rel,
                                  DeliveryMode del_mode) = 0;

    /// \brief Configure the TCP friendliness/aggressiveness of a connected
    /// client or server endpoint.
    ///
    /// This only changes the TCP friendliness/aggressiveness of packets sent
    /// by the local endpoint, not packets sent by the remote endpoint.
    ///
    /// This setting can only be made when the connection is fully connected
    /// (IsConnected() returns true).
    ///
    /// \param  endpt_id   The endpoint ID which will be configured.
    /// \param  num_flows  The number of TCP flows to emulate in terms of
    ///                    TCP friendliness/aggressiveness.  The higher the
    ///                    number, the more aggressive.  Must be greater than
    ///                    or equal to one.
    ///
    /// \return  Returns true on success, or false if this setting is not
    ///          supported by the algorithm.
    bool ConfigureTcpFriendliness(EndptId endpt_id, uint32_t num_flows);

    /// \brief Configure a stream's transmit queue.
    ///
    /// The stream's transmit queue is for packets that cannot be sent yet due
    /// to either congestion control or flow control.  This does not change
    /// the near side sent packet queue.  Nor does it change the far side
    /// transmit queue.
    ///
    /// This may be called after a call to AddStream() succeeds, or a
    /// ProcessNewStream() callback occurs.  It must be called before any data
    /// is sent on the stream.
    ///
    /// \param  endpt_id       The endpoint ID containing the stream.
    /// \param  stream_id      The stream ID of interest.
    /// \param  max_size_pkts  The queue's maximum size, in packets.
    /// \param  dequeue_rule   The queue's dequeue rule.
    /// \param  drop_rule      The queue's drop rule.
    ///
    /// \return  True on success, or false otherwise.
    bool ConfigureTransmitQueue(EndptId endpt_id, StreamId stream_id,
                                size_t max_size_pkts,
                                DequeueRule dequeue_rule, DropRule drop_rule);

    /// \brief Configure a stream's semi-reliable packet delivery
    /// retransmission limit.
    ///
    /// When a semi-reliable stream is created, packets are only retransmitted
    /// for a limited number of times.  After this number of retransmissions,
    /// the packets are dropped from the sender and the receiver is instructed
    /// to pass over them if they have not been received.  This method may be
    /// used to update the near side retransmission limit after the stream has
    /// been created.
    ///
    /// This may be called after a call to AddStream() succeeds, or a
    /// ProcessNewStream() callback occurs.  The stream reliability mode must
    /// be SEMI_RELIABLE_ARQ or SEMI_RELIABLE_ARQ_FEC for this parameter to be
    /// used.
    ///
    /// \param  endpt_id      The endpoint ID containing the stream.
    /// \param  stream_id     The stream ID of interest.
    /// \param  rexmit_limit  The packet delivery retransmission limit.  Only
    ///                       used if the reliability mode is set to
    ///                       SEMI_RELIABLE_ARQ or SEMI_RELIABLE_ARQ_FEC.
    ///
    /// \return  True on success, or false otherwise.
    bool ConfigureRetransmissionLimit(EndptId endpt_id, StreamId stream_id,
                                      RexmitLimit rexmit_limit);

    /// \brief Send data to the remote peer over the specified connected
    /// endpoint and stream.
    ///
    /// The endpoint must be a connected client or server endpoint.  The
    /// stream must have been created successfully using AddStream().
    ///
    /// The data remains owned by the caller.
    ///
    /// \param  endpt_id   The endpoint ID to which the data will be sent.
    /// \param  stream_id  The stream ID to which the data will be sent.
    /// \param  data       A pointer to the data to be sent.
    /// \param  data_len   The length of the data in bytes.
    ///
    /// \return  True on success, or false otherwise.
    bool Send(EndptId endpt_id, StreamId stream_id, uint8_t* data,
              size_t data_len);

    /// \brief Send a packet to the remote peer over the specified connected
    /// endpoint and stream.
    ///
    /// The endpoint must be a connected client or server endpoint.  The
    /// stream must have been created successfully using AddStream().
    ///
    /// Ownership of the packet is transferred to SLIQ when the method call
    /// succeeds (returns true).  Otherwise, the packet remains owned by the
    /// caller.
    ///
    /// This Send() method uses the minimum number of data copies possible,
    /// and is the preferred Send() method.
    ///
    /// \param  endpt_id   The endpoint ID to which the data will be sent.
    /// \param  stream_id  The stream ID to which the data will be sent.
    /// \param  data       A pointer to a packet containing the data to be
    ///                    sent.
    ///
    /// \return  True on success, or false otherwise.
    bool Send(EndptId endpt_id, StreamId stream_id, iron::Packet* data);

    /// \brief A callback method for processing data received from the remote
    /// peer over the specified connected endpoint and stream.
    ///
    /// Called for a SLIQ client or server with a connected endpoint.
    /// Ownership of the packet is transferred to the application.
    ///
    /// \param  endpt_id   The endpoint ID that received the data.
    /// \param  stream_id  The stream ID that received the data.
    /// \param  data       A pointer to a packet containing the received data.
    virtual void Recv(EndptId endpt_id, StreamId stream_id,
                      iron::Packet* data) = 0;

    /// \brief Get the endpoint type.
    ///
    /// \param  endpt_id    The endpoint ID to be queried.
    /// \param  endpt_type  A reference where the endpoint's type will be
    ///                     placed on success.
    ///
    /// \return  True on success, or false otherwise.
    bool GetEndpointType(EndptId endpt_id, EndptType& endpt_type);

    /// \brief Check if an endpoint is connected or not.
    ///
    /// \param  endpt_id  The endpoint ID to be queried.
    ///
    /// \return  True if the endpoint is fully connected, or false
    ///          otherwise.  Once one side has called Close(), this method
    ///          will return false.
    bool IsConnected(EndptId endpt_id) const;

    /// \brief Check if a stream is fully established or not.
    ///
    /// \param  endpt_id   The endpoint ID for the stream.
    /// \param  stream_id  The stream ID to be queried.
    ///
    /// \return  True if the stream is fully established, or false otherwise.
    bool IsStreamEstablished(EndptId endpt_id, StreamId stream_id) const;

    /// \brief Check if the connection associated with an endpoint is
    /// currently in an outage.
    ///
    /// \param  endpt_id  The endpoint ID to be queried.
    ///
    /// \return  True if the connection is currently in an outage.
    bool IsInOutage(EndptId endpt_id) const;

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
    /// The method is optional.  The SLIQ application may not implement this
    /// method.
    ///
    /// \param  endpt_id   The endpoint ID that is dropping the packet.
    /// \param  stream_id  The stream ID that is dropping the packet.
    /// \param  data       A pointer to the packet being dropped.  Remains
    ///                    owned by SLIQ.
    virtual inline void ProcessPacketDrop(
      EndptId endpt_id, StreamId stream_id, iron::Packet* data)
    {
      return;
    }

    /// \brief A callback method for processing an update to the number of
    /// bytes in a stream's transmit queue.
    ///
    /// This method occurs while SLIQ is not re-entrant.  No calls into the
    /// SLIQ API should occur during this callback.
    ///
    /// The method is optional.  The SLIQ application may not implement this
    /// method.
    ///
    /// \param  endpt_id   The endpoint ID for the transmit queue.
    /// \param  stream_id  The stream ID for the transmit queue.
    /// \param  bytes      The updated number of bytes in the stream's
    ///                    transmit queue.
    virtual inline void ProcessTransmitQueueSize(
      EndptId endpt_id, StreamId stream_id, size_t bytes)
    {
      return;
    }

    /// \brief A callback method for processing a connection capacity
    /// estimate.
    ///
    /// \param  endpt_id           The endpoint ID for the connection.
    /// \param  chan_cap_est_bps   The channel capacity estimate, in bps.
    /// \param  trans_cap_est_bps  The transport capacity estimate, in bps.
    /// \param  ccl_time_sec       The time, in seconds, since the last
    ///                            congestion control limit event.
    virtual void ProcessCapacityEstimate(EndptId endpt_id,
                                         double chan_cap_est_bps,
                                         double trans_cap_est_bps,
                                         double ccl_time_sec) = 0;

    /// \brief A callback method for processing RTT and packet delivery delay
    /// (PDD) samples.
    ///
    /// An initial call from the connection may occur first, with the stream
    /// ID set to zero and the PDD estimate set to zero.  Thereafter, the
    /// stream ID and PDD will be set.
    ///
    /// The method is optional.  The SLIQ application may not implement this
    /// method.
    ///
    /// \param  endpt_id     The endpoint ID for the measurements.
    /// \param  num_samples  The number of estimates in the array.
    /// \param  samples      The stream ID, RTT (in usec), and PDD (in usec)
    ///                      for each sample in an array of structures.
    virtual inline void ProcessRttPddSamples(
      EndptId endpt_id, uint32_t num_samples, const RttPdd* samples)
    {
      return;
    }

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
    virtual void ProcessCloseStream(EndptId endpt_id, StreamId stream_id,
                                    bool fully_closed) = 0;

    /// \brief Close the stream.
    ///
    /// Once called on a stream, the application cannot send any more data on
    /// the stream.  The remote peer may still send data to the local
    /// application on the stream if the ProcessCloseStream() callback has not
    /// occurred, in which case fully_closed will be set to false upon return.
    /// If the local application has already received the ProcessCloseStream()
    /// callback for the stream, then fully_closed will be set to true upon
    /// return.
    ///
    /// \param  endpt_id      The endpoint ID for the connection containing
    ///                       the stream.
    /// \param  stream_id     The stream ID to be closed.
    /// \param  fully_closed  A reference to a boolean that is set to true if
    ///                       the stream is fully closed, or false if the
    ///                       stream is in a half-closed state and the local
    ///                       application can still receive data on the stream
    ///                       from the remote peer.
    ///
    /// \return  True if the endpoint and stream are found and the close is
    ///          successful, or false otherwise.
    bool CloseStream(EndptId endpt_id, StreamId stream_id,
                     bool& fully_closed);

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
    virtual void ProcessClose(EndptId endpt_id, bool fully_closed) = 0;

    /// \brief Close the connection.
    ///
    /// Once called on a server listen endpoint, the endpoint will be closed.
    /// New connections will no longer be accepted on the endpoint.  Any
    /// existing server data endpoints created by the server listen endpoint
    /// will be unaffected.  The value returned in fully_closed will always be
    /// true in this case.
    ///
    /// Once called on a client data endpoint or a server data endpoint, the
    /// application cannot create any new streams or send any more data to the
    /// remote peer.  The remote peer may still send data to the local
    /// application if the ProcessClose() callback has not occurred, in which
    /// case fully_closed will be set to false upon return.  If the local
    /// application has already received the ProcessClose() callback, then
    /// fully_closed will be set to true upon return.
    ///
    /// It is desirable to first close all of the streams within the
    /// connection before closing the connection.  Any open streams will be
    /// closed immediately, which may cause their pending data to be lost.
    ///
    /// \param  endpt_id      The endpoint ID to be closed.
    /// \param  fully_closed  A reference to a boolean that is set to true if
    ///                       the endpoint is fully closed, or false if the
    ///                       endpoint is in a half-closed state and the local
    ///                       application can still receive data from the
    ///                       remote peer.
    ///
    /// \return  True if the endpoint is found and the close is successful, or
    ///          false otherwise.
    bool Close(EndptId endpt_id, bool& fully_closed);

    /// \brief Get all of the file descriptors and their events that need to
    /// be monitored for SLIQ.
    ///
    /// \param  fd_event_array  A pointer to an array of event information
    ///                         structures.
    /// \param  array_size      The number of elements in the event
    ///                         information structure array.
    ///
    /// \return  The number of file descriptors recorded in the event
    ///          information structure array.
    size_t GetFileDescriptorList(iron::FdEventInfo* fd_event_array,
                                 size_t array_size) const;

    /// \brief Process a change to the file descriptors and their events due
    /// to some state change in SLIQ.
    virtual void ProcessFileDescriptorChange() = 0;

    /// \brief Called when a file descriptor has an event that is of interest
    /// to it.
    ///
    /// \param  fd     The file descriptor.
    /// \param  event  The event(s) for the file descriptor.
    void SvcFileDescriptor(int fd, iron::FdEvent event);

    /// \brief Get the current size of the stream's transmit queue, in
    /// bytes.
    ///
    /// The stream's transmit queue is for packets that cannot be sent yet due
    /// to either congestion control or flow control.  This does not report on
    /// the sent packet queue.
    ///
    /// \param  endpt_id   The endpoint ID of interest.
    /// \param  stream_id  The stream ID of interest.
    /// \param  size       A reference to where the current size, in bytes, is
    ///                    returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool GetTransmitQueueSizeInBytes(EndptId endpt_id, StreamId stream_id,
                                     size_t& size) const;

    /// \brief Get the current size of the stream's transmit queue, in
    /// packets.
    ///
    /// The stream's transmit queue is for packets that cannot be sent yet due
    /// to either congestion control or flow control.  This does not report on
    /// the sent packet queue.
    ///
    /// \param  endpt_id   The endpoint ID of interest.
    /// \param  stream_id  The stream ID of interest.
    /// \param  size       A reference to where the current size, in packets,
    ///                    is returned on success.
    ///
    /// \return  True on success, or false otherwise.
    bool GetTransmitQueueSizeInPackets(EndptId endpt_id, StreamId stream_id,
                                       size_t& size) const;

    /// \brief Get a pointer to the socket manager for the SLIQ application.
    ///
    /// Necessary for integration with the ns-3 network simulator.
    ///
    /// \return  A pointer to the socket manager.
    inline SocketManager* GetSocketManager()
    {
      return socket_mgr_;
    }

    /// The maximum number of simultaneous congestion control algorithms
    /// allowed in a single SLIQ connection.
    static const size_t  kMaxCcAlgPerConn = 2;

   protected:

    /// Pool containing packets to use.
    iron::PacketPool&   packet_pool_;

   private:

    /// \brief Copy constructor.
    SliqApp(const SliqApp& sa);

    /// \brief Assignment operator.
    SliqApp& operator=(const SliqApp& sa);

    // Manager of all timers.
    iron::Timer&        timer_;

    /// The initialized flag.
    bool                initialized_;

    /// The common socket manager.
    SocketManager*      socket_mgr_;

    /// The common connection manager.
    ConnectionManager*  connection_mgr_;

    /// The common random number generator.
    iron::RNG           rng_;

  }; // end class SliqApp

}  // namespace sliq

#endif // IRON_SLIC_APP_H
