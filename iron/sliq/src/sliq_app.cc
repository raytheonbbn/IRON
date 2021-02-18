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

#include "sliq_app.h"

#include "sliq_connection.h"
#include "sliq_connection_manager.h"
#include "sliq_socket_manager.h"

#include "packet.h"
#include "packet_pool.h"
#include "timer.h"
#include "unused.h"

#include <cstring>


using ::sliq::SliqApp;
using ::iron::FdEvent;
using ::iron::FdEventInfo;
using ::iron::Ipv4Endpoint;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::Timer;


namespace
{
  const char*  UNUSED(kClassName) = "SliqApp";
}


//============================================================================
SliqApp::SliqApp(PacketPool& packet_pool, Timer& timer)
  : packet_pool_(packet_pool), timer_(timer), initialized_(false),
    socket_mgr_(NULL), connection_mgr_(NULL), rng_()
{
}

//============================================================================
SliqApp::~SliqApp()
{
  if (connection_mgr_ != NULL)
  {
    delete connection_mgr_;
    connection_mgr_ = NULL;
  }

  if (socket_mgr_ != NULL)
  {
    delete socket_mgr_;
    socket_mgr_ = NULL;
  }
}

//============================================================================
bool SliqApp::InitializeSliqApp()
{
  if (initialized_)
  {
    LogW(kClassName, __func__, "Initialize called multiple times.\n");
    return true;
  }

  // Create the necessary socket and connection managers.
  socket_mgr_     = new (std::nothrow) SocketManager();
  connection_mgr_ = new (std::nothrow) ConnectionManager(timer_);

  if ((socket_mgr_ == NULL) || (connection_mgr_ == NULL) ||
      (!socket_mgr_->Initialize()))
  {
    LogE(kClassName, __func__, "Error creating new socket and connection "
         "managers.\n");
    return false;
  }

  initialized_ = true;

  return true;
}

//============================================================================
bool SliqApp::Connect(const Ipv4Endpoint& server_address,
                      const CongCtrl* cc_alg, size_t num_cc_alg,
                      EndptId& endpt_id)
{
  if ((cc_alg == NULL) || (num_cc_alg < 1) || (num_cc_alg > kMaxCcAlgPerConn))
  {
    LogE(kClassName, __func__, "Invalid congestion control algorithm "
         "settings (%p/%zu).\n", cc_alg, num_cc_alg);
    return false;
  }

  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Create a new connection and initialize it as a client.
  EndptId      eid  = 0;
  Connection*  conn = new (std::nothrow)
    Connection(*this, *socket_mgr_, *connection_mgr_, rng_, packet_pool_,
               timer_);

  // Use any local address and an ephemeral port number.
  Ipv4Endpoint  client_address("0.0.0.0", 0);

  if ((conn == NULL) ||
      (!conn->InitClient(client_address, server_address, cc_alg, num_cc_alg,
                         false, eid)))
  {
    LogE(kClassName, __func__, "Error creating a new client connection.\n");
    if (conn != NULL)
    {
      delete conn;
    }
    return false;
  }

  // Attempt to initiate a connection to the specified server and store the
  // connection.  The connect call will not block while the connection attempt
  // is made.
  if ((!conn->ConnectToServer(server_address)) ||
      (!connection_mgr_->AddConnection(eid, conn)))
  {
    delete conn;
    return false;
  }

  // The connection is being established, so return the endpoint identifier.
  endpt_id = eid;

  return true;
}

//============================================================================
bool SliqApp::Listen(const Ipv4Endpoint& server_address, EndptId& endpt_id)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Create a new connection and initialize it as a server listen endpoint.
  Connection*  conn = new (std::nothrow)
    Connection(*this, *socket_mgr_, *connection_mgr_, rng_, packet_pool_,
               timer_);

  if ((conn == NULL) || (!conn->InitServerListen(server_address, endpt_id)))
  {
    LogE(kClassName, __func__, "Error creating a new server listen "
         "connection.\n");
    if (conn != NULL)
    {
      delete conn;
    }
    return false;
  }

  // Store the connection.
  if (!connection_mgr_->AddConnection(endpt_id, conn))
  {
    delete conn;
    return false;
  }

  return true;
}

//============================================================================
bool SliqApp::SetupClientDataEndpoint(const Ipv4Endpoint& client_address,
                                      const Ipv4Endpoint& server_address,
                                      const CongCtrl* cc_alg,
                                      size_t num_cc_alg, EndptId& endpt_id)
{
  if ((cc_alg == NULL) || (num_cc_alg < 1) || (num_cc_alg > kMaxCcAlgPerConn))
  {
    LogE(kClassName, __func__, "Invalid congestion control algorithm "
         "settings (%p/%zu).\n", cc_alg, num_cc_alg);
    return false;
  }

  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Create a new connection and initialize it as a direct client.
  EndptId      eid  = 0;
  Connection*  conn = new (std::nothrow)
    Connection(*this, *socket_mgr_, *connection_mgr_, rng_, packet_pool_,
               timer_);

  if ((conn == NULL) ||
      (!conn->InitClient(client_address, server_address, cc_alg, num_cc_alg,
                         true, eid)))
  {
    LogE(kClassName, __func__, "Error creating a new client connection.\n");
    if (conn != NULL)
    {
      delete conn;
    }
    return false;
  }

  // Attempt to initiate a connection to the specified server and store the
  // connection.  The connect call will not block while the connection attempt
  // is made.
  if ((!conn->ConnectToServer(server_address)) ||
      (!connection_mgr_->AddConnection(eid, conn)))
  {
    delete conn;
    return false;
  }

  // The connection is being established, so return the endpoint identifier.
  endpt_id = eid;

  return true;
}

//============================================================================
bool SliqApp::SetupServerDataEndpoint(const Ipv4Endpoint& server_address,
                                      const Ipv4Endpoint& client_address,
                                      EndptId& endpt_id)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Create a new connection and initialize it as a server data endpoint.
  Connection*  conn = new (std::nothrow)
    Connection(*this, *socket_mgr_, *connection_mgr_, rng_, packet_pool_,
               timer_);

  if ((conn == NULL) ||
      (!conn->InitServerDirectData(server_address, client_address, endpt_id)))
  {
    LogE(kClassName, __func__, "Error creating a new server data "
         "connection.\n");
    if (conn != NULL)
    {
      delete conn;
    }
    return false;
  }

  // Store the connection.
  if (!connection_mgr_->AddConnection(endpt_id, conn))
  {
    delete conn;
    return false;
  }

  return true;
}

//============================================================================
bool SliqApp::AddStream(EndptId endpt_id, StreamId stream_id, Priority prio,
                        const Reliability& rel, DeliveryMode del_mode)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to add the stream.
  return conn->AddStream(stream_id, prio, rel, del_mode);
}

//============================================================================
bool SliqApp::ConfigureTcpFriendliness(EndptId endpt_id, uint32_t num_flows)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to change the setting.
  return conn->ConfigureTcpFriendliness(num_flows);
}

//============================================================================
bool SliqApp::ConfigureRttOutlierRejection(EndptId endpt_id, bool rtt_or)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to change the setting.
  conn->ConfigureRttOutlierRejection(rtt_or);

  return true;
}

//============================================================================
bool SliqApp::ConfigureTransmitQueue(EndptId endpt_id, StreamId stream_id,
                                     size_t max_size_pkts,
                                     DequeueRule dequeue_rule,
                                     DropRule drop_rule)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to configure the stream.
  return conn->ConfigureTransmitQueue(stream_id, max_size_pkts, dequeue_rule,
                                      drop_rule);
}

//============================================================================
bool SliqApp::ConfigureRetransmissionLimit(EndptId endpt_id,
                                           StreamId stream_id,
                                           RexmitLimit rexmit_limit)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to configure the delivery retransmission limit.
  return conn->ConfigureRexmitLimit(stream_id, rexmit_limit);
}

//============================================================================
bool SliqApp::Send(EndptId endpt_id, StreamId stream_id, uint8_t* data,
                   size_t data_len)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  if ((data == NULL) || (data_len < 1))
  {
    LogE(kClassName, __func__, "Invalid data arguments.\n");
    return false;
  }

  // Place the data into a packet and call Send().
  Packet*  pkt = packet_pool_.Get();

  if (pkt == NULL)
  {
    LogE(kClassName, __func__, "Error getting packet from pool.\n");
    return false;
  }

  memcpy(pkt->GetBuffer(), data, data_len);

  if (!pkt->SetLengthInBytes(data_len))
  {
    LogE(kClassName, __func__, "Error setting packet length to %zu.\n",
         data_len);
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(pkt);
    return false;
  }

  // Note that Send() takes ownership of the packet on success.
  if (!Send(endpt_id, stream_id, pkt))
  {
    TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
    packet_pool_.Recycle(pkt);
    return false;
  }

  return true;
}

//============================================================================
bool SliqApp::Send(EndptId endpt_id, StreamId stream_id, Packet* data)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  if ((data == NULL) || ((data->GetMetadataHeaderLengthInBytes() +
                          data->GetLengthInBytes()) < 1))
  {
    LogE(kClassName, __func__, "Invalid data arguments.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call send on the connection.
  return conn->Send(stream_id, data);
}

//============================================================================
bool SliqApp::GetEndpointType(EndptId endpt_id, EndptType& endpt_type)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Get the endpoint type.
  endpt_type = conn->endpt_type();

  return true;
}

//============================================================================
bool SliqApp::IsConnected(EndptId endpt_id) const
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Return the connected status.
  return conn->connected();
}

//============================================================================
bool SliqApp::IsStreamEstablished(EndptId endpt_id, StreamId stream_id) const
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Return the stream's established status.
  return conn->IsStreamEstablished(stream_id);
}

//============================================================================
bool SliqApp::IsInOutage(EndptId endpt_id) const
{
  if (initialized_)
  {
    // Find the connection.
    Connection*  conn = connection_mgr_->GetConnection(endpt_id);

    if (conn != NULL)
    {
      return conn->IsInOutage();
    }
  }

  return true;
}

//============================================================================
bool SliqApp::CloseStream(EndptId endpt_id, StreamId stream_id,
                          bool& fully_closed)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Initiate the closing of the stream.
  return conn->InitiateCloseStream(stream_id, fully_closed);
}

//============================================================================
bool SliqApp::Close(EndptId endpt_id, bool& fully_closed)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Close the connection.
  return conn->InitiateClose(SLIQ_CONN_NORMAL_CLOSE, fully_closed);
}

//============================================================================
size_t SliqApp::GetFileDescriptorList(FdEventInfo* fd_event_array,
                                      size_t array_size) const
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return 0;
  }

  return socket_mgr_->GetFileDescriptors(fd_event_array, array_size);
}

//============================================================================
void SliqApp::SvcFileDescriptor(int fd, FdEvent event)
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return;
  }

  // Find the endpoint ID for the specified file descriptor.  For simplicity,
  // the two are equal.
  EndptId  endpt_id = fd;

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return;
  }

  // Service the file descriptor on the connection.
  conn->ServiceFileDescriptor(fd, event);
}

//============================================================================
bool SliqApp::GetTransmitQueueSizeInBytes(EndptId endpt_id,
                                          StreamId stream_id,
                                          size_t& size) const
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to get the size.
  return conn->GetTransmitQueueSizeInBytes(stream_id, size);
}

//============================================================================
bool SliqApp::GetTransmitQueueSizeInPackets(EndptId endpt_id,
                                            StreamId stream_id,
                                            size_t& size) const
{
  if (!initialized_)
  {
    LogE(kClassName, __func__, "Not initialized.\n");
    return false;
  }

  // Find the connection.
  Connection*  conn = connection_mgr_->GetConnection(endpt_id);

  if (conn == NULL)
  {
    return false;
  }

  // Call into the connection to get the size.
  return conn->GetTransmitQueueSizeInPackets(stream_id, size);
}
