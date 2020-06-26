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

#include "sliq_stream.h"

#include "sliq_cc_copa.h"
#include "sliq_cc_interface.h"
#include "sliq_connection.h"

#include "callback.h"
#include "itime.h"
#include "log.h"
#include "packet.h"
#include "packet_pool.h"
#include "timer.h"
#include "unused.h"

#include <cerrno>
#include <cstring>
#include <inttypes.h>


using ::sliq::Connection;
using ::sliq::DequeueRule;
using ::sliq::DropRule;
using ::sliq::Priority;
using ::sliq::Stream;
using ::sliq::StreamId;
using ::sliq::WindowSize;
using ::iron::CallbackNoArg;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::RNG;
using ::iron::Time;
using ::iron::Timer;


namespace
{

  /// The class name string for logging.
  const char*          UNUSED(kClassName) = "Stream";

  /// The maximum number of pending retransmissions that can be queued.
  const size_t         kMaxRexmitPkts = sliq::kFlowCtrlWindowPkts;

  /// The default transmit queue size in packets.
  const size_t         kDefaultTransmitQueueSizePkts = 64;

  /// The default transmit queue dequeue rule.
  const DequeueRule    kDefaultTransmitQueueDequeueRule = sliq::FIFO_QUEUE;

  /// The default transmit queue drop rule.
  const DropRule       kDefaultTransmitQueueDropRule = sliq::NO_DROP;

  /// The maximum number of times that we'll send a create stream packet.
  const int            kMaxCreateStreams = 32;

  /// The wait time for create stream ACK packets, in seconds.
  const double         kCreateStreamTimerSec = 0.333;

  /// The persist timer duration, in seconds.
  const double         kPersistTimerSec = 1.5;

  /// The minimum persist timer duration, in seconds.
  const double         kMinPersistTimerSec = 5.0;

  /// The maximum persist timer duration, in seconds.
  const double         kMaxPersistTimerSec = 60.0;

  /// The minimum interval between ACKs due to received persist packets, in
  /// seconds.
  const double         kMinPersistAckTimeSec = 0.2;

} // namespace


//============================================================================
Stream::Stream(Connection& connection, RttManager& rtt_mgr,
               CcAlgs& cc_algs, RNG& rng, PacketPool& packet_pool,
               Timer& timer, EndptId conn_id, StreamId stream_id,
               Priority priority)
    : connection_(connection),
      rtt_mgr_(rtt_mgr),
      cc_algs_(cc_algs),
      rng_(rng),
      packet_pool_(packet_pool),
      timer_(timer),
      sent_pkt_mgr_(connection, *this, rtt_mgr, packet_pool, cc_algs, conn_id,
                    stream_id),
      rcvd_pkt_mgr_(connection, packet_pool, conn_id, stream_id),
      conn_id_(conn_id),
      stream_id_(stream_id),
      priority_(priority),
      rel_(),
      delivery_mode_(ORDERED_DELIVERY),
      is_established_(false),
      fin_buffered_(false),
      fin_sent_(false),
      fin_received_(false),
      reset_sent_(false),
      reset_received_(false),
      read_side_closed_(false),
      write_side_closed_(false),
      initial_send_seq_num_(0),
      rexmit_queue_head_(0),
      rexmit_queue_size_(0),
      rexmit_queue_flags_(NULL),
      rexmit_queue_(NULL),
      transmit_queue_(packet_pool, kDefaultTransmitQueueSizePkts,
                      kDefaultTransmitQueueDequeueRule,
                      kDefaultTransmitQueueDropRule),
      num_creates_(0),
      create_stream_timer_(),
      num_persists_(0),
      persist_timer_(),
      persist_ack_time_(),
      rto_time_(),
      fec_group_timer_()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Creating stream ID %"
       PRIStreamId ".\n", conn_id_, stream_id_);
#endif

  // Initialize the stream-level retransmission count statistics.
  for (size_t i = 0; i < kRexmitCntStatsSize; ++i)
  {
    rexmit_cnt_[i] = 0;
  }
}

//============================================================================
Stream::~Stream()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Destroying stream ID %"
       PRIStreamId ".\n", conn_id_, stream_id_);
#endif

  // Log the stream-level retransmission count statistics.
  LogI(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       " sent rexmit counts: 0:%zu 1:%zu 2:%zu 3:%zu 4:%zu 5:%zu 6:%zu 7:%zu "
       "8:%zu 9:%zu 10:%zu\n", conn_id_, stream_id_, rexmit_cnt_[0],
       rexmit_cnt_[1], rexmit_cnt_[2], rexmit_cnt_[3], rexmit_cnt_[4],
       rexmit_cnt_[5], rexmit_cnt_[6], rexmit_cnt_[7], rexmit_cnt_[8],
       rexmit_cnt_[9], rexmit_cnt_[10]);

  // Delete the retransmit queue.
  if (rexmit_queue_flags_ != NULL)
  {
    delete [] rexmit_queue_flags_;
    rexmit_queue_flags_ = NULL;
  }

  if (rexmit_queue_ != NULL)
  {
    delete [] rexmit_queue_;
    rexmit_queue_ = NULL;
  }

  // Cancel any timers.
  CancelAllTimers();

  // Clean up the timer callback object pools.
  CallbackNoArg<Stream>::EmptyPool();
}

//============================================================================
bool Stream::InitializeLocalStream(const Reliability& rel,
                                   DeliveryMode del_mode)
{
  if (is_established_)
  {
    return false;
  }

  // Allocate the retransmit queue.
  if (!AllocateRetransmitQueue())
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error allocating retransmit queue.\n", conn_id_, stream_id_);
    return false;
  }

  // Store the settings.
  rel_           = rel;
  delivery_mode_ = del_mode;

  // Select an initial packet sequence number for the stream.
  initial_send_seq_num_ = rng_.GetInt(kInitSeqNumRange);

  // Inform the congestion control algorithms about the new stream.
  ActivateStream();

  // Set a timer for how long to wait for a create stream ACK packet.
  Time                   duration(kCreateStreamTimerSec);
  CallbackNoArg<Stream>  callback(this, &Stream::CreateStreamTimeout);

  if (!timer_.StartTimer(duration, &callback, create_stream_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error starting create stream timer.\n", conn_id_, stream_id_);
    DeactivateStream();
    return false;
  }

  // Send a create stream packet to the peer.
  if (!connection_.SendCreateStreamPkt(false, delivery_mode_, rel_,
                                       stream_id_, priority_,
                                       kFlowCtrlWindowPkts,
                                       initial_send_seq_num_))
  {
    timer_.CancelTimer(create_stream_timer_);
    DeactivateStream();
    return false;
  }

  // Record the transmission.
  num_creates_ = 1;

  return true;
}

//============================================================================
bool Stream::InitializeRemoteStream(CreateStreamHeader& hdr)
{
  if (is_established_)
  {
    return false;
  }

  // Allocate the retransmit queue.
  if (!AllocateRetransmitQueue())
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error allocating retransmit queue.\n", conn_id_, stream_id_);
    return false;
  }

  // Store the settings.
  hdr.GetReliability(rel_);
  delivery_mode_ = hdr.delivery_mode;

  // Select an initial packet sequence number for the stream.
  initial_send_seq_num_ = rng_.GetInt(kInitSeqNumRange);

  // Inform the congestion control algorithms about the new stream.
  ActivateStream();

  // Initialize the sent packet manager.
  if (!sent_pkt_mgr_.Initialize(rel_, initial_send_seq_num_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error initializing sent packet manager.\n", conn_id_, stream_id_);
    DeactivateStream();
    return false;
  }

  // Initialize the received packet manager.
  if (!rcvd_pkt_mgr_.Initialize(rel_, delivery_mode_, hdr.initial_seq_num))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error initializing received packet manager.\n", conn_id_,
         stream_id_);
    DeactivateStream();
    return false;
  }

  // Send back a create stream ACK packet to the peer.
  if (!connection_.SendCreateStreamPkt(true, delivery_mode_, rel_, stream_id_,
                                       priority_, kFlowCtrlWindowPkts,
                                       initial_send_seq_num_))
  {
    DeactivateStream();
    return false;
  }

  // The stream is now established.
  is_established_ = true;

  return true;
}

//============================================================================
bool Stream::ConfigureTransmitQueue(size_t max_size_pkts,
                                    DequeueRule dequeue_rule,
                                    DropRule drop_rule)
{
  // Reconfigure the transmit queue.
  bool  rv = transmit_queue_.Reconfigure(max_size_pkts, dequeue_rule,
                                         drop_rule);

#ifdef SLIQ_DEBUG
  if (rv)
  {
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Configured transmit queue with: size %zu dequeue_rule %d "
         "drop_rule %d\n", conn_id_, stream_id_, max_size_pkts, dequeue_rule,
         drop_rule);
  }
#endif

  return rv;
}

//============================================================================
bool Stream::ConfigureRexmitLimit(RexmitLimit rexmit_limit)
{
  if (rel_.mode == SEMI_RELIABLE_ARQ)
  {
    if (rexmit_limit < 1)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error setting delivery retransmission limit to %" PRIRexmitLimit
           " for ARQ mode.\n", conn_id_, stream_id_, rexmit_limit);
      return false;
    }
  }
  else if (rel_.mode == SEMI_RELIABLE_ARQ_FEC)
  {
    if ((!rel_.fec_del_time_flag) &&
        ((rel_.fec_target_pkt_del_rounds < 1) ||
         (rexmit_limit < (rel_.fec_target_pkt_del_rounds - 1))))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error setting delivery retransmission limit to %" PRIRexmitLimit
           " with target rounds set to %" PRIRexmitRounds " for FEC mode.\n",
           conn_id_, stream_id_, rexmit_limit,
           rel_.fec_target_pkt_del_rounds);
      return false;
    }
  }
  else
  {
    LogE(kClassName, __func__, "Invalid reliability mode for setting "
         "retranmission limit.\n");
    return false;
  }

  // Configure the local components.
  rel_.rexmit_limit = rexmit_limit;

  // Update the sent packet manager.
  sent_pkt_mgr_.SetRexmitLimit(rexmit_limit);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Configured delivery retransmission limit to %" PRIRexmitLimit ".\n",
       conn_id_, stream_id_, rexmit_limit);
#endif

  return true;
}

//============================================================================
bool Stream::Send(Packet* data, bool fin)
{
  if (((data == NULL) && (!fin)) || (!is_established_) || fin_buffered_ ||
      write_side_closed_)
  {
    return false;
  }

  // Get the data length.
  size_t  data_len = ((data != NULL) ?
                      (data->GetMetadataHeaderLengthInBytes() +
                       data->GetLengthInBytes()) : 0);

  // Warn if this packet might be fragmented by IP.  Include the move forward
  // field if the stream is not using full reliability, since it can be added
  // whenever needed.  Include the FEC fields if the stream is using FEC.  Use
  // the encoded data packet header fields since they will be at least the
  // size of this packet.
  size_t  data_hdr_len = (kDataHdrBaseSize +
                          ((rel_.mode != RELIABLE_ARQ) ?
                           kDataHdrMoveFwdSize : 0) +
                          ((rel_.mode == SEMI_RELIABLE_ARQ_FEC) ?
                           (kDataHdrFecSize + kDataHdrEncPktLenSize) : 0));

  if (data_len > (kMaxPacketSize - data_hdr_len))
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Warning, payload length %zu may be fragmented by IP.\n", conn_id_,
         stream_id_, data_len);
  }

  // Get the current time.
  Time  now = Time::Now();

  // If there is at least one packet in the original FEC encoded packet queue
  // (for unsent FEC encoded packets generated in round 1) or transmit queues,
  // or flow control is blocked, or congestion control is blocked, or send
  // pacing does not allow the send right now, or the connection is write
  // blocked, then this data must be placed in the transmit queue.  Note that
  // the Connection::CanSend() call will fill in the cc_id.
  CcId  cc_id = 0;

  if ((sent_pkt_mgr_.OrigFecEncPktsToBeSent() > 0) ||
      (transmit_queue_.GetSizeInPackets() > 0) ||
      (!sent_pkt_mgr_.CanSend()) ||
      (!connection_.CanSend(now, data_len, cc_id)) ||
      (connection_.IsWriteBlocked()))
  {
    if (data != NULL)
    {
      if (!transmit_queue_.Enqueue(data, now))
      {
        return false;
      }

      // Inform the application of the updated transmit queue size.
      connection_.TransmitQueueSizeCallback(stream_id_,
                                            transmit_queue_.GetSizeInBytes());
    }

    if (fin)
    {
      fin_buffered_ = true;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Added FIN to transmit queue.\n", conn_id_, stream_id_);
#endif
    }

    return true;
  }

  // The FEC and transmit queues are empty.  Attempt to send the data
  // immediately.
  DataHeader  hdr;
  bool        new_fec_grp = false;
  bool        fec_grp_end = false;

  // Prepare the next data packet.  Note that this call also updates the send
  // window.
  if (!sent_pkt_mgr_.PrepareNextPkt(data, cc_id, fin, now, hdr, new_fec_grp))
  {
    // The stream has somehow gone off the end of the send window.
    ResetStream(SLIQ_STREAM_FLOW_CONTROL_ERROR);
    return false;
  }

  // Send the data.
  WriteResult  result;
  size_t       bytes = 0;

  SendData(now, hdr, data, result, bytes);

  // The queueing delay was zero.
  Time  queueing_delay;

  queueing_delay.Zero();

  // Handle the result.
  if (result.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Transmit of data packet seq %" PRIPktSeqNumber " size %zu bytes "
         "queueing delay %" PRId64 " us.\n", conn_id_, stream_id_,
         hdr.sequence_number, bytes, queueing_delay.GetTimeInUsec());
#endif

    // Add the packet to the sent packet manager.
    sent_pkt_mgr_.AddSentPkt(hdr, data, bytes, connection_.GetConnSeqNum(),
                             connection_.GetSentPktCnt(), now, queueing_delay,
                             false, fec_grp_end);
  }
  else if (result.status == WRITE_STATUS_BLOCKED)
  {
    // Add the packet to the sent packet manager, noting that the send
    // blocked so the packet can be sent later.
    sent_pkt_mgr_.AddSentPkt(hdr, data, bytes, connection_.GetConnSeqNum(),
                             connection_.GetSentPktCnt(), now, queueing_delay,
                             true, fec_grp_end);
  }
  else if (result.status == WRITE_STATUS_ERROR)
  {
    // There was a send error.  Do not take ownership of the data.
    return false;
  }

  // If this is the end of the current FEC group, then stop the FEC group
  // timer.
  if (fec_grp_end)
  {
    timer_.CancelTimer(fec_group_timer_);
  }
  else
  {
    // If this is the first FEC source data packet of a new FEC group, then
    // start an FEC group timer.
    if (new_fec_grp)
    {
      StartFecGroupTimer();
    }
  }

  return true;
}

//============================================================================
bool Stream::SendAnyBlockedPackets()
{
  if ((!is_established_) || write_side_closed_)
  {
    return true;
  }

  DataHeader   hdr;
  Packet*      data  = NULL;
  bool         rv    = true;
  size_t       bytes = 0;
  WriteResult  result;

  // Get any blocked packets and send them.
  while (sent_pkt_mgr_.GetBlockedPkt(hdr, data))
  {
    // Get the current time.
    Time  now = Time::Now();

    // Send the data immediately.
    SendData(now, hdr, data, result, bytes);

    // Handle the result.
    if (result.status == WRITE_STATUS_OK)
    {
      // Set the packet as unblocked in the sent packet manager.
      sent_pkt_mgr_.SetPktUnblocked(hdr, bytes, connection_.GetSentPktCnt(),
                                    now);
    }
    else if (result.status == WRITE_STATUS_BLOCKED)
    {
      // The blocked packet is still in the sent packet manager.  It still
      // does not have a valid retransmission time.
      rv = false;
      break;
    }
    else if (result.status == WRITE_STATUS_ERROR)
    {
      // There was a send error.  The packet is still in the sent packet
      // manager.
      break;
    }
  }

  return rv;
}

//============================================================================
bool Stream::OnCanSend(size_t& num_sends)
{
  // The stream must be established, the write side must not be closed, and
  // flow control must not be blocked.
  if ((!is_established_) || write_side_closed_ || (!sent_pkt_mgr_.CanSend()))
  {
    return true;
  }

  // Check for a new data packet to be sent.
  bool  send_xq  = (transmit_queue_.GetSizeInPackets() > 0);

  if ((!send_xq) && (!fin_buffered_))
  {
    return true;
  }

  // If the only thing to be sent is the buffered FIN, then give the sent
  // packet manager a chance to complete any FEC block that might have been
  // started before sending the FIN.
  if ((rel_.mode == SEMI_RELIABLE_ARQ_FEC) && (!send_xq) && fin_buffered_)
  {
    // Call into the sent packet manager to end the current FEC group.
    sent_pkt_mgr_.ForceFecGroupToEnd();

    // Check for new original FEC encoded packets (unsent FEC encoded packets
    // generated in round 1) to send before the FIN.
    if (sent_pkt_mgr_.OrigFecEncPktsToBeSent() > 0)
    {
      return OnCanXmitOrigFecEncPkt(num_sends);
    }
  }

  // Get the current time.
  Time  now = Time::Now();

  // Get the data length.  Data packets in the transmit queue come before a
  // buffered FIN.
  size_t  data_len = 0;

  if (send_xq)
  {
    data_len = transmit_queue_.GetNextDequeueSizeInBytes();
  }

  // Check that congestion control will allow sending the packet.  This
  // involves the congestion control send pacing and CanSend() checks.
  CcId  cc_id = 0;

  if (!connection_.CanSend(now, data_len, cc_id))
  {
    return false;
  }

  // Get the next data packet to be sent.
  Time        queueing_delay;
  DataHeader  hdr;
  Packet*     data        = NULL;
  bool        fin         = false;
  bool        new_fec_grp = false;

  if (send_xq)
  {
    // Get the data packet from the transmit queue.
    data = transmit_queue_.Dequeue(now, queueing_delay);

    if (data == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error getting data from transmit queue.\n", conn_id_,
           stream_id_);
      ResetStream(SLIQ_STREAM_TRANSMIT_QUEUE_ERROR);
      return true;
    }

    // Inform the application of the updated transmit queue size.
    connection_.TransmitQueueSizeCallback(
      stream_id_, transmit_queue_.GetSizeInBytes());
  }
  else if (fin_buffered_)
  {
    // Create a data packet for the FIN.
    fin           = true;
    fin_buffered_ = false;
  }
  else
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error getting data to send.\n", conn_id_, stream_id_);
    ResetStream(SLIQ_STREAM_TRANSMIT_QUEUE_ERROR);
    return true;
  }

  // Prepare the next data packet.  Note that this call also updates the
  // send window.
  if (!sent_pkt_mgr_.PrepareNextPkt(data, cc_id, fin, now, hdr, new_fec_grp))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error preparing next packet to send.\n", conn_id_, stream_id_);
    if (data != NULL)
    {
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(data);
    }
    // The stream has somehow gone off the end of the send window.
    ResetStream(SLIQ_STREAM_FLOW_CONTROL_ERROR);
    return true;
  }

  // Do the send.
  WriteResult  result;
  size_t       bytes       = 0;
  bool         fec_grp_end = false;

  SendData(now, hdr, data, result, bytes);

  // Handle the result.
  if (result.status == WRITE_STATUS_OK)
  {
    // Add the packet to the sent packet manager.
    sent_pkt_mgr_.AddSentPkt(hdr, data, bytes, connection_.GetConnSeqNum(),
                             connection_.GetSentPktCnt(), now, queueing_delay,
                             false, fec_grp_end);

    ++num_sends;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Transmit of data packet seq %" PRIPktSeqNumber " size %zu bytes "
         "queueing delay %" PRId64 " us.\n", conn_id_, stream_id_,
         hdr.sequence_number, bytes, queueing_delay.GetTimeInUsec());
#endif
  }
  else if (result.status == WRITE_STATUS_BLOCKED)
  {
    // Add the packet to the sent packet manager, noting that the send blocked
    // so the packet can be sent later.  This packet will not have a
    // retransmission time yet.
    sent_pkt_mgr_.AddSentPkt(hdr, data, bytes, connection_.GetConnSeqNum(),
                             connection_.GetSentPktCnt(), now, queueing_delay,
                             true, fec_grp_end);
  }
  else if (result.status == WRITE_STATUS_ERROR)
  {
    // There was a send error.  Release any data from the transmit queue.
    if (data != NULL)
    {
      TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);
      packet_pool_.Recycle(data);
    }

    return true;
  }

  // If this is the end of the current FEC group, then stop the FEC group
  // timer.
  if (fec_grp_end)
  {
    timer_.CancelTimer(fec_group_timer_);
  }
  else
  {
    // If this is the first FEC source data packet of a new FEC group, then
    // start an FEC group timer.
    if (new_fec_grp)
    {
      StartFecGroupTimer();
    }
  }

  return true;
}

//============================================================================
bool Stream::OnCanFastRexmit(size_t& num_sends)
{
  // First, attempt to send one original FEC encoded packet (an unsent FEC
  // encoded packet generated in round 1).  These can occur when the write
  // side is closed.  These depend on flow control, congestion control, and
  // send pacing checks.
  if ((is_established_) && (sent_pkt_mgr_.OrigFecEncPktsToBeSent() > 0))
  {
    // Check that flow control will allow sending the packet here.  If flow
    // control will not allow the original FEC encoded packet to be sent, then
    // go ahead and attempt to send a fast retransmission instead.
    if (sent_pkt_mgr_.CanSend())
    {
      return OnCanXmitOrigFecEncPkt(num_sends);
    }
  }

  // There are no original FEC encoded packets to be sent.  Attempt to send
  // one fast retransmission.  These can occur when the write side is closed.
  // Fast retransmissions do not depend on flow control, but do depend on
  // congestion control and send pacing checks.
  if ((is_established_) && (rexmit_queue_ != NULL) &&
      (rexmit_queue_size_ > 0))
  {
    PktSeqNumber  rexmit_seq_num = 0;
    size_t        data_len       = 0;
    CcId          orig_cc_id     = 0;
    bool          addl           = false;
    bool          rexmit_found   = false;

    // Get the next retransmission packet (normal, FEC source, or FEC encoded
    // packet that has already been sent at least once) or additional FEC
    // encoded packet (unsent FEC encoded packets generated in round 2+).
    // Retransmission packets must not have been ACKed, but have an
    // orig_cc_id.  Additional FEC encoded packets have never been sent before
    // and do not have an orig_cc_id.
    while (rexmit_queue_size_ > 0)
    {
      addl           = ((rexmit_queue_flags_[(rexmit_queue_head_ / 64)] &
                         (static_cast<uint64_t>(0x1) <<
                          (rexmit_queue_head_ % 64))) != 0);
      rexmit_seq_num = rexmit_queue_[rexmit_queue_head_];

      if (sent_pkt_mgr_.GetRexmitPktLen(rexmit_seq_num, addl, data_len,
                                        orig_cc_id))
      {
        rexmit_found = true;
        break;
      }

      // Remove the ACKed packet from the retransmit queue and try again.
      --rexmit_queue_size_;
      rexmit_queue_head_ = ((rexmit_queue_head_ + 1) % kMaxRexmitPkts);
    }

    if (!rexmit_found)
    {
      return true;
    }

    // Get the current time.
    Time  now = Time::Now();

    // Check that congestion control will allow either resending the
    // retransmission packet or sending the additional FEC encoded packet.
    // This involves the congestion control resend pacing, and the congestion
    // control CanResend() or CanSend() checks.
    CcId  cc_id = 0;

    if (addl)
    {
      if (!connection_.CanSend(now, data_len, cc_id))
      {
        return false;
      }
    }
    else
    {
      if (!connection_.CanResend(now, data_len, orig_cc_id, cc_id))
      {
        return false;
      }
    }

    // The retransmission can be sent.  Remove the packet from the retransmit
    // queue.
    --rexmit_queue_size_;
    rexmit_queue_head_ = ((rexmit_queue_head_ + 1) % kMaxRexmitPkts);

    // Get access to the packet for retransmission.
    DataHeader    hdr;
    Packet*       data = NULL;

    if (!sent_pkt_mgr_.GetRexmitPkt(now, rexmit_seq_num, addl, false, cc_id,
                                    hdr, data))
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Unable to get data packet seq %" PRIPktSeqNumber " for "
           "retransmission.\n", conn_id_, stream_id_, rexmit_seq_num);
      return true;
    }

    // Use the CC ID that is allowing the resend in the data header.
    hdr.cc_id = cc_id;

    // Send the retransmission.
    WriteResult  result;
    size_t       bytes = 0;

    SendData(now, hdr, data, result, bytes);

    // Handle the result.
    if (result.status == WRITE_STATUS_OK)
    {
      ++num_sends;

      // For an additional FEC encoded packet, this is its first transmission,
      // so get its connection sequence number.
      PktSeqNumber  conn_seq = 0;

      if (addl)
      {
        conn_seq = connection_.GetConnSeqNum();
      }

      // Update the packet that was just resent.
      sent_pkt_mgr_.SentRexmitPkt(hdr, bytes, conn_seq,
                                  connection_.GetSentPktCnt(), cc_id, addl,
                                  false, now);

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Retransmit of data packet seq %" PRIPktSeqNumber " cc_id %"
           PRICcId " bytes %zu.\n", conn_id_, stream_id_, rexmit_seq_num,
           cc_id, bytes);
#endif
    }
    else if (result.status == WRITE_STATUS_BLOCKED)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Blocked send of data packet seq %" PRIPktSeqNumber " for "
           "retransmission.\n", conn_id_, stream_id_, rexmit_seq_num);
      return true;
    }
    else if (result.status == WRITE_STATUS_ERROR)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error sending data packet seq %" PRIPktSeqNumber " for "
           "retransmission.\n", conn_id_, stream_id_, rexmit_seq_num);
      return true;
    }
  }

  return true;
}

//============================================================================
void Stream::ProcessCreateStream(CreateStreamHeader& hdr)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Received create stream packet.\n", conn_id_, stream_id_);
#endif

  // Validate the packet.
  Reliability  hdr_rel;

  hdr.GetReliability(hdr_rel);

  if ((delivery_mode_ != hdr.delivery_mode) || (priority_ != hdr.priority) ||
      (rel_ != hdr_rel))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Invalid create stream packet received, ignoring.\n", conn_id_,
         stream_id_);
    return;
  }

  // Send another create stream ACK packet to the peer.
  if (!connection_.SendCreateStreamPkt(true, delivery_mode_, rel_, stream_id_,
                                       priority_, kFlowCtrlWindowPkts,
                                       initial_send_seq_num_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error sending additional create stream ACK packet.\n", conn_id_,
         stream_id_);
  }
}

//============================================================================
void Stream::ProcessCreateStreamAck(CreateStreamHeader& hdr)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Received create stream ACK packet.\n", conn_id_, stream_id_);
#endif

  // Ignore duplicates.
  if (is_established_)
  {
    return;
  }

  // Validate the packet.
  Reliability  hdr_rel;

  hdr.GetReliability(hdr_rel);

  if ((delivery_mode_ != hdr.delivery_mode) || (priority_ != hdr.priority) ||
      (rel_ != hdr_rel))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Invalid create stream ACK packet received, ignoring.\n", conn_id_,
         stream_id_);
    return;
  }

  // Initialize the sent packet manager.
  if (!sent_pkt_mgr_.Initialize(rel_, initial_send_seq_num_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error initializing sent packet manager.\n", conn_id_, stream_id_);
    return;
  }

  // Initialize the received packet manager.
  if (!rcvd_pkt_mgr_.Initialize(rel_, delivery_mode_, hdr.initial_seq_num))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error initializing received packet manager.\n", conn_id_,
         stream_id_);
    return;
  }

  // The stream is now established.
  is_established_ = true;

  // Cancel the create stream timer.
  timer_.CancelTimer(create_stream_timer_);
}

//============================================================================
void Stream::ProcessResetStream()
{
  // Ignore duplicates.
  if (reset_received_)
  {
    return;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Received reset stream packet.\n", conn_id_, stream_id_);
#endif

  reset_received_ = true;

  // Close the stream.
  ImmediateFullClose();
}

//============================================================================
bool Stream::IsGoodDataPacket(DataHeader& hdr)
{
  // The stream must already be established.
  if (!is_established_)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error, stream not established or read side is closed.\n",
         conn_id_, stream_id_);
    return false;
  }

  // The read-side must not be closed.
  if (read_side_closed_)
  {
    return false;
  }

  // If this is a persist packet, then it should always be processed.
  if (hdr.persist_flag)
  {
    return true;
  }

  // Check if this is a duplicate data packet.
  return rcvd_pkt_mgr_.IsGoodDataPacket(hdr);
}

//============================================================================
bool Stream::ProcessData(DataHeader& hdr, const Time& rcv_time, bool& ack_now)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Received data packet seq %" PRIPktSeqNumber " with %zu byte "
       "payload.\n", conn_id_, stream_id_, hdr.sequence_number,
       hdr.payload_length);
#endif

  // Record if a move forward must be done later.
  bool          do_move_fwd  = false;
  PktSeqNumber  move_fwd_seq = 0;

  if (hdr.move_fwd_flag)
  {
    if (rel_.mode == RELIABLE_ARQ)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error, cannot process received move forward in current "
           "reliability mode.\n", conn_id_, stream_id_);
    }
    else
    {
      do_move_fwd  = true;
      move_fwd_seq = hdr.move_fwd_seq_num;
    }
  }

  // If this is a persist packet, then do any move forward processing and
  // possibly allow generation of an ACK packet immediately.  The packet is
  // not to be added to the received packet manager.
  if (hdr.persist_flag)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Received persist data packet, sending ACK immediately.\n",
         conn_id_, stream_id_);
#endif

    if (do_move_fwd)
    {
      rcvd_pkt_mgr_.MoveForward(move_fwd_seq);
    }

    // Limit the number of ACKs that are sent due to persists.
    Time  next_ack_time = persist_ack_time_.Add(kMinPersistAckTimeSec);

    if (rcv_time >= next_ack_time)
    {
      ack_now           = true;
      persist_ack_time_ = rcv_time;
    }
    else
    {
      ack_now = false;
    }

    return false;
  }

  // Add the packet to the received packet manager.  This always takes
  // ownership of the packet and will determine if an ACK packet should be
  // sent immediately or not.
  ack_now = rcvd_pkt_mgr_.AddPkt(hdr, rcv_time);

  // Pass received data to the application.
  Packet*  data        = NULL;
  size_t   data_offset = 0;
  size_t   data_length = 0;
  bool     fin         = false;

  while (rcvd_pkt_mgr_.GetNextAppPkt(data, data_offset, data_length, fin))
  {
    if (data == NULL)
    {
      LogF(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": NULL application data packet.\n", conn_id_, stream_id_);
      continue;
    }

    if (data_length > 0)
    {
      data->RemoveBytesFromBeginning(data_offset);

      // Deliver data to the application, which takes ownership of data.
      connection_.RecvCallback(stream_id_, data);

      data = NULL;
    }
    else
    {
      // Recycle the data.
      packet_pool_.Recycle(data);
      data = NULL;
    }
  }

  // Do any move forward processing now.  It will decide if an ACK packet
  // should be sent immediately.
  if (do_move_fwd)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Received move forward seq %" PRIPktSeqNumber ".\n", conn_id_,
         stream_id_, move_fwd_seq);
#endif

    ack_now |= rcvd_pkt_mgr_.MoveForward(move_fwd_seq);
  }

  // Check if all of the data, including the FIN, has been consumed.
  if (rcvd_pkt_mgr_.IsAllDataAndFinConsumed())
  {
    // Send an ACK packet immediately.
    ack_now = true;

    // The read side is now closed.
    fin_received_     = true;
    read_side_closed_ = true;

    // Notify the application of the stream close now that all of the data is
    // delivered to the application.
    connection_.CloseStreamCallback(stream_id_, (read_side_closed_ &&
                                                 write_side_closed_));
  }

  return true;
}

//============================================================================
bool Stream::IsGoodAckPacket(AckHeader& hdr)
{
  // Check if this is a duplicate ACK packet.
  return sent_pkt_mgr_.IsGoodAckPacket(hdr);
}

//============================================================================
bool Stream::ProcessAck(AckHeader& hdr, const Time& rcv_time, const Time& now,
                        bool leaving_outage, bool& new_data_acked,
                        bool& all_data_acked, PktSeqNumber& lo_conn_seq)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Received ACK packet.\n", conn_id_, stream_id_);
#endif

  // Process the ACK packet.
  if (!sent_pkt_mgr_.ProcessAck(hdr, rcv_time, now, new_data_acked,
                                lo_conn_seq))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error processing received ACK packet.\n", conn_id_, stream_id_);
    all_data_acked = sent_pkt_mgr_.IsAllDataAcked();
    return false;
  }

  // Check if all of the data has been ACKed or not.
  all_data_acked = sent_pkt_mgr_.IsAllDataAcked();

  // If the FIN has been sent, then set the retransmission timer.  Set the
  // new_data_acked and all_data_acked flags to true and false to keep the
  // connection-level RTO timer going.
  if (sent_pkt_mgr_.HasFinBeenSent())
  {
    rto_time_ = (now + rtt_mgr_.GetRtoTime());
    new_data_acked = true;
    all_data_acked = false;
  }
  // If all of the data has been ACKed, then stop the retransmission timer.
  else if (all_data_acked)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": All data ACKed, cancel retransmit timer.\n", conn_id_,
         stream_id_);
#endif

    rto_time_.Zero();
  }
  // If not all of the data has been ACKed and new data was ACKed in the ACK,
  // then set the retransmission timer expiration time.
  else if (new_data_acked)
  {
    rto_time_ = (now + rtt_mgr_.GetRtoTime());
  }

  // If the receive window is zero, then start a persist timer.  Otherwise,
  // cancel any persist timer.
  if (!sent_pkt_mgr_.CanSend())
  {
    StartPersistTimer();
  }
  else
  {
    timer_.CancelTimer(persist_timer_);
  }

  return true;
}

//============================================================================
void Stream::ProcessImplicitAck(const Time& now, PktSeqNumber lo_conn_seq)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Processing implicit ACK for largest observed connection seq %"
       PRIPktSeqNumber ".\n", conn_id_, stream_id_, lo_conn_seq);
#endif

  // Process the implicit ACK.
  sent_pkt_mgr_.ProcessImplicitAck(now, lo_conn_seq);
}

//============================================================================
bool Stream::AddFastRexmitPkt(PktSeqNumber seq)
{
  // Check if the retransmission queue is full.
  if ((rexmit_queue_ == NULL) || (rexmit_queue_size_ >= kMaxRexmitPkts))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Retransmit queue full.\n", conn_id_, stream_id_);
    return false;
  }

  // Add the data packet to the tail of the retransmission queue and mark it
  // as a retransmission (a normal, FEC source, or FEC encoded packet that has
  // already been sent at least once) by clearing the flag.
  size_t  idx = ((rexmit_queue_head_ + rexmit_queue_size_) % kMaxRexmitPkts);

  rexmit_queue_flags_[(idx / 64)] &= ~(static_cast<uint64_t>(0x1) <<
                                       (idx % 64));
  rexmit_queue_[idx]               = seq;
  ++rexmit_queue_size_;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Scheduling fast retransmit of data packet seq %" PRIPktSeqNumber
       ", queue size %zu.\n", conn_id_, stream_id_, seq, rexmit_queue_size_);
#endif

  return true;
}

//============================================================================
bool Stream::AddAddlFecEncPkt(PktSeqNumber tmp_seq)
{
  // Check if the retransmission queue is full.
  if ((rexmit_queue_ == NULL) || (rexmit_queue_size_ >= kMaxRexmitPkts))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Retransmit queue full.\n", conn_id_, stream_id_);
    return false;
  }

  // Add the newly generated FEC encoded data packet to the tail of the
  // retransmission queue and mark it as an additional FEC encoded packet (an
  // unsent FEC encoded packet generated in round 2+) by setting the flag.
  size_t  idx = ((rexmit_queue_head_ + rexmit_queue_size_) % kMaxRexmitPkts);

  rexmit_queue_flags_[(idx / 64)] |= (static_cast<uint64_t>(0x1) <<
                                      (idx % 64));
  rexmit_queue_[idx]               = tmp_seq;
  ++rexmit_queue_size_;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Scheduling transmit of addl FEC encoded packet tmp_seq %"
       PRIPktSeqNumber ", queue size %zu.\n", conn_id_, stream_id_, tmp_seq,
       rexmit_queue_size_);
#endif

  return true;
}

//============================================================================
void Stream::RtoCheck(const Time& now)
{
  // Check if there is a retransmission timer expiration.
  if (((!sent_pkt_mgr_.IsAllDataAcked()) ||
       (sent_pkt_mgr_.HasFinBeenSent())) &&
      (!rto_time_.IsZero()) && (now >= rto_time_))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Rexmit timeout.\n", conn_id_, stream_id_);
#endif

    // Retransmit the oldest unACKed data packet.
    if (!RexmitPkt(now, true, true))
    {
      // Send a persist packet associated with the first congestion control
      // algorithm.
      if (!SendPersist(now, 0))
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Unable to resend packet during RTO.\n", conn_id_, stream_id_);
      }
    }

    // Reset the retransmission timer expiration time.
    rto_time_ = (now + rtt_mgr_.GetRtoTime());
  }
}

//============================================================================
bool Stream::RexmitPkt(const Time& now, bool lowest, bool rto_outage)
{
  if (!is_established_)
  {
    return false;
  }

  // Get the data packet sequence number that requires retransmission.
  PktSeqNumber  seq_num = 0;
  CcId          cc_id   = 0;

  if (!sent_pkt_mgr_.GetRexmitPktSeqNum(now, lowest, seq_num, cc_id))
  {
    return false;
  }

  // Get the packet for retransmission.  Since CanSend() was not called for
  // this method, use the packet's associated CC ID.
  DataHeader  hdr;
  Packet*     data = NULL;

  if (!sent_pkt_mgr_.GetRexmitPkt(now, seq_num, false, rto_outage, cc_id, hdr,
                                  data))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error getting data packet seq %" PRIPktSeqNumber " for "
         "retransmission.\n", conn_id_, stream_id_, seq_num);
    return false;
  }

  // Send the retransmission.
  WriteResult  result;
  size_t       bytes = 0;

  SendData(now, hdr, data, result, bytes);

  // Handle the result.
  if (result.status == WRITE_STATUS_BLOCKED)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Blocked send of data packet seq %" PRIPktSeqNumber ".\n",
         conn_id_, stream_id_, seq_num);
    return true;
  }
  else if (result.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error sending data packet seq %" PRIPktSeqNumber ".\n", conn_id_,
         stream_id_, seq_num);
    return false;
  }

  // Update the packet that was just resent.
  sent_pkt_mgr_.SentRexmitPkt(hdr, bytes, 0, connection_.GetSentPktCnt(),
                              cc_id, false, rto_outage, now);

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Retransmit of data packet seq %" PRIPktSeqNumber " bytes %zu.\n",
       conn_id_, stream_id_, seq_num, bytes);
#endif

  return true;
}

//============================================================================
bool Stream::SendPersist(const Time& now, CcId cc_id)
{
  if (!is_established_)
  {
    return false;
  }

  // Set up the data header.
  DataHeader  hdr(false, false, false, true, false, stream_id_, 0, cc_id, 0,
                  sent_pkt_mgr_.GetMaxSeqNumSent(), 0, 0, 0, FEC_SRC_PKT, 0,
                  0, 0, 0, 0);

  // Send the persist.
  WriteResult  result;
  size_t       bytes = 0;

  SendData(now, hdr, NULL, result, bytes);

  // Handle the result.
  if (result.status == WRITE_STATUS_BLOCKED)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Blocked send of persist data packet seq %" PRIPktSeqNumber ".\n",
         conn_id_, stream_id_, hdr.sequence_number);
    return true;
  }
  else if (result.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error sending persist data packet seq %" PRIPktSeqNumber ".\n",
         conn_id_, stream_id_, hdr.sequence_number);
    return false;
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Sent persist data packet seq %" PRIPktSeqNumber ".\n", conn_id_,
       stream_id_, hdr.sequence_number);
#endif

  return true;
}

//============================================================================
void Stream::ForceUnackedPacketsLost(const Time& now)
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Forcing all unACKed packets to be considered lost.\n", conn_id_,
       stream_id_);
#endif

  // Force any unACKed packets to be considered lost.
  if (!sent_pkt_mgr_.ForceUnackedPacketsLost(now))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error forcing all unACKed packets to be considered lost.\n",
         conn_id_, stream_id_);
    return;
  }
}

//============================================================================
bool Stream::IsInOutage()
{
  // If there are any unACKed packets, then the stream is in an outage.
  if (!(sent_pkt_mgr_.IsAllDataAcked()))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Detected outage.\n", conn_id_, stream_id_);
#endif

    // The connection is now in an outage.
    return true;
  }

  return false;
}

//============================================================================
void Stream::LeaveOutage(const Time& outage_duration)
{
  Time  rexmit_time = rtt_mgr_.GetRexmitTime();

  // If this is a semi-reliable stream and the outage duration exceeds the
  // retransmission limit time estimate, or this is a best effort stream,
  // then flush the transmit queue.
  //
  // Note that this is not exact, but the Queue class does not support storing
  // a reception time for each packet.
  if (((((rel_.mode == SEMI_RELIABLE_ARQ) ||
         (rel_.mode == SEMI_RELIABLE_ARQ_FEC)) &&
        (outage_duration >= rexmit_time.Multiply(rel_.rexmit_limit))) ||
       (rel_.mode == BEST_EFFORT)) &&
      (transmit_queue_.GetSizeInPackets() > 0))
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Purging %zu packets from transmit queue.\n", conn_id_, stream_id_,
         transmit_queue_.GetSizeInPackets());
#endif

    transmit_queue_.Purge();

    // Inform the application of the updated transmit queue size.
    connection_.TransmitQueueSizeCallback(stream_id_,
                                          transmit_queue_.GetSizeInBytes());
  }

  // Perform any data packet dropping in the sent packet manager.
  sent_pkt_mgr_.LeaveOutage();
}

//============================================================================
void Stream::ImmediateHalfCloseNoSend()
{
  write_side_closed_ = true;

  // Inform the congestion control algorithms about the inactive stream.
  DeactivateStream();
}

//============================================================================
void Stream::ImmediateHalfCloseNoRecv()
{
  read_side_closed_ = true;
}

//============================================================================
void Stream::ImmediateFullClose()
{
  read_side_closed_  = true;
  write_side_closed_ = true;

  // Inform the congestion control algorithms about the inactive stream.
  DeactivateStream();
}

//============================================================================
bool Stream::OnCanXmitOrigFecEncPkt(size_t& num_sends)
{
  // Check that flow control will allow sending the packet.
  if (!sent_pkt_mgr_.CanSend())
  {
    return true;
  }

  // Get the current time.
  Time  now = Time::Now();

  // Get the data length of the next original FEC encoded packet (an unsent
  // FEC encoded packet generated in round 1).
  size_t  data_len = sent_pkt_mgr_.GetNextOrigFecEncPktLen();

  // Check that congestion control will allow sending the packet.  This
  // involves the congestion control send pacing and CanSend() checks.
  CcId  cc_id = 0;

  if (!connection_.CanSend(now, data_len, cc_id))
  {
    return false;
  }

  // Get access to the next original FEC encoded data packet that is already
  // in the sent packet manager.
  DataHeader  hdr;
  Packet*     data = NULL;

  if (!sent_pkt_mgr_.GetNextOrigFecEncPkt(now, cc_id, hdr, data))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error getting FEC packet from sent packet manager.\n", conn_id_,
         stream_id_);
    ResetStream(SLIQ_STREAM_TRANSMIT_QUEUE_ERROR);
    return true;
  }

  if (data == NULL)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error getting data from sent packet manager.\n", conn_id_,
         stream_id_);
    ResetStream(SLIQ_STREAM_TRANSMIT_QUEUE_ERROR);
    return true;
  }

  // Do the send.
  WriteResult  result;
  size_t       bytes = 0;

  SendData(now, hdr, data, result, bytes);

  // Handle the result.  Note that there is nothing that must be done if the
  // send blocked or there was a send error (the packet will remain in the
  // sent packet manager).
  if (result.status == WRITE_STATUS_OK)
  {
    // Update the FEC encoded data packet that is already in the sent packet
    // manager.
    sent_pkt_mgr_.SentOrigFecEncPkt(hdr, bytes, connection_.GetConnSeqNum(),
                                    connection_.GetSentPktCnt(), now);

    ++num_sends;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Transmit of orig FEC enc packet seq %" PRIPktSeqNumber " size "
         "%zu bytes.\n", conn_id_, stream_id_, hdr.sequence_number, bytes);
#endif
  }

  return true;
}

//============================================================================
void Stream::SendData(const Time& now, DataHeader& hdr, Packet* data,
                      WriteResult& result, size_t& bytes)
{
  // Get any move forward sequence number that should be included.
  sent_pkt_mgr_.GetMoveForward(hdr);

  // Send the data packet.
  result = connection_.SendDataPkt(now, hdr, data, bytes);

  if (result.status == WRITE_STATUS_OK)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Sent data of length %zu bytes and FIN %s as seq %" PRIPktSeqNumber
         ".\n", conn_id_, stream_id_, bytes,
         (hdr.fin_flag ? "true" : "false"), hdr.sequence_number);
#endif

    // If a FIN was sent, then the write side is now closed.
    if (hdr.fin_flag)
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Sent FIN, write side is now closed.\n", conn_id_, stream_id_);
#endif

      write_side_closed_ = true;

      // Inform the congestion control algorithms about the inactive stream.
      DeactivateStream();
    }

    // If the retransmission timer expiration time is not currently set, then
    // set it.  This is done only for data packets that generate a response
    // (ACK) packet, be they original or retransmitted data packets.
    if (rto_time_.IsZero())
    {
      rto_time_ = (now + rtt_mgr_.GetRtoTime());
    }

    // Update stream-level retransmission count statistics.
    if (static_cast<size_t>(hdr.retransmission_count) < kRexmitCntStatsSize)
    {
      rexmit_cnt_[hdr.retransmission_count]++;
    }
  }
  else if (result.status == WRITE_STATUS_BLOCKED)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Data send blocked.\n", conn_id_, stream_id_);
  }
  else if (result.status == WRITE_STATUS_ERROR)
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error sending data packet: %s.\n", conn_id_, stream_id_,
         strerror(result.error_code));

    // There was a send error.  Reset the stream.  Note that SendDataPkt()
    // will close the connection when this happens.
    ResetStream((result.error_code == EIO) ?
                SLIQ_STREAM_SOCKET_PARTIAL_WRITE_ERROR :
                SLIQ_STREAM_SOCKET_WRITE_ERROR);
  }
}

//============================================================================
void Stream::ResetStream(StreamErrorCode error)
{
  // Send a reset stream packet to the peer.
  if (!connection_.SendResetStreamPkt(
        stream_id_, error, sent_pkt_mgr_.GetMaxSeqNumSent()))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error sending reset stream packet.\n", conn_id_, stream_id_);
  }

  reset_sent_ = true;

  // Close the stream.
  ImmediateFullClose();
}

//============================================================================
void Stream::ActivateStream()
{
  // Inform all of the congestion control algorithms about the new stream.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if (cc_alg != NULL)
    {
      if (!cc_alg->ActivateStream(stream_id_, initial_send_seq_num_))
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error updating congestion control cc_id %zu with new "
             "stream.\n", conn_id_, stream_id_, i);
      }
    }
  }
}

//============================================================================
void Stream::DeactivateStream()
{
  // Inform all of the congestion control algorithms about the inactive
  // stream.
  for (size_t i = 0; i < cc_algs_.num_cc_alg; ++i)
  {
    CongCtrlInterface*  cc_alg = cc_algs_.cc_alg[i].cc_alg;

    if (cc_alg != NULL)
    {
      if (!cc_alg->DeactivateStream(stream_id_))
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error updating congestion control cc_id %zu with inactive "
             "stream.\n", conn_id_, stream_id_, i);
      }
    }
  }
}

//============================================================================
bool Stream::AllocateRetransmitQueue()
{
  // Allocate the arrays of flags and sequence numbers/indices.
  if (rexmit_queue_flags_ == NULL)
  {
    rexmit_queue_flags_ = new (std::nothrow) uint64_t[((kMaxRexmitPkts + 63) /
                                                       64)];

    if (rexmit_queue_flags_ == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error allocating retransmit queue flags.\n", conn_id_,
           stream_id_);
      return false;
    }
  }

  if (rexmit_queue_ == NULL)
  {
    rexmit_queue_ = new (std::nothrow) PktSeqNumber[kMaxRexmitPkts];

    if (rexmit_queue_ == NULL)
    {
      LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Error allocating retransmit queue.\n", conn_id_, stream_id_);
      return false;
    }
  }

  return true;
}

//============================================================================
void Stream::StartPersistTimer()
{
  // The sender is blocked due to the receiver's advertised window being
  // zero.  If a persist timer is already set, then there is nothing to do.
  if (timer_.IsTimerSet(persist_timer_))
  {
    return;
  }

  // Start a persist timer.
  num_persists_ = 0;

  double  sec = kPersistTimerSec;

  sec = ((sec < kMaxPersistTimerSec) ? sec : kMaxPersistTimerSec);
  sec = ((sec > kMinPersistTimerSec) ? sec : kMinPersistTimerSec);

  Time                   duration(sec);
  CallbackNoArg<Stream>  callback(this, &Stream::PersistTimeout);

  if (!timer_.StartTimer(duration, &callback, persist_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error starting persist timer.\n", conn_id_, stream_id_);
  }
}

//============================================================================
void Stream::StartFecGroupTimer()
{
  // If an FEC group timer is already set, then cancel it.
  if (timer_.IsTimerSet(fec_group_timer_))
  {
    timer_.CancelTimer(fec_group_timer_);
  }

  // Get the duration to use from the sent packet manager.
  double  sec = sent_pkt_mgr_.GetFecSrcPktsDurSec();

  // Start an FEC group timer.
  Time                   duration(sec);
  CallbackNoArg<Stream>  callback(this, &Stream::FecGroupTimeout);

  if (!timer_.StartTimer(duration, &callback, fec_group_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error starting FEC group timer.\n", conn_id_, stream_id_);
  }
}

//============================================================================
void Stream::CreateStreamTimeout()
{
  // Check if a create stream packet should be retransmitted.
  if (!is_established_)
  {
    // Limit the number of create stream packets that can be sent.
    if (num_creates_ >= kMaxCreateStreams)
    {
      LogW(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
           ": Too many create stream packets sent.\n", conn_id_, stream_id_);
    }
    else
    {
      // Perform another wait.
      Time                   duration(kCreateStreamTimerSec);
      CallbackNoArg<Stream>  callback(this, &Stream::CreateStreamTimeout);

      if (timer_.StartTimer(duration, &callback, create_stream_timer_))
      {
        // Send another create stream packet.
        if (connection_.SendCreateStreamPkt(false, delivery_mode_, rel_,
                                            stream_id_, priority_,
                                            kFlowCtrlWindowPkts,
                                            initial_send_seq_num_))
        {
          // Record the transmission.
          num_creates_ += 1;
        }
        else
        {
          timer_.CancelTimer(create_stream_timer_);
        }
      }
      else
      {
        LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
             ": Error starting create stream timer.\n", conn_id_, stream_id_);
      }
    }
  }
}

//============================================================================
void Stream::PersistTimeout()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": Persist timeout.\n", conn_id_, stream_id_);
#endif

  // Send a persist data packet.  Associate it with the first congestion
  // control algorithm.
  Time  now = Time::Now();

  if (!SendPersist(now, 0))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error sending persist data packet.\n", conn_id_, stream_id_);
  }

  // Do any pending reentrant callbacks.
  connection_.DoReentrantCallbacks();

  // Start the next persist timer.
  num_persists_++;

  double  sec = (kPersistTimerSec * (1 << num_persists_));

  sec = ((sec < kMaxPersistTimerSec) ? sec : kMaxPersistTimerSec);
  sec = ((sec > kMinPersistTimerSec) ? sec : kMinPersistTimerSec);

  Time                   duration(sec);
  CallbackNoArg<Stream>  callback(this, &Stream::PersistTimeout);

  if (!timer_.StartTimer(duration, &callback, persist_timer_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
         ": Error starting persist timer.\n", conn_id_, stream_id_);
  }
}

//============================================================================
void Stream::FecGroupTimeout()
{
#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " Stream %" PRIStreamId
       ": FEC group timeout.\n", conn_id_, stream_id_);
#endif

  // Call into the sent packet manager to end the current FEC group.
  sent_pkt_mgr_.ForceFecGroupToEnd();
}

//============================================================================
void Stream::CancelAllTimers()
{
  timer_.CancelTimer(create_stream_timer_);
  timer_.CancelTimer(persist_timer_);
  timer_.CancelTimer(fec_group_timer_);
}
