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

#ifndef IRON_SLIQ_STREAM_H
#define IRON_SLIQ_STREAM_H

#include "sliq_framer.h"
#include "sliq_packet_queue.h"
#include "sliq_private_types.h"
#include "sliq_received_packet_manager.h"
#include "sliq_rtt_manager.h"
#include "sliq_sent_packet_manager.h"
#include "sliq_socket_manager.h"
#include "sliq_types.h"

#include "itime.h"
#include "rng.h"
#include "packet_pool.h"
#include "timer.h"


namespace sliq
{
  struct CcAlgs;
  class Connection;

  /// \brief Class implementing the SLIQ streams.
  ///
  /// Each connection consists of multiple independent data streams.
  ///
  /// Note that this class is not thread-safe.
  class Stream
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  connection   A reference to the associated connection.
    /// \param  rtt_mgr      A reference to the RTT manager.
    /// \param  cc_algs      A reference to the congestion control algorithms.
    /// \param  rng          A reference to the common random number
    ///                      generator.
    /// \param  packet_pool  A reference to the common pool of packets.
    /// \param  timer        A reference to the common timer.
    /// \param  conn_id      The connection's ID.
    /// \param  stream_id    The stream's ID.
    /// \param  priority     The stream's priority.
    Stream(Connection& connection, RttManager& rtt_mgr,
           CcAlgs& cc_algs, iron::RNG& rng,
           iron::PacketPool& packet_pool, iron::Timer& timer,
           EndptId conn_id, StreamId stream_id, Priority priority);

    /// \brief Destructor.
    virtual ~Stream();

    /// \brief Initialize a stream created by the local application.
    ///
    /// \param  rel       The reliability settings for the stream.
    /// \param  del_mode  The delivery mode for the stream.
    ///
    /// \return  True on success, or false otherwise.
    bool InitializeLocalStream(const Reliability& rel, DeliveryMode del_mode);

    /// \brief Initialize a stream created by the remote application.
    ///
    /// \param  hdr  A reference to the received create stream header.
    ///
    /// \return  True on success, or false otherwise.
    bool InitializeRemoteStream(CreateStreamHeader& hdr);

    /// \brief Configure the stream's transmit queue.
    ///
    /// \param  max_size_pkts  The queue's maximum size, in packets.
    /// \param  dequeue_rule   The queue's dequeue rule.
    /// \param  drop_rule      The queue's drop rule.
    ///
    /// \return  True on success, or false otherwise.
    bool ConfigureTransmitQueue(size_t max_size_pkts,
                                DequeueRule dequeue_rule, DropRule drop_rule);

    /// \brief Configure the stream's semi-reliable packet delivery
    /// retransmission limit.
    ///
    /// \param  rexmit_limit  The packet delivery retransmission limit.
    ///
    /// \return  True on success, or false otherwise.
    bool ConfigureRexmitLimit(RexmitLimit rexmit_limit);

    /// \brief Send data from the application and/or a FIN on the stream.
    ///
    /// Any data that cannot be immediately sent will be buffered in the
    /// stream's transmit queue.  If the transmit queue is full and the
    /// transmit queue's drop rule is NO_DROP, then the send will fail.
    ///
    /// If the FIN flag is set, then this will begin closing the stream in the
    /// local to remote direction.  No additional data will be able to be sent
    /// to the peer on this stream after this call succeeds.
    ///
    /// \param  data  A pointer to a packet containing the data to be sent.
    /// \param  fin   The FIN flag.
    ///
    /// \return  True if the packet has been sent or enqueued by the stream
    ///          and is now owned by the stream, or false if the send or
    ///          enqueue operation failed and the packet is still owned by the
    ///          caller.
    bool Send(iron::Packet* data, bool fin);

    /// \brief Send any packets that were blocked previously.
    ///
    /// \return  True if all of the blocked packets were sent successfully, or
    ///          false if sending a blocked packet was blocked again.
    bool SendAnyBlockedPackets();

    /// \brief Called to allow the stream to send one more data packet if it
    /// can.
    ///
    /// This method only checks the stream's transmit queue for an unsent data
    /// packet from the application to transmit.
    ///
    /// \param  num_sends  A reference to a counter that is incremented if a
    ///                    data packet is sent.
    ///
    /// \return  False if blocked due to congestion control before any
    ///          transmission occurred, or true otherwise.
    bool OnCanSend(size_t& num_sends);

    /// \brief Called to allow the stream to resend one more fast retransmit
    /// data packet if it can.
    ///
    /// Fast retranmit packets include:
    /// - any original FEC encoded packets (unsent FEC encoded packets
    ///   generated in round 1) first, then
    /// - any retransmission packets (which may be normal, FEC source, or FEC
    ///   encoded packets that have already been sent at least once) or
    ///   additional FEC encoded packets (unsent FEC encoded packets generated
    ///   in round 2+) as found in the retransmit queue second.
    ///
    /// \param  num_sends  A reference to a counter that is incremented if a
    ///                    data packet is sent.
    ///
    /// \return  False if blocked due to congestion control or send pacing
    ///          before any retransmission occurred, or true otherwise.
    bool OnCanFastRexmit(size_t& num_sends);

    /// \brief Process a received create stream header.
    ///
    /// Note that this is not the create stream header that created this
    /// stream object.  It is a duplicate create stream header.
    ///
    /// \param  hdr  A reference to the received create stream header.
    void ProcessCreateStream(CreateStreamHeader& hdr);

    /// \brief Process a received create stream ACK header.
    ///
    /// \param  hdr  A reference to the received create stream ACK header.
    void ProcessCreateStreamAck(CreateStreamHeader& hdr);

    /// \brief Process a received reset stream header.
    void ProcessResetStream();

    /// \brief Check that received data header is good before processing it.
    ///
    /// \param  hdr  A reference to the received data header.
    ///
    /// \return  Returns true if the data header is for this stream and not a
    ///          duplicate, or false otherwise.
    bool IsGoodDataPacket(DataHeader& hdr);

    /// \brief Process a received data header.
    ///
    /// \param  hdr       A reference to the received data header.
    /// \param  rcv_time  The data packet's receive time.
    /// \param  ack_now   A reference to a flag that is set to true if an ACK
    ///                   packet must be sent immediately.
    ///
    /// \return  Returns true if ownership of the packet is passed to the
    ///          stream, or false if not.
    bool ProcessData(DataHeader& hdr, const iron::Time& rcv_time,
                     bool& ack_now);

    /// \brief Check that received ACK header is good before processing it.
    ///
    /// \param  hdr  A reference to the received ACK header.
    ///
    /// \return  Returns true if the ACK header is for this stream and not a
    ///          duplicate, or false otherwise.
    bool IsGoodAckPacket(AckHeader& hdr);

    /// \brief Process a received ACK header.
    ///
    /// \param  hdr             A reference to the received ACK header.
    /// \param  rcv_time        The ACK receive time.
    /// \param  now             The current time.
    /// \param  leaving_outage  Indicates if an outage is being exited due to
    ///                         the reception of this ACK packet.
    /// \param  new_data_acked  A reference to a flag that is set to true if
    ///                         the ACK packet ACKed new data.
    /// \param  all_data_acked  A reference to a flag that is set to true if
    ///                         all of the stream's data is ACKed.
    /// \param  lo_conn_seq     A reference to the largest observed
    ///                         connection sequence number which is returned
    ///                         on success.
    ///
    /// \return  True if the ACK header processing was successful, false
    ///          otherwise.
    bool ProcessAck(AckHeader& hdr, const iron::Time& rcv_time,
                    const iron::Time& now, bool leaving_outage,
                    bool& new_data_acked, bool& all_data_acked,
                    PktSeqNumber& lo_conn_seq);

    /// \brief Process an implicit ACK.
    ///
    /// \param  now          The current time.
    /// \param  lo_conn_seq  The largest observed connection sequence number.
    void ProcessImplicitAck(const iron::Time& now, PktSeqNumber lo_conn_seq);

    /// \brief Called to add a fast retransmission packet to the tail of the
    /// retransmission queue.
    ///
    /// A retransmission packet is a normal, FEC source, or FEC encoded packet
    /// that has already been sent at least once.
    ///
    /// Does not check for duplicates.
    ///
    /// \param  seq  The data packet's sequence number.
    ///
    /// \return  True if the packet is added to the queue, false if not.
    bool AddFastRexmitPkt(PktSeqNumber seq);

    /// \brief Called to add an additional FEC encoded packet to the tail of
    /// the retransmission queue.
    ///
    /// An additional FEC encoded packet is an unsent FEC encoded packet
    /// generated in round 2+.
    ///
    /// Does not check for duplicates.
    ///
    /// \param  tmp_seq  The data packet's temporary sequence number.
    ///
    /// \return  True if the packet is added to the queue, false if not.
    bool AddAddlFecEncPkt(PktSeqNumber tmp_seq);

    /// \brief Called to allow the stream to perform any necessary
    /// stream-level retransmissions.
    ///
    /// This method allows the stream to retransmit one data packet if the
    /// peer has not responded within the RTO time, while other streams might
    /// still be receiving responses from the peer.  It is up to the stream to
    /// decide if its RTO time has been exceeded or not.
    ///
    /// \param  now  The current time.
    void RtoCheck(const iron::Time& now);

    /// \brief Called to allow the stream to resend either the lowest or
    /// highest unACKed data packet if it can.
    ///
    /// Does not check if the packet is considered lost yet, nor does this
    /// method perform any congestion control or send pacing checks.
    ///
    /// \param  now         The current time.
    /// \param  lowest      Controls if the lowest or highest unACKed data
    ///                     packet will be sent.
    /// \param  rto_outage  A flag indicating if the retransmission is due to
    ///                     either an RTO event or an outage end condition.
    ///                     This can affect some of the fields in the packet.
    ///
    /// \return  True if the retransmitted packet was sent successfully or
    ///          there is a packet that can be retransmitted but the kernel
    ///          send blocked.  False if there was no data packet that
    ///          required retransmission.
    bool RexmitPkt(const iron::Time& now, bool lowest, bool rto_outage);

    /// \brief Send a persist packet.
    ///
    /// \param  now    The current time.
    /// \param  cc_id  The congestion control identifier.
    ///
    /// \return  True if the persist is sent successfully.
    bool SendPersist(const iron::Time& now, CcId cc_id);

    /// \brief Force all of the unACKed packets in the stream to be considered
    /// lost.
    ///
    /// \param  now  The current time.
    void ForceUnackedPacketsLost(const iron::Time& now);

    /// \brief Check if the stream detects a connection outage.
    ///
    /// \return  True if the stream determines that the connection is in an
    ///          outage.
    bool IsInOutage();

    /// \brief Handle the end of an outage.
    ///
    /// This will allow a semi-reliable stream to drop packets that are too
    /// old from its transmit queue and its send window.
    ///
    /// \param  outage_duration  The duration of the outage.
    void LeaveOutage(const iron::Time& outage_duration);

    /// \brief Perform a half close on the stream.
    ///
    /// This will prevent any further sending of data on the stream.
    void ImmediateHalfCloseNoSend();

    /// \brief Perform a half close on the stream.
    ///
    /// This will prevent any further receiving of data on the stream.
    void ImmediateHalfCloseNoRecv();

    /// \brief Perform a full close on the stream.
    ///
    /// This will prevent any further sending or receiving of data on the
    /// stream.
    void ImmediateFullClose();

    /// \brief Get the stream's ID.
    ///
    /// \return  The stream's ID.
    inline StreamId stream_id() const
    {
      return stream_id_;
    }

    /// \brief Get the stream's priority.
    ///
    /// \return  The stream's current effective priority.
    inline Priority priority() const
    {
      return priority_;
    }

    /// \brief Check if the stream is fully established or not.
    ///
    /// \return  True if the stream is fully established, or false otherwise.
    inline bool IsEstablished() const
    {
      return is_established_;
    }

    /// \brief Check if the stream is using semi-reliable ARQ+FEC mode.
    ///
    /// \return  True if the stream is using semi-reliable ARQ+FEC mode, or
    /// false otherwise.
    inline bool IsUsingArqFec() const
    {
      return (rel_.mode == SEMI_RELIABLE_ARQ_FEC);
    }

    /// \brief Get the sent data packet count for a data packet.
    ///
    /// \param  seq           The data packet's sequence number.
    /// \param  rexmit_cnt    The data packet's retransmission count.
    /// \param  sent_pkt_cnt  A reference to a location where the sent data
    ///                       packet count is placed on success.
    ///
    /// \return  True if sent data packet count is found and returned, or
    ///          false otherwise.
    inline bool GetSentPktCnt(PktSeqNumber seq, RetransCount rexmit_cnt,
                              PktCount& sent_pkt_cnt) const
    {
      return sent_pkt_mgr_.GetSentPktCnt(seq, rexmit_cnt, sent_pkt_cnt);
    }

    /// \brief Check if all of the stream's send side data is currently ACKed.
    ///
    /// \return  True if all of the stream's data is currently ACKed, or false
    ///          otherwise.
    inline bool IsAllDataAcked() const
    {
      return sent_pkt_mgr_.IsAllDataAcked();
    }

    /// \brief Check if any of the stream's receive side data is missing.
    ///
    /// \return  True if there are any stream data packets missing, or false
    ///          otherwise.
    inline bool IsDataMissing() const
    {
      return rcvd_pkt_mgr_.IsDataMissing();
    }

    /// \brief Check if the stream has any fast retransmit packets waiting to
    /// be sent.
    ///
    /// Fast retranmit packets include:
    /// - any original FEC encoded packets (unsent FEC encoded packets
    ///   generated in round 1) first, then
    /// - any retransmission packets (which may be normal, FEC source, or FEC
    ///   encoded packets that have already been sent at least once) or
    ///   additional FEC encoded packets (unsent FEC encoded packets generated
    ///   in round 2+) as found in the retransmit queue second.
    ///
    /// \return  True if there is at least one fast retransmit packet waiting
    ///          to be sent, or false otherwise.
    inline bool HasFastRexmit()
    {
      return ((sent_pkt_mgr_.OrigFecEncPktsToBeSent() > 0) ||
              (rexmit_queue_size_ > 0));
    }

    /// \brief Check if the stream is fully closed.
    ///
    /// \return  True if the stream is fully closed.
    inline bool IsFullyClosed() const
    {
      return(read_side_closed_ && write_side_closed_);
    }

    /// \brief Check if the stream has either queued or sent a FIN.
    ///
    /// \return  True if the stream has either queued or sent a FIN.
    inline bool HasQueuedOrSentFin() const
    {
      return(fin_buffered_ || fin_sent_);
    }

    /// \brief Prepare the information for the stream's next ACK header.
    ///
    /// This method is used to prepare the information for and get the length
    /// of the next ACK header for the stream.  The length can then be used in
    /// order to determine if it will fit within a given packet before
    /// actually building the ACK header.  It must be called before calling
    /// GetNextAckHdr(), which will actually build the next ACK header using
    /// the information generated in this method.
    ///
    /// \return  The size of the next ACK header in bytes.
    inline size_t PrepareNextAckHdr()
    {
      return rcvd_pkt_mgr_.PrepareNextAckHdr();
    }

    /// \brief Build the next ACK header for the stream after preparing the
    /// information for it.
    ///
    /// This method must be called after PrepareNextAckHdr().  The information
    /// generated in PrepareNextAckHdr() is used to build the ACK header for
    /// the stream in this method.
    ///
    /// \param  ack_hdr  A reference to the ACK header that is to be updated.
    /// \param  now      The current time.
    ///
    /// \return  True if ACK header for this stream is created successfully.
    inline bool BuildNextAckHdr(AckHeader& ack_hdr, const iron::Time& now)
    {
      return rcvd_pkt_mgr_.BuildNextAckHdr(ack_hdr, now);
    }

    /// \brief Get the stream's transmit queue size, in bytes.
    ///
    /// \return The stream's transmit queue size, in bytes.
    inline size_t GetTransmitQueueSizeInBytes() const
    {
      return transmit_queue_.GetSizeInBytes();
    }

    /// \brief Get the stream's transmit queue size, in packets.
    ///
    /// \return The stream's transmit queue size, in packets.
    inline size_t GetTransmitQueueSizeInPackets() const
    {
      return transmit_queue_.GetSizeInPackets();
    }

  private:

    /// \brief Copy constructor.
    Stream(const Stream& s);

    /// \brief Assignment operator.
    Stream& operator=(const Stream& s);

    /// \brief Send the next original FEC encoded data packet waiting to be
    /// sent.
    ///
    /// An original FEC encoded packet is an unsent FEC encoded packet
    /// generated in round 1.
    ///
    /// \return  False if blocked due to congestion control or send pacing
    ///          before any transmission occurred, or true otherwise.
    bool OnCanXmitOrigFecEncPkt(size_t& num_sends);

    /// \brief Send a data packet.
    ///
    /// \param  now       The current time.
    /// \param  hdr       The data header.
    /// \param  data      A pointer to a packet containing any payload.  May
    ///                   be NULL.
    /// \param  result    The details of the send result.
    /// \param  bytes     The number of bytes sent, including SLIQ headers.
    void SendData(const iron::Time& now, DataHeader& hdr, iron::Packet* data,
                  WriteResult& result, size_t& bytes);

    /// \brief Send a reset stream packet and terminate the stream.
    ///
    /// \param  error  The error code.
    void ResetStream(StreamErrorCode error);

    /// \brief Activate the stream within the congestion control algorithms.
    void ActivateStream();

    /// \brief Deactivate the stream within the congestion control algorithms.
    void DeactivateStream();

    /// \brief Allocate the retransmit queue.
    ///
    /// \return  True if the retransmit queue is allocated successfully.
    bool AllocateRetransmitQueue();

    /// \brief Update the persist timer.
    ///
    /// This timer is started when the sender is blocked due to the receiver's
    /// advertised window being zero.
    void StartPersistTimer();

    /// \brief Start an FEC group timer.
    ///
    /// This timer is started when an FEC group is started and limits the
    /// amount of time spent sending the FEC source data packets.  If the
    /// timer goes off, then the FEC group is ended.
    void StartFecGroupTimer();

    /// \brief Process a create stream packet timer callback.
    void CreateStreamTimeout();

    /// \brief Process a persist timer callback.
    void PersistTimeout();

    /// \brief Process an FEC group timer callback.
    void FecGroupTimeout();

    /// \brief Cancel all timers.
    void CancelAllTimers();

    /// The number of stream-level retransmission count statistics to be
    /// gathered.
    static const size_t  kRexmitCntStatsSize = 11;

    // ---------- Components Used By Streams ----------

    /// The connection that owns this stream.
    Connection&               connection_;

    /// The RTT manager.
    RttManager&               rtt_mgr_;

    /// The congestion control algorithms.
    CcAlgs&                   cc_algs_;

    /// The random number generator.
    iron::RNG&                rng_;

    /// Pool containing packets to use.
    iron::PacketPool&         packet_pool_;

    // Manager of all timers.
    iron::Timer&              timer_;

    /// The sent packet manager.
    SentPktManager            sent_pkt_mgr_;

    /// The received packet manager.
    RcvdPktManager            rcvd_pkt_mgr_;

    // ---------- Stream State Information ----------

    /// The connection ID.
    EndptId                   conn_id_;

    /// The stream ID.
    StreamId                  stream_id_;

    /// The priority for this stream.
    Priority                  priority_;

    /// The reliability settings for the stream.
    Reliability               rel_;

    /// The delivery mode for the stream.
    DeliveryMode              delivery_mode_;

    /// Record if the stream is fully established.
    bool                      is_established_;

    /// Record if a FIN is currently buffered.
    bool                      fin_buffered_;

    /// Record if a FIN has been sent.
    bool                      fin_sent_;

    /// Record if a FIN has been received.
    bool                      fin_received_;

    /// Record if a reset stream packet has been sent.
    bool                      reset_sent_;

    /// Record if this stream has received a reset stream packet.
    bool                      reset_received_;

    /// Record if the receive side is closed.
    bool                      read_side_closed_;

    /// Record if the write side is closed.
    bool                      write_side_closed_;

    /// The initial packet sequence number to use for sending.
    PktSeqNumber              initial_send_seq_num_;

    // ---------- Retransmissions ----------

    /// The current index of the first retransmission in the queue.
    size_t                    rexmit_queue_head_;

    /// The current number of retransmissions in the queue.
    size_t                    rexmit_queue_size_;

    /// The array of additional FEC encoded packet flags for the queue.  Used
    /// in conjunction with the rexmit_queue_ array.  There is a one-bit flag
    /// for each queue entry.  The flag is zero for retransmission packets
    /// (normal, FEC source, or FEC encoded packets that have already been
    /// sent at least once), or one for additional FEC encoded packets (unsent
    /// FEC encoded packets generated in round 2+).
    uint64_t*                 rexmit_queue_flags_;

    /// The queue of packet sequence numbers for retransmission.  Used in
    /// conjunction with the rexmit_queue_flags_ array to determine the type
    /// of packet.
    PktSeqNumber*             rexmit_queue_;

    // ---------- Transmit Queues and Buffers ----------

    /// The source data packet transmit queue.
    PacketQueue               transmit_queue_;

    // ---------- Timers ----------

    /// The number of create stream packets sent for stream creation.
    int                       num_creates_;

    /// The create stream timer handle.
    iron::Timer::Handle       create_stream_timer_;

    /// The number of sequential persist timer callbacks.
    int                       num_persists_;

    /// The persist timer handle.
    iron::Timer::Handle       persist_timer_;

    /// The last time that a persist packet was received.
    iron::Time                persist_ack_time_;

    /// The retransmission timer expiration time.
    iron::Time                rto_time_;

    /// The FEC group timer handle.
    iron::Timer::Handle       fec_group_timer_;

    // ---------- Statistics ----------

    // For logging the number of retransmission packets sent.
    size_t                    rexmit_cnt_[kRexmitCntStatsSize];

  }; // class Stream

} // namespace sliq

#endif // IRON_SLIQ_STREAM_H
