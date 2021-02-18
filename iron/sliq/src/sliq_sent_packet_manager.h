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

#ifndef IRON_SLIQ_SENT_PACKET_MANAGER_H_
#define IRON_SLIQ_SENT_PACKET_MANAGER_H_

#include "sliq_app.h"
#include "sliq_framer.h"
#include "sliq_private_defs.h"
#include "sliq_private_types.h"
#include "sliq_rtt_manager.h"
#include "sliq_vdm_fec.h"

#include "itime.h"
#include "packet.h"
#include "packet_pool.h"


namespace sliq
{

  struct CcAlgs;
  class CongCtrlInterface;
  class Connection;
  class Stream;

  /// Class which holds the set of data packets sent on a SLIQ stream.  The
  /// data packets are added to the send window when they are first sent, and
  /// may be resent as allowed by the reliability mode settings.  The send
  /// window is slid forward when data packets are ACKed by the receiver or
  /// have been given up on.
  ///
  /// The send window utilizes the following locators:
  ///
  /// \verbatim
  ///     |<------------- snd_wnd_ -------------->|
  ///
  ///     +---+---+---+---+---+---+---+---+---+---+
  ///     |   |   |   |   |   |   |   |   |   |   |
  ///     +---+---+---+---+---+---+---+---+---+---+
  ///       ^           ^                   ^
  ///       |           |                   |
  ///   snd_fec_    snd_una_            snd_nxt_
  ///
  ///   snd_fec_ - The lowest FEC source packet that is still needed by FEC.
  ///              Marks the left (lower) edge of the send window.
  ///   snd_una_ - The lowest unACKed packet.  May be as low as snd_fec_ or as
  ///              high as snd_nxt_.
  ///   snd_nxt_ - The next packet to be sent.  Determines the right (upper)
  ///              edge of the send window.  May be as low as snd_fec_.
  ///   snd_wnd_ - The maximum size of the send window in packets.  Determines
  ///              the limit on the right (upper) edge of the send window
  ///              given the current left (lower) edge.  Set to
  ///              kFlowCtrlWindowPkts.
  ///
  /// Note that:
  ///   snd_fec_  <=  snd_una_  <=  snd_nxt_  <=  (snd_fec_ + snd_wnd_)
  /// \endverbatim
  ///
  /// When using SEMI_RELIABLE_ARQ_FEC mode (simply called FEC mode throughout
  /// the code), error control will use ARQ, FEC, or a combination of ARQ and
  /// FEC as needed in order to meet the packet delivery requirements.  When
  /// FEC is being used, generated FEC encoded packets are added to a separate
  /// packet queue just for FEC encoded packets waiting to be sent.  Once
  /// these packets are sent, they are moved from the FEC encoded packet queue
  /// to the send window.  By using a separate FEC encoded packet queue, these
  /// packets do not impact the send window size and can be sent whenever it
  /// makes sense to send them.
  ///
  /// The rules controlling packet retransmissions are determined by the
  /// reliability mode in effect at the time.
  /// - In BEST_EFFORT mode, there are no retransmissions allowed.
  /// - In RELIABLE_ACK mode, unlimited retransmissions are allowed in order
  ///   to successfully deliver each packet.
  /// - In SEMI_RELIABLE_ARQ mode, a limited number of retransmissions are
  ///   allowed for each packet.
  /// - In SEMI_RELIABLE_ARQ_FEC mode, retransmissions are controlled within
  ///   each round for the packet's FEC group when within the target number of
  ///   rounds, then controlled using the semi-reliable ARQ mode rules after
  ///   the target number of rounds are over.
  class SentPktManager
  {

   public:

    /// \brief Constructor.
    ///
    /// \param  conn         A reference to the SLIQ connection.
    /// \param  stream       A reference to the SLIQ stream.
    /// \param  rtt_mgr      A reference to the RttManager.
    /// \param  packet_pool  A reference to the PacketPool.
    /// \param  cc_algs      A reference to the congestion control algorithms.
    /// \param  conn_id      The connection ID being controlled.
    /// \param  stream_id    The stream ID being controlled.
    SentPktManager(Connection& conn, Stream& stream, RttManager& rtt_mgr,
                   iron::PacketPool& packet_pool, CcAlgs& cc_algs,
                   EndptId conn_id, StreamId stream_id);

    /// \brief Destructor.
    virtual ~SentPktManager();

    /// \brief Initialize the sent packet manager.
    ///
    /// The rexmit_limit member of the rel argument is only used if the
    /// reliability mode is set to SEMI_RELIABLE_ARQ or SEMI_RELIABLE_ARQ_FEC.
    ///
    /// The fec_target_pkt_recv_prob, fec_del_time_flag,
    /// fec_target_pkt_del_rounds, and fec_target_pkt_del_time_sec members of
    /// the rel argument are only used if the reliability mode is set to
    /// SEMI_RELIABLE_ARQ_FEC.
    ///
    /// \param  rel           The reliability settings for the stream.
    /// \param  init_seq_num  The initial sequence number that will be sent.
    ///
    /// \return  True on success, or false on error.
    bool Initialize(const Reliability& rel, PktSeqNumber init_seq_num);

    /// \brief Get the information for sending the next data packet that will
    /// be stored in the sent packet manager.
    ///
    /// This method updates all the data header fields except for the move
    /// forward fields.  It also updates the send window for adding the packet
    /// after it is sent.  Once the data packet is sent, it must be added to
    /// the manager using the AddSentPkt() method.
    ///
    /// \param  pkt      The data packet to be sent.  May be NULL.
    /// \param  cc_id    The congestion control identifier to use in the data
    ///                  packet.
    /// \param  fin      The FIN flag to use in the data packet.
    /// \param  now      The current time.
    /// \param  hdr      A reference to the data header to be updated for
    ///                  sending the packet.
    /// \param  new_grp  A reference to a flag that is set to true if this
    ///                  packet is the first FEC source packet of a new FEC
    ///                  group, or false otherwise.
    ///
    /// \return  True if there is room in the send window for a transmission,
    ///          or false otherwise.
    bool PrepareNextPkt(iron::Packet* pkt, CcId cc_id, bool fin,
                        const iron::Time& now, DataHeader& hdr,
                        bool& new_grp);

    /// \brief Add a packet that has been transmitted.
    ///
    /// The sent packet manager assumes ownership of the packet that was
    /// prepared by PrepareNextPkt and has been transmitted.  This class takes
    /// responsibility for recycling the packet when it is no longer needed.
    ///
    /// \param  hdr             The transmitted packet's data header as sent.
    /// \param  pkt             The transmitted packet.
    /// \param  bytes_sent      The size of the SLIQ headers and payload sent,
    ///                         in bytes.
    /// \param  conn_seq        The transmitted packet's assigned connection
    ///                         sequence number.
    /// \param  sent_pkt_cnt    The transmitted packet's assigned sent data
    ///                         packet count for the connection.
    /// \param  xmit_time       The transmission time.
    /// \param  queueing_delay  The amount of time the transmitted packet
    ///                         spent in the stream's transmit queue.
    /// \param  blocked         Indicates if the transmission was send socket
    ///                         blocked or not.
    /// \param  grp_end         A reference to a flag that is set to true if
    ///                         this is the last FEC source packet of the
    ///                         current FEC group, or false otherwise.
    void AddSentPkt(DataHeader& hdr, iron::Packet* pkt, size_t bytes_sent,
                    PktSeqNumber conn_seq, PktCount sent_pkt_cnt,
                    const iron::Time& xmit_time,
                    const iron::Time& queueing_delay, bool blocked,
                    bool& grp_end);

    /// \brief Get a blocked packet for transmission.
    ///
    /// This method updates all the data header fields except for the move
    /// forward fields.  Once the blocked data packet is sent successfully, it
    /// must be set unblocked using SetPktUnblocked() method.
    ///
    /// \param  hdr  A reference to the data header to be updated for sending
    ///              the packet.
    /// \param  pkt  A reference to the pointer to the blocked packet.
    ///
    /// \return  True if a blocked packet is found for transmission, or false
    ///          otherwise.
    bool GetBlockedPkt(DataHeader& hdr, iron::Packet*& pkt);

    /// \brief Set the state of the packet with the provided sequence number
    /// to unblocked.
    ///
    /// \param  hdr           The transmitted packet's data header as sent.
    /// \param  bytes_sent    The size of the SLIQ headers and payload sent,
    ///                       in bytes.
    /// \param  sent_pkt_cnt  The transmitted packet's assigned sent data
    ///                       packet count for the connection.
    /// \param  xmit_time     The transmission time.
    void SetPktUnblocked(DataHeader& hdr, size_t bytes_sent,
                         PktCount sent_pkt_cnt, const iron::Time& xmit_time);

    /// \brief Get either the lowest or highest unACKed packet sequence number
    /// for retransmission.
    ///
    /// This method only looks for a retransmission packet (a normal, FEC
    /// source, or FEC encoded packet that has already been sent at least
    /// once), not an additional FEC encoded packet (an unsent FEC encoded
    /// packet generated in round 2+).
    ///
    /// If the packet is allowed to be transmitted, then the GetRexmitPkt()
    /// method must be called to get access to the packet, and the
    /// UpdateRexmitPkt() method must be called for the packet once it is
    /// successfully transmitted.
    ///
    /// \param  now      The current time.
    /// \param  lowest   Controls if the lowest or highest unACKed packet
    ///                  sequence number will be returned.
    /// \param  seq_num  A reference to where the sequence number will be
    ///                  placed on success.
    /// \param  cc_id    A reference where the packet's associated congestion
    ///                  control identifier will be placed on success.
    ///
    /// \return  True if a sequence number is being returned, or false
    ///          otherwise.
    bool GetRexmitPktSeqNum(const iron::Time& now, bool lowest,
                            PktSeqNumber& seq_num, CcId& cc_id);

    /// \brief Get the data length of a retransmission or additional FEC
    /// encoded data packet.
    ///
    /// A retransmission packet is a normal, FEC source, or FEC encoded packet
    /// that has already been sent at least once.  An additional FEC encoded
    /// packet is an unsent FEC encoded packet generated in round 2+.
    ///
    /// The packet must still be unACKed in order to have its data length be
    /// returned by this method.  Note that this does not update congestion
    /// control.
    ///
    /// If the packet is allowed to be transmitted, then the GetRexmitPkt()
    /// method must be called to get access to the packet, and the
    /// UpdateRexmitPkt() method must be called for the packet once it is
    /// successfully transmitted.
    ///
    /// \param  seq_num   The sequence number of the retransmission or
    ///                   additional FEC encoded data packet being requested.
    /// \param  addl      A flag specifying if this is an additional FEC
    ///                   encoded packet (true) or a retransmission packet
    ///                   (false).
    /// \param  data_len  A reference where the data length of the packet in
    ///                   bytes will be placed on success.  Does not include
    ///                   any headers.
    /// \param  cc_id     A reference where the packet's associated congestion
    ///                   control identifier will be placed on success.
    ///                   Additional FEC encoded packets will not have this
    ///                   and will return an invalid identifier instead.
    ///
    /// \return  True if the packet is found for retransmission, or false
    ///          otherwise.
    bool GetRexmitPktLen(PktSeqNumber seq_num, bool addl, size_t& data_len,
                         CcId& cc_id);

    /// \brief Get a packet for retransmission.
    ///
    /// The packet must still be unACKed in order to be returned by this
    /// method.
    ///
    /// This method updates all the data header fields except for the move
    /// forward fields.  The congestion control identifier field is set to the
    /// value used when the packet was originally sent.
    ///
    /// After the packet has been retransmitted successfully, the
    /// UpdateRexmitPkt() method must be called for the packet.
    ///
    /// \param  now         The current time.
    /// \param  seq_num     The sequence number of the data packet being
    ///                     requested.
    /// \param  addl        A flag specifying if this is an additional FEC
    ///                     encoded packet (true) or a retransmission packet
    ///                     (false).
    /// \param  rto_outage  A flag indicating if the retransmission is due to
    ///                     either an RTO event or an outage end condition.
    ///                     This can affect some of the fields in the packet.
    /// \param  cc_id       The congestion control identifier to use in the
    ///                     additional FEC encoded data packet.  Not used for
    ///                     retransmission packets.
    /// \param  hdr         A reference to the data header to be updated for
    ///                     sending the packet.
    /// \param  pkt         A reference to the pointer to the packet to be
    ///                     retransmitted.
    ///
    /// \return  True if the packet is found for retransmission, or false
    ///          otherwise.
    bool GetRexmitPkt(const iron::Time& now, PktSeqNumber seq_num,
                      bool addl, bool rto_outage, CcId cc_id, DataHeader& hdr,
                      iron::Packet*& pkt);

    /// \brief Update the packet information for a packet that has been
    /// retransmitted.
    ///
    /// This method must be called after getting the packet using the
    /// GetRexmitPkt() method and sending the packet.
    ///
    /// \param  hdr           A reference to the data header that was sent.
    /// \param  bytes_sent    The size of the SLIQ headers and payload sent,
    ///                       in bytes.
    /// \param  conn_seq      The transmitted packet's assigned connection
    ///                       sequence number.  Only used if this is an
    ///                       additional FEC encoded packet.
    /// \param  sent_pkt_cnt  The retransmitted packet's assigned sent data
    ///                       packet count for the connection.
    /// \param  rexmit_cc_id  The congestion control identifier allowing the
    ///                       retransmission.
    /// \param  addl          A flag specifying if this is an additional FEC
    ///                       encoded packet (true) or a retransmission packet
    ///                       (false).
    /// \param  rto_outage    A flag indicating if the retransmission is due
    ///                       to either an RTO event or an outage end
    ///                       condition.
    /// \param  now           The current time.
    void SentRexmitPkt(DataHeader& hdr, size_t bytes_sent,
                       PktSeqNumber conn_seq, PktCount sent_pkt_cnt,
                       CcId rexmit_cc_id, bool addl, bool rto_outage,
                       const iron::Time& now);

    /// \brief Inquire how many original FEC encoded data packets are waiting
    /// to be sent.
    ///
    /// An original FEC encoded packet is an unsent FEC encoded packet
    /// generated in round 1.
    ///
    /// \return  The number of original FEC encoded packets waiting to be
    ///          sent.
    WindowSize OrigFecEncPktsToBeSent();

    /// \brief Get the size of the next original FEC encoded data packet
    /// waiting to be sent.
    ///
    /// An original FEC encoded packet is an unsent FEC encoded packet
    /// generated in round 1.
    ///
    /// If the packet is allowed to be transmitted, then the
    /// GetNextOrigFecEncPkt() method must be called to get access to the
    /// packet, and the SentOrigFecEncPkt() method must be called for the
    /// packet once it is successfully transmitted.
    ///
    /// \return  The size of the next original FEC encoded data packet in
    ///          bytes.
    size_t GetNextOrigFecEncPktLen();

    /// \brief Get the next original FEC encoded data packet waiting to be
    /// sent.
    ///
    /// This method updates all the data header fields except for the move
    /// forward fields.
    ///
    /// After the packet has been transmitted successfully, the
    /// SentOrigFecEncPkt() method must be called.
    ///
    /// \param  now    The current time.
    /// \param  cc_id  The congestion control identifier to use in the data
    ///                packet.
    /// \param  hdr    A reference to the data header to be updated for
    ///                sending the packet.
    /// \param  pkt    A reference to the pointer to the FEC packet.
    ///
    /// \return  True if an FEC encoded data packet is found for transmission,
    ///          or false otherwise.
    bool GetNextOrigFecEncPkt(const iron::Time& now, CcId cc_id,
                              DataHeader& hdr, iron::Packet*& pkt);

    /// \brief Update the state of the original FEC encoded data packet that
    /// was just sent.
    ///
    /// \param  hdr           The transmitted packet's data header as sent.
    /// \param  bytes_sent    The size of the SLIQ headers and payload sent,
    ///                       in bytes.
    /// \param  conn_seq      The transmitted packet's assigned connection
    ///                       sequence number.
    /// \param  sent_pkt_cnt  The transmitted packet's assigned sent data
    ///                       packet count for the connection.
    /// \param  xmit_time     The transmission time.
    void SentOrigFecEncPkt(DataHeader& hdr, size_t bytes_sent,
                           PktSeqNumber conn_seq, PktCount sent_pkt_cnt,
                           const iron::Time& xmit_time);

    /// \brief Force the current FEC group to end.
    void ForceFecGroupToEnd();

    /// \brief Get the sent data packet count for a data packet.
    ///
    /// \param  seq_num       The data packet's sequence number.
    /// \param  rexmit_cnt    The data packet's retransmission count.
    /// \param  sent_pkt_cnt  A reference to a location where the sent data
    ///                       packet count is placed on success.
    ///
    /// \return  True if sent data packet count is found and returned, or
    ///          false otherwise.
    bool GetSentPktCnt(PktSeqNumber seq_num, RetransCount rexmit_cnt,
                       PktCount& sent_pkt_cnt) const;

    /// \brief Check that received ACK packet is good before processing it.
    ///
    /// \param  ack_hdr  A reference to the received ACK packet.
    ///
    /// \return  Returns true if the ACK packet is not a duplicate, or false
    ///          otherwise.
    bool IsGoodAckPacket(const AckHeader& ack_hdr);

    /// \brief Process a received ACK header.
    ///
    /// \param  ack_hdr         The received ACK header.
    /// \param  rcv_time        The ACK receive time.
    /// \param  now             The current time.
    /// \param  new_data_acked  A reference to a flag that is set to true if
    ///                         the ACK header ACKed new data.
    /// \param  lo_conn_seq     A reference to the largest observed connection
    ///                         sequence number which is returned on success.
    ///
    /// \return  True if the ACK header processing is successful, false
    ///          otherwise.
    bool ProcessAck(const AckHeader& ack_hdr, const iron::Time& rcv_time,
                    const iron::Time& now, bool& new_data_acked,
                    PktSeqNumber& lo_conn_seq);

    /// \brief Process an implicit ACK.
    ///
    /// Implicit ACKs are caused by ACKs on other streams that increase the
    /// largest observed connection sequence number enough that unACKed
    /// packets on this stream can be considered lost.
    ///
    /// \param  now          The current time.
    /// \param  lo_conn_seq  The largest observed connection sequence number.
    void ProcessImplicitAck(const iron::Time& now, PktSeqNumber lo_conn_seq);

    /// \brief Force all of the unACKed packets to be considered lost.
    ///
    /// \param  now  The current time.
    ///
    /// \return  True if the update is successful, false otherwise.
    bool ForceUnackedPacketsLost(const iron::Time& now);

    /// \brief Handle the end of an outage.
    void LeaveOutage();

    /// \brief Get the move forward flag and sequence number for a data
    /// header that is about to be sent.
    ///
    /// Note that reliable ARQ and semi-reliable FEC modes do not use the move
    /// forward data header option.  In reliable ARQ mode, no packets may be
    /// skipped over.  In semi-reliable FEC mode, the receiver decides when to
    /// skip over packets that it cannot regenerate.
    ///
    /// \param  hdr  A reference to the data header to be updated.
    void GetMoveForward(DataHeader& hdr);

    /// \brief Get the amount of time allowed for sending all of the FEC
    /// source data packets in the current FEC group.
    ///
    /// \return  The amount of time allowed for sending the FEC source
    ///          data packets in the current FEC group, in seconds.
    double GetFecSrcPktsDurSec();

    /// \brief Configure the stream's semi-reliable packet delivery
    /// retransmission limit.
    ///
    /// \param  rexmit_limit  The packet delivery retransmission limit.
    inline void SetRexmitLimit(RexmitLimit rexmit_limit)
    {
      rel_.rexmit_limit = (((rel_.mode == SEMI_RELIABLE_ARQ) ||
                            (rel_.mode == SEMI_RELIABLE_ARQ_FEC)) ?
                           rexmit_limit : 0);
    }

    /// \brief Inquire if a transmission can occur.
    ///
    /// \return  True if a packet can be sent to the receiver without
    ///          overflowing either the send buffer or the receive buffer, or
    ///          false otherwise.
    inline bool CanSend() const
    {
      // There must be room in both the local send window and the receiver's
      // receive window in order to send.
      return (((snd_nxt_ - snd_fec_) < kFlowCtrlWindowPkts) &&
              ((snd_nxt_ - rcv_ack_nxt_exp_) < kFlowCtrlWindowPkts));
    }

    /// \brief Get the maximum data packet sequence number sent thus far.
    ///
    /// \return  The maximum data packet sequence number sent.
    inline PktSeqNumber GetMaxSeqNumSent() const
    {
      return (snd_nxt_ - 1);
    }

    /// \brief Check if all of the data has been ACKed or not.
    ///
    /// \return  True if all of the data has been ACKed.
    inline bool IsAllDataAcked() const
    {
      return (snd_nxt_ == snd_una_);
    }

    /// \brief Check if a FIN has been sent or not.
    ///
    /// \return  True if a FIN has been sent, or false otherwise.
    inline bool HasFinBeenSent() const
    {
      return fin_sent_;
    }

   private:

    /// Count adjustment information for a congestion control algorithm.
    struct CcCntAdjInfo
    {
      CcCntAdjInfo();
      virtual ~CcCntAdjInfo();

      /// A flag recording if the counts have been updated.
      bool     updated_;

      /// The packets in flight adjustment.
      ssize_t  pif_adj_;

      /// The bytes in flight adjustment.
      ssize_t  bif_adj_;

      /// The pipe adjustment, in bytes.
      ssize_t  pipe_adj_;
    };

    /// Unacknowledged packet information for a congestion control algorithm.
    struct CcUnaPktInfo
    {
      CcUnaPktInfo();
      virtual ~CcUnaPktInfo();

      /// A flag recording if there is an oldest unacknowledged packet.
      bool          has_una_;

      /// The oldest unacknowledged packet for the congestion control
      /// algorithm.
      PktSeqNumber  una_cc_seq_num_;

      /// The previously reported flag recording if there is an oldest
      /// unacknowledged packet.
      bool          prev_has_una_;

      /// The previously reported oldest unacknowledged packet for the
      /// congestion control algorithm.
      PktSeqNumber  prev_una_cc_seq_num_;
    };

    /// Information for each sent packet.  The size of this structure needs to
    /// be as small as possible (currently 96 bytes on a 64-bit OS).
    struct SentPktInfo
    {
      SentPktInfo();
      virtual ~SentPktInfo();
      void MoveFecInfo(SentPktInfo& spi);
      void Clear();
      static void SetPacketPool(iron::PacketPool* pool)
      {
        packet_pool_ = pool;
      }

      /// The common packet pool pointer for recycling packets.
      static iron::PacketPool*  packet_pool_;

      /// The transmitted packet.
      iron::Packet*  packet_;

      // The packet's stream sequence number.
      PktSeqNumber   seq_num_;

      /// The packet's connection sequence number.
      PktSeqNumber   conn_seq_num_;

      /// The packet's congestion control sequence number.
      PktSeqNumber   cc_seq_num_;

      /// The congestion-control-specific value when the packet was sent.
      float          cc_val_;

      /// The amount of time the packet was in the stream's transmit queue, in
      /// microseconds.
      uint32_t       q_delay_usec_;

      /// The measured RTT from the last ACK packet containing an observed
      /// packet timestamp for the packet, in microseconds.
      uint32_t       rtt_usec_;

      /// The initial packet transmission time.
      timeval        xmit_time_;

      /// The last packet transmission/retransmission time.
      timeval        last_xmit_time_;

      /// The packet length (not including headers) in bytes.
      uint16_t       pkt_len_;

      /// The total number of bytes sent for the packet (including SLIQ
      /// headers).
      uint16_t       bytes_sent_;

      /// The retransmission limit for the packet.
      RetransCount   rexmit_limit_;

      /// The retransmission count for the packet.
      RetransCount   rexmit_cnt_;

      /// The associated congestion control identifier.
      CcId           cc_id_;

      /// The packet's flags: FEC, FIN, blocked, acked, lost, and candidate.
      uint8_t        flags_;

      /// The sent packet count for this packet with the current
      /// retransmission count in the connection.
      PktCount       sent_pkt_cnt_;

      /// The sent packet count for this packet with the previous
      /// retransmission count in the connection.
      PktCount       prev_sent_pkt_cnt_;

      /// The FEC packet's group ID.
      FecGroupId     fec_grp_id_;

      /// The FEC packet's encoded packet length.
      FecEncPktLen   fec_enc_pkt_len_;

      /// The FEC packet's zero-based group index.
      FecSize        fec_grp_idx_;

      /// The FEC packet's number of FEC source packets in the FEC group.
      /// Only set in FEC encoded packets.
      FecSize        fec_num_src_;

      /// The FEC packet's round number.
      FecRound       fec_round_;

      /// The FEC packet's type.
      uint8_t        fec_pkt_type_;

      /// The FEC packet's last sent timestamp.
      PktTimestamp   fec_ts_;
    };

    /// A queue for sent packet information.
    struct SentPktQueue
    {
      SentPktQueue();
      virtual ~SentPktQueue();
      bool Init(WindowSize max_size);
      bool AddToTail();
      bool RemoveFromHead();
      inline WindowSize GetCount() const
      {
        return cnt_;
      }
      inline WindowSize GetMaxSize() const
      {
        return size_;
      }
      inline SentPktInfo& GetHead()
      {
        return buf_[head_];
      }
      inline SentPktInfo& Get(WindowSize offset_from_head)
      {
        return buf_[((head_ + offset_from_head) % size_)];
      }
      inline SentPktInfo& GetTail()
      {
        return buf_[((head_ + cnt_ + (size_ - 1)) % size_)];
      }

      /// The maximum number of packets that can be stored in the queue.
      WindowSize    size_;

      /// The current number of packets in the queue.
      WindowSize    cnt_;

      /// The index of the first packet in the queue.
      WindowSize    head_;

      /// The circular array of packets in the queue.
      SentPktInfo*  buf_;
    };

    /// Information for each FEC group.  The size of this structure needs to
    /// be as small as possible (currently 32 bytes on a 64-bit OS).
    struct FecGroupInfo
    {
      FecGroupInfo();
      virtual ~FecGroupInfo();

      /// The FEC group ID.
      FecGroupId    fec_grp_id_;

      /// The number of FEC source packets in the FEC group.
      FecSize       fec_num_src_;

      /// The number of FEC encoded packets in the FEC group.  Set to 0 when
      /// the number is not known yet.
      FecSize       fec_num_enc_;

      /// The number of FEC source packets ACKed in the FEC group.
      FecSize       fec_src_ack_cnt_;

      /// The number of FEC encoded packets ACKed in the FEC group.
      FecSize       fec_enc_ack_cnt_;

      /// The number identifying the current FEC transmission round.  The
      /// first round (sending original FEC source packets) is round 1.
      FecRound      fec_round_;

      /// The maximum number of transmission rounds for the FEC group.
      FecRound      fec_max_rounds_;

      /// The FEC round when the FEC encoded packets were first generated.
      FecRound      fec_gen_enc_round_;

      /// The number of FEC source packet transmissions and retransmissions
      /// allowed in the current round.
      FecSize       fec_src_to_send_icr_;

      /// The number of FEC encoded packet transmissions and retransmissions
      /// allowed in the current round.
      FecSize       fec_enc_to_send_icr_;

      /// The number of FEC source packet transmissions and retransmissions
      /// that have occurred in the current round.
      FecSize       fec_src_sent_icr_;

      /// The number of FEC encoded packet transmissions and retransmissions
      /// that have occurred in the current round.
      FecSize       fec_enc_sent_icr_;

      /// The retransmission limit for all FEC source and encoded packets in
      /// the group.
      RetransCount  fec_rexmit_limit_;

      /// The FEC group's flags: pure ARQ, latency sensitive, and force end.
      uint8_t       fec_flags_;

      /// The sequence number of the first FEC source packet in the group.
      PktSeqNumber  start_src_seq_num_;

      /// The sequence number of the last FEC source packet in the group.
      PktSeqNumber  end_src_seq_num_;

      /// The sequence number of the first FEC encoded packet in the group.
      PktSeqNumber  start_enc_seq_num_;

      /// The sequence number of the last FEC encoded packet in the group.
      PktSeqNumber  end_enc_seq_num_;
    };

    /// Information for determining the end of FEC group rounds.
    struct FecEndOfRndInfo
    {
      FecEndOfRndInfo();
      virtual ~FecEndOfRndInfo();

      /// The data packet timestamp, in microseconds, marking the end of the
      /// FEC group round.
      PktTimestamp    pkt_ts_;

      /// The FEC group bit vector of received observed packet information for
      /// this round.  The bit position is the packet's FEC group index.
      FecGroupBitVec  obs_pkt_bvec_;

      /// The FEC group ID.
      FecGroupId      fec_grp_id_;
    };

    /// Information for the VDM encoder.
    struct VdmEncodeInfo
    {
      VdmEncodeInfo();
      virtual ~VdmEncodeInfo();

      /// The number of FEC source data packets.
      int       num_src_pkt_;

      /// The number of FEC encoded data packets.
      int       num_enc_pkt_;

      /// The array of pointers to FEC source data packets.
      uint8_t*  src_pkt_data_[MAX_FEC_RATE];

      /// The array of FEC source data packet sizes in bytes.
      uint16_t  src_pkt_size_[MAX_FEC_RATE];

      /// The array of pointers to FEC encoded data packets.
      uint8_t*  enc_pkt_data_[MAX_FEC_RATE];

      /// The array of FEC encoded data packet sizes in bytes.
      uint16_t  enc_pkt_size_[MAX_FEC_RATE];
    };

    /// Information for packet send statistics.
    struct PktCounts
    {
      PktCounts();
      virtual ~PktCounts();

      /// The number of normal (non-FEC) packets transmitted.
      size_t  norm_sent_;

      /// The number of normal (non-FEC) packets retransmitted.
      size_t  norm_rx_sent_;

      /// The number of FEC source packets transmitted.
      size_t  fec_src_sent_;

      /// The number of FEC source packets retransmitted.
      size_t  fec_src_rx_sent_;

      /// The number of FEC encoded packets transmitted.
      size_t  fec_enc_sent_;

      /// The number of FEC encoded packets retransmitted.
      size_t  fec_enc_rx_sent_;

      /// The number of FEC groups sent that use pure FEC.
      size_t  fec_grp_pure_fec_;

      /// The number of FEC groups sent that use coded ARQ.
      size_t  fec_grp_coded_arq_;

      /// The number of FEC groups sent that use pure ARQ mode with N=1.
      size_t  fec_grp_pure_arq_1_;

      /// The number of FEC groups sent that use pure ARQ mode with N=2+.
      size_t  fec_grp_pure_arq_2p_;
    };

    /// \brief Copy constructor.
    SentPktManager(const SentPktManager& spm);

    /// \brief Assignment operator.
    SentPktManager& operator=(const SentPktManager& spm);

    /// \brief Get the largest observed sequence number from an ACK header.
    ///
    /// \param  ack_hdr  The ACK header.
    ///
    /// \return  The largest observed sequence number.
    PktSeqNumber GetLrgObsSeqNum(const AckHeader& ack_hdr);

    /// \brief Marked the specified packet as ACKed.
    ///
    /// \param  seq_num         The sequence number of the packet to be ACKed.
    /// \param  ack_hdr         The ACK header.
    /// \param  now             The current time.
    /// \param  new_data_acked  The new data ACKed flag that will be updated.
    /// \param  new_bif         The new bytes in flight value that will be
    ///                         updated.
    void MarkPktAcked(PktSeqNumber seq_num, const AckHeader& ack_hdr,
                      const iron::Time& now, bool& new_data_acked,
                      ssize_t& new_bif);

    /// \brief Possibly mark the specified packet as being lost.
    ///
    /// \param  seq_num      The sequence number of the packet that might be
    ///                      considered lost.
    /// \param  pkt_info     The packet information.
    /// \param  now          The current time.
    /// \param  rexmit_time  The current retransmit time from the RTT manager.
    /// \param  force_lost   A flag that forces the packet to be considered
    ///                      lost without consulting the congestion control
    ///                      algorithm.
    void MaybeMarkPktLost(PktSeqNumber seq_num, SentPktInfo& pkt_info,
                          const iron::Time& now,
                          const iron::Time& rexmit_time,
                          bool force_lost = false);

    /// \brief Check if a retransmission is allowed for a packet.
    ///
    /// This method is used for situations such as RTOs and outage recoveries,
    /// when a packet must be resent if possible.  This method only checks if
    /// the packet has the FIN flag set, is stale (including a time check), or
    /// is not to be retransmitted at all.  It does not perform any complex
    /// checks.
    ///
    /// \param  pkt_info     A reference to the packet information.
    /// \param  now          The current time.
    /// \param  rexmit_time  The current retransmit time estimate.
    ///
    /// \return  True if the packet can be retransmitted.
    bool AllowRexmitBasic(const SentPktInfo& pkt_info, const iron::Time& now,
                          const iron::Time& rexmit_time);

    /// \brief Check if a retransmission is allowed for a packet.
    ///
    /// This only checks if the packet has the FIN flag set, is stale (not
    /// including a time check), or is not to be retransmitted at all.  It
    /// includes detailed FEC group checks when in FEC mode.  It does not
    /// perform the fast retransmission checks, but does perform FEC checks if
    /// necessary.
    ///
    /// \param  pkt_info  A reference to the packet information.
    ///
    /// \return  True if the packet can be retransmitted.
    bool AllowRexmit(SentPktInfo& pkt_info);

    /// \brief Get the next FEC encoded packet from the specified queue and
    /// prepare it for transmission.
    ///
    /// \param  now        The current time.
    /// \param  cc_id      The congestion control identifier to use in the
    ///                    data packet header.
    /// \param  fec_enc_q  A reference to the SentPktQueue object where the
    ///                    FEC encoded packet is located.
    /// \param  hdr        A reference to the data header to be updated for
    ///                    sending the packet.
    /// \param  pkt        A reference to the pointer to the FEC packet.
    ///
    /// \return  True on success, or false otherwise.
    bool GetFecEncPkt(const iron::Time& now, CcId cc_id,
                      SentPktQueue& fec_enc_q, DataHeader& hdr,
                      iron::Packet*& pkt);

    /// \brief Move an FEC encoded packet that has been sent from its queue to
    /// the send window and update its information.
    ///
    /// The FEC encoded packet is removed from the queue before returning.
    ///
    /// \param  fec_enc_q     A reference to the SentPktQueue object where the
    ///                       FEC encoded packet is currently located.
    /// \param  hdr           A reference to the data header that was sent.
    /// \param  bytes_sent    The size of the SLIQ headers and payload sent,
    ///                       in bytes.
    /// \param  conn_seq      The transmitted packet's assigned connection
    ///                       sequence number.
    /// \param  sent_pkt_cnt  The transmitted packet's assigned sent data
    ///                       packet count for the connection.
    /// \param  xmit_time     The FEC encoded packet's transmission time.
    void MoveFecEncPkt(SentPktQueue& fec_enc_q, DataHeader& hdr,
                       size_t bytes_sent, PktSeqNumber conn_seq,
                       PktCount sent_pkt_cnt, const iron::Time& xmit_time);

    /// \brief Discard any original FEC encoded packets (unsent FEC encoded
    /// packets generated in round 1) at the head of the original queue that
    /// are invalid or no longer needed.
    void CleanUpOrigFecEncQueue();

    /// \brief Discard any additional FEC encoded packets (unsent FEC encoded
    /// packets generated in round 2+) at the head of the additional queue
    /// that are invalid or no longer needed.
    ///
    /// \param  seq_num  The temporary sequence number assigned to the
    ///                  additional FEC encoded packet that is being
    ///                  requested.
    void CleanUpAddlFecEncQueue(PktSeqNumber seq_num);

    /// \brief Empty the FEC encoded data packet queues.
    void EmptyFecEncodedPktQueues();

    /// \brief Drop any stale or lost packets when in semi-reliable or
    /// best effort modes.
    ///
    /// \param  now             The current time.
    /// \param  leaving_outage  Indicates if an outage is being exited or not.
    void DropPackets(const iron::Time& now, bool leaving_outage);

    /// \brief Reset the congestion control count adjustment information.
    void ResetCcCntAdjInfo();

    /// \brief Report any changes to the congestion control count adjustments
    /// to the congestion control algorithms.
    void ReportCcCntAdjToCc();

    /// \brief Report any changes to the oldest unacknowledged sequence
    /// numbers to the congestion control algorithms.
    void ReportUnaToCc();

    /// \brief Add any necessary time to go fields to a data packet that is to
    /// be transmitted.
    ///
    /// \param  now  The current time.
    /// \param  pkt  A pointer to the packet being transmitted.
    /// \param  hdr  A reference to the data header for the packet being
    ///              transmitted.  Must have the sequence number, FEC flag,
    ///              FEC group ID, and FEC packet type fields already set.
    ///              The TTG fields will be set by this method.
    void AddPktTtgs(const iron::Time& now, iron::Packet* pkt,
                    DataHeader& hdr);

    /// \brief Update the lowest FEC packet that is still needed by FEC.
    ///
    /// \param  force_fwd  A flag that forces the snd_fec_ to be forwarded up
    ///                    to snd_una_.
    void UpdateSndFec(bool force_fwd);

    /// \brief Record an ACK of a packet in its FEC group information.
    ///
    /// Note that the packet may or may not have been considered lost before
    /// this point.
    ///
    /// \param  now       The current time.
    /// \param  pkt_info  A reference to the packet information for the packet
    ///                   being ACKed.
    void RecordFecGroupPktAck(const iron::Time& now, SentPktInfo& pkt_info);

    /// \brief Generate the FEC encoded data packets for an FEC group.
    ///
    /// \param  start_src_seq_num  The starting FEC source data packet
    ///                            sequence number.
    /// \param  end_src_seq_num    The ending FEC source data packet sequence
    ///                            number.
    /// \param  grp_id             The FEC group ID.
    /// \param  n                  The code rate (n,k) n value.  This is the
    ///                            total number of FEC source and encoded data
    ///                            packets.
    /// \param  k                  The code rate (n,k) k value.  This is the
    ///                            number of FEC source data packets.
    /// \param  enc_offset         The offset of the first FEC encoded data
    ///                            packet to be generated.  Must be between 0
    ///                            and (n - k - 1).
    /// \param  enc_cnt            The number of FEC encoded data packets to
    ///                            be generated.  Must be between 1 and
    ///                            (n - k).
    /// \param  fec_enc_q          A reference to the SentPktQueue object
    ///                            where the generated FEC encoded packets
    ///                            will be added.
    /// \param  addl_flag          A flag that indicates if the generated FEC
    ///                            encoded packets are additional FEC encoded
    ///                            packets (generated in round 2+) (true) or
    ///                            original FEC encoded packets (generated in
    ///                            round 1) (false).
    ///
    /// \return  True if the FEC encoded data packets were generated, or false
    ///          otherwise.
    bool GenerateFecEncodedPkts(PktSeqNumber start_src_seq_num,
                                PktSeqNumber end_src_seq_num,
                                FecGroupId grp_id, FecSize n, FecSize k,
                                FecSize enc_offset, FecSize enc_cnt,
                                SentPktQueue& fec_enc_q, bool addl_flag);

    /// \brief Get the current FEC group round number for a packet
    /// retransmission.
    ///
    /// \param  grp_id  The FEC group ID.
    ///
    /// \return  The FEC group round number, or zero if the FEC group
    ///          information cannot be found.
    FecRound GetRexmitFecRound(FecGroupId grp_id);

    /// \brief Prepare the next FEC round.
    ///
    /// \param  grp_info  A reference to the group information.
    ///
    /// \return  True if there is another round to control the FEC packets
    ///          being sent, or false if there are no more rounds.
    bool PrepareNextFecRound(FecGroupInfo& grp_info);

    /// \brief Record the end of an FEC round to be watched for when ACK
    /// packets are processed.
    ///
    /// \param  now       The current time.
    /// \param  grp_info  A reference to the group information.
    /// \param  ts        The timestamp marking the end of the FEC group's
    ///                   round.
    void RecordEndOfFecRound(const iron::Time& now, FecGroupInfo& grp_info,
                             PktTimestamp ts);

    /// \brief Find all FEC group end of rounds and process them.
    ///
    /// \param  seq_num  The received ACK header's observed packet sequence
    ///                  number.
    /// \param  obs_ts   The received ACK header's observed packet timestamp.
    void ProcessEndOfFecRounds(PktSeqNumber seq_num, PktTimestamp obs_ts);

    /// \brief Update the local state to start the next FEC group.
    void StartNextFecGroup();

    /// \brief Create the FEC lookup tables.
    ///
    /// \author Steve Zabele
    ///
    /// \return  True if the tables are created successfully, or false on
    ///          error.
    bool CreateFecTables();

    /// \brief Allocate the memory for the FEC midgame and endgame lookup
    /// tables for the specified target number of rounds.
    ///
    /// \param  n  The target number of rounds.
    ///
    /// \return  True if the tables are allocated successfully, or false on
    ///          error.
    bool AllocateFecTables(FecRound n);

    /// \brief Update the FEC lookup table parameters.
    ///
    /// Updates the packet error rate (PER), target number of rounds (N), and
    /// number of source packets per group (k).  Called before the start of a
    /// new FEC group.
    ///
    /// \return  True if pure ARQ mode is to be used, or false otherwise.
    bool UpdateFecTableParams();

    /// \brief Get the 4D FEC lookup table index.
    ///
    /// \param  per_idx  The PER index.
    /// \param  k        The number of source packets per group.
    /// \param  sr       The number of source packets received.
    /// \param  cr       The number of coded packets received.
    ///
    /// \return  The index.
    size_t TableOffset(size_t per_idx, FecSize k, FecSize sr, FecSize cr);

    /// \brief Calculates the number of required packets to retransmit given
    /// the input parameters.
    ///
    /// \author Steve Zabele
    ///
    /// \param  max_grp_len  The maximum FEC group length in packets.
    /// \param  per          The packet error rate.
    /// \param  tgt_p_recv   The target packet receive probability.
    /// \param  num_src      The number of source packets in the FEC group.
    /// \param  src_rcvd     The number of source packets already received.
    /// \param  enc_rcvd     The number of encoded packets already received.
    /// \param  dof_to_send  A reference to where the degrees of freedom to
    ///                      send is placed.
    ///
    /// \return  The probability of success.
    double CalculateConditionalSimpleFecDofToSend(
      int max_grp_len, double per, double tgt_p_recv, int num_src,
      int src_rcvd, int enc_rcvd, uint8_t& dof_to_send);

    /// \brief Calculates the number of required packets to retransmit given
    /// the input parameters.
    ///
    /// \author Steve Zabele
    ///
    /// \param  max_grp_len  The maximum FEC group length in packets.
    /// \param  per          The packet error rate.
    /// \param  tgt_p_recv   The target packet receive probability.
    /// \param  num_src      The number of source packets in the FEC group.
    /// \param  src_rcvd     The number of source packets already received.
    /// \param  enc_rcvd     The number of encoded packets already received.
    /// \param  dof_to_send  A reference to where the degrees of freedom to
    ///                      send is placed.
    ///
    /// \return  The probability of success.
    double CalculateConditionalSystematicFecDofToSend(
      int max_grp_len, double per, double tgt_p_recv, int num_src,
      int src_rcvd, int enc_rcvd, uint8_t& dof_to_send);

    /// \brief Computes the probability of receiving a packet, given other
    /// packets in the FEC group have been received.
    ///
    /// \author Steve Zabele
    ///
    /// This method models a simple code, where at least num_src packets must
    /// be received to have usable source packets.
    ///
    /// \param  num_src      The number of source packets in the FEC group.
    /// \param  src_rcvd     The number of source packets already received.
    /// \param  enc_rcvd     The number of encoded packets already received.
    /// \param  dof_to_send  The number of packets to be transmitted.
    /// \param  per          The packet error rate.
    ///
    /// \return  The probability of receiving the packet.
    double ComputeConditionalSimpleFecPs(
      int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per);

    /// \brief Computes the probability of receiving a packet, given other
    /// packets in the FEC group have been received.
    ///
    /// \author Steve Zabele
    ///
    /// This method models a systematic code, where there is usable source
    /// packets even if enough packets are not received to decode the FEC.
    ///
    /// \param  num_src      The number of source packets in the FEC group.
    /// \param  src_rcvd     The number of source packets already received.
    /// \param  enc_rcvd     The number of encoded packets already received.
    /// \param  dof_to_send  The number of packets to be transmitted.
    /// \param  per          The packet error rate.
    ///
    /// \return  The probability of receiving the packet.
    double ComputeConditionalSystematicFecPs(
      int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per);

    /// \brief Compute the k-combination of n.
    ///
    /// \author Steve Zabele
    ///
    /// The k-combination of n is the subset of k distinct elements of S, with
    /// S containing n elements.  The order of the k distinct elements in the
    /// subset does not matter.
    ///
    /// \param  n  The number of elements in S.
    /// \param  k  The number of distinct elements of S being selected.
    ///
    /// \return  The k-combination of n as a double.
    double Combination(int n, int k);

    /// The number of lookup tables, indexed directly by the target number of
    /// rounds (N).  The valid range is 1 to kMaxTgtPktDelRnds.  The entry
    /// for index 0 is not used.
    static const size_t  kNumLookupTables = (sliq::kMaxTgtPktDelRnds + 1);

    /// The SLIQ connection.
    Connection&        conn_;

    /// The SLIQ stream.
    Stream&            stream_;

    /// The RTT manager.
    RttManager&        rtt_mgr_;

    /// The packet pool.
    iron::PacketPool&  packet_pool_;

    /// The congestion control algorithms.
    CcAlgs&            cc_algs_;

    /// The owning connection's ID.
    EndptId            conn_id_;

    /// The owning stream's ID.
    StreamId           stream_id_;

    /// The flag for recording if a packet with the FIN flag set has been
    /// sent.
    bool               fin_sent_;

    /// The reliability settings for the stream.  Note that rexmit_limit is
    /// set to zero if the reliability mode does not utilize packet
    /// retransmissions.
    Reliability        rel_;

    /// The oldest FEC sequence number that is still needed.  This packet will
    /// always be the lower edge of the current send window.
    PktSeqNumber       snd_fec_;

    /// The oldest unacknowledged sequence number.  May be as low as snd_fec_
    /// or as high as snd_nxt_.
    PktSeqNumber       snd_una_;

    /// The send window next sequence number to be sent.  May be as low as
    /// snd_una_, or up to just beyond the upper edge of the current send
    /// window.
    PktSeqNumber       snd_nxt_;

    /// The current next expected sequence number from received ACK packets.
    PktSeqNumber       rcv_ack_nxt_exp_;

    /// The current largest observed sequence number from received ACK
    /// packets.
    PktSeqNumber       rcv_ack_lrg_obs_;

    /// The previously reported largest observed connection sequence number.
    PktSeqNumber       last_lo_conn_seq_;

    /// The packet statistics for the stream.
    PktCounts          stats_pkts_;

    /// The number of bytes in flight to the peer.  Only includes data packets
    /// that have not been ACKed yet.  Includes the complete data packet size
    /// (both data header and payload sizes).
    ssize_t            stats_bytes_in_flight_;

    /// The amount of time allowed for sending the source packets in each FEC
    /// group, in seconds.
    double             stats_fec_src_dur_sec_;

    /// The packet inter-send time estimate, in seconds.
    double             stats_pkt_ist_;

    /// The latest packet error rate (PER) for the connection.
    double             fec_per_;

    /// The index for the current packet error rate (PER).
    size_t             fec_per_idx_;

    /// The index for the Epsilon value (target loss probability).
    size_t             fec_epsilon_idx_;

    /// The target number of FEC rounds.
    FecRound           fec_target_rounds_;

    /// The current FEC group index.
    FecSize            fec_grp_idx_;

    /// The current FEC group ID for the group of packets.
    FecGroupId         fec_grp_id_;

    /// The total number of FEC packets in the current FEC group.
    FecSize            fec_total_pkts_;

    /// The FEC dynamic source size value for the number of FEC source packets
    /// to use in the next FEC group.  Not used when in pure ARQ mode.
    FecSize            fec_dss_next_num_src_;

    /// The FEC dynamic source size value for the number of FEC groups
    /// completely sent before receiving an ACK for the group.
    FecSize            fec_dss_ack_after_grp_cnt_;

    /// The FEC mid-game lookup tables, indexed by the number of rounds (N).
    /// Each entry points to a 4D table that is indexed used TableOffset().
    uint8_t*           fec_midgame_tables_[kNumLookupTables];

    /// The FEC end-game lookup tables, indexed by the number of rounds (N).
    /// Each entry points to a 4D table that is indexed used TableOffset().
    uint8_t*           fec_endgame_tables_[kNumLookupTables];

    /// The circular array of FEC group information indexed by group ID.
    FecGroupInfo*      fec_grp_info_;

    /// The number of FEC end of round entries in the array.
    WindowSize         fec_eor_cnt_;

    /// The index of the first FEC end of round entry in the array.
    WindowSize         fec_eor_idx_;

    /// The circular array of FEC end of round information.
    FecEndOfRndInfo*   fec_eor_;

    /// The FEC encoded packets that have been generated in round 1 (and are
    /// thus considered original FEC encoded packets) and are waiting to be
    /// sent.
    SentPktQueue       fec_enc_orig_;

    /// The FEC encoded packets that have been generated in round 2+ (and thus
    /// are considered additional FEC encoded packets) and are waiting to be
    /// sent.
    SentPktQueue       fec_enc_addl_;

    /// The next temporary sequence number to assign to an additional FEC
    /// encoded packet.  Used in the stream's additional/retransmission
    /// candidate list.
    PktSeqNumber       fec_enc_tmp_seq_num_;

    /// The VDM encoder information.
    VdmEncodeInfo      vdm_info_;

    /// The array of congestion control count adjustment information.
    CcCntAdjInfo       cc_cnt_adj_[SliqApp::kMaxCcAlgPerConn];

    /// The array of congestion control unacknowledged packet information.
    CcUnaPktInfo       cc_una_pkt_[SliqApp::kMaxCcAlgPerConn];

    /// The circular array of sent packet information, with elements from
    /// snd_una_ up to (but not including) snd_nxt_.
    SentPktInfo*       sent_pkts_;

  }; // end class SentPktManager

} // end namespace sliq

#endif // IRON_SLIQ_SENT_PACKET_MANAGER_H_
