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

#ifndef IRON_SLIQ_RECEIVED_PACKET_MANAGER_H_
#define IRON_SLIQ_RECEIVED_PACKET_MANAGER_H_

#include "sliq_framer.h"
#include "sliq_types.h"
#include "sliq_vdm_fec.h"

#include "packet_pool.h"
#include "itime.h"


namespace sliq
{
  /// Class which holds all received data packets for a Stream.  The data
  /// packets are added to the receive window when they are received, and are
  /// released to the application in accordance with the delivery mode that is
  /// specified at creation time.  The receive window is slid forward when
  /// data packets have been delivered to the application or the sender has
  /// directed the receiver to skip over certain packets.
  ///
  /// The receive window utilizes the following locators:
  ///
  /// \verbatim
  ///     |<------------- rcv_wnd_ -------------->|
  ///
  ///     +---+---+---+---+---+---+---+---+---+---+
  ///     |   |   |   |   |   |   |   |   |   |   |
  ///     +---+---+---+---+---+---+---+---+---+---+
  ///       ^           ^                   ^
  ///       |           |                   |
  ///   rcv_min_     rcv_nxt_            rcv_max_
  ///
  ///   rcv_min_ - The lowest packet that is either waiting to be delivered to
  ///              the application or is still needed by FEC.  Marks the left
  ///              (lower) edge of the receive window.
  ///   rcv_nxt_ - The lowest missing packet.  Also called the "next expected"
  ///              packet.  May be as low as rcv_min_ or as high as the packet
  ///              just beyond rcv_max_.
  ///   rcv_max_ - The largest received packet.  Also called the "largest
  ///              observed" packet.  Determines the right (upper) edge of the
  ///              receive window.  May be as low as the packet before
  ///              rcv_min_.
  ///   rcv_wnd_ - The maximum size of the receive window in packets.
  ///              Determines the limit on the right (upper) edge of the
  ///              receive window given the current left (lower) edge.  Set to
  ///              kFlowCtrlWindowPkts.
  ///
  /// Note that:
  ///   rcv_min_        <=  rcv_nxt_  <=  (rcv_max_ + 1)
  ///   (rcv_min_ - 1)  <=  rcv_max_  <=  (rcv_min_ + rcv_wnd_ - 1)
  /// \endverbatim
  ///
  /// When using semi-reliable FEC mode, the left edge of the receive window
  /// may be determined by the lowest packet still needed by FEC in order to
  /// regenerate missing packets.  Otherwise, the left edge of the receive
  /// window is the lowest packet yet to be delivered to the application.
  class RcvdPktManager
  {
   public:

    /// Constructor.
    ///
    /// \param  conn         A reference to the SLIQ connection.
    /// \param  packet_pool  A reference to the PacketPool.
    /// \param  conn_id      The connection ID.
    /// \param  stream_id    The stream ID.
    explicit RcvdPktManager(Connection& conn, iron::PacketPool& packet_pool,
                            EndptId conn_id, StreamId stream_id);

    /// Destructor.
    virtual ~RcvdPktManager();

    /// \brief Initialize the received packet manager.
    ///
    /// \param  rel           The reliability settings for the stream.
    /// \param  del_mode      The delivery mode to the application.
    /// \param  init_seq_num  The initial sequence number that will be
    ///                       received.
    ///
    /// \return  True on success, or false on error.
    bool Initialize(const Reliability& rel, DeliveryMode del_mode,
                    PktSeqNumber init_seq_num);

    /// \brief Check that received data packet is good before processing it.
    ///
    /// \param  pkt  A reference to the received data packet.
    ///
    /// \return  Returns true if the data packet is not a duplicate, or false
    ///          otherwise.
    bool IsGoodDataPacket(DataHeader& pkt);

    /// \brief Add a packet that has been received.
    ///
    /// The received packet manager assumes ownership of the packet that has
    /// been received. It is responsible for either relinquishing ownership of
    /// the packet to another object or recycling the packet when it is no
    /// longer needed.
    ///
    /// \param  pkt       The received data packet contained in a data header
    ///                   structure.
    /// \param  rcv_time  The packet receive time.
    ///
    /// \return  Returns true if an ACK packet should be sent immediately due
    ///          to the reception of this data packet, or false if not.
    bool AddPkt(DataHeader& pkt, const iron::Time& rcv_time);

    /// \brief Get the next packet for the application.
    ///
    /// If a packet is available for delivery to the application, the caller
    /// assumes ownership of the Packet and is responsible for recycling it.
    ///
    /// \param  pkt             The packet to be delivered to the
    ///                         application.
    /// \param  payload_offset  The payload offset.
    /// \param  payload_len     The payload length.
    /// \param  fin_flag        Indicates if the packet has the FIN flag set.
    ///
    /// \return True if there is a packet available for delivery to the
    ///         application, false otherwise.
    bool GetNextAppPkt(iron::Packet*& pkt, size_t& payload_offset,
                       size_t& payload_len, bool& fin_flag);

    /// \brief Update the receive window based on a received move forward
    /// packet.
    ///
    /// Only called if the reliability mode is not RELIABLE_ARQ.
    ///
    /// \param  ne_seq_num  The next expected sequence number reported in the
    ///                     packet.
    ///
    /// \return  Returns true if an ACK packet should be sent immediately due
    ///          to the reception of this data packet, or false if not.
    bool MoveForward(PktSeqNumber ne_seq_num);

    /// \brief Prepare the information for the next ACK header.
    ///
    /// This method is used to prepare the information for and get the length
    /// of the next ACK header.  The length can then be used in order to
    /// determine if it will fit within a given packet before actually
    /// building the ACK header.  It must be called before calling
    /// GetNextAckHdr(), which will actually build the next ACK header using
    /// the information generated in this method.
    ///
    /// \return  The size of the next ACK header in bytes.
    size_t PrepareNextAckHdr();

    /// \brief Build the next ACK header after preparing the information for
    /// it.
    ///
    /// This method must be called after PrepareNextAckHdr() without any other
    /// calls into the received packet manager in between.  The information
    /// generated in PrepareNextAckHdr() is used to build the ACK header in
    /// this method.
    ///
    /// \param  ack_hdr  A reference to the ACK header that is to be updated.
    /// \param  now      The current time.
    ///
    /// \return  True if ACK header is created successfully.
    bool BuildNextAckHdr(AckHeader& ack_hdr, const iron::Time& now);

    /// \brief Check if there are any missing data packets.
    ///
    /// \return True if there is at least one missing data packet, or false
    /// otherwise.
    bool IsDataMissing() const;

    /// \brief Check if all of the data packets, including the data packet
    /// with the FIN, have been consumed (delivered to the application).
    ///
    /// \return True if all of the data packets, including the data packet
    ///         with the FIN, have been consumed, or false otherwise.
    bool IsAllDataAndFinConsumed() const;

   private:

    /// Captures the information for a packet that has been received.  The
    /// size of this structure needs to be as small as possible (currently 32
    /// bytes on a 64-bit OS).
    struct RcvdPktInfo
    {
      RcvdPktInfo();
      virtual ~RcvdPktInfo();
      void Clear();
      void MoveFecInfo(RcvdPktInfo& rpi);
      static void SetPacketPool(iron::PacketPool* pool)
      {
        packet_pool_ = pool;
      }

      /// The common packet pool pointer for recycling packets.
      static iron::PacketPool*  packet_pool_;

      /// The received packet.
      iron::Packet*  packet_;

      // The packet's sequence number.
      PktSeqNumber   seq_num_;

      /// The payload offset.
      uint16_t       payload_offset_;

      /// The payload length.
      uint16_t       payload_len_;

      /// The retransmission count.
      RetransCount   rexmit_cnt_;

      /// The packet's flags: FEC, FIN, received, regenerated, and delivered.
      uint8_t        flags_;

      /// The FEC packet's type.
      uint8_t        fec_pkt_type_;

      /// The FEC packet's group ID.
      FecGroupId     fec_grp_id_;

      /// The FEC packet's encoded packet length.
      FecEncPktLen   fec_enc_pkt_len_;

      /// The FEC packet's group index.
      FecSize        fec_grp_idx_;

      /// The FEC packet's number of FEC source packets in the group.  Only
      /// set in FEC encoded packets.
      FecSize        fec_num_src_;

      /// The FEC packet's round number.
      FecRound       fec_round_;
    };

    /// Captures the sequence numbers of the most recently received data
    /// packets for ACK block reporting.
    struct RctRcvInfo
    {
      RctRcvInfo();
      virtual ~RctRcvInfo();
      void RecordSeqNum(PktSeqNumber seq_num);
      bool GetSeqNum(size_t i, PktSeqNumber& seq_num);

      /// The number of elements in the array.
      size_t        cnt_;

      /// The offset for the most recent element in the array.
      size_t        offset_;

      /// The circular array of recently received data packet sequence
      /// numbers.
      PktSeqNumber  seq_num_[kAckHistorySize];
    };

    /// Captures ACK header ACK block information.
    struct AckBlkInfo
    {
      AckBlkInfo();
      virtual ~AckBlkInfo();
      inline void Clear()
      {
        cnt_     = 0;
        hdr_cnt_ = 0;
      }
      bool IsAlreadyInAckBlock(PktSeqNumber seq_num);
      void AddAckBlock(PktSeqNumber ack_lo, PktSeqNumber ack_hi);
      void AddAckBlocksToAckHdr(AckHeader& ack_hdr, PktSeqNumber ne_seq);

      /// The number of ACK blocks in the ack_blk_ array.
      size_t        cnt_;

      /// The number of ACK block offsets in the resulting ACK header.
      size_t        hdr_cnt_;

      /// The array of ACK blocks.  Index 0 is the low end and 1 is the high
      /// end of each ACK block.
      PktSeqNumber  ack_blk_[kMaxAckBlockOffsets][2];
    };

    /// Captures the observed time information for a data packet.
    struct PktObsTime
    {
      PktObsTime();
      virtual ~PktObsTime();

      /// The packet's sequence number.
      PktSeqNumber  seq_num_;

      /// The packet's timestamp.
      PktTimestamp  timestamp_;

      /// The packet receive time.
      iron::Time    rcv_time_;
    };

    /// Captures the information for observed time reporting.
    struct ObsTimeInfo
    {
      ObsTimeInfo();
      virtual ~ObsTimeInfo();
      void StoreObsTime(PktSeqNumber seq_num, PktTimestamp send_ts,
                        const iron::Time& rcv_time);
      void AddObsTimesToAckHdr(AckHeader& ack_hdr, const iron::Time& now);
      void AddLatestObsTimeToAckHdr(AckHeader& ack_hdr,
                                    const iron::Time& now);

      /// The number of observed time elements in the array.
      size_t      cnt_;

      /// The array of observed times.
      PktObsTime  obs_time_[kMaxObsTimes];

      /// The flag recording if there is a latest observed time or not.
      bool        has_latest_;

      /// The latest observed time.
      PktObsTime  latest_obs_time_;
    };

    /// Information for each FEC group.  The size of this structure needs to
    /// be as small as possible (currently 80 bytes on a 64-bit OS).
    struct FecGroupInfo
    {
      FecGroupInfo();
      virtual ~FecGroupInfo();

      /// The FEC group ID.
      FecGroupId    fec_grp_id_;

      /// The number of FEC source packets in the FEC group.
      FecSize       fec_num_src_;

      /// The number of FEC source packets received in the FEC group.
      FecSize       fec_src_rcvd_cnt_;

      /// The number of FEC encoded packets received in the FEC group.
      FecSize       fec_enc_rcvd_cnt_;

      /// The number of FEC source packets delivered from the FEC group.
      FecSize       delivered_cnt_;

      /// The number of TTG values stored in the array for the FEC group.
      TtgCount      ttg_cnt_;

      /// The lowest sequence number of the FEC source packets in the group.
      PktSeqNumber  start_src_seq_num_;

      /// The lowest sequence number of the FEC encoded packets in the group.
      PktSeqNumber  start_enc_seq_num_;

      /// The TTG values, in seconds, from the last received FEC encoded
      /// packet for the FEC group.
      float         ttg_[kMaxTtgs];
    };

    /// Information for the VDM decoder.
    struct VdmDecodeInfo
    {
      VdmDecodeInfo();
      virtual ~VdmDecodeInfo();

      /// The number of received FEC data packets.
      int            num_src_pkt_;

      /// The array of pointers to received FEC data packets.
      uint8_t*       in_pkt_data_[MAX_FEC_RATE];

      /// The array of received FEC data packet sizes in bytes.
      uint16_t       in_pkt_size_[MAX_FEC_RATE];

      /// The array of received FEC data packet encoded sizes.
      uint16_t       in_enc_pkt_size_[MAX_FEC_RATE];

      /// The array of received FEC data packet group indexes.
      int            in_pkt_index_[MAX_FEC_RATE];

      /// The array of pointers to Packet objects for regenerated FEC source
      /// data packets.
      iron::Packet*  out_pkt_[MAX_FEC_RATE];

      /// The array of pointers to received and regenerated FEC source data
      /// packets.
      uint8_t*       out_pkt_data_[MAX_FEC_RATE];

      /// The array of received and regenerated FEC source data packet sizes
      /// in bytes.
      uint16_t       out_pkt_size_[MAX_FEC_RATE];
    };

    /// Information for packet receive and regeneration statistics.
    struct PktCounts
    {
      PktCounts();
      virtual ~PktCounts();
      void Update(const Reliability& rel, const DataHeader& pkt);

      /// The number of FEC packets delivered to the application that were
      /// received in the target number of rounds.
      size_t      target_app_rcvd_;

      /// The total number of FEC packets that were received in the target
      /// number of rounds.
      size_t      target_tot_rcvd_;

      /// The number of original normal (non-FEC) packets received.
      size_t      norm_rcvd_;

      /// The number of retransmitted normal (non-FEC) packets received.
      size_t      norm_rx_rcvd_;

      /// The number of original FEC source packets received.
      size_t      fec_src_rcvd_;

      /// The number of retransmitted FEC source packets received.
      size_t      fec_src_rx_rcvd_;

      /// The number of FEC source packets regenerated.
      size_t      fec_src_regen_;

      /// The number of original FEC encoded packets received.
      size_t      fec_enc_rcvd_;

      /// The number of retransmitted FEC encoded packets received.
      size_t      fec_enc_rx_rcvd_;

      /// The total number of FEC source packets delivered to the application
      /// on time.
      size_t      fec_total_src_rcvd_;

      /// The total number of extra FEC source and encoded packets received on
      /// time but not adding any value.
      size_t      fec_total_ext_rcvd_;

      /// The number of raw goodput bytes delivered to the application.
      /// Includes the payload, base SLIQ data header (no FEC information),
      /// UDP header, IP header, and Ethernet header.
      size_t      raw_goodput_bytes_;

      /// The time that the first data was delivered to the application.
      iron::Time  start_time_;

      /// The time that the last data was delivered to the application.
      iron::Time  end_time_;
    };

    /// \brief Copy constructor.
    RcvdPktManager(const RcvdPktManager& rpm);

    /// \brief Assignment operator.
    RcvdPktManager& operator=(const RcvdPktManager& rpm);

    /// \brief Update the next expected sequence number.
    ///
    /// \param  reset_to_min  If true, then reset rcv_nxt_ to rcv_min_ before
    ///                       searching for the next expected packet.
    void UpdateNextExpected(bool reset_to_min);

    /// \brief Attempt to move the left edge of the receive window to the
    /// right.
    void MoveWindowRight();

    /// \brief Generate an ACK block for the specified sequence number.
    ///
    /// \param  seq_num  The data packet sequence number for the generated ACK
    ///                  block.
    void GenerateAckBlock(PktSeqNumber seq_num);

    /// \brief Store a received data packet.
    ///
    /// \param  pkt       The received data packet contained in a data header
    ///                   structure.
    /// \param  pkt_info  The location where the packet is to be stored.
    void StorePkt(DataHeader& pkt, RcvdPktInfo& pkt_info);

    /// \brief Attempt to regenerate any missing packets within the FEC group
    /// of the received FEC packet that has just been added to the window.
    ///
    /// \param  fec_pkt   The received FEC data packet that has just been
    ///                   added to the window.
    /// \param  rcv_time  The FEC data packet's receive time.
    void RegeneratePkts(DataHeader& fec_pkt, const iron::Time& rcv_time);

    // The receive window:
    //
    //     |<-------- rcv_wnd_ ------->|
    //
    //     +---+---+---+---+---+---+---+
    //     |   |   |   |   |   |   |   |
    //     +---+---+---+---+---+---+---+
    //       ^       ^           ^
    //       |       |           |
    //   rcv_min_ rcv_nxt_    rcv_max_
    //
    // Note that:
    //   rcv_min_        <=  rcv_nxt_  <=  (rcv_max_ + 1)
    //   (rcv_min_ - 1)  <=  rcv_max_  <=  (rcv_min_ + rcv_wnd_ - 1)

    /// The SLIQ connection.
    Connection&        conn_;

    /// The packet pool.
    iron::PacketPool&  packet_pool_;

    /// The owning connection's ID.
    EndptId            conn_id_;

    /// The owning stream's ID.
    StreamId           stream_id_;

    /// The reliability settings for the stream.
    Reliability        rel_;

    /// The delivery mode to the application.
    DeliveryMode       del_mode_;

    /// The receive window size in packets.  This is a fixed value.
    WindowSize         rcv_wnd_;

    /// The receive window minimum sequence number.  For all modes other than
    /// SEMI_RELIABLE_ARQ_FEC, this is the next packet to deliver to the
    /// application.  For SEMI_RELIABLE_ARQ_FEC mode, this may be either the
    /// next packet to deliver to the application, or the oldest FEC packet
    /// that must be retained in order to be able to regenerate missing
    /// packets.  All packets prior to this sequence number have been either
    /// delivered to the application or skipped due to received move forward
    /// information.  This locates the lower edge of the current receive
    /// window.
    PktSeqNumber       rcv_min_;

    /// The receive window next expected sequence number.  This is the lowest
    /// missing packet sequence number.  May be as low as rcv_min_, or up to
    /// just beyond rcv_max_.
    PktSeqNumber       rcv_nxt_;

    /// The receive window maximum sequence number.  This is the largest
    /// observed sequence number thus far.  May be as low as just before
    /// rcv_min_, or up to (rcv_min_ + rcv_wnd_ - 1).  This locates the upper
    /// edge of the current receive window.
    PktSeqNumber       rcv_max_;

    /// The flag for recording if the packet with the maximum received
    /// sequence number has the FIN flag set.
    bool               rcv_max_fin_flag_;

    /// The ACK block information.
    AckBlkInfo         ack_blk_;

    /// The VDM decoder information.
    VdmDecodeInfo      vdm_info_;

    /// The observed time information to be reported in the next ACK packet.
    ObsTimeInfo        obs_times_;

    /// The most recently received data packet sequence numbers to be reported
    /// in the next ACK packet.
    RctRcvInfo         rct_rcvs_;

    /// The packet statistics for the stream.
    PktCounts          stats_pkts_;

    /// The circular array of FEC group information indexed by group ID.
    FecGroupInfo*      fec_grp_info_;

    /// The array of received packet information for FEC source data packets
    /// prior to rcv_min_.  These packets are still needed for regenerating
    /// missing FEC source data packets and are indexed by the packet's FEC
    /// group index.
    RcvdPktInfo*       fec_src_pkts_;

    /// The circular array of received packet information, with elements from
    /// rcv_min_ up to (and including) rcv_max_.  The array is indexed by the
    /// packet's sequence number.
    RcvdPktInfo*       rcvd_pkts_;

  }; // end class RcvdPktManager

} // namespace sliq

#endif // IRON_SLIQ_RECEIVED_PACKET_MANAGER_H_
