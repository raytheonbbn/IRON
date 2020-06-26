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

#ifndef IRON_TCP_PROXY_SEND_BUFFER_H
#define IRON_TCP_PROXY_SEND_BUFFER_H

#include "pkt_info_pool.h"
#include "out_seq_buffer.h"
#include "tcp_proxy_config.h"

class Socket;

/// Manages the packets that are to be transmitted by the TCP Proxy.
///
/// The size of the buffer is the amount of application data that can be
/// stored. It does not include the headers (IP and TCP).
class SendBuffer
{
  public:

  /// \brief Constructor.
  ///
  /// \param  pkt_info_pool     The PktInfo pool.
  /// \param  max_size_bytes    The maximum size of the send buffer, in
  ///                           bytes.
  /// \param  adaptive_buffers  Indicates if adaptive buffers are being used.
  /// \param  socket            The Socket that owns the send buffer.
  SendBuffer(PktInfoPool& pkt_info_pool, uint32_t max_size_bytes,
             bool adaptive_buffers, Socket* socket);

  /// \brief Destructor.
  virtual ~SendBuffer();

  /// \brief Add a new Packet to the send buffer.
  ///
  /// The packets that get added to the send buffer are always in order. So
  /// when a Packet is enqueued, we can simply add it to the tail of the list.
  ///
  /// \param  pkt_info  The packet, and its associated metadata, to add to the
  ///                   send buffer.
  ///
  /// \return True if there is room in the send buffer, false if the buffer is
  ///         full.
  bool Enqueue(PktInfo* pkt_info);

  /// \brief Add a list of contiguous Packets to the send buffer.
  ///
  /// The packets that get added to the send buffer are always in order. So
  /// when a list of Packet is enqueued, we can simply add the new list to the
  /// tail of the existing list.
  ///
  /// \param  pkt_info_list  The list of Packets, and associated metadata, to
  ///                        add to the send buffer.
  ///
  /// \return True if there is room in the send buffer, false if the buffer is
  ///         full.
  bool EnqueuePackets(PktInfo* pkt_info_list);

  /// \brief Get the next packet to be transmitted.
  ///
  /// If there is a packet whose rexmit time has expired, it is selected as
  /// the next packet to be transmitted. Otherwise, the oldest new but
  /// untransmitted packet is selected for transmission.
  ///
  /// The send buffer maintains ownership of the packet selected for
  /// transmission. The caller must not delete it.
  ///
  /// \param  now        The current time.
  /// \param  sock_uwe   The socket's upper window edge.
  /// \param  cfg_if_id  The socket's configuration interface id.
  ///
  /// \return The next packet to be transmitted. NULL is returned if there are
  ///         no packets available for transmission.
  PktInfo* GetNextTransmission(iron::Time& now, uint32_t sock_uwe,
                               ProxyIfType cfg_if_id);

  /// \brief Record the successful transmission of a send buffer packet.
  ///
  /// This method modifies snd_nxt_ and snd_una_, if required.
  ///
  /// \param  pkt_info  Pointer to the PktInfo that was successfully
  ///                   transmitted.
  void RecordPktXmitSuccess(PktInfo* pkt_info);

  /// \brief Process a set of plugs.
  ///
  /// This will mark holes and remove plugs from the send buffer.
  ///
  /// \param  plugs        The set of plugs.
  /// \param  num_plugs    The number of plugs contained in the set of plugs.
  /// \param  buf_changed  Set to true if the plugs that are process change
  ///                      the state of the buffer.
  void ProcessPlugs(OutSeqBuffer::PlugInfo* plugs, uint32_t num_plugs,
                    bool& buf_changed);

  /// \brief Move a packet to the head of the retransmission list.
  ///
  /// When a RTO timeout occurs, the retransmission time of the packet at
  /// snd_una_ is set/reset. When this happens, the packet at snd_una_ needs
  /// to be the first packet in the retransmission list.
  ///
  /// \param  pkt_info  The packet that needs to be moved to the head of the
  ///                   retransmission list.
  void MoveToHeadOfRexmitList(PktInfo* pkt_info);

  /// \brief Move a packet to the end of the retransmission list.
  ///
  /// When a packet is retransmitted, its next retransmission time is
  /// adjusted. When this happens, it needs to be moved to the end of the
  /// retransmission list.
  ///
  /// \param  pkt_info  The packet that needs to be moved to the end of the
  ///                   retransmission list.
  void MoveToEndOfRexmitList(PktInfo* pkt_info);

  /// \brief Mark all packets in the buffer for retransmission.
  void ResendAllPkts();

  /// \brief Modify internal state in response to RTO.
  ///
  /// This moves the snd_nxt_ pointer back to snd_una_ when an RTO occurs when
  /// SACK is not supported.
  void GoBackN();

  /// \brief Release packets from the head of the send buffer.
  ///
  /// When the buffered packets have been successfully delivered to the
  /// destination (they have been sent and ACKed) they can be removed from the
  /// send buffer. This entails removing the packets from the buffer and
  /// recycling them.
  ///
  /// \param  seq_num  The sequence number that will be the new head of the
  ///                  send buffer. All packets with a sequence number less
  ///                  than this will be trimmed from the packet buffer.
  void Trim(uint32_t seq_num);

  bool RexmitSanityCheck();


  /// \brief Sets the TH_PUSH bit in the all of the Packets' TCP headers.
  void SetPacketsPushFlag();

  /// \brief Get the current size of the buffer, in bytes.
  ///
  /// \return The current size of the buffer, in bytes.
  inline uint32_t BytesInBuffer() const
  {
    return nxt_seq_ - una_seq_;
  }

  /// \brief Set the maximum size of the buffer, in bytes.
  ///
  /// \param  max_size_bytes The maximum size of the buffer, in bytes.
  inline void set_max_size_bytes(size_t max_size_bytes)
  {
    max_size_bytes_ = max_size_bytes;
  }

  /// \brief Get the maximum size of the buffer, in bytes.
  ///
  /// \return The maximum size of the buffer, in bytes.
  inline size_t max_size_bytes() const
  {
    return max_size_bytes_;
  }

  /// \brief Get the Packet at snd_una_ in the send buffer.
  ///
  /// The send buffer maintains ownership of the packet at snd_una_. The
  /// caller must not delete it.
  ///
  /// \return The packet at snd_una_ in the send buffer. NULL is returned if
  ///         snd_una_ is NULL.
  inline PktInfo* snd_una() const
  {
    return snd_una_;
  }

  /// \brief Get the next packet that contains new data from the send buffer.
  ///
  /// The send buffer maintains ownership of the new packet. The caller must
  /// not delete it.
  ///
  /// \return The next packet that contains new data in the send buffer. NULL
  ///         is returned if no such packet exists.
  inline PktInfo* snd_nxt() const
  {
    return snd_nxt_;
  }

  /// \brief Request a buffer size update.
  ///
  /// \param  rtt          The current RTT.
  /// \param  send_rate    The current send rate.
  /// \param  queue_depth  The current queue depth.
  void UpdateBufferSize(uint32_t rtt, double send_rate, uint32_t queue_depth);

  /// \brief Get the remaining usable window in the send buffer.
  ///
  /// \return The remaining usable window in the send buffer.
  size_t GetUsableWindow();

  /// \brief Get the upper window edge of the send buffer.
  ///
  /// The upper window edge of the send buffer is the sequence number of the
  /// first unacknowledged packet in the send buffer plus the maximum size of
  /// the send buffer.
  ///
  /// \return The upper window edge of the send buffer.
  uint32_t uwe();

  /// \brief Initialize the sequence number of the first unacknowledged packet
  /// in the send buffer.
  ///
  /// \param  una_seq_num  The sequence number of the first unacknowledged
  ///                      packet in the send buffer.
  inline void init_una_seq(uint32_t una_seq_num)
  {
    una_seq_ = una_seq_num;
    win_hwm_ = una_seq_ + max_size_bytes_;
  }

  /// \brief Initialize the sequence number of the next packet to be enqueued
  /// in the send buffer.
  ///
  /// \param  nxt_seq_num  The sequence number of the next packet to be
  ///                      enqueued in the send buffer.
  inline void init_nxt_seq(uint32_t nxt_seq_num)
  {
    nxt_seq_ = nxt_seq_num;
  }

  /// \brief Set the maximum size of the buffer, in bytes.
  ///
  /// \param  size_limit  The maximum size of the buffer, in bytes.
  inline void set_adaptive_buffer_size_limit(size_t size_limit)
  {
    adaptive_buffer_size_limit_ = size_limit;
  }

  /// \brief Get the number of bytes acked by the remote proxy.
  ///
  /// \return The number of bytes acked by the remote proxy.
  inline uint64_t cum_acked_bytes() const
  {
    return cum_acked_bytes_;
  }

  private:

  /// \brief Default no-arg Constructor.
  SendBuffer();

  /// \brief Copy constructor.
  SendBuffer(const SendBuffer& sb);

  /// \brief Copy operator.
  SendBuffer& operator=(const SendBuffer& sb);

  /// \brief Mark the packet as a hole.
  ///
  /// \param  pkt_info  The packet that is to be marked as a hole.
  /// \param  now       The current time.
  /// \param  force     Flag to force updating of the retransmit time.
  void MarkHole(PktInfo* pkt_info, iron::Time& now, bool force = false);

  /// \brief Release a list of contiguous packets from the send buffer.
  ///
  /// This will recycle the packets that are being released and modify the
  /// retransmission list if any of the released packets are part of it.
  ///
  /// \param  pkt_info  The first packet in the list of contiguous packets
  ///                   that are being released.
  void ReleasePkts(PktInfo* pkt_info);

  // The send buffer and retransmission list are depicted below:
  //
  //  snd_una_                     snd_nxt_      tail_              uwe
  //     |                             |           |                 |
  //     v                             v           v                 v
  //     +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
  //     | PI* | PI* | PI* | PI* | PI* | PI* | PI* | PI* |     |     |
  //     +-----+-----+-----+-----+-----+-----+-----+-----+-----+-----+
  //              |     |     |           |
  //              |     |  ---|  ---------|
  //           ---|  ---|  |     |
  //           |     |     |     |
  //           v     v     v     v
  //        +-----+-----+-----+-----+
  //        | PI* | PI* | PI* | PI* |
  //        +-----+-----+-----+-----+
  //        ^                 ^
  //        |                 |
  //   rexmit_head_      rexmit_tail_
  //
  // Packets are placed into the send buffer as they are received.
  //
  // If a packet has a retransmission time set, it is placed into the
  // retransmission list. NOTE: the retransmission list simply contains
  // pointers to the real packets in the send buffer, i.e., it is a "second
  // set of books" that enables for fast access to packets that need to be
  // retransmitted. The retransmission list does not duplicate packets.
  //
  // Packets are removed from the send buffer as TCP ACKs are received. If a
  // packet is removed that has a corresponding entry in the retransmission
  // list, the packet is also removed from the retransmission
  // list. Additionally, the Packets can be removed from the send buffer as
  // SACK Plugs are received. Once a Packet is removed from the send buffer,
  // it is never added back.

  /// The PktInfo pool.
  PktInfoPool&  pkt_info_pool_;

  /// Maximum size of the buffer, in bytes.
  size_t        max_size_bytes_;

  /// Pointer to the oldest sent but unacknowledged Packet in the buffer.
  PktInfo*      snd_una_;

  /// Pointer to the next new Packet that is available for transmission.
  PktInfo*      snd_nxt_;

  /// Pointer to the tail of the list of packets.
  PktInfo*      tail_;

  /// Pointer to the Socket that owns the buffer.
  Socket*       socket_;

  /// Sequence number of the first unacknowledged packet in the send buffer.
  uint32_t      una_seq_;

  /// Remember when the una_seq_ class member variable is first initialized.
  bool          una_seq_initialized_;

  /// Sequence number of the next packet to be enqueued in the send buffer.
  uint32_t      nxt_seq_;

  /// Pointer to the head of the retransmission list.
  PktInfo*      rexmit_head_;

  /// Pointer to the tail of the retransmission list.
  PktInfo*      rexmit_tail_;

  /// The upper window edge of the send buffer the last time the usable window
  /// was requested.
  uint32_t      win_hwm_;

  /// The last time that the buffer size was dynamically adjusted.
  iron::Time    last_size_update_time_;

  /// The number of bytes transmitted since the buffer size was last
  /// dynamically adjusted.
  size_t        xmit_bytes_since_last_size_update_;

  /// Remembers if adaptive buffers are being used.
  bool          adaptive_buffers_;

  /// The maximum allowable buffer size when adaptive buffers are used.
  uint32_t      adaptive_buffer_size_limit_;

  /// The smallest we'll allow the dynamic buffer size to be.
  uint32_t      adaptive_buffer_min_size_;

  /// The largest we'll allow the dynamic buffer size to be.
  uint32_t      adaptive_buffer_max_size_;

  /// The total number of bytes acked by the remote proxy.
  uint64_t      cum_acked_bytes_;

}; // end class SendBuffer

#endif // IRON_TCP_PROXY_SEND_BUFFER_H
