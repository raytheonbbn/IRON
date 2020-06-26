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

#ifndef IRON_TCP_PROXY_OUT_SEQ_BUFFER_H
#define IRON_TCP_PROXY_OUT_SEQ_BUFFER_H

#include "packet.h"
#include "pkt_info_pool.h"

class Socket;

/// Provides an out of sequence Packet buffer.
class OutSeqBuffer
{
  public:

  /// \brief Constructor.
  ///
  /// \param  pkt_info_pool   A reference to the PktInfo pool.
  /// \param  max_size_bytes  The maximum size of the packet buffer, in
  ///                         bytes.
  /// \param  socket          The Socket that owns the out-of-sequence
  ///                         buffer.
  OutSeqBuffer(PktInfoPool& pkt_info_pool, uint32_t max_size_bytes,
               Socket* socket);

  /// \brief Destructor.
  virtual ~OutSeqBuffer();

  /// \brief Add a Packet to the tail of the buffer.
  ///
  /// The buffer assumes ownership of the Packet that is enqueued.
  ///
  /// \param  pkt_info  Pointer to the Packet, and its metadata, to be
  ///                   enqueued.
  ///
  /// \return True if there is room in the buffer, false if the buffer is
  ///         full.
  bool Enqueue(PktInfo* pkt_info);

  /// \brief Get the PktInfo at the head of the buffer.
  ///
  /// The caller assumes ownership of the PktInfo that is dequeued.
  ///
  /// \return  Pointer to the PktInfo at the head of the buffer. NULL is
  ///          returned if the buffer is empty.
  PktInfo* Dequeue();

  /// \brief Insert a Packet into the out-of-sequence buffer.
  ///
  /// This is invoked when packets arrive out of order. In order packets are
  /// placed into the buffer via the Enqueue() method.
  ///
  /// \param  pkt_info  The Packet, and its metadata, to insert into the
  ///                   out-of-sequence buffer.
  ///
  /// \return True if the insertion is successful, false otherwise.
  bool Insert(PktInfo* pkt_info);

  /// \brief Get a pointer to the head of the out-of-sequence buffer.
  ///
  /// The out-of-sequence buffer maintains ownership of the packet at the head
  /// of the buffer. The caller must not delete it.
  ///
  /// \return Pointer to the head of the out-of-sequence buffer.
  PktInfo* head() const
  {
    return head_;
  }

  /// \brief Get a pointer to the tail of the out-of-sequence buffer.
  ///
  /// The out-of-sequence buffer maintains ownership of the packet at the tail
  /// of the buffer. The caller must not delete it.
  ///
  /// \return Pointer to the tail of the out-of-sequence buffer.
  PktInfo* tail() const
  {
    return tail_;
  }

  /// \brief Get the size of the buffer, in bytes.
  ///
  /// \return The size of the buffer, in bytes.
  inline size_t size_bytes() const
  {
    return size_bytes_;
  }

  typedef struct plug_info
  {
    uint32_t lower_seq;
    uint32_t upper_seq;
  } PlugInfo;

  /// \brief Gather plug information
  ///
  /// \param  plugs        Array of PlugInfos to cotain the plugs found
  /// \param  max_to_find  Number of plugs to find. Plugs is at least this long
  /// 
  /// \return The number of plugs found
  size_t GatherPlugs(PlugInfo* plugs, uint32_t max_to_find);

  /// \brief Find a specific plug covering a sequence number
  ///
  /// \param  plug  Plug covering the sequence number
  ///
  /// \return Success or failure. Should never fail
  bool GetPlugCoveringLastPkt(PlugInfo& plug);

  /// \brief Set the last inserted sequence number when a packet passed
  /// directly to the send buffer.
  ///
  /// If a packet is enqueued directly into the send buffer, it bypasses the
  /// setting of last inserted sequence which is needed for SACK generation.
  ///
  /// \param  seq_num  The sequence number of the packet that was enqueued
  ///                  directly into the send buffer.
  inline void set_last_inserted_seq(uint32_t seq_num)
  {
    last_inserted_seq_ = seq_num;
  }

  private:

  /// \brief Default no-arg Constructor.
  OutSeqBuffer();

  /// \brief Copy constructor.
  OutSeqBuffer(const OutSeqBuffer& osb);

  /// \brief Copy operator.
  OutSeqBuffer& operator=(const OutSeqBuffer& osb);

  /// \brief Unlink the head of the out-of-sequence buffer from the list of
  /// packets.
  ///
  /// \return The PktInfo at the head of the out-of-sequencebuffer, or NULL if
  ///         there are no packets in the buffer.
  PktInfo* UnlinkHead();

  // The following depicts the out-of-sequence buffer.
  //
  //     +-----+-----+-----+-----+-----+-----+-----+-----+-----+
  //     | PI* | PI* | PI* | PI* | PI* | PI* |     |     |     |
  //     +-----+-----+-----+-----+-----+-----+-----+-----+-----+
  //        ^                             ^
  //        |                             |
  //      head_                         tail_

  /// The PktInfo pool.
  PktInfoPool&  pkt_info_pool_;

  /// The current, instantaneous, size of the buffer, in bytes.
  size_t        size_bytes_;

  /// Maximum size of the buffer, in bytes.
  size_t        max_size_bytes_;

  /// Pointer to the head of the linked list of Packets in the out-of-sequence
  /// buffer.
  PktInfo*      head_;

  /// Pointer to the tail of the linked list of Packets in the out-of-sequence
  /// buffer.
  PktInfo*      tail_;

  /// Sequence number for the last packet added to the out of sequence buffer
  uint32_t      last_inserted_seq_;

  /// Pointer to the Socket that owns the buffer.
  Socket*       socket_;

}; // end class OutSeqBuffer

#endif // IRON_TCP_PROXY_OUT_SEQ_BUFFER_H
