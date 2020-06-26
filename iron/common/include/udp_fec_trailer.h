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

#ifndef IRON_COMMON_UDP_FEC_TRAILER_H
#define IRON_COMMON_UDP_FEC_TRAILER_H

#include "iron_constants.h"
#include "itime.h"

/// Data structure describing the FEC chunk (or blob) trailer.
typedef struct fecchunktrailer // 2 bytes
{
  /// Boolean indicating if this contains multiple original packets
  unsigned short is_blob:1;  
  /// At most 32 packets (consistent with slotID limit below)
  unsigned short pkt_id:5;
  /// At most 31 chunks
  unsigned short chunk_id:5;
  /// At most 31 chunks
  unsigned short n_chunks:5;

  fecchunktrailer() : is_blob(0), pkt_id(0), chunk_id(0), n_chunks(0) {}
} FECChunkTrailer;

/// Data structure describing the FEC control trailer.
typedef struct feccontroltrailer // 18 Bytes
{
  /// Bytes 0 - 3.
  /// Indicates whether this is a original or repair (FEC) type.
  uint32_t  type:1;
  /// Indicates whether in order delivery is required.
  uint32_t  in_order:1;
  /// Indicates whether FEC is actually used.
  uint32_t  fec_used:1;
  /// No more then 32 slots.
  uint32_t  slot_id:5;
  /// The FEC group ID.
  uint32_t  group_id:24;
  /// Monotonically increasing for original packet only, repair packets 
  /// use the sequence number of the last original packet.  
  uint32_t  seq_number;
  /// Total bytes, up to and including this packet. 
  uint64_t  total_bytes_sent;
  /// The priority of the current flow to which the packet belongs.
  uint8_t   priority;
  /// The loss threshold for this flow, as a percentage.
  uint8_t   loss_thresh;
  /// The reordering time for this flow, in milliseconds.
  uint16_t  reorder_time_ms;
  feccontroltrailer() : type(0), in_order(0), fec_used(0), slot_id(0), group_id(0),
    seq_number(0), total_bytes_sent(0), priority(0), loss_thresh(100),
    reorder_time_ms(0)
  {}

  inline uint32_t get_seq_number() const {return seq_number; }
  inline void set_seq_number(uint32_t sn) { seq_number = sn; }
  inline uint32_t get_total_bytes_sent() const { return total_bytes_sent; }
  inline void set_total_bytes_sent(uint32_t bytes_sent) { total_bytes_sent = bytes_sent; }
  uint32_t get_slot_id() const { return slot_id; }
  uint32_t get_group_id() const { return group_id; }
  void set_group_id(const uint32_t id) { group_id = id; }

} __attribute__((packed)) FECControlTrailer;

/// Data structure describing the FEC repair trailer.
typedef struct fecrepairtrailer // 4 bytes
{
  unsigned char  base_rate;
  unsigned char  fec_rate;
  unsigned short fec_len;

  fecrepairtrailer() : base_rate(0), fec_rate(0), fec_len(0) {}
} FECRepairTrailer;

#endif // IRON_COMMON_UDP_FEC_TRAILER_H
