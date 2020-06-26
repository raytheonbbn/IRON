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

#ifndef IRON_TCP_PROXY_PKT_INFO_H
#define IRON_TCP_PROXY_PKT_INFO_H

#include "packet.h"
#include "pkt_info_pool.h"

/// Encapsulates a Packet with its associated meta-data.
struct PktInfo
{
  friend class PktInfoPool;

  iron::Packet*  pkt;
  uint32_t       seq_num;
  uint16_t       data_len;
  uint8_t        flags;
  uint32_t       timestamp;
  uint16_t       orig_tcp_cksum;
  uint16_t       orig_tcp_hdr_cksum;
  iron::Time     rexmit_time;
  PktInfo*       prev;
  PktInfo*       next;
  PktInfo*       rexmit_prev;
  PktInfo*       rexmit_next;
  uint32_t       last_flow_svc_id;
  bool           has_been_encapsulated;

  /// \brief Reset the PktInfo structure.
  void Reset()
  {
    pkt                   = NULL;
    seq_num               = 0;
    data_len              = 0;
    flags                 = 0;
    timestamp             = 0;
    orig_tcp_cksum        = 0;
    orig_tcp_hdr_cksum    = 0;
    rexmit_time.SetInfinite();
    prev                  = NULL;
    next                  = NULL;
    rexmit_prev           = NULL;
    rexmit_next           = NULL;
    last_flow_svc_id      = 0;
    has_been_encapsulated = false;
  }

  private:

  /// \brief Constructor.
  PktInfo()
  : pkt(NULL),
    seq_num(0),
    data_len(0),
    flags(0),
    timestamp(0),
    orig_tcp_cksum(0),
    orig_tcp_hdr_cksum(0),
    rexmit_time(),
    prev(NULL),
    next(NULL),
    rexmit_prev(NULL),
    rexmit_next(NULL),
    last_flow_svc_id(0),
    has_been_encapsulated(false)
  {
    rexmit_time.SetInfinite();
  }

  /// \brief Destructor.
  ~PktInfo() { }

};

#endif // IRON_TCP_PROXY_PKT_INFO_H
