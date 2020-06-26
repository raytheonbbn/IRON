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

#ifndef IRON_TCP_PROXY_PKT_INFO_POOL_H
#define IRON_TCP_PROXY_PKT_INFO_POOL_H

#include "packet_pool.h"
#include "pkt_info.h"

/// A pool of PktInfo objects.
class PktInfoPool
{
  public:

  /// \brief Constructor.
  ///
  /// \param  packet_pool  The Packet pool.
  PktInfoPool(iron::PacketPool& packet_pool);

  /// \brief Destructor.
  virtual ~PktInfoPool();

  /// \brief Get a PktInfo object from the pool.
  ///
  /// \param  packet  The IRON Packet that the PktInfo references.
  ///
  /// \return A pointer to the reused or newly allocated PktInfo object.
  PktInfo* Get(iron::Packet* packet = NULL);

  /// \brief Recycle a PktInfo object so that it may be reused later.
  ///
  /// \param  pkt_info  Pointer to the PktInfo object to be returned to the
  ///                   pool.
  void Recycle(PktInfo* pkt_info);

  private:

  /// The pool of PktInfo objects.
  PktInfo*           pool_;

  /// The IRON Packet pool.
  iron::PacketPool&  packet_pool_;

}; // end class PktInfoPool

#endif // IRON_TCP_PROXY_PKT_INFO_POOL_H
