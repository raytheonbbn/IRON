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

#ifndef IRON_UDP_PROXY_SRC_INFO_H
#define IRON_UDP_PROXY_SRC_INFO_H

#include "queue.h"

/// \brief A class to store and maintains information about the traffic source.
///
/// SrcInfo is used to access the size of the current backlog for the flow and
/// the total bytes sourced by the application.
class SrcInfo
{
  public:

  /// \brief Constructor.
  inline SrcInfo(iron::Queue& pkt_queue)
    : encoded_pkts_queue_(pkt_queue),
      total_bytes_sent_(0)
  {
  }
  
  /// \brief Destructor.
  virtual ~SrcInfo()
  {
  }

  /// \brief Get the total bytes sourced by the application.
  ///
  /// \return The total bytes sourced by the application. 
  inline uint64_t total_bytes_sent() const
  {
    return total_bytes_sent_;
  }

  /// \brief Get the current backlog size, in bytes.
  ///
  /// \return The current backlog size, in bytes.
  inline uint32_t cur_backlog_bytes() const
  {
    return encoded_pkts_queue_.GetSize();
  }

  /// \brief Increment the total bytes sent. 
  ///
  /// \param  new_bytes_sent  The total number of new bytes that have been
  ///                         sent.
  inline void UpdateTotalBytesSent(uint32_t new_bytes_sent)
  {
    total_bytes_sent_ += new_bytes_sent;
  }

  private:
  
  /// \brief No-arg constructor.
  SrcInfo();

  /// \brief Copy constructor.
  SrcInfo(const SrcInfo& si);

  /// \brief Assignment operator.
  SrcInfo& operator=(const SrcInfo& si);

  /// Reference to the encoded packets queue.
  iron::Queue&  encoded_pkts_queue_;

  /// The total number of bytes sent by the source application.
  uint64_t      total_bytes_sent_;

}; // end class SrcInfo

#endif // IRON_UDP_PROXY_SRC_INFO_H

