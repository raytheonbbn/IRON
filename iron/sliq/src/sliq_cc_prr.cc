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

#include "sliq_cc_prr.h"

#include "log.h"
#include "unused.h"


using ::sliq::Prr;
using ::iron::Log;


namespace
{
  /// Class name for logging.
  const char*   UNUSED(kClassName) = "Prr";

  /// Default maximum packet size used in the Linux TCP implementation.
  const size_t  kDefaultTcpMss = 1460;

  /// Constant based on TCP defaults.
  const size_t  kMaxSegmentSize = kDefaultTcpMss;
}

//============================================================================
Prr::Prr(EndptId conn_id)
    : conn_id_(conn_id),
      bytes_sent_since_loss_(0),       // prr_out_ = 0
      bytes_delivered_since_loss_(0),  // prr_delivered_ = 0
      ack_count_since_loss_(0),
      bytes_in_flight_before_loss_(0)
{
}

//============================================================================
Prr::~Prr()
{
}

//============================================================================
void Prr::OnPacketLost(size_t bytes_in_flight)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args bif %zu\n", conn_id_,
       bytes_in_flight);
#endif

  bytes_sent_since_loss_       = 0;  // prr_out_
  bytes_delivered_since_loss_  = 0;  // prr_delivered_
  ack_count_since_loss_        = 0;
  bytes_in_flight_before_loss_ = bytes_in_flight;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": PRR on packet lost"
       " bytes_in_flight_before_loss_ %zu"
       " bytes_sent_since_loss_ %zu"
       " bytes_delivered_since_loss_ %zu"
       " ack_count_since_loss_ %zu\n",
       conn_id_,
       bytes_in_flight_before_loss_,
       bytes_sent_since_loss_,
       bytes_delivered_since_loss_,
       ack_count_since_loss_);
#endif
}

//============================================================================
void Prr::OnPacketSent(size_t sent_bytes)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args bytes %zu\n",
       conn_id_, sent_bytes);
#endif

  bytes_sent_since_loss_ += sent_bytes;  // prr_out_ += bytes

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": PRR on packet sent"
       " bytes_in_flight_before_loss_ %zu"
       " bytes_sent_since_loss_ %zu"
       " bytes_delivered_since_loss_ %zu"
       " ack_count_since_loss_ %zu\n",
       conn_id_,
       bytes_in_flight_before_loss_,
       bytes_sent_since_loss_,
       bytes_delivered_since_loss_,
       ack_count_since_loss_);
#endif
}

//============================================================================
void Prr::OnPacketAcked(size_t acked_bytes)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args bytes %zu\n",
       conn_id_, acked_bytes);
#endif

  bytes_delivered_since_loss_ += acked_bytes;  // prr_delivered_ += bytes
  ++ack_count_since_loss_;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": PRR on packet ACKed"
       " bytes_in_flight_before_loss_ %zu"
       " bytes_sent_since_loss_ %zu"
       " bytes_delivered_since_loss_ %zu"
       " ack_count_since_loss_ %zu\n",
       conn_id_,
       bytes_in_flight_before_loss_,
       bytes_sent_since_loss_,
       bytes_delivered_since_loss_,
       ack_count_since_loss_);
#endif
}

//============================================================================
bool Prr::CanSend(size_t cwnd_bytes, size_t bytes_in_flight,
                  size_t ssthresh_bytes) const
{
#ifdef SLIQ_CC_DEBUG
  // LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args cwnd %zu bif %zu "
  //      "ssthresh %zu\n", conn_id_, cwnd_bytes, bytes_in_flight,
  //      ssthresh_bytes);
#endif

  if ((bytes_sent_since_loss_ == 0) || (bytes_in_flight < kMaxSegmentSize))
  {
#ifdef SLIQ_CC_DEBUG
    // LogD(kClassName, __func__, "Conn %" PRIEndptId ": Allow limited "
    //      "transmit during fast recovery, return true.\n", conn_id_);
#endif

    // Can send immediately in order to ensure limited transmit always works.
    return true;
  }

  if (cwnd_bytes > bytes_in_flight)
  {
    // During PRR-SSRB (Slow Start Reduction Bound), limit outgoing packets to
    // 1 extra MSS per ACK, instead of sending the entire available window.
    // This prevents burst retransmits when more packets are lost than the
    // cwnd reduction.
    //
    //   limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
    if ((bytes_delivered_since_loss_ +
         (ack_count_since_loss_ * kMaxSegmentSize)) <= bytes_sent_since_loss_)
    {
#ifdef SLIQ_CC_DEBUG
      // LogD(kClassName, __func__, "Conn %" PRIEndptId ": Deny transmit "
      //      "until ACK during fast recovery, PRR-SSRB, return false.\n",
      //      conn_id_);
#endif

      // Must wait to send.
      return false;
    }

#ifdef SLIQ_CC_DEBUG
    // LogD(kClassName, __func__, "Conn %" PRIEndptId ": Allow transmit due "
    //      "to ACKs during fast recovery, PRR-SSRB, return true.\n",
    //      conn_id_);
#endif

    // Can send immediately.
    return true;
  }

  // Implement Proportional Rate Reduction (RFC6937).  Checks a simplified
  // version of the PRR formula that doesn't use division:
  //
  // AvailableSendWindow =
  //   CEIL(prr_delivered * ssthresh / BytesInFlightAtLoss) - prr_sent
  if ((bytes_delivered_since_loss_ * ssthresh_bytes) >
      (bytes_sent_since_loss_ * bytes_in_flight_before_loss_))
  {
#ifdef SLIQ_CC_DEBUG
    // LogD(kClassName, __func__, "Conn %" PRIEndptId ": Allow transmit due "
    //      "to bytes in flight during fast recovery, PRR, return true.\n",
    //      conn_id_);
#endif

    // Can send immediately.
    return true;
  }

#ifdef SLIQ_CC_DEBUG
  // LogD(kClassName, __func__, "Conn %" PRIEndptId ": PRR, return false.\n",
  //      conn_id_);
#endif

  // Must wait to send.
  return false;
}
