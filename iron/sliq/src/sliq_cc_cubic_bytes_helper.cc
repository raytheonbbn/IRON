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

// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#include "sliq_cc_cubic_bytes_helper.h"
#include "sliq_private_defs.h"

#include "log.h"
#include "unused.h"

#include <cmath>
#include <inttypes.h>


using ::sliq::CubicBytesHelper;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName) = "CubicBytesHelper";

  /// Default maximum packet size used in the Linux TCP implementation.
  const size_t    kDefaultTcpMss = 1460;

  /// Constants based on TCP defaults.
  /// The following constants are in 2^10 fractions of a second instead of ms
  /// to allow a 10 shift right to divide.
  ///
  /// 1024*1024^3 (first 1024 is from 0.100^3) where 0.100 is 100 ms which is
  /// the scaling round trip time.
  const int       kCubeScale = 40;

  /// The cube congestion window scale.
  const int       kCubeCongestionWindowScale = 410;

  /// The cube factor for packets, in bytes.
  const uint64_t  kCubeFactor = ((UINT64_C(1) << kCubeScale) /
                                 kCubeCongestionWindowScale /
                                 kDefaultTcpMss);

  /// The default number of streams.
  const int       kDefaultNumStreams = 2;

  /// The default Cubic backoff factor.
  const double    kBeta = 0.7;

  // Additional backoff factor when loss occurs in the concave part of the
  // Cubic curve. This additional backoff factor is expected to give up
  // channel capacity to new concurrent flows and speed up convergence.
  const double    kBetaLastMax = 0.85;

  /// The number of microseconds in a second.
  const uint64_t  kNumMicrosPerSecond = (1000 * 1000);
}

//============================================================================
CubicBytesHelper::CubicBytesHelper(EndptId conn_id)
    : conn_id_(conn_id),
      num_streams_(kDefaultNumStreams),
      epoch_(),
      last_update_time_(),
      last_cwnd_(0),
      last_max_cwnd_(0),
      acked_bytes_count_(0),
      estimated_tcp_cwnd_(0),
      origin_point_cwnd_(0),
      time_to_origin_point_(0),
      last_target_cwnd_(0)
{
}

//============================================================================
CubicBytesHelper::~CubicBytesHelper()
{
  // Nothing to destroy.
}

//============================================================================
void CubicBytesHelper::Reset()
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Reset.\n", conn_id_);
#endif

  epoch_.Zero();
  last_update_time_.Zero();
  last_cwnd_            = 0;
  last_max_cwnd_        = 0;
  acked_bytes_count_    = 0;
  estimated_tcp_cwnd_   = 0;
  origin_point_cwnd_    = 0;
  time_to_origin_point_ = 0;
  last_target_cwnd_     = 0;
}

//============================================================================
size_t CubicBytesHelper::CongestionWindowAfterPacketLoss(size_t cur_cwnd)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args cwnd %zu #conn %d\n",
       conn_id_, cur_cwnd, num_streams_);
#endif

  if (cur_cwnd < last_max_cwnd_)
  {
    // We never reached the old max, so assume we are competing with another
    // flow.  Use our extra back off factor to allow the other flow to go up.
    last_max_cwnd_ = static_cast<size_t>(kBetaLastMax * cur_cwnd);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Never reached old cwnd "
         "max, set last_max_cwnd_ %zu\n", conn_id_, last_max_cwnd_);
#endif
  }
  else
  {
    last_max_cwnd_ = cur_cwnd;

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Reached old cwnd max, "
         "set last_max_cwnd_ %zu\n", conn_id_, last_max_cwnd_);
#endif
  }

  // Reset the cycle start time.
  epoch_.Zero();

  size_t  target_cwnd = static_cast<size_t>(cur_cwnd * Beta());

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": New cwnd %zu.\n",
       conn_id_, target_cwnd);
#endif

  return target_cwnd;
}

//============================================================================
size_t CubicBytesHelper::CongestionWindowAfterAck(
  size_t acked_bytes, size_t cur_cwnd, const Time& delay_min, const Time& now)
{
#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Args acked_bytes %zu "
       "cwnd %zu min_delay %s #conn %d\n", conn_id_, acked_bytes, cur_cwnd,
       delay_min.ToString().c_str(), num_streams_);
#endif

  acked_bytes_count_ += acked_bytes;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Update "
       "acked_bytes_count_ %zu\n", conn_id_, acked_bytes_count_);
#endif

  // Cubic is "independent" of RTT, the update is limited by the time elapsed.
  if ((last_cwnd_ == cur_cwnd) &&
      (now.Subtract(last_update_time_) <= MaxCubicTimeInterval()))
  {
    size_t  rv = ((last_target_cwnd_ > estimated_tcp_cwnd_) ?
                  last_target_cwnd_ : estimated_tcp_cwnd_);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": No cwnd change and not "
         "enough elapsed time, new cwnd %zu\n", conn_id_, rv);
#endif

    return rv;
  }

  last_cwnd_        = cur_cwnd;
  last_update_time_ = now;

  if (epoch_.IsZero())
  {
    // First ACK after a loss event.
#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Start of cubic "
         "epoch.\n", conn_id_);
#endif

    epoch_             = now;          // Start of epoch.
    acked_bytes_count_ = acked_bytes;  // Reset count.

    // Reset estimated_tcp_cwnd_ to be in sync with cubic.
    estimated_tcp_cwnd_ = cur_cwnd;

    if (last_max_cwnd_ <= cur_cwnd)
    {
      time_to_origin_point_ = 0;
      origin_point_cwnd_    = cur_cwnd;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Last cwnd <= "
           "current cwnd.\n", conn_id_);
#endif
    }
    else
    {
      time_to_origin_point_ = static_cast<uint32_t>(
        cbrt(kCubeFactor * (last_max_cwnd_ - cur_cwnd)));
      origin_point_cwnd_    = last_max_cwnd_;

#ifdef SLIQ_CC_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId ": Last cwnd > "
           "current cwnd.\n", conn_id_);
#endif
    }
  }

  // Change the time unit from microseconds to 2^10 fractions per second.
  // Take the round trip time in account.  This is done to allow us to use
  // shift as a divide operator.
  int64_t  elapsed_time =
    ((now.Add(delay_min).Subtract(epoch_).GetTimeInUsec() << 10) /
     kNumMicrosPerSecond);

  int64_t  offset = (time_to_origin_point_ - elapsed_time);

  size_t  delta_cwnd =
    (((kCubeCongestionWindowScale * offset * offset * offset) >> kCubeScale) *
     kDefaultTcpMss);

  size_t  target_cwnd = (origin_point_cwnd_ - delta_cwnd);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Computation, "
       "elapsed_time %" PRId64 " offset %" PRId64 " delta_cwnd %zu "
       "target_cwnd %zu\n", conn_id_, elapsed_time, offset, delta_cwnd,
       target_cwnd);
#endif

  // Increase the window by Alpha * 1 MSS of bytes every time we ACK an
  // estimated TCP window of bytes.
  if (estimated_tcp_cwnd_ > 0)
  {
    estimated_tcp_cwnd_ += ((acked_bytes_count_ *
                             (Alpha() * kDefaultTcpMss)) /
                            estimated_tcp_cwnd_);

#ifdef SLIQ_CC_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Computed "
         "estimated_tcp_cwnd_ %zu\n", conn_id_, estimated_tcp_cwnd_);
#endif
  }
  else
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": Warning, "
         "estimated_tcp_cwnd_ = 0.\n", conn_id_);
  }

  acked_bytes_count_ = 0;

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Resulting "
       "acked_bytes_count_ %zu estimated_tcp_cwnd_ %zu.\n", conn_id_,
       acked_bytes_count_, estimated_tcp_cwnd_);
#endif

  // We have a new cubic congestion window.
  last_target_cwnd_ = target_cwnd;

  // Compute target cwnd based on cubic target and estimated TCP
  // cwnd, use highest (fastest).
  if (target_cwnd < estimated_tcp_cwnd_)
  {
    target_cwnd = estimated_tcp_cwnd_;
  }

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": New cubic cwnd (target) "
       "%zu.\n", conn_id_, target_cwnd);
#endif

  return target_cwnd;
}

//============================================================================
double CubicBytesHelper::Alpha() const
{
  // TCPFriendly alpha is described in Section 3.3 of the CUBIC paper.  Note
  // that beta here is a cwnd multiplier, and is equal to 1-beta from the
  // paper.  We derive the equivalent alpha for an N-connection emulation as:
  const double  beta = Beta();

  double alpha = ((3.0 * num_streams_ * num_streams_ * (1.0 - beta)) /
                  (1.0 + beta));

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic alpha %f "
       "(#conn %d).\n", conn_id_, alpha, num_streams_);
#endif

  return alpha;
}

//============================================================================
double CubicBytesHelper::Beta() const
{
  // kNConnectionBeta is the backoff factor after loss for our N-connection
  // emulation, which emulates the effective backoff of an ensemble of N
  // TCP-Reno connections on a single loss event.  The effective multiplier is
  // computed as:
  if (num_streams_ == 0)
  {
    LogW(kClassName, __func__, "Conn %" PRIEndptId ": Warning, num_streams_ "
         "= 0.\n", conn_id_);
    return kBeta;
  }

  double  beta = (((num_streams_ - 1) + kBeta) / num_streams_);

#ifdef SLIQ_CC_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Cubic beta %f (#conn "
       "%d).\n", conn_id_, beta, num_streams_);
#endif

  return beta;
}
