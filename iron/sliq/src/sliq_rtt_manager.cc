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

// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//============================================================================

#include "sliq_rtt_manager.h"
#include "sliq_connection.h"
#include "sliq_private_defs.h"

#include "log.h"
#include "unused.h"

#include <cstdlib>
#include <inttypes.h>


using ::sliq::RttManager;
using ::iron::Log;
using ::iron::Time;


namespace
{
  /// Class name for logging.
  const char*   UNUSED(kClassName) = "RttManager";

  /// Initial smoothed RTT used before any samples are received, per RFC 6298.
  const int          kInitialRttMsec    = 1000;

  /// Initial RTO used before any samples are received, per RFC 6298.
  const int          kInitialRtoMsec    = 1000;

  /// The mimimum allowable RTO in milliseconds.  Note that RFC 6298 specifies
  /// that this should be set to 1 second, but this uses 200 milliseconds to
  /// be more aggressive.
  const int          kMinRtoMsec        = 200;

  /// The RTO tolerance in microseconds.
  const suseconds_t  kRtoToleranceUsec  = 4000;

  /// The gain, g, used to compute the smoothed RTT.  Set to 1/8 (0.125) per
  /// RFC 6298.
  const double       kAlpha             = 0.125;

  /// One minus the alpha parameter.
  const double       kOneMinusAlpha     = (1.0 - kAlpha);

  /// The gain, h, used to compute the mean deviation.  Set to 1/4 (0.25) per
  /// RFC 6298.
  const double       kBeta              = 0.25;

  /// One minus the beta parameter.
  const double       kOneMinusBeta      = (1.0 - kBeta);
}

//============================================================================
RttManager::RttManager()
    : initialized_(false),
      smoothed_rtt_(),
      mean_deviation_(),
      latest_rtt_(),
      min_rtt_()
{
  smoothed_rtt_ = Time::FromMsec(kInitialRttMsec);
}

//============================================================================
RttManager::~RttManager()
{
  // Nothing to destroy.
}

//============================================================================
void RttManager::UpdateRtt(EndptId conn_id, const Time& rtt_sample)
{
  // Update the minimum RTT observed.
  if ((!initialized_) || (min_rtt_ > rtt_sample))
  {
    min_rtt_ = rtt_sample;
  }

  // Store that latest RTT sample.
  latest_rtt_ = rtt_sample;

  // Next, update the smoothed RTT and the smoothed mean deviation.
  if (!initialized_)
  {
    // This is the first RTT sample received.  Follow RFC 6298.
    smoothed_rtt_   = rtt_sample;
    mean_deviation_ = Time::FromUsec(rtt_sample.GetTimeInUsec() / 2);
    initialized_    = true;
  }
  else
  {
    // Update following RFC 6298.
    mean_deviation_ = Time::FromUsec(
      static_cast<int64_t>(
        (kOneMinusBeta * mean_deviation_.GetTimeInUsec()) +
        (kBeta *
         labs(smoothed_rtt_.Subtract(rtt_sample).GetTimeInUsec()))));

    smoothed_rtt_ = smoothed_rtt_.Multiply(kOneMinusAlpha).Add(
      rtt_sample.Multiply(kAlpha));
  }

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId ": Sample(us) %" PRId64
       " smoothed_rtt(us) %" PRId64 " mean_deviation(us) %" PRId64 ".\n",
       conn_id, rtt_sample.GetTimeInUsec(), smoothed_rtt_.GetTimeInUsec(),
       mean_deviation_.GetTimeInUsec());
#endif
}

//============================================================================
Time RttManager::GetRtoTime() const
{
  // Until a RTT measurement has been made, the RTO should be set to 1 second.
  // See RFC 6298.
  if (!initialized_)
  {
    return Time::FromMsec(kInitialRtoMsec);
  }

  // The RTO is the smoothed RTT plus 4 times the RTT mean deviation.  Since
  // ACKs can be delayed at the receiver, include that time too.
  Time  rto = (smoothed_rtt_.Add(mean_deviation_.Multiply(4)) +
               Time(0, (kAckTimerUsec + kRtoToleranceUsec)));

  // Round up to a mimimum allowable RTO.  See RFC 6298.
  return Time::Max(rto, Time::FromMsec(kMinRtoMsec));
}

//============================================================================
Time RttManager::GetRexmitTime(int multiplier) const
{
  // Until a RTT measurement has been made, the retransmission time should be
  // set to 1 second.  See RFC 6298.
  if (!initialized_)
  {
    return Time::FromMsec(kInitialRtoMsec);
  }

  // The retransmission time is the smoothed RTT plus the specified multiplier
  // times the RTT mean deviation.  Since ACKs can be delayed at the receiver,
  // include that time too.
  Time  rxt = (smoothed_rtt_.Add(mean_deviation_.Multiply(multiplier)) +
               Time(0, (kAckTimerUsec + kRtoToleranceUsec)));

  return rxt;
}

//============================================================================
Time RttManager::GetFastRexmitTime() const
{
  // Until a RTT measurement has been made, the fast retransmission time
  // should be set to 1 second.  See RFC 6298.
  if (!initialized_)
  {
    return Time::FromMsec(kInitialRtoMsec);
  }

  // The fast retransmission time is the smoothed RTT plus 4 times the RTT
  // mean deviation.
  Time  frxt = smoothed_rtt_.Add(mean_deviation_.Multiply(4));

  return frxt;
}
