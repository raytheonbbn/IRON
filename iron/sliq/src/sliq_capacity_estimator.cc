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

#include "sliq_capacity_estimator.h"

#include "sliq_private_defs.h"

#include "log.h"
#include "unused.h"

#include <inttypes.h>


using ::sliq::CapacityEstimator;
using ::iron::Log;
using ::iron::Time;


namespace
{

  /// Class name for logging.
  const char*   UNUSED(kClassName)       = "CapacityEstimator";

  /// The capacity estimate collection interval in milliseconds.
  const int64_t  kCollectionIntervalMsec = 1000;

  /// The congestion control rate estimate to peer receive rate agreement
  /// threshold for algorithms that do not use a congestion window.
  const double   kRateEstThresh          = 0.10;

  /// The maximum capacity estimate report interval, in seconds.
  const double   kMaxReportInterval      = 4.0;

  /// The capacity estimate change threshold for reporting decreases.
  const double   kCapEstReportThresh     = 0.10;

  /// The packet overhead due to Ethernet (8 + 14 + 4 = 26 bytes), IP (20
  /// bytes), and UDP (8 bytes), in bytes.  This assumes that no 802.1Q tag is
  /// present in the Ethernet frame, that no IP header options are present,
  /// and that IP fragmentation is not occurring.
  const size_t   kPktOverheadBytes       = 54;

}

//============================================================================
CapacityEstimator::CwndRate::CwndRate()
    : cwnd_size_(0),
      chan_rate_(0.0),
      trans_rate_(0.0),
      total_chan_rate_(0.0),
      total_trans_rate_(0.0)
{}

//============================================================================
CapacityEstimator::CwndRate::~CwndRate()
{}

//============================================================================
CapacityEstimator::CcState::CcState()
    : init_(false),
      use_cwnd_(true),
      start_cc_cwnd_(0),
      end_cc_cwnd_(0),
      end_cc_rate_(0.0),
      last_cc_limit_time_(),
      num_samples_(0),
      chan_acked_bytes_(0),
      trans_acked_bytes_(0),
      chan_recv_rate_(0.0),
      trans_recv_rate_(0.0),
      chan_cap_est_(0.0),
      trans_cap_est_(0.0),
      rate_()
{}

//============================================================================
CapacityEstimator::CcState::~CcState()
{}

//============================================================================
CapacityEstimator::CapacityEstimator()
    : conn_id_(0),
      is_in_outage_(false),
      start_time_(),
      collection_interval_(static_cast<double>(kCollectionIntervalMsec /
                                               1000.0)),
      next_report_time_(),
      chan_cap_est_(0.0),
      trans_cap_est_(0.0),
      last_chan_cap_est_(0.0),
      last_trans_cap_est_(0.0),
      cc_state_()
{}

//============================================================================
CapacityEstimator::~CapacityEstimator()
{}

//============================================================================
void CapacityEstimator::Initialize(EndptId conn_id)
{
  conn_id_ = conn_id;
}

//============================================================================
bool CapacityEstimator::InitCcAlg(CcId cc_id, bool use_cwnd, size_t cwnd)
{
  if ((cc_id >= SliqApp::kMaxCcAlgPerConn) || (cc_state_[cc_id].init_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid or already "
         "initialized cc_id %" PRICcId ".\n", conn_id_, cc_id);
    return false;
  }

  CcState&  state = cc_state_[cc_id];

  state.init_               = true;
  state.use_cwnd_           = use_cwnd;
  state.start_cc_cwnd_      = 0;
  state.end_cc_cwnd_        = cwnd;
  state.end_cc_rate_        = 0.0;
  state.last_cc_limit_time_ = Time::Now();
  state.num_samples_        = 0;
  state.chan_acked_bytes_   = 0;
  state.trans_acked_bytes_  = 0;
  state.chan_cap_est_       = 0.0;
  state.trans_cap_est_      = 0.0;

  if (use_cwnd)
  {
    for (size_t i = 0; i < kRateHistorySize; ++i)
    {
      state.rate_[i].cwnd_size_  = ((i == 0) ? cwnd : 0);
      state.rate_[i].chan_rate_  = 0.0;
      state.rate_[i].trans_rate_ = 0.0;
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": ccid %" PRICcId
         " rate_ [%zu/%f,%f/%f,%f] [%zu/%f,%f/%f,%f]\n", conn_id_, cc_id,
         state.rate_[0].cwnd_size_, state.rate_[0].chan_rate_,
         state.rate_[0].trans_rate_, state.rate_[0].total_chan_rate_,
         state.rate_[0].total_trans_rate_, state.rate_[1].cwnd_size_,
         state.rate_[1].chan_rate_, state.rate_[1].trans_rate_,
         state.rate_[1].total_chan_rate_, state.rate_[1].total_trans_rate_);
#endif
  }

  return true;
}

//============================================================================
bool CapacityEstimator::UpdateCapacityEstimate(
  CcId cc_id, const Time& now, size_t app_payload_bytes,
  size_t bytes_sent, size_t cwnd, double rate_est_bps, bool in_outage,
  double& chan_ce_bps, double& trans_ce_bps, double& ccl_time_sec)
{
  bool  rv = false;

#ifdef SLIQ_DEBUG
  LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %" PRICcId
       ": payload %zu sent %zu cwnd %zu rate %f outage %d.\n", conn_id_,
       cc_id, app_payload_bytes, bytes_sent, cwnd, rate_est_bps,
       static_cast<int>(in_outage));
#endif

  // Make sure that the congestion control algorithm was initialized.
  if ((cc_id >= SliqApp::kMaxCcAlgPerConn) || (!cc_state_[cc_id].init_))
  {
    LogE(kClassName, __func__, "Conn %" PRIEndptId ": Invalid or "
         "uninitialized cc_id %" PRICcId ".\n", conn_id_, cc_id);
    return rv;
  }

  // Handle currently being in an outage separately.
  if (in_outage)
  {
    // The capacity estimates are zero.
    chan_cap_est_  = 0.0;
    trans_cap_est_ = 0.0;

    // If entering an outage or if it is time, report the capacity estimate.
    if ((!is_in_outage_) || (now > next_report_time_))
    {
#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %" PRICcId
           ": Reporting outage.\n", conn_id_, cc_id);
#endif

      next_report_time_   = (now + kMaxReportInterval);
      last_chan_cap_est_  = chan_cap_est_;
      last_trans_cap_est_ = trans_cap_est_;
      chan_ce_bps         = chan_cap_est_;
      trans_ce_bps        = trans_cap_est_;
      ccl_time_sec        = 0.0;

      rv = true;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %" PRICcId
           ": Capacity report (outage): %f Mbps %f Mbps %f sec.\n", conn_id_,
           cc_id, (chan_ce_bps / 1.0e6), (trans_ce_bps / 1.0e6),
           ccl_time_sec);
#endif
    }

    is_in_outage_ = true;

    return rv;
  }

  // If leaving an outage, reset the state and start a new collection
  // interval.
  if (is_in_outage_)
  {
#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %" PRICcId
         ": Reset after outage.\n", conn_id_, cc_id);
#endif

    is_in_outage_        = false;
    start_time_          = now;
    collection_interval_ = Time::FromMsec(kCollectionIntervalMsec);
    next_report_time_    = (now + kMaxReportInterval);
    chan_cap_est_        = 0.0;
    trans_cap_est_       = 0.0;
    last_chan_cap_est_   = 0.0;
    last_trans_cap_est_  = 0.0;

    for (size_t i = 0; i < SliqApp::kMaxCcAlgPerConn; ++i)
    {
      CcState&  ccs = cc_state_[i];

      if (ccs.init_)
      {
        ccs.start_cc_cwnd_      = 0;
        ccs.end_cc_cwnd_        = 0;
        ccs.end_cc_rate_        = 0.0;
        ccs.last_cc_limit_time_ = now;
        ccs.num_samples_        = 0;
        ccs.chan_acked_bytes_   = 0;
        ccs.trans_acked_bytes_  = 0;
        ccs.chan_cap_est_       = 0.0;
        ccs.trans_cap_est_      = 0.0;
      }
    }
  }

  // Get accesss to the congestion control algorithm's state.
  CcState&  state = cc_state_[cc_id];

  // Check if it is the end of the current collection interval or not.
  if ((now - start_time_) > collection_interval_)
  {
    double  total_chan_recv_rate  = 0.0;
    double  total_trans_recv_rate = 0.0;

    // The collection interval is over.  Compute the raw peer receive rates
    // for each algorithm and the total raw peer receive rates for the
    // connection.
    for (size_t i = 0; i < SliqApp::kMaxCcAlgPerConn; ++i)
    {
      CcState&  ccs = cc_state_[i];

      if (ccs.init_)
      {
        ccs.chan_recv_rate_  =
          ((static_cast<double>(ccs.chan_acked_bytes_) * 8.0e6) /
           static_cast<double>(collection_interval_.GetTimeInUsec()));
        ccs.trans_recv_rate_ =
          ((static_cast<double>(ccs.trans_acked_bytes_) * 8.0e6) /
           static_cast<double>(collection_interval_.GetTimeInUsec()));

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": Bytes %zu %zu\n",
             conn_id_, ccs.chan_acked_bytes_, ccs.trans_acked_bytes_);
        LogD(kClassName, __func__, "Conn %" PRIEndptId ": PLT_RAW_CE %f %f\n",
             conn_id_, ccs.chan_recv_rate_, ccs.trans_recv_rate_);
#endif

        total_chan_recv_rate  += ccs.chan_recv_rate_;
        total_trans_recv_rate += ccs.trans_recv_rate_;
      }
    }

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": PLT_RAW_CE %f %f\n",
         conn_id_, total_chan_recv_rate, total_trans_recv_rate);
#endif

    // Update all of the congestion control algorithms.
    for (size_t i = 0; i < SliqApp::kMaxCcAlgPerConn; ++i)
    {
      CcState&  ccs = cc_state_[i];

      if (ccs.init_)
      {
#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %zu: Update "
             "capacity estimate.\n", conn_id_, i);
        LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %zu: start %d "
             "cwnd %zu %zu ccr %f samp %zu bytes %zu %zu rate %f %f ce %f %f "
             "rate_ [%zu/%f,%f/%f,%f] [%zu/%f,%f/%f,%f]\n", conn_id_, i,
             (int)ccs.use_cwnd_, ccs.start_cc_cwnd_, ccs.end_cc_cwnd_,
             ccs.end_cc_rate_, ccs.num_samples_, ccs.chan_acked_bytes_,
             ccs.trans_acked_bytes_, ccs.chan_recv_rate_,
             ccs.trans_recv_rate_, ccs.chan_cap_est_, ccs.trans_cap_est_,
             ccs.rate_[0].cwnd_size_, ccs.rate_[0].chan_rate_,
             ccs.rate_[0].trans_rate_, ccs.rate_[0].total_chan_rate_,
             ccs.rate_[0].total_trans_rate_, ccs.rate_[1].cwnd_size_,
             ccs.rate_[1].chan_rate_, ccs.rate_[1].trans_rate_,
             ccs.rate_[1].total_chan_rate_, ccs.rate_[1].total_trans_rate_);
#endif

        bool  cap_est_update = false;

        if (ccs.use_cwnd_ && (ccs.num_samples_ > 0))
        {
#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId ": PLT_CWND %zu "
               "%zu\n", conn_id_, ccs.end_cc_cwnd_, ccs.start_cc_cwnd_);
#endif

          // If the congestion window size has changed enough, then the
          // current peer receive rates are new candidates for the capacity
          // estimate.
          if (((ccs.end_cc_cwnd_ > ccs.start_cc_cwnd_) &&
               ((ccs.end_cc_cwnd_ - ccs.start_cc_cwnd_) > kMaxPacketSize)) ||
              ((ccs.end_cc_cwnd_ < ccs.start_cc_cwnd_) &&
               ((ccs.start_cc_cwnd_ - ccs.end_cc_cwnd_) > kMaxPacketSize)))
          {
            for (int idx = (kRateHistorySize - 1); idx > 0; --idx)
            {
              ccs.rate_[idx] = ccs.rate_[idx - 1];
            }

            ccs.rate_[0].cwnd_size_        = ccs.end_cc_cwnd_;
            ccs.rate_[0].chan_rate_        = ccs.chan_recv_rate_;
            ccs.rate_[0].trans_rate_       = ccs.trans_recv_rate_;
            ccs.rate_[0].total_chan_rate_  = total_chan_recv_rate;
            ccs.rate_[0].total_trans_rate_ = total_trans_recv_rate;

            ccs.last_cc_limit_time_ = now;

#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId ": Candidate "
                 "update (cwnd): %f Mbps %f Mbps.\n", conn_id_,
                 (ccs.rate_[0].total_chan_rate_ / 1.0e6),
                 (ccs.rate_[0].total_trans_rate_ / 1.0e6));
#endif
          }
          // Otherwise, if the total raw channel peer receive rate is higher,
          // then use the new results in place of the old results.
          else if (total_chan_recv_rate > ccs.rate_[0].total_chan_rate_)
          {
            ccs.rate_[0].chan_rate_        = ccs.chan_recv_rate_;
            ccs.rate_[0].trans_rate_       = ccs.trans_recv_rate_;
            ccs.rate_[0].total_chan_rate_  = total_chan_recv_rate;
            ccs.rate_[0].total_trans_rate_ = total_trans_recv_rate;

#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId ": Candidate "
                 "update (cwnd max): %f Mbps %f Mbps.\n", conn_id_,
                 (ccs.rate_[0].total_chan_rate_ / 1.0e6),
                 (ccs.rate_[0].total_trans_rate_ / 1.0e6));
#endif
          }

          // Update the algorithm's capacity estimate.
          double  old_cap_est = ccs.chan_cap_est_;

          ccs.chan_cap_est_  = ccs.rate_[0].total_chan_rate_;
          ccs.trans_cap_est_ = ccs.rate_[0].total_trans_rate_;

          for (int idx = 1; idx < static_cast<int>(kRateHistorySize); ++idx)
          {
            if (ccs.rate_[idx].total_chan_rate_ > ccs.chan_cap_est_)
            {
              ccs.chan_cap_est_  = ccs.rate_[idx].total_chan_rate_;
              ccs.trans_cap_est_ = ccs.rate_[idx].total_trans_rate_;
            }
          }

          if (ccs.chan_cap_est_ != old_cap_est)
          {
#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId ": Capacity "
                 "update (cwnd): %f Mbps %f Mbps.\n", conn_id_,
                 (ccs.chan_cap_est_ / 1.0e6), (ccs.trans_cap_est_ / 1.0e6));
#endif

            cap_est_update = true;
          }

          ccs.start_cc_cwnd_ = ccs.end_cc_cwnd_;
        }
        else if ((!ccs.use_cwnd_) && (ccs.num_samples_ > 0))
        {
#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId ": PLT_RATE %f\n",
               conn_id_, rate_est_bps);
#endif

          // If the congestion control send pacing rate matches the measured
          // peer receive rate close enough, then the current peer receive
          // rates are the algorithm's new capacity estimate.
          if ((ccs.end_cc_rate_ <= (ccs.chan_recv_rate_ *
                                    (1.0 + kRateEstThresh))) &&
              (ccs.end_cc_rate_ >= (ccs.chan_recv_rate_ *
                                    (1.0 - kRateEstThresh))))
          {
            ccs.rate_[0].chan_rate_        = ccs.chan_recv_rate_;
            ccs.rate_[0].trans_rate_       = ccs.trans_recv_rate_;
            ccs.rate_[0].total_chan_rate_  = total_chan_recv_rate;
            ccs.rate_[0].total_trans_rate_ = total_trans_recv_rate;

            ccs.chan_cap_est_  = total_chan_recv_rate;
            ccs.trans_cap_est_ = total_trans_recv_rate;

            ccs.last_cc_limit_time_ = now;

#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId ": Capacity "
                 "update (rate): %f Mbps %f Mbps.\n", conn_id_,
                 (ccs.chan_cap_est_ / 1.0e6), (ccs.trans_cap_est_ / 1.0e6));
#endif

            cap_est_update = true;
          }
          // Otherwise, if the total raw channel peer receive rate is higher,
          // then use the new results in place of the old results.
          else if (total_chan_recv_rate > ccs.rate_[0].total_chan_rate_)
          {
            ccs.rate_[0].chan_rate_        = ccs.chan_recv_rate_;
            ccs.rate_[0].trans_rate_       = ccs.trans_recv_rate_;
            ccs.rate_[0].total_chan_rate_  = total_chan_recv_rate;
            ccs.rate_[0].total_trans_rate_ = total_trans_recv_rate;

            ccs.chan_cap_est_  = total_chan_recv_rate;
            ccs.trans_cap_est_ = total_trans_recv_rate;

#ifdef SLIQ_DEBUG
            LogD(kClassName, __func__, "Conn %" PRIEndptId ": Capacity "
                 "update (rate max): %f Mbps %f Mbps.\n", conn_id_,
                 (ccs.chan_cap_est_ / 1.0e6), (ccs.trans_cap_est_ / 1.0e6));
#endif

            cap_est_update = true;
          }
        }

        if (cap_est_update)
        {
#ifdef SLIQ_DEBUG
          LogD(kClassName, __func__, "Conn %" PRIEndptId ": PLT_NEW_CE %f "
               "%f\n", conn_id_, ccs.chan_cap_est_, ccs.trans_cap_est_);
#endif
        }

#ifdef SLIQ_DEBUG
        LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %zu:   end %d "
             "cwnd %zu %zu ccr %f samp %zu bytes %zu %zu rate %f %f ce %f %f "
             "rate_ [%zu/%f,%f/%f,%f] [%zu/%f,%f/%f,%f]\n", conn_id_, i,
             (int)ccs.use_cwnd_, ccs.start_cc_cwnd_, ccs.end_cc_cwnd_,
             ccs.end_cc_rate_, ccs.num_samples_, ccs.chan_acked_bytes_,
             ccs.trans_acked_bytes_, ccs.chan_recv_rate_,
             ccs.trans_recv_rate_, ccs.chan_cap_est_, ccs.trans_cap_est_,
             ccs.rate_[0].cwnd_size_, ccs.rate_[0].chan_rate_,
             ccs.rate_[0].trans_rate_, ccs.rate_[0].total_chan_rate_,
             ccs.rate_[0].total_trans_rate_, ccs.rate_[1].cwnd_size_,
             ccs.rate_[1].chan_rate_, ccs.rate_[1].trans_rate_,
             ccs.rate_[1].total_chan_rate_, ccs.rate_[1].total_trans_rate_);
#endif
      }
    }

    double  new_chan_cap_est  = 0.0;
    double  new_trans_cap_est = 0.0;
    double  new_ccl_time      = 0.0;

    // Find the new capacity estimate and congestion control limit time for
    // the connection from all of the algorithm information.
    for (size_t i = 0; i < SliqApp::kMaxCcAlgPerConn; ++i)
    {
      CcState&  ccs = cc_state_[i];

      if (ccs.init_)
      {
        if (ccs.chan_cap_est_ > new_chan_cap_est)
        {
          new_chan_cap_est  = ccs.chan_cap_est_;
          new_trans_cap_est = ccs.trans_cap_est_;
        }

        double  ccl_time = (now - ccs.last_cc_limit_time_).ToDouble();

        if (ccl_time > new_ccl_time)
        {
          new_ccl_time = ccl_time;
        }
      }
    }

    chan_cap_est_  = new_chan_cap_est;
    trans_cap_est_ = new_trans_cap_est;

#ifdef SLIQ_DEBUG
    LogD(kClassName, __func__, "Conn %" PRIEndptId ": Total capest %f %f\n",
         conn_id_, chan_cap_est_, trans_cap_est_);
#endif

    // Reset the state for the next interval.
    start_time_          = now;
    collection_interval_ = Time::FromMsec(kCollectionIntervalMsec);

    for (size_t i = 0; i < SliqApp::kMaxCcAlgPerConn; ++i)
    {
      CcState&  ccs = cc_state_[i];

      if (ccs.init_)
      {
        ccs.num_samples_       = 0;
        ccs.chan_acked_bytes_  = 0;
        ccs.trans_acked_bytes_ = 0;
      }
    }

    // If the capacity estimate has changed enough or if it has been too long
    // since the last report time, then report the capacity estimate now.
    if ((chan_cap_est_ > last_chan_cap_est_) ||
        (chan_cap_est_ < (last_chan_cap_est_ *
                          (1.0 - kCapEstReportThresh))) ||
        (now > next_report_time_))
    {
      last_chan_cap_est_  = chan_cap_est_;
      last_trans_cap_est_ = trans_cap_est_;
      next_report_time_   = (now + kMaxReportInterval);
      chan_ce_bps         = chan_cap_est_;
      trans_ce_bps        = trans_cap_est_;
      ccl_time_sec        = new_ccl_time;

      rv = true;

#ifdef SLIQ_DEBUG
      LogD(kClassName, __func__, "Conn %" PRIEndptId " cc_id %" PRICcId
           ": Capacity report (normal): %f Mbps %f Mbps %f sec.\n", conn_id_,
           cc_id, (chan_ce_bps / 1.0e6), (trans_ce_bps / 1.0e6),
           ccl_time_sec);
#endif
    }
  }

  // Update this congestion control algorithm's state.
  if (bytes_sent > 0)
  {
    if (state.use_cwnd_)
    {
      state.end_cc_cwnd_ = cwnd;
    }
    else
    {
      state.end_cc_rate_ = rate_est_bps;
    }

    state.num_samples_       += 1;
    state.chan_acked_bytes_  += (kPktOverheadBytes + bytes_sent);
    state.trans_acked_bytes_ += app_payload_bytes;
  }

  return rv;
}
