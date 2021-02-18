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

#ifndef IRON_SLIQ_RTT_MANAGER_H_
#define IRON_SLIQ_RTT_MANAGER_H_

#include "sliq_types.h"

#include "log.h"
#include "itime.h"

namespace sliq
{
  class Connection;

  /// A class for managing RTT measurements.
  class RttManager
  {

   public:

    /// Constructor.
    RttManager();

    /// Destructor.
    virtual ~RttManager();

    /// \brief Configure the RTT outlier rejection setting.
    ///
    /// \param  enable_ror  The new RTT outlier rejection setting.
    void ConfigureRttOutlierRejection(bool enable_ror);

    /// \brief Updates the state using a new RTT sample.
    ///
    /// \param  now         The current time.
    /// \param  conn_id     The connection ID.  Only used for logging.
    /// \param  rtt_sample  The new RTT sample.
    void UpdateRtt(const iron::Time& now, EndptId conn_id,
                   const iron::Time& rtt_sample);

    /// \brief Updates the state using a new remote-to-local one-way delay
    /// (OWD) sample.
    ///
    /// \param  now             The current time.
    /// \param  conn_id         The connection ID.  Only used for logging.
    /// \param  rtl_owd_sample  The new remote-to-local OWD sample.
    void UpdateRmtToLocOwd(const iron::Time& now, EndptId conn_id,
                           const iron::Time& rtl_owd_sample);

    /// \brief Get the RTO time.
    ///
    /// The RTO time is computed as follows:
    ///
    ///   RTO = max( (A + 4D + ACK_DELAY), 200 msec )
    ///
    /// where A is the smoothed RTT, D is the smoothed mean deviation, and
    /// ACK_DELAY is the amount of time that an ACK can be delayed by a
    /// receiver.
    ///
    /// This is the standard RFC 6298 RTO time, with the addition of the ACK
    /// delay and the RTO floor changed from 1 second to 200 milliseconds to
    /// act more aggressively with retransmissions.
    ///
    /// \return  The next RTO time.
    iron::Time GetRtoTime() const;

    /// \brief Get the retransmission time.
    ///
    /// The retransmission time is computed as follows:
    ///
    ///   RXT = A + (M * D) + ACK_DELAY
    ///
    /// where A is the smoothed RTT, M is the multiplier, D is the smoothed
    /// mean deviation, and ACK_DELAY is the amount of time that an ACK can be
    /// delayed by a receiver.
    ///
    /// \param  multiplier  The smoothed mean deviation multiplier.  Defaults
    ///                     to 4, per RFC 6298.
    ///
    /// \return  The retransmission time.
    iron::Time GetRexmitTime(int multiplier = 4) const;

    /// \brief Get the fast retransmission time.
    ///
    /// The fast retransmission time is computed as follows:
    ///
    ///   FRXT = A + 4D
    ///
    /// where A is the smoothed RTT and D is the smoothed mean deviation.
    /// This is for use when packets are lost and ACKs are not being delayed
    /// by a receiver.
    ///
    /// \return  The fast retransmission time.
    iron::Time GetFastRexmitTime() const;

    /// \brief Get the smoothed RTT.
    ///
    /// This smoothed RTT is computed as described in RFC 6298.
    ///
    /// \return  The smoothed RTT.
    inline iron::Time smoothed_rtt() const
    {
      return srtt_obj_;
    }

    /// \brief Get the RTT's smoothed mean deviation.
    ///
    /// This smoothed mean deviation is computed as described in RFC 6298.
    ///
    /// \return  The RTT's smoothed mean deviation.
    inline iron::Time mean_deviation() const
    {
      return mdev_obj_;
    }

    /// \brief Get the recent minimum RTT received.
    ///
    /// Returns the minimum RTT observed during the current and previous two
    /// intervals.
    ///
    /// \return  The recent minimum RTT received.
    inline iron::Time minimum_rtt() const
    {
      return iron::Time(mmf_rtt_.min_est_);
    }

    /// \brief Get the recent maximum RTT received.
    ///
    /// If outlier rejection is disabled, then this method returns the maximum
    /// RTT observed during the current and previous two intervals.
    /// Otherwise, this method returns the median of the previous five
    /// intervals.
    ///
    /// \return  The recent maximum RTT received.
    inline iron::Time maximum_rtt() const
    {
      return iron::Time(mmf_rtt_.max_est_);
    }

    /// \brief Get the recent minimum remote-to-local one-way delay (OWD).
    ///
    /// Returns the minimum remote-to-local OWD observed during the current
    /// and previous two intervals.
    ///
    /// \return  The recent minimum remote-to-local OWD.
    inline iron::Time minimum_rtl_owd() const
    {
      return iron::Time(mmf_owd_.min_est_);
    }

    /// \brief Get the recent maximum remote-to-local one-way delay (OWD).
    ///
    /// If outlier rejection is disabled, then this method returns the maximum
    /// remote-to-local OWD observed during the current and previous two
    /// intervals.  Otherwise, this method returns the median of the previous
    /// five intervals.
    ///
    /// \return  The recent maximum remote-to-local OWD.
    inline iron::Time maximum_rtl_owd() const
    {
      return iron::Time(mmf_owd_.max_est_);
    }

    /// \brief Get the interval used for the maximum/minimum filtering.
    ///
    /// \return  The current maximum/minimum filtering interval.
    inline iron::Time max_min_filter_interval() const
    {
      return iron::Time(kMmfIntvMult * mmf_interval_srtt_);
    }

    /// \brief Get the latest RTT sample received.
    ///
    /// \return  The latest RTT sample received.
    inline iron::Time latest_rtt() const
    {
      return latest_rtt_;
    }

   private:

    /// \brief Copy constructor.
    RttManager(const RttManager& rm);

    /// \brief Assignment operator.
    RttManager& operator=(const RttManager& rm);

    /// The maximum number of intervals in the max/min filters.  Used for
    /// sizing the arrays of interval information in the max/min filter
    /// structure.
    static const size_t  kNumMmfIntv = 5;

    /// The multiplier to use to compute the max/min filter interval from the
    /// smoothed RTT.  The inter-packet send time oscillations in Copa may be
    /// up to approximately 8.5 times the smoothed RTT.  Using 10 instead of
    /// 8.5 improves the odds of witnessing an RTT maximum and minimum in each
    /// max/min filter interval.
    static const double  kMmfIntvMult = 10.0;

    /// \brief The structure for generating the maximum and minimum estimates
    /// for a time varying parameter.
    struct MaxMinFilter
    {
      /// \brief Constructor.
      MaxMinFilter()
          : init_(false),
            outlier_rejection_(false),
            interval_srtt_(0.0),
            prev_cnt_(0),
            prev_end_idx_(kNumMmfIntv - 1),
            prev_min_(),
            prev_max_(),
            curr_min_(0.0),
            curr_max_(0.0),
            curr_end_time_(0, 0),
            min_est_(0.0),
            max_est_(0.0)
      {}

      /// \brief Destructor.
      virtual ~MaxMinFilter()
      {}

      /// \brief Updates the state for a new sample.
      ///
      /// Make sure that interval_srtt_ is updated before calling this method.
      ///
      /// \param  now     The current time.
      /// \param  sample  The new sample, in seconds.
      void Update(const iron::Time& now, double sample);

      /// \brief Return the minimum value of the previous two intervals.
      ///
      /// \return  The minimum value found.
      double MinValue();

      /// \brief Return the maximum value of the previous two intervals.
      ///
      /// \return  The maximum value found.
      double MaxValue();

      /// \brief Return the maximum value using the median of the previous
      /// five intervals.
      ///
      /// \return  The maximum value found.
      double MedianFilterMaxValue();

      /// The initialization flag.
      bool        init_;

      /// The outlier rejection setting.
      bool        outlier_rejection_;

      /// The smoothed RTT for computing interval durations, in seconds.
      double      interval_srtt_;

      /// The count of previous intervals that are stored.
      size_t      prev_cnt_;

      /// The index of the last previous interval stored.
      size_t      prev_end_idx_;

      /// The array of stored minimum values for previous intervals.
      double      prev_min_[kNumMmfIntv];

      /// The array of stored maximum values for previous intervals.
      double      prev_max_[kNumMmfIntv];

      /// The minimum value observed in the current interval.
      double      curr_min_;

      /// The maximum value observed in the current interval.
      double      curr_max_;

      /// The end time for the current interval.
      iron::Time  curr_end_time_;

      /// The current minimum value estimate in seconds.
      double      min_est_;

      /// The current maximum value estimate in seconds.
      double      max_est_;
    };

    /// The initialization flag.
    bool          initialized_;

    /// The smoothed RTT in seconds.
    double        srtt_;

    /// The smoothed RTT as a Time object.
    iron::Time    srtt_obj_;

    /// The RTT's smoothed mean deviation in seconds.  This is an
    /// approximation of standard deviation.  The error is roughly 1.25 times
    /// larger than the standard deviation for a normally distributed signal.
    double        mdev_;

    /// The RTT's smoothed mean deviation as a Time object.
    iron::Time    mdev_obj_;

    /// The smoothed RTT, in seconds, for computing the max/min filter
    /// intervals.
    double        mmf_interval_srtt_;

    /// The max/min filter for RTTs.
    MaxMinFilter  mmf_rtt_;

    /// The max/min filter for remote-to-local one-way delays (OWDs).
    MaxMinFilter  mmf_owd_;

    /// The latest RTT sample.
    iron::Time    latest_rtt_;

  }; // end class RttManager

} // namespace sliq

#endif // IRON_SLIQ_RTT_MANAGER_H_
