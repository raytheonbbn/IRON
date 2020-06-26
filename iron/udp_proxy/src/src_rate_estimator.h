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

#ifndef IRON_UDP_PROXY_SRC_RATE_ESTIMATOR_H
#define IRON_UDP_PROXY_SRC_RATE_ESTIMATOR_H

#include "inttypes.h"

/// \brief The SrcRateEstimator computes and maintains an average of the rate
///        at which packets are being sourced by the application.
///
/// The average is computed by sampling the bytes received from the application
/// over intervals and aggregated using an exponentially weighted moving
/// average.
class SrcRateEstimator
{
  public:

  /// \brief No-arg constructor.
  SrcRateEstimator();

  /// \brief Destructor.
  virtual ~SrcRateEstimator();

  /// \brief Compute and update the average rate at which packets are
  /// sourced.
  ///         
  /// \param  bytes_sourced  The number of bytes sourced.
  /// \param  ttg            The time-to-go, in microseconds, of the packet
  ///                        used for the computation.
  void UpdateRate(uint64_t bytes_sourced, uint64_t ttg);

  /// \brief Get the time since the average source rate was last updated. 
  ///
  /// \return The time at which the last average source rate was updated.
  inline uint64_t rate_comp_ttg_usec() const {return rate_comp_ttg_usec_; }

  /// \brief  Get the total bytes sourced at the time the source rate was
  ///         last computed.
  /// \return The the total bytes sourced at the time the source rate was
  ///         last computed.
  inline uint64_t rate_comp_bytes() const {return rate_comp_bytes_; } 

  /// \brief  Get the computed average rate at which packets are sourced. 
  ///
  /// \return The computed average rate at which packets are sourced.
  double avg_src_rate();

  private:
  
  /// \brief Copy constructor.
  SrcRateEstimator(const SrcRateEstimator& sre);

  /// \brief Assignment operator.
  SrcRateEstimator& operator=(const SrcRateEstimator& sre);

  /// The time-to-go on the last packet used to compute the source rate.
  uint64_t  rate_comp_ttg_usec_;

  /// The number of bytes sourced up to the last packet used to compute 
  /// source rate.
  uint64_t  rate_comp_bytes_;

  /// The average rate at which packets are being sourced. 
  double    avg_src_rate_;

}; // end class SrcRateEstimator

#endif // IRON_UDP_PROXY_SRC_RATE_ESTIMATOR_H
