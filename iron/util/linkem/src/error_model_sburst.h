/* IRON: iron_headers */
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

#ifndef IRON_UTIL_LINKEM_ERROR_MODEL_SBURST_H
#define IRON_UTIL_LINKEM_ERROR_MODEL_SBURST_H

#include "error_model.h"
#include "error_model_sber.h"
#include "high_resolution_clock.h"

/**
 * Gilbert-Elliot Burst Error Model.
 */
class SBURSTModel : public ErrorModel
{
  public:

  /// \brief Default constructor.
  SBURSTModel();

  /// \brief Destructor.
  virtual ~SBURSTModel();

  /// \brief Check the model for errors.
  ///
  /// \param  buf     The buffer containing the received packet.
  /// \param  length  The packet length.
  ///
  /// \return  True if model determines the packet has an error, false
  ///          otherwise.
  virtual bool CheckForErrors(const char* buf, unsigned int length);

  /// \brief Sets a model feature value.
  ///
  /// \param  name   The feature name.
  /// \param  value  The feature value.
  virtual void SetFeature(const std::string& name,
                          const std::string& value);

  /// \brief Get a model feature value.
  ///
  /// \param  name  The name of the feature whose value is being requested.
  ///
  /// \return The feature value.
  virtual std::string GetFeature(const std::string& name);

  protected:

  /// \brief Get a string representation of the error model's features.
  ///
  /// \return String representation of the error model's features.
  virtual std::string FeaturesToString() const;

  private:


  /// Copy constructor.
  SBURSTModel(const SBURSTModel& other);

  /// Copy operator.
  SBURSTModel& operator=(const SBURSTModel& other);

  /// Performs bit error model on packets when SBURST model is in the B state 

  /// Mean time spent in G state in ms
  double g_;

  /// Mean time spent in B state in ms
  double b_;

  /// Bit Error Rate when in B state
  double ber_;

  /// Pre computed log(1-ber_)
  double log_arg_;

  /// Time in ns that the transition G->B will occur
  unsigned long long  burst_start_time_;

  /// Time in ns that the transition B->G will occur
  unsigned long long  burst_end_time_;


  /// Used to give accurate time in ns
  HighResolutionClock  hrc_;

  /// Used to handle error when in B state
  SBERModel * sber_model;

}; // end class SBURSTModel

#endif // IRON_UTIL_LINKEM_EROR_MODEL_SBURST_H
