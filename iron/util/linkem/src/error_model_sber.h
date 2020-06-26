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

#ifndef IRON_UTIL_LINKEM_ERROR_MODEL_SBER_H
#define IRON_UTIL_LINKEM_ERROR_MODEL_SBER_H

#include "error_model.h"

class SBERModel : public ErrorModel
{
  public:

  /// \brief Default constructor.
  SBERModel();

  /// \brief Destructor.
  virtual ~SBERModel();

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
  SBERModel(const SBERModel& other);

  /// Copy operator.
  SBERModel& operator=(const SBERModel& other);

  /// The Bit Error Rate.
  double  ber_;

  double  log_arg_;

}; // end class SBERModel

#endif // IRON_UTIL_LINKEM_ERROR_MODEL_SBER_H
