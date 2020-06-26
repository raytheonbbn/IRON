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

#ifndef IRON_UTIL_LINKEM_JITTER_MODEL_H
#define IRON_UTIL_LINKEM_JITTER_MODEL_H

#include <string>

/// Names of supported jitter models.
#define JITTER_MODEL_GMM  "GMM"
#define JITTER_MODEL_DMM  "DMM"
#define JITTER_MODEL_NONE "None"

/// \brief Pure virtual base class for jitter models.
class JitterModel
{
  public:

  /// \brief Creates a jitter model object.
  ///
  /// \param  type  The type of jitter model to create.
  ///
  /// \return A pointer to the created jitter model object on success, or NULL
  ///         if an error occurs.
  static JitterModel* Create(const std::string& type);

  /// \brief Default, no-arg constructor.
  JitterModel();

  /// \brief Destructor.
  virtual ~JitterModel();

  /// \brief Get the jitter model's jitter value, in nanoseconds.
  ///
  /// \return The jitter model's jitter value, in nanoseconds.
  virtual unsigned long long GetJitterInNsec() = 0;

  /// \brief Sets a jitter model feature value.
  ///
  /// \param  name   The jitter model feature name.
  /// \param  value  The jitter model feature value.
  ///
  /// \return True if the jitter model feature is successfully set, false if
  ///         an errors occurs.
  virtual bool SetFeature(const std::string& name,
                          const std::string& value) = 0;

  /// \brief Get a jitter model feature value.
  ///
  /// \param  name  The name of the jitter model feature whose value is being
  ///               requested.
  ///
  /// \return The jitter model feature value.
  virtual std::string GetFeature(const std::string& name) = 0;

  /// \brief Get the jitter model name.
  ///
  /// \return The jitter model name.
  inline std::string name() const
  {
    return name_;
  }

  /// \brief Get a string representation of the jitter model name and its
  /// features.
  ///
  /// \return String representation of the jitter model name and its
  ///         features.
  std::string ToString() const;

  protected:

  /// \brief Get a string representation of the jitter model's features.
  ///
  /// \return String representation of the jitter model's features.
  virtual std::string FeaturesToString() const = 0;

  /// The Jitter Model name.
  std::string  name_;

}; // end class JitterModel

#endif // IRON_UTIL_LINKEM_JITTER_MODEL_H
