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

/// \brief The IRON Random Number Generator header file.
///
/// Provides the IRON software with a Random Number Generator.

#ifndef IRON_COMMON_RNG_H
#define IRON_COMMON_RNG_H

#include <string>

#include <cstdio>
#include <cstdlib>
#include <stdint.h>

namespace iron
{

  /// \brief Class implementing a standalone Random Number Generator.
  ///
  /// This class is a simple wrapper around the thread-safe random_r(3).  It
  /// allows someone to set the seed and call GetInt(), GetFloat(), and
  /// GetRand().
  class RNG
  {

   public:

    /// \brief Default constructor to create and initialize a RNG with seed
    ///	equals to 'now'.
    RNG();

    /// \brief Constructor to create and initialize a RNG with specified
    /// seed.
    ///
    /// \param  seed  The seed of the RNG.
    RNG(uint32_t seed);

    /// \brief Destructor.
    virtual ~RNG();

    /// \brief Method to set the seed of the RNG.
    ///
    /// \param  seed  The seed of the RNG.
    ///
    /// \return  Returns true on success, or false otherwise.
    bool SetSeed(uint32_t seed);

    /// \brief Method to display human-readable text about the object.
    ///
    /// \return  A string describing the RNG object.
    std::string ToString();

    /// \brief Method to get the next random integer in the RNG.
    ///
    /// \param  upper  The upper bound of the returned random number.  It
    ///                cannot be less than 1 or larger than the RNG's maximum
    ///                number (returned by GetRandMaxValue()).
    ///
    /// \return  The next integer in the generator mapped to [0, upper].  Note
    ///          that upper may be returned.  If an error occurs, then -1 is
    ///          returned.
    int32_t GetInt(int32_t upper);

    /// \brief Method to get the next random float in the RNG.
    ///
    /// \param  upper  The upper bound of the returned random number.  It
    ///                cannot be smaller than 0.000001.
    ///
    /// \return  The next float in the generator mapped to [0, upper].  Note
    ///          that upper may be returned.  If an error occurs, then -1.0 is
    ///          returned.
    float GetFloat(float upper);

    /// \brief Method to get the next random double in the RNG.
    ///
    /// \param  upper  The upper bound of the returned random number.  It
    ///                cannot be smaller than 0.000001.
    ///
    /// \return  The next double in the generator mapped to [0, upper].  Note
    ///          that upper may be returned.  If an error occurs, then -1.0 is
    ///          returned.
    double GetDouble(double upper);

    /// \brief Method to get a random sequence of bytes from the RNG.
    ///
    /// \param  dst    A pointer to the location where the random bytes will
    ///                be placed.
    /// \param  bytes  The number of random bytes to generate and place
    ///                sequentially in dst.
    ///
    /// \return  Returns true on success, or false if an error occurs.
    bool GetByteSequence(uint8_t* dst, size_t bytes);

    /// \brief Method to get the next raw random number in the RNG.
    ///
    /// \return  The next random integer in the generator in the range
    ///          [0, GetRandMaxValue()], or -1 on error.
    int32_t GetRand();

    /// \brief Method to get the maximum random number returned by
    /// GetRand().
    ///
    /// \return  The maximum random number returned by GetRand().
    inline int32_t GetRandMaxValue()
    {
      return RAND_MAX;
    }

  private:

    /// \brief Method to create and initialize a RNG with specified seed
    ///
    /// \param  seed  The seed to use for the RNG.
    void InitRNG(unsigned int seed);

    /// \brief Copy constructor.
    RNG(const RNG& rng);

    /// \brief Assignment operator.
    void operator=(const RNG& rng);

    /// The RNG state array.  May be 8, 32, 64, 128, or 256 elements long.
    /// See random(3) for details.
    char                 state_array_[64];

    /// The RNG state information.
    struct random_data   state_info_;

    /// RNG seed
    uint32_t             seed_;

  }; // class RNG

} // namespace iron

#endif //IRON_COMMON_RNG_H
