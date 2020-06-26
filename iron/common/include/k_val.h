//============================================================================
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

///
/// Class for storing and using the fluid K value: the previous and current
/// value of K, the time to start transitioning, and how long the transition
/// should take.
///

#ifndef IRON_COMMON_K_VAL_H
#define IRON_COMMON_K_VAL_H

#include "iron_constants.h"
#include "itime.h"
#include "log.h"

#include <inttypes.h>
#include <string>
#include <stdint.h>
#include <sstream>

namespace iron
{
  /// \brief Class representing a fluid K value.
  class KVal
  {
    public:

    /// \brief Default constructor.
    KVal() : k_current_(static_cast<uint64_t>(kDefaultK)),
      k_diff_(0), start_time_ms_(0), transition_time_ms_(0)
    {};

    /// \brief Copy constructor.
    ///
    /// \param other KVal to copy.
    KVal(const KVal& other) :
      k_current_(other.k_current_), k_diff_(other.k_diff_),
      start_time_ms_(other.start_time_ms_),
      transition_time_ms_(other.transition_time_ms_)
    {};

    /// \brief Destructor.
    virtual ~KVal() {};

    /// \brief Assignment operator.
    ///
    /// \param other KVal to copy.
    /// \return KVal the new instance.
    inline KVal& operator=(const KVal& other)
    {
      if (this != &other)
      {
        k_current_ = other.k_current_;
        k_diff_ = other.k_diff_;
        start_time_ms_ = other.start_time_ms_;
        transition_time_ms_ = other.transition_time_ms_;
      }
      return *this;
    }

    /// \brief Set the current k value. Used for initialization.
    ///
    /// \param k_current The value to use.
    inline void set_k_current(uint64_t k_current)
    {
      LogA("KVal", __func__, "Set K current to %" PRIu64 "\n", k_current);
      k_current_ = k_current;
    }

    /// \brief Set all the values.
    ///
    /// \param   new_k_val      The value to which we want to transition.
    /// \param   start_transition_time_ms  What time (in ms) to start
    ///          transitioning.
    /// \param   transition_time_ms How long the transition should time (in ms).
    inline void Update(uint64_t new_k_val,
                       uint64_t start_transition_time_ms,
                       uint64_t transition_time_ms)
    {
      // Start the new transition where ever we left off on the previous
      // transition. This avoids big jumps if K is updated is rapid
      // succession.
      k_current_ = GetValue();
      // Compute the new difference.
      k_diff_ = new_k_val - k_current_;
      // When to start the next transition.
      start_time_ms_ = start_transition_time_ms;
      // How long the next transition should take.
      transition_time_ms_ = transition_time_ms;
    }

    /// \brief Return the K value to use at this instant.
    ///
    /// Scales the K value linearly between current_k_val_ at
    /// start_transition_time_ms_ through current_k_val_ + diff_ at
    /// start_transition_time_ms + transition_time_ms. If k_diff_ is 0, this
    /// just returns k_current_. If the current time is after the transition
    /// is complete, this updates and returns k_current_ to complete the
    /// transition.
    ///
    /// \return The value of K to be used at this instant.
    inline uint64_t GetValue()
    {
      uint64_t value = k_current_;
      // If k_diff_ is 0, we're not currently adapting K.
      if (k_diff_ != 0)
      {
        uint64_t now = Time::Now().GetTimeInMsec();
        if (start_time_ms_ + transition_time_ms_ < now)
        {
          // We're done adapting. Jump to the new value.
          k_current_ += k_diff_;
          k_diff_ = 0;
          value = k_current_;
        }
        else
        {
          double fraction =
            static_cast<double>(now - start_time_ms_) / transition_time_ms_;
          value = k_current_ + (k_diff_ * fraction);
        }
      }
      return value;
    }

    /// \brief Returns a std::string representing the contents of this KVal.
    ///
    /// \return A string with the current and diff for the K value and the
    /// transition time to get to the new value.
    inline std::string GetKString()
    {
      std::stringstream ret_str;
      ret_str << "Current: "
              << k_current_
              << ", diff: "
              << k_diff_
              << ", transition time: "
              << transition_time_ms_
              << " ms";
        return ret_str.str();
    }

    private:

    /// The K value before the transition (or the K value if no transition is
    /// taking place.)
    uint64_t  k_current_;

    /// The difference between k_current_ and the goal K value.
    int64_t   k_diff_;

    /// The time when we want to start transitioning.
    uint64_t  start_time_ms_;

    /// How long to take for the K value transition.
    uint64_t  transition_time_ms_;
  };
}

#endif // IRON_COMMON_K_VAL_H
