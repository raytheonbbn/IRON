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

#ifndef IRON_UTIL_LINKEM_HIGH_RESOLUTION_CLOCK_H
#define IRON_UTIL_LINKEM_HIGH_RESOLUTION_CLOCK_H

#include <x86intrin.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <time.h>

#define CONFIG_X86_TSC

class HighResolutionClock
{
  public:

  /// \brief Default constructor.
  HighResolutionClock();

  /// \brief Destructor.
  virtual ~HighResolutionClock();

  /// \brief Initialize the clock.
  ///
  /// \return True if successful, false otherwise.
  bool Initialize();

  /// \brief Get the current time, in nanoseconds.
  ///
  /// \return The current time, in nanoseconds.
  inline unsigned long long GetTimeInNsec() const
  {
#ifdef CONFIG_X86_TSC
    return ((unsigned long long)((double)__rdtsc() *
                                 ns_per_tick_));
#else
    struct timespec  ts;
    clock_gettime(&ts, NULL);
    return ((unsigned long long)ts.tv_sec * 1000000000llu
	    + (unsigned long long)ts.tv_nsec);
#endif
  };

  private:

  /// \brief Copy constructor.
  HighResolutionClock(const HighResolutionClock& other);

  /// \brief Copy operator.
  HighResolutionClock& operator=(const HighResolutionClock& other);

  /// \brief Get the number of nanoseconds in each CPU clock tick.
  ///
  /// \return The number of nanaseconds in each CPU clock tick.
  inline double ns_per_tick() const
  {
    return ns_per_tick_;
  }

  /// \brief Get the number of clock ticks since boot time.
  ///
  /// \return The number of clock ticks since boot time.
  inline unsigned long long GetTickCount() const
  {
#ifdef CONFIG_X86_TSC
    return (__rdtsc());
#else
    struct timespec  ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000llu
      + (unsigned long long)ts.tv_nsec;
#endif
  };

  /// \brief Get the current time, in nanoseconds.
  ///
  /// \return The current time, in nanoseconds.
  inline unsigned long long GetCalibrationTimeInNsec() const
  {
    struct timespec  ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (((unsigned long long)ts.tv_sec) * 1000000000llu
	    + (unsigned long long)ts.tv_nsec);
  }

  /// The number of nanoseconds per tick.
  double              ns_per_tick_;

  /// Clock offset.
  unsigned long long  offset_;

}; // end class HighResolutionClock

#endif // IRON_UTIL_LINKEM_HIGH_RESOLUTION_CLOCK_H
