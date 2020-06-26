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

/// \brief The IRON time header file.
///
/// Provides the IRON software with a time class.

#ifndef IRON_COMMON_ITIME_H
#define IRON_COMMON_ITIME_H

#include "log.h"

#include <limits>

#include <stdint.h>
#include <string>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>

namespace iron
{

  /// Time class: Provides a wrapper to a timeval time and a good number of
  /// accessors and operators for a monotonic clock.  The timeval is rounded
  /// from a timespec, which is returned in seconds and nanoseconds.  Math and
  /// logical operators are provided as part of this class, which also
  /// provides 'now'.
  ///
  /// This class does support negative times. The internal representation of
  /// negative times is as follows:
  ///
  /// Internally, time is stored in a struct timeval, which is composed of a
  /// time_t member for seconds and a suseconds_t member for microseconds. The
  /// glibc timeradd and timersub functions are used for adding and
  /// subtracting struct timevals. When the result of invoking these functions
  /// is a negative time, the seconds are negative and the microseconds are
  /// positive. For example, the human readable time "-10.70000s" is stored
  /// internally as:
  ///
  ///   tv.tv_sec  = -11
  ///   tv.tv_usec = 300000
  ///
  /// When asked to retrieve the above stored time as a string, "-10.700000"
  /// is returned as expected. Additionally, if the time in microseconds is
  /// asked for, -10700000 is returned as expected.
  class Time
  {
    public:

    /// \brief Default constructor.
    ///
    /// This sets the value of the Time to 0.
    inline Time() : t_val_() {}

    /// \brief Copy constructor.
    ///
    /// \param  other_time  A reference to the Time object to copy from.
    inline Time(const Time& other_time) : t_val_(other_time.t_val_) {}

    /// \brief Constructor builds a Time object from timeval.
    ///
    /// \param  t_val  Timeval time to wrap in Time object.
    inline explicit Time(const timeval& t_val)  : t_val_(t_val) {}

    /// \brief Constructor builds a Time object from timespec (nanosecond
    /// resolution).
    ///
    /// \param  t_spec  Timespec time to wrap in Time object.
    explicit Time(const timespec& t_spec);

    /// \brief Constructor builds a Time object from integer time in seconds.
    ///
    /// \param  time_in_sec  Time to wrap in Time object (in seconds).
    inline explicit Time(int time_in_sec)
    {
      t_val_.tv_sec  = static_cast<time_t>(time_in_sec);
      t_val_.tv_usec = 0;
    }

    /// \brief Constructor builds a Time object from time_t time in seconds.
    ///
    /// \param  time_in_sec  Time to wrap in Time object (in seconds).
    inline explicit Time(time_t time_in_sec)
    {
      t_val_.tv_sec  = time_in_sec;
      t_val_.tv_usec = 0;
    }

    /// \brief Constructor builds a Time object from time expressed in seconds
    /// and microseconds.
    ///
    /// \param  seconds       Number of seconds of time.
    /// \param  microseconds  Number of microseconds of time.
    inline explicit Time(time_t seconds, suseconds_t microseconds)
    {
      t_val_.tv_sec  = seconds;
      t_val_.tv_usec = microseconds;
    }

    /// \brief Constructor builds a Time object from time expressed in a
    /// floating point value in seconds.
    ///
    /// \param  fractional_time_in_seconds  The fractional time in seconds.
    explicit Time(double fractional_time_in_seconds);

    /// \brief Default destructor.
    virtual ~Time() {};

    /// \brief Create a new Time object and initialize its value from the
    /// provided seconds value.
    ///
    /// \param  seconds  The seconds value from which to initialize the new
    ///                  Time object's value.
    ///
    /// \return  Time object with a value set to the provided seconds value.
    static Time FromSec(time_t seconds);

    /// \brief Create a new Time object and initialize its value from the
    /// provided milliseconds value.
    ///
    /// \param  milliseconds  The milliseconds value from which to initialize
    ///                       the new Time object's value.
    ///
    /// \return  Time object with a value set to the provided milliseconds
    ///          value.
    static Time FromMsec(int64_t milliseconds);

    /// \brief Create a new Time object and initialize its value from the
    /// provided microseconds value.
    ///
    /// \param  microseconds  The microseconds value from which to initialize
    ///                       the new Time object's value.
    ///
    /// \return  Time object with a value set to the provided microseconds
    ///          value.
    static Time FromUsec(int64_t microseconds);

    /// \brief Create a new Time object and set its value to 'now' (monotonic
    /// clock).
    ///
    /// Note that this rounds to the nearest microsecond.
    ///
    /// \return Time object whose time is set to now. If an error occurs
    ///         getting the 'now' time, the current object's time is set to
    ///         0.
    static Time Now();

    /// \brief Create a new Time object and set its value to infinite.
    ///
    /// \return Time object set to infinite time.
    static Time Infinite();

    /// \brief Create a new Time object and set its value to the maximum of the
    /// provided Time objects.
    ///
    /// \param  t1  The first time to consider.
    /// \param  t2  The second time to consider.
    ///
    /// \return  The maximum of the two Time objects.
    static Time Max(const Time& t1, const Time& t2);

    /// \brief Create a new Time object and set its value to the minimum of the
    /// provided Time objects.
    ///
    /// \param  t1  The first time to consider.
    /// \param  t2  The second time to consider.
    ///
    /// \return  The minimum of the two Time objects.
    static Time Min(const Time& t1, const Time& t2);

    /// \brief Returns a simple string describing the Time object.
    ///
    /// If an error occurs, then the string "Error" is returned.
    ///
    /// \return  The string describing the Time object.
    std::string ToString() const;

    /// \brief Convert the Time object to a timeval structure.
    ///
    /// \return  The value of the Time object as a timeval structure.
    inline timeval ToTval() const
    {
      return t_val_;
    }

    /// \brief Convert the Time object to a floating point number of seconds.
    ///
    /// \return  The value of the Time object as a double, in seconds.
    inline double ToDouble() const
    {
      return (static_cast<double>(t_val_.tv_sec) +
              (static_cast<double>(t_val_.tv_usec) / 1000000.0));
    }

    /// \brief Get the current monotonic clock time in seconds.
    ///
    /// Note that this truncates the current time to seconds.  So, a current
    /// time of 5.999999 seconds will return 5.
    ///
    /// \return  The current time in seconds.
    static time_t GetNowInSec();

    /// \brief Get the current monotonic clock time in microseconds.
    ///
    /// Note that this rounds to the nearest microsecond.
    ///
    /// \return  The current time in microseconds.
    static int64_t GetNowInUsec();

    /// \brief Zero the Time object.
    void Zero();

    /// \brief Set current Time object to 'now' (monotonic clock).
    ///
    /// Note that this rounds to the nearest microsecond.
    ///
    /// \return  True if could fetch clock time, False otherwise
    bool GetNow();

    /// \brief The addition operator.
    ///
    /// \param  time_to_add  Time to be added to object.
    ///
    /// \return  Summed Time object.
    inline iron::Time operator+(const iron::Time& time_to_add) const
    {
      timeval  ret_tval;
      timeradd(&t_val_, &time_to_add.t_val_, &ret_tval);
      return Time(ret_tval);
    }

    /// \brief The addition operator.
    ///
    /// \param  time_to_add_in_secs  Time to be added to object in seconds.
    ///
    /// \return  Summed Time object
    iron::Time operator+(const time_t time_to_add_in_secs) const;

    /// \brief The += operator.
    ///
    /// \param  time_to_add  Time as a time object to be added to this.
    ///
    /// \return  A reference to this object after the addition.
    Time& operator+=(const Time& time_to_add);

    /// \brief The subtraction operator.
    ///
    /// \param  time_to_remove  Time to be subtracted from object.
    ///
    /// \return  Subtracted Time object.
    inline Time operator-(const Time& time_to_remove) const
    {
      timeval  ret_tval;
      timersub(&t_val_, &time_to_remove.t_val_, &ret_tval);
      return Time(ret_tval);
    }

    /// \brief The < operator.
    ///
    /// \param  time_to_compare  The Time object to compare.
    ///
    /// \return  True if this Time object is less than time_to_compare.
    inline bool operator<(const Time& time_to_compare) const
    {
      return (timercmp(&t_val_, &time_to_compare.t_val_, <) != 0);
    }

    /// \brief The > operator.
    ///
    /// \param  time_to_compare  The Time object to compare.
    ///
    /// \return  True if this Time object is greater than time_to_compare.
    inline bool operator>(const Time& time_to_compare) const
    {
      return (timercmp(&t_val_, &time_to_compare.t_val_, >) != 0);
    }

    /// \brief The != operator.
    ///
    /// \param  time_to_compare  The Time object to compare.
    ///
    /// \return  True if this Time object is not equal to time_to_compare.
    inline bool operator!=(const Time& time_to_compare) const
    {
      return (timercmp(&t_val_, &time_to_compare.t_val_, !=) != 0);
    }
    /// \brief The <= operator.
    ///
    /// \param  time_to_compare  The Time object to compare.
    ///
    /// \return  True if this Time object is less than or equal to
    ///          time_to_compare.
    inline bool operator<=(const Time& time_to_compare) const
    {
      return (timercmp(&t_val_, &time_to_compare.t_val_, >) == 0);
    }

    /// \brief The >= operator.
    ///
    /// \param  time_to_compare  The Time object to compare.
    ///
    /// \return  True if this Time object is greater than or equal to
    ///          time_to_compare.
    inline bool operator>=(const Time& time_to_compare) const
    {
      return (timercmp(&t_val_, &time_to_compare.t_val_, <) == 0);
    }
    /// \brief The == operator.
    ///
    /// \param  time_to_compare  The Time object to compare.
    ///
    /// \return  True if this Time object is equal to time_to_compare.
    inline bool operator==(const Time& time_to_compare) const
    {
      return (timercmp(&t_val_, &time_to_compare.t_val_, !=) == 0);
    }

    /// \brief The assignment operator.
    ///
    /// \param  time_to_assign  The Time object to assign to this Time
    ///                         object.
    ///
    /// \return  A reference to the updated Time object.
    inline Time& operator=(const Time& time_to_assign)
    {
      t_val_ = time_to_assign.t_val_;
      return *this;
    }

    /// \brief The assignment operator.
    ///
    /// \param  time_to_assign  The time value, in seconds, to assign to this
    ///                         Time object.
    ///
    /// \return  A reference to the updated Time object.
    inline Time& operator=(time_t time_to_assign)
    {
      t_val_.tv_sec  = time_to_assign;
      t_val_.tv_usec = 0;
      return *this;
    }

    /// \brief Add a Time object to this Time object.
    ///
    /// \param  time_to_add  Time to be added to this Time object.
    ///
    /// \return  Time object that is the result of adding the provided time to
    ///          this Time.
    iron::Time Add(const iron::Time& time_to_add) const;

    /// \brief Add a floating point time to this Time object.
    ///
    /// \param  time_to_add  Time to be added to this object in seconds.
    ///
    /// \return  Time object that is the result of adding the provided time to
    ///          this Time.
    iron::Time Add(double time_to_add) const;

    /// \brief Subtract a Time object from this Time object.
    ///
    /// \param  time_to_remove  Time to be subtracted from this Time object.
    ///
    /// \return  Time object that results from subtracting the provided Time
    ///          from this Time.
    iron::Time Subtract(const iron::Time& time_to_remove) const;

    /// \brief Subtract a floating point time from this Time object.
    ///
    /// \param  time_to_remove  Time to be subtracted from this object in
    ///                         seconds.
    ///
    /// \return  Time object that results from subtracting the provided time
    ///          from this Time.
    iron::Time Subtract(double time_to_remove) const;

    /// \brief Multiply the Time by the provided integer multiplier.
    ///
    /// \param  multiplier  The multiplier value.
    ///
    /// \return  Time object that results from multiplying this Time by the
    ///          multiplier.
    iron::Time Multiply(int multiplier) const;

    /// \brief Multiply the Time by the provided floating point multiplier.
    ///
    /// \param  multiplier  The multiplier value.
    ///
    /// \return  Time object that results from multiplying this Time by the
    ///          multiplier.
    iron::Time Multiply(double multiplier) const;

    /// \brief Check if the time value is zero or not.
    ///
    /// \return  True if the time value is zero.
    inline bool IsZero() const
    {
      return ((t_val_.tv_sec == 0) && (t_val_.tv_usec == 0));
    }

    /// \brief Set the time value to the max it could ever be.
    void SetInfinite();

    /// \brief Check if the time value is infinite or not.
    ///
    /// \return  True if the time value is infinite, false otherwise.
    inline bool IsInfinite() const
    {
      return (t_val_.tv_sec == std::numeric_limits<time_t>::max());
    }

    /// \brief Function to get this Time object's time in seconds.
    ///
    /// Note that this only returns the object's seconds value.  So, an object
    /// storing a time of 5.999999 seconds will return 5.
    ///
    /// \return  This object's time in seconds.
    time_t GetTimeInSec() const;

    /// \brief Get the time in milliseconds.
    ///
    /// \return  The time in milliseconds.
    int64_t GetTimeInMsec() const;

    /// \brief Function to get Time in microseconds.
    ///
    /// \return  The time in microseconds.
    int64_t GetTimeInUsec() const;

    /// \brief Format the Time object as a string using a user-specified
    /// format.
    ///
    /// Examples of the format string (where Time is 24hr-format):
    /// - '%H:%M': Hours and minutes
    /// - '%Y-%m-%dT%H:%M:%S:%us': Year-month-day-Hours:Min:Sec:MicroS
    ///
    /// If an error occurs, then the string "Error" is returned.
    ///
    /// \param  format  A string containing the desired format of the Time
    ///                 object.  The format is the same as used by strftime(3)
    ///                 (man strftime).
    ///
    /// \return  String in the specified format.
    std::string GetTimeInFormat(const char *format);

    private:

    /// The struct timeval that keeps the internal time representation.
    timeval  t_val_;

  }; // end class Time

} // namespace iron

#endif // IRON_COMMON_ITIME_H
