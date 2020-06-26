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

// \brief The IRON logging source file.
//
// Provides the IRON software with a time class.

#include "itime.h"
#include "unused.h"

#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <inttypes.h>


using ::iron::Log;
using ::iron::Time;
using ::std::numeric_limits;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "Time";
}

Time::Time(const timespec& t_spec)
{
  t_val_.tv_sec  = t_spec.tv_sec;
  t_val_.tv_usec = static_cast<suseconds_t>((t_spec.tv_nsec + 500) / 1000);

  while (t_val_.tv_usec >= 1000000)
  {
    t_val_.tv_sec  += 1;
    t_val_.tv_usec -= 1000000;
  }
}

//============================================================================
Time::Time(double fractional_time_in_seconds)
{
  double  sec = floor(fractional_time_in_seconds);

  t_val_.tv_sec  = static_cast<time_t>(sec);
  t_val_.tv_usec = static_cast<suseconds_t>(
    round((fractional_time_in_seconds - sec) * 1000000.0));
}

//============================================================================
Time Time::FromSec(time_t seconds)
{
  return Time(seconds, 0);
}

//============================================================================
Time Time::FromMsec(int64_t milliseconds)
{
  Time  t;

  if (milliseconds >= 0)
  {
    t.t_val_.tv_sec  = static_cast<time_t>(milliseconds / 1000);
    t.t_val_.tv_usec = static_cast<suseconds_t>((milliseconds % 1000) * 1000);
  }
  else
  {
    t.t_val_.tv_sec  = static_cast<time_t>((milliseconds / 1000) - 1);
    t.t_val_.tv_usec = static_cast<suseconds_t>(
      (1000 - abs(milliseconds % 1000)) * 1000);
  }

  return t;
}

//============================================================================
Time Time::FromUsec(int64_t microseconds)
{
  Time  t;

  if (microseconds >= 0)
  {
    t.t_val_.tv_sec  = static_cast<time_t>(microseconds / 1000000);
    t.t_val_.tv_usec = static_cast<suseconds_t>(microseconds % 1000000);
  }
  else
  {
    t.t_val_.tv_sec  = static_cast<time_t>((microseconds / 1000000) - 1);
    t.t_val_.tv_usec = static_cast<suseconds_t>(
      (1000000 - abs(microseconds % 1000000)));
  }

  return t;
}

//============================================================================
Time Time::Now()
{
  Time  t;

  t.GetNow();

  return t;
}

//============================================================================
Time Time::Infinite()
{
  Time  t;

  t.t_val_.tv_sec  = numeric_limits<time_t>::max();
  t.t_val_.tv_usec = 0;

  return t;
}

//============================================================================
Time Time::Max(const Time& t1, const Time& t2)
{
  if (t1 > t2)
  {
    return t1;
  }

  return t2;
}

//============================================================================
Time Time::Min(const Time& t1, const Time& t2)
{
  if (t1 < t2)
  {
    return t1;
  }

  return t2;
}

//============================================================================
string Time::ToString() const
{
  char  ret_str[30];

  if (t_val_.tv_sec >= 0)
  {
    if (snprintf(ret_str, sizeof(ret_str), "%" PRId64 ".%06" PRId64 "s",
                 static_cast<int64_t>(t_val_.tv_sec),
                 static_cast<int64_t>(t_val_.tv_usec)) < 0)
    {
      return "Error";
    }
  }
  else if (t_val_.tv_sec < -1)
  {
    if (snprintf(ret_str, sizeof(ret_str), "%" PRId64 ".%06" PRId64 "s",
                 static_cast<int64_t>(t_val_.tv_sec + 1),
                 static_cast<int64_t>(1000000 - t_val_.tv_usec)) < 0)
    {
      return "Error";
    }
  }
  else  // fractional negative time
  {
    if (snprintf(ret_str, sizeof(ret_str), "-%" PRId64 ".%06" PRId64 "s",
                 static_cast<int64_t>(t_val_.tv_sec + 1),
                 static_cast<int64_t>(1000000 - t_val_.tv_usec)) < 0)
    {
      return "Error";
    }
  }
  return ret_str;
}

//============================================================================
time_t Time::GetNowInSec()
{
  timespec  t_spec;

  if (clock_gettime(CLOCK_MONOTONIC, &t_spec) != 0)
  {
    LogF(kClassName, __func__, "Monotonic gettime failed with error %s\n",
         strerror(errno));
    return 0;
  }

  return t_spec.tv_sec;
}

//============================================================================
int64_t Time::GetNowInUsec()
{
  timespec  t_spec;

  if (clock_gettime(CLOCK_MONOTONIC, &t_spec) != 0)
  {
    LogF(kClassName, __func__, "Monotonic gettime failed with error %s\n",
         strerror(errno));
    return 0;
  }

  Time tmp(t_spec);

  return tmp.GetTimeInUsec();
}

//============================================================================
void Time::Zero()
{
  t_val_.tv_sec  = 0;
  t_val_.tv_usec = 0;
}

//============================================================================
bool Time::GetNow()
{
  timespec  t_spec;

  if (clock_gettime(CLOCK_MONOTONIC, &t_spec) != 0)
  {
    LogF(kClassName, __func__, "Monotonic clock failed with error %s\n",
         strerror(errno));
    t_val_.tv_sec  = 0;
    t_val_.tv_usec = 0;
    return false;
  }

  t_val_.tv_sec  = t_spec.tv_sec;
  t_val_.tv_usec = static_cast<suseconds_t>((t_spec.tv_nsec + 500) / 1000);

  return true;
}

//============================================================================
iron::Time iron::Time::operator+(const time_t time_to_add_in_secs) const
{
  timeval  tval;
  timeval  ret_tval;

  tval.tv_sec  = time_to_add_in_secs;
  tval.tv_usec = 0;

  timeradd(&t_val_, &tval, &ret_tval);

  return Time(ret_tval);
}

//============================================================================
Time& Time::operator+=(const Time& time_to_add)
{
  timeval  tval;
  timeval  ret_tval;

  tval = time_to_add.ToTval();

  timeradd(&t_val_, &tval, &ret_tval);

  t_val_.tv_sec  = ret_tval.tv_sec;
  t_val_.tv_usec = ret_tval.tv_usec;

  return *this;
}

//============================================================================
iron::Time iron::Time::Add(const iron::Time& time_to_add) const
{
  timeval  res_time;

  timeradd(&t_val_, &time_to_add.t_val_, &res_time);

  return Time(res_time);
}

//============================================================================
iron::Time iron::Time::Add(double time_to_add) const
{
  timeval  res_time;
  timeval  delta_time;
  double   sec = floor(time_to_add);

  delta_time.tv_sec  = static_cast<time_t>(sec);
  delta_time.tv_usec = static_cast<suseconds_t>(
    round((time_to_add - sec) * 1000000.0));

  timeradd(&t_val_, &delta_time, &res_time);

  return Time(res_time);
}

//============================================================================
iron::Time iron::Time::Subtract(const iron::Time& time_to_remove) const
{
  timeval  res_time;

  timersub(&t_val_, &time_to_remove.t_val_, &res_time);

  return Time(res_time);
}

//============================================================================
iron::Time iron::Time::Subtract(double time_to_remove) const
{
  timeval  res_time;
  timeval  delta_time;
  double   sec = floor(time_to_remove);

  delta_time.tv_sec  = static_cast<time_t>(sec);
  delta_time.tv_usec = static_cast<suseconds_t>(
    round((time_to_remove - sec) * 1000000.0));

  timersub(&t_val_, &delta_time, &res_time);

  return Time(res_time);
}

//============================================================================
iron::Time iron::Time::Multiply(int multiplier) const
{
  return Time::FromUsec(GetTimeInUsec() * static_cast<int64_t>(multiplier));
}

//============================================================================
iron::Time iron::Time::Multiply(double multiplier) const
{
  return Time::FromUsec(static_cast<int64_t>
                        (static_cast<double>(GetTimeInUsec()) * multiplier));
}

//============================================================================
void Time::SetInfinite()
{
  t_val_.tv_sec   = numeric_limits<time_t>::max();
  t_val_.tv_usec  = 0;
}

//============================================================================
time_t Time::GetTimeInSec() const
{
  return t_val_.tv_sec;
}

//============================================================================
int64_t Time::GetTimeInMsec() const
{
  return ((static_cast<int64_t>(t_val_.tv_sec) * (int64_t)1000) +
          static_cast<int64_t>(t_val_.tv_usec / 1000));
}

//============================================================================
int64_t Time::GetTimeInUsec() const
{
  return ((static_cast<int64_t>(t_val_.tv_sec) * (int64_t)1000000) +
          static_cast<int64_t>(t_val_.tv_usec));
}

//============================================================================
string Time::GetTimeInFormat(const char *format)
{
  char  buf[64];
  char  c       = '\0';
  tm*   tm_time = gmtime(&t_val_.tv_sec);

  if (!tm_time)
  {
    return "";
  }

  // Make a format a string so we can work on it more easily.
  string  local_format(format);

  // Find the call to print microseconds since strftime does not support it.
  size_t  found = local_format.find("%us");

  if (std::string::npos != found)
  {
    // The format asks for microseconds.
    if (found == 0)
    {
      // Found at beginning, no separator!  Now remove it to pass format to
      // strftime.
      c = '\0';
      local_format.erase(found, 3);
    }
    else
    {
      // Found, copy the separator.
      c = local_format.at(found - 1);

      // Found!  Now remove it to pass format to strftime
      local_format.erase((found - 1), 4);
    }
  }

  // Convert to char* for strftime.
  const char*  new_format = local_format.c_str();

  // Get proper char* out of the format.
  strftime(buf, sizeof(buf), new_format, tm_time);

  // Make it a string again.
  string  ret_str(buf);

  if (std::string::npos != found)
  {
    // Insert the microseconds.
    char  us_chars[8];

    found = ret_str.rfind(":");

    if (std::string::npos == found)
    {
      // The : is at the end of the string, don't worry about it.
      if (snprintf(us_chars, sizeof(us_chars), "%06" PRId64,
                   static_cast<int64_t>(t_val_.tv_usec)) < 0)
      {
        return "Error";
      }

      ret_str.insert(0, us_chars);
    }
    else
    {
      // Print :microseconds as :xxxxxx.
      if (snprintf(us_chars, sizeof(us_chars), "%c%06" PRId64, c,
                   static_cast<int64_t>(t_val_.tv_usec)) < 0)
      {
        return "Error";
      }

      ret_str.insert((found + 3), us_chars);
    }
  }

  return ret_str;
}
