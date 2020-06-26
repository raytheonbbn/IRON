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

#include "string_utils.h"
#include "log.h"
#include "unused.h"

#include <sstream>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>

using ::iron::Ipv4Address;
using ::iron::Log;
using ::iron::StringUtils;
using ::iron::List;
using std::string;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "StringUtils";
}


//============================================================================
void StringUtils::Tokenize(const string& str, const char* delim,
                           List<string>& tokens)
{
  size_t  str_len = (str.size() + 1);
  char*   str_to_tokenize;

  tokens.Clear();

  str_to_tokenize = new (std::nothrow) char[str_len];

  if (str_to_tokenize != NULL)
  {
    ::memcpy(str_to_tokenize, str.c_str(), str_len);

    char*  p = strtok(str_to_tokenize, delim);

    while (p)
    {
      tokens.Push(p);
      p = strtok(NULL, delim);
    }

    delete [] str_to_tokenize;
  }
}

//============================================================================
bool StringUtils::Substitute(
  std::string& str, std::string& start, std::string& end, std::string& val)
{
  // Get the start of the target substring.
  size_t  start_pos = str.find(start);

  if (start_pos == string::npos)
  {
    return false;
  }

  // Get the end of the target substring.
  size_t  end_pos = str.find(end, start_pos);

  if (end_pos == string::npos)
  {
    return false;
  }

  str = str.substr(0,start_pos + start.size()) + val
        + str.substr(end_pos, (str.size() - end_pos));

  return true;
}

//============================================================================
bool StringUtils::Replace(std::string& input, std::string& search,
                          std::string& replace)
{
  size_t  pos      = 0;
  bool    replaced = false;

  while ((pos = input.find(search, pos)) != string::npos)
  {
    input.replace(pos, search.length(), replace);
    pos     += replace.length();
    replaced = true;
  }

  return replaced;
}

//============================================================================
bool StringUtils::GetBool(const string& str, const bool default_value)
{
  bool  rv = default_value;

  //
  // Use strncasecmp() to do a case-insensitive comparisons on "true" and
  // "false". Also permits the value "0" to be used to represent false or the
  // value "1" to be used to represent true.
  //

  if (::strncasecmp(str.c_str(), "true", 4) == 0)
  {
    rv = true;
  }
  else if (::strncasecmp(str.c_str(), "false", 5) == 0)
  {
    rv = false;
  }
  else if (::strncmp(str.c_str(), "0", 1) == 0)
  {
    rv = false;
  }
  else if (::strncmp(str.c_str(), "1", 1) == 0)
  {
    rv = true;
  }

  return rv;
}

//============================================================================
int StringUtils::GetInt(const string& str, const int default_value)
{
  char*        end_ptr = NULL;
  const char*  str_ptr = str.c_str();

  // Clear errno before the call, per strtol(3).
  errno = 0;

  long  val = ::strtol(str_ptr, &end_ptr, 10);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && ((val == LONG_MAX) || (val == LONG_MIN)))
      || ((errno != 0) && (val == 0)))
  {
    LogE(kClassName, __func__, "Error converting string %s to int: %s\n",
         str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    LogE(kClassName, __func__, "Error converting string %s to int.\n",
         str_ptr);
    return default_value;
  }

  return static_cast<int>(val);
}

//============================================================================
int64_t StringUtils::GetInt64(const string& str, const int64_t default_value)
{
  char*        end_ptr = NULL;
  const char*  str_ptr = str.c_str();

  // Clear errno before the call, per strtoll(3).
  errno = 0;

  long long  val = ::strtoll(str_ptr, &end_ptr, 10);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && ((val == LLONG_MAX) || (val == LLONG_MIN)))
      || ((errno != 0) && (val == 0)))
  {
    LogE(kClassName, __func__, "Error converting string %s to int64_t: %s\n",
         str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    LogE(kClassName, __func__, "Error converting string %s to int64_t.\n",
         str_ptr);
    return default_value;
  }

  return static_cast<int64_t>(val);
}

//============================================================================
unsigned int StringUtils::GetUint(const string& str,
                                  const unsigned int default_value)
{
  char*        end_ptr = NULL;
  const char*  str_ptr = str.c_str();

  // Clear errno before the call, per strtoul(3).
  errno = 0;

  unsigned long  val = ::strtoul(str_ptr, &end_ptr, 10);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && (val == ULONG_MAX))
      || ((errno != 0) && (val == 0)))
  {
    LogE(kClassName, __func__, "Error converting string %s to unsigned int: "
         "%s\n", str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    LogE(kClassName, __func__, "Error converting string %s to unsigned "
         "int.\n", str_ptr);
    return default_value;
  }

  return static_cast<unsigned int>(val);
}

//============================================================================
uint64_t StringUtils::GetUint64(const string& str,
                                const uint64_t default_value)
{
  char*        end_ptr = NULL;
  const char*  str_ptr = str.c_str();

  // Clear errno before the call, per strtoull(3).
  errno = 0;

  unsigned long long  val = ::strtoull(str_ptr, &end_ptr, 10);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && (val == ULLONG_MAX))
      || ((errno != 0) && (val == 0)))
  {
    LogE(kClassName, __func__, "Error converting string %s to uint64_t: %s\n",
         str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    LogE(kClassName, __func__, "Error converting string %s to uint64_t.\n",
         str_ptr);
    return default_value;
  }

  return static_cast<uint64_t>(val);
}

//============================================================================
float StringUtils::GetFloat(const string& str, const float default_value)
{
  char*        end_ptr = NULL;
  const char*  str_ptr = str.c_str();

  // Clear errno before the call, per strtof(3).
  errno = 0;

  float  val = ::strtof(str_ptr, &end_ptr);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && ((val == HUGE_VALF) || (val == 0.0f)))
      || ((errno != 0) && (val == 0.0f)))
  {
    LogE(kClassName, __func__, "Error converting string %s to float: %s\n",
         str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    LogE(kClassName, __func__, "Error converting string %s to float.\n",
         str_ptr);
    return default_value;
  }

  return val;
}

//============================================================================
double StringUtils::GetDouble(const string& str, const double default_value)
{
  char*        end_ptr = NULL;
  const char*  str_ptr = str.c_str();

  // Clear errno before the call, per strtod(3).
  errno = 0;

  double  val = ::strtod(str_ptr, &end_ptr);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && ((val == HUGE_VAL) || (val == 0.0)))
      || ((errno != 0) && (val == 0.0)))
  {
    LogE(kClassName, __func__, "Error converting string %s to double: %s\n",
         str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    LogE(kClassName, __func__, "Error converting string %s to double.\n",
         str_ptr);
    return default_value;
  }

  return val;
}

//============================================================================
Ipv4Address StringUtils::GetIpAddr(const std::string& str,
                                   const std::string& default_value)
{
  Ipv4Address  rv(str);

  if (rv.address() == 0)
  {
    if (!default_value.empty())
    {
      rv = default_value;
    }
  }

  return rv;
}

//============================================================================
std::string StringUtils::ToString(int value)
{
  int   rv;
  char  buf[16];

  rv = snprintf(buf, sizeof(buf), "%d", value);

  if (rv <= 0)
  {
    LogE(kClassName, __func__, "Error converting integer %d to a string.\n",
         value);
    buf[0] = '?';
    buf[1] = '\0';
  }

  return buf;
}

//============================================================================
std::string StringUtils::ToString(uint16_t value)
{
  return StringUtils::ToString(static_cast<int>(value));
}

//============================================================================
std::string StringUtils::ToString(uint32_t value)
{
  int   rv;
  char  buf[16];

  rv = snprintf(buf, sizeof(buf), "%" PRIu32, value);

  if (rv <= 0)
  {
    LogE(kClassName, __func__, "Error converting integer %" PRIu32
         " to a string.\n", value);
    buf[0] = '?';
    buf[1] = '\0';
  }

  return buf;
}

//============================================================================
std::string StringUtils::ToString(uint64_t value)
{
  int   rv;
  char  buf[32];

  rv = snprintf(buf, sizeof(buf), "%" PRIu64, value);

  if (rv <= 0)
  {
    LogE(kClassName, __func__, "Error converting integer %" PRIu64
         " to a string.\n", value);
    buf[0] = '?';
    buf[1] = '\0';
  }

  return buf;
}

//============================================================================
std::string StringUtils::ToString(double value)
{
  int   rv;
  char  buf[32];

  rv = snprintf(buf, sizeof(buf), "%.06f", value);

  if (rv <= 0)
  {
    LogE(kClassName, __func__, "Error converting double %f to a string.\n",
         value);
    buf[0] = '?';
    buf[1] = '\0';
  }

  return buf;
}

//============================================================================
std::string StringUtils::FormatString(int size, const char* format, ...)
{
  char     format_str[size];
  va_list  vargs;

  if ((size < 2) || (format == NULL))
  {
    return "";
  }

  //
  // Use vsnprintf(), which is made to take in the variable argument list.
  //

  va_start(vargs, format);
  if (vsnprintf(format_str, size, format, vargs) > size)
  {
    LogW(kClassName, __func__, "String was truncated during formatting.\n");
  }
  va_end(vargs);

  return format_str;
}
