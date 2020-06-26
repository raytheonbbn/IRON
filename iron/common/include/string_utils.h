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

///
/// Provides the IRON software with a collection of methods for manipulating
/// std::string objects.
///

#ifndef IRON_COMMON_STRING_UTILS_H
#define IRON_COMMON_STRING_UTILS_H

#include "ipv4_address.h"
#include "list.h"

#include <string>
#include <inttypes.h>

#include <cfloat>
#include <climits>

namespace iron
{
  ///
  /// A class that provides a set of static utility methods that deal with
  /// strings. This class enables us to capture frequently used string
  /// manipulation routines in a common place.
  ///
  class StringUtils
  {
    public:

    /// \brief Tokenize a string into a list of tokens.
    ///
    /// NOTE: This method expects a list for returning the tokens. It does
    ///       not expose internal pointers.
    ///
    /// \param  str     The string to tokenize.
    /// \param  delim   The characters to use as the delimiter between the
    ///                 tokens.
    /// \param  tokens  The list in which to return the tokens.
    static void Tokenize(const std::string& str,
                         const char* delim,
                         ::iron::List<std::string>& tokens);

    /// \brief Replace a delimiter-specified substring with a given substring.
    ///
    /// The delimiters are included in the new string.
    ///
    /// \param  str    The original string in which to perform the
    ///                substitution.
    /// \param  start  A substring that immediately precedes the substring to
    ///                be replaced.  This should be the first occurance of
    ///                this substring in the original string.
    /// \param  end    A string to indicate the end of the substring to be
    ///                replaced.  This should not appear within the substring
    ///                being substituted.
    /// \param  val    The new substring to be inserted in the original
    ///                string.
    ///
    /// \return  True if the substring was found and replaced.
    static bool Substitute(std::string& str, std::string& start,
                           std::string& end, std::string& val);

    /// \brief Replace one string with another in an input string.
    ///
    /// \param  input    The string on which the replacement is to be
    ///                  performed.
    /// \param  search   The substring that is to be replaced.
    /// \param  replace  The string that is to be substituted.
    ///
    /// \return  True if a match was found and replaced.
    static bool Replace(std::string& input, std::string& search,
                        std::string& replace);

    /// \brief Convert the provided string to a boolean value.
    ///
    /// The default value is used if there is an error interpreting the
    /// provided string value as a boolean.
    ///
    /// Valid boolean values can be specified as:
    /// - Case insensitive characters 'true' evaluate to true
    /// - '1' evaluates to true
    /// - Case insensitive characters 'false' evaluate to false
    /// - '0' evaluates to false
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default boolean value to return if
    ///                        there is a conversion error.  Defaults to true.
    ///
    /// \return  The boolean value for the provided string.
    static bool GetBool(const std::string& str,
                        const bool default_value = true);

    /// \brief Convert the provided string to an integer.
    ///
    /// The default value is used if there is an error interpreting the
    /// provided string value as an integer.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default integer value to return if
    ///                        there is a conversion error.  Defaults to
    ///                        INT_MAX.
    ///
    /// \return  The integer value for the provided string.
    static int GetInt(const std::string& str,
                      const int default_value = INT_MAX);

    /// \brief Convert the provided string to a 64-bit integer.
    ///
    /// The default value is used if there is an error interpreting the
    /// provided string value as an integer.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default int64_t value to return if
    ///                        there is a conversion error.  Defaults to
    ///                        INT64_MAX.
    ///
    /// \return  The int64_t value for the provided string.
    static int64_t GetInt64(const std::string& str,
                            const int64_t default_value = INT64_MAX);

    /// \brief Convert the provided string to an unsigned integer.
    ///
    /// The default value is used if there is an error converting the provided
    /// string to an unsigned integer.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default unsigned integer value to
    ///                        return if there is a conversion error.
    ///                        Defaults to UINT_MAX.
    ///
    /// \return  The unsigned integer value for the provided string.
    static unsigned int GetUint(const std::string& str,
                                const unsigned int default_value = UINT_MAX);

    /// \brief Convert the provided string to a uint64_t integer.
    ///
    /// The default value is used if there is an error converting the provided
    /// string to the uint64_t integer.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default uint64_t value to return
    ///                        if there is a conversion error.  Defaults to
    ///                        UINT64_MAX.
    ///
    /// \return  The uint64_t value for the provided string.
    static uint64_t GetUint64(const std::string& str,
                              const uint64_t default_value = UINT64_MAX);

    /// \brief Convert the provided string to a float.
    ///
    /// The default value is used if there is an error converting the provided
    /// string value to a float.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default float value to return if
    ///                        there is a conversion error.  Defaults to
    ///                        FLT_MAX.
    ///
    /// \return  The float value for the provided string.
    static float GetFloat(const std::string& str,
                          const float default_value = FLT_MAX);

    /// \brief Convert the provided string to a double.
    ///
    /// The default value is used if there is an error converting the provided
    /// string value to a double.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default double value to return if
    ///                        there is a conversion error.  Defaults to
    ///                        DBL_MAX.
    ///
    /// \return  The double value for the provided string.
    static double GetDouble(const std::string& str,
                            const double default_value = DBL_MAX);

    /// \brief Convert the provided string to an Ipv4Address object.
    ///
    /// \param  str            The string containing the value to be
    ///                        converted.
    /// \param  default_value  The optional default string representation of
    ///                        the IP address to use if there is a conversion
    ///                        error.  Defaults to "0.0.0.0".
    ///
    /// \return  The Ipv4Address object for the provided string.
    static ::iron::Ipv4Address GetIpAddr(
      const std::string& str, const std::string& default_value = "0.0.0.0");

    /// \brief Convert the provided integer value into a string.
    ///
    /// \param  value  The integer value to convert to a string.
    ///
    /// \return  The integer value as a string.
    static std::string ToString(int value);

    /// \brief Convert the provided uint16_t value into a string.
    ///
    /// \param  value  The uint16_t value to convert to a string.
    ///
    /// \return  The uint16_t value as a string.
    static std::string ToString(uint16_t value);

    /// \brief Convert the provided uint32_t value into a string.
    ///
    /// \param  value  The uint32_t value to convert to a string.
    ///
    /// \return  The uint32_t value as a string.
    static std::string ToString(uint32_t value);

    /// \brief Convert the provided uint62_t value into a string.
    ///
    /// \param  value  The uint62_t value to convert to a string.
    ///
    /// \return  The uint62_t value as a string.
    static std::string ToString(uint64_t value);

    /// \brief Convert the provided double value into a string.
    ///
    /// \param  value  The double value to convert to a string.
    ///
    /// \return  The double value as a string.
    static std::string ToString(double value);

    /// \brief Create a string with content derived from a 'printf' style
    /// format.
    ///
    /// \param  size    The maximize length of the created string, in bytes.
    /// \param  format  The formatting string, using 'printf' conventions.
    /// \param  ...     Additional arguments, one for each format field.
    ///
    /// \return  The formatted output as a string.
    static std::string FormatString(int size, const char* format, ...);

  }; // end class StringUtils

} // namespace iron

#endif // IRON_COMMON_STRING_UTILS_H
