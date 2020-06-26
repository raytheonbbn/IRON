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

#include "nftp_config_info.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using ::std::map;
using ::std::string;

//============================================================================
ConfigInfo::ConfigInfo()
{
}

//============================================================================
ConfigInfo::~ConfigInfo()
{
  // Nothing to destroy.
}

//============================================================================
void ConfigInfo::Add(const string& key, const string& value)
{
  if (key.empty() || value.empty())
  {
    fprintf(stderr, "[ConfigInfo::Add] key: '%s', value: '%s'\n", key.c_str(),
            value.c_str());

    fprintf(stderr, "[ConfigInfo::Add] Bad argument. Missing key or "
            "value.\n");
    return;
  }

  config_items_[key] = value;
}

//============================================================================
string ConfigInfo::Get(const string& key, const string& default_value) const
{
  map<string, string>::const_iterator it;

  it = config_items_.find(key);

  if (it != config_items_.end())
  {
    return it->second;
  }
  else
  {
    return default_value;
  }
}

//============================================================================
bool ConfigInfo::GetBool(const string& key, const bool default_value) const
{
  const string  value = Get(key);

  if (value.empty())
  {
    // The configuration item isn't in the collection of items, so return the
    // default value.
    return default_value;
  }

  bool  rv = default_value;

  // Use strncasecmp() to do a case-insensitive comparisons on "true" and
  // "false". Also permits the value "0" to be used to represent false or the
  // value "1" to be used to represent true.
  if (::strncasecmp(value.c_str(), "true", 4) == 0)
  {
    rv = true;
  }
  else if (::strncasecmp(value.c_str(), "false", 5) == 0)
  {
    rv = false;
  }
  else if (::strncmp(value.c_str(), "0", 1) == 0)
  {
    rv = false;
  }
  else if (::strncmp(value.c_str(), "1", 1) == 0)
  {
    rv = true;
  }

  return rv;
}

//============================================================================
int ConfigInfo::GetInt(const string& key, const int default_value) const
{
  const string  value = Get(key);

  if (value.empty())
  {
    // The configuration item isn't in the collection of items, so return the
    // default value.
    return default_value;
  }

  char*        end_ptr = NULL;
  const char*  str_ptr = value.c_str();

  // Clear errno before the call, per strtol(3).
  errno = 0;

  long  val = ::strtol(str_ptr, &end_ptr, 10);

  // Check for overflow, underflow, and any other conversion error.
  if (((errno == ERANGE) && ((val == LONG_MAX) || (val == LONG_MIN)))
      || ((errno != 0) && (val == 0)))
  {
    fprintf(stderr, "[ConfigInfo::GetInt] Error converting string %s to int: "
            "%s\n", str_ptr, strerror(errno));
    return default_value;
  }

  // Check for no conversion.
  if (end_ptr == str_ptr)
  {
    fprintf(stderr, "[ConfigInfo GetInt] Error converting string %s to "
            "int.\n", str_ptr);
    return default_value;
  }

  return static_cast<int>(val);
}
