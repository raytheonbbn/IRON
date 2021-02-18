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

#include "config_info.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <cstdio>
#include <cstring>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>


using ::iron::Ipv4Address;
using ::iron::ConfigInfo;
using ::iron::StringUtils;
using ::std::map;
using ::std::string;


namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "ConfigInfo";
}

//============================================================================
ConfigInfo::ConfigInfo()
{
}

//============================================================================
ConfigInfo::~ConfigInfo()
{
  //
  // Nothing to destroy.
  //
}

//============================================================================
void ConfigInfo::Add(const string& key, const string& value)
{
  if (key.empty() || value.empty())
  {
    LogE(kClassName, __func__, "Bad argument. Missing key or value.\n");
    return;
  }

  config_items_[key] = value;
}

//============================================================================
bool ConfigInfo::LoadFromFile(const string& file_name)
{
  if (file_name.empty())
  {
    LogF(kClassName, __func__, "No configuration file specified\n");
    return false;
  }

  FILE*  input_file = ::fopen(file_name.c_str(), "r");

  if (input_file == NULL)
  {
    LogF(kClassName, __func__, "Unable to open configuration file %s\n",
         file_name.c_str());
    return false;
  }

  char  line[1024];
  char  tok_a[1024];
  char  tok_b[1024];

  while (::fgets(line, 1024, input_file) != NULL)
  {
    int line_len = ::strlen(line);

    if (line_len <= 1)
    {
      //
      // Skip blank lines.
      //
      continue;
    }

    if (line[line_len -1] == '\n')
    {
      line[line_len - 1] = '\0';
    }
    else
    {
      LogW(kClassName, __func__, "Input file %s missing final newline "
           "character.\n", file_name.c_str());
    }

    ::sscanf(line, "%s %s", tok_a, tok_b);

    if (::strcmp(tok_a, "include") == 0)
    {

      //
      // If the file that we are including starts with a '/' character, we
      // will interpret it as an absolute path. Otherwise, it will be relative
      // to the location of the file that is currently being loaded.
      //

      if (tok_b[0] == '/')
      {
        if (!LoadFromFile(tok_b))
        {
          LogF(kClassName, __func__, "Error loading file %s.\n", tok_b);
          ::fclose(input_file);
          return false;
        }
      }
      else
      {
        char*  file_name_dup = new (std::nothrow) char [file_name.size() + 1];

        if (file_name_dup == NULL)
        {
          LogF(kClassName, __func__, "Unable to allocate memory for file "
               "name duplicate.\n");
          ::fclose(input_file);
          return false;
        }

        ::memcpy(file_name_dup, file_name.c_str(), file_name.size() + 1);

        char*   base_name     = ::dirname(file_name_dup);
        string  file_to_load;

        file_to_load.append(base_name);
        file_to_load.append("/");
        file_to_load.append(tok_b);

        if (!LoadFromFile(file_to_load))
        {
          LogF(kClassName, __func__, "Error loading file %s.\n",
               file_to_load.c_str());
          delete [] file_name_dup;
          ::fclose(input_file);
          return false;
        }

        delete [] file_name_dup;
      }
    }
    else if (tok_a[0] == '#')
    {
      //
      // Skip comment lines.
      //
      continue;
    }
    else
    {
      Add(tok_a, tok_b);
    }
  }

  ::fclose(input_file);

  return true;
}

//============================================================================
bool ConfigInfo::WriteToFile(const string& file_name) const
{
  string  file_name_to_open = file_name;

  if (file_name.empty())
  {
    LogE(kClassName, __func__, "No file name provided.\n");
    return false;
  }

  //
  // Open the file now to prevent TOCTOU race condition
  // If opened after ::access, then the contents of the file could change
  // between access and fopen, opening the door to an attack that would replace
  // the file with a same name to point to another and use the privileges of
  // the process to edit it.
  //
  FILE*  output_file = ::fopen(file_name_to_open.c_str(), "a");

  if (output_file == NULL)
  {
    LogE(kClassName, __func__, "Error opening file %s\n", file_name.c_str());
    return false;
  }

  //
  // Don't overwrite an existing file. If the file identified by the provided
  // parameter already exists, write to the provided file name appended with
  // ".bak" to ensure we don't damage the existing file.
  //

  struct stat sb;
  if (::stat(file_name_to_open.c_str(), &sb) == -1)
  {
    LogW(kClassName, __func__, "Could not stat file %s\n",
          file_name_to_open.c_str());
    perror("fstat");
    ::fclose(output_file);
    return false;
  }

  if (sb.st_size > 0)
  {
    ::fclose(output_file);
    file_name_to_open.append(".bak");

    LogW(kClassName, __func__, "File %s exists, will try to write to file "
         "%s instead\n", file_name.c_str(), file_name_to_open.c_str());
    output_file = ::fopen(file_name_to_open.c_str(), "a");

    if (output_file == NULL)
    {
      LogF(kClassName, __func__, "Error opening file %s\n",
            file_name_to_open.c_str());
      return false;
    }

    if (::stat(file_name_to_open.c_str(), &sb) == -1)
    {
      LogW(kClassName, __func__, "Could not stat file %s\n",
            file_name_to_open.c_str());
      perror("fstat");
      ::fclose(output_file);
      return false;
    }

    if (sb.st_size > 0)
    {
      LogW(kClassName, __func__, "File %s also exists, unable to write "
           "configuration information to file.\n", file_name_to_open.c_str());
      ::fclose(output_file);
      return false;
    }
  }


  //
  // Iterate over the collection of configuration items and write the key
  // value pairs for each item to the output file that was opened.
  //

  map<string, string>::const_iterator  it;

  for (it  = config_items_.begin();
       it != config_items_.end();
       ++it)
  {
    ::fprintf(output_file, "%s %s\n", it->first.c_str(),
              it->second.c_str());
  }

  ::fflush(output_file);
  ::fclose(output_file);

  return true;
}

//============================================================================
string ConfigInfo::ToString() const
{
  string                               result;
  map<string, string>::const_iterator  it;

  result.append("\n");
  for (it  = config_items_.begin();
       it != config_items_.end();
       ++it)
  {
    result.append(it->first);
    result.append(" ");
    result.append(it->second);
    result.append("\n");
  }

  return result;
}

//============================================================================
string ConfigInfo::Get(const string& key,
                       const string& default_value,
                       bool log_customizations) const
{
  map<string, string>::const_iterator it;

  it = config_items_.find(key);

  if (it != config_items_.end())
  {
    if (log_customizations &&
        !default_value.empty() &&
        (it->second.compare(default_value) != 0))
    {
      LogC(kClassName, __func__,
           "CUSTOMIZATION Key %s mismatch: value is %s, default is %s.\n",
           key.c_str(), it->second.c_str(), default_value.c_str());
    }
    return it->second;
  }
  else
  {
    return default_value;
  }
}

//============================================================================
bool ConfigInfo::GetBool(const string& key, const bool default_value,
                         bool log_customizations) const
{
  const string value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value.
    //

    return default_value;
  }

  bool to_return = StringUtils::GetBool(value, default_value);
  if (log_customizations && (to_return != default_value))
  {
    LogC(kClassName, __func__,
         "CUSTOMIZATION Key %s mismatch: value is %c, default is %c.\n",
         key.c_str(), (to_return ? 'T' : 'F'), (default_value ? 'T' : 'F'));
  }
  return to_return;
}

//============================================================================
int ConfigInfo::GetInt(const string& key, const int default_value,
                       bool log_customizations) const
{
  const string  value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value.
    //

    return default_value;
  }

  int to_return = StringUtils::GetInt(value, default_value);
  if (log_customizations && (to_return != default_value))
  {
    LogC(kClassName, __func__,
         "CUSTOMIZATION Key %s mismatch: value is %d, default is %d.\n",
         key.c_str(), to_return, default_value);
  }
  return to_return;
}

//============================================================================
unsigned int ConfigInfo::GetUint(const string& key,
                                 const unsigned int default_value,
                                 bool log_customizations) const
{
  const string  value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value.
    //

    return default_value;
  }

  unsigned int to_return = StringUtils::GetUint(value, default_value);
  if (log_customizations && (to_return != default_value))
  {
    LogC(kClassName, __func__,
         "CUSTOMIZATION Key %s mismatch: value is %u, default is %u.\n",
         key.c_str(), to_return, default_value);
  }
  return to_return;
}

//============================================================================
uint64_t ConfigInfo::GetUint64(const string& key,
                               const uint64_t default_value,
                               bool log_customizations) const
{
  const string  value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value.
    //

    return default_value;
  }

  uint64_t to_return = (StringUtils::GetUint64(value, default_value));
  if (log_customizations && (to_return != default_value))
  {
    LogC(kClassName, __func__,
         "CUSTOMIZATION Key %s mismatch: value is %" PRIu64
         ", default is %" PRIu64 ".\n",
         key.c_str(), to_return, default_value);
  }
  return to_return;
}

//============================================================================
float ConfigInfo::GetFloat(const string& key, const float default_value,
                           bool log_customizations) const
{
  const string  value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value.
    //

    return default_value;
  }

  float to_return = StringUtils::GetFloat(value, default_value);
  if (log_customizations && (to_return != default_value))
  {
    LogC(kClassName, __func__,
         "CUSTOMIZATION Key %s mismatch: value is %f, default is %f.\n",
         key.c_str(), to_return, default_value);
  }
  return to_return;
}

//============================================================================
double ConfigInfo::GetDouble(const string& key,
                             const double default_value,
                             bool log_customizations) const
{
  const string  value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value.
    //

    return default_value;
  }

  double to_return = StringUtils::GetDouble(value, default_value);
  if (log_customizations && (to_return != default_value))
  {
    LogC(kClassName, __func__,
         "CUSTOMIZATION Key %s mismatch: value is %f, default is %f.\n",
         key.c_str(), to_return, default_value);
  }
  return to_return;
}

//============================================================================
Ipv4Address ConfigInfo::GetIpAddr(const std::string& key,
                                  const std::string& default_value) const
{
  const string value = Get(key);

  if (value.empty())
  {

    //
    // The configuration item isn't in the collection of items, so return the
    // default value converted to an ip address.
    //

    return StringUtils::GetIpAddr(default_value, "");
  }

  return StringUtils::GetIpAddr(value, default_value);
}
