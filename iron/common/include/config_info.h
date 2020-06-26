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

#ifndef IRON_COMMON_CONFIG_INFO_H
#define IRON_COMMON_CONFIG_INFO_H

#include "ipv4_address.h"

#include <map>
#include <string>

#include <arpa/inet.h>

#define LOG_CUSTOMIZATIONS true

///
/// Support for accessing properties from a file.
///

namespace iron
{

  ///
  /// Properties are specifed in configuration files as "key value" pairs. The
  /// key cannot include a space in its definition, but may include other
  /// separation characters such as '.', '_', '-', etc. The value is
  /// interpreted as the remainder of the line on which the key is found. All
  /// leading whitespace is removed from the value.
  /// 
  /// Comments may be inserted into the property file using the '#'
  /// character. The '#' character MUST be the first character of comment
  /// lines in the configuration file.
  /// 
  /// A number of accessor methods enable users to request configuration
  /// information associated with a provided key. The accessors return the
  /// provided default values if the requested key does not map to a
  /// configuration item.
  ///
  class ConfigInfo
  {
    public:

    ///
    /// Default no-arg constructor.
    ///
    ConfigInfo();

    ///
    /// Destructor.
    ///
    virtual ~ConfigInfo();
  
    ///
    /// Add a configuration item, a key and value pair, to the collection of
    /// configuration information. Note that any previous value assigned to
    /// the key will be replaced by the new value.
    ///
    /// \param  key    The configuration item key.
    /// \param  value  The configuration item value.
    ///
    void Add(const std::string& key, const std::string& value);

    ///
    /// Loads the configuration information from a file.
    ///
    /// \param  file_name  The name of the file containing the configuration
    ///                    information.
    ///
    /// \return true if the configuration information is loaded successfully,
    ///         false otherwise.
    ///
    bool LoadFromFile(const std::string& file_name);

    ///
    /// Write the configuration information to a file.
    ///
    /// \param  file_name  The name of the output file.
    ///
    /// \return true if the configuration information is written to the file,
    ///         false otherwise.
    ///
    bool WriteToFile(const std::string& file_name) const;

    ///
    /// Get a string representation of the configuration information.
    ///
    /// \return String representation of the configuration information.
    ///
    std::string ToString() const;

    ///
    /// Fetch the string value associated with the provided key. The default
    /// value is returned if the provided key does not map to a configuration
    /// item.
    ///
    /// @param  key            The requested configuration item key.
    /// @param  default_value  An optional default value that is returned in
    ///                        the event that the provided key does not map to
    ///                        a configuration item.
    /// @param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// @return A pointer to the property value string.
    ////
    std::string Get(const std::string& key,
                    const std::string& default_value = "",
                    bool log_customizations = LOG_CUSTOMIZATIONS) const;

    ///
    /// Fetch the boolean associated with the provided key. If the key is not
    /// defined, then use the provided default value. The default value is
    /// also used if there is an error interpreting the configuration item
    /// value as a boolean.
    ///
    /// Valid boolean values can be specified in the configuration file as:
    /// - Case insensitive characters 'true' evaluate to true
    /// - '1' evaluates to true
    /// - Case insensitive characters 'false' evaluate to false
    /// - '0' evaluates to false
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default boolean value when there is no
    ///                        configuration item associated with the provided
    ///                        key.
    /// \param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// \return The boolean value associated with the provided key or the
    ///         provided default boolean value.
    ///
    bool GetBool(const std::string& key, const bool default_value,
                 bool log_customizations = LOG_CUSTOMIZATIONS) const;
    
    ///
    /// Fetch the integer associated with the provided key. If the key is not
    /// defined, then use the specified default value. The default value is
    /// also used if there is an error interpreting the configuration item
    /// value as an integer.
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default integer value when there is no
    ///                        configuration item associated with the provided
    ///                        key.
    /// \param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// \return The integer value associated with the provided key or the
    ///         provided default integer value.
    ///
    int GetInt(const std::string& key, const int default_value,
               bool log_customizations = LOG_CUSTOMIZATIONS) const;
    
    ///
    /// Fetch the unsigned integer associated with the provided key. If the
    /// key is not defined, then use the specified default value. The default
    /// value is also used if there is an error interpreting the configuration
    /// item value as an unsigned integer.
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default unsigned integer value when there
    ///                        is no configuration item associated with the
    ///                        provided key.
    /// \param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// \return The unsigned integer value associated with the provided key or
    ///         the provided default unsigned integer value.
    ///
    unsigned int GetUint(const std::string& key,
                         const unsigned int default_value,
                         bool log_customizations = LOG_CUSTOMIZATIONS) const;

    ///
    /// Fetch the uint64 unsigned integer associated with the provided key. If
    /// the key is not defined, then use the specified (uint64_t) default value.
    /// The default value is also used if there is an error interpreting the
    /// configuration item value as a uint64_t unsigned integer.
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default uint64_t unsigned integer value when
    ///                        there is no configuration item associated with
    ///                        the provided key.
    /// \param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// \return The uint64_t unsigned integer value associated with the provided
    ///         key or the provided default uint64_t unsigned integer value.
    ///
    uint64_t GetUint64(const std::string& key,
                       const uint64_t default_value,
                       bool log_customizations = LOG_CUSTOMIZATIONS) const;

    ///
    /// Fetch the float associated with the provided key. If the key is not
    /// defined, then use the specified default value. The default value is
    /// also used if there is an error interpreting the configuration item
    /// value as a float.
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default float value when there is no
    ///                        configuration item associated with the provided
    ///                        key. 
    /// \param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// \return The float value associated with the provided key or the
    ///         provided default float value.
    ///
    float GetFloat(const std::string& key, const float default_value,
                   bool log_customizations = LOG_CUSTOMIZATIONS) const;

    ///
    /// Fetch the double associated with the provided key. If the key is not
    /// defined, then use the specified default value. The default value is
    /// also used if there is an error interpreting the configuration item
    /// value as a double.
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default double value when there is no
    ///                        configuration item associated with the provided
    ///                        key.
    /// \param  log_customizations True if we want to print a log message if
    ///                        the value doesn't match the default
    ///                        value. Defaults to LOG_CUSTOMIZATIONS.
    ///
    /// \return The double value associated with the provided key or the
    ///         provided default double value.
    ///
    double GetDouble(const std::string& key, const double default_value,
                     bool log_customizations = LOG_CUSTOMIZATIONS) const;

    ///
    /// Fetch an Internet Address associated with the provided key. If the
    /// key is not defined, then use the specified default value. The returned
    /// Internet Address is in network byte order (NBO).
    ///
    /// \param  key            The requested configuration item key.
    /// \param  default_value  The default Internet Address value when there
    ///                        is no configuration item associated with the
    ///                        provided key. 
    ///
    /// \return The Internet Address value associated with the provided key or
    ///         the provided default Internet Address value.
    ///
    ::iron::Ipv4Address GetIpAddr(const std::string& key,
                          const std::string& default_value) const;

    ///
    /// Remove all entries from the ConfigInfo object
    ///
    inline void Reset()
    {
      config_items_.clear();
    } 

    private:

    /// Copy constructor.
    ConfigInfo(const ConfigInfo& other);
    
    /// Copy operator.
    ConfigInfo& operator=(const ConfigInfo& other);

    /// The collection of configuration items.
    std::map<std::string, std::string>  config_items_;

  }; // end class ConfigInfo
} // namespace iron

#endif // IRON_COMMON_CONFIG_INFO_H
