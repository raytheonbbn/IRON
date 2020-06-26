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

#ifndef IRON_UTIL_NFTP_NFTP_CONFIG_INFO_H
#define IRON_UTIL_NFTP_NFTP_CONFIG_INFO_H

#include <map>
#include <string>

/// Class that contains configuration information, as "key value" pairs.
///
/// A number of accessor methods enable users to request configuration
/// information associated with a provided key. The accessors return the
/// provided default values if the requested key does not map to a
/// configuration item.
class ConfigInfo
{
  public:

  /// \brief Default constructor.
  ConfigInfo();

  /// \brief Destructor.
  virtual ~ConfigInfo();

  /// \brief Add a configuration item.
  ///
  /// Add a configuration item, a key and value pair, to the collection of
  /// configuration information. Note that any previous value assigned to
  /// the key will be replaced by the new value.
  ///
  /// \param  key    The configuration item key.
  /// \param  value  The configuration item value.
  ///
  void Add(const std::string& key, const std::string& value);

  /// \brief Fetch the string value associated with the provided key.
  ///
  /// The default value is returned if the provided key does not map to a
  /// configuration item.
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
                  const std::string& default_value = "") const;

  /// \brief Fetch the boolean associated with the provided key.
  ///
  /// If the key is not defined, then use the provided default value. The
  /// default value is also used if there is an error interpreting the
  /// configuration item value as a boolean.
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
  ///
  /// \return The boolean value associated with the provided key or the
  ///         provided default boolean value.
  ///
  bool GetBool(const std::string& key, const bool default_value) const;

  /// Fetch the integer associated with the provided key. If the key is not
  /// defined, then use the specified default value. The default value is
  /// also used if there is an error interpreting the configuration item
  /// value as an integer.
  ///
  /// \param  key            The requested configuration item key.
  /// \param  default_value  The default integer value when there is no
  ///                        configuration item associated with the provided
  ///                        key.
  ///
  /// \return The integer value associated with the provided key or the
  ///         provided default integer value.
  ///
  int GetInt(const std::string& key, const int default_value) const;

  private:
  
  /// Copy constructor.
  ConfigInfo(const ConfigInfo& other);
    
  /// Copy operator.
  ConfigInfo& operator=(const ConfigInfo& other);

  /// The collection of configuration items.
  std::map<std::string, std::string>  config_items_;

};  // end class ConfigInfo

#endif // IRON_UTIL_NFTP_NFTP_CONFIG_INFO_H
