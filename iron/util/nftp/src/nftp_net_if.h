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

#ifndef IRON_UTIL_NFTP_NFTP_NET_IF_H
#define IRON_UTIL_NFTP_NFTP_NET_IF_H

#include "nftp_config_info.h"

/// \brief Base class for nftp network interfaces.
class NftpNetIf
{
  public:

  /// \brief Default constructor.
  NftpNetIf()
  { }

  /// \brief Destructor.
  virtual ~NftpNetIf()
  { }

  /// \brief Initialize the nftp network interface.
  ///
  /// \param  config_info  The configuration information.
  ///
  /// \return True if successful, false otherwise.
  virtual bool Initialize(const ConfigInfo& config_info)
  {
    return true;
  }

  /// \brief Virtual function to coordinate with the network.
  ///
  /// \return True if successful, false otherwise.
  virtual bool CoordinateWithNetwork()
  {
    return true;
  }

  private:

  /// Copy constructor.
  NftpNetIf(const NftpNetIf& other);

  /// Copy operator.
  NftpNetIf& operator=(const NftpNetIf& other);

}; // end class NftpNetIf

#endif // IRON_UTIL_NFTP_NFTP_NET_IF_H
