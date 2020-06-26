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
#ifndef IRON_TCP_PROXY_TCP_CONTEXT_H
#define IRON_TCP_PROXY_TCP_CONTEXT_H

#include <inttypes.h>
#include <string>

/// Class for managing the utility functions utilized by the TCP Proxy.
class TcpContext
{
  public:

  /// Default constructor
  TcpContext();

  /// Constructor that explicitly sets all instance variables
  ///
  /// \param  lo_port       Lower end of the UDP port capture range
  /// \param  hi_port       Upper end of the UDP port capture range
  /// \param  util_fn_defn  The utility function definition.
  /// \param  dscp          The desired flow dscp value.
  TcpContext(int lo_port, int hi_port, std::string util_fn_defn,
             int8_t dscp);

  /// Destructor.
  virtual ~TcpContext();

  /// Get the lower end of the port range for this context.
  ///
  /// \return The lower end of the port range for this context.
  inline int lo_port() const
  {
    return lo_port_;
  }

  /// Get the upper end of the port range for this context.
  ///
  /// \return The upper end of the port range for this context.
  inline int hi_port() const
  {
    return hi_port_;
  }

  /// Set the lower end of the port range for this context.
  ///
  /// \param  lo_port  The lower end of the port range for the context.
  inline void set_lo_port(const int lo_port)
  {
    lo_port_ = lo_port;
  }

  /// Set the upper end of the port range for this context.
  ///
  /// \param  hi_port  The upper end of the port range for this context.
  inline void set_hi_port(const int hi_port)
  {
    hi_port_ = hi_port;
  }

  /// Set the utility function definition string.
  ///
  /// \param  util_fn_defn  The utility function definition string.
  inline void set_util_fn_defn(const std::string util_fn_defn)
  {
    util_fn_defn_ = util_fn_defn;
  }

  /// Get the utility function definition as a string.
  ///
  /// \return The utility function definition as a string.
  inline const ::std::string util_fn_defn() const
  {
    return util_fn_defn_;
  }

  /// \brief  Get the dscp value to add to packets of this flow.
  ///
  /// \return The dscp value for this associated flow.
  inline int8_t dscp() const
  {
    return dscp_;
  }

  private:

  /// \brief Copy constructor.
  TcpContext(const TcpContext& tc);

  /// Lower end of the covered port range.
  int          lo_port_;

  /// Upper end of the covered port range.
  int          hi_port_;

  /// Utility function definition string.
  std::string  util_fn_defn_;

  /// DSCP value to add (or not, if -1) to packets.
  int8_t       dscp_;

}; // end class TcpContext

#endif // IRON_TCP_PROXY_TCP_CONTEXT_H
