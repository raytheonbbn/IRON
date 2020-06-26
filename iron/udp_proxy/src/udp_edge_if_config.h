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

#ifndef IRON_UDP_PROXY_UDP_EDGE_IF_CONFIG_H
#define IRON_UDP_PROXY_UDP_EDGE_IF_CONFIG_H

#include "edge_if_config.h"

/// \brief Edge interface configuration information for the IRON UDP Proxy.
///
/// This class captures the "filter" information for the edge interface for
/// the IRON UDP Proxy. This filter is composed of 2 interconnected pieces: 1)
/// a Berkeley Packet Filter (BPF) that identifies the packet pattern that is
/// of interest to the UDP Proxy's edge interface and 2) the iptables rules
/// that direct the kernel to DROP all packets that match the BPF (as the
/// proxy will handle the received packets).
class UdpEdgeIfConfig : public iron::EdgeIfConfig
{
  public:

  /// \brief Constructor.
  UdpEdgeIfConfig();

  /// \brief Destructor.
  virtual ~UdpEdgeIfConfig();

  /// \brief Initialize the edge interface configuration information.
  ///
  /// \param  ci  The configuration information.
  ///
  /// \return True if the initialization is successful, false otherwise.
  bool Initialize(iron::ConfigInfo& ci);

  private:

  /// \brief Copy Constructor.
  UdpEdgeIfConfig(const UdpEdgeIfConfig& ueic);

  /// \brief Copy operator.
  UdpEdgeIfConfig& operator=(const UdpEdgeIfConfig& ueic);

}; // end class UdpEdgeIfConfig

#endif // IRON_UDP_PROXY_UDP_EDGE_IF_CONFIG_H
