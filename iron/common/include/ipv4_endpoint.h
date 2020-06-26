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

/// \brief The IRON IPv4 Endpoint header file.
///
/// Provides the IRON software with an efficient way to encapsulate the
/// information for an IPv4 Endpoint, consisting of an IPv4 Address and a
/// port.

#ifndef IRON_COMMON_IPV4_ENDPOINT_H
#define IRON_COMMON_IPV4_ENDPOINT_H

#include "ipv4_address.h"

#include <string>

namespace iron
{
  /// A class to encapsulate the information for an IPv4 Endpoint, consisting
  /// of an IPv4 Address and a port. All addresses and ports are stored and
  /// accessed in Network Byte Order.
  class Ipv4Endpoint : public Ipv4Address
  {
    public:

    /// Defaul no-arg constructor.
    Ipv4Endpoint();

    /// Constructor.
    ///
    /// \param  ep_str  String representation of an Endpoint,
    ///                 (e.g. 192.168.10.1:5555).
    Ipv4Endpoint(const std::string& ep_str);

    /// Constructor.
    ///
    /// \param  addr      The IPv4 address in dot decimal format
    ///                   (e.g. 192.168.10.1).
    /// \param  port_hbo  The port number, in Host Byte Order.
    Ipv4Endpoint(const std::string& addr, uint16_t port_hbo);

    /// Constructor.
    ///
    /// \param  addr_nbo  The IPv4 address represeted as an integer, in
    ///                   Network Byte Order.
    /// \param  port_nbo  The port number, in Network Byte Order.
    Ipv4Endpoint(uint32_t addr_nbo, uint16_t port_nbo);

    /// Constructor.
    ///
    /// \param  addr_nbo  A pointer to an array of bytes, where the bytes are
    ///                   in Network Byte Order.
    /// \param  port_nbo  The port number, in Network Byte Order.
    Ipv4Endpoint(const uint8_t* addr_nbo, uint16_t port_nbo);

    /// Constructor.
    ///
    /// \param  addr      A reference to the Ipv4Address object representing
    ///                   the IPv4 Address.
    /// \param  port_nbo  The port number, in Network Byte Order.
    Ipv4Endpoint(const Ipv4Address& addr, uint16_t port_nbo);

    /// Copy constructor.
    ///
    /// \param  ep  A reference to the Ipv4Endpoint object from which to
    ///             create the object.
    Ipv4Endpoint(const Ipv4Endpoint& ep);

    /// \brief Destructor.
    virtual ~Ipv4Endpoint();

    /// Get the IPv4 Endpoint port, in Network Byte Order.
    ///
    /// \return The IPv4 Endpoint port, in Network Byte Order.
    inline uint16_t port() const { return port_nbo_; }

    /// Set the IPv4 Endpoint port.
    ///
    /// \param  port_nbo  The IPv4 Endpoint port, in Network Byte Order.
    inline void set_port(uint16_t port_nbo) { port_nbo_ = port_nbo; }

    /// Set the endpoint address and port number from a string.
    ///
    /// \param  ep_str  String representation of an Endpoint,
    ///                 (e.g. 192.168.10.1:5555).
    ///
    /// \return Returns true on success, or false on error.  If false is
    ///         returned, the Endpoint object is not modified.
    bool SetEndpoint(const std::string& ep_str);

    /// Get string representation of the IPv4 Endpoint.
    ///
    /// \return String representatation of the IPv4 Endpoint.
    std::string ToString() const;

    /// Get the contents of the Endpoint as a struct sockaddr.
    ///
    /// \param  address  The struct sockaddr to be filled in.
    void ToSockAddr(struct sockaddr* address) const;

    /// Equality operator.
    ///
    /// \param  left   A reference to the left Ipv4Endpoint object.
    /// \param  right  A reference to the right Ipv4Endpoint object.
    ///
    /// \return Returns true if the addresses are equal, false otherwise.
    friend bool operator==(const Ipv4Endpoint& left,
                           const Ipv4Endpoint& right);

    ///
    /// Inequality operator.
    ///
    /// \param  left   A reference to the left Ipv4Endpoint object.
    /// \param  right  A reference to the right Ipv4Endpoint object.
    ///
    /// \return Return true if the addresses are different, false otherwise.
    ///
    friend bool operator!=(const Ipv4Endpoint& left,
                           const Ipv4Endpoint& right);

    /// Copy operator.
    ///
    /// \param  ep  A reference to the Ipv4Endpoint object to copy.
    ///
    /// \return A reference to the updated Ipv4Endpoint object.
    Ipv4Endpoint& operator=(const Ipv4Endpoint& ep);

    private:

    /// The port, in Network Byte Order.
    uint16_t  port_nbo_;

  }; // end class Ipv4Endpoint

} // namespace iron

#endif // IRON_COMMON_IPV4_ENDPOINT_H
