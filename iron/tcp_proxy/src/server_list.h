//============================================================================
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
//============================================================================

#ifndef IRON_TCP_PROXY_SERVER_LIST_H
#define IRON_TCP_PROXY_SERVER_LIST_H

#include "bin_map.h"
#include "config_info.h"
#include "ipv4_endpoint.h"
#include "packet_pool.h"

class TcpProxy;

/// \brief A class that maps a client configured server address and port to a
/// set of alternative server addresses and ports that may be used.
///
/// This class stores a collection of possible alternative server addresses
/// and ports that can be used in place of the server address and port
/// received from the client in the initial TCP SYN packet.
class ServerList
{
  public:

  /// \brief Constructor.
  ///
  /// \param  tcp_proxy  The TCP Proxy.
  ServerList(TcpProxy& tcp_proxy);

  /// \brief Destructor.
  ~ServerList();

  /// \brief Initialize the server list.
  ///
  /// \param  config_info        The configuration information.
  /// \param  packet_pool        The IRON packet pool.
  /// \param  bin_map            The IRON bin map.
  /// \param  server_list_index  The configuration index of the server list.
  ///
  /// \return True if successful, false otherwise.
  bool Initialize(const iron::ConfigInfo& config_info,
                  iron::PacketPool& packet_pool,
                  iron::BinMap& bin_map, uint8_t server_list_index);

  /// \brief Get the client configured server for the server list.
  ///
  /// \return The client configured server for the server list.
  const iron::Ipv4Endpoint& client_configured_server() const
  {
    return client_configured_server_;
  }

  /// \brief Get an available server from the list of servers.
  ///
  /// The chosen server will be the server that is reachable that has the
  /// smallest queue depth associated with it. This search criteria enables
  /// the TCP Proxy to load balance the TCP flows.
  ///
  /// \param  server  The chosen server.
  ///
  /// \return True if an alternate server is available, false otherwise.
  bool GetServer(iron::Ipv4Endpoint& server) const;

  /// \brief Mark the provided server as unreachable.
  ///
  /// \param  server  The server that is unreachable.
  void MarkAsUnreachable(iron::Ipv4Endpoint& server);

  private:

  /// The maximum number of servers allowed in the server list.
  static const uint8_t  kMaxServerAddrs = 8;

  /// \brief Copy constructor.
  ServerList(const ServerList& sl);

  /// Copy operator.
  ServerList& operator=(const ServerList& sl);

  /// \brief Contains the information relevant to an alternate server.
  struct AlternateServerInfo
  {
    /// \brief Constructor.
    AlternateServerInfo()
      : server(), bin_idx(0), reachable(true)
    {
    }

    /// The alternate server address and port.
    iron::Ipv4Endpoint  server;

    /// The IRON bin index associated with the alternate server.
    iron::BinIndex      bin_idx;

    /// Flag that remembers if the alternate server is reachable.
    bool                reachable;
  };

  /// The TCP Proxy.
  TcpProxy&            tcp_proxy_;

  /// The client configured server address and port.
  iron::Ipv4Endpoint   client_configured_server_;

  /// The number of alternate servers in the server list.
  uint8_t              num_alternate_servers_;

  /// Array of alternate server information.
  AlternateServerInfo  alternate_servers_[kMaxServerAddrs];

}; // end class ServerList

#endif // IRON_TCP_PROXY_SERVER_LIST_H
