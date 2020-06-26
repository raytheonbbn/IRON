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

#include "server_list.h"
#include "log.h"
#include "packet.h"
#include "string_utils.h"
#include "tcp_proxy.h"

#include <limits>
#include <string>

using ::iron::BinMap;
using ::iron::ConfigInfo;
using ::iron::Ipv4Endpoint;
using ::iron::Packet;
using ::iron::PacketPool;
using ::iron::StringUtils;
using ::std::numeric_limits;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "ServerList";
}

//============================================================================
ServerList::ServerList(TcpProxy& tcp_proxy)
    : tcp_proxy_(tcp_proxy),
      client_configured_server_(),
      num_alternate_servers_(0),
      alternate_servers_()
{
}

//============================================================================
ServerList::~ServerList()
{
  // Nothing to destroy.
}

//============================================================================
bool ServerList::Initialize(const ConfigInfo& config_info,
                            PacketPool& packet_pool, BinMap& bin_map,
                            uint8_t server_list_index)
{
  string  config_prefix = "ServerList.";
  config_prefix.append(
    StringUtils::ToString(static_cast<int>(server_list_index)));

  LogC(kClassName, __func__, "%s configuration:\n", config_prefix.c_str());

  // Extract the client configured server for the server list.
  string  config_name = config_prefix;
  config_name.append(".ClientConfiguredServer");
  string  ccs_str = config_info.Get(config_name, "");

  if (ccs_str == "")
  {
    LogE(kClassName, __func__, "Required client configured server not "
         "provided for server list %" PRIu8 " configuration.\n",
         server_list_index);
    return false;
  }

  client_configured_server_.SetEndpoint(ccs_str);

  LogC(kClassName, __func__, "%s : %s\n", config_name.c_str(),
       ccs_str.c_str());

  // Extract the number of servers for the server list.
  config_name = config_prefix;
  config_name.append(".NumAlternateServers");

  num_alternate_servers_ = static_cast<uint8_t>(
    config_info.GetUint(config_name, 0));

  LogC(kClassName, __func__, "%s    : %" PRIu8 "\n",
       config_name.c_str(), num_alternate_servers_);

  // Extract the server information.
  for (uint8_t i = 0; i < num_alternate_servers_; i++)
  {
    config_name = config_prefix;
    config_name.append(".AlternateServer.");
    config_name.append(StringUtils::ToString(static_cast<int>(i)));

    string  server_str = config_info.Get(config_name, "");

    if (server_str == "")
    {
      LogE(kClassName, __func__, "Missing required alternate server "
           "'address:port' pair for alternate server %" PRIu8 ".\n", i);
      return false;
    }

    alternate_servers_[i].server.SetEndpoint(server_str);

    // This will LogF if there is no valid bin for this address.
    alternate_servers_[i].bin_idx   = bin_map.GetDstBinIndexFromAddress(
      alternate_servers_[i].server);
    alternate_servers_[i].reachable = true;

    LogC(kClassName, __func__, "%s      : %s\n",
         config_name.c_str(), server_str.c_str());
  }

  LogC(kClassName, __func__, "%s configuration complete.\n",
       config_prefix.c_str());

  return true;
}

//============================================================================
bool ServerList::GetServer(Ipv4Endpoint& server) const
{
  bool      found_server  = false;
  uint8_t   chosen_index  = 0;
  uint32_t  min_bin_depth = numeric_limits<uint32_t>::max();

  for (uint8_t i = 0; i < num_alternate_servers_; i++)
  {
    if (alternate_servers_[i].reachable)
    {
      uint32_t  cur_bin_depth =
        tcp_proxy_.GetBinDepth(alternate_servers_[i].bin_idx);

      LogD(kClassName, __func__, "Current bin depth is %" PRIu32 ", minimum "
           "bin depth is %" PRIu32 ".\n", cur_bin_depth, min_bin_depth);

      if (cur_bin_depth < min_bin_depth)
      {
        min_bin_depth = cur_bin_depth;
        chosen_index  = i;
        found_server  = true;
      }
    }
    else
    {
      LogD(kClassName, __func__, "Server %s is unreachable.\n",
           alternate_servers_[i].server.ToString().c_str());
    }
  }

  if (found_server)
  {
    server = alternate_servers_[chosen_index].server;
    return true;
  }

  LogD(kClassName, __func__, "Did not find a suitable server.\n");

  return false;
}

//============================================================================
void ServerList::MarkAsUnreachable(Ipv4Endpoint& server)
{
  for (uint8_t i = 0; i < num_alternate_servers_; i++)
  {
    if (server == alternate_servers_[i].server)
    {
      alternate_servers_[i].reachable = false;
      LogD(kClassName, __func__, "Marking server %s as unreachable.\n",
           alternate_servers_[i].server.ToString().c_str());
      break;
    }
  }
}
