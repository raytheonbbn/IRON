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

#ifndef IRON_TCP_PROXY_CONFIG_H
#define IRON_TCP_PROXY_CONFIG_H

#include "config_info.h"

/// Make room for ipv4 addresses.
typedef char addrstr[INET_ADDRSTRLEN];

/// Enumerates the interfaces types, either LAN or WAN.
enum ProxyIfType
{
  LAN = 0,
  WAN = 1,
};

/// Contains the configuration information, read in from the config file at
/// initialization, for the PEP. There are a few instances when the state of
/// this object is changed post-initialization, e.g., when actuations are
/// received that modify the behavior of the Gateway.
class TcpProxyConfig
{
  public:

  /// \brief Constructor.
  TcpProxyConfig();

  /// \brief Destructor.
  ~TcpProxyConfig();

  /// \brief Initialize the Proxy configuration information from the
  /// ConfigInfo.
  ///
  /// \param   config_info  A reference to the configuration information.
  void Initialize(const iron::ConfigInfo& config_info);

  /// \brief Set the interface's Congestion Control Algorithm.
  ///
  /// \param  type   Which interface.
  /// \param  value  The Congestion Control Algorithm for the interface.
  void SetIfCongCtrlAlg(ProxyIfType type, int value)
  {
    LAN == type ? lan_if_cfg_.cc = value : wan_if_cfg_.cc = value;
  }

  /// \brief Get the interface's buffer size.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's buffer size.
  int32_t GetIfBufSize(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.bufSize : wan_if_cfg_.bufSize;
  }

  /// \brief Get the interface's maximum allowable buffer size.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's maximum allowable buffer size.
  int32_t GetIfMaxBufSize(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.max_buf_size : wan_if_cfg_.max_buf_size;
  }

  /// \brief Get the interface's Congestion Control Algorithm type.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's Congestion Control Algorithm type.
  int32_t GetIfCongCtrlAlg(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.cc : wan_if_cfg_.cc;
  }

  /// \brief Get the interface's MTU in bytes.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's MTU in bytes.
  int GetIfMtu(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.mtu : wan_if_cfg_.mtu;
  }

  /// \brief Get the interface's timestamp option.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's timestamp option.
  int GetIfTs(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.ts : wan_if_cfg_.ts;
  }

  /// \brief Get the interface's no delay option.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's no delay option.
  int GetIfNoDelay(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.noDelay : wan_if_cfg_.noDelay;
  }

  /// \brief Get the interface's ack delay option.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's ack delay option.
  int GetIfAckDelay(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.ackDelay : wan_if_cfg_.ackDelay;
  }

  /// \brief Get the interface's ack behavior option.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's ack behavior option.
  int GetIfAckBehavior(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.ackBehave : wan_if_cfg_.ackBehave;
  }

  /// \brief Get the interface's initial RTO.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's initial RTO.
  int32_t GetIfInitialRto(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.irto : wan_if_cfg_.irto;
  }

  /// \brief Get the interface's Flow Control Cap value.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's Flow Control Cap value.
  int GetIfFlowControlCap(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.flowControlCap :
      wan_if_cfg_.flowControlCap;
  }

  /// \brief Get the interface's SACK value.
  ///
  /// \param  type  Which interface.
  ///
  /// \return The interface's SACK value.
  int GetIfSack(ProxyIfType type) const
  {
    return LAN == type ? lan_if_cfg_.sack : wan_if_cfg_.sack;
  }

  /// \brief Get the Proxy's RTT Max Shift value.
  ///
  /// \return The Proxy's RTT Max Shift value.
  int rtt_max_shift() const
  {
    return rtt_max_shift_;
  }

  /// \brief Query if adaptive buffer management is being used.
  ///
  /// \return True if adaptive buffer management is being used, false
  ///         otherwise.
  bool adaptive_buffers() const
  {
    return adaptive_buffers_;
  }

  private:

  /// \brief Copy constructor.
  TcpProxyConfig(const TcpProxyConfig& tpc);

  /// \brief Copy operator.
  TcpProxyConfig& operator=(const TcpProxyConfig& tpc);

  /// Interface information for AIF and BIF, the interfaces supported by the
  /// Gateway.
  struct TcpProxyIfConfig
  {
    int32_t  bufSize;
    int32_t  max_buf_size;
    int32_t  cc;
    int      mtu;
    int      ts;
    int      noDelay;
    int      ackBehave;
    int      ackDelay;
    int32_t  irto;
    int      flowControlCap;
    int      sack;
  };

  /// \brief Load the LAN side interface configuration information.
  ///
  /// \param  config_info    A reference to the configuration information.
  /// \param  lan_if_config  A reference to the LAN interface configuration
  ///                        structure.
  ///
  /// \return True if the LAN interface configuration structure is loaded with
  ///         the configurable items, false if an error occurs.
  void LoadLanIfInfo(const iron::ConfigInfo& config_info,
                     TcpProxyIfConfig& lan_if_config);

  /// \brief Load the WAN side interface configuration information.
  ///
  /// \param  config_info    A reference to the configuration information.
  /// \param  wan_if_config  A reference to the WAN interface configuration
  ///                        structure.
  ///
  /// \return True if the WAN interface configuration structure is loaded with
  ///         the configurable items, false if an error occurs.
  void LoadWanIfInfo(const iron::ConfigInfo& config_info,
                     TcpProxyIfConfig& wan_if_config);

  /// Interface configuration for the LAN interface.
  TcpProxyIfConfig  lan_if_cfg_;

  /// Interface configuration for the WAN interface.
  TcpProxyIfConfig  wan_if_cfg_;

  /// The maximum value of the exponential retransmission backoff shift. To
  /// support the dynamic MTU changes, we wanted the retransmission timers to
  /// be more aggressive. To accomplish this we decreased the maximum value of
  /// the exponential retransmission backoff shift from 12 to 1. Instead of
  /// hardcoding this value, we wanted to make it run-time configurable so
  /// that we could experiment with different values without having to
  /// recompile the source code between executions.
  int             rtt_max_shift_;

  /// Remembers if the proxy is using adaptive buffers or not.
  bool            adaptive_buffers_;

}; // end class TcpProxyConfig

#endif // IRON_TCP_PROXY_CONFIG_H
