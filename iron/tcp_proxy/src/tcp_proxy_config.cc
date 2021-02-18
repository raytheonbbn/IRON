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

#include "tcp_proxy_config.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"

using ::iron::ConfigInfo;
using ::iron::StringUtils;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName) = "TcpProxyConfig";

  /// Default MTU size, in bytes.
  const int       kDefaultMtuBytes = 1200;

  /// Default setting for adaptive buffers.
  const bool      kDefaultAdaptiveBuffers = true;

  /// Default send buffer size, in bytes.
  const int32_t   kDefaultBufSizeBytes = 1000000;

  /// Default LAN facing send buffer size, in bytes, when adaptive buffers are
  /// being used.
  const int32_t   kDefaultLanBufSizeBytesAdaptiveBuffers = 1000000;

  /// Default send buffer size, in bytes, when adaptive buffers are being
  /// used.
  const int32_t   kDefaultWanBufSizeBytesAdaptiveBuffers = 20000;

  /// Maximum send buffer size, in bytes, when adaptive buffers are being
  /// used.
  const int32_t   kMaxBufSizeBytesAdaptiveBuffers = 3000000;

  /// Default LAN interface congestion control: 0=Pure Rate Control, 1=VJ
  /// Congestion Control
  const int32_t   kDefaultLanIfCc = 1;

  /// Default LAN interface enable timestamps directive: 0=Disable, 1=Enable.
  const int       kDefaultLanIfEnableTimestamps = 1;

  /// Default LAN interface enable snack directive: 0=Disable, 1=Enable.
  const int       kDefaultLanIfEnableSnack = 0;

  /// Default LAN interface No Delay directive: 0=Disable, 1=Enable.
  const int       kDefaultLanIfNoDelay = 0;

  /// Default LAN interface ACK behavior.
  const int       kDefaultLanIfAckBehave = 1;

  /// Default LAN interface ACK delay, in milliseconds.
  const int       kDefaultLanIfAckDelay = 0;

  /// Default LAN interface initial value of Retransmission Timer, in
  /// microseconds.
  const int32_t   kDefaultLanIfIrto = 0;

  /// Default LAN interface Flow Control Cap.
  const int       kDefaultLanIfFlowControlCap = 0;

  /// Default LAN interface MSS FF.
  const int32_t   kDefaultLanIfMssFf = 0;

  /// Default LAN interface sack.
  const int       kDefaultLanIfSack = 0;

  /// Default WAN interface congestion control: 0=Pure Rate Control, 1=VJ
  /// Congestion Control
  const int32_t   kDefaultWanIfCc = 0;

  /// Default WAN interface enable timestamps directive: 0=Disable, 1=Enable.
  const int       kDefaultWanIfEnableTimestamps = 1;

  /// Default WAN interface No Delay directive: 0=Disable, 1=Enable.
  const int       kDefaultWanIfNoDelay = 0;

  /// Default WAN interface ACK behavior.
  const int       kDefaultWanIfAckBehave = 1;

  /// Default WAN interface ACK delay, in milliseconds.
  const int       kDefaultWanIfAckDelay = 0;

  /// Default WAN interface initial value of Retransmission Timer, in
  /// microseconds.
  const int32_t   kDefaultWanIfIrto = 0;

  /// Default WAN interface Flow Control Cap.
  const int       kDefaultWanIfFlowControlCap = 0;

  /// Default WAN interface MSS FF.
  const int32_t   kDefaultWanIfMssFf = 0;

  /// Default WAN interface sack.
  const int       kDefaultWanIfSack = 1;

  /// Default RTT max shift.
  const int       kDefaultRttMaxShift = 12;
}

//============================================================================
TcpProxyConfig::TcpProxyConfig()
    : lan_if_cfg_(),
      wan_if_cfg_(),
      rtt_max_shift_(kDefaultRttMaxShift),
      adaptive_buffers_(kDefaultAdaptiveBuffers)
{
}

//============================================================================
TcpProxyConfig::~TcpProxyConfig()
{
  // Nothing to destroy.
}

//============================================================================
void TcpProxyConfig::Initialize(const ConfigInfo& config_info)
{
  string  tmp;
  string  keyBase;

  // Extract whether we are using adaptive buffers.
  adaptive_buffers_ = config_info.GetBool("AdaptiveBuffers",
                                          kDefaultAdaptiveBuffers);
  // Load the LAN IF configuration.
  LoadLanIfInfo(config_info, lan_if_cfg_);

  // Load the WAN IF configuration.
  LoadWanIfInfo(config_info, wan_if_cfg_);

  // The following proxy parameters are not configurable.
  rtt_max_shift_ = kDefaultRttMaxShift;
}

//============================================================================
void TcpProxyConfig::LoadLanIfInfo(const ConfigInfo& config_info,
                                   TcpProxyIfConfig& lan_if_config)
{
  // Extract the LAN interface send buffer size, in bytes.
  if (adaptive_buffers_)
  {
    lan_if_config.bufSize = 2 * kMaxBufSizeBytesAdaptiveBuffers;
  }
  else
  {
    lan_if_config.bufSize = config_info.GetUint(
      "BufferBytes", kDefaultBufSizeBytes);
  }
  lan_if_config.max_buf_size = lan_if_config.bufSize;

  // Extract the MTU size, in bytes.
  lan_if_config.mtu = config_info.GetUint("MtuBytes",
                                           kDefaultMtuBytes);

  // Set the remaining values in the TcpProxyIfConfig structure for the LAN
  // interface to the default values. We don't provide the ability to change
  // the configuration of the remaining values.

  lan_if_config.cc             = kDefaultLanIfCc;
  lan_if_config.ts             = kDefaultLanIfEnableTimestamps;
  lan_if_config.noDelay        = kDefaultLanIfNoDelay;
  lan_if_config.ackBehave      = kDefaultLanIfAckBehave;
  lan_if_config.ackDelay       = kDefaultLanIfAckDelay;
  lan_if_config.irto           = kDefaultLanIfIrto;
  lan_if_config.flowControlCap = kDefaultLanIfFlowControlCap;
  lan_if_config.sack           = kDefaultLanIfSack;

  // Log the values of the configurable LAN interface parameters.
  LogC(kClassName, __func__, "TCP Proxy LAN configuration:\n");
  LogC(kClassName, __func__, "BufferBytes    : %" PRId32 " bytes\n",
       lan_if_cfg_.bufSize);
  LogC(kClassName, __func__, "MtuBytes       : %d bytes\n",
       lan_if_cfg_.mtu);
  LogC(kClassName, __func__, "TCP Proxy LAN configuration complete.\n");
}

//============================================================================
void TcpProxyConfig::LoadWanIfInfo(const ConfigInfo& config_info,
                                   TcpProxyIfConfig& wan_if_config)
{
  // Extract the WAN interface send buffer size, in bytes.
  if (adaptive_buffers_)
  {
    wan_if_config.bufSize      = kDefaultWanBufSizeBytesAdaptiveBuffers;
    wan_if_config.max_buf_size = kMaxBufSizeBytesAdaptiveBuffers;
  }
  else
  {
    wan_if_config.bufSize = config_info.GetUint("BufferBytes",
                                                kDefaultBufSizeBytes);
    wan_if_config.max_buf_size = wan_if_config.bufSize;
  }

  // Extract the MTU size, in bytes.
  wan_if_config.mtu = config_info.GetUint("MtuBytes", kDefaultMtuBytes);

  // Set the remaining values in the TcpProxyIfConfig structure for the WAN
  // interface to the default values. We don't provide the ability to change
  // the configuration of the remaining values.

  wan_if_config.cc             = kDefaultWanIfCc;
  wan_if_config.ts             = kDefaultWanIfEnableTimestamps;
  wan_if_config.noDelay        = kDefaultWanIfNoDelay;
  wan_if_config.ackBehave      = kDefaultWanIfAckBehave;
  wan_if_config.ackDelay       = kDefaultWanIfAckDelay;
  wan_if_config.irto           = kDefaultWanIfIrto;
  wan_if_config.flowControlCap = kDefaultWanIfFlowControlCap;
  wan_if_config.sack           = kDefaultWanIfSack;

  // Log the values of the configurable WAN interface parameters.
  LogC(kClassName, __func__, "TCP Proxy WAN configuration:\n");
  LogC(kClassName, __func__, "BufferBytes    : %" PRId32 " bytes\n",
       wan_if_cfg_.bufSize);
  LogC(kClassName, __func__, "MtuBytes       : %d bytes\n", wan_if_cfg_.mtu);
  LogC(kClassName, __func__, "TCP Proxy WAN configuration complete.\n");
}
