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

#include "flow_stats.h"
#include "string_utils.h"

#include <list>

using ::iron::FlowFilter;
using ::iron::FlowStats;
using ::iron::List;
using ::iron::StringUtils;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "FlowStats";
}

//============================================================================
FlowFilter::FlowFilter()
    : saddr_set_(false),
      saddr_(0),
      sport_set_(false),
      sport_(0),
      daddr_set_(false),
      daddr_(0),
      dport_set_(false),
      dport_(0),
      proto_set_(false),
      proto_(0),
      dscp_set_(false),
      dscp_(0)
{
}

//============================================================================
FlowFilter::~FlowFilter()
{
  // Nothing to destroy.
}

//============================================================================
bool FlowFilter::Configure(const string& filter_spec)
{
  // Following is the format of the flow statistics filter specification:
  //
  //   field1=value1,field2=value2,...
  //
  // Valid field/value pairs are:
  //
  //   saddr=<source address>
  //   sport=<source port>
  //   daddr=<destination address>
  //   dport=<destination port>
  //   proto=<protocol number>
  //   dscp=<dscp value>

  LogD(kClassName, __func__, "Received filter specification: %s\n",
       filter_spec.c_str());

  List<string>  filter_spec_tokens;
  StringUtils::Tokenize(filter_spec, ",", filter_spec_tokens);

  if (filter_spec_tokens.size() == 0)
  {
    LogE(kClassName, __func__, "Invalid flow statistics filter spec "
         "received.\n");
    return false;
  }

  while (filter_spec_tokens.size() > 0)
  {
    string  filter_spec_token;
    if (!filter_spec_tokens.Pop(filter_spec_token))
    {
      LogE(kClassName, __func__, "Error getting filter spec token.\n");
      return false;
    }

    List<string> key_value_pair;
    StringUtils::Tokenize(filter_spec_token, "=", key_value_pair);

    string  filter_key;
    if (!key_value_pair.Pop(filter_key))
    {
      LogE(kClassName, __func__, "Error getting filter spec token key.\n");
      return false;
    }

    string  filter_value;
    if (!key_value_pair.Pop(filter_value))
    {
      LogE(kClassName, __func__, "Error getting filter spec token value.\n");
      return false;
    }

    if (filter_key == "saddr")
    {
      LogD(kClassName, __func__, "Source address is part of the filter.\n");

      Ipv4Address  addr = StringUtils::GetIpAddr(filter_value);

      set_saddr(addr.address());
    }
    else if (filter_key == "sport")
    {
      LogD(kClassName, __func__, "Source port is part of the filter.\n");

      set_sport(htons(static_cast<uint16_t>(StringUtils::GetUint(filter_value))));
    }
    else if (filter_key == "daddr")
    {
      LogD(kClassName, __func__, "Destination address is part of the "
           "filter.\n");

      Ipv4Address  addr = StringUtils::GetIpAddr(filter_value);

      set_daddr(addr.address());
    }
    else if (filter_key == "dport")
    {
      LogD(kClassName, __func__, "Destination port is part of the filter.\n");

      set_dport(htons(static_cast<uint16_t>(StringUtils::GetUint(filter_value))));
    }
    else if (filter_key == "proto")
    {
      LogD(kClassName, __func__, "Protocol is part of the filter.\n");

      set_proto(static_cast<uint8_t>(StringUtils::GetUint(filter_value)));
    }
    else if (filter_key == "dscp")
    {
      LogD(kClassName, __func__, "DSCP is part of the filter.\n");

      set_dscp(static_cast<uint8_t>(StringUtils::GetUint(filter_value)));
    }
    else
    {
      LogW(kClassName, __func__, "Received improperly formatted flow "
           "statistics filter spec.: %s\n", filter_spec.c_str());

      // Since we have received an improperly formatted filter spec., ensure
      // that the filter is "empty".
      saddr_set_ = false;
      sport_set_ = false;
      daddr_set_ = false;
      dport_set_ = false;
      proto_set_ = false;
      dscp_set_  = false;

      return false;
    }
  }

  return true;
}

//============================================================================
bool FlowFilter::Matches(const Packet* packet) const
{
  bool  get_five_tuple = (saddr_set_ || sport_set_ || daddr_set_ ||
                          dport_set_ || proto_set_);

  if (get_five_tuple || dscp_set_)
  {
    if (get_five_tuple)
    {
      uint32_t  saddr;
      uint32_t  daddr;
      uint16_t  sport;
      uint16_t  dport;
      uint32_t  proto;

      if (!packet->GetFiveTuple(saddr, daddr, sport, dport, proto))
      {
        return false;
      }

      if (saddr_set_ && (saddr_ != saddr))
      {
        return false;
      }

      if (sport_set_ && (sport_ != sport))
      {
        return false;
      }

      if (daddr_set_ && (daddr_ != daddr))
      {
        return false;
      }

      if (dport_set_ && (dport_ != dport))
      {
        return false;
      }

      if (proto_set_ && (proto_ != proto))
      {
        return false;
      }
    }

    if (dscp_set_)
    {
      uint8_t  dscp;

      if ((!packet->GetIpDscp(dscp)) || (dscp_ != dscp))
      {
        return false;
      }
    }

    return true;
  }

  return false;
}

//============================================================================
FlowStats::FlowStats()
    : flow_filter_(),
      byte_count_(0)
{
}

//============================================================================
FlowStats::~FlowStats()
{
  // Nothing to destroy.
}

//============================================================================
void FlowStats::Record(const Packet* packet)
{
  if (flow_filter_.Matches(packet))
  {
    byte_count_ += packet->GetLengthInBytes();
  }
}

//============================================================================
uint32_t FlowStats::Report()
{
  uint32_t  rv = byte_count_;

  byte_count_ = 0;

  return rv;
}
