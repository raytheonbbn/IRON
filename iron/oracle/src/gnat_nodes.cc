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

#include "gnat_nodes.h"
#include "list.h"
#include "log.h"
#include "string_utils.h"
#include <string>
#include "unused.h"

#include <sstream>

using ::iron::GnatNodes;
using ::iron::List;
using ::iron::StringUtils;
using ::std::string;
using ::std::stringstream;

namespace
{
  const char* UNUSED(kClassName) = "Foo";
}

GnatNodes::GnatNodes(){}
GnatNodes::~GnatNodes(){}
bool GnatNodes::Initialize(const ConfigInfo& config_info)
{
  // Extract the Unicast Destination (Edge Node) Bin ID information.
  string  dst_bin_ids_str = config_info.Get("BinMap.BinIds", "");

  if (dst_bin_ids_str.empty())
  {
    LogF(kClassName, __func__, "Error: No BinMap.BinIds value in BinMap "
         "configuration file.\n");
    return false;
  }

  List<string>  dst_bin_ids;

  StringUtils::Tokenize(dst_bin_ids_str, ",", dst_bin_ids);

  while (dst_bin_ids.size() > 0)
  {
    string  dst_bin_id_str;

    dst_bin_ids.Pop(dst_bin_id_str);

    int     dst_bin_id  = static_cast<int>(
      StringUtils::GetUint(dst_bin_id_str, kInvalidBinId));

    // Add the Bin ID to the Unicast Destination information.
    if (!AddExternalBinId(config_info, dst_bin_id))
    {
      LogF(kClassName, __func__, "Error: Unable to add the unicast "
           "destination Bin ID %i.\n", dst_bin_id);
      return false;
    }
    else
      {
	printf("Added BinId %i to bin_map\n",dst_bin_id);
      }
  }

  // Extract the Interior Node Bin ID information.
  string        int_node_bin_ids_str = config_info.Get("BinMap.IntBinIds",
                                                       "");
  List<string>  int_node_bin_ids;

  StringUtils::Tokenize(int_node_bin_ids_str, ",", int_node_bin_ids);

  while (int_node_bin_ids.size() > 0)
  {
    string  int_node_bin_id_str;

    int_node_bin_ids.Pop(int_node_bin_id_str);

    int     int_node_bin_id  = static_cast<int>(
      StringUtils::GetUint(int_node_bin_id_str, kInvalidBinId));

    // Add the Bin ID to the Interior Node information.
    if (!AddInternalBinId(int_node_bin_id))
    {
      LogF(kClassName, __func__, "Error: Unable to add the interior node Bin "
           "ID %i.\n", int_node_bin_id);
      return false;
    }
  }

  return true;
}
  
bool GnatNodes::AddInternalBinId(int binId)
{
  internal_gnat_nodes_.push_back(binId);
  return true;
}

bool GnatNodes::AddExternalBinId(const ConfigInfo& config_info, int binId)
{
  ExternalGnatNode node;
  node.bin_id_ = binId;

  // Extract the BinId.x.HostMasks value from the configuration file.

  string  config_prefix  = "BinMap.BinId." + std::to_string(binId);
  string  host_masks_str = config_info.Get(config_prefix + ".HostMasks", "");

  if (host_masks_str.empty())
    {
      LogF(kClassName, __func__, "Configuration must include HostMasks "
	   "value for Bin ID %i.\n", binId);
      return false;
    }

  // Tokenize the host_masks string so we can create and initialize the
  // required number of Subnet objects.
  List<string>  host_masks;

  StringUtils::Tokenize(host_masks_str, ",", host_masks);

  while (host_masks.size() > 0)
    {
      string  host_mask_str;

      host_masks.Pop(host_mask_str);

      List<string>  host_mask_parts;

      StringUtils::Tokenize(host_mask_str, "/", host_mask_parts);

      string  network_str;
      string  prefix_len_str;

      if (host_mask_parts.size() < 2)
	{
	  network_str    = host_mask_str;
	  prefix_len_str = "32";
	}
      else
	{
	  host_mask_parts.Pop(network_str);
	  host_mask_parts.Pop(prefix_len_str);
	}

      if (!node.AddSubnet(network_str, prefix_len_str))
	{
	  LogW(kClassName, __func__, "Unable to add a new Subnet object for "
	       "Bin ID %i.\n", binId);
	  return false;
	}
    }

  // The addition was a success.
  external_gnat_nodes_.push_back(node);

  return true;
}
  
std::vector<int> GnatNodes::ExternalBinIds()
{
  std::vector<int> externalBinIds;
  for (uint i = 0; i < external_gnat_nodes_.size(); i++)
    {
      externalBinIds.push_back(external_gnat_nodes_[i].bin_id_);
    }
  return externalBinIds;
}

bool GnatNodes::ExternalGnatNode::AddSubnet(const std::string& network_str,
				      const std::string& prefix_len_str)
{
  Subnet subnet(network_str, prefix_len_str);
  subnets_.push_back(subnet);
  
  return true;
}

GnatNodes::ExternalGnatNode::Subnet::Subnet(const std::string& network_str,
			 const std::string& prefix_len_str)
{
  int  num_mask_bits = StringUtils::GetInt(prefix_len_str, INT_MAX);

  if ((num_mask_bits < 0) || (num_mask_bits > 32))
    {
      LogF(kClassName, __func__, "Error: Prefix length %d out of range. "
	   "Must be between 0 and 32.\n", num_mask_bits);
    }

  subnet_addr_ = network_str;
  prefix_len_  = num_mask_bits;

  if (num_mask_bits == 0)
    {
      subnet_mask_ = htonl(0);
    }
  else
    {
      subnet_mask_ = htonl((0xffffffffU << (32 - num_mask_bits)));
    }
}

bool GnatNodes::ExternalGnatNode::Subnet::IsInSubnet(const Ipv4Address& dst_addr) const
{
  // The masking is done in network byte order.
  return ((dst_addr.address() & subnet_mask_) ==
          (subnet_addr_.address() & subnet_mask_));
}

int GnatNodes::BinIdFromAddress(const Ipv4Address& ip_addr)
{
  // Look for the IP address being within one of the unicast destination
  // subnets.
  for (size_t j = 0; j < external_gnat_nodes_.size(); ++j)
    {
      for (size_t k = 0; k < external_gnat_nodes_[j].subnets_.size(); ++k)
	{
	  if (external_gnat_nodes_[j].subnets_[k].IsInSubnet(ip_addr))
	    {
	      return external_gnat_nodes_[j].bin_id_;
	    }
	}
    }

  return kInvalidBinId;
}

std::vector<std::string> GnatNodes::SubnetsFromBinId(const int binId)
{
  std::vector<std::string> ret_str;
  ret_str.clear();
  std::vector<ExternalGnatNode>::iterator it;
  for (it = external_gnat_nodes_.begin(); it < external_gnat_nodes_.end(); it++)
    {
      if (it->bin_id_ == binId)
	{
	  std::vector<ExternalGnatNode::Subnet> subnets = it->subnets_;
	  for (uint j = 0; j < subnets.size(); j++)
	    {
	      ExternalGnatNode::Subnet subnet = subnets[j];
	      string subnet_str;
	      subnet_str.append(subnet.subnet_addr_.ToString());
	      subnet_str.append("/");
	      subnet_str.append(StringUtils::ToString(subnet.prefix_len_));
	      ret_str.push_back(subnet_str);
	    }
	  break;
	}
    }
  if (it == external_gnat_nodes_.end())
    {
      LogE(kClassName, __func__, "Problem with binId %i\n",binId);}
  return ret_str;
}

bool GnatNodes::ValidateBinId(int binId)
{
  std::vector<int> externalBinIds = ExternalBinIds();
  if (std::find(externalBinIds.begin(), externalBinIds.end(), binId) != externalBinIds.end())
    {
      return true;
    }
  if (std::find(internal_gnat_nodes_.begin(), internal_gnat_nodes_.end(), binId)
      != internal_gnat_nodes_.end())
    {
      return true;
    }
  return false;
}
