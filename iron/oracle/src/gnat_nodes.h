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

#ifndef IRON_GNAT_NODES_H
#define IRON_GNAT_NODES_H

/// Provides the IRON software with various identifer-related mappings.

#include "config_info.h"
#include "ipv4_address.h"
#include "iron_constants.h"
#include "iron_types.h"

#include <string>
#include <vector>
#include <algorithm>

namespace iron
{
  class GnatNodes
  {

  public:
    GnatNodes();
    virtual ~GnatNodes();
    
    bool Initialize(const ConfigInfo& config_info);
    //    void ExternalGnatNodes(std::vector<int> externalNodes);
    //    void InternalGnatNodes(std::vector<int> internalNodes);
    int  BinIdFromAddress(const Ipv4Address& address);
    bool ValidateBinId(int binId);
    std::vector<std::string> SubnetsFromBinId(const int binId);
    std::vector<int> ExternalBinIds();
    
    class ExternalGnatNode
    {
    public:
      ExternalGnatNode(){}
      virtual ~ExternalGnatNode(){}
      bool AddSubnet(const std::string& network_str,
		     const std::string& prefix_len_str);
      int bin_id_;

      class Subnet
      {

      public:

	/// Default no arg constructor.
      Subnet() : subnet_addr_(), prefix_len_(0), subnet_mask_(0) { }

	/// Constructor with address description
	Subnet(const std::string& network_str,
	       const std::string& prefix_len_str);

	/// Destructor.
	virtual ~Subnet() { }

	/// \brief Determine if an IPv4 destination address is in the subnet.
	///
	/// \param  dst_addr  The Ipv4 destination address to be tested.
	///
	/// \return  Returns true if the destination address is in the subnet,
	///          or false otherwise.
	bool IsInSubnet(const iron::Ipv4Address& dst_addr) const;

	/// \brief Get the subnet address.
	///
	/// \return  The subnet address.
	inline iron::Ipv4Address GetSubnetAddress() const
	{
	  return subnet_addr_;
	}

	/// \brief Get the prefix length.
	///
	/// \return  The prefix length.
	inline int GetPrefixLength() const
	{
	  return prefix_len_;
	}

	/// \brief Get a string representation of the Subnet object.
	///
	/// \return  A string representation of the Subnet object.
	std::string ToString() const;

	/// The subnet address.
	iron::Ipv4Address  subnet_addr_;

	/// The mask prefix length.
	int                prefix_len_;

	/// The subnet mask, in network byte order.
	uint32_t           subnet_mask_;

      };

      std::vector<Subnet> subnets_;

    };

    bool AddExternalBinId(const ConfigInfo& config_info, int binId);
    bool AddInternalBinId(int binId);
    std::vector<int> internal_gnat_nodes_;
    std::vector<ExternalGnatNode> external_gnat_nodes_;
    
  };
}
#endif // IRON_GNAT_NODES_H
