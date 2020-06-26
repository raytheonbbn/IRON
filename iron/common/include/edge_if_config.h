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

#ifndef IRON_COMMON_EDGE_IF_CONFIG_H
#define IRON_COMMON_EDGE_IF_CONFIG_H

#include "config_info.h"
#include "list.h"

#include <string>

#include <linux/filter.h>

namespace iron
{
  /// \brief Structure that contains bypass information.
  ///
  /// This structure contains the information for a flow that is to bypass
  /// IRON.
  struct BypassInfo
  {
    BypassInfo()
    : bypass_tuple_str(), protocol(), saddr(), sport(), sport_range(false),
      sport_low(), sport_high(), daddr(), dport(), dport_range(false),
      dport_low(), dport_high()
    {}

    std::string  bypass_tuple_str;
    std::string  protocol;
    std::string  saddr;
    std::string  sport;
    bool         sport_range;
    std::string  sport_low;
    std::string  sport_high;
    std::string  daddr;
    std::string  dport;
    bool         dport_range;
    std::string  dport_low;
    std::string  dport_high;
  };


  /// \brief Base class for edge interface configuration information.
  ///
  /// The edge interface configuration information includes a filter
  /// consisting of: 1) the Berkeley Packet Filter that describes the
  /// "pattern" that must be matched for the edge interface to receive packets
  /// and 2) a corresponding set of iptables commands that direct the kernel
  /// to DROP packets that the edge interface receives.
  class EdgeIfConfig
  {
    public:

    /// \brief Constructor.
    ///
    /// \param  protocol                     Type of packets processed by the
    ///                                      edge interface (either
    ///                                      IPPROTO_TCP or IPPROTO_UDP).
    /// \param  flush_iptables_mangle_table  True if the iptables mangle table
    ///                                      should be flushed when creating
    ///                                      the edge interface, false
    ///                                      otherwise.
    /// \param  external_plumbing            True if the iptables portion of
    ///                                      the edge interface filter is
    ///                                      configured externally, false
    ///                                      otherwise.
    EdgeIfConfig(int protocol, bool flush_iptables_mangle_table,
                 bool external_plumbing);

    /// \brief Destructor.
    virtual ~EdgeIfConfig();

    /// \brief Initialize the edge interface configuration information.
    ///
    /// \param  ci  The configuration information.
    ///
    /// \return True if the initialization is successful, false otherwise.
    virtual bool Initialize(ConfigInfo& ci);

    /// \brief Retrieve the edge interface's Berkeley Packet Filter.
    ///
    /// \return Pointer to the edge interface's Berkeley Packet Filter. Note
    ///         that this could be NULL.
    inline sock_fprog* bpf() const
    {
      return bpf_;
    }

    /// \brief Get the inbound dev name.
    ///
    /// \return The inbound dev name.
    inline std::string inbound_dev_name() const
    {
      return inbound_dev_name_;
    }

    /// \brief Get the inbound dev IP Address string.
    ///
    /// \return The inbound dev IP Address string.
    inline std::string inbound_dev_ip_str() const
    {
      return inbound_dev_ip_str_;
    }

    /// \brief Get the edge interface's iptables add rule.
    ///
    /// The add rule is the iptables rule to drop packets matching edge
    /// interface's Berkeley Packet Filter.
    inline iron::List<std::string>& iptables_add_rule_list()
    {
      return iptables_add_rule_list_;
    }

    /// \brief Get the edge interface's iptables delete rule.
    ///
    /// The delete rule is used when the edge interface is destroyed.
    inline iron::List<std::string>& iptables_del_rule_list()
    {
      return iptables_del_rule_list_;
    }

    /// \brief Get the edge interface protocol.
    ///
    /// \return The edge interface protocol (either IPPROTO_TCP or IPPROTO_UDP).
    inline int protocol() const
    {
      return protocol_;
    }

    /// \brief Query if the iptables mangle table should be flushed when the
    /// edge interface is created.
    ///
    /// \return True if the iptables mangle table should be flushed during
    ///         edge interface creation, false otherwise.
    inline bool flush_iptables_mangle_table() const
    {
      return flush_iptables_mangle_table_;
    }

    /// \brief Query if the iptables portion of the edge interface configuration
    /// is configured externally.
    ///
    /// \return True if the iptables portion of the edge interface configuration
    ///         is configure externally, false otherwise.
    inline bool external_plumbing() const
    {
      return external_plumbing_;
    }

    protected:

    /// \brief Initialize the Berkeley Packet Filter.
    ///
    /// Dynamically compiles the BPF from the string representation of the
    /// filter.
    bool InitializeBpf();

    /// The Berkeley Packet Filter (BPF) string. The BPF will be dynamically
    /// compiled from this string.
    std::string                 bpf_str_;

    /// The bypass portion of the Berkeley Packet Filter (BPF) string.
    std::string                 bpf_bypass_str_;

    /// The edge interface's Berkeley Packet Filter.
    sock_fprog*                 bpf_;

    /// Name of the inbound device.
    std::string                 inbound_dev_name_;

    /// IP Address of the inbound device, in host byte order.
    uint32_t                    inbound_dev_ip_;

    /// String representation of IP Address of the inbound device.
    std::string                 inbound_dev_ip_str_;

    /// Fully qualified path to the iptables executable.
    std::string                 iptables_cmd_;

    /// The iptables rules used during initialization of the edge interface.
    iron::List<std::string>     iptables_add_rule_list_;

    /// The iptables rules used during destruction of the edge interface.
    iron::List<std::string>     iptables_del_rule_list_;

    private:

    /// \brief Copy Constructor.
    EdgeIfConfig(const EdgeIfConfig& eic);

    /// \brief Copy operator.
    EdgeIfConfig& operator=(const EdgeIfConfig& eic);

    /// \brief Get the inbound dev information.
    ///
    /// The information obtained includes the inbound device IP Address and
    /// string representation of the IP Address.
    ///
    /// \return True if successful, false if an error occurs.
    bool GetInboundDevInfo();

    /// \brief Parse a bypass tuple.
    ///
    /// \param  bypass_tuple  The bypass tuple that is to be parsed.
    void ParseBypassTuple(std::string bypass_tuple);

    /// \brief Generate the bypass iptables rules and BPF string.
    void GenerateBypassIptablesRulesAndBpfStr();

    /// The protocol the edge interface supports, either IPPROTO_TCP or
    /// IPPROTO_UDP.
    int                     protocol_;

    /// Remembers if the iptables mangle table should be flushed when the edge
    /// interface is created.
    bool                    flush_iptables_mangle_table_;

    /// Remembers if the iptables portion of the edge interface configuration
    /// is configured externally.
    bool                    external_plumbing_;

    /// List containing the information for the flows that are to bypass IRON.
    iron::List<BypassInfo>  bypass_info_list_;

  }; // end class EdgeIfConfig
} // namespace iron

#endif // IRON_COMMON_EDGE_IF_CONFIG_H
