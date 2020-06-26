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

///
/// Implements Supervisory Control for IRON.
///
/// Supervisory control takes a top-down approach to managing flows in 
/// the network. It looks at all on-going flows, their utility, and
/// the state of the network to determine with should be allowed into
/// the network, which should be turned off, and if any that are currently
/// off should be turned on.

#ifndef IRON_SUPERVISORY_CONTROL_H
#define IRON_SUPERVISORY_CONTROL_H

#include "config_info.h"
#include "iron_constants.h"
#include "list.h"
#include "ordered_mash_table.h"
#include "supervisory_ctl_if.h"

#include <list>

namespace iron
{
  /// An elastic flow is considered to be underdriving if is
  /// sending at a rate less than this fraction of the rate it
  /// should be sending at, given the current queue depth.
  /// This is a very lenient threshold as the admission rate can
  /// vary as the queue changes.
  const double kUnderdrivingThreshFrac  = 0.25;

  /// An elastic flow is considered to be a low volume flow if it is
  /// underdriving and sending at a rate less that this fraction of
  /// the total outbound capacity.
  const double kLowVolThreshFrac        = 0.01;

  class Svcr : public SupervisoryControl
  {
  public:
    /// \brief Constructor with ref to queue normalizer.
    /// \param k_val The queue normalizer used by the utility functions.
    /// \param amp A reference to the admission planner object that
    ///        owns this supervisory control.
    Svcr(const uint64_t& k_val, Amp& amp);

    /// \brief Destructor.
    virtual ~Svcr();

    /// \brief Update a FlowInfo object in the flow info list.
    /// \param ci  A config info object with all the parameters needed to
    ///            create or update the FlowInfo object.
    virtual void UpdateFlowInfo(const ConfigInfo& ci);

    /// \brief Update the deadline and size of a file transfer FlowInfo.
    /// \param five_tuple The five tuple of the file transfer, of the form:
    ///        "proxy;saddr;sport;daddr;dport".
    /// \param deadline The deadline of the file transfer, in seconds.
    /// \param size The size of the file being transfered, in bytes.
    /// \param priority The priority of the file transfer.
    virtual void UpdateFtFlowInfo(::std::string& five_tuple, uint32_t deadline,
                                  uint32_t size, uint32_t priority);

    /// \brief Delete a flow from the flow_info_list_
    ///
    /// If the flow is an aggregated flow, the members of the coupled
    /// flow set are not removed from flow_info_list. They would no
    /// longer point to this object as their aggregate_flow_. 
    /// 
    /// \param five_tuple proxy;sport;dport;saddr;daddr;
    virtual void DeleteFlowInfo(const ::std::string& five_tuple);

    /// \brief Update the minimum latency and maximum capacity to a 
    ///        destination bin id, through a particular next hop. 
    /// \param next_hop A string with the IP address of the next hop. 
    /// \param bin The bin Id of the destination to which the latency
    ///        estimate applies.
    /// \param latency The minimum latency to the destination bin 
    ///        through a given next hop.
    /// \param capacity The capacity of this link.
    inline void UpdateLinkChar(const ::std::string& next_hop, 
      BinId bin, uint32_t latency, uint32_t capacity)
    {
      LinkChar link;
      link.latency = latency;
      link.capacity = capacity;
      latency_cache_[bin][next_hop] = link;
    }

    /// \brief Check if a flow is a low volume flow.
    /// Low volume flows are no treated as elastic flows as they will not use
    /// all available capacity.
    ///
    /// \param rate The current rate at which the flow is being admitted.
    /// \param nominal_rate The rate at which it should be admitted.
    /// \param capacity The current capacity estimate to the destination.
    /// \return true if the flow is a low volume flow, false otherwise.
    inline bool IsLowVolFlow(double rate, double nominal_rate, double capacity)
    {
      return ((rate < (nominal_rate*kUnderdrivingThreshFrac)) &&
             (rate < capacity*kLowVolThreshFrac));
    }

    /// \brief Update the priorities, seen by the proxies, for ongoing file
    ///        transfers.
    /// Note that the actual priority (and therefore utility) of the file
    /// transfer does not change, only the value of the priority used to make
    /// the admission rate decisions.
    ///
    /// \param p1_send_rate A list of the expected admission rates of elastic
    ///        flow, of priority 1, to each destination.
    /// \param capacity The current capacity estimate to the destination. 
    void UpdateFtPriorities(double  p1_send_rate[kMaxBinId + 1], double capacity);

    /// \brief Select a single probe for each destination bin.
    ///
    /// \param available_capacity The egress capacity that is not yet allocated
    ///        to ongoing flows.
    ///
    /// \return True if the state of any flow has changed, false otherwise.
    bool CalibrateLossProbes(double available_capacity);

    /// \brief  Compute the highest priority flows that can fit on the
    ///         network capacity.
    ///
    /// \param  total_capacity  The outbound capacity in bps, as reported
    ///         by the CATs.
    ///
    /// \result True if there is a flow that needs to change state, false
    ///         otherwise.
    virtual bool ComputeFit(double total_capacity);

    /// \brief  Add a relationship between flows that means they are coupled.
    ///         Coupled flows must all be admitted for any one of them to
    ///         realize their utility.
    ///
    /// NOTE: This method does not currently check or prevent adding a flow 
    ///       coupling multiple times. It also does not handle overlapping
    ///       flow couplings.
    ///
    /// \param  five_tuple_list The list of five tuples identifying flows
    ///                         coupled together.
    ///                         Proxy:x.x.x.x:xx->x.x.x.x:xx.
    ///
    /// \return true on success, false otherwise.
    virtual bool AddFlowCoupling(std::list<std::string>& five_tuple_list);

    /// \brief  Get Flow info object from the flow_info_list_. 
    /// \param  five_tuple The five tuple proxy;sport;dport;saddr;daddr
    /// \return A pointer to the flow info object if found or NULL.
    virtual FlowInfo* FindFlowInfo(::std::string& five_tuple);

    /// \brief Print info on all the flows in the flow info list.
    virtual void PrintAllFlowInfo();

    /// \brief  Get the total capacity to a given destination, subject
    ///         to a latency deadline.
    /// \param  dest The destination Bin ID.
    /// \param  deadline The deadline for delivering the packet. 
    /// \return The maximum bandwidth available for delivering
    ///         the packets on time.
    uint32_t  GetConstrainedBw(BinId dest, uint32_t deadline) const; 

    /// \brief  Compute the utility of an elastic flow.
    /// \param  priority The priority of the flow.
    /// \param  rate The current admission rate of the flow.
    /// \return The instantaneous utility of the flow.
    inline double ComputeUtility(int priority, double rate)
    {
      return priority*log(rate + 1);
    }

    /// \brief Check is a flow is elastic.
    /// Note that currently LOG and FLOG utilities are the only supported
    /// elastic utility functions.
    /// \param utility_type A string with the utility type of the flow.
    /// \return true if the flow has a LOG or FLOG utility, false otherwise.
    inline bool IsElastic(std::string utility_type)
    {
      return (utility_type.compare("LOG") == 0) || 
             (utility_type.compare("FLOG"));
    } 

  protected:
    /// \brief  Remove a flow from a set of coupled flows.
    ///         This does not delete the flow_info, but removes it
    ///         from the linked list of coupled flows and updates the
    ///         info for the aggregated flow. 
    /// \param  flow_info A pointer to the flow info being uncoupled.
    void UncoupleFlow(FlowInfo* flow_info);

    /// A MashTable used to store FlowInfo pointers. 
    OrderedMashTable<FiveTuple, FlowInfo*, double>  flow_info_table_;

  private:
    /// \brief Default constructor.
    Svcr();

    /// \brief A struture for storing capacity of a link and the minimum
    /// latency to a paricular destination.
    struct LinkChar
    {
      /// Default constructor. 
      LinkChar() : capacity(0), latency(0) {}

      /// Destructor.
      virtual ~LinkChar() {}

      /// \brief Copy operator.
      ///
      /// \param  link  A reference to the object to copy from.
      LinkChar& operator=(const LinkChar& link)
      {
        if (this != &link)
        {
          capacity = link.capacity;
          latency  = link.latency; 
        }
        return *this;
      }

      /// The maximum capacity to a destination.
      uint32_t capacity;
      /// The minimum latency to a destination.
      uint32_t latency;
    };

    /// \brief  Compute the size of the queues needed to support elastic
    ///         traffic at implied rates. 
    /// NOTE:   q = K*p/r , where r = p*capacity/(cumulative_priority)
    /// \param  cumulative_priority The sum of the priorities of the 
    ///         known elastic traffic. 
    /// \param  capacity The available capacity for all elastic traffic.
    /// \return The size of the queues for elastic flows given the sum
    ///         of the priorities of all the elastic flows and the
    ///         capacity available for elastic flows.
    double ComputeElasticQueue(int cumulative_priority, double capacity);

    /// \brief  Compute the maximum queue size before an inelastic utility
    ///         function starts stepping down.
    /// \param  priority The priority of the inelastic flow flow.
    /// \param  nominal_rate_bps The nominal rate, in bps of the inelastic flow.
    /// \return The maximum queue size that can be tolerated.
    double ComputeInelasticMaxQueue(int priority, double nominal_rate_bps); 

    /// brief Send a message to turn a flow on in a proxy.
    /// 
    /// \param flow_info A reference to the FlowInfo object that should
    ///        be turned on.
    virtual void TurnFlowOn(FlowInfo& flow_info);

    /// brief Send a message to turn a flow onff in a proxy.
    /// 
    /// \param flow_info A reference to the FlowInfo object that should
    ///        be turned off.
    virtual void TurnFlowOff(FlowInfo& flow_info);

    /// Reference to the k value queue normalizer, maintained in amp.
    const uint64_t&                  k_val_;

    /// The latency to each destination bin through each next hop. 
    std::map<std::string, LinkChar>  latency_cache_[kMaxBinId + 1];

    /// The number of flows turned on in the last evaluation.
    uint16_t                         num_flows_toggled_on_[kMaxBinId + 1];

    /// A pointer to the flow that is currently configured for probing.
    FlowInfo*                        probing_flow_[kMaxBinId + 1];

    /// A pointer to the flow that is currently configured for loss probing.
    FlowInfo*                        loss_probing_flow_[kMaxBinId + 1];

    /// The last time each probe was restarted per each bin.
    iron::Time                       loss_probe_start_time_[kMaxBinId + 1];
  }; // SupervisoryControl class
} // iron namespace
#endif
