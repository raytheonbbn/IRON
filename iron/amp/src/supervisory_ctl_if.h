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
/// Supervisory Control Interface for IRON.
///
/// Supervisory control takes a top-down approach to managing flows in
/// the network. It looks at all on-going flows, their utility, and
/// the state of the network to determine which should be allowed into
/// the network, which should be turned off, and if any that are currently
/// off should be turned on.

#ifndef IRON_SUPERVISORY_CONTROL_IF_H
#define IRON_SUPERVISORY_CONTROL_IF_H

#include "config_info.h"
#include "iron_constants.h"
#include "iron_types.h"
#include "list.h"
#include "log.h"
#include "iron_types.h"
#include "itime.h"
#include "string.h"

#include <inttypes.h>
#include <list>
#include <cmath>


namespace iron
{
  class Amp;

  /// Struct for five-tuple string.
  ///
  /// This is needed as the index of the hash table must have a Hash() method.
  struct FiveTuple
  {
    /// Default constructor.
    FiveTuple() {}

    /// Constructor with a std::string.
    /// \param ft A std::string representation of the five-tuple.
    FiveTuple(const std::string& ft)
    {
      str_ = ft;
    }

    /// Destructor.
    virtual ~FiveTuple() {}

    /// \brief Equals operator.
    ///
    /// \param  ft  A reference to the object to the right of the operator.
    ///
    /// \return  Returns true if equal, or false otherwise.
    bool operator==(const FiveTuple& ft) const
    {
      return ( str_ == ft.str_);
    }

    /// \brief Copy operator.
    ///
    /// \param  ft  A reference to the object to copy from.
    FiveTuple& operator=(const FiveTuple& ft)
    {
      if (this != &ft)
      {
        str_ = ft.str_;
      }
      return *this;
    }

    /// \brief Hash the object into a table index for quick lookups.
    ///
    /// Hashes the object into 16-bit unsigned integer.
    ///
    /// \return  Returns the hashed five-tuple value.
    size_t Hash() const
    {
       const uint16_t*  data  = reinterpret_cast<const uint16_t*>(str_.c_str());
       uint16_t  sum = 0;
       int size = (str_.size() + 1)/2;
       for (int i = 0; i < size; ++i)
       {
         sum += data[i];
       }
       return static_cast<size_t>(sum);
    }

    std::string str_;
  };

  /// Structure used to cache information about file transfers.
  struct FtInfo
  {
    /// The time of the deadline of the transfer.
    Time      deadline;

    /// The original time to deadline of the transfer.
    uint32_t  ttd;

    /// The total number of bits to be sent.
    uint64_t  size_bits;

    /// The total number of bits acknowledge.
    uint64_t  acked_bits;

    /// The original priority of the transfer.
    uint32_t  priority;

    /// The utility earned for completing the transfer on time.
    double    utility;

    /// Default constructor.
    FtInfo()
    : deadline(Time(0)),
      ttd(0),
      size_bits(0),
      acked_bits(0),
      priority(0),
      utility(0)
    {}

    /// \brief Constructor with parameters.
    ///
    /// \param sec_to_deadline The deadline of the transfer, in seconds,
    ///                        relative to the start time.
    /// \param size The size of the file to be transfered, in bits.
    /// \param priority The priority of the file transfer.
    FtInfo(int sec_to_deadline, uint64_t size, uint32_t priority)
    : deadline(Time::Now() + Time(sec_to_deadline)),
      ttd(sec_to_deadline),
      size_bits(size),
      acked_bits(0),
      priority(priority),
      utility(priority * log((size/sec_to_deadline) + 1))
    {
      LogD("FtInfo", __func__, 
           "File transfers started with deadline: %s, and size %" PRIu64
           " bits, now: %s\n", deadline.ToString().c_str(), size_bits,
           Time::Now().ToString().c_str());
    }

    /// \brief Destructor.
    ~FtInfo() {}
  };

  /// Structure used to cache information about the flows from the proxies.
  struct FlowInfo
  {
    /// The proxy which reported the flow.
    std::string       proxy_;

    /// The five tuple of the flow - proxy;saddr;sport;daddr;dport
    FiveTuple         five_tuple_;

    /// The four tuple of the flow in saddr:sport --> daddr:dport format.
    std::string       four_tuple_;

    /// The utility function string for the flow.
    std::string       utility_fn_;

    /// The type of utility function, extracted from the utility function string.
    std::string       utility_type_;

    /// EWM average of the admission rate, as reported in the stats from the proxy.
    double            adm_rate_;

    /// EWM average of the utility, as reported in the stats from the proxy.
    double            utility_;

    /// The last known state of the flow: On, Off or triaged.
    FlowState         flow_state_;

    /// Average BW needed if it is inelastic, 0 otherwise
    double            nominal_rate_bps_;

    /// The priority based on the utility function.
    uint32_t          priority_;

    /// The maximum acceptable loss rate, as a fraction of data sourced,
    /// for the flow (this is the delta_ value if it has TRAP utility).
    /// Note: This is used for triage based on error rate which is only defined
    /// for flows with STRAP/TRAP utility function.
    double            delta_;

    /// The normalized priority also used to order the flow info objects in
    /// list.
    double            normalized_utility_;

    /// A pointer to the linked list of coupled flows, which are pointers to
    /// other flows.
    List<FlowInfo*>*  coupled_flows_;

    /// The sum of the priorities of the elastic flows in a set of coupled
    /// flows.
    uint32_t          sum_elastic_priority_;

    /// A pointer to the aggregate flow info object for this flow, if it
    /// was a member of a coupled flow set.
    FlowInfo*         aggregate_flow_;

    /// The last sequence number acknowledged by the destination.
    uint32_t          acked_seq_num_;

    /// The average number of packets that are yet to be acked.
    double            avg_unacked_pkts_;

    /// The loss rate reported by the destination, as a percentage of
    /// bytes sent by the source.
    uint32_t          loss_rate_pct_;

    /// The time of the last update for this FlowInfo.
    Time              last_update_time_;

    /// The BinId of the destination of this flow.
    BinId             bin_id_;

    /// The time-to-go for this flow. This is only applicable for UDP flows.
    uint32_t          ttg_;

    /// The number of time the flow has toggled-off. This is used to detect
    /// thrashing.
    uint32_t          toggle_count_;

    /// The last time the flow toggled in the proxy.
    Time              last_toggle_time_;

    /// A flag to indicate if the flow is currently traiged for thrashing.
    bool              is_thrash_triaged_;

    /// A flag to indicate if the flow is loss triaged.
    bool              is_loss_triaged_;

    /// The maximum queue that would allow this flow to be admitted, in bits.
    double            max_queue_bits_;

    /// A pointer to filetransfer-specific information.
    FtInfo*           ft_info_;

    /// Default constructor
    FlowInfo()
    : proxy_(), five_tuple_(), four_tuple_(), utility_fn_(), utility_type_(),
      adm_rate_(0.0), utility_(0.0),
      flow_state_(FLOW_ON),
      nominal_rate_bps_(0),
      priority_(0),
      delta_(0.0),
      normalized_utility_(0.0),
      coupled_flows_(NULL),
      sum_elastic_priority_(0),
      aggregate_flow_(NULL),
      acked_seq_num_(0),
      avg_unacked_pkts_(0.0),
      loss_rate_pct_(0),
      last_update_time_(Time(0)),
      bin_id_(0),
      ttg_(0),
      toggle_count_(0),
      last_toggle_time_(Time(0)),
      is_thrash_triaged_(false),
      is_loss_triaged_(false),
      max_queue_bits_(std::numeric_limits<uint32_t>::max()),
      ft_info_(NULL)
    {}

    /// \brief  Constructor.
    ///
    /// \param  ci  The config item containing the configuration for the flow
    ///             info.
    FlowInfo(const ConfigInfo& ci)
    : coupled_flows_(NULL),
      sum_elastic_priority_(0),
      aggregate_flow_(NULL),
      last_update_time_(Time::Now()),
      is_thrash_triaged_(false),
      is_loss_triaged_(false),
      ft_info_(NULL)
    {
      proxy_              = ci.Get("proxy", "");
      five_tuple_         = FiveTuple(ci.Get("five_tuple", "", false));
      four_tuple_         = ci.Get("four_tuple", "", false);
      utility_fn_         = ci.Get("utility_fn", "", false);
      utility_type_       = ci.Get("type", "", false);
      adm_rate_           = ci.GetDouble("adm_rate", 0., false);
      utility_            = ci.GetDouble("utility", 0., false);
      flow_state_         = static_cast<FlowState>(
        ci.GetInt("flow_state",0, false));
      nominal_rate_bps_   = ci.GetDouble("nominal_rate_bps", 0., false);
      priority_           = ci.GetUint("priority", 0, false);
      delta_              = ci.GetDouble(
        "delta", kDefaultMaxLossThreshold, false);
      normalized_utility_ = ci.GetDouble("normalized_utility",0., false);
      acked_seq_num_      = ci.GetInt("acked_seq_num",0., false);
      avg_unacked_pkts_   = ci.GetInt("sent_pkts",0,false) -
        ci.GetInt("acked_seq_num",0, false);
      loss_rate_pct_      = ci.GetInt("loss_rate_pct",0, false);
      bin_id_             = ci.GetUint("bin_id",0, false);
      ttg_                = ci.GetUint("ttg",0, false);
      toggle_count_       = ci.GetUint("toggle_count", 0, false);
      max_queue_bits_     = ci.GetDouble("max_queue", 0, false);
      int sec_to_deadline = ci.GetInt("deadline", 0, false);
      uint64_t file_size  = ci.GetUint64("file_size",0, false);
 
      if (toggle_count_ > 1)
      {
        last_toggle_time_ = Time::Now();
      }
      else
      {
        last_toggle_time_ = Time(0);
      }

      if (file_size != 0)
      {
        ft_info_ = new FtInfo(sec_to_deadline, file_size, priority_);

        if (!ft_info_)
        {
          LogF("FlowInfo", __func__, "Failed to allocate flow info.\n");
        }
      }
    }

    /// \brief A destructor.
    /// Note: This should not be called directly, except when tearing down.
    /// It does not decouple coupled flows and can leave dangling pointers.
    /// Instead, use DeleteFlowInfo, which handles coupled flows properly.
    ~FlowInfo()
    {
      if (coupled_flows_ != NULL)
      {
        delete coupled_flows_;
      }

      if (ft_info_ != NULL)
      {
        delete ft_info_;
      }
    }

    /// \brief Equals operator.
    ///
    /// \param  fi  A reference to the object to the right of the operator.
    ///
    /// \return  Returns true if equal, or false otherwise.
    bool operator==(const FlowInfo& fi) const
    {
      return ((four_tuple_ == fi.four_tuple_) && (proxy_ == fi.proxy_));
    }

    /// \brief Greater-than operator.
    ///
    /// \param  fi  A reference to the object to the right of the operator.
    ///
    /// \return  Returns true if this flow has a higher normalized utility than
    ///          than the flow being compared, or false otherwise.
    bool operator>(const FlowInfo& fi) const
    {
      return normalized_utility_ > fi.normalized_utility_;
    }

    /// \brief Determine if this flow is currently thrashing.
    ///
    /// \param now A reference to the current time.
    ///
    /// \param interval_ms The interval for triaging flows for thrashing.
    /// \return True if the flow is currently thrashing, false otherwise.
    bool IsThrashing(Time& now, uint32_t interval_ms)
    {
      if (flow_state_ == FLOW_TRIAGED)
      {
        return true;
      }

      Time window = now - Time::FromMsec(1.5*interval_ms);
      if((flow_state_ == FLOW_ON) && (last_toggle_time_ > window))
      {
        LogW("FlowInfo", __func__, "Thrash: %s vs %s, %u\n",
             last_toggle_time_.ToString().c_str(), window.ToString().c_str(),
             interval_ms);
        return true;
      }
      return false;
    }

    /// \brief  Print some key parameters of the flow.
    inline void Print()
    {
      if ((utility_type_.compare("LOG") == 0) ||
          (utility_type_.compare("FLOG") == 0))
      {
        LogW("FlowInfo", __func__,
             "%s: (%f) prio: %" PRId32 " rate: %.01fbps state: %s.\n",
             five_tuple_.str_.c_str(),
             normalized_utility_,
             priority_,
             adm_rate_,
             flowStateString[flow_state_].c_str());
       }
       else
       {
         LogW("FlowInfo", __func__,
             "%s: (%f) prio: %" PRId32 " rate: %.01fbps state: %s.\n",
             five_tuple_.str_.c_str(),
             normalized_utility_,
             priority_,
             nominal_rate_bps_,
             flowStateString[flow_state_].c_str());
       }
    }
  };

  class SupervisoryControl
  {
  public:
    /// \brief Default constructor.
    SupervisoryControl(Amp& amp)
      : amp_(amp) {};

    /// \brief Destructor.
    virtual ~SupervisoryControl() {};

    /// \brief Update a FlowInfo object in the flow info list.
    /// \param ci  A config info object with all the parameters needed to
    ///            create or update the FlowInfo object.
    virtual void UpdateFlowInfo(const ConfigInfo& ci) = 0;

    /// \brief Update the deadline and size of a file transfer FlowInfo.
    /// \param five_tuple The five tuple of the file transfer, of the form:
    ///        "proxy;saddr;sport;daddr;dport".
    /// \param deadline The deadline of the file transfer, in seconds.
    /// \param size The size of the file being transfered, in bytes.
    /// \param priority The priority of the file transfer.
    virtual void UpdateFtFlowInfo(::std::string& five_tuple, uint32_t deadline,
                                  uint32_t size, uint32_t priority) = 0;

    /// \brief Delete a flow from the flow_info_list_
    /// \param five_tuple proxy;sport;dport;saddr;daddr;
    virtual void DeleteFlowInfo(const ::std::string& five_tuple) = 0;

    /// \brief Update the minimum latency to a destination bin id,
    ///        through a particular next hop.
    /// \param next_hop A string with the IP address of the next hop.
    /// \param bin The bin Id of the destination to which the latency
    ///        estimate applies.
    /// \param latency The minimum latency to the destination bin
    ///        through a given next hop.
    /// \param capacity The capacity of the link.
    virtual void UpdateLinkChar(const ::std::string& next_hop,
      BinId bin, uint32_t latency, uint32_t capacity) = 0;

    /// \brief  Compute the highest priority flows that can fit on the
    ///         network capacity.
    ///
    /// \param  total_capacity  The outbound capacity in bps, as reported
    ///         by the CATs.
    ///
    /// \result True if there is a flow that needs to change state, false
    ///         otherwise.
    virtual bool ComputeFit(double total_capacity) = 0;

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
    virtual bool AddFlowCoupling(std::list<std::string>& five_tuple_list) = 0;

    /// \brief  Get Flow info object from the flow_info_list_.
    /// \param  five_tuple The five tuple proxy;sport;dport;saddr;daddr
    /// \return A pointer to the flow info object if found or NULL.
    virtual FlowInfo* FindFlowInfo(::std::string& five_tuple) = 0;

    /// \brief Print info on all the flows in the flow info list.
    virtual void PrintAllFlowInfo() = 0;

  protected:
    /// A reference to the AMP object that owns the supervisory control.
    Amp& amp_;

  }; // SupervisoryControl Interface class.
} // iron namespace.
#endif
