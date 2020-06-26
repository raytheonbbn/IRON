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

#include "svcr.h"
#include "amp.h"
#include "list.h"
#include "ordered_list.h"
#include "string_utils.h"
#include "unused.h"

#include <inttypes.h>
#include <math.h>

using ::iron::FlowInfo;
using ::iron::OrderedList;
using ::iron::StringUtils;
using ::iron::SupervisoryControl;
using ::iron::Svcr;
using ::iron::Time;
using ::std::list;
using ::std::string;

namespace
{
  // The alpha used in the EWMA for utility and rate
  const double    kDefaultAlpha           = 0.8;

  const char* UNUSED(kClassName)          = "Svcr";

  /// The number of buckets in the flow_info_ hash table.  This value supports
  /// fast lookups with up to 10,000 flows.
  const size_t  kFlowInfoHashTableBuckets = 32768;

  /// A prefix to indicate a FlowInfo is for a coupled flow.
  const string  kCoupledProxy             = "COUPLED";

  /// The number of supervisory control cycles that a triaged flow
  /// should remain off for, after being triaged for error rate.
  const size_t kDefaultTriageCycles       = 8;

  /// The minimum interval between loss-based triage.
  /// After a flow is triaged, due to loss rate, the remaining flows
  /// have this much time to recover.
  const Time kDefaultLossTriageInterval   = Time(2);

  /// The minimum expected total CAT capacity.
  /// If the CATs are underdiven, the capacity estimates can be very low.
  /// This value is used to avoid making supervisory control decision
  /// based on bad estimates.
  const double kMinEgressCapacity        = 750000.0;

  /// The maximum fractional downtime allowed for a flow before it is
  /// considered to be thrashing.
  const double kDefaultThrashThresh      = 0.1;

  /// The value of loss tolerance (delta) for probing flows.
  const string kDefaultProbingMaxLoss    = "0.98";

  /// If a flow is not reported on for this many consecutive intervals it
  /// is removed from the flow table.
  const uint8_t kDefaultFlowTimeout      = 2; 

  /// The time a thrashing flow must remain on for it to be considered
  /// stable, as a multiple of it's initial time-to-go.
  const uint8_t kDefaultStabilityMultiper = 40;

  /// The maximum fraction of the capacity used by elastic flows that
  /// can be reallocated to file transfers.
  const double kMaxFtAllocation           = 0.9;

  /// The maximum priority for a file transfer.
  const uint32_t ft_max_priority          = 25;

  /// The minimum priority for a file transfer that cannot meet its deadline.
  const uint32_t ft_min_priority          = 1;
}

Svcr::Svcr(const uint64_t& k_val, Amp& amp)
  : SupervisoryControl(amp),
    flow_info_table_(iron::LIST_DECREASING),
    k_val_(k_val),
    latency_cache_(),
    num_flows_toggled_on_(),
    probing_flow_(),
    loss_probing_flow_(),
    loss_probe_start_time_()
{
  flow_info_table_.Initialize(kFlowInfoHashTableBuckets);
  for (size_t i = 0; i <= kMaxBinId; ++i)
  {
    num_flows_toggled_on_[i]  = 0;
    probing_flow_[i]          = NULL;
    loss_probing_flow_[i]     = NULL;
    loss_probe_start_time_[i] = Time(0);
  }
}

//=============================================================================
Svcr::~Svcr()
{
  OrderedMashTable<FiveTuple,FlowInfo*, double>::WalkState  ws;

  FlowInfo* flow_info = NULL;
  while (flow_info_table_.GetNextItem(ws, flow_info))
  {
    delete flow_info;
  }
  flow_info_table_.Clear();
}

//=============================================================================
void Svcr::UpdateFlowInfo(const ConfigInfo& ci)
{
  string    ft_str        = ci.Get("five_tuple");
  FiveTuple five_tuple    = FiveTuple(ft_str);
  FlowInfo* flow_info     = NULL;
  Time      now           = Time::Now();
  flow_info_table_.Find(five_tuple, flow_info);

  // If this is not a new flow, update the stats.
  if (flow_info)
  {
    // Order should be p for LOG, p / m for TRAP, STRAP.
    double    order            = ci.GetDouble("normalized_utility", 0.0, false);
    string    proxy            = ci.Get("proxy","", false);
    double    adm_rate         = ci.GetDouble("adm_rate", -1.0, false);
    double    utility          = ci.GetDouble("utility", -1.0, false);
    int       priority         = ci.GetInt("priority", -1, false);
    double    nominal_rate     = ci.GetDouble("nominal_rate_bps", -1.0, false);
    string    utility_type     = ci.Get("type","", false);
    uint32_t  acked_seq_num    = ci.GetInt("acked_seq_num",0, false);
    uint32_t  loss_rate_pct    = ci.GetInt("loss_rate_pct",0, false);
    uint32_t  sent_pkts        = ci.GetInt("sent_pkts",0, false);
    uint32_t  unacked_pkts     = sent_pkts - acked_seq_num;
    double    src_rate         = ci.GetDouble("src_rate",0.0, false);
    uint32_t  toggle_count     = ci.GetUint("toggle_count",0, false);
    uint64_t  acked_bytes      = ci.GetUint64("cumulative_acked_bytes",0, false);
    flow_info->max_queue_bits_ = ci.GetDouble("max_queue", 0, false);
    FlowState flow_state       =
      static_cast<FlowState>(ci.GetInt("flow_state",iron::UNDEFINED, false));

    bool reposition = false;
 
    flow_info->last_update_time_ = now;
    if (flow_info->aggregate_flow_ != NULL)
    {
      flow_info->aggregate_flow_->last_update_time_ = now;
    }

    if ((toggle_count > flow_info->toggle_count_) &&
        (flow_state != iron::FLOW_OFF))
    {
        LogA(kClassName, __func__, "Flow %s is thrashing: %" PRIu32 ".\n",
                                   ft_str.c_str(), toggle_count);
        flow_info->last_toggle_time_ = now;
    }

    flow_info->toggle_count_   = toggle_count;

    if (adm_rate != -1.0)
    {
      flow_info->adm_rate_ *= kDefaultAlpha;
      flow_info->adm_rate_ += adm_rate * (1 - kDefaultAlpha);
    }

    if (utility != -1.0)
    {
      flow_info->utility_  *= kDefaultAlpha;
      flow_info->utility_  += utility * ( 1 - kDefaultAlpha);
    }

    if (flow_state != UNDEFINED)
    {
      flow_info->flow_state_ = flow_state;
      if (flow_state == LOSS_TRIAGED)
      {
        flow_info->is_loss_triaged_ = true;
        LogA(kClassName, __func__, "%s is loss triaged.\n", ft_str.c_str());
      }
    }

    if (priority != -1)
    {
      if (static_cast<uint32_t>(priority) != flow_info->priority_)
      {
        reposition = true;
      }
      flow_info->priority_ = priority;
    }

    if (utility_type != "")
    {
      flow_info->utility_type_ = utility_type;
    }

    if (utility_type == "STRAP")
    {
      if ((src_rate > 1.2*flow_info->nominal_rate_bps_) ||
          (src_rate < 0.8*flow_info->nominal_rate_bps_))
      {
        reposition = true;
      }

      LogD(kClassName, __func__,
        "Using STRAP's computed nominal rate: %f, utility per bit:%f\n",
        src_rate, order);

      flow_info->nominal_rate_bps_ = src_rate;
    }
    else if (nominal_rate != -1.0)
    {
      flow_info->nominal_rate_bps_ = nominal_rate;
    }

    if (order != 0.0)
    {
      flow_info->normalized_utility_ = order;
    }

    if ((acked_bytes != 0) && (flow_info->ft_info_ != NULL))
    {
      flow_info->ft_info_->acked_bits = acked_bytes*8;
    }

    if (acked_seq_num > flow_info->acked_seq_num_)
    {
      flow_info->acked_seq_num_    = acked_seq_num;
      flow_info->loss_rate_pct_    = loss_rate_pct;
      flow_info->avg_unacked_pkts_ = flow_info->avg_unacked_pkts_*kDefaultAlpha
        + unacked_pkts*(1 - kDefaultAlpha);
    }

    LogD(kClassName, __func__,
      "Flow: %s, Acked SN: %" PRIu32 ", Loss Rate: %" PRIu32 "%, Thresh: %f%.\n",
      ft_str.c_str(), flow_info->acked_seq_num_, flow_info->loss_rate_pct_,
      flow_info->delta_);

    //handle changes in normalized utility.
    if (reposition)
    {
      flow_info_table_.Reposition(five_tuple, flow_info->normalized_utility_);
    }
  }
  else
  {
    FlowInfo* flow_info = new (std::nothrow) FlowInfo(ci);

    if (!flow_info)
    {
      LogF(kClassName, __func__, "Failed to allocate flow info.\n");
      return;
    }

    if (!flow_info_table_.OrderedInsert(five_tuple, flow_info,
      flow_info->normalized_utility_))
    {
      // This can only fail if memory allocation failed in the internal
      // structures.
      delete flow_info;
      LogF(kClassName, __func__,
           " - Failed insertion of %s into flow info table.\n",
           five_tuple.str_.c_str());
      return;
    }
    else
    {
      LogD(kClassName, __func__, "Created and inserted flow %s.\n",
           five_tuple.str_.c_str());
      flow_info->Print();
    }
  }
}



//=============================================================================
void Svcr::UpdateFtFlowInfo(::std::string& five_tuple, uint32_t deadline,
                            uint32_t size, uint32_t priority)
{
  FlowInfo* flow_info     = NULL;
  Time      now           = Time::Now();

  flow_info_table_.Find(five_tuple, flow_info);
  if (flow_info)
  {
    if ((flow_info->ft_info_ == NULL) && (deadline > 0) &&
        (priority > 0) && (size > 0))
    {
      flow_info->ft_info_ = new FtInfo(deadline, size, priority);
    }
    else if (flow_info->ft_info_ == NULL)
    {
      LogE(kClassName, __func__, "Flow %s is not a file transfer.\n",
                                 five_tuple.c_str());
    }
    else
    {
      if (deadline > 0)
      {
        flow_info->ft_info_->deadline  = now + Time::FromSec(deadline);
      }
      if (size > 0)
      {
        flow_info->ft_info_->size_bits = size;
      }
      if (priority > 0)
      {
        flow_info->ft_info_->priority  = priority;
      }
    }
  }
  else
  {
    LogE(kClassName, __func__, "File transfer flow info not found for %s\n",
                               five_tuple.c_str());
  }
}
//=============================================================================
void Svcr::DeleteFlowInfo(const ::std::string& five_tuple)
{
  LogD(kClassName, __func__, "Deleting Flow %s .\n", five_tuple.c_str());
  FlowInfo* flow_info = NULL;
  FiveTuple ft        = FiveTuple(five_tuple);
  BinId bin           = 0;

  // If we have pointers to this flow in pointer arrays, they should
  // be set to NULL before deleting the flows.
  if (flow_info == probing_flow_[bin])
  {
    probing_flow_[bin] = NULL;
  }

  if (flow_info == loss_probing_flow_[bin])
  {
    loss_probing_flow_[bin] = NULL;
  }

  if (flow_info_table_.Find(ft, flow_info))
  {
    bin  = flow_info->bin_id_;

    // If we have pointers to this flow in pointer arrays, they should
    // be set to NULL before deleting the flows.
    if (flow_info == probing_flow_[bin])
    {
      probing_flow_[bin] = NULL;
    }

    if (flow_info == loss_probing_flow_[bin])
    {
      loss_probing_flow_[bin] = NULL;
    }

    if (flow_info->aggregate_flow_ != NULL)
    {
      // This flow is a member of a collection of coupled flows.
      // We must remove it from that list and update the aggregate flow info
      // for that list.
      UncoupleFlow(flow_info);
    }
    else if (flow_info->coupled_flows_ != NULL)
    {
      List<FlowInfo*>::WalkState  ws;
      FlowInfo*                   coupled_flow  = NULL;
      while (flow_info->coupled_flows_->GetNextItem(ws, coupled_flow))
      {
        coupled_flow->aggregate_flow_ = NULL;
      }
      delete flow_info->coupled_flows_;
      flow_info->coupled_flows_ = NULL;
    }
    flow_info_table_.FindAndRemove(ft, flow_info);
    delete flow_info;
    return;
  }

  LogE(kClassName, __func__, "Did not find FlowInfo for %s\n",
    five_tuple.c_str());
}

//=============================================================================
void Svcr::UpdateFtPriorities(double p1_send_rate[kMaxBinId + 1],
                              double capacity)
{
  FlowInfo* flow_info  = NULL;
  Time      now        = Time::Now();
  uint32_t  agg_elastic_priority[kMaxBinId + 1];
  double    agg_elastic_traffic_bps[kMaxBinId + 1];
  uint64_t  admitted_ft_size_bits[kMaxBinId + 1];
  Time      admitted_ft_deadline[kMaxBinId + 1];
  double    admitted_ft_utility[kMaxBinId + 1];
  double    ft_rate[kMaxBinId + 1];
  FlowInfo* lead_ft[kMaxBinId + 1];
  OrderedList<FlowInfo*, double>  ft_list(iron::LIST_DECREASING);
  List<FlowInfo*>  ft_update_list;

  for (size_t i = 0; i <= kMaxBinId; ++i)
  {
    agg_elastic_priority[i]    = 0;
    agg_elastic_traffic_bps[i] = 0.0;
    admitted_ft_size_bits[i]   = 0;
    admitted_ft_deadline[i]    = now;
    admitted_ft_utility[i]     = 0.0;
    ft_rate[i]                 = 0.0;
    lead_ft[i]                 = NULL;
  }

  OrderedMashTable<FiveTuple,FlowInfo*, double>::WalkState  ws;
  ws.PrepareForWalk();

  // Get the sum of elastic priorities and create a prioritized list
  // of file transfers. Turn off transfers that are complete or past due.
  // This loop also computes the sum of the priorities and capacity used
  // by all elastic flows (both file transfers and non filetransfers).
  while (flow_info_table_.GetNextItem(ws, flow_info))
  {
    if (flow_info->ft_info_ != NULL)
    {
      agg_elastic_traffic_bps[flow_info->bin_id_] += flow_info->adm_rate_;
      if (flow_info->ft_info_->acked_bits >= flow_info->ft_info_->size_bits)
      {
        // The file transfer is complete, set the priority to 1 if it was admitted.
        LogD(kClassName, __func__,
             "Ft %s is complete.\n",flow_info->four_tuple_.c_str());
        if (flow_info->priority_ > 1)
        {
          flow_info->priority_ = 1;
          ft_update_list.Push(flow_info);
        }
      }
      else if (flow_info->ft_info_->deadline <= now)
      {
        // The file transfer is past due, set the priority to 1 if it was
        // previously admitted.
        LogD(kClassName, __func__,
             "Ft %s has past its deadline\n", flow_info->four_tuple_.c_str());
        if (flow_info->priority_ > ft_min_priority)
        {
          --flow_info->priority_;
          ft_update_list.Push(flow_info);
        }
      }
      else
      {
        LogD(kClassName, __func__,
             "Found Ft %s \n", flow_info->four_tuple_.c_str());
        uint64_t bits_to_go = (flow_info->ft_info_->size_bits -
                               flow_info->ft_info_->acked_bits);
        ft_list.Push(flow_info, static_cast<double>(
                                flow_info->ft_info_->utility)/bits_to_go);
      }
    }
    else if (IsElastic(flow_info->utility_type_))
    {
      if (!IsLowVolFlow(flow_info->adm_rate_, p1_send_rate[flow_info->bin_id_]*
                        flow_info->priority_, capacity))
      {
        agg_elastic_priority[flow_info->bin_id_]    += flow_info->priority_;
        agg_elastic_traffic_bps[flow_info->bin_id_] += flow_info->adm_rate_;
      }
    }
  }

  // Walk the list of filetransfers and determine which can be admitted and
  // compute the total priority assigned to the file transfers.
  OrderedList<FlowInfo*, double>::WalkState ft_ws;
  ft_ws.PrepareForWalk();
  flow_info = NULL;
  size_t num_admitted_ft = 0;

  while (ft_list.GetNextItem(ft_ws, flow_info))
  {
    // When considering a file transfer, we lump the bits remaining of the
    // file transfer being completed and those already accepted into a
    // new abstract file transfer. The deadline of this "aggregated" file
    // trasfer is the latest deadline of the flows being considered and the
    // utility of the "aggregated" file transfer is the sum of the utility
    // of the component file transfers. This abstraction is used only for
    // making an admission decision and computing the total priority to be
    // distributed to the file transfers. The file transfers are not actually
    // merged and are handled independedntly in the proxies.

    BinId bin_id = flow_info->bin_id_;
    // Check if it can fit given the current queues.
    // Compute the amount of data remaining to be transferred.
    uint64_t agg_ft_size       = admitted_ft_size_bits[bin_id] +
                                 flow_info->ft_info_->size_bits -
                                 flow_info->ft_info_->acked_bits;
    // Compute time remaining until the deadline
    int64_t flow_ttd           = (flow_info->ft_info_->deadline - now).GetTimeInSec();
    int64_t ttd                = std::max((admitted_ft_deadline[bin_id] - now).GetTimeInSec(),
                                    flow_ttd);
    double orig_ttd            = static_cast<double>(flow_info->ft_info_->ttd);

    if (flow_ttd == 0)
    {
      LogE(kClassName, __func__, "Deadline has expired.\n");
      continue;
    }

    double agg_ft_utility      = admitted_ft_utility[bin_id] + (orig_ttd/flow_ttd)*
                                 flow_info->ft_info_->utility;

    uint32_t bin_depth           = amp_.GetAvgQueueDepth(bin_id)*8;
    // The minimum rate needed to complete the transfer by the deadline.
    double   min_rate            = static_cast<double>(agg_ft_size)/ttd;
    // The maximum rate we are allowed to admit this file transfer -- what share
    // of the outbound capacity this flow is allowed to fairly get.
    double   max_rate            = k_val_*agg_ft_utility/bin_depth;

    LogD(kClassName, __func__, "Considering aggregate flow. Deadline: %s, %"
         PRId64 ", max_rate: %f, min_rate: %f, capacity: %f, utility: %f\n",
         flow_info->ft_info_->deadline.ToString().c_str(),
         flow_info->ft_info_->deadline.GetTimeInSec() - now.GetTimeInSec(),
         max_rate, min_rate, agg_elastic_traffic_bps[bin_id], agg_ft_utility);

    // Check that the max rate is greater than the minimum required rate, and that
    // the minimum required rate is less than the available capacity.
    if ((max_rate < min_rate) || (agg_elastic_traffic_bps[bin_id] < min_rate))
    {
      if (flow_info->priority_ >  ft_min_priority)
      {
        --flow_info->priority_;
        ft_update_list.Push(flow_info);
      }
      LogD(kClassName, __func__,
           "Flow %s cannot be supported. Setting priority to %" PRIu32 ".\n",
           flow_info->four_tuple_.c_str(), flow_info->priority_);
      continue;
    }

    // The flow can be admitted. The rate should not be more than twice the
    // minimum rate needed to complete the transfer on time.
    double target_rate = std::min(max_rate, 2*min_rate);
    target_rate = std::min(target_rate,
                  kMaxFtAllocation*agg_elastic_traffic_bps[bin_id]);

    admitted_ft_size_bits[bin_id]       = agg_ft_size;
    admitted_ft_deadline[bin_id]        = now + Time(ttd);
    admitted_ft_utility[bin_id]         = agg_ft_utility;
    ++num_admitted_ft;

    // The target rate of the aggregate transfer should not be less than the
    // rate needed to finish previously accepted file transfers in time.
    target_rate            = std::max(target_rate, ft_rate[bin_id]);
    ft_rate[bin_id]        = target_rate;
    double target_priority = ceil(target_rate*agg_elastic_priority[bin_id]/
                             (agg_elastic_traffic_bps[bin_id] - target_rate));
    target_priority        = std::min(target_priority,
                             static_cast<double>(ft_max_priority));

    LogD(kClassName, __func__,
         "Flow %s can be supported. Rate: %f bps. Bits to go: %" PRIu64
         " Mb, total bits to go: %" PRIu64 " target priority: %f\n",
         flow_info->four_tuple_.c_str(), target_rate,
         (flow_info->ft_info_->size_bits -
         flow_info->ft_info_->acked_bits)/1000000,
         admitted_ft_size_bits[bin_id]/1000000, target_priority);

    // Of the accepted file transfers, the one with the earilest deadline will
    // get most of the capacity allocated to all the ongoing file transfers.
    // This is called the "lead_ft". All other file transfers get a priority
    // of 1 and the lead gets the remainder such that the total is equal to
    // the target priority of the aggregate prioroty.
    if (lead_ft[bin_id] == NULL)
    {
      LogD(kClassName, __func__,
           "First lead ft: %s\n", flow_info->four_tuple_.c_str());
      flow_info->priority_ = target_priority;
      ft_update_list.Push(flow_info);
      lead_ft[bin_id] = flow_info;
    }
    else if (lead_ft[bin_id]->ft_info_->deadline >
             flow_info->ft_info_->deadline)
    {
      flow_info->priority_       = std::max(1.0, target_priority);
      LogD(kClassName, __func__, "New lead ft: %s prio: %" PRIu32 "\n",
           flow_info->four_tuple_.c_str(), flow_info->priority_);
      lead_ft[bin_id]->priority_ = 1;
      lead_ft[bin_id] = flow_info;
      ft_update_list.Push(flow_info);
    }
    else if (target_priority != 1)
    {
      LogD(kClassName, __func__, "Not lead ft, setting priority to 1.\n");
      flow_info->priority_       = 1;
      lead_ft[bin_id]->priority_ = std::max(target_priority - 1.0, 1.0);
      ft_update_list.Push(flow_info);
    }
  }

  // All file transfers has been processed. Update the priorities at the
  // proxies.
  List<FlowInfo*>::WalkState update_ws;
  flow_info = NULL;
  while (ft_update_list.GetNextItem(update_ws, flow_info))
  {
    amp_.UpdateFlowPriority(flow_info->proxy_, flow_info->four_tuple_,
                            StringUtils::ToString(flow_info->priority_));
  }
}
//=============================================================================
bool Svcr::CalibrateLossProbes(double available_capacity)
{
  // Candidate loss-triaged flow probing.
  FlowInfo*  candidate_loss_probe[kMaxBinId + 1];

  // Flow to turn off.
  FlowInfo*  flow_to_turn_off = NULL;

  // New probe flag
  bool need_loss_probe[kMaxBinId + 1];

  // The weight of the current probe candidate
  uint8_t probe_weight[kMaxBinId + 1];

  Time      now       = Time::Now();

  // Initialize the per-bin arrays declared above.
  for (size_t i = 0; i <= kMaxBinId; ++i)
  {
    probe_weight[i]             = 0;
    candidate_loss_probe[i]     = NULL;

    // Check if a probe is now stable.
    Time diff = now - loss_probe_start_time_[i];
    if ((loss_probing_flow_[i] != NULL) &&
        (loss_probing_flow_[i]->flow_state_ == FLOW_ON) &&
        (diff > Time::FromUsec(kDefaultStabilityMultiper*
                               loss_probing_flow_[i]->ttg_)))
    {
      LogA(kClassName, __func__,"Stable: %s\n",
                                loss_probing_flow_[i]->four_tuple_.c_str());

      loss_probing_flow_[i]->is_loss_triaged_ = false;
      loss_probing_flow_[i]                   = NULL;
    }

    if ((loss_probing_flow_[i] != NULL) &&
        (loss_probing_flow_[i]->flow_state_ == FLOW_ON))
    {
      need_loss_probe[i] = false;
    }
    else if ((now - loss_probe_start_time_[i]) > Time::FromSec(10))
    {
      need_loss_probe[i] = true;
    }
    else
    {
      need_loss_probe[i] = false;
    }
  }

  FlowInfo* flow_info = NULL;
  bool turn_flow_off  = false;
  bool has_changed    = false;
  OrderedMashTable<FiveTuple,FlowInfo*, double>::WalkState  ws;
  ws.PrepareForWalk();
  while (flow_info_table_.GetNextItem(ws, flow_info))
  {
    BinId bin = flow_info->bin_id_;

    if (flow_info->is_loss_triaged_ )
    {
      LogD(kClassName, __func__," bin:%" PRIBinId "loss triaged\n", bin);
    }

    if (!flow_info->is_loss_triaged_)
    {
      continue;
    }

    if (flow_info->nominal_rate_bps_ > available_capacity)
    {
      continue;
    }

    if (!need_loss_probe[bin])
    {
      if ((flow_info != loss_probing_flow_[bin]) && (flow_info->flow_state_ != FLOW_OFF))
      {
        LogA(kClassName, __func__,"Loss thrashing, not probe: %s\n",
                                  flow_info->four_tuple_.c_str());
        TurnFlowOff(*flow_info);
        flow_info->flow_state_ = FLOW_OFF;
        has_changed            = true;
      }
      continue;
    }
    turn_flow_off   = false;
    flow_to_turn_off = NULL;

    // If there isn't a probe for this bin, use the one with the longest
    if (loss_probing_flow_[bin] == NULL)
    {
      LogA(kClassName, __func__,"No current loss probe\n");
      if (candidate_loss_probe[bin] == NULL)
      {
        candidate_loss_probe[bin] = flow_info;
        LogA(kClassName, __func__,"Initial loss probe candidate: %s\n",
                                  flow_info->four_tuple_.c_str());
      }
      else if (candidate_loss_probe[bin]->ttg_ < flow_info->ttg_)
      {
        // There isn't a current probe, pick the one with the longest ttg
        if (candidate_loss_probe[bin]->flow_state_ != FLOW_OFF)
        {
          flow_to_turn_off          = candidate_loss_probe[bin];
          candidate_loss_probe[bin] = flow_info;
          LogA(kClassName, __func__,"New loss probe candidate: %s\n",
                 flow_info->four_tuple_.c_str());
        }
        else if (flow_info->flow_state_ != FLOW_OFF)
        {
          turn_flow_off = true;
        }
      }
    }
    else  // There is a current failing probe, find a better probe.
    {
      LogD(kClassName, __func__,"Current failing probe\n");
      FlowInfo* curr_probe = loss_probing_flow_[bin];
      if (candidate_loss_probe[bin] != NULL)
      {
        curr_probe = candidate_loss_probe[bin];
      }

      if ((flow_info->ttg_ > curr_probe->ttg_) &&
          (flow_info->nominal_rate_bps_ < curr_probe->nominal_rate_bps_))
      {
        LogD(kClassName, __func__,"New best candidate: %s\n",
                                  flow_info->four_tuple_.c_str());
        if ((candidate_loss_probe[bin] != NULL) &&
            (candidate_loss_probe[bin]->flow_state_ != FLOW_OFF))
        {
          flow_to_turn_off = candidate_loss_probe[bin];
        }
        candidate_loss_probe[bin] = flow_info;
        probe_weight[bin] = 3;
      }
      else if ((probe_weight[bin] < 3) && (flow_info != loss_probing_flow_[bin]))
      {
        double flow_probe_weight = 0;
        if (flow_info->ttg_ > loss_probing_flow_[bin]->ttg_)
        {
          flow_probe_weight += std::min(static_cast<double>(flow_info->ttg_)/
                                       (2*loss_probing_flow_[bin]->ttg_), 1.0);
        }
        if (flow_info->nominal_rate_bps_ <
            loss_probing_flow_[bin]->nominal_rate_bps_)
        {
          flow_probe_weight += std::min(1.0,
            static_cast<double>(loss_probing_flow_[bin]->nominal_rate_bps_)/
            (2*flow_info->nominal_rate_bps_));
        }

        if (flow_probe_weight > (1.1*probe_weight[bin]))
        { // found a better probe
          LogD(kClassName, __func__,"New better candidate: %s, %f vs %f\n",
               flow_info->four_tuple_.c_str(), flow_probe_weight,
               probe_weight[bin]);

          if ((candidate_loss_probe[bin] != NULL) &&
              (candidate_loss_probe[bin]->flow_state_ != FLOW_OFF))
          {
            flow_to_turn_off = candidate_loss_probe[bin];
          }

          candidate_loss_probe[bin] = flow_info;
          probe_weight[bin] = flow_probe_weight;
        }
        else if (flow_info->flow_state_ != FLOW_OFF)
        {
          turn_flow_off = true;
        }
      }
      else if ((flow_info != loss_probing_flow_[bin]) &&
               (flow_info->flow_state_ != FLOW_OFF))
      {
        turn_flow_off = true;
      }
    }
    if (turn_flow_off)
    {
      TurnFlowOff(*flow_info);
      flow_info->flow_state_ = FLOW_OFF;
      has_changed            = true;
    }
    if ((flow_to_turn_off != NULL) &&
        (flow_to_turn_off->flow_state_ != FLOW_OFF))
    {
      TurnFlowOff(*flow_to_turn_off);
      flow_to_turn_off->flow_state_ = FLOW_OFF;
      has_changed                   = true;
    }
  }

  // Turn on loss triaged probes
  for (size_t i = 1; i <= kMaxBinId; ++i)
  {
    if (candidate_loss_probe[i] != NULL)
    {
      if (candidate_loss_probe[i] != loss_probing_flow_[i])
      {
        if ((loss_probing_flow_[i] != NULL) &&
            (loss_probing_flow_[i]->flow_state_ != FLOW_OFF) &&
            loss_probing_flow_[i]->is_loss_triaged_)
        {
          TurnFlowOff(*loss_probing_flow_[i]);
          loss_probing_flow_[i]->flow_state_ = FLOW_OFF;
          has_changed            = true;

          LogA(kClassName, __func__, "%s:%s old probe should toggle ON->OFF.\n",
                                     loss_probing_flow_[i]->proxy_.c_str(),
                                     loss_probing_flow_[i]->four_tuple_.c_str());
        }
        loss_probing_flow_[i] = candidate_loss_probe[i];
        loss_probe_start_time_[i] = Time::Now();
      }

      if (candidate_loss_probe[i]->flow_state_ != FLOW_ON)
      {
        TurnFlowOn(*candidate_loss_probe[i]);
        loss_probe_start_time_[i] = Time::Now();
        has_changed = true;
        LogA(kClassName, __func__, "Turning on loss probe %s\n",
            candidate_loss_probe[i]->four_tuple_.c_str());
      }
    }
  }
  return has_changed;
}

//=============================================================================
bool Svcr::ComputeFit(double total_capacity)
{
  bool     has_changed                   = false;
  double   original_capacity             = total_capacity;

  // The following arrays store current per-bin state, which is used to
  // iteratively make admission decisions.

  // The total rate of all admitted inelastic flows.
  double   tot_adm_rate_bps[kMaxBinId + 1];
  
  // The number of thrashing flows.
  uint16_t num_thrash_flows[kMaxBinId + 1];
 
  // The sum of the priorities of the elastic flows, used to estimate queues.
  uint32_t tot_elastic_priority[kMaxBinId + 1];

  // The admission rate for a priority 1 elastic flow to each destination,
  // given the current queue depths. This is used to check if an elastic flow
  // is sourcing packets at at a rate smaller than it's admission rate.
  double    p1_log_send_rate[kMaxBinId + 1];

  // To minimize thrashing, we can only toggle on twice as many flows
  // as the previous iteration. This allows for faster ramp up when the
  // capacity increases.
  uint16_t  max_toggle_on[kMaxBinId + 1];

  // The smallest queue size that would cause an admitted inelastic
  // flow to step down.
  double   inelastic_queue_limit[kMaxBinId + 1];

  // The total rate of the admitted low volume flows per bin.
  // These are treated as inelastic flows.
  double   low_vol_elastic_traf_bps[kMaxBinId + 1];

  Time      now       = Time::Now();
  uint32_t bin_depth = 0;
  // Initialize the per-bin arrays declared above.
  for (size_t i = 0; i <= kMaxBinId; ++i)
  {
    tot_adm_rate_bps[i]         = 0;
    tot_elastic_priority[i]     = 0;
    num_thrash_flows[i]         = 0; 
    low_vol_elastic_traf_bps[i] = 0;
    num_flows_toggled_on_[i]    = 0;
    inelastic_queue_limit[i]    = std::numeric_limits<double>::max();
    bin_depth                   = amp_.GetAvgQueueDepth(i)*8;

    if (bin_depth > 0)
    {
      p1_log_send_rate[i]  = k_val_/bin_depth;
    }
    else
    {
      p1_log_send_rate[i]  = total_capacity;
    }

    if (num_flows_toggled_on_[i] == 0)
    {
      max_toggle_on[i] = 1;
    }
    else
    {
      max_toggle_on[i] = std::min(4, 2*num_flows_toggled_on_[i]);
    }
  }

  OrderedMashTable<FiveTuple,FlowInfo*, double>::WalkState  ws;
  ws.PrepareForWalk();

  // If the capacity estimate is very small, the link is likely underdriven 
  // resulting in a poor capacity estimate and we should not react.
  if (total_capacity < kMinEgressCapacity)
  {
    LogW(kClassName, __func__, "Estimated capacity is less than %f, "
         "not running supervisor control.\n", kMinEgressCapacity);
    return false;
  }

  FlowInfo* flow_info = NULL;

  // Initial walk of the flow table to get the per-bin total admission
  // rates and the number of thrashing flows per bin.
  while (flow_info_table_.GetNextItem(ws, flow_info))
  {
    if (flow_info->flow_state_ != FLOW_OFF)
    {
      tot_adm_rate_bps[flow_info->bin_id_] += flow_info->adm_rate_;
    }
    if (flow_info->IsThrashing(now, amp_.triage_interval_ms()) &&
        !flow_info->is_loss_triaged_)
    {
      num_thrash_flows[flow_info->bin_id_] += 1;
    }
  }

  // Update filetransfer priorities.
  UpdateFtPriorities(p1_log_send_rate, original_capacity);

  // Walk the flow table and decided if flows need to be turned on/off.
  string flow_to_delete = "";
  ws.PrepareForWalk();
  while (flow_info_table_.GetNextItem(ws, flow_info))
  {
    BinId bin = flow_info->bin_id_;
 
    // Delete a stale flow discovered the previous step. Cannot delete
    // it the same step it is discovered as this will corrupt the walkstate.
    if (flow_to_delete != "")
    {
      DeleteFlowInfo(flow_to_delete);
      flow_to_delete = "";
    }

    // Mark flows that are no longer being reported by the proxies.
    if ((now - flow_info->last_update_time_).GetTimeInSec() >
        kDefaultFlowTimeout*amp_.stat_interval_s())
    {
      LogD(kClassName, __func__, "Deleting stale flow %s\n",
                                 flow_info->five_tuple_.str_.c_str());
      flow_to_delete = flow_info->five_tuple_.str_;
      continue;
    }

    // Flows are on, by default, unless there is a reason to turn them off.
    bool set_flow_off     = false;
    bool can_probe        = true;
    double avail_capacity = tot_adm_rate_bps[bin];

    // Skip individual flows that belong to a set of coupled flows
    // as they would be considered together.
    if (flow_info->aggregate_flow_ != NULL)
    {
      continue;
    }

    LogA(kClassName, __func__,
      "Looking at %s flow %s, remaining capacity now: %0.3f, "
      "egress capacity: %0.3f\n", flow_info->utility_type_.c_str(),
      flow_info->five_tuple_.str_.c_str(), avail_capacity, total_capacity);

    // Determine if the flow is inelastic. Only inelastic flows can be triaged.
    // LOG utility is the only elastic utility that is currently supported.
    if (flow_info->utility_type_.compare("LOG") == 0)
    {
      if (IsLowVolFlow(flow_info->adm_rate_,
                       p1_log_send_rate[bin]*flow_info->priority_,
                       original_capacity))
      {
        low_vol_elastic_traf_bps[bin] += flow_info->adm_rate_;
        LogD(kClassName, __func__,
             "Low volume flow with rate %f\n", flow_info->adm_rate_);
      }
      else
      {
        tot_elastic_priority[bin] += flow_info->priority_;
      }
    }
    else
    {
      // If it is not a LOG flow (elastic), it is either an
      // inelastic flow (TRAP or  STRAP) or a coupled flow.
      // Either of these can be triaged as a result of the following checks.

      // If there is not enough capacity for an inelastic flow
      // it should be triaged (unless it is later set as a probe).
      uint32_t flow_rate = flow_info->nominal_rate_bps_;
      if (flow_rate > avail_capacity)
      {
        set_flow_off = true;
        LogW(kClassName, __func__, "%s:%s OFF: Insufficient capacity.\n",
             flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());
      }

      // Check the egress capacity, which is an upper bound.
      if (flow_info->nominal_rate_bps_ > total_capacity)
      {
        set_flow_off = true;
        can_probe    = false;
        LogW(kClassName, __func__, "%s:%s OFF: Insufficient egr. capacity.\n",
             flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());
      }

      // If admitting this will result in it thrashing due to high queues,
      // it should be turned off. This flow my be set as a probe later on,
      // and in this case it would not be turned off even if it may thrash.
      // Note that this uses the egress capacity and not the estimate per
      // bin. This approach allows the estimate to grow faster when there is
      // an increase in capacity.
      double   elastic_queue = 0;
      if (!set_flow_off)
      {
        elastic_queue = ComputeElasticQueue(
          tot_elastic_priority[bin] + flow_info->sum_elastic_priority_,
          total_capacity - flow_rate - low_vol_elastic_traf_bps[bin]);

        double inelastic_queue_max =
          ComputeInelasticMaxQueue(flow_info->priority_, flow_rate);

        double queue_limit = inelastic_queue_limit[bin] < inelastic_queue_max ?
          inelastic_queue_limit[bin] : inelastic_queue_max;

        LogW(kClassName, __func__, "If we admit, elastic queue: %f, "
          "max trap queue without thrashing: %f.\n", elastic_queue, queue_limit);

        if (elastic_queue > queue_limit)
        {
          set_flow_off = true;
          LogW(kClassName, __func__,
            "%s:%s OFF: It will thrash due to elastic traffic.\n",
            flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());
        }
        else if (queue_limit < inelastic_queue_limit[bin])
        {
          // We now have a lower threshold for an admitted ineleastic flow
          // to step down.
          inelastic_queue_limit[bin] = queue_limit;
        }
      }

      // If it is a coupled flows, update the cumulative_elastic_priority.
      if (!set_flow_off && (flow_info->coupled_flows_ != NULL))
      {
        tot_elastic_priority[bin] += flow_info->sum_elastic_priority_;
      }

      // Update the bandwidth available for other flows.
      if (!set_flow_off && (flow_info->flow_state_ != FLOW_OFF))
      {
        total_capacity        -= flow_info->nominal_rate_bps_;
        tot_adm_rate_bps[bin] -= flow_info->nominal_rate_bps_;
      }

      if (flow_info->is_loss_triaged_)
      {
        // This will be taken care off in loss probing.
        continue;
      }
    }

    // Finished checking all the requirements for admitting a flow.
    // If the flow is set to off, check if it should be the probe and
    // send messages to the proxies to turn toggle flow state as needed.
    if (set_flow_off)
    {
      // If there is not already a probe, allow this flow to be the probe
      // even though it may thrash. Probes are only allowed if they can fit
      // in a remaining egress capacity, as this is a better upper-bound than
      // the per-bin bottleneck capacity estimates. We do not allow probing
      // if the queues are building.
      LogW(kClassName, __func__, "Checking probe: %u\n", max_toggle_on[bin]);
      if (amp_.IsQueueNonIncreasing(bin))
      {
        LogA(kClassName, __func__, "Queue is non-increasing\n");
      }

      if ((max_toggle_on[bin] > 0) &&
          amp_.IsQueueNonIncreasing(bin) &&
          (num_thrash_flows[bin] == 0) && can_probe)
      {
        if (flow_info->flow_state_ == FLOW_OFF)
        {
          has_changed          = true;
          ++num_flows_toggled_on_[bin];
          TurnFlowOn(*flow_info);
          amp_.ResetMaxQueueDepth(bin);
        }

        LogA(kClassName, __func__, "%s:%s (probe) should toggle OFF->ON.\n",
             flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());

        total_capacity        -= flow_info->nominal_rate_bps_;
        tot_adm_rate_bps[bin] -= std::max(0.0, flow_info->nominal_rate_bps_);
        --(max_toggle_on[bin]);
      }
      else if ((flow_info->flow_state_ != FLOW_OFF) &&
               ((num_thrash_flows[bin] > 1) || !can_probe))
      {
        TurnFlowOff(*flow_info);
        flow_info->flow_state_ = FLOW_OFF;
        has_changed            = true;

        LogD(kClassName, __func__, "%s:%s should toggle ON->OFF.\n",
             flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());
      }
    }
    else if((flow_info->flow_state_ == FLOW_OFF) && 
            (num_thrash_flows[bin] == 0) &&
            amp_.IsQueueNonIncreasing(bin))
    {
      has_changed           = true;
      max_toggle_on[bin]    = std::max(0, max_toggle_on[bin] - 1);
      total_capacity        = total_capacity - flow_info->nominal_rate_bps_;
      tot_adm_rate_bps[bin] = tot_adm_rate_bps[bin] - 
                              flow_info->nominal_rate_bps_;
      TurnFlowOn(*flow_info);
      ++num_flows_toggled_on_[bin];
      amp_.ResetMaxQueueDepth(bin);
      LogD(kClassName, __func__, "%s:%s should toggle OFF->ON.\n",
          flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());
    }
    else if ((flow_info->flow_state_ == FLOW_TRIAGED) &&
             (num_thrash_flows[bin] > 1))
    {
      TurnFlowOn(*flow_info);
      LogD(kClassName, __func__, "%s:%s should toggle TRIAGED->ON.\n",
          flow_info->proxy_.c_str(), flow_info->four_tuple_.c_str());
    }
  }

  if (flow_to_delete != "")
  {
    DeleteFlowInfo(flow_to_delete);
    flow_to_delete = "";
  }

  if (amp_.enable_thrash_triage())
  {
    has_changed |= CalibrateLossProbes(total_capacity);
  }

  return has_changed;
}

//=============================================================================
void Svcr::TurnFlowOn(FlowInfo& flow_info)
{
  amp_.TurnFlowOn(flow_info);
}

//=============================================================================
void Svcr::TurnFlowOff(FlowInfo& flow_info)
{
  amp_.TurnFlowOff(flow_info);
}

//=============================================================================
FlowInfo* Svcr::FindFlowInfo(::std::string& five_tuple)
{
  FlowInfo* flow_info = NULL;
  FiveTuple ft        = FiveTuple(five_tuple);
  flow_info_table_.Find(five_tuple, flow_info);
  return flow_info;
}

//=============================================================================
void Svcr::PrintAllFlowInfo()
{
  OrderedMashTable<FiveTuple, FlowInfo*, double>::WalkState ws;
  FlowInfo*   flow_info     = NULL;

  while (flow_info_table_.GetNextItem(ws, flow_info))
  {
    if (!flow_info)
    {
      LogE(kClassName, __func__, "Flow info is NULL.\n");
      return;
    }

    flow_info->Print();
  }
}

//=============================================================================
bool Svcr::AddFlowCoupling(list<string>& five_tuple_list)
{
  // When we receive information about a set of coupled  flows,
  // we do the following:
  // 1. Create a new FlowInfo object representing this set of coupled flows.
  // 2. Create a LinkedList within the new FlowInfo that points to the
  //    FlowInfo for each individual flow.
  // 3. Point back to the aggregate FlowInfo from each individual
  //    FlowInfo using the aggregated_flow_ field.
  // 4. Set the priority for the new aggregate FlowInfo to the max priority
  //     of all coupled flow (and accordingly set the normalized utility).

  if (five_tuple_list.empty())
  {
    LogA(kClassName, __func__, "List of flows to couple is empty\n");
    return true;
  }

  // Allocate the flow info for the coupled flows. If this were to
  // fail, it's better that it fails before we start moving flows
  // around.
  FlowInfo* aggregated_flows = new (std::nothrow) FlowInfo();
  if (!aggregated_flows)
  {
    LogF(kClassName, __func__, "Failed to allocate flow info.\n");
    return false;
  }

  Time now = Time::Now();
  aggregated_flows->last_update_time_ = now;

  List<FlowInfo*>*  coupled_flows = new (std::nothrow) List<FlowInfo*>();

  if (!coupled_flows)
  {
    LogF(kClassName, __func__,
         "Failed to allocate linked list for coupled flows.");
    return false;
  }
  uint32_t max_p                = 0;
  double   sum_bw               = 0;
  uint32_t sum_elastic_priority = 0;
  size_t   min_hash             = std::numeric_limits<size_t>::max();
  string   min_four_tuple       = "";

  while (!five_tuple_list.empty())
  {
    FiveTuple ft              = FiveTuple(five_tuple_list.front());
    FlowInfo* flow_to_couple  = NULL;

    if (!flow_info_table_.Find(ft, flow_to_couple))
    {
      // TODO: Handle this better depending on how we learn about
      // coupled flows.
      LogF(kClassName, __func__, "Cannot couple unknown flow: %s .\n",
           five_tuple_list.front().c_str());
      return false;
    }

    // The aggregate flow inherits the four-tuple with the smallest
    // hash value. This is to prevent duplicate reporting of a coupling
    // from resulting in two aggregate flows with different names
    // (five-tuples).
    size_t hash = ft.Hash();
    if (hash < min_hash)
    {
      min_hash       = hash;
      min_four_tuple = flow_to_couple->four_tuple_;
    }

    coupled_flows->Push(flow_to_couple);
    flow_to_couple->aggregate_flow_ = aggregated_flows;
    five_tuple_list.pop_front();

    max_p     = max_p > flow_to_couple->priority_ ?
                max_p : flow_to_couple->priority_;
    if ((flow_to_couple->utility_type_.compare("TRAP") == 0) ||
        (flow_to_couple->utility_type_.compare("STRAP") == 0))
    {
      sum_bw   += flow_to_couple->nominal_rate_bps_;
    }
    else if (flow_to_couple->utility_type_.compare("LOG") == 0)
    {
      sum_elastic_priority += flow_to_couple->priority_;
    }
  }

  LogD(kClassName, __func__, "Aggregated flow 4-tuple: %s\n",
    min_four_tuple.c_str());
  aggregated_flows->five_tuple_ =
    FiveTuple(kCoupledProxy + ";" + min_four_tuple);
  aggregated_flows->four_tuple_ = min_four_tuple;
  aggregated_flows->utility_type_ = kCoupledProxy;
  aggregated_flows->nominal_rate_bps_ = sum_bw;
  if (sum_bw != 0)
  {
    aggregated_flows->normalized_utility_ = max_p/sum_bw;
  }
  else
  {
    aggregated_flows->normalized_utility_ = max_p;
  }
  aggregated_flows->priority_ = max_p;
  aggregated_flows->coupled_flows_ = coupled_flows;
  aggregated_flows->sum_elastic_priority_ = sum_elastic_priority;
  aggregated_flows->proxy_ = kCoupledProxy;

  if (!flow_info_table_.OrderedInsert(aggregated_flows->five_tuple_,
    aggregated_flows, aggregated_flows->normalized_utility_))
  {
    // This can only fail if memory allocation failed in the internal
    // structures.
    delete aggregated_flows;
    LogF(kClassName, __func__, "Failed insertion of coupled-flow"
         " into flow info table.\n");
    return false;
  }
  return true;
}

//=============================================================================
uint32_t  Svcr::GetConstrainedBw(BinId dest, uint32_t deadline) const
{
  if (latency_cache_[dest].size() == 0)
  {
    LogW(kClassName, __func__, "No latency information available.\n");
    return std::numeric_limits<uint32_t>::max();
  }
  uint32_t viable_bw = 0;
  std::map<string, LinkChar>::const_iterator  iter;
  for (iter = latency_cache_[dest].begin(); iter != latency_cache_[dest].end();
     ++iter)
  {
    if (iter->second.latency < deadline)
    {
      viable_bw += iter->second.capacity;
    }
  }

  return viable_bw;
}

//=============================================================================
void Svcr::UncoupleFlow(FlowInfo* flow_info)
{
  if (flow_info->aggregate_flow_ == NULL)
  {
    LogW(kClassName, __func__,
         "Attempt to uncouple flow %s that is not coupled.\n",
         flow_info->five_tuple_.str_.c_str());
    return;
  }

  FlowInfo* agg_flow = flow_info->aggregate_flow_;
  agg_flow->coupled_flows_->Remove(flow_info);

  // Update the aggregate_flow_ to which this flow belonged or
  // delete it if this was the only coupled flow in it.
  if (agg_flow->coupled_flows_->size() != 0)
  {
    LogD(kClassName, __func__, "Updating aggregate flow.\n");
    if ((flow_info->utility_type_ == "TRAP") ||
        (flow_info->utility_type_ == "STRAP"))
    {
      agg_flow->nominal_rate_bps_ -= flow_info->nominal_rate_bps_;

      if (agg_flow->nominal_rate_bps_ > 0)
      {
        agg_flow->normalized_utility_ =  agg_flow->priority_ /
                                         agg_flow->nominal_rate_bps_;
      }
      else
      {
        agg_flow->normalized_utility_ = agg_flow->priority_;
      }
    }
    else if (flow_info->utility_type_ == "LOG")
    {
      agg_flow->sum_elastic_priority_ -= flow_info->priority_;
    }
  }
  else
  {
    LogD(kClassName, __func__, "Deleting empty aggregate flow: %s.\n",
      agg_flow->five_tuple_.str_.c_str());
    flow_info_table_.FindAndRemove(agg_flow->five_tuple_, agg_flow);
    delete agg_flow;
  }
  flow_info->aggregate_flow_ = NULL;
}

//=============================================================================
double Svcr::ComputeElasticQueue(int cumulative_priority, double capacity)
{
  if (cumulative_priority == 0)
  {
    return 0;
  }
  else if (capacity <= 0)
  {
    return std::numeric_limits<double>::max();
  }
  return k_val_*cumulative_priority/static_cast<double>(capacity);
}

//=============================================================================
double Svcr::ComputeInelasticMaxQueue(int priority, double nominal_rate_bps)
{
  // TRAP and STRAP are the only inelastic utility functions that are
  // currently supported. If the queue exceeds
  // (k_val_*priority/nominal_rate_bps) for either of these, they would not
  // admit packets at the required rate.
  if (nominal_rate_bps < 0)
  {
    LogE(kClassName, __func__, "The nominal rate should be greater than 0.\n");
    return std::numeric_limits<double>::max();
  }
  else if (nominal_rate_bps == 0)
  {
    return std::numeric_limits<double>::max();
  }

  return k_val_*priority/nominal_rate_bps;
}
