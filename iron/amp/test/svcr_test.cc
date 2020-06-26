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

#include <cppunit/extensions/HelperMacros.h>

#include "iron_constants.h"
#include "itime.h"
#include "amp.h"
#include "log.h"
#include "timer.h"
#include "svcr.h"

#include <string>
#include <cstdio>

using ::std::string;
using ::iron::ConfigInfo;
using ::iron::Time;
namespace iron
{

const char*  kCn = "SvcrTester";

// A child class of Amp for testing Amp.

class SvcrTester : public Svcr
{
public:
  /// Default constructor for SvcrTester.
  SvcrTester(const uint64_t& k_val, Amp& amp);

  virtual ~SvcrTester();

  /// \brief  Get the number of FlowInfo objects in the cache.
  /// \return The number of FlowInfo objects in flow_info_table_.
  size_t NumFlowInfo()
  {
    return flow_info_table_.size();
  }

  /// \brief A wrapper for AMP's DeleteFlow method.
  /// \param five_tuple The five tuple of the flow to be deleted.
  void DelFlowInfo(const string& five_tuple)
  {
    DeleteFlowInfo(five_tuple);
  }

  /// \brief Turn on a flow.
  /// \param flow_info A pointer to the FlowInfo to set to the ON state.
  void TurnFlowOn(FlowInfo& flow_info)
  {
    flow_info.flow_state_     = FLOW_ON;
  }

  /// \brief Turn on a flow.
  /// \param flow_info A pointer to the FlowInfo to set to the OFF state.
  void TurnFlowOff(FlowInfo& flow_info)
  {
    flow_info.flow_state_     = FLOW_OFF;
  }

  /// \brief A wrapper for AMP's AddFlowCoupling method.
  /// \param five_tuple_list A list of five-tuples indicating the flows
  ///                        which are to be coupled.
  void CoupleFlows(std::list<string>& five_tuple_list)
  {
    AddFlowCoupling(five_tuple_list);
  }

  /// \brief A wrapper for AMP's UncoupleFlow method.
  /// \param flow_info A pointer to the FlowInfo object to be uncoupled.
  void UncpleFlow(FlowInfo* flow_info)
  {
    return UncoupleFlow(flow_info);
  }

  /// \brief A wrapper for AMP's FindFlowInfo method.
  /// \param five_tuple The five-tuple for the flow.
  /// \param order      The normalized utility of the flow.
  /// \param ws         A reference to a WalkState object to be set
  ///                   on return.
  FlowInfo* FindFlwInfo(const std::string& five_tuple)
  {
    FlowInfo * flow = NULL;
    flow_info_table_.Find(FiveTuple(five_tuple), flow);
    return flow;
  }

  /// \brief  Add a flow to the list of flows.
  ///
  /// \param  flow_four_tuple The four tuple identifying a flow.
  ///
  /// \param  priority  The priority of the flow.
  ///
  /// \param  rate  The rate of the flow in bps.
  ///
  /// \param  state The state of the flow: on, off or triaged.
  /// \return A pointer to the FlowInfo onject created.
  FlowInfo* AddFlow(string flow_four_tuple, int priority,
                     double rate_bps, string utility_type,
                     FlowState state);


  /// \brief  Find all the flows that would fit in aggregate capacity in bps.
  ///
  /// \param  total_capacity_bps  The aggregate capacity for which we need to
  ///                             fit a number of flows.
  ///
  /// \return False if there is nothing to do, true otherwise.
  bool FindFit(double total_capacity);

  /// \brief  Toggle flows on and off to maximize utility.
  ///
  /// \param  The aggregate outbound capacity in bps.
  //void Triage(double capacity_bps);

}; // class SvcrTester

//============================================================================
SvcrTester::SvcrTester(const uint64_t& k_val, Amp& amp)
  : Svcr(k_val, amp)
{
}

//============================================================================
SvcrTester::~SvcrTester()
{
}

//============================================================================
FlowInfo* SvcrTester::AddFlow(std::string flow_four_tuple, int priority,
                   double rate, string utility_type, FlowState state)
{
  LogD(kCn, __func__,
       "Adding flow %s with priority %d and rate %0.3fbps.\n",
       flow_four_tuple.c_str(), priority, rate);

    double  order = priority;
    if (utility_type == "TRAP" || utility_type == "STRAP")
    {
      order = static_cast<double>(order) / rate;
    }
    LogD(kCn, __func__,"order: %0.3f\n", order);

    Time now                = Time::Now();
    FlowInfo* fi            = new FlowInfo();
    fi->five_tuple_         = FiveTuple("udp_proxy;" + flow_four_tuple);
    fi->four_tuple_         = flow_four_tuple;
    fi->utility_type_       = utility_type;
    fi->priority_           = priority;
    fi->proxy_              = "udp_proxy";
    fi->nominal_rate_bps_   = rate;
    fi->flow_state_         = state;
    fi->normalized_utility_ = order;
    fi->adm_rate_           = rate;
    fi->last_update_time_   = now;
    fi->bin_id_             = 1;
    CPPUNIT_ASSERT(flow_info_table_.OrderedInsert(fi->five_tuple_, fi,
      fi->normalized_utility_));

    return fi;
}

//============================================================================
bool SvcrTester::FindFit(double total_capacity)
{
  return ComputeFit(total_capacity);
}

//============================================================================
class SCtlTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE(SCtlTest);

  CPPUNIT_TEST(testConstructor);
  CPPUNIT_TEST(testUpdateFlowInfo);
  CPPUNIT_TEST(testComputeFit);
  CPPUNIT_TEST(testCoupledFlows);
  CPPUNIT_TEST(testFlowInfoRemoval);
  CPPUNIT_TEST(testPriorityChange);

  CPPUNIT_TEST_SUITE_END();

private:
  uint64_t     k_val_;
  SvcrTester*  s_ctl_;
  Amp*         amp_;
  Timer*       timer_;
  char         filename_[32];


public:

  //==========================================================================
  void setUp()
  {
    Log::SetDefaultLevel("F");
    k_val_ = kDefaultK;

    timer_  = new (std::nothrow) Timer();
    CPPUNIT_ASSERT(timer_);

    // Create a temp config file
    memset(filename_,0,sizeof(filename_));
    strncpy(filename_,"/tmp/ampcfg-XXXXXX",18);
    int fd = mkstemp(filename_);
    if (fd == -1)
    {
      LogF(kCn, __func__, "Unable to create temp file\n", filename_);
    }

    amp_   = new (std::nothrow) Amp(*timer_, filename_);
    CPPUNIT_ASSERT(amp_);
    s_ctl_ = new (std::nothrow) SvcrTester(k_val_, *amp_);
    CPPUNIT_ASSERT(s_ctl_);
    k_val_ = 100000000000;
  }

  //==========================================================================
  void tearDown()
  {
    delete s_ctl_;
    delete amp_;
    delete timer_;
    Log::SetDefaultLevel("F");
  }

  //==========================================================================
  void testConstructor()
  {
    // Check that there are no FlowInfo objects in flow_info_table_.
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 0);
  }

  //==========================================================================
  void testUpdateFlowInfo()
  {
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 0);
    ConfigInfo ci;
    ci.Add("priority", "2");
    ci.Add("nominal_rate_bps", "1000");
    ci.Add("four_tuple","1:1 -> 2:1");
    ci.Add("five_tuple","udp_proxy;1:1 -> 2:1");
    ci.Add("proxy","udp_proxy");
    ci.Add("utility_fn", "my_utility");
    ci.Add("type", "STRAP");
    ci.Add("adm_rate", "10000");
    ci.Add("utility", "2");
    ci.Add("flow_state","0");

    s_ctl_->UpdateFlowInfo(ci);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 1);

    FlowInfo* fi = s_ctl_->FindFlwInfo("udp_proxy;1:1 -> 2:1");

    CPPUNIT_ASSERT(fi != NULL);
    CPPUNIT_ASSERT(fi->priority_ == 2);
    CPPUNIT_ASSERT(fi->adm_rate_ == 10000);
    CPPUNIT_ASSERT(fi->utility_ == 2);

    ci.Add("priority", "3");
    ci.Add("nominal_rate_bps", "2000");
    ci.Add("four_tuple","1:2 -> 2:2");
    ci.Add("five_tuple","udp_proxy;1:2 -> 2:2");
    s_ctl_->UpdateFlowInfo(ci);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 2);

    fi = s_ctl_->FindFlwInfo("udp_proxy;1:2 -> 2:2");

    CPPUNIT_ASSERT(fi != NULL);
    CPPUNIT_ASSERT(fi->priority_ == 3);

    ci.Add("adm_rate", "20000");
    ci.Add("utility", "3");

    s_ctl_->UpdateFlowInfo(ci);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 2);
    CPPUNIT_ASSERT(fi->adm_rate_ == 10000*0.8 + 20000*0.2);
    CPPUNIT_ASSERT(fi->utility_ == 2*0.8 + 3*0.2);
  }

  //==========================================================================
  void testComputeFit()
  {
    s_ctl_->FindFit(11000.);


    FlowInfo* f1 = s_ctl_->AddFlow("1:1 -> 2:1", 11, 900000., "STRAP", FLOW_ON);
    FlowInfo* f2 = s_ctl_->AddFlow("1:2 -> 2:2", 1, 1000000., "STRAP", FLOW_ON);
    // Both flows should fit in 20000 bps
    CPPUNIT_ASSERT(!s_ctl_->FindFit(2000000.));
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 2);
    CPPUNIT_ASSERT(f1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f2->flow_state_ == FLOW_ON);

    // Only Flow one will fit if the capacity is 11000 bps.
    CPPUNIT_ASSERT(s_ctl_->FindFit(1100000.));
    CPPUNIT_ASSERT(f1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f2->flow_state_ == FLOW_OFF);

    // If the capacity goes back on, we should toggle on Flow2.
    CPPUNIT_ASSERT(s_ctl_->FindFit(2000000.));
    CPPUNIT_ASSERT(f1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f2->flow_state_ == FLOW_ON);

    FlowInfo* f3 = s_ctl_->AddFlow("1:3 -> 2:3", 10., 1100000., "STRAP", FLOW_OFF);
    FlowInfo* f4 = s_ctl_->AddFlow("1:4 -> 2:4", 10., 1000000., "STRAP", FLOW_OFF);
    FlowInfo* f5 = s_ctl_->AddFlow("1:5 -> 2:5", 11., 1000000., "STRAP", FLOW_OFF);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 5);
    s_ctl_->FindFit(1100000.);
    // Only Flow1 fits, it has highest p/m
    CPPUNIT_ASSERT(f1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f2->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f3->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f4->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f5->flow_state_ == FLOW_OFF);

    FlowInfo* f6 = s_ctl_->AddFlow("1:6 -> 2:6", 11., 10000., "STRAP", FLOW_OFF);
    FlowInfo* f7 = s_ctl_->AddFlow("1:7 -> 2:7", 1., 50000., "STRAP", FLOW_OFF);
    FlowInfo* f8 = s_ctl_->AddFlow("1:8 -> 2:8", 1., 8000., "STRAP", FLOW_OFF);
    FlowInfo* f9 = s_ctl_->AddFlow("1:9 -> 2:9", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* f10 = s_ctl_->AddFlow("1:10 -> 2:10", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* f11 = s_ctl_->AddFlow("1:11 -> 2:11", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* f12 = s_ctl_->AddFlow("1:12 -> 2:12", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* f13 = s_ctl_->AddFlow("1:13 -> 2:13", 1., 1000000., "LOG", FLOW_ON);
    FlowInfo* f14 = s_ctl_->AddFlow("1:14 -> 2:14", 1., 1000000., "LOG", FLOW_ON);
    //FlowInfo* f14 = s_ctl_->AddFlow("1:14 -> 2:14", 1., 559000., "LOG", FLOW_ON);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);
    CPPUNIT_ASSERT(f6->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f7->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f8->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f9->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f10->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f11->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f12->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f13->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f14->flow_state_ == FLOW_ON);

    s_ctl_->FindFit(1999000.);

    // Flows that should be on: 6-14,1
    // Already on: 1,9,10,11,12,13,14
    // Need to turn on: 6,7,8
    CPPUNIT_ASSERT(f6->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f7->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f8->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f9->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f10->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f11->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f12->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f13->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f14->flow_state_ == FLOW_ON);

    // Test impact of elastic traffic
    // The flows that are currently on use 11080 Mbps.
    FlowInfo* f15 = s_ctl_->AddFlow("1:15 -> 2:15", 5., 600000., "STRAP", FLOW_OFF);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 15);
    //The above flow should fit.
    s_ctl_->FindFit(2000000.);
    CPPUNIT_ASSERT(f15->flow_state_ == FLOW_ON);
    FlowInfo* f16 = s_ctl_->AddFlow("1:16 -> 2:16", 1., 350000., "STRAP", FLOW_OFF);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 16);
    // There should be enough BW for the flow, if the total is 20000, but
    // there will not be enough room for the elastic traffic, but it can
    // act as a probe.
    s_ctl_->FindFit(2000000.);
    CPPUNIT_ASSERT(f16->flow_state_ == FLOW_ON);

    // If we remove the elastic flows, then flow 16 should fit in the 20,000
    s_ctl_->DelFlowInfo("udp_proxy;1:13 -> 2:13");
    s_ctl_->DelFlowInfo("udp_proxy;1:14 -> 2:14");
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);
    s_ctl_->FindFit(2000000.);
    CPPUNIT_ASSERT(f16->flow_state_ == FLOW_ON);
  }

  //==========================================================================
  void testCoupledFlows()
  {
    FlowInfo* flow1 = s_ctl_->AddFlow("1:1 -> 2:1", 10, 900000., "STRAP", FLOW_ON);
    FlowInfo* flow2 = s_ctl_->AddFlow("1:2 -> 2:2", 1, 1000000., "STRAP", FLOW_ON);
    FlowInfo* flow3 = s_ctl_->AddFlow("1:3 -> 2:3", 10., 1100000., "STRAP", FLOW_OFF);
    FlowInfo* flow4 = s_ctl_->AddFlow("1:4 -> 2:4", 10., 1000000., "STRAP", FLOW_OFF);
    FlowInfo* flow5 = s_ctl_->AddFlow("1:5 -> 2:5", 11., 1000000., "STRAP", FLOW_OFF);
    FlowInfo* flow6 = s_ctl_->AddFlow("1:6 -> 2:6", 11., 10000., "STRAP", FLOW_OFF);
    FlowInfo* flow7 = s_ctl_->AddFlow("1:7 -> 2:7", 1., 50000., "STRAP", FLOW_OFF);
    FlowInfo* flow8 = s_ctl_->AddFlow("1:8 -> 2:8", 1., 8000., "STRAP", FLOW_OFF);
    FlowInfo* flow9 = s_ctl_->AddFlow("1:9 -> 2:9", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* flow10 = s_ctl_->AddFlow("1:10 -> 2:10", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* flow11 = s_ctl_->AddFlow("1:11 -> 2:11", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* flow12 = s_ctl_->AddFlow("1:12 -> 2:12", 1., 10000., "STRAP", FLOW_ON);
    FlowInfo* flow13 = s_ctl_->AddFlow("1:13 -> 2:13", 1., 1000000., "LOG", FLOW_ON);
    FlowInfo* flow14 = s_ctl_->AddFlow("1:14 -> 2:14", 1., 1000000., "LOG", FLOW_ON);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);

    s_ctl_->FindFit(1200000.);

    // At this point,
    // on flows : 1, 6-14
    // off flows: 2-5
    CPPUNIT_ASSERT(flow1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow2->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow3->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow4->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow5->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(flow6->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow7->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow8->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow9->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow10->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow11->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow12->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow13->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow14->flow_state_ == FLOW_ON);

    std::list<std::string> five_tuple_list;
    five_tuple_list.push_back("udp_proxy;1:1 -> 2:1");
    five_tuple_list.push_back("udp_proxy;1:10 -> 2:10");
    five_tuple_list.push_back("udp_proxy;1:14 -> 2:14");

    FlowInfo* flow_info = s_ctl_->FindFlwInfo("COUPLED;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info == NULL);

    s_ctl_->CoupleFlows(five_tuple_list);
    // This will move the three flows out of flow_info_table_ into
    // a coupled_flows list, which will be inserted into flow_info_table_ .
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 15);

    // Verify that we can still find these flows even though they have
    // been moved.
    flow_info = s_ctl_->FindFlwInfo("udp_proxy;1:10 -> 2:10");
    CPPUNIT_ASSERT(flow_info != NULL);
    CPPUNIT_ASSERT(flow_info->priority_ == 1);

    // We should be able to find the coupled flow, which will inherit the
    // four tuple for the first flow in the coupling.
    flow_info = NULL;
    flow_info = s_ctl_->FindFlwInfo("COUPLED;1:10 -> 2:10");
    CPPUNIT_ASSERT(flow_info != NULL);

    // If we reduce the BW to 8000, the coupled flow will not longer fit.
    s_ctl_->FindFit(800000.);
    CPPUNIT_ASSERT(flow1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow10->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow14->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(flow10->aggregate_flow_ != NULL);

    // If the capacity goes up to 12000, we should turn on flow 5 since it
    // has slightling higher normailzed utility than the coupled flows.
    s_ctl_->FindFit(1200000.);
    CPPUNIT_ASSERT(flow5->flow_state_ == FLOW_ON);

    // If the capacity goes to 22000, then the coupled flows should turn on.
    s_ctl_->FindFit(2200000.);
    CPPUNIT_ASSERT(flow10->flow_state_ == FLOW_ON);
  }

  //==========================================================================
  void testFlowInfoRemoval()
  {
    s_ctl_->AddFlow("1:1 -> 2:1", 10, 9000., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:2 -> 2:2", 1, 10000., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:3 -> 2:3", 10., 11000., "STRAP", FLOW_OFF);
    s_ctl_->AddFlow("1:4 -> 2:4", 10., 10000., "STRAP", FLOW_OFF);
    s_ctl_->AddFlow("1:5 -> 2:5", 11., 10000., "STRAP", FLOW_OFF);
    s_ctl_->AddFlow("1:6 -> 2:6", 11., 100., "STRAP", FLOW_OFF);
    s_ctl_->AddFlow("1:7 -> 2:7", 1., 500., "STRAP", FLOW_OFF);
    s_ctl_->AddFlow("1:8 -> 2:8", 1., 80., "STRAP", FLOW_OFF);
    s_ctl_->AddFlow("1:9 -> 2:9", 1., 100., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:10 -> 2:10", 1., 100., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:11 -> 2:11", 1., 100., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:12 -> 2:12", 1., 100., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:13 -> 2:13", 1., 0., "LOG", FLOW_ON);
    s_ctl_->AddFlow("1:14 -> 2:14", 1., 0., "LOG", FLOW_ON);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);

    // Remove a non-coupled flow using DeleteFlowInfo
    s_ctl_->DelFlowInfo("udp_proxy;1:1 -> 2:1");
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 13);    
    List<FlowInfo*>::WalkState  ws;
    FlowInfo* flow_info = s_ctl_->FindFlwInfo("COUPLED;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info == NULL);

    // Add back the flow to flow_info_table_
    s_ctl_->AddFlow("1:1 -> 2:1", 10, 9000., "STRAP", FLOW_ON);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);
    flow_info = s_ctl_->FindFlwInfo("udp_proxy;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info != NULL);

    // Create a coupling
    std::list<std::string> five_tuple_list;
    five_tuple_list.push_back("udp_proxy;1:1 -> 2:1");
    five_tuple_list.push_back("udp_proxy;1:10 -> 2:10");
    five_tuple_list.push_back("udp_proxy;1:14 -> 2:14");

    flow_info = s_ctl_->FindFlwInfo("COUPLED;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info == NULL);
    s_ctl_->CoupleFlows(five_tuple_list);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 15);

    // Test UncoupleFlow
    FlowInfo* agg_flow_info = s_ctl_->FindFlwInfo("COUPLED;1:10 -> 2:10");
    CPPUNIT_ASSERT(agg_flow_info != NULL);
    CPPUNIT_ASSERT(agg_flow_info->coupled_flows_->size() == 3);
    CPPUNIT_ASSERT(agg_flow_info->nominal_rate_bps_ == 9100.0);
    CPPUNIT_ASSERT(agg_flow_info->sum_elastic_priority_ == 1);
    flow_info = s_ctl_->FindFlwInfo("udp_proxy;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info != NULL);
    s_ctl_->UncpleFlow(flow_info);

    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 15);
    // There should now be two coupled flows in the collection.
    CPPUNIT_ASSERT(agg_flow_info->coupled_flows_->size() == 2);

    // We just removed the flow_info from the coupling, not deleted it.
    CPPUNIT_ASSERT(flow_info->priority_ == 10);
    CPPUNIT_ASSERT(flow_info->aggregate_flow_ == NULL);

    // Check that we updated the aggregate flow.
    CPPUNIT_ASSERT(agg_flow_info->nominal_rate_bps_ == 100.0);

    CPPUNIT_ASSERT(agg_flow_info->sum_elastic_priority_ == 1);
    LogD(kCn, __func__, "nom rate: %f\n", agg_flow_info->normalized_utility_);

    CPPUNIT_ASSERT(agg_flow_info->normalized_utility_ == 0.1);

    // Test behavior when we remove a member of a coupled flow with
    // the 'DeleteFlowInfo' method.
    flow_info = s_ctl_->FindFlwInfo("udp_proxy;1:14 -> 2:14");
    CPPUNIT_ASSERT(flow_info != NULL);
    s_ctl_->DelFlowInfo("udp_proxy;1:14 -> 2:14");
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);

    // Check that we updated the aggregate flow info.
    CPPUNIT_ASSERT(agg_flow_info->nominal_rate_bps_ == 100.0);
    CPPUNIT_ASSERT(agg_flow_info->sum_elastic_priority_ == 0);
    CPPUNIT_ASSERT(agg_flow_info->normalized_utility_ == 0.1);

    // There should only be one flow in coupled_flows.
    CPPUNIT_ASSERT(agg_flow_info->coupled_flows_->size() == 1);
    CPPUNIT_ASSERT(!s_ctl_->FindFlwInfo("udp_proxy;1:14 -> 2:14"));

    // If we remove the last memeber of the coupled flow, we should delete
    // the aggregate flow object, since it would be empty.
    flow_info = s_ctl_->FindFlwInfo("udp_proxy;1:10 -> 2:10");
    CPPUNIT_ASSERT(flow_info != NULL);
    agg_flow_info = s_ctl_->FindFlwInfo("COUPLED;1:10 -> 2:10");
    CPPUNIT_ASSERT(agg_flow_info != NULL);
    s_ctl_->DelFlowInfo("udp_proxy;1:10 -> 2:10");
    CPPUNIT_ASSERT(!s_ctl_->FindFlwInfo("COUPLED;1:10 -> 2:10"));
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 12);

    // Add the flows back, couple them and then delete the aggregate flow.
    s_ctl_->AddFlow("1:10 -> 2:10", 1., 100., "STRAP", FLOW_ON);
    s_ctl_->AddFlow("1:14 -> 2:14", 1., 0., "LOG", FLOW_ON);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);
    CPPUNIT_ASSERT(s_ctl_->FindFlwInfo("udp_proxy;1:1 -> 2:1"));

    flow_info = s_ctl_->FindFlwInfo("COUPLED;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info == NULL);
    five_tuple_list.push_back("udp_proxy;1:1 -> 2:1");
    five_tuple_list.push_back("udp_proxy;1:10 -> 2:10");
    five_tuple_list.push_back("udp_proxy;1:14 -> 2:14");
    s_ctl_->CoupleFlows(five_tuple_list);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 15);
    flow_info = s_ctl_->FindFlwInfo("COUPLED;1:10 -> 2:10");
    CPPUNIT_ASSERT(flow_info != NULL);

    // We can find memebers of the coupled flows before removal.
    CPPUNIT_ASSERT(s_ctl_->FindFlwInfo("udp_proxy;1:1 -> 2:1"));

    s_ctl_->DelFlowInfo("COUPLED;1:10 -> 2:10");
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 14);

    // We should still be able to find members of the coupled flow if
    // we delete the aggregate flow.
    FlowInfo* flow_info3 = s_ctl_->FindFlwInfo("udp_proxy;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info3 != NULL);
    // But they should no longer point to an aggregated flow.
    CPPUNIT_ASSERT(flow_info3->aggregate_flow_ == NULL);

    flow_info3 = s_ctl_->FindFlwInfo("COUPLED;1:1 -> 2:1");
    CPPUNIT_ASSERT(flow_info3 == NULL);

  }

  //==========================================================================
  void testPriorityChange()
  {
    FlowInfo* f1 = s_ctl_->AddFlow("1:1 -> 2:1", 10, 500000., "STRAP", FLOW_ON);
    FlowInfo* f2 = s_ctl_->AddFlow("1:2 -> 2:2", 8, 500000., "STRAP", FLOW_ON);
    FlowInfo* f3 = s_ctl_->AddFlow("1:3 -> 2:3", 6., 500000., "STRAP", FLOW_OFF);
    FlowInfo* f4 = s_ctl_->AddFlow("1:4 -> 2:4", 5., 500000., "STRAP", FLOW_OFF);
    FlowInfo* f5 = s_ctl_->AddFlow("1:5 -> 2:5", 7., 500000., "STRAP", FLOW_OFF);
    FlowInfo* f6 = s_ctl_->AddFlow("1:6 -> 2:6", 9., 500000., "STRAP", FLOW_ON);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 6);

    std::list<FlowInfo*> toggle_on;
    std::list<FlowInfo*> toggle_off;
    // If the capacity is 20Mbps, then:
    // ON FLOWS: 1,2,5,6
    CPPUNIT_ASSERT(s_ctl_->FindFit(2000000.));
    CPPUNIT_ASSERT(f1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f2->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f3->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f4->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f5->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f6->flow_state_ == FLOW_ON);

    // If we change priorities without rearranging the linked list, then
    // compute fit will return the wrong answer: no changes.
    f6->priority_ = 2;
    CPPUNIT_ASSERT(!s_ctl_->FindFit(2000000.));

    // If we update via UpdateFlowInfo, flow 6 will be moved within
    // the linkedlist and ComputeFit will have the correct answer.
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 6);
    f6->priority_ = 9;
    ConfigInfo ci;
    ci.Add("priority", "2");
    ci.Add("nominal_rate_bps", "500000");
    ci.Add("four_tuple","1:6 -> 2:6");
    ci.Add("five_tuple","udp_proxy;1:6 -> 2:6");
    ci.Add("proxy","udp_proxy");
    ci.Add("utility_fn", "my_utility");
    ci.Add("type", "STRAP");
    ci.Add("adm_rate", "500000");
    ci.Add("src_rate", "500000");
    ci.Add("utility", "2");
    ci.Add("flow_state","2");
    ci.Add("normalized_utility","0.000004");

    s_ctl_->UpdateFlowInfo(ci);
    CPPUNIT_ASSERT(s_ctl_->NumFlowInfo() == 6);
    CPPUNIT_ASSERT(f6->priority_ == 2);
    CPPUNIT_ASSERT(s_ctl_->FindFit(2000000.));
    CPPUNIT_ASSERT(f1->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f2->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f3->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f4->flow_state_ == FLOW_OFF);
    CPPUNIT_ASSERT(f5->flow_state_ == FLOW_ON);
    CPPUNIT_ASSERT(f6->flow_state_ == FLOW_OFF);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(SCtlTest);

}
