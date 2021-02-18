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

#include "solver.h"

#include "config_info.h"
#include "iron_types.h"
#include "itime.h"
#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <cassert>
#include <iostream>
#include <vector>
#include <tuple>
#include <unordered_set>

using namespace Ipopt;

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

namespace
{
  const char* UNUSED(kClassName)          = "Solver";
}

// constructor
Solver::Solver()
{
  bpnlp_ = new BpNlp();
  nlp_solver_   = IpoptApplicationFactory();
  // Set options
  nlp_solver_->Options()->SetNumericValue("tol", 1e-7);
  nlp_solver_->Options()->SetStringValue("mu_strategy", "adaptive");
  nlp_solver_->Options()->SetStringValue("output_file", "ipopt.out");
  nlp_solver_->Options()->SetIntegerValue("print_level", 0);
  nlp_solver_->Options()->SetStringValue("sb", "yes");
  //  nlp_solver_->Options()->SetStringValue("derivative_test", "second-order");
  have_topology_ = false;
  have_petition_ = false;
}

// destructor
Solver::~Solver()
{ }

// This method creates:
// bin_id_to_internal_id_ map. Maps binIds to a set of numbers used internally by BpNlp.
// Internal numbers are sequential starting at 0 and running to N-1 where N is the number of
//   reachable nodes. internal_node_to_bin_id_ map is the reverse map from above.
// The internal_links_ vector. Vector of tuples of form (src_node, dst_node, capacity) using
//   internal node Ids.

void Solver::SetTopology(Topology links, std::vector<int> reachable_nodes)
{
  // Renumber reachable nodes
  num_nodes_ = reachable_nodes.size();
  int* new_nums = new int[num_nodes_];
  std::fill_n(new_nums,num_nodes_,0);

  bin_id_to_internal_id_.clear();
  internal_node_to_bin_id_.clear();
  
  for (int i = 0; i < num_nodes_; i++)
    {
      bin_id_to_internal_id_[reachable_nodes[i]] = i;
      internal_node_to_bin_id_[i] = reachable_nodes[i];
      LogD(kClassName, __func__, "binId = %i, internalNode = %i\n", reachable_nodes[i], i);
    }
 
  // Now renumber endpoints of links
  internal_links_ = links;
  for (uint i = 0; i < internal_links_.size(); i++){
    internal_links_[i].src = bin_id_to_internal_id_[links[i].src];
    internal_links_[i].dst = bin_id_to_internal_id_[links[i].dst];
  }
  
  for (uint i = 0; i < internal_links_.size(); i++){
    LogD(kClassName, __func__, "%i -> %i: %f, %f\n", internal_links_[i].src,
	 internal_links_[i].dst, internal_links_[i].capacity, internal_links_[i].latency);
  }

  bpnlp_->initialize_topology(num_nodes_, internal_links_);
  have_topology_ = true;

}

void Solver::GetSolution(std::vector<double> &s)
{
  s = Solver::bpnlp_->get_solution();
}

void Solver::SetMcastFlows(const FlowSpec_vec mcastFlow_vec)
{
  // Translate from binIds to internalNode numbers
  // format of vector is
  //  [[srcBinId1, [dstBinId_11, dstBinId_12, ... dstBinId_1X],
  //    priority, lowRate, hiRate,
  //    [array of prohibited links]],
  //   ...

  FlowSpec_vec mcast_flows;

  num_flows_ = mcastFlow_vec.size();

  for (int i = 0; i < num_flows_; i++)
    {
      std::vector<int> internalDstList;
      int srcInternalNode = bin_id_to_internal_id_[mcastFlow_vec[i].src];
      
      std::vector<int> dstBinId_vec = mcastFlow_vec[i].dsts;
      for (uint j = 0; j < dstBinId_vec.size(); j++)
	{
	  internalDstList.push_back(bin_id_to_internal_id_[dstBinId_vec[j]]);
	}
      std::vector<int> prohibLinkIndex;
      prohibLinkIndex.clear();
      Topology prohibLinks = mcastFlow_vec[i].prohibLinks;
      for (uint j = 0; j < prohibLinks.size(); j++)
	{
	  int prohibSrc = bin_id_to_internal_id_[prohibLinks[j].src];
	  int prohibDst = bin_id_to_internal_id_[prohibLinks[j].dst];
	  for (uint k = 0; k < internal_links_.size(); k++)
	    {
	      if ((prohibSrc == internal_links_[k].src) &&
		  (prohibDst == internal_links_[k].dst))
		{
		  prohibLinkIndex.push_back(k);
		  break;
		}
	    }
	}
      FlowSpec mcast_flow;
      mcast_flow.src = srcInternalNode;
      mcast_flow.dsts = internalDstList;
      mcast_flow.pri = mcastFlow_vec[i].pri;
      mcast_flow.loRate = mcastFlow_vec[i].loRate;
      mcast_flow.hiRate = mcastFlow_vec[i].hiRate;
      mcast_flow.prohibIndices = prohibLinkIndex;
      mcast_flows.push_back(mcast_flow);
    }
  
  bpnlp_->set_mcast_flows(mcast_flows);
  have_petition_ = true;
}

ApplicationReturnStatus Solver::Solve()
{
  // Initialize the IpoptApplication and process the options
  if ((!have_topology_) ||(!have_petition_))
    {
      LogE(kClassName,__func__,"Need to specify topology and petition before solving problem\n");
      return Invalid_Problem_Definition;
    }
  ApplicationReturnStatus status;
  status = nlp_solver_->Initialize();

  if( status != Solve_Succeeded )
    {
      LogD(kClassName, __func__, "**** Error during initialization ****\n");
    }

  status = nlp_solver_->OptimizeTNLP(bpnlp_);
  if( (status == Solve_Succeeded) || (status == Solved_To_Acceptable_Level) )
    {
      if (status == Solved_To_Acceptable_Level)
	{
	  LogD(kClassName, __func__, "Caution: Only Solved to acceptable level\n");
	}
    }
  else if (status == Infeasible_Problem_Detected)
    {
      LogD(kClassName, __func__, "Infeasible Problem\n");
    }
  else
    {
      LogD(kClassName, __func__, "*** Problem FAILED ***");
    }
  have_petition_ = false;

  return status;
}

