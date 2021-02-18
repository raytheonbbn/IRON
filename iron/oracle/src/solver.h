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

#ifndef __Solver_HPP__
#define __Solver_HPP__

#include <map>
#include <string>
#include <cmath>
#include "BpNlp.h"
#include "IpTNLP.hpp"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "IpIpoptApplication.hpp"

using namespace Ipopt;
using namespace rapidjson;

class Solver
{
public:
  /** Default constructor */
  Solver();

  /** Default destructor */
  virtual ~Solver();

  virtual void SetTopology(Topology links, std::vector<int>reachable_nodes);

  virtual void SetMcastFlows(const FlowSpec_vec mcastFlowlist);

  virtual ApplicationReturnStatus Solve();
  
  virtual void GetSolution(std::vector<double> &sol);

private:

  SmartPtr<BpNlp> bpnlp_;
  SmartPtr<IpoptApplication> nlp_solver_;

  Topology internal_links_;
  std::map<int, int> bin_id_to_internal_id_;
  std::map<int, int> internal_node_to_bin_id_;

  int num_nodes_;
  int num_flows_;

  bool have_topology_;
  bool have_petition_;

};
#endif
