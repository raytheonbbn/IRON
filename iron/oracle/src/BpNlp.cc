// Copyright (C) 2005, 2006 International Business Machines and others.
// All Rights Reserved.
// This code is published under the Eclipse Public License.
//
// Authors:  Carl Laird, Andreas Waechter     IBM    2005-08-16

#include "BpNlp.h"

#include <cassert>
//#include <iostream>
#include <vector>
#include <tuple>
#include <unordered_set>

using namespace Ipopt;

#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif

// constructor
BpNlp::BpNlp()
{ }

// destructor
BpNlp::~BpNlp()
{
  delete [] mcast_dsts_;
  delete [] cum_mcast_dsts_;
}

// [get_nlp_info]
// returns the size of the problem
bool BpNlp::get_nlp_info(
   Index&          n,
   Index&          m,
   Index&          nnz_jac_g,
   Index&          nnz_h_lag,
   IndexStyleEnum& index_style
)
{
  // Variables have following form
  // Lxlink_flows_for_flow1_dest1,..Lxlink_flows_for_flow1_destD_1, Lxmax_link_flows_for_flow1, rate_for_flow1,
  // Lxlink_flows_for_flow2_dest1,..Lxlink_flows_for_flow2_destD_2, Lxmax_link_flows_for_flow2, rate_for_flow2,
  // ...
  // Lxlink_flows_for_flowF_dest1,..Lxlink_flows_for_flowF_destD_F, Lxmax_link_flows_for_flowF, rate_for_flowF

  // Number of variables is one per link plus one for input/output for each flow

  n = num_mcast_dsts_ * num_links_ + num_flows_ * (num_links_ + 1);
  // Number of rows...
  m = num_mcast_dsts_ * (num_nodes_ + num_links_) + num_links_;
  // Jacobian is sparse with two non-zeros per variable for the node flow equality constraints
  // plus entries for max over flow destinations and capacity constraints
  
  nnz_jac_g = 2 * num_mcast_dsts_ * (2 * num_links_ + 1) + num_flows_ * num_links_;
  // the Hessian has only num_flows_ entries since constraints are linear
  // and objective is only a function of flows

  nnz_h_lag = num_flows_;

  // use the C style indexing (0-based)
  index_style = TNLP::C_STYLE;

  return true;
}
// [get_nlp_info]

// [get_bounds_info]
// returns the variable bounds
bool BpNlp::get_bounds_info(
   Index   n,
   Number* x_l,
   Number* x_u,
   Index   m,
   Number* g_l,
   Number* g_u
)
{
   // initialize the variables with lower bounds of 0 and upper bounds of infinity
   for( Index i = 0; i < n; i++ )
   {
      x_l[i] = 0.0;
      x_u[i] = 2e19;
   }

   // overwrite flow rate lower/upper bounds
   for (uint f = 0; f < mcast_flows_.size(); f++)
     {
       // Compute index into variable list for rate of flow f
       Index i = cum_mcast_dsts_[f+1]*num_links_ + f*(num_links_+1) + num_links_;
       x_l[i] = mcast_flows_[f].loRate;
       x_u[i] = mcast_flows_[f].hiRate;
     }

   // set upper bound to zero for links that cannot be used for a specific flow
   for (uint f = 0; f < mcast_flows_.size(); f++)
     {
       std::vector< int > prohibitedLinkIndex = mcast_flows_[f].prohibIndices;
       for (uint i = 0; i < prohibitedLinkIndex.size(); i++)
	 {
	   // Compute index into variable list for max flow over all destinations
	   Index j = cum_mcast_dsts_[f+1]*num_links_ + f*(num_links_+1) + prohibitedLinkIndex[i];
	   x_u[j] = 0.0;
	 }
     }

   // system equations

   int row_offset;
   int row_index;
   for ( Index flow = 0; flow < num_flows_; flow++ )
     {
       row_offset = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_);
       for ( Index r = 0; r < num_nodes_ * mcast_dsts_[flow]; r++ )
	 {
	   row_index = row_offset + r;
	   // the node flow equality constraints gi have equality to zero
	   g_l[row_index] = 0.0;
	   g_u[row_index] = 0.0;
	 }
       // equations to find max link flow over all destinations in this multicast flow
       row_offset = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + mcast_dsts_[flow] * num_nodes_;
       for ( Index r = 0; r < mcast_dsts_[flow] * num_links_; r++ )
	 {
	   row_index = row_offset + r;
	   g_l[row_index] = 0.0;
	   g_u[row_index] = 2e19;
	 }
     }
   // the sum of the link flows have upper bound of link capacity

   row_offset = cum_mcast_dsts_[num_flows_] * (num_links_ + num_nodes_);
   for ( Index r = 0; r < num_links_; r++ )
     {
       row_index = row_offset + r;
       g_l[row_index] = 0.0;
       g_u[row_index] = links_[r].capacity;
     }

   return true;
}
// [get_bounds_info]

// [get_starting_point]
// returns the initial point for the problem
bool BpNlp::get_starting_point(
   Index   n,
   bool    init_x,
   Number* x,
   bool    init_z,
   Number* z_L,
   Number* z_U,
   Index   m,
   bool    init_lambda,
   Number* lambda
)
{
   assert(init_x == true);
   assert(init_z == false);
   assert(init_lambda == false);

   // initialize starting point to one

   for (Index i = 0; i < n; i++ )
     {
       x[i] = 1.0;
     }

   return true;
}
// [get_starting_point]

// [eval_f]
// returns the value of the objective function
// objective function is -ln(eps + x[n-1])
bool BpNlp::eval_f(
   Index         n,
   const Number* x,
   bool          new_x,
   Number&       obj_value
)
{
  // IpOpt wants to minimize, so need to flip sign of objective

  obj_value = 0.0;
  for (Index flow = 0; flow < num_flows_; flow++ )
    {
      double pri = mcast_flows_[flow].pri;
      int var_index = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
      float val     = -pri*log(1e-9+x[var_index]);
      obj_value    += val;
  }

  return true;
}
// [eval_f]

// [eval_grad_f]
// return the gradient of the objective function grad_{x} f(x)
bool BpNlp::eval_grad_f(
   Index         n,
   const Number* x,
   bool          new_x,
   Number*       grad_f
)
{
  // Everything is zero
  for (Index i = 0; i < n; i++)
    {
      grad_f[i] = 0.0;
    }

  // Except the flow rates
  for (Index flow = 0; flow < num_flows_; flow++ )
    {
      double pri = mcast_flows_[flow].pri;
      int var_index = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
      float val     = -pri/(1e-9+x[var_index]);
      grad_f[var_index] = val;
    }

   return true;
}
// [eval_grad_f]

// [eval_g]
// return the value of the constraints: g(x)
bool BpNlp::eval_g(
   Index         n,
   const Number* x,
   bool          new_x,
   Index         m,
   Number*       g
)
{
  // g(x) = G*x where G is an m x n matrix and x is vector of variables

  std::fill_n(g,m,0);
  
  int var_offset;
  int var_index;

  int row_offset;
  int row_index;
  
  int src_row_index;
  int dst_row_index;

  for (Index flow = 0; flow < num_flows_; flow++ )
    {
      // Equality constraints
      // Loop over destinations within multicast flow
      for (Index d = 0; d < mcast_dsts_[flow]; d++ )
	{
	  // Loop over links

	  for (Index link = 0; link < num_links_; link++ )
	    {
	      // Use cummulative number of destinations to simplify math...
	      var_index     = cum_mcast_dsts_[flow] * num_links_ + flow * (num_links_ + 1) + d * num_links_ + link;
	      // links[link] it tuple of (src_no, dst_no, capacity)
	      src_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + links_[link].src;
	      dst_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + links_[link].dst;
	      g[src_row_index] -= x[var_index]; // flow leaves link source node
	      g[dst_row_index] += x[var_index]; // flow arrives at link destination node
	    }
	  // Add/subtract multicast flow rates for each node conservation equation
	  int src                   = mcast_flows_[flow].src;
	  std::vector<int> dst_list = mcast_flows_[flow].dsts;
	  int dst                   = dst_list[d];
	  var_index     = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
	  src_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + src;
	  dst_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + dst;
	  g[dst_row_index] -= x[var_index]; // flow leaves destination node
	  g[src_row_index] += x[var_index]; // flow arrives at source node
	}

      // Set up equations to find max link flow over all destinations in a multicast flow
      int max_offset;
      for (Index d = 0; d < mcast_dsts_[flow]; d++ )
	{
	  row_offset = cum_mcast_dsts_[flow] * (num_links_ + num_nodes_) + mcast_dsts_[flow] * num_nodes_ + d * num_links_;
	  var_offset = cum_mcast_dsts_[flow] * num_links_ + flow * (num_links_ + 1) + d * num_links_;
	  max_offset = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1);
	  for (Index link = 0; link < num_links_; link++ )
	    {
	      // Max constraints
	      row_index = row_offset + link;
	      var_index = var_offset + link;
	      g[row_index] -= x[var_index]; // Subtract link flow
	      var_index     = max_offset + link;
	      g[row_index] += x[var_index]; // Add maximum flow
	    }
	}
      // Per link capacity constraints
      row_offset = cum_mcast_dsts_[num_flows_] * (num_links_ + num_nodes_);
      var_offset = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1); 
      for (Index link = 0; link < num_links_; link++ )
	{
	  row_index = row_offset + link;
	  var_index = var_offset + link;
	  g[row_index] += x[var_index];
	}
    }
  return true;
}
// [eval_g]

// [eval_jac_g]
// return the structure or values of the Jacobian
bool BpNlp::eval_jac_g(
   Index         n,
   const Number* x,
   bool          new_x,
   Index         m,
   Index         nele_jac,
   Index*        iRow,
   Index*        jCol,
   Number*       values
			     )
{
  int src_row_index;
  int dst_row_index;
  int row_offset;
  int row_index;
  int var_offset;
  int var_index;
  
  if( values == NULL )
    {
      // return the structure of the Jacobian

      int k = 0;

      for (Index flow = 0; flow < num_flows_; flow++ )
	{
	  // Equality constraints
	  // Loop over destinations within multicast flow
	  for (Index d = 0; d < mcast_dsts_[flow]; d++ )
	    {
	      // Loop over links

	      for (Index link = 0; link < num_links_; link++ )
		{
		  // Use cummulative number of destinations to simplify math...
		  var_index     = cum_mcast_dsts_[flow] * num_links_ + flow * (num_links_ + 1) + d * num_links_ + link;
		  // links[link] is tuple of (src_no, dst_no, capacity)
		  src_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + links_[link].src;
		  dst_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + links_[link].dst;
		  iRow[k] = src_row_index;
		  jCol[k] = var_index;
		  k++;
		  iRow[k] = dst_row_index;
		  jCol[k] = var_index;
		  k++;
		}
	      // Add/subtract multicast flow rates for each node conservation equation
	      int src                   = mcast_flows_[flow].src;
	      std::vector<int> dst_list = mcast_flows_[flow].dsts;
	      int dst                   = dst_list[d];
	      var_index     = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
	      src_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + src;
	      dst_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + dst;
	      iRow[k] = dst_row_index;
	      jCol[k] = var_index;
	      k++;
	      iRow[k] = src_row_index;
	      jCol[k] = var_index;
	      k++;
	    }
	  int max_offset;
	  // Equations to find max link flow over all destinations in a multicast flow
	  for (Index d = 0; d < mcast_dsts_[flow]; d++ )
	    {
	      row_offset = cum_mcast_dsts_[flow] * (num_links_ + num_nodes_) + mcast_dsts_[flow] * num_nodes_ + d * num_links_;
	      var_offset = cum_mcast_dsts_[flow] * num_links_ + flow * (num_links_ + 1) + d * num_links_;
	      max_offset = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1);
	      for (Index link = 0; link < num_links_; link++ )
		{
		  // Max constraints
		  row_index = row_offset + link;
		  var_index = var_offset + link;
		  iRow[k] = row_index;
		  jCol[k] = var_index;
		  k++;
		  var_index     = max_offset + link;
		  iRow[k] = row_index;
		  jCol[k] = var_index;
		  k++;
		}
	    }
	  // Per link capacity constraints
	  row_offset = cum_mcast_dsts_[num_flows_] * (num_links_ + num_nodes_);
	  var_offset = cum_mcast_dsts_[flow + 1] *num_links_ + flow * (num_links_ + 1); 
	  for (Index link = 0; link < num_links_; link++ )
	    {
	      row_index = row_offset + link;
	      var_index = var_offset + link;
	      iRow[k] = row_index;
	      jCol[k] = var_index;
	      k++;
	    }
	}
    }

  else
    {
      // return the values of the Jacobian of the constraints
      // values are +- 1 depending on direction of link flow

      int k = 0;

      for (Index flow = 0; flow < num_flows_; flow++ )
	{
	  // Equality constraints
	  // Loop over destinations within multicast flow
	  for (Index d = 0; d < mcast_dsts_[flow]; d++ )
	    {
	      // Loop over links

	      for (Index link = 0; link < num_links_; link++ )
		{
		  // Use cummulative number of destinations to simplify math...
		  var_index     = cum_mcast_dsts_[flow] * num_links_ + flow * (num_links_ + 1) + d * num_links_ + link;
		  // links[link] it tuple of (src_no, dst_no, capacity)
		  src_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + links_[link].src;
		  dst_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + links_[link].dst;
		  values[k] = -1;
		  k++;
		  values[k] =  1;
		  k++;
		}
	      // Add/subtract multicast flow rates for each node conservation equation
	      int src                   = mcast_flows_[flow].src;
	      std::vector<int> dst_list = mcast_flows_[flow].dsts;
	      int dst                   = dst_list[d];
	      var_index     = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
	      src_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + src;
	      dst_row_index = cum_mcast_dsts_[flow] * (num_nodes_ + num_links_) + d * num_nodes_ + dst;
	      values[k] = -1;
	      k++;
	      values[k] =  1;
	      k++;
	    }

	  int max_offset;
	  // Set up equations to find max link flow over all destinations in a multicast flow
	  for (Index d = 0; d < mcast_dsts_[flow]; d++ )
	    {
	      row_offset = cum_mcast_dsts_[flow] * (num_links_ + num_nodes_) + mcast_dsts_[flow] * num_nodes_ + d * num_links_;
	      var_offset = cum_mcast_dsts_[flow] * num_links_ + flow * (num_links_ + 1) + d * num_links_;
	      max_offset = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1);
	      for (Index link = 0; link < num_links_; link++ )
		{
		  // Max constraints
		  row_index = row_offset + link;
		  var_index = var_offset + link;
		  values[k] = -1;
		  k++;
		  var_index     = max_offset + link;
		  values[k] =  1;
		  k++;
		}
	    }
	  // Per link capacity constraints
	  row_offset = cum_mcast_dsts_[num_flows_] * (num_links_ + num_nodes_);
	  var_offset = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1); 
	  for (Index link = 0; link < num_links_; link++ )
	    {
	      row_index = row_offset + link;
	      var_index = var_offset + link;
	      values[k] = 1;
	      k++;
	    }
	}
      assert(k == nele_jac);
    }
  return true;
}
// [eval_jac_g]

// [eval_h]
//return the structure or values of the Hessian
bool BpNlp::eval_h(
   Index         n,
   const Number* x,
   bool          new_x,
   Number        obj_factor,
   Index         m,
   const Number* lambda,
   bool          new_lambda,
   Index         nele_hess,
   Index*        iRow,
   Index*        jCol,
   Number*       values
)
{
  // Assume objective function is -ln(eps + x[n-1])

  if ( values == NULL )
    {
      for (Index flow = 0; flow < num_flows_; flow++ )
	{
	  int var_index = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
	  iRow[flow] = var_index;
	  jCol[flow] = var_index;
	}
    }
  else
    {
      for (Index flow = 0; flow < num_flows_; flow++ )
	{
	  double pri = mcast_flows_[flow].pri;
	  int var_index = cum_mcast_dsts_[flow + 1] * num_links_ + flow * (num_links_ + 1) + num_links_;
	  values[flow] = obj_factor * pri / pow(1e-9 + x[var_index],2);
	}
      
    }
  return true;
}
// [eval_h]

// [finalize_solution]
void BpNlp::finalize_solution(
   SolverReturn               status,
   Index                      n,
   const Number*              x,
   const Number*              z_L,
   const Number*              z_U,
   Index                      m,
   const Number*              g,
   const Number*              lambda,
   Number                     obj_value,
   const IpoptData*           ip_data,
   IpoptCalculatedQuantities* ip_cq
)
{
  // Save the solution
  solution_.assign(x, x+n);
  // Save the objective value
  objective_value_ = obj_value;
  
}

// [finalize_solution]

// [initialize_topology]

void BpNlp::initialize_topology(const int n_nodes, const Topology internalLinks){
  num_nodes_ = n_nodes;
  links_ = internalLinks;
  num_links_ = links_.size();
}

// [initialize_topology]

// [get_solution]
std::vector<double> BpNlp::get_solution()
{
  // return vector of optimal rates
  
  std::vector<double> sol;
  for (Index flow = 0; flow < num_flows_; flow++ )
    {
      int var_index = cum_mcast_dsts_[flow+1]*num_links_+flow*(num_links_+1)+num_links_;
      double rate = solution_[var_index];
      sol.push_back(rate);
    }
  return sol;
}

// [get_solution]

// [set_mcast_flows]

void BpNlp::set_mcast_flows(const FlowSpec_vec mcastFlows)
{
  num_flows_      = mcastFlows.size();
  mcast_dsts_     = new int [num_flows_];
  cum_mcast_dsts_ = new int [num_flows_+1];
  cum_mcast_dsts_[0] = 0;
  
  for (int i = 0; i < num_flows_; i++)
    {
      mcast_dsts_[i] = mcastFlows[i].dsts.size();
      cum_mcast_dsts_[i+1] = cum_mcast_dsts_[i] + mcast_dsts_[i];
    }
  num_mcast_dsts_ = cum_mcast_dsts_[num_flows_];
  mcast_flows_ = mcastFlows;
}

