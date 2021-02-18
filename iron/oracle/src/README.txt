# IRON: iron_headers
#
# Distribution A
#
# Approved for Public Release, Distribution Unlimited
#
# EdgeCT (IRON) Software Contract No.: HR0011-15-C-0097
# DCOMP (GNAT)  Software Contract No.: HR0011-17-C-0050
# Copyright (c) 2015-20 Raytheon BBN Technologies Corp.
#
# This material is based upon work supported by the Defense Advanced
# Research Projects Agency under Contracts No. HR0011-15-C-0097 and
# HR0011-17-C-0050. Any opinions, findings and conclusions or
# recommendations expressed in this material are those of the author(s)
# and do not necessarily reflect the views of the Defense Advanced
# Research Project Agency.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# IRON: end

The Oracle can respond to petitions. The petitions and responses are JSON messages.
Currently 3 types are supported:
- Maximize Network Utility
- List Reachable LANs
- Provide Multicast Information

The Maximize Network Utility petition/response has the following format:
Petition format:
"objective": "maxNetworkUtility"
"linkConstraints": {"minCapacity": minRate, "maxLatency": maxLat} - optional
"multicastlows": [array of multicast flows]
   multicastflow looks like:
   "src": "srcLanAddress",
   "dstList": [array of LAN addresses]
   "pri": priority      (double)
   "flowRateConstraints": {"lowerRate": double, "upperRate": double}  - optional

Petition response is query with additional fields
"status": statusMessage
      "success" or "failed" or "infeasible problem"
each multicastflow has additional fields
   "rate": flowRate     (double)
      - if problem is feasible and flow was not pruned
   "unreachableAddrs": [array of unreachable LAN addresses]
      - if some nodes are unreachable
   "status": statusMessage (string)
       UNMODIFIED
        - all destinations are reachable, rate computed
       MODIFIED
        - some destinations are reachable, rate computed for reachable destinations
       REMOVED_SRC_UNREACHABLE
        - source node is not reachable, so no rate computed
       REMOVED_SOME_DSTS_IN_SRC_ENCLAVE (
        - the only reachable destinations are in the source enclave, so no rate computed
          the transmit rate to nodes in source enclave is not constrained by GNAT nodes
       REMOVED_ALL_DSTS_UNREACHABLE
        - no destinations are reachable, so no rate computed

The List Reachable LANs petition/response has the following format:
Petition format:
"objective": "reachableLANs"
"constraints": ["minCapacity": minRate, "maxLatency": maxLat] - optional

Petition response is query with additional fields
"status": statusMessage
        "success" or "failed"
"reachableLANs": [array of LAN subnets]

The Provide Multicast Information petition/response has the following format:
Petition format:
"objective": "mcastInfo",
"linkConstraints": {"minCapacity": minRate, "maxLatency": maxLat} - optional
Petition response is query with additional fields
"status": statusMessage,
    "Success" or "Failure"
"mcastInfo": [array of unicast info] (one entry for each reachable external GNAT node
  unicast info has format
  "rate": double
  "subnets": [array of subnets associated with GNAT node]

Overall program flow:
- oracle_main.cc is responsible for
  - command line processing
  - calling Initialize and Start methods for oracle.cc
  - interrupt handling
- oracle.cc is responsible for
  - connecting to a BPF and querying for stats
  - servicing connections from petitioners
  - mapping between petition flow descriptions (IP Addresses) and Bin Ids
  - generating a vector of multicast flows that are "feasible"
    - i.e., do not include unreachable nodes
  - pruning out links that don't meet specified minimum capacity or maximum latency (optional)
  - parsing BPF message regarding capacities and latencies
  - generating a vector of links (srcBinId, dstBinId, capacity, latency)
  - pushing the topology and flow vectors down to the Solver layer
  - parsing the Solver response and using it to generate a response to the petition
- Solver.cc is responsible for
  - mapping binIds into a consecutive set of integers starting at 0
    - these internal ids are used to index into the convex optimization array
  - pushing the remapped topology and flow vectors down to the BpNlp layer
  - setting up and calling the convex optimizer
  - sending the solution back up to the oracle layer
- BpNlp.cc is a class with methods that compute information needed by the Solver
  - function value at a point
  - derivative at a point
  - Hessian at a point
  - these sparse matrices are computed dynamically from the topology and flow vectors
    passed down to it
- gnat_nodes.cc is a helper class that can parse a bin_map.cfg file and determine
  the binId for an IP address
  - basically a subset of the bin_map.cc code

PruneTopology
This method is responsible for "sanitizing" the topology reported by the BPF.
It handles the following concerns:
-  There may be "stale" LSAs at the reporting BPF, if the topology is disconnected.
   In particular, nodes that are unreachable now will report links to reachable nodes.
   Thus PruneTopology removes
   - one-way links,
   - nodes which are unreachable and
   - links connected to unreachable nodes.

FlowStatus
This method is responsible for "pruning" the flows described in a petition.
It handles the following concerns:
-  Multiple multicast destinations may be attached to the same BPF. Since the topology
   we consider is the BPF topology, we have to prune duplicate destination BPF from
   the petition
-  Some destinations may be unreachable and should be pruned. If no destinations are
   reachable, the flow should not be included in the problem presented to the Solver
-  The source of a flow may be unreachable (if for example, the petitioner knows about
   existing flows and is asking about the impact of a new flow). If so the flow should
   be pruned
-  There may be destinations which are in the source enclave of the flow. These destinations
   should be removed. If there are no other reachable destinations, then the flow is not
   constrained by the GNAT network and the flow is not present in the problem presented
   to the Solver.


Comments
- Need to ensure that the BPF supplying stats has a bpf.cfg which includes
  Bpf.IncludeLinkCapacity true
- Petitions and responses are formatted as JSON
- The solver needs the IpOpt library to be installed. For details see iron/extern/IpOpt/README.gnat
  - I've installed the IpOpt library on Forge
- If you want to run the oracle on a gnat node but don't want to build IpOpt on those nodes, you
  can copy the following libraries from forge to the gnat node and then run ldconfig
  - /usr/local/lib/libipopt.so3.13.1
  - /usr/local/lib/libcoinmumps.so.0.0.0
  - /usr/lib/liblapack.so.3
  - /usr/lib/libblas.so.3.6.0
  - /usr/lib/libatlas.so.3
  - /usr/lib/x86_64-linux-gnu/libgfortran.so.3
  

Issues
- The oracle attempts to connect to a specified BPF. When it's running on the same node
  as the BPF, it tries to connect to 127.0.0.1. If it tries too quickly after the BPF
  has started, it sometimes fails to connect.
- The oracle will try to connect a specified number of times (kMaxNumRetries) and will
  LogF if it cannot connect (since it cannot operate without a BPF).
  
