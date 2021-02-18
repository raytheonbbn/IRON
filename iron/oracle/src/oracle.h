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
/// Implements the Oracle for IRON.
///
///
///                               CMD file
///                                  |
///                                  |
///                         +-----------------+       +------------+
///                         |                 |  /----| Petitioner |
///                         |     Oracle      | /     +------------+
/// +-----------+           |                 |/      +------------+
/// | BPF proxy |-----------|client    server |-------| Petitioner |
/// +-----------+           |                 |       +------------+
///                         |                 |
///                         +-----------------+
///

#ifndef IRON_ORACLE_H
#define IRON_ORACLE_H

#include "gnat_nodes.h"
#include "config_info.h"
#include "four_tuple.h"
#include "hash_table.h"
#include "ipv4_address.h"
#include "iron_constants.h"
#include "remote_control.h"
#include "timer.h"

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <list>
#include <vector>
#include <string>
#include <unordered_set>

#include <stdint.h>
#include <sys/select.h>

#include "solver.h"
#include "common.h"
#include "IpIpoptApplication.hpp"

#define MAX_NUM_PETITIONERS 30
#define APP_MAX_BUFLEN 64000

namespace iron
{
  /// Maximum number of retries to connect to BPF on initialization
  const uint32_t kMaxNumRetries     = 15;
  
  typedef enum FLOW_STATUS {
    UNMODIFIED = 0,
    MODIFIED,
    REMOVED_SRC_UNREACHABLE,
    REMOVED_SOME_DSTS_IN_SRC_ENCLAVE,
    REMOVED_ALL_DSTS_UNREACHABLE
  } flow_status_t;

  typedef struct FlowMapEntry
  {
    int flow_num;
    flow_status_t status;
    int solution_index;
  } FlowMapEntry;
 
  typedef std::vector<FlowMapEntry> FlowMap;

  typedef struct PrunedTopology
  {
    Topology remaining_links;
    std::vector<int> reachable_nodes;
    Topology removed_links;
  } PrunedTopology;

  typedef struct FlowDests
  {
    flow_status_t flow_status;
    std::vector<int> dest_list;
  } FlowDests;

  class Oracle
  {

  public:

    /// \brief  The constructor.
    Oracle();
    
    /// \brief The destructor.
    virtual ~Oracle();

    /// \brief  Configure Oracle
    /// \param   ci A config info object for the IRON node for this ORACLE.
    /// \return  True if successful.
    bool Configure(const ConfigInfo& ci);

    /// \brief   Initialize Oracle connections 
    bool Initialize();

    /// \brief Start the ORACLE process.
    void Start();

    /// \brief Terminates the execution of ORACLE.
    ///
    /// Currently, the only way to terminate the execution of Oracle
    /// Forwarder is to send the process a Ctrl-c signal.
    inline void Stop() { running_ = false; };

  protected:

    /// \brief Parse topology contained in BPF update
    void ParseTopology(char *buffer);

    /// \brief parse petition
    Document ParsePetition(char *buffer);


  private:

    /// \brief   Send get stats message to bpf
    void SendGetStatsMsg();

    // Perhaps replace GetJsonMsg and SendJsonMsg with remote control classes?

    /// \brief Get JSON message from connection
    void GetJsonMsg(int fd, char *buffer);

    /// \brief Send JSON message on connection
    void SendJsonMsg(int sd, Document &query);

    /// \brief Handle message from petitioner
    void HandlePetitioner(int sd);

    /// \brief Parse a "maximimize network utility" petition
    Document MaximizeNetworkUtility(char *buffer);

    /// \brief Parse a "find reachable LANs" petition
    Document ReachableLANs(char *buffer);

    /// \brief Parse a "return multicast information" petition
    Document McastInfo(char *buffer);

    /// \brief Handle topology update from BPF
    void HandleBpf();

    /// \brief Prune topology
    PrunedTopology PruneTopology(double min_cap, double max_lat);

    /// \brief Determine reachable destinations for a multicast flow
    FlowDests FlowStatus(FlowSpec flow, 
			 std::vector<int> reachableNodes);

    /// \brief Check that all LAN addresses map into valid binIds
    std::vector<std::string> CheckLanAddresses(Value& multicastflows);

    
    // file descriptors for bpf and clients
    
    int bpf_fd_;
    uint16_t bpf_ctl_port;
    uint16_t petitioner_port;
    Ipv4Address bpf_addr;


    int master_socket_;
    int petitioner_socket_[MAX_NUM_PETITIONERS];
    int max_clients_;

    fd_set readfds;

    /// Flags
    bool running_;
    bool topology_initialized_;

    /// how often to poll bpf
    double stat_interval_s_;

    /// My BinId
    int my_bin_id_;

    /// Helper class for parsing bin_map.cfg
    GnatNodes gnat_nodes_;
    
    /// Topology information

    Topology topology_;
    std::vector<int> reachable_nodes_;

    Solver sol_;


  }; // Oracle class
} // Iron namespace
#endif
