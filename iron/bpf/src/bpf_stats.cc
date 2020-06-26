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

/// \file bpf_stats.cc

#include "bpf_stats.h"
#include "path_controller.h"

#include "log.h"
#include "queue_depths.h"
#include "stats.h"
#include "string_utils.h"
#include "itime.h"

#include <map>
#include <sstream>
#include <string>

#include <climits>
#include <cstdio>
#include <cstring>
#include <inttypes.h>

using ::iron::BpfStats;
using ::iron::PathController;
using ::iron::QueueDepths;
using ::iron::Stats;
using ::iron::StringUtils;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::std::map;
using ::std::numeric_limits;
using ::std::string;


//
// Constants.
//
namespace
{
  /// Class name for logging.
  const char  kClassName[] = "BpfStats";
}


//============================================================================
BpfStats::BpfStats(BinMap& bin_map)
  : Stats(),
    pc_data_tx_queue_depths_(),
    pc_data_rx_queue_depths_(),
    proxy_data_tx_queue_depths_(),
    proxy_data_rx_queue_depths_(),
    avg_queue_depths_(),
    pc_capacity_estimate_(),
    bin_map_(bin_map),
    queue_depths_incr_count_(0),
    latency_per_bin_per_pc_(),
    test_override_(false),
    push_active_(false)
{
  LogI(kClassName, __func__, "Creating BpfStats...\n");
}

//============================================================================
BpfStats::~BpfStats()
{
  LogI(kClassName, __func__, "Destroying BpfStats...\n");

  Purge();
}

//============================================================================
bool BpfStats::Initialize()
{
  queue_depths_incr_count_ = 0;

  if (!latency_per_bin_per_pc_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize latency array.\n");
    return false;
  }

  return true;
}

//============================================================================
void BpfStats::Purge()
{
  // Delete all the data stores.
  map<string, map<uint32_t, QueueDepths*> >::iterator pc_it;

  // First the path controller transmit queue maps
  for (pc_it = pc_data_tx_queue_depths_.begin();
       pc_it != pc_data_tx_queue_depths_.end();
       ++pc_it)
  {
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  pc_it->second.begin();
	it_inner != pc_it->second.end();
	++it_inner)
    {
      if (it_inner->second)
      {
	delete it_inner->second;
      }
    }
    pc_it->second.clear();
  }
  pc_data_tx_queue_depths_.clear();

  // Next the path controller receive queue maps
  for (pc_it = pc_data_rx_queue_depths_.begin();
       pc_it != pc_data_rx_queue_depths_.end();
       ++pc_it)
  {
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  pc_it->second.begin();
	it_inner != pc_it->second.end();
	++it_inner)
    {
      if (it_inner->second)
      {
	delete it_inner->second;
      }
    }
    pc_it->second.clear();
  }
  pc_data_rx_queue_depths_.clear();

  map<uint32_t, map<uint32_t, QueueDepths*> >::iterator pr_it;

  // Next the proxy transmit queue depth maps
  for (pr_it = proxy_data_tx_queue_depths_.begin();
       pr_it != proxy_data_tx_queue_depths_.end();
       ++pr_it)
  {
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  pr_it->second.begin();
	it_inner != pr_it->second.end();
	++it_inner)
    {
      if (it_inner->second)
      {
	delete it_inner->second;
      }
    }
    
    pr_it->second.clear();
  }
  proxy_data_tx_queue_depths_.clear();

  // Next the proxy receive queue depth maps
  for (pr_it = proxy_data_rx_queue_depths_.begin();
       pr_it != proxy_data_rx_queue_depths_.end();
       ++pr_it)
  {
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  pr_it->second.begin();
	it_inner != pr_it->second.end();
	++it_inner)
    {
      if (it_inner->second)
      {
	delete it_inner->second;
      }
    }

    pr_it->second.clear();
  }
  proxy_data_rx_queue_depths_.clear();

  // Finally, the avq queue depth map
  for(map<BinIndex, QueueDepths*>::iterator it_inner =
	avg_queue_depths_.begin();
      it_inner != avg_queue_depths_.end();
      ++it_inner)
  {
    if (it_inner->second)
    {
      delete it_inner->second;
    }
  }
  avg_queue_depths_.clear();
}

//============================================================================
void BpfStats::WriteStats(Writer<StringBuffer>* writer)
{
  // return early if nothing would be written out
  if (!test_override_ &&
    (writer == NULL && (!dump_ok_ || !WouldLogI(kClassName))))
  {
    return;
  }

  // Stats "keyvals" format.  Note that "b" is "Uint" and "n" is "Uint".
  //  "stats" :
  //  {
  //    "BpfToPcBytes" :
  //    {
  //      "xxx.xxx.xxx.xxx" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //        ...
  //      }
  //      "yyy.yyy.yyy.yyy" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //        ...
  //      }
  //      ...
  //    },
  //    "PcToBpfBytes" :
  //    {
  //      "xxx.xxx.xxx.xxx" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //        ...
  //      }
  //      "yyy.yyy.yyy.yyy" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //        ...
  //      }
  //      ...
  //    },
  //    "BpfToProxyBytes" :
  //    {
  //      "TCP" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //      }
  //      "UDP" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //      }
  //    },
  //    "ProxyToBpfBytes" :
  //    {
  //      "TCP" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //      }
  //      "UDP" :
  //      {
  //        "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //        "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //      }
  //    },
  //    "AvgQueueDepthsBytes" :
  //    {
  //      "aaa.aaa.aaa.aaa" : [ b, n, b, n, b, n ],
  //      "bbb.bbb.bbb.bbb" : [ b, n, b, n, b, n ],
  //    }
  //    "PcProperties" :
  //    {
  //      "xxx.xxx.xxx.xxx-i" : {capacity:n, latencies:{"binx": l1, "biny": l2,..}},
  //      "yyy.yyy.yyy.yyy-i" : {capacity:m, latencies:{"binx": l3, "biny": l2,..}},
  //      ...
  //    }
  //  }
  uint32_t  depth    = 0;

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "---BPF Stats-------------\n");
  }

  if (writer)
  {
    writer->Key("stats");
    writer->StartObject();
  }

  std::stringstream ss;

  ss.str("");

  // ----- NumDataBytesSentOnPC -----
  // Dump the number of bytes sent on each path controller, per group, per bin,
  // such that we get:
  // {pc->pc_remote_addr0:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //                       grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},
  // {pc->pc_remote_addr1:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //                       grpaddr2:[(bin_id0:depth0),(bin_id1:depth1)],...}},

  ss << "NumDataBytesSentOnPC={";

  if (writer)
  {
    writer->Key("BpfToPcBytes");
    writer->StartObject();
  }

  bool add_outer_comma = false;
  for (map<string, map<uint32_t, QueueDepths*> >::iterator it =
         pc_data_tx_queue_depths_.begin();
       it != pc_data_tx_queue_depths_.end();
       ++it)
  {
    string rmt_iron_node = it->first;

    if (add_outer_comma)
    {
      ss << ",";
    }
    add_outer_comma = true;
    
    ss << "pc->" << rmt_iron_node << ":{";
    
    if (writer)
    {
      writer->Key(rmt_iron_node.c_str());
      writer->StartObject();
    }
    
    bool add_inner_comma = false;
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  it->second.begin();
	it_inner != it->second.end();
	++it_inner)
    {
      QueueDepths* qd       = it_inner->second;
      string       bin_dump = qd->StatDump();
      string       grp_addr;

      if (add_inner_comma)
      {
	ss << ",";
      }
      add_inner_comma = true;
      
      if (it_inner->first == 0)
      {
	grp_addr = "unicast";
      }
      else
      {
	grp_addr = bin_map_.GetIdToLog(it_inner->first,true); 
      }
      ss << grp_addr << ":[" << bin_dump << "]";

      if (writer)
      {
	writer->Key(grp_addr.c_str());
	writer->StartArray();
      
	BinIndex  idx = 0;
	for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	     valid;
	     valid = bin_map_.GetNextUcastBinIndex(idx))
	{
	  depth = qd->GetBinDepthByIdx(idx);
	  writer->Uint(bin_map_.GetPhyBinId(idx));
	  writer->Uint(depth);
	}

	writer->EndArray();
      }
	
      qd->ClearAllBins();
    }
    
    ss << "}";

    if (writer)
    {
      writer->EndObject();
    }
  }
  
  ss << "}";

  if (writer)
  {
    writer->EndObject();
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "%s\n", ss.str().c_str());
  }

  // --- End NumDataBytesSentOnPC ---

  ss.str("");

  // ----- NumDataBytesRcvdOnPC -----
  // Dump the number of bytes rcvd on each path controller, per group, per bin,
  // such that we get:
  // {pc->pc_remote_addr0:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //                       grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},
  // {pc->pc_remote_addr1:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //                       grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},

  ss << "NumDataBytesRcvdOnPC={";

  if (writer)
  {
    writer->Key("PcToBpfBytes");
    writer->StartObject();
  }

  add_outer_comma = false;
  for (map<string, map<uint32_t, QueueDepths*> >::iterator it =
         pc_data_rx_queue_depths_.begin();
       it != pc_data_rx_queue_depths_.end();
       ++it)
  {
    string rmt_iron_node = it->first;

    if (add_outer_comma)
    {
      ss << ",";
    }
    add_outer_comma = true;

    ss << "pc->" << rmt_iron_node << ":{";

    if (writer)
    {
      writer->Key(rmt_iron_node.c_str());
      writer->StartObject();
    }

    bool add_inner_comma = false;
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  it->second.begin();
	it_inner != it->second.end();
	++it_inner)
    {
      QueueDepths* qd       = it_inner->second;
      string       bin_dump = qd->StatDump();

      if (add_inner_comma)
      {
	ss << ",";
      }
      add_inner_comma = true;

      string grp_addr;
      if (it_inner->first == 0)
      {
	grp_addr = "unicast";
      }
      else
      {
	grp_addr = bin_map_.GetIdToLog(it_inner->first,true); 
      }
      ss << grp_addr << ":[" << bin_dump << "]";

      if (writer)
      {
	writer->Key(grp_addr.c_str());
	writer->StartArray();
      
	BinIndex  idx = 0;	
	for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	     valid;
	     valid = bin_map_.GetNextUcastBinIndex(idx))
	{
	  depth = qd->GetBinDepthByIdx(idx);
	  writer->Uint(bin_map_.GetPhyBinId(idx));
	  writer->Uint(depth);
	}
	
	writer->EndArray();
      }

      qd->ClearAllBins();
    }
    
    ss << "}";
    
    if (writer)
    {
      writer->EndObject();
    }
  }

  ss << "}";
  
  if (writer)
  {
    writer->EndObject();
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "%s\n", ss.str().c_str());
  }

  // --- End NumDataBytesRcvdOnPC ---

  ss.str("");

  // ----- NumDataBytesSentOnProxy -----
  // Dump the number of bytes sent to each proxy, per group, per bin,
  // such that we get:
  // {proxy_type0:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //               grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},
  // {proxy_type1:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //               grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},

  ss << "NumDataBytesSentOnProxy={";

  if (writer)
  {
    writer->Key("BpfToProxyBytes");
    writer->StartObject();
  }

  add_outer_comma = false;
  for (map<uint32_t, map<uint32_t, QueueDepths*> >::iterator it =
         proxy_data_tx_queue_depths_.begin();
       it != proxy_data_tx_queue_depths_.end();
       ++it)
  {
    uint32_t proto = it->first;
    
    string proxy_type = "Unknown";
    if (IPPROTO_TCP == proto)
    {
      proxy_type = "TCP";
    }
    else if (IPPROTO_UDP == proto)
    {
      proxy_type = "UDP";
    }
    
    if (add_outer_comma)
    {
      ss << ",";
    }
    add_outer_comma = true;

    ss << proxy_type << ":{";
      
    if (writer)
    {
      writer->Key(proxy_type.c_str());
      writer->StartObject();
    }

    bool add_inner_comma = false;
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  it->second.begin();
	it_inner != it->second.end();
	++it_inner)
    {
      QueueDepths* qd       = it_inner->second;
      string       bin_dump = qd->StatDump();

      if (add_inner_comma)
      {
	ss << ",";
      }
      add_inner_comma = true;

      string grp_addr;
      if (it_inner->first == 0)
      {
	grp_addr = "unicast";
      }
      else
      {
	grp_addr = bin_map_.GetIdToLog(it_inner->first,true); 
      }
      ss << grp_addr << ":[" << bin_dump << "]";

      if (writer)
      {
	writer->Key(grp_addr.c_str());
	writer->StartArray();
      
	BinIndex  idx = 0;
	for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	     valid;
	     valid = bin_map_.GetNextUcastBinIndex(idx))
	{
	  depth = qd->GetBinDepthByIdx(idx);
	  writer->Uint(bin_map_.GetPhyBinId(idx));
	  writer->Uint(depth);
	}
	
	writer->EndArray();
      }
      
      qd->ClearAllBins();
    }

    ss << "}";
    
    if (writer)
    {
      writer->EndObject();
    }
  }

  ss << "}";

  if (writer)
  {
    writer->EndObject();
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "%s\n", ss.str().c_str());
  }
  
  // --- End NumDataBytesSentOnProxy ---


  ss.str("");

  // ----- NumDataBytesRcvdOnProxy -----
  // Dump the number of bytes received on each proxy, per group, per bin,
  // such that we get:
  // {proxy_type0:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //               grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},
  // {proxy_type1:{unicast:[(bin_id0:depth0),(bin_id1:depth1)],
  //               grpaddr1:[(bin_id0:depth0),(bin_id1:depth1)],...}},

  ss << "NumDataBytesRcvdOnProxy={";

  if (writer)
  {
    writer->Key("ProxyToBpfBytes");
    writer->StartObject();
  }

  add_outer_comma = false;
  for (map<uint32_t, map<uint32_t, QueueDepths*> >::iterator it =
         proxy_data_rx_queue_depths_.begin();
       it != proxy_data_rx_queue_depths_.end();
       ++it)
  {
    uint32_t proto = it->first;
    
    if (add_outer_comma)
    {
      ss << ",";
    }
    add_outer_comma = true;

    string proxy_type = "Unknown";
    if (IPPROTO_TCP == proto)
    {
      proxy_type = "TCP";
    }
    else if (IPPROTO_UDP == proto)
    {
      proxy_type = "UDP";
    }
    
    ss << proxy_type << ":{";
      
    if (writer)
    {
      writer->Key(proxy_type.c_str());
      writer->StartObject();
    }

    bool add_inner_comma = false;
    for(map<uint32_t, QueueDepths*>::iterator it_inner =
	  it->second.begin();
	it_inner != it->second.end();
	++it_inner)
    {
      QueueDepths* qd       = it_inner->second;
      string       bin_dump = qd->StatDump();

      if (add_inner_comma)
      {
	ss << ",";
      }
      add_inner_comma = true;

      string grp_addr;
      if (it_inner->first == 0)
      {
	grp_addr = "unicast";
      }
      else
      {
	grp_addr = bin_map_.GetIdToLog(it_inner->first,true); 
      }
      ss << grp_addr << ":[" << bin_dump << "]";

      if (writer)
      {
	writer->Key(grp_addr.c_str());
	writer->StartArray();
      
	BinIndex  idx = 0;
	for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	     valid;
	     valid = bin_map_.GetNextUcastBinIndex(idx))
	{
	  depth = qd->GetBinDepthByIdx(idx);
	  writer->Uint(bin_map_.GetPhyBinId(idx));
	  writer->Uint(depth);
	}
	
	writer->EndArray();
      }
      
      qd->ClearAllBins();
    }

    ss << "}";
    
    if (writer)
    {
      writer->EndObject();
    }
  }

  ss << "}";
  
  if (writer)
  {
    writer->EndObject();
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "%s\n", ss.str().c_str());
  }

  // --- End NumDataBytesRcvdOnProxy ---

  ss.str("");

  // ----- AvgQueueDepths -----
  // Dump the average queue depths (in bytes) for all bins, such that we get:
  // (bin_id0:av_depth0),(bin_id1:av_depth1),.

  ss << "AvgQueueDepths=:{";

  if (writer)
  {
    writer->Key("AvgQueueDepthsBytes");
    writer->StartObject();
  }

  bool add_inner_comma = false;
  for(map<BinIndex, QueueDepths*>::iterator it =
	avg_queue_depths_.begin();
      it != avg_queue_depths_.end();
      ++it)
  {
    QueueDepths* qd       = it->second;
    string       bin_dump = qd->StatDump();
    
    if (add_inner_comma)
    {
      ss << ",";
    }
    add_inner_comma = true;

    string grp_addr;
    if (it->first == 0)
    {
      grp_addr = "unicast";
    }
    else
    {
      grp_addr = bin_map_.GetIdToLog(it->first,true); 
    }
    ss << grp_addr << ":[" << bin_dump << "]";

    if (writer)
    {
      writer->Key(grp_addr.c_str());
      writer->StartArray();
      
      BinIndex  idx = 0;
      for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	   valid;
	   valid = bin_map_.GetNextUcastBinIndex(idx))
      {
	depth = qd->GetBinDepthByIdx(idx);
	writer->Uint(bin_map_.GetPhyBinId(idx));
	writer->Uint(depth);
      }
      
      writer->EndArray();
    }
      
    // Clear all of the average bin depths for the next interval.
    qd->ClearAllBins();
  }

  ss << "}";
    
  if (writer)
  {
    writer->EndObject();
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "%s\n", ss.str().c_str());
  }

  // Reset the call counter for the next round
  queue_depths_incr_count_ = 0;;
  
  // --- End AvgQueueDepths ---

  ss.str("");

  // ----- PCProperties -----
  // Dump the path controller capacity estimates in bps, such that we get:
  // (pc->pc_remote_addr0:cap0),(pc->pc_remote_addr1:cap1),...
  ss << "PcProperties=";
  if (writer)
  {
    writer->Key("PcProperties");
    writer->StartObject();
  }

  for (map<string, PcCapEst>::const_iterator it =
         pc_capacity_estimate_.begin();
       it != pc_capacity_estimate_.end();
       ++it)
  {
    string    rmt_iron_node = it->first;
    PcCapEst  pc_cap_est    = it->second;

    ss << "(" << rmt_iron_node << ":{CapacityBitsPerSec:";
    ss << pc_cap_est.chan_cap_est_bps << "bps},";
    ss << "{TransportBitsPerSec:";
    ss << pc_cap_est.trans_cap_est_bps << "bps},";
    ss << "{LatencyUsec:";

    // TODO: Revisit to include mcast destinations.
    BinIndex  dst_bin_idx = 0;

    for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bin_idx);
         valid;
         valid = bin_map_.GetNextUcastBinIndex(dst_bin_idx))
    {
      BinId bin = bin_map_.GetPhyBinId(dst_bin_idx);
      std::map<string,uint32_t>& lat_map =
        latency_per_bin_per_pc_[dst_bin_idx];
      std::map<string,uint32_t>::iterator lat_it =
        lat_map.find(rmt_iron_node);
      if (lat_it != lat_map.end())
      {
        ss << "{Bin " << static_cast<uint32_t>(bin) << ":";
        ss << static_cast<uint64_t>(lat_map[rmt_iron_node]);
        ss << "us}";
      }
    }
    ss << "})";

    if (writer)
    {
      writer->Key(rmt_iron_node.c_str());
      writer->StartObject();
      writer->Key("CapacityBitsPerSec");
      writer->Uint(pc_cap_est.chan_cap_est_bps);
      writer->Key("TransportBitsPerSec");
      writer->Uint(pc_cap_est.trans_cap_est_bps);
      writer->Key("LatenciesUsec");
      writer->StartObject();

      // TODO: Revisit to include mcast destinations.
      BinIndex  dst_bin_idx = 0;

      for (bool valid = bin_map_.GetFirstUcastBinIndex(dst_bin_idx);
           valid;
           valid = bin_map_.GetNextUcastBinIndex(dst_bin_idx))
      {
        BinId bin = bin_map_.GetPhyBinId(dst_bin_idx);
        std::map<string,uint32_t>& lat_map =
          latency_per_bin_per_pc_[dst_bin_idx];
        std::map<string,uint32_t>::iterator lat_it =
          lat_map.find(rmt_iron_node);
        if(lat_it != lat_map.end())
        {
          writer->Key(StringUtils::ToString(bin).c_str());
          writer->Uint(lat_map[rmt_iron_node]);
        }
      }
      writer->EndObject();
      writer->EndObject();
    }
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "%s\n", ss.str().c_str());
  }

  if (writer)
  {
    writer->EndObject();
  // --- End PCProperties ---
    writer->EndObject();
  }

  if (dump_ok_)
  {
    LogI(kClassName, __func__, "-------------BPF Stats---\n");
  }
}

//============================================================================
string BpfStats::ToString() const
{
  std::stringstream ss;

  ss << "Stats=(DataBytesSentToBinOnPC:";
  ss << pc_data_tx_queue_depths_.size();
  ss << "El),(DataBytesRcvdForBinOnPC:";
  ss << pc_data_rx_queue_depths_.size();
  ss << "El),(DataBytesSentToBinOnProxy:";
  ss << proxy_data_tx_queue_depths_.size();
  ss << "El),(DataBytesRcvdForBinOnProxy:";
  ss << proxy_data_rx_queue_depths_.size();
  ss << "El),(NumQueues:";
  ss << avg_queue_depths_.size();
  ss << "El),(PCCapacity:";
  ss << pc_capacity_estimate_.size() << "El)";

  return ss.str();
}

//============================================================================
bool BpfStats::IncrementNumDataBytesSentToBinOnPathCtrl(
  PathController* pc, BinIndex bin_idx, uint64_t num_bytes,
  DstVec dst_vec)
{
  if (!push_active_ && !test_override_ && (!dump_ok_ || !WouldLogI(kClassName)))
  {
    return false;
  }

  if (!pc)
  {
    LogW(kClassName, __func__,
          "Cannot increment data for NULL path controller.\n");
    return false;
  }

  // Note: We use a special qd_idx value of zero to access
  // the unicast queue depths object. Otherwise we use the
  // provided bin_idx directly to look up the specific
  // multicast queue depths object
  
  uint32_t qd_idx = 0;
  if (bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd_idx = bin_idx;
  }

  string rmt_iron_node = CreateRemoteNodeAddrForPC(pc);
  QueueDepths* qd      = NULL;

  if (pc_data_tx_queue_depths_[rmt_iron_node].find(qd_idx) ==
      pc_data_tx_queue_depths_[rmt_iron_node].end())
  {
    qd = new (std::nothrow) QueueDepths(bin_map_);
    pc_data_tx_queue_depths_[rmt_iron_node][qd_idx] = qd;
  }
  else
  {
    qd = pc_data_tx_queue_depths_[rmt_iron_node][qd_idx];
  }

  if (!qd)
  {
    LogF(kClassName, __func__,
	 "Error allocating memory for QueueDepth object.\n");
    return false;
  }

  if (!bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd->Increment(bin_idx, static_cast<uint32_t>(num_bytes));
  }
  else
  {
    BinIndex idx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(idx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, idx))
      {
	qd->Increment(idx, static_cast<uint32_t>(num_bytes));
      }
    }
  }

  return true;
}

//============================================================================
bool BpfStats::IncrementNumDataBytesRcvdForBinOnPathCtrl(
  PathController* pc, BinIndex bin_idx, uint64_t num_bytes,
  DstVec dst_vec)
{
  if (!push_active_ && !test_override_ && (!dump_ok_ || !WouldLogI(kClassName)))
  {
    return false;
  }

  if (!pc)
  {
    LogW(kClassName, __func__,
          "Cannot increment data for NULL path controller.\n");
    return false;
  }

  // Note: We use a special qd_idx value of zero to access
  // the unicast queue depths object. Otherwise we use the
  // provided bin_idx directly to look up the specific
  // multicast queue depths object
  
  uint32_t qd_idx = 0;
  if (bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd_idx = bin_idx;
  }

  string rmt_iron_node = CreateRemoteNodeAddrForPC(pc);
  QueueDepths* qd      = NULL;
  
  if (pc_data_rx_queue_depths_[rmt_iron_node].find(qd_idx) ==
      pc_data_rx_queue_depths_[rmt_iron_node].end())
  {
    qd = new (std::nothrow) QueueDepths(bin_map_);
    pc_data_rx_queue_depths_[rmt_iron_node][qd_idx] = qd;
  }
  else
  {
    qd = pc_data_rx_queue_depths_[rmt_iron_node][qd_idx];
  }

  if (!qd)
  {
    LogF(kClassName, __func__,
	 "Error allocating memory for QueueDepth object.\n");
    return false;
  }

  if (!bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd->Increment(bin_idx, static_cast<uint32_t>(num_bytes));
  }
  else
  {
    BinIndex idx = 0;	
    for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(idx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, idx))
      {
	qd->Increment(idx, static_cast<uint32_t>(num_bytes));
      }
    }
  }

  return true;
}

//============================================================================
bool BpfStats::IncrementNumDataBytesSentToBinOnProxy(uint32_t proxy,
                                                     BinIndex bin_idx,
                                                     uint64_t num_bytes,
						     DstVec dst_vec)
{
  if (!push_active_ && !test_override_ && (!dump_ok_ || !WouldLogI(kClassName)))
  {
    return false;
  }

  // Note: We use a special qd_idx value of zero to access
  // the unicast queue depths object. Otherwise we use the
  // provided bin_idx directly to look up the specific
  // multicast queue depths object
  
  uint32_t qd_idx = 0;
  if (bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd_idx = bin_idx;
  }

  QueueDepths* qd = NULL;
  if (proxy_data_tx_queue_depths_[proxy].find(qd_idx) ==
      proxy_data_tx_queue_depths_[proxy].end())
  {
    qd = new (std::nothrow) QueueDepths(bin_map_);
    proxy_data_tx_queue_depths_[proxy][qd_idx] = qd;
  }
  else
  {
    qd = proxy_data_tx_queue_depths_[proxy][qd_idx];
  }

  if (!qd)
  {
    LogF(kClassName, __func__,
	 "Error allocating memory for QueueDepth object.\n");
    return false;
  }

  if (!bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd->Increment(bin_idx, static_cast<uint32_t>(num_bytes));
  }
  else
  {
    BinIndex idx = 0;	
    for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(idx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, idx))
      {
	qd->Increment(idx, static_cast<uint32_t>(num_bytes));
      }
    }
  }

  return true;
}

//============================================================================
bool BpfStats::IncrementNumDataBytesRcvdForBinOnProxy(uint32_t proxy,
                                                      BinIndex bin_idx,
                                                      uint64_t num_bytes,
						      DstVec dst_vec)
{
  if (!push_active_ && !test_override_ && (!dump_ok_ || !WouldLogI(kClassName)))
  {
    return false;
  }

  // Note: We use a special qd_idx value of zero to access
  // the unicast queue depths object. Otherwise we use the
  // provided bin_idx directly to look up the specific
  // multicast queue depths object
  
  uint32_t qd_idx = 0;
  if (bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd_idx = bin_idx;
  }

  QueueDepths* qd = NULL;
  if (proxy_data_rx_queue_depths_[proxy].find(qd_idx) ==
      proxy_data_rx_queue_depths_[proxy].end())
  {
    qd = new (std::nothrow) QueueDepths(bin_map_);
    proxy_data_rx_queue_depths_[proxy][qd_idx] = qd;
  }
  else
  {
    qd = proxy_data_rx_queue_depths_[proxy][qd_idx];
  }

  if (!qd)
  {
    LogF(kClassName, __func__,
	 "Error allocating memory for QueueDepth object.\n");
    return false;
  }

  if (!bin_map_.IsMcastBinIndex(bin_idx))
  {
    qd->Increment(bin_idx, static_cast<uint32_t>(num_bytes));
  }
  else
  {
    BinIndex idx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(idx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(idx))
    {
      if (bin_map_.IsBinInDstVec(dst_vec, idx))
      {
	qd->Increment(idx, static_cast<uint32_t>(num_bytes));
      }
    }
  }

  return true;
}

//============================================================================
// MCAST TODO: Modify to be compatible with new mcast structures.
void BpfStats::ReportQueueDepthsForBins(BinIndex grp_idx, QueueDepths* qd)
{
  if (!qd)
  {
    LogE(kClassName, __func__,
         "Queue depth object is NULL.\n");
  }

  if (!push_active_ && !test_override_ && (!dump_ok_ || !WouldLogI(kClassName)))
  {
    return;
  }

  uint32_t qd_idx = 0;
  if (bin_map_.IsMcastBinIndex(grp_idx))
  {
    qd_idx = grp_idx;
  }

  // Grab the pointer to the queue_depths object we are
  // going to modify
  
  QueueDepths* aqd = NULL;
  if (avg_queue_depths_.find(qd_idx) == avg_queue_depths_.end())
  {
    aqd = new (std::nothrow) QueueDepths(bin_map_);
    avg_queue_depths_[qd_idx] = aqd;
  }
  else
  {
    aqd = avg_queue_depths_[qd_idx];
  }

  // Check for a NULL ptr, just in case (should never happen)
  if (!aqd)
  {
    LogF(kClassName, __func__,
   	 "Error allocating memory for QueueDepth object.\n");
  }

  // Check to see whether we have a multicast bin index or
  // a unicast index, and perform updates appropriately
  
  if (!bin_map_.IsMcastBinIndex(grp_idx))
  {
    // If grp_idx is not a multicast index, use it directly
    // as the bin index for the average we're going to modify
    BinIndex bin_idx = grp_idx;

    // The averages are computed as follows:
    //
    //   avg_T+1   = ((avg_T * count_T) + qd_T+1) / (count_T + 1)
    //   count_T+1 = count_T + 1
    //
    // Note that this will not be exact, since the QueueDepths object
    // only stores integer depths.  But, at least use floating point
    // numbers for the local computations here.
    
    uint32_t new_bin_depth_bytes =
      qd->GetBinDepthByIdx(bin_idx, NORMAL_LATENCY);
    
    int32_t  cnt = queue_depths_incr_count_;
    double   avg = static_cast<double>(
      aqd->GetBinDepthByIdx(bin_idx));
    
    avg = (((avg * static_cast<double>(cnt)) +
	    static_cast<double>(new_bin_depth_bytes)) /
	   static_cast<double>(cnt + 1));
    
    // Store the updated average queue depth.
    aqd->SetBinDepthByIdx(bin_idx, avg);
  }
  else
  {
    // Else grp_idx is a multicast index, so we need to loop over
    // all unicast bin indexes
    
    BinIndex  bin_idx = 0;
    for (bool valid = bin_map_.GetFirstUcastBinIndex(bin_idx);
	 valid;
	 valid = bin_map_.GetNextUcastBinIndex(bin_idx))
    {
      uint32_t new_bin_depth_bytes =
	qd->GetBinDepthByIdx(bin_idx, NORMAL_LATENCY);
      
      int32_t  cnt = queue_depths_incr_count_;
      double   avg = static_cast<double>(
	aqd->GetBinDepthByIdx(bin_idx));
      
      avg = (((avg * static_cast<double>(cnt)) +
	      static_cast<double>(new_bin_depth_bytes)) /
	     static_cast<double>(cnt + 1));
      
      // Store the updated average queue depth.
      aqd->SetBinDepthByIdx(bin_idx, avg);
    }
  }
}

//============================================================================
void BpfStats::ReportCapacityUpdateForPC(PathController* pc,
                                         uint64_t chan_cap_est_bps,
                                         uint64_t trans_cap_est_bps)
{
  if (!push_active_ && !test_override_ && (!dump_ok_ || !WouldLogI(kClassName)))
  {
    return;
  }

  if (pc && (pc->remote_bin_idx() != kInvalidBinIndex))
  {
    string    rmt_iron_node = CreateRemoteNodeAddrForPC(pc);
    PcCapEst  pc_cap_est(chan_cap_est_bps, trans_cap_est_bps);

    pc_capacity_estimate_[rmt_iron_node] = pc_cap_est;
  }
}

//============================================================================
string BpfStats::CreateRemoteNodeAddrForPC(const PathController* pc)
{
  // TODO: The path controller remote IRON node IPv4 address is no longer
  // supported, as the IRON node IPv4 addresses in the bin map have been
  // eliminated.  However, the BPF stats still requires a node-specific IPv4
  // address string for some of its stats.  The remote IPv4 address within the
  // path controller endpoints string (the IPv4 address after the "->") cannot
  // be used, as this is just an interface address and nodes may be
  // multi-homed.  Thus, the "next_hop" string is now a synthesized IPv4
  // address that uses the remote node's bin id in the format
  // "10.<bin_id>.0.1".  This works as long as the bin ids are between 0 and
  // 255.  Fix this issue by changing this class and all of the stats
  // receivers to use something other than a node-specific IPv4 address.
  BinId  pc_bin_id = pc->remote_bin_id();

  string  next_hop = "10.";
  next_hop.append(StringUtils::ToString(static_cast<int>(pc_bin_id)));
  next_hop.append(".0.1");

  if (!pc->label().empty())
  {
    next_hop.append("-");
    next_hop.append(pc->label());
  }

  return next_hop;
}
