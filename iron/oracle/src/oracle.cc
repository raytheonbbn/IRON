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

#include "oracle.h"
#include "gnat_nodes.h"
#include "config_info.h"
#include "iron_types.h"
#include "itime.h"
#include <time.h>
#include "log.h"
#include "string_utils.h"
#include "unused.h"

#include <cstdlib>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <vector>
#include <tuple>
#include <unordered_set>
#include <limits>

using ::iron::Oracle;
using ::iron::FlowDests;
using ::iron::PrunedTopology;
using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::Log;
using ::iron::StringUtils;
using ::iron::Time;
using ::std::string;
using ::std::list;
using ::std::tuple;
using ::rapidjson::Document;
using ::rapidjson::Value;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;

using namespace Ipopt;

namespace
{
  /// The default remote control BPF port number.
  const uint16_t  kDefaultBpfCtlPort              = 5560;

  /// The default remote control port for petitioners to use
  const uint16_t  kDefaultPetitionerPort          = 3200;

  /// The default interval to send stats get messages
  const double  kDefaultStatIntervalS             = 2.0;

  const char* UNUSED(kClassName)                  = "Oracle";
}

//=============================================================================
Oracle::Oracle()
  :   max_clients_ (MAX_NUM_PETITIONERS),
      running_ (true),
      topology_initialized_ (false),
      stat_interval_s_ (kDefaultStatIntervalS)
{
}

//=============================================================================
Oracle::~Oracle()
{
}

//=============================================================================
bool Oracle::Configure(const ConfigInfo& config_info)
{
  LogI(kClassName, __func__, "Configuring Oracle...\n");

  // Read the config files and get the IP address/port of the BPF

  bpf_ctl_port        =
    static_cast<uint16_t>(config_info.GetUint("Bpf.RemoteControl.Port",
                                              kDefaultBpfCtlPort));

  petitioner_port =
    static_cast<uint16_t>(config_info.GetUint("Petitioner.Port",
                                              kDefaultPetitionerPort));

  // Oracle can run on GNAT node or anywhere else. If on GNAT node,
  // then use loopback address for communication with BPF

  bpf_addr          =
    config_info.GetIpAddr("Oracle.BpfAddr","127.0.0.1");

  // If on GNAT node, then get binId from bpf config file or specification
  // in oracle.cfg (needed for determining reachability)

  my_bin_id_ =
    static_cast<int>(config_info.GetUint("Bpf.BinId", kInvalidBinId));

  if (my_bin_id_ == kInvalidBinId)
    {
      my_bin_id_ = static_cast<int>(config_info.GetUint("Oracle.BinId", kInvalidBinId));
      LogD(kClassName, __func__, "Coudn't find Bpf.BinId, trying Oracle.BinId: %hhu\n", my_bin_id_);
    }

  if (my_bin_id_ == kInvalidBinId)
    {
      // TODO: if no binId, then skip reachability tests?
      
      LogE(kClassName, __func__, "Cannot find my binId\n");
    }

  // Determine all possible binIds and LAN subnets associated with Edge nodes

  gnat_nodes_.Initialize(config_info);
  
     
  LogC(kClassName, __func__, "Oracle configuration:\n");
  LogC(kClassName, __func__,
       "BPF IP address                          : %s\n", bpf_addr.ToString().c_str());
  LogC(kClassName, __func__,
       "BPF control port                        : %" PRIu16 "\n",
       bpf_ctl_port);
  LogC(kClassName, __func__, "Oracle configuration complete.\n");

  return true;
}

//=============================================================================
bool Oracle::Initialize()
{
  // Connect to the BPF. If cannot connect, then oracle cannot run, so
  // pick kMaxNumRetries large enough...else error out

  // Also listen on master socket for connection attempts from petitioners

  struct sockaddr_in bpf;
  ::memset(&bpf, 0, sizeof(bpf));
  bpf.sin_family       = AF_INET;
  bpf.sin_addr.s_addr  = bpf_addr.address();
  bpf.sin_port         = htons(bpf_ctl_port);
    
  //Create socket
  uint count = 0;

  bpf_fd_ = socket(AF_INET , SOCK_STREAM , 0);
  if (bpf_fd_ == -1)
    {
      LogE(kClassName, __func__,
	   "Could not create socket for BPF connection\n");
      abort();
    }
		
  bool bpf_connected = false;
  while (!bpf_connected) {

    // Connect to bpf that we're using
    if (connect(bpf_fd_ , (struct sockaddr *)&bpf , sizeof(bpf)) < 0)
      {
	close(bpf_fd_);
	sleep(1);
	if (++count > kMaxNumRetries)
	  {
	    LogF(kClassName, __func__,
		 "Unable to connect to the bpf after %" PRIu32
		 " attempts. Deferring\n",kMaxNumRetries);
	  }
      }
    else
      {
	bpf_connected = true;
      }
  }

  // Create master socket and data structs for petitioners
  // Initialize client sockets to 0 so not checked
  
  for (int i=0; i < max_clients_; i++)
    {
      petitioner_socket_[i] = 0;
    }

  if ( (master_socket_ = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
      LogE(kClassName, __func__,
	   "Creating Oracle master socket failed\n");
    }

  int opt;
  // Set master socket to allow multiple connections
  if( setsockopt(master_socket_, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
		 sizeof(opt)) < 0 )
    {
      LogF(kClassName, __func__, "Oracle master socket setsockopt error\n");
    }

  // type of socket created
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons( petitioner_port );

  // bind the socket to localhost 
  if (bind(master_socket_, (struct sockaddr *)&address, sizeof(address))<0)
    {
      LogF(kClassName, __func__, "Oracle master socket bind failed\n");
    }

  // try to specify maximum of 3 pending connections for the master socket
  if (listen(master_socket_, 3) < 0)
    {
      LogF(kClassName, __func__, "Oracle master socket listen error\n");
    }

  return true;
}

//=============================================================================
void Oracle::Start()
// Infinite loop which sends "get stats message" to BPF periodically, parses
// response, handles petition connection/disconnection and parse requests
 

{
  Time send_get_msg_time = Time::Now();

  LogD(kClassName, __func__, "Starting Oracle.\n");

  struct sockaddr_in address;
  int addrlen = sizeof(address);
  int new_socket;
  int activity;
  Time poll_time = Time(stat_interval_s_);
  timeval poll_tv = poll_time.ToTval();
  timeval local_poll_tv;
  int max_sd;

  while(running_)
    {
      Time now = Time::Now();

      // If past time to send get stats message, then send one
      if (now >= send_get_msg_time)
	{
	  SendGetStatsMsg();
	  send_get_msg_time = now + Time(stat_interval_s_);
	}

      //clear the socket set
      FD_ZERO(&readfds);

      //add master socket to set
      FD_SET(master_socket_, &readfds);
      max_sd = master_socket_;
      // add BPF to set
      FD_SET(bpf_fd_, &readfds);
      if (bpf_fd_ > max_sd)
	{
	  max_sd = bpf_fd_;
	}

      //add child sockets to set
      for (int i = 0 ; i < max_clients_ ; i++)
	{
	  //socket descriptor
	  int sd = petitioner_socket_[i];

	  //if valid socket descriptor then add to read list
	  if(sd > 0)
	    {
	      FD_SET( sd , &readfds);
	    }
	  
	  //highest file descriptor number, need it for the select function
	  if(sd > max_sd)
	    max_sd = sd;
	}

      // wait for an activity on one of the sockets , timeout is stat_interval_s_
      // timeout is overwritten by select, so re-write before setting
      
      local_poll_tv.tv_sec = poll_tv.tv_sec;
      local_poll_tv.tv_usec = poll_tv.tv_usec;

      activity = select( max_sd + 1 , &readfds , NULL , NULL , &local_poll_tv);

      if ((activity < 0) && (errno!=EINTR))
	{
	  LogE(kClassName, __func__, "Master socket select error\n");
	}

      // If something happened on the master socket, then its an incoming connection
      if (FD_ISSET(master_socket_, &readfds))
	{
	  if ((new_socket = accept(master_socket_,
				   (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
	    {
	      LogE(kClassName, __func__, "Master socket accept error\n");
	      exit(EXIT_FAILURE);
	    }

	  LogD(kClassName,__func__,
	       "New connection , socket fd is %d , ip is : %s , port : %d\n", new_socket,
	       inet_ntoa(address.sin_addr), ntohs(address.sin_port));

	  // add new socket to array of sockets
	  for (int i = 0; i < max_clients_; i++)
	    {
	      //if position is empty
	      if( petitioner_socket_[i] == 0 )
		{
		  LogD(kClassName, __func__, "inserting socket %i at petitioner_socket_[%i]\n", new_socket, i);
		  petitioner_socket_[i] = new_socket;
		  break;
		}
	    }
	}

      // if it's from the BPF, handle topology update
      if (FD_ISSET(bpf_fd_, &readfds))
	{
	  LogD(kClassName, __func__, "Calling HandleBpf\n");
	  HandleBpf();
	}
      // else handle petitioner request
      else
	{
	  for (int i = 0; i < max_clients_; i++)
	    {
	      int sd = petitioner_socket_[i];
	      if (FD_ISSET( sd , &readfds))
		{
		  LogD(kClassName, __func__, "Calling HandlePetitioner\n");

		  // Check to see if this is a disconnect (activity on socket but zero bytes)
		  // NOTE: activity on a socket with nothing to read is a HEURISTIC for
		  // determining that the underlying TCP connection has gone away

		  int bytes_available;
		  ioctl(sd,FIONREAD,&bytes_available);
		  LogD(kClassName, __func__, "Bytes_available = %i\n", bytes_available);
		  if (bytes_available < 0)
		    {
		      LogE(kClassName, __func__, "Read error on socket %i\n", sd);
		    }
		  else if (bytes_available == 0)
		    {
		      // Somebody disconnected
		      // Close the socket and mark as 0 in list so it can be reused
		      close( sd );
		      LogD(kClassName, __func__, "Socket %i closed\n", sd);
		      petitioner_socket_[i] = 0;
		    }
		  else
		    {
		      // Have bytes to read
		      HandlePetitioner(sd);
		    }
		}
	    }
	}
    }
}

//=============================================================================
void Oracle::SendGetStatsMsg()
// We send a get stats message periodically
// Think about making code on BPF send stats periodically instead

{
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);

  writer.StartObject();

  writer.Key("msg");
  writer.String("get");

  writer.Key("msgid");
  uint32_t stat_msg_id_ = 1;
  writer.Uint(stat_msg_id_);

  writer.Key("tgt");
  string target = "bpf";
  writer.String(target.c_str());

  writer.Key("keys");
  writer.StartArray();
  writer.Key("cap_and_lat");

  writer.EndArray();

  writer.EndObject();

  // Prepend json message length
  
  int       json_len     = static_cast<int>(str_buf.GetSize());
  uint32_t  json_len_nbo = static_cast<uint32_t>(htonl(json_len));
  int       msg_len      = (json_len + sizeof(json_len_nbo));
  char      *snd_buf     = new char[msg_len];

  ::memcpy(&(snd_buf[0]), &json_len_nbo, sizeof(json_len_nbo));
  ::memcpy(&(snd_buf[sizeof(json_len_nbo)]), str_buf.GetString(), json_len);

  // Send get message
  if( send(bpf_fd_ , static_cast<void*>(snd_buf) , msg_len , 0) < 0)
    {
      LogE(kClassName, __func__, "Sending GET message to BPF failed.\n");
    }

  // delete snd_buf here? 

  return;
}

//=============================================================================
void Oracle::GetJsonMsg(int fd, char *buffer)
// Perhaps replace with remote control class?
{
  std::fill_n(buffer, APP_MAX_BUFLEN, 0);
  bool normalPath = true;
  
  int status = 0;
  size_t tot = 0;

  // Read the length value at the head of the message
  while (tot < 4)
    {
      status = recv(fd, buffer + tot, 4 - tot, 0);
      if (status >= 0)
	{
	  tot += status;
	}
      else
	{ // < 0
	  LogW(kClassName,__func__,
	       "Error reading JSON buffer length from socket.\n");
	  break;
	}
    }
  if (!normalPath)
    {
      LogD(kClassName, __func__, "Couldn't read JSON header\n");
      delete[] buffer;
      return;
    }

  uint32_t len = ntohl(*(uint32_t *) buffer);
  // TODO is  len > APP_MAX_BUFLEN, reallocate the buffer
  status = 0;
  tot    = 0;

  while (tot < len)
    {
      status = recv(fd, buffer + tot, len - tot, 0);
      if (status >= 0)
	{
	  tot += status;
	}
      else
	{ // < 0
	  LogW(kClassName,__func__,
	       "Error receiving buffer from socket: %s", strerror(errno));
	  normalPath = false;
	  break;
	}
    }

  if (!normalPath)
    {
      LogW(kClassName, __func__, "Error reading JSON.\n");
      // need to release buffer;
      delete[] buffer;
      return;
    }
}

//=============================================================================
void Oracle::SendJsonMsg(int sd, Document &query)
// Perhaps replace with remote control class?
{
  StringBuffer str_buf;
  Writer<StringBuffer> writer(str_buf);
  query.Accept(writer);

  // Prepend json message length
  
  int       json_len     = static_cast<int>(str_buf.GetSize());
  uint32_t  json_len_nbo = static_cast<uint32_t>(htonl(json_len));
  int       msg_len      = (json_len + sizeof(json_len_nbo));
  char      *snd_buf     = new char[msg_len];

  ::memcpy(&(snd_buf[0]), &json_len_nbo, sizeof(json_len_nbo));
  ::memcpy(&(snd_buf[sizeof(json_len_nbo)]), str_buf.GetString(), json_len);

  // Send response
  if( send(sd , static_cast<void*>(snd_buf) , msg_len , 0) < 0)
    {
      LogE(kClassName, __func__, "Sending reponse to petitioner failed.\n");
    }

  // delete[] snd_buf here
  
}

//=============================================================================
void Oracle::HandleBpf()
{

  char *buffer = new char[APP_MAX_BUFLEN];
  GetJsonMsg(bpf_fd_, buffer);
  // Parse the reported topology and push it into the Solver
  ParseTopology(buffer);

}

//=============================================================================
void Oracle::HandlePetitioner(int sd)
{
  char *buffer = new char[APP_MAX_BUFLEN];
  GetJsonMsg(sd, buffer);

  if (!topology_initialized_)
    {
      LogW(kClassName, __func__, "Received petition but haven't got a topology yet.\n");

      // Send error message back to peitioner
      Document query;
      query.Parse(buffer);
      Value message;
      message.SetString("Failed: Topology unknown. Repeat query in a few seconds", query.GetAllocator());
      query.AddMember("status", message, query.GetAllocator());
      SendJsonMsg(sd, query);
      return;
    }

  // Parse petition

  Document response = ParsePetition(buffer);
  SendJsonMsg(sd, response);

}

//=============================================================================
void Oracle::ParseTopology(char *buffer)
// Parse BPF JSON response and put information into member variable topology_
{
  Document doc;
  doc.Parse(buffer);
  LogD(kClassName,__func__,"BPF buffer: %s\n", buffer);

  if (!(doc.IsObject()) || !(doc.HasMember("keyvals")) || !(doc["keyvals"].HasMember("cap_and_lat")))
    {
      LogE(kClassName,__func__,"Don't know how to parse this JSON message.\n");
      LogE(kClassName,__func__,"JSON: %s\n", buffer);
      LogE(kClassName,__func__,"Ensure that bpf.cfg has Bpf.IncludeLinkCapacity true.\n");

      return;
    }
  const Value& keyvals = doc["keyvals"];
  const Value& cap_and_lat = keyvals["cap_and_lat"];

  topology_.clear();
  for (Value::ConstMemberIterator itr1 = cap_and_lat.MemberBegin();
       itr1 != cap_and_lat.MemberEnd(); ++itr1)
    {
      // Update the following code if we change how topology is reported by BPF
      // BPF reports links using fake IP addresses where 4th octet is binId
      
      std::string src_ip = itr1->name.GetString();
      uint8_t src_octets[4];
      inet_pton(AF_INET, src_ip.c_str(), src_octets);
      int srcBinId = src_octets[3];
      if (!gnat_nodes_.ValidateBinId(srcBinId))
	{
	  LogF(kClassName, __func__, "srcBinId %i is not valid\n", srcBinId);
	}
	
      for (Value::ConstMemberIterator itr2 = itr1->value.MemberBegin();
	   itr2 != itr1->value.MemberEnd(); ++itr2)
	{
	  std::string dst_ip = itr2->name.GetString();
	  uint8_t dst_octets[4];
	  inet_pton(AF_INET, dst_ip.c_str(), dst_octets);
	  int dstBinId = dst_octets[3];
	  if (!gnat_nodes_.ValidateBinId(dstBinId))
	    {
	      LogF(kClassName, __func__, "dstBinId %i is not valid\n", dstBinId);
	    }
	  double cap = itr2->value[0].GetDouble();
	  double lat = itr2->value[1].GetDouble();
	  TopoLink entry = {srcBinId, dstBinId, cap, lat};
	  topology_.push_back(entry);
	}
    }
  topology_initialized_ = true;
}

//=============================================================================
PrunedTopology Oracle::PruneTopology(double min_cap, double max_lat)
// Remove links that don't meet minCapacity or maxLatency constraints
// Remove uni-directional links
// Prune unreachable nodes and links to unreachable nodes
// Return PrunedTopology object containing
// - vector pruned_topology (links that remain after processing)
// - vector of reachable nodes
// - vector of links that were removed

{
  LogD(kClassName, __func__, "minCap = %f, maxLat = %f\n", min_cap, max_lat);
  Topology pruned_topology;
  pruned_topology = topology_;
  LogD(kClassName, __func__, "topology_:\n");
  for (uint i = 0; i < pruned_topology.size(); i++)
    {
      LogD(kClassName, __func__, "%i -> %i (%f, %f)\n", pruned_topology[i].src, pruned_topology[i].dst,
	   pruned_topology[i].capacity, pruned_topology[i].latency);
    }
  Topology removedLinks;
  removedLinks.clear();
  // Get rid of links that don't meet capacity or latency requirements
  Topology::iterator itr = pruned_topology.begin();
  while (itr != pruned_topology.end())
    {
      double cap = (*itr).capacity;
      double lat = (*itr).latency;
      if ((cap < min_cap) || (lat > max_lat))
	{
	  TopoLink link;
	  link.src = (*itr).src;
	  link.dst = (*itr).dst;
	  removedLinks.push_back(link);
	  LogD(kClassName, __func__, "Pruning link %i -> %i due to link requirements\n",
	       (*itr).src, (*itr).dst);

	  itr = pruned_topology.erase(itr);
	}
      else
	{
	  itr++;
	}
    }

  // Get rid of one-way links

  Topology bidir_topology;
  bidir_topology.clear();

  for (uint i = 0; i < pruned_topology.size(); i++)
    {
      for (uint j = 0; j < pruned_topology.size(); j++)
	{
	  if((pruned_topology[i].src == pruned_topology[j].dst) &&
	     (pruned_topology[i].dst == pruned_topology[j].src))
	    {
	      bidir_topology.push_back(pruned_topology[i]);
	      break;
	    }
	  // If we go through loop completely and don't break out, then it's
	  // a one-way link
	  if (j == pruned_topology.size()-1)
	    {
	      TopoLink link;
	      link.src = pruned_topology[i].src;
	      link.dst = pruned_topology[i].dst;
	      removedLinks.push_back(link);
	      LogD(kClassName, __func__, "Pruning link %i -> %i since it's one-way\n",
		   link.src, link.dst);
	    }
	}
    }

  pruned_topology = bidir_topology;

  int num_links = pruned_topology.size();
  
  // Discard unreachable nodes by starting with this node and adding
  // nodes one hop away to set of seen nodes; iterate over set until it doesn't change
  // Eventually replace this hack with a Dijkstra calculation
  
  std::unordered_set<int> current_node_set;
  std::unordered_set<int> next_node_set;
  // start at this node

  current_node_set.insert(my_bin_id_);
  next_node_set.insert(my_bin_id_);
  while (1) {
    // Iterate over elements in current set
    for (std::unordered_set<int>::iterator itr1=current_node_set.begin();
	 itr1 != current_node_set.end(); itr1++)
      {
	// Search links for ones starting at src
	for (int i = 0; i < num_links; i++){
	  int src_num = pruned_topology[i].src;
	  int dst_num = pruned_topology[i].dst;
	  // Add nodes
	  if (src_num == *itr1){
	    next_node_set.insert(dst_num);
	  }
	}
      }
    // This while loop should never take more than L passes
    // where L is number of links. Maybe replace with loop
    // and add error handling
    if (current_node_set == next_node_set) break;
    current_node_set = next_node_set;
  }

  std::vector<int> reachableNodes;
  reachableNodes.clear();

  // Current_node_set holds all the reachable nodes
  // Store them in an easier to use vector

  for (std::unordered_set<int>::iterator itr1=current_node_set.begin(); itr1 != current_node_set.end(); itr1++)
    {
      reachableNodes.push_back(*itr1);
    }

  // Now get rid of links that are connected to unreachable nodes

  {
    Topology::iterator itr1 = pruned_topology.begin();
    while (itr1 != pruned_topology.end())
      {
  	int src = (*itr1).src;
	int dst = (*itr1).dst;
	// If count is zero, the node is not in the currnet_node_set (i.e., is not reachable)
  	if (current_node_set.count(src) == 0 || current_node_set.count(dst) == 0)
  	  {
	    TopoLink link;
	    link.src = src;
	    link.dst = dst;
	    removedLinks.push_back(link);
	    LogD(kClassName, __func__, "Pruning link %i -> %i attached to unreachable node\n",
	       link.src, link.dst);

  	    // Use returned valid iterator since erase will invalidate iterator
  	    itr1 = pruned_topology.erase(itr1);
  	  }
  	else
  	  {
  	    itr1++;
  	  }
      }
  }
  
  PrunedTopology prunedTopology = {pruned_topology, reachableNodes, removedLinks};
  return prunedTopology;
}

//=============================================================================
Document Oracle::ParsePetition(char *buffer)
// Currently we support three types of petitions.
// A petition is a JSON message and the types are differentiated by the
// "objective" field which can take on values of
// - maxNetworkUtility
// - reachableLANs
// - mcastInfo

{
  LogD(kClassName, __func__, "%s\n", buffer);

  Document query;
  query.Parse(buffer);
  Document response;

  if( (query.IsObject()) && (query.HasMember("objective")))
    {
      if (query["objective"] == "maxNetworkUtility")
	{
	  response = MaximizeNetworkUtility(buffer);
	}
      else if (query["objective"] == "reachableLANs")
	{
	  response = ReachableLANs(buffer);
	}
      else if (query["objective"] == "mcastInfo")
	{
	  response = McastInfo(buffer);
	}
    }
  else
    {
      LogE(kClassName,__func__,"Don't know how to parse this message.\n %s\n", buffer);
      // Add error message to petition and return
      Value message;
      message.SetString("Don't know how to parse this petition", query.GetAllocator());
      query.AddMember("status", message, query.GetAllocator());
      return query;
    }
  return response;
}

//=============================================================================
Document Oracle::MaximizeNetworkUtility(char *buffer)
// Petition format:
// "objective": "maxNetworkUtility"
// "constraints": {"minCapacity": minRate, "maxLatency": maxLat} - optional
// "multicastlows": [array of multicast flows]
//    multicastflow looks like:
//    "src": "srcLanAddress",
//    "dstList": [array of LAN addresses]
//    "pri": priority      (double)
//    "flowRateConstraints": {"lowerRate": double, "upperRate": double}  - optional

// Petition response is query with additional fields
// "status": statusMessage
//       "success" or "failed" or "infeasible problem"
// each multicastflow has additional fields
//    "rate": flowRate     (double)
//       - if it is feasible
//    "unreachableAddrs": [array of unreachable LAN addresses]
//       - if some nodes are unreachable
//    "status": statusMessage (string)
//        current statusMessages are:
//        UNMODIFIED
//         - all destinations are reachable, rate computed
//        MODIFIED
//         - some destinations are reachable, rate computed for reachable destinations
//        REMOVED_SRC_UNREACHABLE
//         - source node is not reachable, so no rate computed
//        REMOVED_SOME_DSTS_IN_SRC_ENCLAVE (
//         - the only reachable destinations are in the source enclave, so no rate computed
//           the transmit rate to nodes in source enclave is not constrained by GNAT nodes
//        REMOVED_ALL_DSTS_UNREACHABLE
//         - no destinations are reachable, so no rate computed

{
  Document query;
  query.Parse(buffer);
  
  LogD(kClassName, __func__, "Objective: %s\n", query["objective"].GetString());
  
  // Prune topology of unreachable nodes and attached links
  // This will be the default topolgoy for the Solver to use
  // Later we will re-prune the topology to account for multicast-flow specific
  // topology constratints
  
  double minCap = 0.0;
  double maxLat = std::numeric_limits<double>::infinity();
  PrunedTopology prunedTopology  = PruneTopology(minCap, maxLat);
  Topology pruned_topology = prunedTopology.remaining_links;
  reachable_nodes_ = prunedTopology.reachable_nodes;
  int num_links = pruned_topology.size();

  for (int i = 0; i < num_links; i++)
    {
      LogD(kClassName, __func__, "%i -> %i: %f, %f\n", pruned_topology[i].src,
	   pruned_topology[i].dst, pruned_topology[i].capacity, pruned_topology[i].latency);
    }

  // Push pruned links down to solver 

  sol_.SetTopology(pruned_topology, reachable_nodes_);

  // Check for well formed JSON petition
  
  if ( !(query.HasMember("multicastflows")) || !(query["multicastflows"].IsArray()))
    {
      LogE(kClassName, __func__, "No multicast flows found in query\n");
      Value message;
      message.SetString("Failed: No multicast flows found in query", query.GetAllocator());
      query.AddMember("status", message, query.GetAllocator());
      return query;

    }      
  Value& multicastflows = query["multicastflows"];
  
  std::vector<std::string> badLanAddresses = CheckLanAddresses(multicastflows);
  
  if (badLanAddresses.size() > 0)
    {
      Value message;
      std::string error("Failed: Unknown LAN addresses: ");
      for (uint j = 0; j < badLanAddresses.size(); j++)
	{
	  error = error + badLanAddresses[j] + ", ";
	}
      message.SetString(error.c_str(), query.GetAllocator());
      query.AddMember("status", message, query.GetAllocator());
      return query;
    }  

  // Need to keep track of which flows are modified or removed due
  // to reachability concerns so that we can associate the Solver
  // responses with the correct flow in the request

  //  std::vector<std::tuple<int, flow_status_t, int> > flow_map;
  FlowMap flow_map;

  int solution_indexber = 0;
  FlowSpec_vec mcast_flows;
  std::vector<int> reachableNodes;

  // flow_map keeps track of modifications to flows. flow_map elements are:
  // Original_flow_number, flow_status (enum), solution_indexber
  // Flow_status can be one of
  //   UNMODIFIED = 0
  //    - rate computed for flow to all specified destinations
  //   MODIFIED
  //    - rate computed for flow to all reachable destinations
  //    - all unreachable destinations listed
  //   REMOVED_SRC_UNREACHABLE
  //    - infeasible flow, so no rate computed
  //   REMOVED_SOME_DSTS_IN_SRC_ENCLAVE
  //    - only reachable nodes are in source enclave, so rate not bounded by GNAT topology
  //   REMOVED_ALL_DSTS_UNREACHABLE
  //    - infeasible since no destinations reachable, so no rate computed

  for (uint i = 0; i < multicastflows.Size(); i++)
    {
      const Value& entry = multicastflows[i];
      FlowSpec flow;
      Ipv4Address src = Ipv4Address(entry["src"].GetString());
      
      int srcBinId = gnat_nodes_.BinIdFromAddress(src);
      flow.src = srcBinId;

      std::vector<int> dstList;
      for (uint j = 0; j < entry["dstList"].Size(); j++)
	{
	  Ipv4Address dst = Ipv4Address(entry["dstList"][j].GetString());
	  int dstBinId = gnat_nodes_.BinIdFromAddress(dst);
	  dstList.push_back(dstBinId);
	}

      flow.dsts = dstList;
      flow.pri = entry["pri"].GetDouble();
      double loRate = 0.0;
      double hiRate = std::numeric_limits<double>::infinity();
      if (entry.HasMember("flowRateConstraints"))
	{
	  if (entry["flowRateConstraints"].HasMember("lowerRate"))
	    {
	      loRate = entry["flowRateConstraints"]["lowerRate"].GetDouble();
	    }
	  if (entry["flowRateConstraints"].HasMember("upperRate"))
	    {
	      hiRate = entry["flowRateConstraints"]["upperRate"].GetDouble();
	    }
	}
      flow.loRate = loRate;
      flow.hiRate = hiRate;

      // Check to see if flow has link constraints

      minCap = 0.0;
      maxLat = std::numeric_limits<double>::infinity();
  
      if (entry.HasMember("linkConstraints"))
	{
	  const Value& constraints = entry["linkConstraints"];
	  if (constraints.HasMember("minCapacity"))
	    {
	      minCap = constraints["minCapacity"].GetDouble();
	    }
	  if (constraints.HasMember("maxLatency"))
	    {
	      maxLat = constraints["maxLatency"].GetDouble();
	    }
	}

      prunedTopology = PruneTopology(minCap, maxLat);
      reachableNodes = prunedTopology.reachable_nodes;
      Topology removedLinks   = prunedTopology.removed_links;
      
      // Test to see if sources and/or destinations are reachable

      FlowMapEntry flow_map_entry;
      std::vector<int> dest_list;
      flow_map_entry.flow_num = i;
      srcBinId = flow.src;

      FlowDests dests = FlowStatus(flow, reachableNodes);

      flow_map_entry.status = dests.flow_status;
      switch (dests.flow_status)
	{
	case UNMODIFIED:
	case MODIFIED:
	  {
	    flow_map_entry.solution_index = solution_indexber++;

	    flow.dsts = dests.dest_list;
	    flow.prohibLinks = removedLinks;
	    mcast_flows.push_back(flow);
	    break;
	  }
	case REMOVED_SRC_UNREACHABLE:
	case REMOVED_SOME_DSTS_IN_SRC_ENCLAVE:
	case REMOVED_ALL_DSTS_UNREACHABLE:
	default:
	  // -1 means this flow is not pushed to Solver
	  flow_map_entry.solution_index = -1;
	}

      flow_map.push_back(flow_map_entry);
    }

  sol_.SetMcastFlows(mcast_flows);

  ApplicationReturnStatus status = sol_.Solve();

  if ((status == Solve_Succeeded) || (status == Solved_To_Acceptable_Level))
    {
      std::vector<double> solution;
      sol_.GetSolution(solution);

      // Create query response
      // Add status and rate to each multicast flow entry
  
      for (uint i = 0; i < multicastflows.Size(); i++)
	{
	  Value& entry = multicastflows[i];
      
	  FlowMapEntry flow_map_entry;
	  flow_map_entry = flow_map[i];
	  flow_status_t stat = flow_map_entry.status;
	  int new_index = flow_map_entry.solution_index;

	  if (new_index >= 0)
	    {
	      entry.AddMember("rate", solution[new_index], query.GetAllocator());
	    }
	  
	  Value status;
	  status.SetInt(flow_map_entry.status);
	  entry.AddMember("status", status, query.GetAllocator());

	  if (stat == MODIFIED)
	    {
	      // Walk list of destinations, checking to see which ones are unreachable
	  
	      Value unreachNodes(kArrayType);
	      Document::AllocatorType& allocator = query.GetAllocator();
	  
	      for (uint j = 0; j < entry["dstList"].Size(); j++)
		{
		  std::string dstIp (entry["dstList"][j].GetString());
		  Ipv4Address dst = Ipv4Address(dstIp);
		  int dstBinId = gnat_nodes_.BinIdFromAddress(dst);
		  if (std::find(reachableNodes.begin(), reachableNodes.end(), dstBinId)
		      == reachableNodes.end())
		    {
		      Value lanAddr;
		      lanAddr.SetString(dstIp.c_str(), allocator);
		      unreachNodes.PushBack(lanAddr, allocator);
		    }
		}
	      entry.AddMember("unreachableAddrs", unreachNodes, allocator);
	    }
	}
      // Add overall status message
      Document::AllocatorType& allocator = query.GetAllocator();
      Value status;
      status.SetString("Success", allocator);
      query.AddMember("status", status, allocator);
    }
  else if (status == Infeasible_Problem_Detected)
    {
      // Generate error message
      Document::AllocatorType& allocator = query.GetAllocator();
      Value status;
      status.SetString("Infeasible Problem", allocator);
      query.AddMember("status", status, allocator);
    }
  else
    {
      // Generate error message
      Document::AllocatorType& allocator = query.GetAllocator();
      Value status;
      status.SetString("Failed: Could Not Solve Problem", allocator);
      query.AddMember("status", status, allocator);
    }

  return query;

}

//=============================================================================
Document Oracle::ReachableLANs(char *buffer)
// Return all the LAN subnets that are reachable from the BPF providing
// connectivity info. We assume that the petitioner is reachable from the oracle
// the BPF is reachable from the oracle, so this is reasonable

// Petition has form:
// "objective": "reachableLANs"
// "constraints": ["minCapacity": minRate, "maxLatency": maxLat] - optional

// Petition response is query with additional fields
// "status": statusMessage
//         "success" or "failed"
// "reachableLANs": [array of LAN subnets]

{
  Document query;
  query.Parse(buffer);

  LogD(kClassName, __func__, "Objective: %s\n", query["objective"].GetString());
  double minCap = 0.0;
  double maxLat = std::numeric_limits<double>::infinity();
  
  if (query.HasMember("linkConstraints"))
    {
      const Value& constraints = query["linkConstraints"];
      if (constraints.HasMember("minCapacity"))
	{
	  minCap = constraints["minCapacity"].GetDouble();
	}
      if (constraints.HasMember("maxLatency"))
	{
	  maxLat = constraints["maxLatency"].GetDouble();
	}
    }

  PrunedTopology prunedTopology = PruneTopology(minCap, maxLat);
  std::vector<int> reachableNodes = prunedTopology.reachable_nodes;
  Document::AllocatorType& allocator = query.GetAllocator();
  Value reachableLans(kArrayType);

  // Loop over reachable nodes adding LAN subnets to query
  for (uint i = 0; i < reachableNodes.size(); i++)
    {
      std::vector<std::string> subnets = gnat_nodes_.SubnetsFromBinId(reachableNodes[i]);
      for (uint j = 0; j < subnets.size(); j++)
	{
	  Value lanAddr;
	  lanAddr.SetString(subnets[j].c_str(), allocator);
	  reachableLans.PushBack(lanAddr, allocator);
	}
    }
  query.AddMember("reachableLANs", reachableLans, allocator);
  Value status;
  status.SetString("Success", allocator);
  query.AddMember("status", status, allocator);

  return query;
}

//=============================================================================
Document Oracle::McastInfo(char *buffer)
// Petition format:
// "objective": "mcastInfo",
// 
{
  Document query;
  query.Parse(buffer);

  LogD(kClassName, __func__, "Objective: %s\n", query["objective"].GetString());

  // Compute reachable nodes
  
  double minCap = 0.0;
  double maxLat = std::numeric_limits<double>::infinity();
  
  if (query.HasMember("linkConstraints"))
    {
      const Value& constraints = query["linkConstraints"];
      if (constraints.HasMember("minCapacity"))
	{
	  minCap = constraints["minCapacity"].GetDouble();
	}
      if (constraints.HasMember("maxLatency"))
	{
	  maxLat = constraints["maxLatency"].GetDouble();
	}
    }

  // Baseline topology for all unicast flows
  PrunedTopology prunedTopology = PruneTopology(minCap, maxLat);
  reachable_nodes_ = prunedTopology.reachable_nodes;
  Topology pruned_topology = prunedTopology.remaining_links;
  
  sol_.SetTopology(pruned_topology, reachable_nodes_);

  // Setup unicast flow to each destination
  
  FlowSpec_vec mcast_flows;
  FlowSpec flow;
  flow.src = my_bin_id_;
  std::vector<int> dest_list; // destinations
  flow.pri = 1.0; // priority
  flow.loRate = 0.0; // min rate
  flow.hiRate = std::numeric_limits<double>::infinity(); // max rate

  // Storage for response
  Document::AllocatorType& allocator = query.GetAllocator();
  Value mcast_info(kArrayType);

  bool success = true;
  for (uint i = 0; i < reachable_nodes_.size(); i++)
    {
      if (reachable_nodes_[i] != my_bin_id_)
	{
	  dest_list.clear();
	  dest_list.push_back(reachable_nodes_[i]);
	  flow.dsts = dest_list;
	  mcast_flows.clear();
	  mcast_flows.push_back(flow);

	  sol_.SetMcastFlows(mcast_flows);

	  ApplicationReturnStatus status = sol_.Solve();

	  Value destInfo(kObjectType);
	  if ((status == Solve_Succeeded) || (status == Solved_To_Acceptable_Level))
	    {
	      std::vector<double> solution;
	      sol_.GetSolution(solution);

	      destInfo.AddMember("rate", solution[0], allocator);

	      Value reachableLans(kArrayType);
	      
	      // Add to petition response
	      std::vector<std::string> subnets = gnat_nodes_.SubnetsFromBinId(reachable_nodes_[i]);
	      for (uint j = 0; j < subnets.size(); j++)
		{
		  Value lanAddr;
		  lanAddr.SetString(subnets[j].c_str(), allocator);
		  reachableLans.PushBack(lanAddr, allocator);
		}
	      destInfo.AddMember("subnets", reachableLans, allocator);
	      mcast_info.PushBack(destInfo, allocator);
	    }
	  else
	    {
	      success = false;
	    }
	}
    }
  if (success)
    {
      query.AddMember("mcastInfo", mcast_info, allocator);
      Document::AllocatorType& allocator = query.GetAllocator();
      Value status;
      status.SetString("Success", allocator);
      query.AddMember("status", status, allocator);
    }
  else
    {
      Document::AllocatorType& allocator = query.GetAllocator();
      Value status;
      status.SetString("Failure", allocator);
      query.AddMember("status", status, allocator);
    }

  return query;
}

//=======================================================================
FlowDests Oracle::FlowStatus(FlowSpec flow,  std::vector<int> reachableNodes)
{
  int srcBinId = flow.src;
  // Test if source is unreachable. If yes, don't add multicast flow
  FlowDests value;
  std::vector<int>::iterator it = std::find(reachableNodes.begin(),
					    reachableNodes.end(), srcBinId);
  if (it == reachableNodes.end())
    {
      LogD(kClassName, __func__, "All flows from %i removed as source is not reachable\n",srcBinId);
      value.flow_status = REMOVED_SRC_UNREACHABLE;
      // dest_list is initialized empty
      return value;
    }
  else
    {
      std::vector<int> dstBinId_vec = flow.dsts;

      // Make sure that dstBinId_vec does not contain source binId 
      // This could happen if you're sending to other nodes in the source LAN
      // Just exclude them from the computation as we assume LAN BW is not a constraint

      bool dstInSrcEnclave = false;
      {
	std::vector<int>::iterator itr = dstBinId_vec.begin();
	while (itr != dstBinId_vec.end())
	  {
	    if (srcBinId == *itr)
	      {
		itr = dstBinId_vec.erase(itr);
		dstInSrcEnclave = true;
	      }
	    else
	      {
		itr++;
	      }
	  }
      }
      // Loop over destinations to see if they're reachable

      bool dsts_unreachable = false;

      for (uint j = 0; j < dstBinId_vec.size(); j++)
	{
	  int dstBinId = dstBinId_vec[j];
	  // If destination is unreachable, don't add that destination.
	  it = std::find(reachableNodes.begin(), reachableNodes.end(), dstBinId);
	  if (it == reachableNodes.end())
	    {
	      LogD(kClassName, __func__, "Flow from %i->%i removed as destination is not reachable\n",
		   srcBinId, dstBinId);
	      dsts_unreachable = true;
	    }
	  else
	    // Destination is OK, check if it's duplicate
	    // Duplicate destinations can occur in the binIds if multiple application
	    // nodes are destinations on the same LAN
	    {
	      bool noDup = true;
	      for (uint k = 0; k < j; k++)
		{
		  if (dstBinId == dstBinId_vec[k])
		    {
		      LogD(kClassName, __func__, "Removing duplicate destination\n");
		      noDup = false;
		      break;
		    }
		}
	      if (noDup)
		{
		  value.dest_list.push_back(dstBinId);
		}
	    }
	}
      // If some destinations are reachable, then that flow is included in
      // maxNetworkUtility computation
      if (value.dest_list.size() > 0)
	{
	  // No destinations removed so flow is unmodified
	  if (!dsts_unreachable)
	    {
	      value.flow_status = UNMODIFIED;
	    }
	  else
	    // Else some destinations were remove and flow is modified
	    {
	      value.flow_status =  MODIFIED;
	    }
	}
      // Else destination list is empty so these flowsares removed from computation
      else if (dstInSrcEnclave)
	// Some destinations were in source enclave, so rate to those nodes
	// is unbounded
	{
	  value.flow_status = REMOVED_SOME_DSTS_IN_SRC_ENCLAVE;
	}
      else
	{
	  value.flow_status = REMOVED_ALL_DSTS_UNREACHABLE;
	}
    }
  return value;
}

std::vector<std::string> Oracle::CheckLanAddresses(Value& multicastflows)
// Verify that all LAN addresses are associated with a binId for an external GNAT node
{
  // Check that all LAN IP addresses map into valid binIds
  std::vector<std::string> badLanAddresses;
  for (uint i = 0; i < multicastflows.Size(); i++)
    {
      const Value& entry = multicastflows[i];
      Ipv4Address src = Ipv4Address(entry["src"].GetString());
      int srcBinId = gnat_nodes_.BinIdFromAddress(src);
      if (srcBinId == kInvalidBinId)
	{
	  badLanAddresses.push_back(entry["src"].GetString());
	}

      std::vector<int> dstList;
      for (uint j = 0; j < entry["dstList"].Size(); j++)
	{
	  Ipv4Address dst = Ipv4Address(entry["dstList"][j].GetString());
	  int dstBinId = gnat_nodes_.BinIdFromAddress(dst);
	  if (dstBinId == kInvalidBinId)
	    {
	      badLanAddresses.push_back(entry["dstList"][j].GetString());
	    }
	}
    }
  return badLanAddresses;
}
