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

#include "amp.h"
#include "config_info.h"
#include "iron_types.h"
#include "itime.h"
#include "log.h"
#include "string_utils.h"
#include "svcr.h"
#include "unused.h"

#include <cstdlib>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <limits>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <vector>

using ::iron::Amp;
using ::iron::FlowInfo;
using ::iron::FourTuple;
using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::Log;
using ::iron::StringUtils;
using ::iron::Time;
using ::std::string;
using ::iron::FlowDefn;
using ::iron::SvcDefn;
using ::std::list;
using ::rapidjson::Value;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;

namespace
{
  /// The default remote control BPF port number.
  const uint16_t  kDefaultBpfCtlPort              = 5560;

  /// The default remote control TCP port number for the UDP Proxy.
  const uint16_t  kDefaultUdpProxyCtlPort         = 3144;

  /// The default remote control TCP port number for the TCP Proxy.
  const uint16_t  kDefaultTcpProxyCtlPort         = 3145;

  /// The default remote control TCP port number for the GUI.
  const uint16_t  kDefaultGuiPort                 = 3140;

  // The default stat reporting interval for the supervisory controller.
  const double    kDefaultStatIntervalS           = 0.5;

  /// The default start-up delay before which AMP checks to triage flows.
  const uint32_t  kDefaultStartupIntvMs           = 10000;

  /// The default interval at which AMP checks to triage flows.
  const uint32_t  kDefaultTriageIntvMs            = 2000;

  /// The default interval at which stats are sent to the GUI in milliseconds.
  const uint32_t  kDefaultGuiPushIntvMs           = 1000;

  /// The default msg id for the push request to the supervisory controller.
  const uint8_t   kDefaultStatMsgId               = 10;

  /// Supervisory control is disabled by default.
  const bool      kDefaultSupervisoryCtl          = true;

  /// Thrash triage is disabled by default.
  const bool      kDefaultDoThrashTriage          = true;

  /// The default number of buckets used in the flow definition hash table.
  /// This value supports fast lookups with up to 10,000 flows.
  const size_t    kDefaultFlowDefHashTableBuckets = 32768;

  /// The maximum queue trajectory. This number indicates how far in the past,
  /// in terms of number of updates, to see if the queue is growing.
  const int8_t    kDefaultMaxQueueTrajectory      = 8;

  const char* UNUSED(kClassName)                  = "Amp";
}

//=============================================================================
Amp::Amp(Timer& timer, const string& cmd_file)
    : connection_map_(),
      flow_def_cache_(),
      svc_def_cache_(),
      msg_endpoint_map_(),
      reconnect_map_(),
      rc_connect_(true),
      rc_client_(),
      rc_server_(),
      aggregate_outbound_capacity_(0),
      timer_(timer),
      cmd_file_name_(cmd_file), read_fds_(), max_fds_(0),
      cmds_(), next_server_id_(1), gui_ep_(NULL),
      stat_interval_s_(kDefaultStatIntervalS),
      stat_msg_id_(kDefaultStatMsgId),
      smallest_pending_traf_(std::numeric_limits<double>::max()),
      triage_interval_ms_(kDefaultTriageIntvMs),
      gui_push_interval_ms_(kDefaultGuiPushIntvMs),
      triage_timer_handle_(),
      gui_push_timer_handle_(),
      cached_push_req_(),
      enable_supervisory_ctl_(kDefaultSupervisoryCtl),
      enable_thrash_triage_(kDefaultDoThrashTriage),
      running_(true),
      supervisory_ctl_(NULL),
      k_val_(kDefaultK),
      udp_str_buf_(),
      udp_last_msg_id_(0),
      tcp_str_buf_(),
      tcp_last_msg_id_(0),
      bpf_str_buf_(),
      bpf_last_msg_id_(0),
      avg_queue_depths_(),
      max_queue_depths_(),
      max_queue_trajectory_(),
      default_utility_fns_()
{
}

//=============================================================================
Amp::~Amp()
{
  if (triage_timer_handle_.id() != 0)
  {
    timer_.CancelTimer(triage_timer_handle_);
    triage_timer_handle_.Clear();
  }

  if (gui_push_timer_handle_.id() != 0)
  {
    timer_.CancelTimer(gui_push_timer_handle_);
    gui_push_timer_handle_.Clear();
  }
  CallbackNoArg<Amp>::EmptyPool();

  if (supervisory_ctl_ != NULL)
  {
    delete supervisory_ctl_;
  }
}

//=============================================================================
bool Amp::Initialize(const ConfigInfo& config_info)
{
  LogI(kClassName, __func__, "Configuring Amp...\n");

  // Read the config files and get the control port number for the proxy.
  uint16_t  bpf_ctl_port        =
    static_cast<uint16_t>(config_info.GetUint("Bpf.RemoteControl.Port",
                                              kDefaultBpfCtlPort));

  uint16_t  udp_proxy_ctl_port =
    static_cast<uint16_t>(config_info.GetUint("Udp.RemoteControl.Port",
                                              kDefaultUdpProxyCtlPort));

  uint16_t  tcp_proxy_ctl_port =
    static_cast<uint16_t>(config_info.GetUint("Tcp.RemoteControl.Port",
                                              kDefaultTcpProxyCtlPort));

  uint16_t  gui_ctl_port =
    static_cast<uint16_t>(config_info.GetUint("Gui.RemoteControl.Port",
                                              kDefaultGuiPort));

  enable_supervisory_ctl_      =
    config_info.GetBool("Amp.EnableSupervisoryCtl", kDefaultSupervisoryCtl);

  enable_thrash_triage_        =
    config_info.GetBool("Amp.EnableThrashTriage", kDefaultDoThrashTriage);

  double double_k = config_info.GetDouble("KVal", kDefaultK);
  if (double_k > std::numeric_limits<uint64_t>::max())
  {
    LogE(kClassName, __func__, "k val is too large.\n");
    k_val_ = static_cast<uint64_t>(kDefaultK);
  }
  else
  {
    k_val_ = static_cast<uint64_t>(double_k);
  }

  triage_interval_ms_ =
    static_cast<uint32_t>(config_info.GetUint("Amp.TriageIntervalMs",
    kDefaultTriageIntvMs));

  // Initialize the hash table for the flow_def_cache
  if (!flow_def_cache_.Initialize(kDefaultFlowDefHashTableBuckets))
  {
    LogF(kClassName, __func__, "Unable to initialize hash tables.\n");
    return false;
  }

  for (size_t i = 0; i < kMaxBinId; i++)
  {
    avg_queue_depths_[i] = 0;
    max_queue_trajectory_[i] = 0;
  }

  // Setup the default utility functions.
  default_utility_fns_["udp_proxy"]["LOG"]   = kDefaultUdpLogUtilityDefn;
  default_utility_fns_["udp_proxy"]["STRAP"] = kDefaultStrapUtilityDefn;
  default_utility_fns_["tcp_proxy"]["LOG"]   = kDefaultTcpLogUtilityDefn;

  LogC(kClassName, __func__, "AMP configuration:\n");
  LogC(kClassName, __func__,
       "BPF control port                        : %" PRIu16 "\n",
       bpf_ctl_port);
  LogC(kClassName, __func__,
       "UDP proxy control port                  : %" PRIu16 "\n",
       udp_proxy_ctl_port);
  LogC(kClassName, __func__,
       "TCP proxy control port                  : %" PRIu16 "\n",
       tcp_proxy_ctl_port);
  LogC(kClassName, __func__,
       "GUI control port                        : %" PRIu16 "\n",
       gui_ctl_port);
  LogC(kClassName, __func__,
       "Triage interval is in ms                : %" PRIu32 "\n",
       triage_interval_ms_);
  LogC(kClassName, __func__,
       "kVal                                    : %" PRIu64 "\n",
       k_val_);
  LogC(kClassName, __func__,
       "Supervisory Control enabled             : %s \n",
       enable_supervisory_ctl_ ? "true" : "false");
  LogC(kClassName, __func__,
       "Thrash triage enabled                   : %s \n",
       enable_thrash_triage_ ? "true" : "false");
  LogC(kClassName, __func__, "AMP configuration complete.\n");

  if (rc_connect_)
  {
    // Connect to the BPF.
    struct sockaddr_in  bpf_addr;
    ::memset(&bpf_addr, 0, sizeof(bpf_addr));
    bpf_addr.sin_family       = AF_INET;
    bpf_addr.sin_addr.s_addr  = htonl(INADDR_LOOPBACK);
    bpf_addr.sin_port         = htons(bpf_ctl_port);
    uint32_t ep_id            = 0;

    int count = 0;

    while ((ep_id = rc_client_.Connect(bpf_addr)) == 0)
    {
      // Sleep for 1 sec and retry
      sleep(1);
      if (++count > kMaxNumRetries)
      {
        LogE(kClassName, __func__,
             "Unable to connect to the bpf after %" PRIu32
             " attempts. Deferring\n",kMaxNumRetries);
        break;
      }
    }

    if (ep_id != 0)
    {
      connection_map_["bpf"] = ep_id;
    }
    else
    {
      reconnect_map_["bpf"] = bpf_addr;
    }

    // Connect to the UDP proxy
    struct sockaddr_in  udp_addr;
    ::memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family      = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    udp_addr.sin_port        = htons(udp_proxy_ctl_port);

    count = 0;

    while ((ep_id = rc_client_.Connect(udp_addr)) == 0)
    {
      // Sleep for 1 sec and retry
      sleep(1);
      if (++count > kMaxNumRetries)
      {
        LogE(kClassName, __func__,
             "Unable to connect to the udp_proxy after %" PRIu32
             " attempts. Deferring\n",kMaxNumRetries);
        break;
      }
    }

    if (ep_id != 0)
    {
      connection_map_["udp_proxy"] = ep_id;
    }
    else
    {
      reconnect_map_["udp_proxy"] = udp_addr;
    }

    // Connect to the TCP proxy
    struct sockaddr_in  tcp_addr;
    ::memset(&tcp_addr, 0, sizeof(tcp_addr));
    tcp_addr.sin_family      = AF_INET;
    tcp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    tcp_addr.sin_port        = htons(tcp_proxy_ctl_port);

    count = 0;

    while ((ep_id = rc_client_.Connect(tcp_addr)) == 0)
    {
      // Sleep for 1 sec and retry
      sleep(1);
      if (++count > kMaxNumRetries)
      {
        LogE(kClassName, __func__,
             "Unable to connect to the tcp_proxy after %" PRIu32
             " attempts. Deferring\n",kMaxNumRetries);
        break;
      }
    }

    if (ep_id != 0)
    {
      connection_map_["tcp_proxy"] = ep_id;
    }
    else
    {
      reconnect_map_["tcp_proxy"] = tcp_addr;
    }
  }

  // Open server socket for GUI connections.
  if (!rc_server_.Initialize(gui_ctl_port))
  {
    LogF(kClassName, __func__,
      "Unable to initialize remote control communications module to GUI.\n");
    return false;
  }

  // Set up supervisory control.
  supervisory_ctl_ = new (std::nothrow) Svcr(k_val_, *this);

  if (supervisory_ctl_ == NULL)
  {
    LogF(kClassName, __func__, "Failed to allocate supervisory control.\n");
    return false;
  }

  return true;
}

//=============================================================================
void Amp::Start()
{
  Time start_time = Time::Now();
  uint32_t curr_cmd = 0;

  fd_set           read_fds;

  LogD(kClassName, __func__, "Starting Amp.\n");

  // Load the command file if there is one.
  if(cmd_file_name_ != "")
  {
    LoadCmdFile();
  }

  if (enable_supervisory_ctl_)
  {
    StartStatsCollection(string("bpf"));
    StartStatsCollection(string("udp_proxy"));
    StartStatsCollection(string("tcp_proxy"));
    CallbackNoArg<Amp>  cb(this, &Amp::ConsiderTriage);
    Time                delta_time  = Time::FromMsec(kDefaultStartupIntvMs);

    if (!timer_.StartTimer(delta_time, &cb, triage_timer_handle_))
    {
      LogE(kClassName, __func__,
         "Error starting triage timer.\n");
    }
  }

  while(running_)
  {
    Time now = Time::Now();
    FD_ZERO(&read_fds);
    int max_fd = 0;
    rc_client_.AddFileDescriptors(max_fd,read_fds);
    rc_server_.AddFileDescriptors(max_fd,read_fds);

    // Get the relative time to send the next command.
    Time cmd_time = Time::Infinite();
    if (curr_cmd < cmds_.size())
    {
      LogD(kClassName, __func__, "cmd %u of %u\n", curr_cmd, cmds_.size());
      cmd_time = Time::Max((start_time + cmds_[curr_cmd].time_ - now),Time(0));
    }

    // Get the next expiration time from the timer.
    Time next_exp_time = timer_.GetNextExpirationTime();

    struct timeval  cmd_time_tv = Time::Min(cmd_time, next_exp_time).ToTval();

    LogD(kClassName, __func__, "TIMER: select timeout in %d microseconds.\n",
      cmd_time_tv.tv_usec + (1000000 * cmd_time_tv.tv_sec));

    int  num_fds = select(max_fd + 1, &read_fds, NULL, NULL,
                          &cmd_time_tv);

    // Out of the select call, first process any messages received.
    if (num_fds < 0)
    {
      LogE(kClassName, __func__, "select() error: errno is %d\n",
	errno);
    }
    else if (num_fds > 0)
    {
      if (rc_client_.ServiceFileDescriptors(read_fds))
      {
        // Process a received remote control message.
        ProcessClientRemoteControlMessage();
      }

      if (rc_server_.ServiceFileDescriptors(read_fds))
      {
        // Process a received remote control message.
        ProcessServerRemoteControlMessage();
      }
    }

    timer_.DoCallbacks();

    // If we have any extant connection failures, see if we can (re)connect.
    if (rc_connect_)
    {
      std::map<string,struct sockaddr_in>::iterator itr =
        reconnect_map_.begin();
      std::vector<string> connections;

      while (itr != reconnect_map_.end())
      {
        connections.push_back(itr->first);
        ++itr;
      }

      std::vector<string>::iterator it = connections.begin();

      while (it != connections.end())
      {
        LogD(kClassName, __func__, "Retrying connection to %s.\n",
             it->c_str());

        uint32_t ep_id = rc_client_.Connect(reconnect_map_[*it]);

        if(ep_id != 0)
        {
          connection_map_[*it] = ep_id;
          reconnect_map_.erase(*it);
          if (enable_supervisory_ctl_)
          {
            StartStatsCollection(*it);
          }
        }
        ++it;
      }
    }

    if (curr_cmd >= cmds_.size())
    {
      continue;
    }

    // Send any AMP command from the command file
    while((now > start_time + Time(cmds_[curr_cmd].time_)))
    {
      if (connection_map_.find(cmds_[curr_cmd].tgt_) != connection_map_.end())
      {
        if (cmds_[curr_cmd].arg2_ != "")
        {
          SendSetMsgToClient(cmds_[curr_cmd].tgt_, cmds_[curr_cmd].cmd_,
            cmds_[curr_cmd].arg1_ + ";" + cmds_[curr_cmd].arg2_);
        }
        else
        {
          SendSetMsgToClient(cmds_[curr_cmd].tgt_, cmds_[curr_cmd].cmd_,
            cmds_[curr_cmd].arg1_);
        }
      }
      else
      {
        LogE(kClassName, __func__, "Invalid target or no connection: %s\n",
                              cmds_[curr_cmd].tgt_.c_str());
      }

      // Update the utility function caches.
      if (cmds_[curr_cmd].cmd_ == "add_service")
      {
        UpdateServiceCache(cmds_[curr_cmd].tgt_, cmds_[curr_cmd].arg1_);
      }
      else if ((cmds_[curr_cmd].cmd_ == "add_flow"))
      {
        //UpdateFlowCache(cmds_[curr_cmd].tgt_ ";" + cmds_[curr_cmd].arg1_,
        //                cmds_[curr_cmd].arg2_);
        UpdateFlowCache(cmds_[curr_cmd].tgt_, cmds_[curr_cmd].arg1_);
      }
      else if (cmds_[curr_cmd].cmd_ == "del_flow")
      {
        DeleteFlow(cmds_[curr_cmd].tgt_ + ";" + cmds_[curr_cmd].arg1_);
      }
      else
      {
        LogE(kClassName, __func__,
          "Unsupported remote control command: %s\n",
          cmds_[curr_cmd].cmd_.c_str());
      }

      LogD(kClassName, __func__, "Sending command - %u.\n", curr_cmd);
      curr_cmd++;

      if (curr_cmd > cmds_.size() -1)
      {
        LogD(kClassName, __func__, "Done executing commands from file.\n");
        break;
      }
    }
  }
}

//=============================================================================
void Amp::StartStatsCollection(string target)
{
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);

  writer.StartObject();

  writer.Key("msg");
  writer.String("pushreq");

  writer.Key("msgid");
  writer.Uint(stat_msg_id_);

  writer.Key("tgt");
  writer.String(target.c_str());

  writer.Key("intv");
  writer.Double(stat_interval_s_);

  writer.Key("keys");
  writer.StartArray();
  writer.Key("stats");
  writer.EndArray();

  writer.EndObject();

  int index = TGT_TO_INDEX(target);

  if (IS_VALID_TGT_INDEX(index))
  {
    if (!SendMessageToClient(connection_map_[target], str_buf))
    {
      LogW(kClassName, __func__,
	   "Failed to send push request to %s.\n", target.c_str());
      return;
    }

    cached_push_req_[index].SetPushReqMsg(target, stat_msg_id_,
					  stat_interval_s_);

    stat_msg_id_++;

    LogD(kClassName, __func__,
	 "Sent push request to %s.\n", target.c_str());
  }
  else
  {
    LogF(kClassName, __func__,
	 "bad target %s index %d\n", target.c_str(), index);
  }
}

//=============================================================================
void Amp::StopStatsCollection(string target)
{
  StringBuffer          str_buf;
  Writer<StringBuffer>  writer(str_buf);
  uint32_t              index = TGT_TO_INDEX(target);

  if (!IS_VALID_TGT_INDEX(index))
  {
    LogF(kClassName, __func__, "Invalid target %s\n.", target.c_str());
    return;
  }

  writer.StartObject();

  writer.Key("msg");
  writer.String("pushstop");

  writer.Key("msgid");
  writer.Uint(stat_msg_id_);
  stat_msg_id_++;

  writer.Key("tgt");
  writer.String(target.c_str());

  writer.Key("to_stop");
  writer.StartArray();
  writer.Uint(cached_push_req_[index].msg_id_);
  writer.EndArray();

  writer.EndObject();

  if (!SendMessageToClient(connection_map_[target], str_buf))
  {
    LogW(kClassName, __func__,
         "Failed to send push stop request to %s.\n", target.c_str());
    return;
  }

  cached_push_req_[index].ResetPushReqMsg();

  LogD(kClassName, __func__,
       "Sent push stop to %s.\n", target.c_str());
}

//=============================================================================
uint32_t  Amp::GetAvgQueueDepth(McastId bin_id)
{
  if (avg_queue_depths_.count(bin_id) > 0)
  {
    return avg_queue_depths_[bin_id];
  }
  return 0;
}

//=============================================================================
bool Amp::LoadCmdFile()
{
  if (cmd_file_name_.empty())
  {
    LogW(kClassName, __func__, "No command file specified.\n");
  }

  FILE*  input_file = ::fopen(cmd_file_name_.c_str(), "r");

  if (input_file == NULL)
  {
    LogF(kClassName, __func__, "Unable to open command file %s\n",
         cmd_file_name_.c_str());
    return false;
  }

  char  line[1024];

  while (::fgets(line, 1024, input_file) != NULL)
  {
    int line_len = ::strlen(line);

    if (line_len <= 1)
    {
      //
      // Skip blank lines.
      //
      continue;
    }
    else if (line[0] == '#')
    {
      //
      // Skip comment lines.
      //
      continue;
    }
    else
    {
      line[line_len - 1] = '\0';
      int time[128];
      char tgt[128];
      char cmd[1024];
      char arg1[1024];
      char arg2[1024];
      int num_param = ::sscanf(line, "%d %[^ ] %[^ ] %[^ ] %[^ ]",
                               time, tgt, cmd, arg1, arg2);
      if (num_param != 4 && num_param != 5)
      {
        LogD(kClassName, __func__, "Invalid command %s\n", line);
        continue;
      }
      LogD(kClassName, __func__, "Storing command %s\n", line);
      CmdEntry new_cmd;
      new_cmd.time_ = *time;
      new_cmd.tgt_ = tgt;
      new_cmd.cmd_ = cmd;
      new_cmd.arg1_ = arg1;
      if (num_param == 5)
      {
        new_cmd.arg2_ = arg2;
      }
      cmds_.push_back(new_cmd);
    }
  }
  ::fclose(input_file);
  return true;
}

//=============================================================================
bool Amp::ProcessClientRemoteControlMessage()
{
  // Switch on the type of request message.
  RmtCntlMsgType  msg_type = GetClientMsgType();
  bool ret_val;
  switch (msg_type)
  {
    case iron::RC_PUSH:
      ret_val = ProcessPushMessage();
      break;

    case iron::RC_SETREPLY:
      ret_val = ProcessSetReplyMessage();
      break;

    case iron::RC_INVALID:
    default:
      LogE(kClassName, __func__, "Unsupported message type\n");
      ret_val = false;
  }
  rc_client_.ResetEndpoint();
  return ret_val;
}

//=============================================================================
bool Amp::ProcessPushMessage()
{
  const Value*  key_vals  = NULL;
  uint32_t      client_id = 0;
  string        target    = "";

  // Get the message contents.
  if ((!rc_client_.GetPushMessage(client_id, key_vals)) || (key_vals == NULL))
  {
    LogE(kClassName, __func__, "Error getting remote control push message.\n");
    return false;
  }

  CachedRCMsg*  cached_rc_msg = NULL;
  if (FindRCMsgFromMsgId(rc_client_.msg_id(), cached_rc_msg))
  {
    if ((cached_rc_msg->type_ == "pushreq") &&
      (cached_rc_msg->msg_id_ != 0))
    {
      if (!rc_client_.SetJsonMsgId(cached_rc_msg->mapped_msg_id_))
      {
        LogE(kClassName, __func__,
             "Failed to set msg id in push.\n");
      }
      else
      {
        LogD(kClassName, __func__,
             "Mapping message id from %" PRIu32 " to %" PRIu32 ".\n",
             rc_client_.msg_id(), cached_rc_msg->mapped_msg_id_);
        rc_client_.set_msg_id(cached_rc_msg->mapped_msg_id_);
      }
    }
  }

  bool is_periodic = true;
  Value::ConstMemberIterator itr = key_vals->FindMember("stats");
  if (itr != key_vals->MemberEnd())
  {
    LogD(kClassName, __func__, "This is a periodic stats push.\n");
  }
  else
  {
    itr = key_vals->FindMember("event_stats");
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__,
        "Push message is neither periodic stats nor event_stats.\n");
      return false;
    }
    LogD(kClassName, __func__, "This is an event stats push.\n");
    is_periodic = false;
  }

  const Value& stats = itr->value;

  if (!stats.IsObject())
  {
    LogE(kClassName, __func__, "Malformed push message stats\n");
    return false;
  }

  // Check if it is from the udp proxy, the tcp proxy, or the bpf.
  if (client_id == connection_map_["udp_proxy"])
  {
    target = "udp_proxy";

    // UDP Stats "keyvals" format.
    //  "stats" :
    //  {
    //    "NumActiveOutboundFlows" : xx,
    //    "NumActiveInboundFlows"  : xx,
    //    "MaxQueueDepthsBytes"    : [ b, n, b, n, b, n ],
    //    "ActiveOutboundFlows" :
    //    [
    //      { "flow_id"         : "a.b.c.d:eph -> e.f.g.h:svc",
    //        "prio"            : xxxx.xxx,
    //        "pkts"            : xxxxxx,
    //        "bytes"           : xxxxxx,
    //        "rate_bps"        : xxxx.xxx,
    //        "rate_pps"        : xxxx.xxx,
    //        "acked_seq_num"   : xxxx,
    //        "loss_rate_pct" : xx,
    //        "utility"         : xxxx.xxx,
    //        "flow_state"      : x,
    //        "bin_id"          : x,
    //        "toggle_count"    " x
    //      },
    //      ...
    //    ],
    //    "ActiveInboundFlows" :
    //    [
    //      { "flow_id"     : "a.b.c.d:eph -> e.f.g.h:svc",
    //        "pkts"        : xxxxxx,
    //        "bytes"       : xxxxxx,
    //        "rate_bps"    : xxxx.xxx,
    //        "rate_pps"    : xxxx.xxx,
    //        "avg_delay_ms": xxx.xxx,
    //        "max_delay_ms": xxx,
    //        "utility"     : xxxx.xxx
    //      },
    //      ...
    //    ],
    //    "CumulativeUtility" : xxxx.xxx,
    //    "KVal" : n
    //  }



    Value::ConstMemberIterator stats_itr
        = stats.FindMember("MaxQueueDepthsBytes");

    if (stats_itr == stats.MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have MaxQueueDepthsBytes.\n");
      return false;
    }

    const Value& bin_depths = stats["MaxQueueDepthsBytes"];
    if (!bin_depths.IsArray())
    {
       LogE(kClassName, __func__,
            "Malformed push message, MaxQueueDepthsBytes in not an array.\n");
       return false;
    }
    for (size_t i = 0; i + 1 < bin_depths.Size(); i = i + 2)
    {
      McastId bin = bin_depths[i].GetUint();
      if ((max_queue_depths_.count(bin) == 0) ||
          (bin_depths[i+1].GetUint() > max_queue_depths_[bin]))
      {
        max_queue_trajectory_[bin] = kDefaultMaxQueueTrajectory;
        max_queue_depths_[bin]     = bin_depths[i+1].GetUint();
      }
      else
      {
        max_queue_trajectory_[bin] = std::max(0,max_queue_trajectory_[bin] - 1);
      }

      LogD(kClassName, __func__, "Bin: %" PRIMcastId ", max depth: %" PRIu32
          "Bytes\n", bin, avg_queue_depths_[bin]);
    }

    stats_itr = stats.FindMember("InactiveOutboundFlows");
    if (stats_itr == stats.MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have Outbound flows.\n");
      return false;
    }

    const Value& inactive_flows = stats["InactiveOutboundFlows"];
    for (rapidjson::SizeType i = 0; i < inactive_flows.Size(); i++)
    {
      const Value& flow = inactive_flows[i];
      string flow_id    = "";

      if (!flow.IsString())
      {
         LogE(kClassName, __func__, "Malformed InactiveOutboundFlows.\n");
         return false;
      }
      else
      {
        flow_id = flow.GetString();
        LogD(kClassName, __func__, "Inactive flow: %s .\n", flow_id.c_str());
        string flow_tuple = ReformatTuple(flow_id);
        if (flow_tuple == "")
        {
          LogE(kClassName, __func__,
               "Unable to process inactive flow. Bad tuple string %s.\n",
               flow_id.c_str());
          continue;
        }
        supervisory_ctl_->DeleteFlowInfo("udp_proxy;" + flow_tuple);
      }
    }

    stats_itr = stats.FindMember("ActiveOutboundFlows");
    if (stats_itr == stats.MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have Outbound flows.\n");
      return false;
    }
    const Value& flows = stats["ActiveOutboundFlows"];

    for (rapidjson::SizeType i = 0; i < flows.Size(); i++)
    {
      const Value& flow = flows[i];

      if (!flow.IsObject())
      {
         LogE(kClassName, __func__, "Malformed push message stats\n");
         return false;
      }

      string flow_id = "";
      //double utility = 0;
      double rate_bps = 0;
      ConfigInfo  ci;

      Value::ConstMemberIterator flow_itr = flow.FindMember("flow_id");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsString())
        {
          flow_id = flow_itr->value.GetString();
        }
      }

      flow_itr = flow.FindMember("rate_bps");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsDouble())
        {
          rate_bps = flow_itr->value.GetDouble();
          ci.Add("adm_rate", StringUtils::ToString(rate_bps));
        }
      }

      flow_itr = flow.FindMember("flow_state");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsInt())
        {
          ci.Add("flow_state", StringUtils::ToString(flow_itr->value.GetInt()));
        }
      }

      flow_itr = flow.FindMember("acked_seq_num");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsInt())
        {
          ci.Add("acked_seq_num",
            StringUtils::ToString(flow_itr->value.GetInt()));
        }
      }

      flow_itr = flow.FindMember("pkts");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsInt())
        {
          ci.Add("sent_pkts",
            StringUtils::ToString(flow_itr->value.GetInt()));
        }
      }

      flow_itr = flow.FindMember("loss_rate_pct");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsInt())
        {
          ci.Add("loss_rate_pct",
            StringUtils::ToString(flow_itr->value.GetInt()));
        }
      }

      flow_itr = flow.FindMember("bin_id");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsUint())
        {
          ci.Add("bin_id",
            StringUtils::ToString(flow_itr->value.GetUint()));
        }
      }

      flow_itr = flow.FindMember("src_rate");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsDouble())
        {
          ci.Add("src_rate",
            StringUtils::ToString(flow_itr->value.GetDouble()));
        }
      }

      flow_itr = flow.FindMember("toggle_count");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsUint())
        {
          ci.Add("toggle_count",
            StringUtils::ToString(flow_itr->value.GetUint()));
        }
      }

      ci.Add("proxy", "udp_proxy");
      string  four_tuple = ReformatTuple(flow_id);
      if (four_tuple == "")
      {
        LogE(kClassName, __func__,
             "Unable to process outbound flow. Bad tuple string %s.\n",
             flow_id.c_str());
        continue;
      }
      ci.Add("four_tuple", four_tuple);
      string  five_tuple  = "udp_proxy;" + four_tuple;
      string  utility_fn;
      string  ttg;
      GetUdpFlowParams(five_tuple, utility_fn, ttg);
      ci.Add("ttg", ttg);

      if (!ParseUtilityFn(five_tuple, utility_fn, ci))
      {
        LogE(kClassName, __func__,
            "Could not parse utility function %s.\n",
            utility_fn.c_str());
        continue;
      }

      if (!SanitizeUtilityFn(ci))
      {
        continue;
      }

      supervisory_ctl_->UpdateFlowInfo(ci);
    }

    stats_itr = stats.FindMember("KVal");
    if (stats_itr == stats.MemberEnd())
    {
      LogE(kClassName, __func__, "Push msg does not have k value.\n");
      return false;
    }
    if (!stats_itr->value.IsUint64())
    {
      LogE(kClassName, __func__, "Malformed push message from UDP proxy: "
           "k value must be an int.\n");
      return false;
    }
    k_val_ = stats_itr->value.GetUint64();
    LogD(kClassName, __func__, "UDP proxy advertised K value %" PRIu64 ".\n",
      stats_itr->value.GetUint64());
  }
  else if (client_id == connection_map_["tcp_proxy"])
  {
    target = "tcp_proxy";
    // TCP Stats "keyvals" format.
    // "stats" :
    // {
    //   "Flows" :
    //   [
    //     { "flow_id"                   : "a.b.c.d:eph -> a.b.c.d:svc",
    //       "priority"                  : xx.xx,
    //       "bin_id"                    : x,
    //       "flow_state"                : x,
    //       "cumulative_sent_pkt_cnt"   : xxxx,
    //       "cumulative_sent_bytes_cnt" : xxxx,
    //       "cumulative_acked_bytes"    : xxxx,
    //       "send_rate_bps"             : x.x,
    //       "send_rate_pps"             : x.x,
    //       "cumulative_rcvd_pkt_cnt"   : xxxx,
    //       "cumulative_rcvd_bytes_cnt" : xxxx,
    //       "recv_rate_bps"             : xx.xx,
    //       "recv_rate_pps"             : xx.xx,
    //       "ave_instantaneous_utility" : xx.xx
    //     },
    //     ...
    //   ],
    //   "NumActiveFlows"                    : xx,
    //   "CumulativeAveInstantaneousUtility" : xx.xx,
    //   "CumulativeAggregateUtility"        : xx.xx
    // }

    Value::ConstMemberIterator stats_itr =
      stats.FindMember("Flows");

    if (stats_itr == stats.MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have any flow.\n");
      return false;
    }
    const Value& flows = stats["Flows"];

    for (rapidjson::SizeType i = 0; i < flows.Size(); i++)
    {
      const Value& flow = flows[i];

      if (!flow.IsObject())
      {
         LogE(kClassName, __func__, "Malformed push message stats\n");
         return false;
      }

      string flow_id = "";
      double utility = 0;
      double rate_bps = 0;
      ConfigInfo  ci;

      Value::ConstMemberIterator flow_itr = flow.FindMember("flow_id");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsString())
        {
          flow_id = flow_itr->value.GetString();
        }
      }

      flow_itr = flow.FindMember("bin_id");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsUint())
        {
          ci.Add("bin_id",
            StringUtils::ToString(flow_itr->value.GetUint()));
        }
      }

      flow_itr = flow.FindMember("flow_state");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsInt())
        {
          ci.Add("flow_state", StringUtils::ToString(flow_itr->value.GetInt()));
        }
      }

      flow_itr = flow.FindMember("ave_instantaneous_utility");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsDouble())
        {
          utility = flow_itr->value.GetDouble();
          ci.Add("utility", StringUtils::ToString(utility));
        }
      }

      flow_itr = flow.FindMember("send_rate_bps");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsDouble())
        {
          rate_bps = flow_itr->value.GetDouble();
          ci.Add("adm_rate", StringUtils::ToString(rate_bps));
        }
      }

      flow_itr = flow.FindMember("cumulative_acked_bytes");
      if (flow_itr != flow.MemberEnd())
      {
        if (flow_itr->value.IsUint64())
        {
          uint64_t acked_bytes = flow_itr->value.GetUint64();
          ci.Add("cumulative_acked_bytes", StringUtils::ToString(acked_bytes));
        }
      }

      ci.Add("proxy", "tcp_proxy");
      string  four_tuple = ReformatTuple(flow_id);
      if (four_tuple == "")
      {
        LogE(kClassName, __func__,
             "Unable to process flow. Bad flow string %s.\n", flow_id.c_str());
        continue;
      }
      ci.Add("four_tuple", four_tuple);
      string  five_tuple  = "tcp_proxy;" + four_tuple;
      string  utility_fn;
      GetUtilityFn(five_tuple, utility_fn);

      if (!ParseUtilityFn(five_tuple, utility_fn, ci))
      {
        LogE(kClassName, __func__,
            "Could not parse utility function %s.\n",
            utility_fn.c_str());
        continue;
      }

      if (!SanitizeUtilityFn(ci))
      {
        continue;
      }

      supervisory_ctl_->UpdateFlowInfo(ci);
    }
  }
  else if (client_id == connection_map_["bpf"])
  {
  // Original format supporting only unicast

  // BPF stats "keyvals" format.  Note that "b" is "Uint" and "n" is "Uint".
  //  "stats" :
  //  {
  //    "BpfToPcBytes" :
  //    {
  //      "xxx.xxx.xxx.xxx" : [ b, n, b, n, b, n ],
  //      "yyy.yyy.yyy.yyy" : [ b, n, b, n, b, n ],
  //      ...
  //    },
  //    "PcToBpfBytes" :
  //    {
  //      "xxx.xxx.xxx.xxx" : [ b, n, b, n, b, n ],
  //      "yyy.yyy.yyy.yyy" : [ b, n, b, n, b, n ],
  //      ...
  //    },
  //    "BpfToProxyBytes" :
  //    {
  //      "TCP" : [ b, n, b, n, b, n ],
  //      "UDP" : [ b, n, b, n, b, n ]
  //    },
  //    "ProxyToBpfBytes" :
  //    {
  //      "TCP" : [ b, n, b, n, b, n ],
  //      "UDP" : [ b, n, b, n, b, n ]
  //    },
  //    "AvgQueueDepthsBytes" :
  //    [ b, n, b, n, b, n ],
  //    "PcProperties" :
  //    {
  //      "xxx.xxx.xxx.xxx-i" : {capacity:n, latencies:{"binx": l1, "biny": l2,..}},
  //      "yyy.yyy.yyy.yyy-i" : {capacity:m, latencies:{"binx": l3, "biny": l2,..}},
  //      ...
  //    }
  //  }

  // New format supporting multicast

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

    // TODO: Near term this code has been modified to pull just the unicast information
    // out o fthe new format, so that

    target = "bpf";
    Value::ConstMemberIterator stats_itr
        = stats.FindMember("PcProperties");
    if (stats_itr == stats.MemberEnd())
    {
      LogE(kClassName, __func__, "Push msg does not have per-pc capacity.\n");
      return false;
    }
    LogD(kClassName, __func__,
	 "Looking for AvgQueueDepthsBytes object.\n");
    const Value& bin_depths = stats["AvgQueueDepthsBytes"];
    if (!bin_depths.IsObject())
    {
      LogE(kClassName, __func__,
	   "Malformed push message, AvgQueueDepthsBytes in not an object.\n");
      return false;
    }
    const Value& grp_bin_depths = bin_depths["unicast"];
    if (!grp_bin_depths.IsArray())
    {
      LogE(kClassName, __func__,
	   "AvgQueueDepthsBytes unicast information not found.\n");
    }
    else
    {
      for (size_t i = 0; i + 1 < grp_bin_depths.Size(); i = i + 2)
      {
	McastId bin = grp_bin_depths[i].GetUint();

	avg_queue_depths_[bin] = grp_bin_depths[i+1].GetUint();
	LogD(kClassName, __func__, "Bin: %" PRIMcastId ", depth: %" PRIu32
	     "Bytes\n", bin, avg_queue_depths_[bin]);
      }
      LogD(kClassName, __func__,
	   "Loaded AvgQueueDepthsBytes values for unicast group.\n");
    }

    const Value& path_ctrls = stats["PcProperties"];

    if (!path_ctrls.IsObject())
    {
       LogE(kClassName, __func__, "Malformed push message stats from BPF,"
                                  "PcProperties is not an object.\n");
       return false;
    }
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    path_ctrls.Accept(writer);

    aggregate_outbound_capacity_  = 0;
    for (Value::ConstMemberIterator itr = path_ctrls.MemberBegin();
         itr != path_ctrls.MemberEnd(); ++itr)
    {
      string nbr_ip_str  = itr->name.GetString();
      if (itr->value.IsObject())
      {
        const Value& pc_props = itr->value;
        Value::ConstMemberIterator pc_itr =
          pc_props.FindMember("TransportBitsPerSec");
        if (pc_itr == pc_props.MemberEnd())
        {
          LogE(kClassName, __func__,
            "Path controller does not have capacity estimate.\n");
          return false;
        }
        if (!pc_itr->value.IsUint())
        {
          LogE(kClassName, __func__, "Malformed push message from BPF: "
           "path controller capacity value must be an int.\n");
          return false;
        }
        uint32_t capacity = pc_itr->value.GetUint();
        aggregate_outbound_capacity_  += capacity;
        LogD(kClassName, __func__,
             "Path controller %s has capacity %dbps.\n",
             nbr_ip_str.c_str(), pc_itr->value.GetUint());

        pc_itr = pc_props.FindMember("LatenciesUsec");
        if (pc_itr == pc_props.MemberEnd())
        {
          LogE(kClassName, __func__,
            "Path controller does not have latency estimates.\n");
          return false;
        }
        if (!pc_itr->value.IsObject())
        {
          LogE(kClassName, __func__, "Malformed push message from BPF: "
           "path controller latencies value must be an object.\n");
          return false;
        }
        const Value& pc_latencies = pc_itr->value;

        // Parse the per-next-hop per binId latencies.
        for (Value::ConstMemberIterator lat_itr = pc_latencies.MemberBegin();
          lat_itr != pc_latencies.MemberEnd(); ++lat_itr)
        {
          BinId dest_bin = StringUtils::GetUint(lat_itr->name.GetString());
          if (!lat_itr->value.IsUint())
          {
            LogE(kClassName, __func__, "Malformed push message from BPF: "
            "path controller latencies value must be an unsigned integer.\n");
            return false;
          }
          uint32_t latency = lat_itr->value.GetUint();
          supervisory_ctl_->UpdateLinkChar(nbr_ip_str, dest_bin, latency,
            capacity);
          LogA(kClassName, __func__, "Bin: %" PRIBinId ", latency: %" PRIu32
            ", capacity: %" PRIu32 ".\n", dest_bin, latency, capacity);
        }
      }
    }
  }

  // If there is a GUI timer set, and this is a periodic push message,
  // then cache the message. If there is no timer set, then the message
  // is relayed immediately.
  if (is_periodic)
  {
    if (gui_push_timer_handle_.id() != 0)
    {
      LogD(kClassName, __func__, "Caching push message.\n");
      return CachePushMessage(target);
    }
    else
    {
      return RelayMessageToGui();
    }
  }
  return true;
}

//=============================================================================
bool Amp::CachePushMessage(string target)
{
  LogD(kClassName, __func__,
       "Caching message %" PRIu32 " from %s.\n",
       rc_client_.msg_id(), target.c_str());

  if (target == "udp_proxy")
  {
    udp_str_buf_.Clear();
    rc_client_.GetMsgBuffer(udp_str_buf_);
    udp_last_msg_id_  = rc_client_.msg_id();
  }
  else if (target == "tcp_proxy")
  {
    tcp_str_buf_.Clear();
    rc_client_.GetMsgBuffer(tcp_str_buf_);
    tcp_last_msg_id_  = rc_client_.msg_id();
  }
  else if (target == "bpf")
  {
    bpf_str_buf_.Clear();
    rc_client_.GetMsgBuffer(bpf_str_buf_);
    bpf_last_msg_id_  = rc_client_.msg_id();
  }
  else
  {
    LogW(kClassName, __func__, "Unknown target.\n");
    rc_client_.ResetEndpoint();
    return false;
  }

  rc_client_.ResetEndpoint();
  return true;
}

//=============================================================================
void Amp::RelayAllMessagesToGui()
{
  LogD(kClassName, __func__,
       "Forward all messages to the GUI.\n");

  if (udp_last_msg_id_ != 0)
  {
    if (RelayMessageToGui("udp_proxy"))
    {
      udp_last_msg_id_  = 0;
    }
  }

  if (tcp_last_msg_id_ != 0)
  {
    if (RelayMessageToGui("tcp_proxy"))
    {
      tcp_last_msg_id_  = 0;
    }
  }

  if (bpf_last_msg_id_ != 0)
  {
    if (RelayMessageToGui("bpf"))
    {
      bpf_last_msg_id_  = 0;
    }
  }

  CallbackNoArg<Amp>  cb(this, &Amp::RelayAllMessagesToGui);
  Time                delta_time  = Time::FromMsec(gui_push_interval_ms_);

  if (!timer_.StartTimer(delta_time, &cb, gui_push_timer_handle_))
  {
    LogE(kClassName, __func__,
       "Error starting GUI push timer.\n");
  }
}

//=============================================================================
bool Amp::RelayMessageToGui(string target)
{
  uint32_t      msg_id      = 0;
  StringBuffer  str_buf;
  StringBuffer* str_buf_ptr = &str_buf;

  if (target == "udp_proxy")
  {
    msg_id      = udp_last_msg_id_;
    str_buf_ptr = &udp_str_buf_;
  }
  else if (target == "tcp_proxy")
  {
    msg_id      = tcp_last_msg_id_;
    str_buf_ptr = &tcp_str_buf_;
  }
  else if (target == "bpf")
  {
    msg_id      = bpf_last_msg_id_;
    str_buf_ptr = &bpf_str_buf_;
  }
  else
  {
    msg_id  = GetClientRcvMsgId();
    rc_client_.GetMsgBuffer(*str_buf_ptr);
  }

  LogD(kClassName, __func__,
       "Relaying message %" PRIu32 " from target %s to GUI.\n",
       msg_id, target.c_str());

  // Send it to the GUI if it's for the GUI.
  if (msg_endpoint_map_.find(msg_id) != msg_endpoint_map_.end())
  {
    if (!SendMessageToServer(msg_endpoint_map_[msg_id], *str_buf_ptr))
    {
      LogE(kClassName, __func__, "Failed to relay message to GUI.\n");
      return false;
    }
    LogD(kClassName, __func__, "Relayed push message to server.\n");
  }
  else
  {
    LogD(kClassName, __func__, "Failed to map message %" PRIu32 " to origin.\n",
         msg_id);
    return false;
  }

  return true;
}

//=============================================================================
bool Amp::ProcessSetReplyMessage()
{
  return RelayMessageToGui();
}

//=============================================================================
bool Amp::ProcessServerRemoteControlMessage()
{
  LogD(kClassName, __func__, "Processing Server Remote Control message.\n");

  // Switch on the type of request message.
  RmtCntlMsgType  msg_type = GetServerMsgType();
  msg_endpoint_map_[rc_server_.msg_id()] = rc_server_.endpoint_ready()->id_;
  switch (msg_type)
  {
    case iron::RC_PUSHREQ:
      ProcessGuiPushReq();
      break;

    case iron::RC_SET:
      ProcessSetMessage();
      break;

    case iron::RC_GET:
      ProcessGetMessage();
      break;

    case iron::RC_INVALID:
    default:
      LogE(kClassName, __func__, "Unsupported message type\n");
      return false;
  }
  rc_server_.ResetEndpoint();
  return true;
}

//==============================================================================
bool Amp::ProcessGuiPushReq()
{
  uint32_t      client_id     = 0;
  uint32_t      msg_id        = 0;
  string        target        = "";
  double        interval_sec  = 0.;
  const Value*  keys          = NULL;

  if (!rc_server_.GetPushRequestMessage(client_id, msg_id, target,
    interval_sec, keys))
  {
    LogW(kClassName, __func__,
         "Could not parse push req message for %s.\n", target.c_str());
    return false;
  }

  LogD(kClassName, __func__,
       "Got push req message for %s.\n", target.c_str());

  int index = TGT_TO_INDEX(target);
  if (!IS_VALID_TGT_INDEX(index))
  {
    rc_server_.SendPushErrorMessage(client_id, msg_id, "Unexpected target.");
    LogF(kClassName, __func__,
	 "bad target %s index %d\n", target.c_str(), index);
    return false;
  }
  CachedRCMsg*  cached_msg  = &cached_push_req_[index];

  // Check if we have already requested pushes from target.
  if (cached_msg->msg_id_ == 0)
  {
    // Not yet.  But that is OK as we either just retried and we succeeded
    // (then we go through the normal process of handling a GUI request after
    // we started) or we failed, and we will retry before the next message.
    LogD(kClassName, __func__,
         "Received push req intended for %s but not yet pushing.\n",
         target.c_str());
    // Send a push error to tell GUI to keep trying.
    rc_server_.SendPushErrorMessage(client_id, msg_id, "AMP not ready.");
    return false;
  }

  // We have already started.  Handle receiving a push req from GUI after we
  // have started.
  if (cached_msg->type_ == "pushreq")
  {
    cached_msg->mapped_msg_id_  = msg_id;
    LogD(kClassName, __func__,
         "Received push req intended for %s but already pushing.\n",
         target.c_str());

    if (interval_sec > cached_msg->interval_s_)
    {
      LogD(kClassName, __func__,
           "Received push req from GUI requesting less frequent pushes (every "
           "%.1fs) than already started (every %.1fs); starting timer.\n",
           interval_sec, cached_msg->interval_s_);

      // Start new timer for GUI pushes.
      if (gui_push_timer_handle_.id() != 0)
      {
        timer_.CancelTimer(gui_push_timer_handle_);
        gui_push_timer_handle_.Clear();
      }

      gui_push_interval_ms_ = interval_sec * 1000;

      CallbackNoArg<Amp>  cb(this, &Amp::RelayAllMessagesToGui);
      Time                delta_time  = Time::FromMsec(gui_push_interval_ms_);

      if (!timer_.StartTimer(delta_time, &cb, gui_push_timer_handle_))
      {
        LogE(kClassName, __func__,
           "Error starting GUI push timer.\n");
      }
    }
    else if (interval_sec < cached_msg->interval_s_)
    {
      LogD(kClassName, __func__,
           "Received push req from GUI requesting more frequent pushes (every"
           "%.1fs) than already started (every %.1fs); canceling previous "
           "request, issuing new one.\n",
           interval_sec, cached_msg->interval_s_);

      if (gui_push_timer_handle_.id() != 0)
      {
        // Cancel the timer, we will push the messages as soon as they are
        // received.
        timer_.CancelTimer(gui_push_timer_handle_);
        gui_push_timer_handle_.Clear();
      }

      stat_interval_s_  = interval_sec;
      StopStatsCollection(target);
      StartStatsCollection(target);
      // Fix the mapping.
      cached_msg->mapped_msg_id_  = msg_id;
    }
    else
    {
      LogD(kClassName, __func__,
           "Received push req from GUI requesting pushes, same interval.\n");
    }
    return true;
  }

  return true;
}

//==============================================================================
string Amp::ReformatTuple(string tuple_str)
{
  char saddr[1024];
  char daddr[1024];
  char sport_s[1024];
  char dport_s[1024];
  if (::sscanf(tuple_str.c_str(),
      "%[^:]:%[^ ] -> %[^:]:%s", saddr, sport_s, daddr, dport_s) != 4)
  {
    LogE(kClassName, __func__, "Invalid flow string %s\n", tuple_str.c_str());
    return("");
  }

  char tuple_s[1024];
  if (!sprintf(tuple_s, "%s;%s;%s;%s",sport_s, dport_s, saddr, daddr))
  {
    LogE(kClassName, __func__, "Failed to create tuple\n");
    return("");
  }
  return tuple_s;
}

//==============================================================================
void Amp::UpdateFlowPriority(string target, string tuple, string priority)
{
  string flow_defn;
  if (!GetFlowDefn(target, tuple, flow_defn))
  {
    LogE(kClassName, __func__, "Did not find a flow definition for %s\n",
                               tuple.c_str());
    return;
  }

  LogD(kClassName, __func__, "Old flow definition is: %s.\n",
    flow_defn.c_str());

  // replace the priority with the new value
  string start_delim("p=");
  string end_delim(":");
  if( !StringUtils::Substitute(flow_defn, start_delim, end_delim, priority))
  {
    LogE(kClassName, __func__, "Failed to substitute new priority value.\n");
    return;
  }

  LogD(kClassName, __func__, "New flow definition is: %s\n",
                              flow_defn.c_str());

  // Send to proxy, receive reply and send it to the GUI.
  if(connection_map_.find(target) != connection_map_.end())
  {
    SendSetMsgToClient(target, "update_util", tuple + ";" + "p:" + priority);
    string five_tuple = target + ";" + tuple;
    UpdateFlowCache(five_tuple, flow_defn);
  }
  else
  {
    LogE(kClassName, __func__, "Unknown target %s for set message\n",
                                GetServerRcvMsgTgt().c_str());
  }
  return;
}

//==============================================================================
void Amp::ProcessSetMessage()
{
  // Set messages have the following format.
  //
  // \verbatim
  // {
  //   "msg": "set",
  //   "msgid": 1234,
  //   "tgt": "udp_proxy",
  //   "keyvals": { "parameter": "priority",
  //                "priority": 8,
  //                "flow_tuple": "192.168.12.1:5000 -> 192.168.12.2:5001"
  //              }
  // }
  //
  // {
  //   "msg": "set",
  //   "msgid": 1234,
  //   "tgt": "amp",
  //   "keyvals": { "parameter": "ft_params",
  //                "deadline": "8",
  //                "flow_tuple": "192.168.12.1:5000 -> 192.168.12.2:5001",
  //                "size": "2000000",
  //                "priority" : "5"
  //              }
  // }
  //
  // {
  //   "msg":"set",
  //   "msgid": 1234,
  //   "tgt": "amp",
  //   "keyvals": { "parameter": "mcast_group",
  //                "action" : "join" or "leave",
  //                "addr"  : "224.X.Y.X"
  //              }
  // }
  //
  // The following message provides a destination list for a multicast
  // group. This information is relayed to the UDP Proxy.
  //
  // {
  //   "msg": "set",
  //   "msgid": 1234,
  //   "tgt": "udp_proxy",
  //   "keyvals" : { "parameter": "mcast_dst_list",
  //                 "flow_tuple": "a.b.c.d:wwww->e.f.g.h:xxxx",
  //                 "dst_list": "i.j.k.l,m.n.o.p,...q.r.s.t"
  //               }
  // }
  const Value*  key_vals = NULL;
  string        target;
  Ipv4Address   saddr;

  // Get the message contents.
  if ((!GetSetMessageFromServer(target, key_vals, saddr)) ||
      (key_vals == NULL))
  {
    LogE(kClassName, __func__, "Error getting remote control set message.\n");
    return;
  }

  if (!key_vals->IsObject())
  {
    LogE(kClassName, __func__, "Malformed GUI set message key_vals\n");
    return;
  }

  // All set messages must have a "parameter" key.
  Value::ConstMemberIterator itr = key_vals->FindMember("parameter");

  if (itr == key_vals->MemberEnd())
  {
    LogE(kClassName, __func__, "Does not have parameter key.\n");
    return;
  }

  string parameter = itr->value.GetString();

  // Handle cases where the message is for the BPF.  Currently, we support
  // multicast group membership management messages to the BPF via AMP.
  if (target == "bpf")
  {
    if (parameter != "mcast_group")
    {
      LogE(kClassName, __func__, "AMP does not support setting %s.\n",
           parameter.c_str());
      return;
    }
    itr          = key_vals->FindMember("action");
    string action = itr->value.GetString();
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "GMM does not have an action key.\n");
      return;
    }

    itr                    = key_vals->FindMember("mcast_addr");
    string  mcast_addr_str = itr->value.GetString();
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "GMM does not have a mcast_addr key.\n");
      return;
    }

    LogD(kClassName, __func__, "Recieved group management message. %s group "
         "%s.\n", action.c_str(), mcast_addr_str.c_str());

    // Relay to the BPF.
    if(connection_map_.find("bpf") != connection_map_.end())
    {
      SendSetMsgToClient("bpf", "update_group", mcast_addr_str + ";" +
                         action);
    }
    else
    {
      LogE(kClassName, __func__, "Unknown target %s for set message\n",
           GetServerRcvMsgTgt().c_str());
    }
    return;
  }

  if (strcmp(parameter.c_str(), "mcast_dst_list") == 0)
  {
    // We have received a destination list for a multicast group. We need to
    // send this to the UDP Proxy.
    if (target != "udp_proxy")
    {
      LogE(kClassName, __func__, "Improper target (%s) for multicast "
           "destination list set message.\n", target.c_str());
      return;
    }

    itr = key_vals->FindMember("flow_tuple");
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "Multicast destination list set message "
           "does not have a flow_tuple key.\n");
      return;
    }
    string  flow_tuple = itr->value.GetString();

    itr = key_vals->FindMember("dst_list");
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "Multicast destination list set message "
           "does not have a dst_list key.\n");
      return;
    }
    string  dst_list = itr->value.GetString();

    LogD(kClassName, __func__, "Received flow (%s) multicast destination "
         "list: %s\n", flow_tuple.c_str(), dst_list.c_str());

    // Relay the multicast destination list to the UDP Proxy.
    if(connection_map_.find(target.c_str()) != connection_map_.end())
    {
      SendSetMsgToClient(target.c_str(), "add_mcast_dst_list", flow_tuple +
                         ";" + dst_list);
    }
    else
    {
      LogE(kClassName, __func__, "Unknown target %s for set message.\n",
           target.c_str());
    }
    return;
  }
  else if (strcmp(parameter.c_str(), "svc_defn") == 0)
  {
    string defn;
    itr = key_vals->FindMember("svc_defn");
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have a service definition.\n");
      return;
    }

    defn = itr->value.GetString();
    string search = "..";
    string replace= ":";
    iron::StringUtils::Replace(defn, search, replace);
    search = ".";
    replace= ";";
    iron::StringUtils::Replace(defn, search, replace);

    UpdateServiceCache(target, defn);
    SendSetMsgToClient(target, "add_service", defn);
  }

  // Get the flow tuple, which must be in any set message.
  string tuple_str;
  string tuple;
  itr = key_vals->FindMember("flow_tuple");
  if (itr == key_vals->MemberEnd())
  {
    LogE(kClassName, __func__, "Does not have flow_tuple key.\n");
    return;
  }
  tuple_str = itr->value.GetString();
  tuple = ReformatTuple(tuple_str);
  if (tuple == "")
  {
    LogE(kClassName, __func__,
         "Unable to process set message. Bad tuple string %s.\n",
         tuple_str.c_str());
    return;
  }
  LogD(kClassName, __func__, "Flow tuple is: %s\n", tuple.c_str());

  // AMP supports updates for file transfer params.
  if (target == "amp")
  {
    if (strcmp(parameter.c_str(), "ft_params") == 0)
    {
      uint32_t deadline;
      uint32_t size_bits;
      uint32_t priority;

      itr = key_vals->FindMember("deadline");
      if (itr == key_vals->MemberEnd())
      {
       LogE(kClassName, __func__, "Does not have deadline key.\n");
       return;
      }

      deadline = StringUtils::GetUint(itr->value.GetString());

      itr = key_vals->FindMember("size");
      if (itr == key_vals->MemberEnd())
      {
        LogE(kClassName, __func__, "Does not have size key.\n");
        return;
      }

      size_bits = StringUtils::GetUint(itr->value.GetString())*8;

      itr = key_vals->FindMember("priority");
      if (itr == key_vals->MemberEnd())
      {
       LogE(kClassName, __func__, "Does not have priority key.\n");
       return;
      }

      priority = StringUtils::GetUint(itr->value.GetString());

      LogI(kClassName, __func__, "Updating FT params for %s: deadline= %"
                                  PRIu32 ", size= %" PRIu32 ", p= %" PRIu32
                                  "\n", tuple.c_str(), deadline, size_bits,
                                  priority);

      // File transfers are always assumed to be TCP flows.
      tuple = "tcp_proxy;" + tuple;
      supervisory_ctl_->UpdateFtFlowInfo(tuple, deadline, size_bits, priority);
      return;
    }
    LogW(kClassName, __func__, "Unsupported parameter for AMP: %s\n",
         parameter.c_str());
    return;
  }

  string  five_tuple  = target + ";" + tuple;
  LogD(kClassName, __func__, "Updating utility for 5-tuple: %s\n",
       five_tuple.c_str());

  // The message should be processed and send to the appropriate proxy.
  if (strcmp(parameter.c_str(), "del_flow") == 0)
  {
    DeleteFlow(target + ";" + tuple);
    SendSetMsgToClient(target, "del_flow", tuple);
  }
  else if (strcmp(parameter.c_str(), "utility_fn") == 0)
  {
    itr = key_vals->FindMember("utility");
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have utility key.\n");
      return;
    }
    string utility_type = itr->value.GetString();

    // Get the current Utility Function for the flow.
    string  utility_fn;
    GetUtilityFn(five_tuple, utility_fn);

    // Check if it is the same type of utility function.
    if ((utility_fn.size() == 0) ||
        (utility_fn.find(utility_type) == std::string::npos))
    {
      if ((default_utility_fns_.count(target) > 0) &&
          (default_utility_fns_[target].count(utility_type) > 0))
      {
        utility_fn = default_utility_fns_[target][utility_type];
      }
      else
      {
        LogE(kClassName, __func__,
             "Unsupported utility function %s with proxy %s.\n",
             utility_fn.c_str(), target.c_str());
        return;
      }
    }

    // We have the utility function, update the priority if specified.
    itr = key_vals->FindMember("priority");
    if (itr != key_vals->MemberEnd())
    {
      string start_delim("p=");
      string end_delim(":");
      string priority = itr->value.GetString();
      if( !StringUtils::Substitute(utility_fn, start_delim, end_delim,
                                   priority))
      {
        LogE(kClassName, __func__, "Failed to substitute new priority value.\n");
        return;
      }
    }
    // Send to proxy, receive reply and send it to the GUI.
    if(connection_map_.find(target) != connection_map_.end())
    {
      SendSetMsgToClient(target, "add_flow", tuple + ";" + utility_fn);
      string five_tuple = target + ";" + tuple;
      UpdateFlowCache(five_tuple, utility_fn);
    }
  }
  else if (strcmp(parameter.c_str(), "priority") == 0)
  {
    itr = key_vals->FindMember("priority");
    if (itr == key_vals->MemberEnd())
    {
      LogE(kClassName, __func__, "Does not have priority key.\n");
      return;
    }

    UpdateFlowPriority(target, tuple, itr->value.GetString());
  }
  else
  {
    LogE(kClassName, __func__, "Unsupported set command %s\n",
                                key_vals->GetString());
    return;
  }

  return;
}

//=============================================================================
bool Amp::ProcessGetMessage()
{
  // Send to proxy.
  if(connection_map_.find(GetServerRcvMsgTgt()) != connection_map_.end())
  {
    StringBuffer str_buf;
    rc_server_.GetMsgBuffer(str_buf);
    if (!SendMessageToClient(connection_map_[GetServerRcvMsgTgt()], str_buf))
    {
      LogW(kClassName, __func__,
         "Failed to relay GET message to %s.\n", GetServerRcvMsgTgt().c_str());
      return false;
    }
  }
  else
  {
    LogE(kClassName, __func__, "Unknown target %s for get message\n",
                                GetServerRcvMsgTgt().c_str());
    return false;
  }
  return true;
}

//=============================================================================
bool Amp::GetSvcDefn(const string& five_tuple, SvcDefn& svc_defn) const
{
  string    prot;
  uint32_t  sport_hbo  = 0;
  uint32_t  dport_hbo  = 0;
  uint32_t  span       = 100000;
  bool      found      = false;

  List<string>  tokens;
  StringUtils::Tokenize(five_tuple, ";", tokens);

  LogD(kClassName, __func__, "Looking up service defn for %s\n",
                             five_tuple.c_str());

  if (tokens.size() != 5)
  {
    LogE(kClassName, __func__, "Malformed five-tuple: %s.\n",
      five_tuple.c_str());
    return false;
  }

  tokens.Pop(prot);

  string  token;
  tokens.Pop(token);
  sport_hbo = StringUtils::GetUint(token, span);
  if (sport_hbo == span)
  {
    LogE(kClassName, __func__,
       "Invalid flow string %s.\n", five_tuple.c_str());
    return false;
  }
  tokens.Peek(token);

  dport_hbo = StringUtils::GetUint(token, span);
  if (dport_hbo == span)
  {
    LogE(kClassName, __func__,
         "Invalid flow string %s.\n", five_tuple.c_str());
    return false;
  }

  std::map<string, SvcDefn>::const_iterator svc_def_itr;

  for (svc_def_itr = svc_def_cache_.begin();
       svc_def_itr != svc_def_cache_.end();
       ++svc_def_itr)
  {

    string    protocol  = svc_def_itr->second.prot;
    uint32_t  hi_port   = svc_def_itr->second.hi_port_hbo;
    uint32_t  lo_port   = svc_def_itr->second.lo_port_hbo;
    uint32_t  new_span  = hi_port - lo_port;

    if (hi_port < lo_port)
    {
      LogE(kClassName, __func__,
           "Service %s contains malformed port range %" PRIu32 "-%" PRIu32 ".\n",
           protocol.c_str(), lo_port, hi_port);
      return false;
    }

    // Make sure the protocols match.
    if (prot != protocol)
    {
      continue;
    }

    // try to match on dest port
    if ((dport_hbo >= lo_port) && (dport_hbo <= hi_port) && (new_span < span))
    {
      svc_defn  = svc_def_itr->second;
      span      = new_span;
      found     = true;
    }

    // try to match on source port
    if ((sport_hbo >= lo_port) && (sport_hbo <= hi_port) && (new_span < span))
    {
      svc_defn  = svc_def_itr->second;
      span      = new_span;
      found     = true;
    }
  }

  return found;
}

//=============================================================================
bool Amp::GetFlowDefn(const string& proxy, const string& four_tuple,
  string& flow_defn) const
{
  flow_defn = "";
  string five_tuple = proxy + ";" + four_tuple;
  // Check if there is a flow definition for this flow.
  FiveTuple ft(five_tuple);
  FlowDefn  flow_def;
  if (flow_def_cache_.Find(ft, flow_def))
  {
    flow_defn  = flow_def.defn_str;
    return true;
  }
  else
  {
    SvcDefn svc_def;
    if (GetSvcDefn(five_tuple, svc_def))
    {
      iron::List<string> tokens;
      StringUtils::Tokenize(svc_def.defn_str, ";", tokens);

      string  token;
      tokens.Pop(token);
      flow_defn = four_tuple + ";";
      while (tokens.size() > 0)
      {
        tokens.Pop(token);
        flow_defn += token + ";";
      }
      return true;
    }
  }
  LogE(kClassName, __func__, "Did not find a matching flow or service "
    " definition for flow: %s.\n", four_tuple.c_str());
  return false;
}

//=============================================================================
void Amp::GetUtilityFn(const string& five_tuple, string& utility_fn) const
{
  utility_fn = "";

  FiveTuple ft(five_tuple);
  FlowDefn  flow_def;
  if (flow_def_cache_.Find(ft, flow_def))
  {
    LogD(kClassName, __func__,
      "Found FlowDefn for flow %s.\n", five_tuple.c_str());
    utility_fn = flow_def.utility_fn;
    return;
  }

  LogD(kClassName, __func__,
       "Found no utility for this flow %s, looking into services cache.\n",
       five_tuple.c_str());

  SvcDefn svc_defn;
  if (GetSvcDefn(five_tuple, svc_defn))
  {
    utility_fn = svc_defn.utility_fn;
    LogD(kClassName, __func__,"Found svc defn %s.\n", utility_fn.c_str());
  }
}

//=============================================================================
void Amp::GetUdpFlowParams(const string& five_tuple, string& utility_fn,
  string& ttg) const
{
  utility_fn = "";
  ttg = "0";

  FiveTuple ft(five_tuple);
  FlowDefn  flow_def;
  if (flow_def_cache_.Find(ft, flow_def))
  {
    utility_fn = flow_def.utility_fn;
    ttg        = flow_def.ttg;
    return;
  }

  LogD(kClassName, __func__,
       "Found no utility for this flow %s, looking into services cache.\n",
       five_tuple.c_str());

  SvcDefn svc_defn;
  if (GetSvcDefn(five_tuple, svc_defn))
  {
    utility_fn = svc_defn.utility_fn;
    ttg        = svc_defn.ttg;
  }
}

//=============================================================================
bool Amp::GetUtilityFnFromDefn(const string& defn, string& utility_fn) const
{
  // Flow and service definitions are of the form:
  // param1;param2;...;utility_fn;optional_param1=val;optional_param2=val2;
  // TCP service and flow definitions only contain the utility function
  // specification.
  // The utility function string is of the format:
  // type=utility_type:param1=x;param2=y
  // Different utility function have different parameter names and different
  // number of parameters.
  utility_fn = "";
  List<string> tokens;
  StringUtils::Tokenize(defn, ";", tokens);
  List<string>::WalkState ws;
  ws.PrepareForWalk();

  string  token;
  while (tokens.GetNextItem(ws, token))
  {
    if (token.find("type") != std::string::npos)
    {
      utility_fn = token;
      return true;
    }
  }
  return false;
}

//=============================================================================
bool Amp::GetTtgFromUdpDefn(const string& defn, string& ttg, bool isSvc) const
{
  ttg = "0";
  List<string>  tokens;
  StringUtils::Tokenize(defn, ";", tokens);

  string  token;

  // The ttg is the 6th token if it is a flow definition and 7th if it is
  // a service definition.
  // Service definitions are of the form: <port_range>;<params>
  // Flow definitions do not have the port range, only the flow parameters.
  // If it is a service definition, the extra leading token <port_range>
  // should be removed, then it can be treated exactly like a flow  definition.
  if (isSvc && (tokens.size() > 0))
  {
    tokens.Pop(token);
  }

  if (tokens.size() < 7)
  {
    LogE(kClassName, __func__,
      "Udp service or flow definition does not have enough parameters: %s.\n",
      defn.c_str());
    return false;
  }
  // The ttg is now the 6th token of the remaining tokens.
  tokens.Pop(token);
  tokens.Pop(token);
  tokens.Pop(token);
  tokens.Pop(token);
  tokens.Pop(token);
  tokens.Peek(token);
  if (token != "")
  {
    ttg = token;
    return true;
  }
  return false;
}
//=============================================================================
void Amp::UpdateServiceCache(const string& proxy, const string& svc_def)
{
  List<string>  tokens;
  StringUtils::Tokenize(svc_def, ";", tokens);

  LogD(kClassName, __func__, "Updating service definition cache %s:%s.\n",
       proxy.c_str(), svc_def.c_str());

  string range;

  tokens.Pop(range);

  if (range.find("-") == std::string::npos)
  {
    LogE(kClassName, __func__, "Bad service definition %s.\n", range.c_str());
    return;
  }

  string  utility_fn;
  if (!GetUtilityFnFromDefn(svc_def, utility_fn))
  {
    LogW(kClassName, __func__,
      "Service definition does not contain a utility fn.\n");
    return;
  }

  // Note: The ttg is only used by the UDP Proxy and it is a required field.
  string ttg = "0";
  if (proxy == "udp_proxy")
  {
    if (!GetTtgFromUdpDefn(svc_def, ttg, true))
    {
      LogE(kClassName, __func__,
        "UDP Service definition does not contain a ttg value.\n");
      return;
    }
  }

  List<string>  range_tokens;
  StringUtils::Tokenize(range, "-", range_tokens);

  string  lo_port_str;
  string  hi_port_str;

  range_tokens.Peek(lo_port_str);
  range_tokens.PeekBack(hi_port_str);
  uint32_t lo_port = StringUtils::GetUint(lo_port_str);
  uint32_t hi_port = StringUtils::GetUint(hi_port_str);

  svc_def_cache_[proxy + ";" + range] =
    SvcDefn(proxy, lo_port, hi_port, utility_fn, svc_def, ttg);

  LogD(kClassName, __func__,
    "Added new service definition %s with utility %s to cache.\n",
     range.c_str(), utility_fn.c_str());
}

//=============================================================================
void Amp::UpdateFlowCache(const string& five_tuple, const string& flow_def)
{
  List<string>  tokens;
  StringUtils::Tokenize(five_tuple, ";", tokens);

  string utility_fn;
  if (!GetUtilityFnFromDefn(flow_def, utility_fn))
  {
    LogW(kClassName, __func__,
	 "Flow definition %s (%s) does not contain a utility fn.\n",
	 flow_def.c_str(),five_tuple.c_str());
    return;
  }

  // Note: The ttg is only used by the UDP Proxy and it is a required field.
  string  ttg = "0";
  string  proxy;
  tokens.Peek(proxy);

  if (proxy == "udp_proxy")
  {
    if (!GetTtgFromUdpDefn(flow_def, ttg, false))
    {
      LogE(kClassName, __func__,
        "UDP Flow definition does not contain a ttg value.\n");
      return;
    }
  }

  FiveTuple ft(five_tuple);
  FlowDefn def(five_tuple, utility_fn, flow_def, ttg);
  flow_def_cache_.Erase(ft);
  if (!flow_def_cache_.Insert(ft, def))
  {
    LogE(kClassName, __func__, "Failed to insert flow definition.\n");
    return;
  }

  LogD(kClassName, __func__, "Added flow definition %s with defn %s.\n",
    five_tuple.c_str(), flow_def.c_str());
}

//=============================================================================
bool Amp::DeleteFlow(const string& five_tuple)
{
  FiveTuple ft(five_tuple);
  if (flow_def_cache_.Erase(ft) > 0)
  {
    LogD(kClassName, __func__,
         "Removed flow from %s cache.\n", five_tuple.c_str());
    return true;
  }

  LogD(kClassName, __func__, "Did not find flow %s.\n", five_tuple.c_str());
  return false;
}

//=============================================================================
void Amp::TurnFlowOff(FlowInfo& flow_info)
{
  List<FlowInfo*>::WalkState  cf_ws;
  FlowInfo* cf_info                         = NULL;

  // If it is a coupled flow, then turn off all constituent flows.
  if (flow_info.coupled_flows_ != NULL)
  {
    flow_info.flow_state_     = FLOW_OFF;
    cf_ws.PrepareForWalk();
    while (flow_info.coupled_flows_->GetNextItem(cf_ws, cf_info))
    {
      SendSetMsgToClient(cf_info->proxy_, "off_flow", cf_info->four_tuple_);
      cf_info->flow_state_     = FLOW_OFF;
      LogA(kClassName, __func__, "Turning off flow %s in %s.\n",
           cf_info->four_tuple_.c_str(),cf_info->proxy_.c_str());
    }
  }
  else
  {
    SendSetMsgToClient(flow_info.proxy_, "off_flow", flow_info.four_tuple_);
    flow_info.flow_state_     = FLOW_OFF;
    LogA(kClassName, __func__, "Turning off flow %s in %s.\n",
         flow_info.four_tuple_.c_str(), flow_info.proxy_.c_str());
  }
}

//=============================================================================
void Amp::TurnFlowOn(FlowInfo& flow_info)
{
  List<FlowInfo*>::WalkState  cf_ws;
  FlowInfo* cf_info                         = NULL;

  // If it is a coupled flow, then turn on all constituent flows.
  if (flow_info.coupled_flows_ != NULL)
  {
    cf_ws.PrepareForWalk();
    while (flow_info.coupled_flows_->GetNextItem(cf_ws, cf_info))
    {
      string flow_defn;
      if (!GetFlowDefn(cf_info->proxy_, cf_info->four_tuple_, flow_defn))
      {
        LogE(kClassName, __func__,
             "Failed to get a flow definition for flow %s\n",
             cf_info->four_tuple_.c_str());
        return;
      }
      SendSetMsgToClient(cf_info->proxy_, "add_flow", flow_defn);
      cf_info->flow_state_     = FLOW_ON;
      LogA(kClassName, __func__, "Turning on flow %s in %s.\n",
           cf_info->four_tuple_.c_str(), cf_info->proxy_.c_str());
    }
  }
  else
  {
    string flow_defn;
    if (!GetFlowDefn(flow_info.proxy_, flow_info.four_tuple_, flow_defn))
    {
      LogE(kClassName, __func__,
           "Failed to get a flow definition for flow %s\n",
           flow_info.four_tuple_.c_str());
      return;
    }
    SendSetMsgToClient(flow_info.proxy_, "add_flow", flow_defn);
    flow_info.flow_state_     = FLOW_ON;
    LogA(kClassName, __func__, "Turning on flow %s in %s.\n",
         flow_info.four_tuple_.c_str(), flow_info.proxy_.c_str());
  }
}

//=============================================================================
bool Amp::ParseUtilityFn(const string& five_tuple, const string& utility_fn,
                         ConfigInfo& ci)
{
  List<string>  five_tuple_tokens;
  StringUtils::Tokenize(five_tuple, ";", five_tuple_tokens);

  if (five_tuple_tokens.size() != 5)
  {
    LogE(kClassName, __func__,
         "Malformed five tuple %s.\n", five_tuple.c_str());
    return false;
  }

  ci.Add("five_tuple", five_tuple);
  ci.Add("utility_fn", utility_fn);

  // remove any optional fields at the end of the service defn.
  List<string>  tokens;
  StringUtils::Tokenize(utility_fn, ";", tokens);

  List<string>  utility_tokens;
  string        utility_str;
  tokens.Peek(utility_str);

  StringUtils::Tokenize(utility_str, ":", utility_tokens);
  List<string>  param_tokens;
  string        key;
  string        value;

  string        utility_token;

  while (utility_tokens.Pop(utility_token))
  {
    StringUtils::Tokenize(utility_token, "=", param_tokens);

    if (param_tokens.size() != 2)
    {
      string param_token;
      param_tokens.Peek(param_token);
      LogE(kClassName, __func__,
           "Malformed utility function %s.\n", utility_str.c_str());
      return false;
    }

    param_tokens.Pop(key);
    param_tokens.Peek(value);

    LogD(kClassName, __func__,
         "Parsing %s: %s.\n", key.c_str(), value.c_str());
    ci.Add(key, value);
  }
  return true;
}

//=============================================================================
bool Amp::SanitizeUtilityFn(ConfigInfo& ci)
{
  string  utility_type  = ci.Get("type", "None", false);

  if ((utility_type != "LOG") && (utility_type != "TRAP") &&
    (utility_type != "STRAP") && (utility_type != "FLOG"))
  {
    LogE(kClassName, __func__,
         "Utility function has unknown type : %s.\n", utility_type.c_str());
    return false;
  }

  double m = ci.GetDouble("m", 0.0, false);
  if ((utility_type == "TRAP") && (m == 0.0))
  {
    LogE(kClassName, __func__, "Invalid m value: %f.\n", m);
    return false;
  }

  double a = ci.GetDouble("a", 0.0, false);
  if ((utility_type == "LOG") && (a == 0.0))
  {
    LogE(kClassName, __func__, "Invalid a value: %f.\n", a);
    return false;
  }

  double p = ci.GetDouble("p", -1.0, false);
  if (p == -1.0)
  {
    LogE(kClassName, __func__, "Invalid p value %f.\n", p);
    return false;
  }

  double src_rate = ci.GetDouble("src_rate",0.0, false);
  if ((utility_type == "STRAP") && (src_rate == 0.0))
  {
    LogE(kClassName, __func__, "No computed source rate value %s.\n", src_rate);
    return false;
  }

  double normalized_utility = 0.0;
  double max_queue          = 0.0;
  string nominal_rate       = "1";
  if (utility_type == "LOG")
  {
    normalized_utility = p;
    max_queue          = k_val_  * p * a;
  }
  else if (utility_type == "TRAP")
  {
    normalized_utility = p/m;
    max_queue          = k_val_  * p  / m;
    nominal_rate       = ci.Get("m", "1", false);
  }
  else if (utility_type == "STRAP")
  {
    normalized_utility = p/src_rate;
    max_queue          = k_val_  * p  / src_rate;
    nominal_rate       = ci.Get("m", "1", false);
  }
  else
  {
    LogE(kClassName, __func__,
         "Unsupported utility type: %s.\n", utility_type.c_str());
    return false;
  }

  ci.Add("normalized_utility", StringUtils::ToString(normalized_utility));
  ci.Add("max_queue", StringUtils::ToString(max_queue));
  ci.Add("nominal_rate_bps", nominal_rate);
  ci.Add("priority", ci.Get("p", "0", false));
  return true;
}

//=============================================================================
void Amp::ConsiderTriage()
{
  LogA(kClassName, __func__,
       "Considering triage for outbound capacity %.01f.\n",
       aggregate_outbound_capacity_);
  triage_timer_handle_.Clear();

  if (supervisory_ctl_->ComputeFit(aggregate_outbound_capacity_))
  {
    LogD(kClassName, __func__,
         "Supervisory Control has finished updating flow state\n");
  }

  supervisory_ctl_->PrintAllFlowInfo();
  CallbackNoArg<Amp>  cb(this, &Amp::ConsiderTriage);
  Time                delta_time  = Time::FromMsec(triage_interval_ms_);

  if (!timer_.StartTimer(delta_time, &cb, triage_timer_handle_))
  {
    LogE(kClassName, __func__,
         "Error starting triage timer.\n");
  }
}

//=============================================================================
bool Amp::FindRCMsgFromMsgId(uint32_t msg_id, CachedRCMsg*& rc_msg)
{
  for (uint8_t i = 0; i < kMaxNumAmpSupportedTargets; ++i)
  {
    if (cached_push_req_[i].msg_id_ == msg_id)
    {
      rc_msg  = &cached_push_req_[i];
      return true;
    }
  }

  return false;
}
