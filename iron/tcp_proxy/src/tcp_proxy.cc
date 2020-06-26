//============================================================================
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
//============================================================================

#include "tcp_proxy.h"

#include "bin_map.h"
#include "ipv4_endpoint.h"
#include "iron_constants.h"
#include "itime.h"
#include "log.h"
#include "packet_pool_shm.h"
#include "shared_memory_if.h"
#include "string_utils.h"
#include "unused.h"

#include <string>

#include <cstdlib>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>

using ::iron::BinIndex;
using ::iron::BinMap;
using ::iron::CallbackNoArg;
using ::iron::ConfigInfo;
using ::iron::FourTuple;
using ::iron::FifoIF;
using ::iron::Ipv4Address;
using ::iron::Ipv4Endpoint;
using ::iron::IPV4_PACKET;
using ::iron::List;
using ::iron::Packet;
using ::iron::PacketFifo;
using ::iron::PACKET_OWNER_BPF;
using ::iron::PACKET_OWNER_TCP_PROXY;
using ::iron::PacketPool;
using ::iron::PacketType;
using ::iron::PktMemIndex;
using ::iron::RemoteControlServer;
using ::iron::RmtCntlMsgType;
using ::iron::SharedMemoryIF;
using ::iron::StringUtils;
using ::iron::Time;
using ::rapidjson::SizeType;
using ::rapidjson::StringBuffer;
using ::rapidjson::Writer;
using ::rapidjson::Value;
using ::std::map;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*     UNUSED(kClassName) = "TcpProxy";

  /// The default statistics collection interval.
  const uint32_t  kDefaultStatsCollectionIntervalMs = 5000;

  /// The default service sockets interval, in microseconds.
  const uint32_t  kDefaultSvcSocketsIntervalUs =
    iron::kDefaultBpfMinBurstUsec / 2;

  /// The default remote control port.
  const uint16_t  kDefaultRemoteControlPort = 3145;

  /// The maximum number of packets to be read from a FIFO at once.
  const size_t    kMaxPktsPerFifoRecv = 256;

  /// The max number of packets to read from the LAN IF each pass through the
  /// main event loop.
  const size_t    kMaxLanRecvs = 200;

  /// The maximum number of bytes for a packet read from the LAN IF.
  const size_t    kMaxPktSizeBytes = 1500;

  /// The minimum number of bytes for a packet read from the LAN IF.
  const size_t    kMinPktSizeBytes = kMaxTcpOptLen;

  /// The number of buckets in the flow utility function definition hash
  /// table.  This value supports fast lookups with up to 10,000 flows.
  const size_t    kUtilDefHashTableBuckets = 32768;

  /// The number of buckets in the DSCP hash table.  This value supports fast
  /// lookups with up to 10,000 flows.
  const size_t    kContextDscpHashTableBuckets = 32768;
}

//============================================================================
TcpProxy::TcpProxy(TcpProxyConfig& proxy_config,
                   iron::PacketPool& packet_pool,
                   iron::VirtualEdgeIf& edge_if,
                   iron::BinMap& bin_map,
                   iron::SharedMemoryIF& weight_qd_shared_memory,
                   iron::FifoIF* bpf_to_tcp_pkt_fifo,
                   iron::FifoIF* tcp_to_bpf_pkt_fifo,
                   iron::RemoteControlServer& remote_control_server)
    : running_(false),
      edge_if_(edge_if),
      bin_map_shm_(bin_map),
      packet_pool_(packet_pool),
      bpf_to_tcp_pkt_fifo_(packet_pool_, bpf_to_tcp_pkt_fifo, PACKET_OWNER_BPF,
                           kMaxPktsPerFifoRecv),
      tcp_to_bpf_pkt_fifo_(packet_pool_, tcp_to_bpf_pkt_fifo, PACKET_OWNER_BPF,
                           0),
      weight_qd_shared_memory_(weight_qd_shared_memory),
      proxy_config_(proxy_config),
      socket_mgr_(),
      pkt_info_pool_(packet_pool_),
      timer_(),
      k_val_(),
      local_queue_depths_(bin_map_shm_),
      svc_configs_(),
      flow_utility_def_cache_(),
      context_dscp_cache_(),
      default_utility_def_(),
      num_server_lists_(0),
      server_lists_(),
      num_recon_reqs_(0),
      recon_reqs_(),
      svc_sockets_timer_(),
      next_sched_socket_svc_time_(Time::Now()),
      remote_control_(remote_control_server),
      tcp_stats_push_(),
      stats_interval_ms_(kDefaultStatsCollectionIntervalMs),
      log_stats_(false),
      qd_direct_access_(iron::kDirectAccessQueueDepths),
      flow_tag_(0)
{
  socket_mgr_.SetTcpProxy(this);

  for (uint8_t i = 0; i < kMaxServerLists; i++)
  {
    server_lists_[i] = NULL;
  }

  for (uint8_t i = 0; i < kMaxReconnects; i++)
  {
    recon_reqs_[i] = NULL;
  }
}

//============================================================================
TcpProxy::~TcpProxy()
{
  // Remove all sockets.
  socket_mgr_.RemoveAllSockets();

  // Delete the collection of Service context information.
  map<int, TcpContext*>::iterator  iter;
  for (iter = svc_configs_.begin(); iter != svc_configs_.end(); ++iter)
  {
    delete iter->second;
  }
  svc_configs_.clear();

  // Close the edge interface.
  edge_if_.Close();

  // Cancel the service sockets update timer.
  if (timer_.IsTimerSet(svc_sockets_timer_))
  {
    LogD(kClassName, __func__, "Canceling service sockets timer %" PRIu64
         ".\n", svc_sockets_timer_.id());
    timer_.CancelTimer(svc_sockets_timer_);
  }

  // Delete the seamless server handoff lists.
  for (uint8_t i = 0; i < num_server_lists_; i++)
  {
    delete server_lists_[i];
    server_lists_[i] = NULL;
  }

  // Detach the shared memory segments.
  weight_qd_shared_memory_.Detach();

  // Cancel the statistics timer.
  if (timer_.IsTimerSet(tcp_stats_push_.timer_handle))
  {
    LogD(kClassName, __func__, "Canceling timer %" PRIu64 ".\n",
         tcp_stats_push_.timer_handle.id());
    timer_.CancelTimer(tcp_stats_push_.timer_handle);
  }

  // Clean up the timer callback object pool.
  CallbackNoArg<TcpProxy>::EmptyPool();
}

//============================================================================
bool TcpProxy::Initialize(const ConfigInfo& config_info)
{
  // Create the edge interface and insert the iptables rules and attach the
  // Berkeley Packet Filter that will divert packets into the TCP Proxy.
  if (!edge_if_.Open())
  {
    LogF(kClassName, __func__, "Error creating edge interface.\n");
    return false;
  }

  // Inialize the inter-process communications between the TCP Proxy and the
  // Backpressure Forwarder.
  if (!bpf_to_tcp_pkt_fifo_.OpenReceiver())
  {
    LogW(kClassName, __func__, "Unable to open backpressure forwarder packet "
         "FIFO.\n");
    return false;
  }

  if (!tcp_to_bpf_pkt_fifo_.OpenSender())
  {
    LogD(kClassName, __func__, "Backpressure forwarder packet FIFO not ready "
         "yet.\n");
  }

  // Get the default utility function definition
  default_utility_def_  = config_info.Get("DefaultUtilityDef", "");

  // Inialize k
  double double_k = config_info.GetDouble("KVal", iron::kDefaultK);
  if (double_k > std::numeric_limits<uint64_t>::max())
  {
    LogE(kClassName, __func__, "k val is too large.\n");
    k_val_.set_k_current(static_cast<uint64_t>(::iron::kDefaultK));
  }
  else
  {
    k_val_.set_k_current(static_cast<uint64_t>(double_k));
  }

  // Initialize the hash tables.
  if ((!flow_utility_def_cache_.Initialize(kUtilDefHashTableBuckets)) ||
      (!context_dscp_cache_.Initialize(kContextDscpHashTableBuckets)))
  {
    LogF(kClassName, __func__, "Unable to initialize hash tables.\n");
    return false;
  }

  // Initialize the remote control communications module.
  uint16_t  remote_control_port = static_cast<uint16_t>(
    config_info.GetUint("Tcp.RemoteControl.Port", kDefaultRemoteControlPort));

  if (!remote_control_.Initialize(remote_control_port))
  {
    LogF(kClassName, __func__, "Unable to initialize remote control "
         "communications module.\n");
    return false;
  }

  // Log the configuration information.
  LogC(kClassName, __func__, "TCP Proxy configuration:\n");
  LogC(kClassName, __func__, "DefaultUtilityFn           : %s\n",
       default_utility_def_.c_str());
  LogC(kClassName, __func__, "RemoteControlPort          : %" PRIu16 "\n",
       remote_control_port);
  LogC(kClassName, __func__, "K                          : %.2e\n",
       static_cast<double>(k_val_.GetValue()));
  LogC(kClassName, __func__, "DirectAccess               : %s\n",
       qd_direct_access_ ? "On" : "Off");

  // Retrieve zero or more service configurations.
  for (int i = 0; i < 16; i++)
  {
    char  serv_name[100];

    snprintf(&serv_name[0], sizeof(serv_name)-1, "Service%d", i);

    char    parm[300];
    string  pvar;
    if ((pvar = config_info.Get(serv_name, "")) != "")
    {
      strncpy(&parm[0], pvar.c_str(), sizeof(parm)-1);

      TcpContext*  context;
      if ((context = ParseService(&parm[0], TcpModAction)) != NULL)
      {
        // Enable this service.
        if (ModService(context) == false)
        {
          LogE(kClassName, __func__, "Addition of service %s failed.\n",
               pvar.c_str());

          delete context;
          return false;
        }

        delete context;

        LogC(kClassName, __func__, "Service                    : %s\n",
             pvar.c_str());
      }
    }
  }

  // Initialize any configured server lists.

  // Extract the number of server lists.
  num_server_lists_ =
    static_cast<uint8_t>(config_info.GetUint("NumServerLists", 0));

  if (num_server_lists_ > kMaxServerLists)
  {
    LogE(kClassName, __func__, "Too many server lists (%" PRIu32
         ") secified.\n", num_server_lists_);
    return false;
  }

  // Extract the server lists.
  for (uint8_t i = 0; i < num_server_lists_; i++)
  {
    if (server_lists_[i] != NULL)
    {
      LogE(kClassName, __func__, "Server list %" PRIu32 " already "
           "created.\n", i);
      return false;
    }

    // Create and initialize the server list.
    server_lists_[i] = new (std::nothrow) ServerList(*this);
    if (server_lists_[i] == NULL)
    {
      LogF(kClassName, __func__, "Error allocating new ServerList.\n");
      return false;
    }

    server_lists_[i]->Initialize(config_info, packet_pool_, bin_map_shm_, i);
  }

  // Extract the statistics collection interval.
  stats_interval_ms_ =
    config_info.GetUint("StatsCollectionIntervalMs",
                        kDefaultStatsCollectionIntervalMs);

  LogC(kClassName, __func__, "StatsCollectionIntervalMs  : %" PRIu32 "\n",
       stats_interval_ms_);

  // Extract the directive that controls whether the statistics will be
  // logged.
  log_stats_ = config_info.GetBool("LogStatistics", true);

  LogC(kClassName, __func__, "LogStatistics              : %s\n", log_stats_ ?
       "true" : "false");

  if (!AttachSharedMemory(config_info))
  {
    LogE(kClassName, __func__, "TCP Proxy failed to attach to required "
         "shared memory segments.");
    return false;
  }

  LogC(kClassName, __func__, "TCP Proxy configuration complete.\n");

  return true;
}

//============================================================================
int TcpProxy::Select(int nfds, fd_set* readfs, struct timeval* timeout)
{
  return select(nfds, readfs, NULL, NULL, timeout);
}

//============================================================================
void TcpProxy::Start()
{
  LogI(kClassName, __func__, "Starting main TCP Proxy service loop...\n");

  running_ = true;

  // Start the statistics collection timer.
  Time                     duration = Time::FromMsec(stats_interval_ms_);
  CallbackNoArg<TcpProxy>  callback(this, &TcpProxy::PushStats);

  if (!timer_.StartTimer(duration, &callback, tcp_stats_push_.timer_handle))
  {
    LogE(kClassName, __func__, "Error setting next statistics push timer.\n");
  }
  LogD(kClassName, __func__, "Started push stats timer: handle is %" PRIu64
       ", duration is %s\n", tcp_stats_push_.timer_handle.id(),
       duration.ToString().c_str());

  while (running_)
  {
    MainLoop();
  }
}

//============================================================================
void TcpProxy::MainLoop()
{
  int max_fd = 0;
  fd_set read_fds;
  FD_ZERO(&read_fds);

  edge_if_.AddFileDescriptors(max_fd, read_fds);
  bpf_to_tcp_pkt_fifo_.AddFileDescriptors(max_fd, read_fds);

  // Add the fd for the remote control to the set of read fds.
  remote_control_.AddFileDescriptors(max_fd, read_fds);

  // Get the next backstop time.
  Time  next_timer_expiration = timer_.GetNextExpirationTime();
  struct timeval tv = next_timer_expiration.ToTval();

  int rv = Select(max_fd + 1, &read_fds, &tv);

  if (rv < 0)
  {
    LogE(kClassName, __func__, "select() error %s.\n", strerror(errno));
  }
  else if (rv > 0)
  {
    LogD(kClassName, __func__, "Servicing LAN side file descriptor.\n");

    // For now, limit the number of packets that are read from the LAN IF.
    //
    // if (edge_if_.InSet(&read_fds))
    // {
      ssize_t   bytes_read   = 0;
      uint32_t  num_lan_rcvs = 0;
      do
      {
        Packet*  pkt = packet_pool_.Get();
        bytes_read = edge_if_.Recv(pkt, kMaxTcpOptLen);
        if (bytes_read < 0)
        {
          packet_pool_.Recycle(pkt);
          continue;
        }

        if ((size_t)bytes_read > kMaxPktSizeBytes)
        {
          LogF(kClassName, __func__, "Packet size of %" PRIu32 " is too "
               "large for proxy.\n", bytes_read);
        }
        else if ((size_t)bytes_read < kMinPktSizeBytes)
        {
          LogF(kClassName, __func__, "Packet size of %" PRIu32 " is too "
               "small for proxy.\n", bytes_read);
        }

        pkt->SetLengthInBytes(bytes_read + kMaxTcpOptLen);
        pkt->RemoveBytesFromBeginning(kMaxTcpOptLen);
        ProcessRcvdPkt(pkt, LAN);
        num_lan_rcvs++;
      } while (bytes_read > 0 && num_lan_rcvs < kMaxLanRecvs);
    // }

    if (bpf_to_tcp_pkt_fifo_.InSet(&read_fds))
    {
      ReceivePktsFromBpf();
    }

    // Process any messages received from the remote control communications.
    if (remote_control_.ServiceFileDescriptors(read_fds))
    {
      ProcessRemoteControlMessage();
    }
  }

  socket_mgr_.RemoveMarkedSockets();
  timer_.DoCallbacks();

  if (num_recon_reqs_ > 0)
  {
    socket_mgr_.RemoveMarkedSockets();

    for (uint8_t i = 0; i < num_recon_reqs_; i++)
    {
      ProcessRcvdPkt(recon_reqs_[i], LAN);
    }

    num_recon_reqs_ = 0;
  }
}

//============================================================================
void TcpProxy::Stop()
{
  running_ = false;
}

//============================================================================
ssize_t TcpProxy::SendToLan(const Packet* pkt)
{
  return edge_if_.Send(pkt);
}

//============================================================================
bool TcpProxy::SendToWan(Packet* pkt)
{
  if (!tcp_to_bpf_pkt_fifo_.IsOpen())
  {
    if (!tcp_to_bpf_pkt_fifo_.OpenSender())
    {
      LogW(kClassName, __func__, "Backpressure forwarder packet FIFO not "
           "ready yet, dropping packet.\n");
      return false;
    }
  }

  return tcp_to_bpf_pkt_fifo_.Send(pkt);
}

//============================================================================
void TcpProxy::MarkServerAsUnreachable(Ipv4Endpoint& server)
{
  for (uint8_t i = 0; i < num_server_lists_; i++)
  {
    LogD(kClassName, __func__, "Marking server %s as unreachable in server "
         "list %" PRIu8 ".\n", server.ToString().c_str(), i);

    server_lists_[i]->MarkAsUnreachable(server);
  }
}

//============================================================================
void TcpProxy::Reconnect(Packet* pkt)
{
  if (num_recon_reqs_ >= kMaxReconnects)
  {
    LogF(kClassName, __func__, "Maximum number of reconnection requests (%"
         PRIu8 ") exceeded.\n", kMaxReconnects);
  }

  recon_reqs_[num_recon_reqs_++] = pkt;
}

//============================================================================
uint32_t TcpProxy::SimpleSendPkt(ProxyIfType out_if, PktInfo* pkt_info)
{
  if (pkt_info->pkt == NULL)
  {
    LogW(kClassName, __func__, "Invalid argument. Discarding...\n");
    pkt_info_pool_.Recycle(pkt_info);
    return 0;
  }

  if (out_if == LAN)
  {
    pkt_info->pkt->UpdateChecksums();

    uint32_t bytes_written = edge_if_.Send(pkt_info->pkt);

    // Recycle the packet and delete its container.
    pkt_info_pool_.Recycle(pkt_info);

    return bytes_written;
  }

  packet_pool_.AssignPacketId(pkt_info->pkt);

  bool  sent_pkt     = false;
  bool  fifo_is_open = tcp_to_bpf_pkt_fifo_.IsOpen();

  if (!fifo_is_open)
  {
    fifo_is_open = tcp_to_bpf_pkt_fifo_.OpenSender();

    if (!fifo_is_open)
    {
      LogW(kClassName, __func__, "Backpressure forwarder packet FIFO not "
           "ready yet, dropping packet.\n");
    }
  }

  if (fifo_is_open)
  {
    sent_pkt = tcp_to_bpf_pkt_fifo_.Send(pkt_info->pkt);
  }

  if (sent_pkt)
  {
    // Remove the packet so only the PktInfo is recycled.
    // When the packet is processed by the bpf, the packet will be recycled.
    uint32_t length = pkt_info->pkt->GetLengthInBytes();
    pkt_info->pkt = NULL;
    pkt_info_pool_.Recycle(pkt_info);
    return length;
  }
  TRACK_UNEXPECTED_DROP(kClassName, packet_pool_);

  pkt_info_pool_.Recycle(pkt_info);
  return 0;
}

//============================================================================
void TcpProxy::SvcSocketsTimeout()
{
  LogD(kClassName, __func__, "Service sockets timeout fired for handle %"
       PRIu64 ".\n", svc_sockets_timer_.id());

  Time  now = Time::Now();

  // If we aren't configured to do direct access to the queue depths, update
  // them now.
  if (!qd_direct_access_)
  {
    local_queue_depths_.CopyFromShm(weight_qd_shared_memory_);
  }

  LogD(kClassName, __func__, "Servicing sockets, Queue depths are: %s.\n",
       local_queue_depths_.ToString().c_str());

  // Service all of the sockets.
  Socket*  iter = socket_mgr_.GetSocketList();
  while (iter != NULL)
  {
    iter->SvcEvents(now);

    iter = iter->next();
  }

  // Schedule the next service sockets timer.
  Time  end_time = Time::Now();
  Time  duration = Time::FromUsec(kDefaultSvcSocketsIntervalUs) -
    (end_time - now);
  if (duration.GetTimeInUsec() < 0)
  {
    duration = 0.0;
  }
  CallbackNoArg<TcpProxy>  callback(this, &TcpProxy::SvcSocketsTimeout);

  if (!timer_.StartTimer(duration, &callback, svc_sockets_timer_))
  {
    LogE(kClassName, __func__, "Error starting service sockets timer.\n");
  }

  next_sched_socket_svc_time_ = now + duration;

  LogD(kClassName, __func__, "Started service sockets timer with duration %s "
       "for handle %" PRId64 ".\n", duration.ToString().c_str(),
       svc_sockets_timer_.id());

  LogD(kClassName, __func__, "Finished servicing sockets.\n");
}

//============================================================================
bool TcpProxy::GetBinIndex(const iron::Ipv4Address& ip_addr,
                               iron::BinIndex& ret_index) const
{
  iron::BinIndex  bin_idx = bin_map_shm_.GetDstBinIndexFromAddress(ip_addr);

  if (bin_idx == iron::kInvalidBinIndex)
  {
    return false;
  }

  ret_index = bin_idx;

  return true;
}

//============================================================================
uint32_t TcpProxy::GetBinDepth(BinIndex bin_idx) const
{
  return local_queue_depths_.GetBinDepthByIdx(bin_idx);
}

//============================================================================
string TcpProxy::GetUtilityFnDef(uint16_t port_hbo)
{
  map<int, TcpContext*>::reverse_iterator  iter;
  for (iter = svc_configs_.rbegin(); iter != svc_configs_.rend(); ++iter)
  {
    if (iter->first <= port_hbo)
    {
      TcpContext*  context = iter->second;

      if (context->hi_port() >= port_hbo)
      {
        return context->util_fn_defn();
      }
      else
      {
        return default_utility_def_;
      }
    }
  }

  return default_utility_def_;
}

//============================================================================
int8_t TcpProxy::GetContextDscp(uint16_t port_hbo)
{
  map<int, TcpContext*>::reverse_iterator  iter;
  for (iter = svc_configs_.rbegin(); iter != svc_configs_.rend(); ++iter)
  {
    if (iter->first <= port_hbo)
    {
      TcpContext*  context = iter->second;

      if (context->hi_port() >= port_hbo)
      {
        return context->dscp();
      }
      else
      {
        return -1;
      }
    }
  }

  return -1;
}

//============================================================================
void TcpProxy::PushStats()
{
  LogD(kClassName, __func__, "Push stats timeout for handle %" PRIu64 ".\n",
       tcp_stats_push_.timer_handle.id());

  if (!tcp_stats_push_.is_active)
  {
    // We aren't pushing stats to an external client, but they still may be
    // logged to the log file.
    socket_mgr_.WriteStats();
  }
  else
  {
    // Start the next push of statistics to the remote control client.
    Writer<StringBuffer>*  writer =
      remote_control_.StartPushMessage(tcp_stats_push_.client_id,
                                       tcp_stats_push_.msg_id);

    // If NULL is returned, then we must stop pushing statistics immediately.
    if (writer == NULL)
    {
      LogD(kClassName, __func__, "Stopping statistics pushing.\n");

      tcp_stats_push_.is_active    = false;
      tcp_stats_push_.client_id    = 0;
      tcp_stats_push_.msg_id       = 0;
      tcp_stats_push_.interval_sec = 0.0;

      // The external client is no longer connected but the stats may still be
      // logged to the log file.
      socket_mgr_.WriteStats();
    }
    else
    {
      // Add in the statistics.
      socket_mgr_.WriteStats(writer);

      // Complete the push message and send it.
      remote_control_.SendPushMessage(tcp_stats_push_.client_id);
    }
  }

  // Start the next timer. We do this even if we are not pushing the
  // statistics to an external client, as they still may be logged to the log
  // file.
  Time                     duration;
  CallbackNoArg<TcpProxy>  callback(this, &TcpProxy::PushStats);

  if (tcp_stats_push_.is_active)
  {
    // We use the statistics interval extracted from the JSON message received
    // from the external client.
    duration = Time(tcp_stats_push_.interval_sec);
  }
  else
  {
    // We will use the statistics interval from the configuration.
    duration = Time::FromMsec(stats_interval_ms_);
  }

  if (!timer_.StartTimer(duration, &callback, tcp_stats_push_.timer_handle))
  {
    LogE(kClassName, __func__, "Error setting next statistics push timer.\n");

    if (tcp_stats_push_.is_active)
    {
      remote_control_.SendPushErrorMessage(tcp_stats_push_.client_id,
                                           tcp_stats_push_.msg_id,
                                           "Timer error.");
    }

    tcp_stats_push_.is_active    = false;
    tcp_stats_push_.client_id    = 0;
    tcp_stats_push_.msg_id       = 0;
    tcp_stats_push_.interval_sec = 0.0;
  }
  LogD(kClassName, __func__, "Started push stats timer: handle is %" PRIu64
       ", duration is %s\n", tcp_stats_push_.timer_handle.id(),
       duration.ToString().c_str());
}

//============================================================================
bool TcpProxy::AttachSharedMemory(const ConfigInfo& config_info)
{
  key_t   w_key   =
    config_info.GetUint("Tcp.Weight.SemKey", iron::kDefaultWeightSemKey);
  string  w_name  =
    config_info.Get("Tcp.Weight.ShmName", kDefaultWeightShmName);

  LogI(kClassName, __func__, "Attaching weights queue depth shared "
       "memory...\n");

  bool  weights_attached  =
    weight_qd_shared_memory_.Attach(w_key, w_name.c_str(),
                                    local_queue_depths_.GetShmSize());

  uint32_t  wait_count  = 0;

  while (!weights_attached)
  {
    sleep(1);

    ++wait_count;
    if (wait_count % 10 == 0)
    {
      if (wait_count % 120 == 0)
      {
        LogW(kClassName, __func__,
             "... Waiting to attach to queue depths shared memory.\n");
      }
      else
      {
        LogD(kClassName, __func__, "... Waiting to attach.\n");
      }
    }

    weights_attached  =
      weight_qd_shared_memory_.Attach(w_key, w_name.c_str(),
                                      local_queue_depths_.GetShmSize());
  }

  LogI(kClassName, __func__, "Queue weights shared memory "
       "attached (after %" PRIu32 " seconds).\n", wait_count);

  if (qd_direct_access_)
  {
    if (!local_queue_depths_.InitializeShmDirectAccess(
          &weight_qd_shared_memory_))
    {
      LogE(kClassName, __func__, "Unable to attach to shared memory for "
           "weight queue depth information.\n");
      return false;
    }
  }

  return true;
}

//============================================================================
void TcpProxy::ReceivePktsFromBpf()
{
  LogD(kClassName, __func__, "Servicing BPF file descriptor.\n");

  // \todo Currently, Packets that are received from the BPF CAN NOT grow in
  // length. If we find we need this, we will have to have the BPF "reserve"
  // some bytes at the beginning of all received Packets. See Start() method
  // where we receive from the TUN IF for an example of how this is done.

  // Read in packet indices from the IRON Backpressure Forwarder.
  if (bpf_to_tcp_pkt_fifo_.Recv())
  {
    Packet *packet;
    while (bpf_to_tcp_pkt_fifo_.GetNextRcvdPacket(&packet))
    {
      if (packet != NULL)
      {
        PacketType  pkt_type = packet->GetType();

        // Only expect IPv4 packets.
        if (pkt_type != IPV4_PACKET)
        {
          LogD(kClassName, __func__, "Received unsupported packet type "
               "0x%02x.\n", static_cast<unsigned int>(pkt_type));
          packet_pool_.Recycle(packet);
        }
        else
        {
          ProcessRcvdPkt(packet, WAN);
        }
      }
    }
  }
}

//============================================================================
void TcpProxy::ProcessRcvdPkt(Packet* packet, ProxyIfType in_if)
{
  // We first need to determine if the received packet is an tunneled TCP
  // packet. If so, the flow's TCP and IP headers are encapsulated and we need
  // to take this into account when extracting them.
  uint8_t  protocol;
  if (!packet->GetIpProtocol(protocol))
  {
    LogE(kClassName, __func__, "Unable to get packet protocol from received "
         "packet.\n");
    packet_pool_.Recycle(packet);
    return;
  }

  bool            is_tunnel = false;
  struct iphdr*   ip_hdr    = NULL;
  struct tcphdr*  tcp_hdr   = NULL;
  if (protocol == IPPROTO_UDP)
  {
    // This is a TCP packet encapsulated in a UDP tunnel. Verify that the
    // destination port for the encapsulated packet is supported by the
    // proxy. Currently, we only support VXLAN tunnels which have a
    // destination port of 4789.
    uint16_t  dport;
    if (!packet->GetDstPort(dport))
    {
      LogE(kClassName, __func__, "Unable to get destination port from "
           "received packet.\n");
      packet_pool_.Recycle(packet);
      return;
    }

    if (ntohs(dport) != iron::kVxlanTunnelDstPort)
    {
      LogE(kClassName, __func__, "Received tunneled packet to unsupported "
           "destination port: %" PRIu16 ".\n", dport);
      packet_pool_.Recycle(packet);
      return;
    }

    LogD(kClassName, __func__, "Rcvd. VXLAN tunneled packet.\n");

    is_tunnel = true;

    // Skip over the encapsulating tunnel headers to get to the IP and TCP
    // headers for the received TCP packet.
    ip_hdr  = reinterpret_cast<struct iphdr*>(
      packet->GetBuffer(iron::kVxlanTunnelHdrLen));
    tcp_hdr = reinterpret_cast<struct tcphdr*>(
      packet->GetBuffer(iron::kVxlanTunnelHdrLen + (ip_hdr->ihl * 4)));
  }
  else
  {
    // Normal, non-tunneled TCP packet.
    ip_hdr  = packet->GetIpHdr();
    tcp_hdr = packet->GetTcpHdr();
  }

  if ((tcp_hdr == NULL) || (ip_hdr == NULL))
  {
    LogE(kClassName, __func__, "Packet is not an IPv4 TCP packet. Dumping "
         "contents:\n%s\n", packet->ToHexString().c_str());
    LogF(kClassName, __func__, "TCP proxy is misconfigured.\n");
  }

  // Verify that the destination address of the packet received on the
  // LAN-facing interface has a mapping in the BinMap. If no such mapping is
  // found, simply recycle the packet.
  BinIndex index = iron::kInvalidBinIndex;
  if ((in_if == LAN) &&
      (!GetBinIndex(Ipv4Address(ip_hdr->daddr), index)))
  {
    LogW(kClassName, __func__, "No mapping for destination address %s found "
         "in BinMap.\n", Ipv4Address(ip_hdr->daddr).ToString().c_str());
    packet_pool_.Recycle(packet);
    packet = NULL;
    return;
  }

  // Try demuxing to an existing socket.
  FourTuple  ft(ip_hdr->saddr, tcp_hdr->th_sport,
                ip_hdr->daddr, tcp_hdr->th_dport);

  Socket*  sock = socket_mgr_.GetExistingSocket(ft);

  bool  created_active_socket = false;

  if (sock)
  {
    LogD(kClassName, __func__, "Demuxed packet to initialized socket on %s "
         "IF with flow myport(%" PRIu32 ") hisport(%" PRIu32 ") seq(%" PRIu32
         ") ack(%" PRIu32 ")\n", sock->cfg_if_id() == WAN ? "WAN" : "LAN",
         ntohs(sock->my_port()), ntohs(sock->his_port()), ntohl(tcp_hdr->th_seq),
         htonl(tcp_hdr->th_ack));

    if ((in_if == LAN) && sock->is_tunneled())
    {
      // We have recevied an encapsulated TCP packet for a known
      // flow. "Remove" the tunnel headers.
      packet->RemoveBytesFromBeginning(iron::kVxlanTunnelHdrLen);
    }
  }
  else
  {
    if (tcp_hdr->th_flags & TH_RST)
    {
      // We have no state for the received packet, so just recycle it.
      LogD(kClassName, __func__, "Discarding RST packet with no state.\n");

      packet_pool_.Recycle(packet);

      return;
    }

    if ((tcp_hdr->th_flags & TH_SYN) && (tcp_hdr->th_flags & TH_ACK))
    {
      // If we are here, we have received a SYN/ACK packet for which we don't
      // have any existing flow state information. This means that the proxy
      // never "saw" the SYN packet. We'll log an error and recycle the
      // packet.
      LogE(kClassName, __func__, "Received a SYN/ACK packet on %s IF for "
           "flow %s for which there is no existing internal proxy flow "
           "information. Discarding packet with no state.\n",
           in_if == LAN ? "LAN" : "WAN", ft.ToString().c_str());

      packet_pool_.Recycle(packet);

      return;
    }

    if (!(tcp_hdr->th_flags & TH_SYN))
    {
      if (in_if == LAN)
      {
        // We have no state and the receive packet is not a SYN, so generate a
        // RST and send it out the interface the packet was received on.
        PktInfo*  smpl_pkt_info = pkt_info_pool_.Get(packet);
        if (smpl_pkt_info == NULL)
        {
          LogF(kClassName, __func__, "Error allocating new PktInfo.\n");
          return;
        }

        SimpleReset(smpl_pkt_info, in_if, is_tunnel);
      }
      else
      {
        // If we are here, we don't have any existing state, and the packet
        // was received on the WAN side and doesn't have a SYN. This can
        // happen with multipath delayed packets after the socket is
        // closed. We simply recycle the packet.
        LogD(kClassName, __func__, "Discarding packet with no state.\n");

        packet_pool_.Recycle(packet);
      }

      return;
    }

    sock = CreateSocketPair(packet, in_if, is_tunnel);
    if (sock == NULL)
    {
      LogW(kClassName, __func__, "Error creating socket pair.\n");

      return;
    }

    created_active_socket = true;
  }

  if (sock->state() == TCP_CLOSE)
  {
    // The socket is in a CLOSED state, so simply recycle the packet.
    packet_pool_.Recycle(packet);
    return;
  }

  if (sock->desired_dscp() != -1)
  {
    if (!packet->SetIpDscp(sock->desired_dscp()))
    {
      LogW(kClassName, __func__, "Failed to set DSCP value %" PRIu8
           " in packet.\n", sock->desired_dscp());
    }
  }
  else
  {
    if (sock->tos() != ip_hdr->tos)
    {
      sock->set_tos(ip_hdr->tos);
    }
  }

  if ((sock->peer()) && (sock->peer()->tos() != ip_hdr->tos))
  {
    sock->peer()->set_tos(ip_hdr->tos);
  }

  // Record the reception of a packet. We only record statistics for WAN side
  // sockets.
  if (sock->cfg_if_id() == WAN)
  {
    int  len = (int)(ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) -
                     (tcp_hdr->th_off << 2));

    LogD(kClassName, __func__, "Recording %d bytes rcvd for on %s IF for "
         "flow myport(%" PRIu16 ") hisport(%" PRIu16 ")\n",
         len, sock->cfg_if_id() == WAN ? "WAN" : "LAN", ntohs(sock->my_port()),
         ntohs(sock->his_port()));

    sock->IncrementRcvdBytes(len);
  }

  PktInfo*  pkt_info = pkt_info_pool_.Get(packet);
  if (pkt_info == NULL)
  {
    LogF(kClassName, __func__, "Error allocating new PktInfo.\n");
    return;
  }

  pkt_info->seq_num  = ntohl(tcp_hdr->th_seq);
  pkt_info->data_len = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) -
    (tcp_hdr->th_off * 4);
  pkt_info->flags    = tcp_hdr->th_flags;

  LogD(kClassName, __func__, "Created PktInfo for packet rcvd on %s IF: seq "
       "(%" PRIu32 ") data len (%" PRIu32 ").\n", sock->cfg_if_id() == WAN ?
       "WAN" : "LAN", pkt_info->seq_num, pkt_info->data_len);

  int  rc = sock->ProcessPkt(pkt_info, tcp_hdr, ip_hdr);

  // Need to pull these out to make sure s1 and s2 are non-NULL, otherwise
  // this will generate a core dump
  Socket*  s1 = sock;
  Socket*  s2 = sock->peer();

  switch (rc)
  {
    case 0:
      socket_mgr_.CloseSocket(s1);
      socket_mgr_.CloseSocket(s2);
      break;

    case -2:
      s1->Abort();
      s2->Abort();
      break;

    case -1:
      break;

    default:
      if ((sock->gw_flags() & PROXY_SEND_SYN) && (s2 > 0)) // <- UGGGH!
      {
        sock->gw_flags() &= (~PROXY_SEND_SYN);

        LogD(kClassName, __func__, "Invoking connect...\n");

        if (!s2->Connect())
        {
          // If you can't complete the connection you must abort.
          s1->Abort();
          s2->Abort();

          return;
        }

        // If we created a socket pair, we would have set
        // created_active_socket to true. If so, the passive socket is s1 and
        // the active socket is s2.
        if (created_active_socket)
        {
          Socket*  UNUSED(passive_socket) = s1;
          Socket*  active_socket          = s2;
          LogI(kClassName, __func__, "Active side %d %d %d passive side %d "
               "%d %d\n", htons(active_socket->my_port()),
               htons(active_socket->his_port()), active_socket->cfg_if_id(),
               htons(passive_socket->my_port()), htons(passive_socket->his_port()),
               passive_socket->cfg_if_id());

          // Setup the src and destination endpoints for statistics
          // reporting. We will report statistics on the WAN side socket but
          // the reported flow id will be the corresponding LAN side
          // addresses/ports. See the class level comment in TpSocket.hh for
          // an example of why the values are as they are below.
          if (active_socket->cfg_if_id() == WAN)
          {
            Ipv4Endpoint& stats_src_endpt = active_socket->stats_src_endpt();
            Ipv4Endpoint& stats_dst_endpt = active_socket->stats_dst_endpt();

            stats_src_endpt.set_address(active_socket->peer()->his_addr().s_addr);
            stats_src_endpt.set_port(active_socket->peer()->his_port());
            stats_dst_endpt.set_address(active_socket->peer()->my_addr().s_addr);
            stats_dst_endpt.set_port(active_socket->peer()->my_port());
          }
          else
          {
            // We can't use tpSock here as it may have been cloned. Instead we
            // will use the activeSock addresses/ports as it is on the LAN
            // side.
            Ipv4Endpoint& stats_src_endpt =
              active_socket->peer()->stats_src_endpt();
            Ipv4Endpoint& stats_dst_endpt =
              active_socket->peer()->stats_dst_endpt();

            stats_src_endpt.set_address(active_socket->my_addr().s_addr);
            stats_src_endpt.set_port(active_socket->my_port());
            stats_dst_endpt.set_address(active_socket->his_addr().s_addr);
            stats_dst_endpt.set_port(active_socket->his_port());
          }
        }
      }

      break;
  }
}

//============================================================================
void TcpProxy::SimpleReset(PktInfo* rst_pkt_info, ProxyIfType rcv_if,
                           bool is_tunnel)
{
  if (is_tunnel)
  {
    // The received packet is a VXLAN tunneled packet. We need to swap:
    //
    // - the source and destination addresses in the outer IP header
    // - the destination and source MAC addresses in the inner Ethernet header
    struct iphdr*  ip_hdr   = rst_pkt_info->pkt->GetIpHdr();
    uint32_t       tmp_addr = ip_hdr->saddr;

    ip_hdr->saddr      = ip_hdr->daddr;
    ip_hdr->daddr      = tmp_addr;

    uint8_t         tmp_eth_addr[ETH_ALEN];
    struct ethhdr*  eth_hdr = reinterpret_cast<struct ethhdr*>(
      rst_pkt_info->pkt->GetBuffer(sizeof(struct iphdr) +
                                   sizeof(struct udphdr) + 8));

    memcpy(tmp_eth_addr, eth_hdr->h_dest, ETH_ALEN);
    memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
    memcpy(eth_hdr->h_source, tmp_eth_addr, ETH_ALEN);

    // Now, we temporarily "remove" the VXLAN headers from the packet so that
    // we can create the RST packet to send back to the source of the received
    // packet.
    rst_pkt_info->pkt->RemoveBytesFromBeginning(iron::kVxlanTunnelHdrLen);
  }


  // Swap src/dst addrs and ports, seq and ack numbers, and set RST flag. Then
  // send RST packet back out interface it was received on. Additionally, trim
  // off all TCP header options and any data in the received packet and set
  // the window size to 0.
  struct iphdr*   ip_hdr  = rst_pkt_info->pkt->GetIpHdr();
  struct tcphdr*  tcp_hdr = rst_pkt_info->pkt->GetTcpHdr();

  uint32_t  tmp_addr = ip_hdr->saddr;
  ip_hdr->saddr      = ip_hdr->daddr;
  ip_hdr->daddr      = tmp_addr;

  uint16_t  tmp_port = tcp_hdr->th_sport;
  tcp_hdr->th_sport  = tcp_hdr->th_dport;
  tcp_hdr->th_dport  = tmp_port;

  uint32_t  tmp_seq = tcp_hdr->th_seq;
  tcp_hdr->th_seq   = tcp_hdr->th_ack;
  tcp_hdr->th_ack   = tmp_seq;

  tcp_hdr->th_flags |= TH_RST;

  tcp_hdr->th_win = 0;

  ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
  tcp_hdr->th_off = sizeof(struct tcphdr) >> 2;
  rst_pkt_info->pkt->SetLengthInBytes(sizeof(struct iphdr) +
                                      sizeof(struct tcphdr));

  if (is_tunnel)
  {
    // Make sure that the checksums are computed on the inner packet.
    rst_pkt_info->pkt->UpdateChecksums();

    // "Add" back the VXLAN headers. The bytes were never removed from the
    // received packet so we simply need to add bytes to the beginning of the
    // packet.
    rst_pkt_info->pkt->AddBytesToBeginning(iron::kVxlanTunnelHdrLen);
    rst_pkt_info->pkt->SetLengthInBytes(iron::kVxlanTunnelHdrLen +
                                        sizeof(struct iphdr) +
                                        sizeof(struct tcphdr));
  }

  if (SimpleSendPkt(rcv_if, rst_pkt_info) < 0)
  {
    LogW(kClassName, __func__, "Error sending RST.\n");
    pkt_info_pool_.Recycle(rst_pkt_info);
  }
}

//============================================================================
Socket* TcpProxy::CreateSocketPair(Packet* packet, ProxyIfType in_if,
                                   bool is_tunnel)
{
  bool            seamless_handoff = false;
  uint32_t        tag              = flow_tag();
  struct tcphdr*  tcp_hdr          = NULL;
  struct tcphdr*  handoff_tcp_hdr  = NULL;
  struct iphdr*   ip_hdr           = NULL;
  struct iphdr*   handoff_ip_hdr   = NULL;

  if (is_tunnel)
  {
    // Skip over the encapsulating tunnel headers to get to the IP and TCP
    // headers for the received TCP packet.
    ip_hdr  = reinterpret_cast<struct iphdr*>(
      packet->GetBuffer(iron::kVxlanTunnelHdrLen));
    tcp_hdr = reinterpret_cast<struct tcphdr*>(
      packet->GetBuffer(iron::kVxlanTunnelHdrLen + (ip_hdr->ihl * 4)));
  }
  else
  {
    ip_hdr  = packet->GetIpHdr();
    tcp_hdr = packet->GetTcpHdr();
  }

  Ipv4Endpoint  client_configured_server(ip_hdr->daddr, tcp_hdr->th_dport);
  Ipv4Endpoint  handoff_server;

  LogD(kClassName, __func__, "Number of server lists is %" PRIu8 ", client "
       "configured server is %s.\n", num_server_lists_,
       client_configured_server.ToString().c_str());

  // Determine if the server destination, an address:port pair, from the
  // received TCP SYN packet matches a server destination for which we are
  // doing seamless handoffs. We only need to worry about this for packets
  // that were received on the LAN-facing interface.
  //
  // NOTE: For now, we don't support seamless handoffs for tunneled packets.
  if ((in_if == LAN) && !is_tunnel)
  {
    for (uint8_t i = 0; i < num_server_lists_; i++)
    {
      if (client_configured_server ==
          server_lists_[i]->client_configured_server())
      {
        if (server_lists_[i]->GetServer(handoff_server))
        {
          seamless_handoff = true;

          LogI(kClassName, __func__, "Doing seamless handoff for client "
               "configured server %s to server %s.\n",
               client_configured_server.ToString().c_str(),
               handoff_server.ToString().c_str());

          handoff_tcp_hdr  = new (std::nothrow) struct tcphdr;
          handoff_ip_hdr   = new (std::nothrow) struct iphdr;
          if ((handoff_tcp_hdr == NULL) || (handoff_ip_hdr == NULL))
          {
            LogF(kClassName, __func__, "Error allocating new TCP or IP "
                 "header.\n");
            return NULL;
          }
          memcpy(handoff_tcp_hdr, tcp_hdr, sizeof(struct tcphdr));
          memcpy(handoff_ip_hdr, ip_hdr, sizeof(struct iphdr));
          handoff_ip_hdr->daddr     = handoff_server.address();
          handoff_tcp_hdr->th_dport = handoff_server.port();
          break;
        }
        else
        {
          LogI(kClassName, __func__, "There are no reachable servers for "
               "client configured server %s. Generating and sending TCP RST "
               "packet.\n", client_configured_server.ToString().c_str());

          // There are no reachable alternate servers for the received
          // destination address. Generate a TCP RST and send it out the
          // LAN-facing interface.
          GenerateAndSendReset(tcp_hdr, ip_hdr);
          return NULL;
        }
      }
    }
  }

  // Create passive socket.
  LogD(kClassName, __func__, "Attempting to create passive socket...\n");

  Socket*  passive_socket = NULL;
  if ((passive_socket = CreatePassiveSocket(tcp_hdr, ip_hdr)) == NULL)
  {
    LogE(kClassName, __func__, "Error creating passive socket.\n");
    return NULL;
  }

  socket_mgr_.AddSocket(passive_socket);

  passive_socket->set_tos(ip_hdr->tos);
  passive_socket->set_flow_tag(tag);
  passive_socket->set_cfg_if_id(in_if);

  passive_socket->SetProxyOptions();
  passive_socket->SetMss(0);

  passive_socket->set_prev_state(TCP_CLOSE);
  passive_socket->set_state(TCP_LISTEN);
  passive_socket->set_timeout(0x7ffffff);

  // Create active socket.
  LogD(kClassName, __func__, "Attempting to create active socket...\n");

  Socket*         active_socket         = NULL;
  struct tcphdr*  active_socket_tcp_hdr =
    (handoff_tcp_hdr == NULL) ? tcp_hdr : handoff_tcp_hdr;
  struct iphdr*   active_socket_ip_hdr  =
    (handoff_ip_hdr == NULL) ? ip_hdr : handoff_ip_hdr;

  if ((active_socket = CreateActiveSocket(active_socket_tcp_hdr,
                                          active_socket_ip_hdr)) == NULL)
  {
    LogE(kClassName, __func__, "Error creating active socket. "
         "Closing passive socket.\n");
    socket_mgr_.CloseSocket(passive_socket);

    return NULL;
  }

  socket_mgr_.AddSocket(active_socket);

  // Pass the seamless server handoff information to the newly created
  // sockets, if required.
  if (seamless_handoff)
  {
    passive_socket->set_do_seamless_handoff();
    passive_socket->set_seamless_handoff_endpoint(handoff_server);
    active_socket->set_do_seamless_handoff();
    active_socket->set_client_configured_server_endpoint(
      client_configured_server);
  }

  if (is_tunnel)
  {
    // The packet is encapsulated. Remember the tunnel headers in the active
    // socket so that they can be prepended to the tranmitted SYN packets. In
    // the passive socket we remember the tunnel headers and then invert them
    // so they are ready for transmissions to the LAN-facing interface. Then
    // "remove" the tunnel headers from the received packet.
    memcpy(passive_socket->tunnel_hdrs(), packet->GetBuffer(),
           iron::kVxlanTunnelHdrLen);
    passive_socket->InvertTunnelHdrs();
    memcpy(active_socket->tunnel_hdrs(), packet->GetBuffer(),
           iron::kVxlanTunnelHdrLen);
    packet->RemoveBytesFromBeginning(iron::kVxlanTunnelHdrLen);

    // Remember that the socket pair is supporting a tunnel.
    passive_socket->set_is_tunneled();
    active_socket->set_is_tunneled();
  }

  // Set the tag for both sockets to help with tracking.
  active_socket->set_flow_tag(tag);

  if (in_if == LAN)
  {
    active_socket->set_cfg_if_id(WAN);
  }
  else
  {
    active_socket->set_cfg_if_id(LAN);
  }

  active_socket->SetProxyOptions();
  active_socket->set_tos(ip_hdr->tos);

  // Now, connect the 2 sockets.
  LogD(kClassName, __func__, "Attempting to connect 2 sockets...\n");

  passive_socket->set_peer(active_socket);
  active_socket->set_peer(passive_socket);
  passive_socket->gw_flags() |= PROXY_SEND_SYN;

  active_socket->send_buf()->init_una_seq(active_socket->snd_una());
  active_socket->peer()->set_last_uwe(active_socket->send_buf()->uwe());

  LogI(kClassName, __func__, "Creating Utility function, Active side %d %d "
       "%d passive side %d %d %d\n", htons(active_socket->my_port()),
       htons(active_socket->his_port()), active_socket->cfg_if_id(),
       htons(passive_socket->my_port()), htons(passive_socket->his_port()),
       passive_socket->cfg_if_id());

  // Get the utility function definition for the socket's four tuple. The
  // values in the search 4-tuple depend on whether the active socket is on
  // the LAN or WAN side. Once the search 4-tuple is created, search the TCP
  // Proxy's flow cache for the utility function definition to assign to the
  // newly created socket. If not found there, search the Service definitions
  // for the utility function definition.
  string     utility_fn_def;
  FourTuple  four_tuple(active_socket->my_addr().s_addr,
                        active_socket->my_port(),
                        active_socket->his_addr().s_addr,
                        active_socket->his_port());

  // Now that we have a 4-tuple for the new TCP flow, search the TCP Proxy's
  // flow cache for the utility function definition to assign to the newly
  // created socket. If not found there, search the Service definitions for
  // the utility function definition.
  if (!GetFlowUtilityFnDef(four_tuple, utility_fn_def))
  {
    utility_fn_def = GetUtilityFnDef(ntohs(four_tuple.dst_port_nbo()));
  }

  if (active_socket->cfg_if_id() == WAN)
  {
    // Since the active socket is on the WAN side, we find the bin index by
    // matching the destination address of the original packet when not doing
    // a seamless handoff and by matching the handoff server address when
    // doing a seamless handoff.
    Ipv4Address handoff_addr =
      (seamless_handoff ? handoff_server : client_configured_server);
    BinIndex idx = iron::kInvalidBinIndex;
    if (!GetBinIndex(handoff_addr, idx))
    {
      LogF(kClassName, __func__, "No bin defined for address %s\n",
           handoff_addr.ToString().c_str());
    }
    active_socket->set_bin_idx(idx);

    // The active socket is on the WAN side, so set the utility function in
    // the active_socket. We must do this after the socket's bin index has
    // been set.
    active_socket->ConfigureUtilityFn(utility_fn_def, local_queue_depths_);
    LogI(kClassName, __func__, "Flow tag: %" PRIu32 " <==> %s\n", tag,
         four_tuple.ToString().c_str());
  }
  else
  {
    // Since the active socket is on the LAN side, we find the bin index by
    // matching the source address of the original packet.
    BinIndex idx = iron::kInvalidBinIndex;
    if (!GetBinIndex(ip_hdr->saddr, idx))
    {
      LogF(kClassName, __func__, "No bin defined for address %" PRIu32 "\n",
           ip_hdr->saddr);
    }
    passive_socket->set_bin_idx(idx);

    // The passive_socket is on the WAN side, so set the utility function in
    // the passive_socket. We must do this after the socket's bin index has
    // been set.
    passive_socket->ConfigureUtilityFn(utility_fn_def, local_queue_depths_);
    LogI(kClassName, __func__, "Flow tag: %" PRIu32 " <==> %s\n", tag,
         four_tuple.ToString().c_str());
  }

  if (passive_socket->cfg_if_id() == LAN)
  {
    int8_t  context_dscp = -1;
    if (!GetFlowDscpDef(four_tuple, context_dscp))
    {
      context_dscp = GetContextDscp(ntohs(four_tuple.dst_port_nbo()));
    }

    passive_socket->set_desired_dscp(context_dscp);
    if (context_dscp != -1)
    {
      packet->SetIpDscp(context_dscp);
    }
  }

  LogI(kClassName, __func__, "Flow tag: %" PRIu32 " <==> %s (%s)\n", tag,
       four_tuple.ToString().c_str(), is_tunnel ? "is tunnel" :
       "is not tunnel");

  if (!timer_.IsTimerSet(svc_sockets_timer_))
  {
    // We have created sockets and the service sockets timer is not started,
    // so start it now.
    Time                     duration =
      Time::FromUsec(kDefaultSvcSocketsIntervalUs);
    next_sched_socket_svc_time_       = Time::Now() + duration;
    CallbackNoArg<TcpProxy>  callback(this, &TcpProxy::SvcSocketsTimeout);

    if (!timer_.StartTimer(duration, &callback, svc_sockets_timer_))
    {
      LogE(kClassName, __func__, "Error setting service sockets timer.\n");
    }

    LogD(kClassName, __func__, "Started service sockets timer with duration "
         "%s for handle %" PRIu64 ".\n", duration.ToString().c_str(),
         svc_sockets_timer_.id());
  }

  // If we are doing seamless handoff for the socket pair that was just
  // created, be sure to delete the temporary copies of the original TCP and
  // IP headers.
  if (handoff_tcp_hdr != NULL)
  {
    delete handoff_tcp_hdr;
    handoff_tcp_hdr = NULL;
  }

  if (handoff_ip_hdr != NULL)
  {
    delete handoff_ip_hdr;
    handoff_ip_hdr = NULL;
  }

  return passive_socket;
}

//============================================================================
Socket* TcpProxy::CreatePassiveSocket(const struct tcphdr* tcp_hdr,
                                      const struct iphdr* ip_hdr)
{
  Socket*  new_sock = new (std::nothrow) Socket(*this, packet_pool_, bin_map_shm_,
                                                pkt_info_pool_, proxy_config_,
                                                socket_mgr_);

  if (new_sock == NULL)
  {
    LogF(kClassName, __func__, "Error allocating new Socket.\n");
    return new_sock;
  }

  // Set the starting sequence number equal to the sequence number in the
  // received packet.
  new_sock->set_seq_num(ntohl(tcp_hdr->th_seq));
  new_sock->set_snd_una(ntohl(tcp_hdr->th_seq));
  new_sock->set_seq_sent(ntohl(tcp_hdr->th_seq));
  new_sock->set_snd_max(ntohl(tcp_hdr->th_seq));
  new_sock->set_last_uwe_in(ntohl(tcp_hdr->th_seq));
  new_sock->set_initial_seq_num(ntohl(tcp_hdr->th_seq));

  new_sock->ph().src.s_addr = ip_hdr->daddr;

  new_sock->set_is_active(false);

  // Complete the bind early. This is so we can insert the 4-tuple into the
  // map soonest.
  new_sock->my_addr().s_addr  = ip_hdr->daddr;
  new_sock->set_my_port(tcp_hdr->th_dport);
  new_sock->his_addr().s_addr = ip_hdr->saddr;
  new_sock->set_his_port(tcp_hdr->th_sport);

  new_sock->t_template().saddr = ip_hdr->daddr;
  new_sock->t_template().daddr = ip_hdr->saddr;

  return new_sock;
}

//============================================================================
Socket* TcpProxy::CreateActiveSocket(const struct tcphdr* tcp_hdr,
                                     const struct iphdr* ip_hdr)
{
  Socket*  new_sock = new (std::nothrow) Socket(*this, packet_pool_, bin_map_shm_,
                                                pkt_info_pool_, proxy_config_,
                                                socket_mgr_);

  if (new_sock == NULL)
  {
    LogF(kClassName, __func__, "Error allocating new Socket.\n");
    return new_sock;
  }

  // Set the starting sequence number equal to the sequence number in the
  // received packet.
  new_sock->set_seq_num(ntohl(tcp_hdr->th_seq));
  new_sock->set_snd_una(ntohl(tcp_hdr->th_seq));
  new_sock->set_seq_sent(ntohl(tcp_hdr->th_seq));
  new_sock->set_snd_max(ntohl(tcp_hdr->th_seq));
  new_sock->set_last_uwe_in(ntohl(tcp_hdr->th_seq));
  new_sock->set_initial_seq_num(ntohl(tcp_hdr->th_seq));

  new_sock->ph().src.s_addr = ip_hdr->saddr;

  new_sock->set_is_active(true);

  // Complete the bind early. This is so we can insert the 4-tuple into the
  // map soonest.
  new_sock->his_addr().s_addr = ip_hdr->daddr;
  new_sock->set_his_port(tcp_hdr->th_dport);
  new_sock->my_addr().s_addr  = ip_hdr->saddr;
  new_sock->set_my_port(tcp_hdr->th_sport);

  new_sock->t_template().saddr = ip_hdr->saddr;
  new_sock->t_template().daddr = ip_hdr->daddr;

  return new_sock;
}

//============================================================================
void TcpProxy::GenerateAndSendReset(const struct tcphdr* tcp_hdr,
                                    const struct iphdr* ip_hdr)
{
  LogD(kClassName, __func__, "Generating and sending a TCP RST packet.\n");

  PktInfo*  rst_pkt_info = pkt_info_pool_.Get();
  rst_pkt_info->pkt->SetLengthInBytes(sizeof(struct iphdr) +
                                      sizeof(struct tcphdr));

  LogD(kClassName, __func__, "Setting length in bytes to %zd.\n",
       sizeof(struct iphdr) + sizeof(struct tcphdr));

  struct iphdr*   rst_ip_hdr  =
    reinterpret_cast<struct iphdr*>(rst_pkt_info->pkt->GetBuffer());
  struct tcphdr*  rst_tcp_hdr =
    reinterpret_cast<struct tcphdr*>(
      rst_pkt_info->pkt->GetBuffer(sizeof(struct tcphdr)));

  memset(rst_ip_hdr, 0, sizeof(struct iphdr));
  memset(rst_tcp_hdr, 0, sizeof(struct tcphdr));

  rst_ip_hdr->ihl       = sizeof(struct iphdr) >> 2;
  rst_ip_hdr->version   = 4;
  rst_ip_hdr->tot_len   = ntohs(sizeof(struct iphdr) + sizeof(struct tcphdr));
  rst_ip_hdr->ttl       = 96;
  rst_ip_hdr->protocol  = IPPROTO_TCP;
  rst_ip_hdr->saddr     = ip_hdr->daddr;
  rst_ip_hdr->daddr     = ip_hdr->saddr;
  rst_tcp_hdr->th_sport = tcp_hdr->th_dport;
  rst_tcp_hdr->th_dport = tcp_hdr->th_sport;
  rst_tcp_hdr->ack_seq  = htonl(ntohl(tcp_hdr->th_seq) + 1);
  rst_tcp_hdr->th_off   = 5;
  rst_tcp_hdr->th_flags = (TH_RST | TH_ACK);

  if (SimpleSendPkt(LAN, rst_pkt_info) < 0)
  {
    LogW(kClassName, __func__, "Error sending RST.\n");
    pkt_info_pool_.Recycle(rst_pkt_info);
  }
}

//============================================================================
void TcpProxy::ProcessRemoteControlMessage()
{
  LogW(kClassName, __func__, "Processing received remote control "
       "message...\n");

  // Switch on the type of request message.
  RmtCntlMsgType  msg_type = remote_control_.msg_type();

  switch (msg_type)
  {
    case iron::RC_SET:
      ProcessSetMessage();
      break;

    case iron::RC_GET:
      ProcessGetMessage();
      break;

    case iron::RC_PUSHREQ:
      ProcessPushReqMessage();
      break;

    case iron::RC_PUSHSTOP:
      ProcessPushStopMessage();
      break;

    case iron::RC_INVALID:
    default:
      LogE(kClassName, __func__, "Unknown remote control message type: %d\n",
           static_cast<int>(msg_type));

      // Abort this client connection.
      remote_control_.AbortClient();
  }
}

//============================================================================
void TcpProxy::ProcessSetMessage()
{
  bool          success  = false;
  const Value*  key_vals = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetSetMessage(target, key_vals)) ||
      (key_vals == NULL))
  {
    LogE(kClassName, __func__, "Error getting remote control set message.\n");
    remote_control_.SendSetReplyMessage(false, "Message processing error.");

    return;
  }

  LogD(kClassName, __func__, "Processing remote control set message for "
       "target %s.\n", target.c_str());

  // ---------- TCP proxy target ----------
  if (target == "tcp_proxy")
  {
    bool  overall_success = true;

    // Loop over the key/value pairs, processing each one.
    for (Value::ConstMemberIterator it = key_vals->MemberBegin();
         it != key_vals->MemberEnd(); ++it)
    {
      // The key must be a string.
      if (!(it->name.IsString()))
      {
        LogE(kClassName, __func__, "Error, key is not a string.\n");
        success = false;
        err_msg = "Key is not a string.";
      }
      else
      {
        string  key = it->name.GetString();

        // ---------- Service Definition ----------
        if (key == "add_service")
        {
          success = ProcessSvcDefUpdateMsg(key, it->value, err_msg);
        }
        // ---------- Flow Definition ----------
        else if ((key == "add_flow") || (key == "del_flow") ||
                 (key == "off_flow") || (key == "update_util"))
        {
          success = ProcessFlowDefUpdateMsg(key, it->value, err_msg);
        }
        else
        {
          success = false;
          err_msg = "Unknown set key: " + key;
        }
      }

      overall_success = (overall_success && success);
    }

    success = overall_success;
  }
  else
  {
    LogE(kClassName, __func__, "Unknown remote control set message target: "
         "%s\n", target.c_str());
    err_msg = "Unknown target: " + target;
  }

  remote_control_.SendSetReplyMessage(success, err_msg);

}

//============================================================================
void TcpProxy::ProcessGetMessage()
{

  bool          success = false;
  const Value*  keys    = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetGetMessage(target, keys)) || (keys == NULL))
  {
    LogE(kClassName, __func__, "Error getting remote control get message.\n");
    remote_control_.StartGetReplyMessage(false, "Message processing error.");
    remote_control_.SendGetReplyMessage(false);
    return;
  }

  LogD(kClassName, __func__, "Processing remote control get message for "
       "target %s.\n", target.c_str());

  // ---------- TCP Proxy target ----------
  if (target == "tcp_proxy")
  {
    success = true;

    // Only support the "stats" key right now, so make this loop simple.
    for (SizeType i = 0; i < keys->Size(); ++i)
    {
      if ((*keys)[i].IsString())
      {
        string  key = (*keys)[i].GetString();

        if (key == "stats")
        {
          continue;
        }

        LogE(kClassName, __func__, "Unsupported get message key %s.\n",
             key.c_str());
        success = false;
        err_msg = "Unsupported key " + key + ".";
      }
      else
      {
        LogE(kClassName, __func__, "Non-string key is not supported.\n");
        success = false;
        err_msg = "Non-string key.";
      }
    }

    Writer<StringBuffer>* writer =
      remote_control_.StartGetReplyMessage(success, err_msg);

    if (success)
    {
      socket_mgr_.WriteStats(writer);
    }

    remote_control_.SendGetReplyMessage(success);
    return;
  }

  LogE(kClassName, __func__, "Unknown remote control get message target: "
       "%s\n", target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.StartGetReplyMessage(false, err_msg);
  remote_control_.SendGetReplyMessage(false);
}

//============================================================================
void TcpProxy::ProcessPushReqMessage()
{
  bool          success   = false;
  uint32_t      client_id = 0;
  uint32_t      msg_id    = 0;
  double        interval  = 0.0;
  const Value*  keys      = NULL;
  string        target;
  string        err_msg;

  // Get the message contents.
  if ((!remote_control_.GetPushRequestMessage(client_id, msg_id, target,
                                              interval, keys)) ||
      (keys == NULL) || (interval < 0.01))
  {
    LogE(kClassName, __func__, "Error getting remote control push request "
         "message.\n");
    return;
  }

  LogD(kClassName, __func__, "Processing remote control push request message "
       "for client %" PRIu32 " msg %" PRIu32 " target %s interval %f.\n",
       client_id, msg_id, target.c_str(), interval);

  // ---------- TCP Proxy target ----------
  if (target == "tcp_proxy")
  {
    success = true;

    // Only support the "stats" key right now, so make this loop simple.
    for (SizeType i = 0; i < keys->Size(); ++i)
    {
      if ((*keys)[i].IsString())
      {
        string  key = (*keys)[i].GetString();

        if (key == "stats")
        {
          continue;
        }

        LogE(kClassName, __func__, "Unsupported push request message key "
             "%s.\n", key.c_str());
        success = false;
        err_msg = "Unsupported key " + key + ".";
      }
      else
      {
        LogE(kClassName, __func__, "Non-string key is not supported.\n");
        success = false;
        err_msg = "Non-string key.";
      }
    }

    if (success)
    {
      // If currently pushing to a client, then return an error.
      if (tcp_stats_push_.is_active)
      {
        remote_control_.SendPushErrorMessage(client_id, msg_id,
                                             "Already pushing to a client.");
        return;
      }

      // Set up pushing statistics to the client.
      Time                     duration(interval);
      CallbackNoArg<TcpProxy>  callback(this, &TcpProxy::PushStats);

      // Cancel any existing stats timer.
      if (timer_.IsTimerSet(tcp_stats_push_.timer_handle))
      {
        LogD(kClassName, __func__, "Canceling timer %" PRIu64 ".\n",
             tcp_stats_push_.timer_handle.id());
        timer_.CancelTimer(tcp_stats_push_.timer_handle);
      }

      if (!timer_.StartTimer(duration, &callback,
                             tcp_stats_push_.timer_handle))
      {
        remote_control_.SendPushErrorMessage(client_id, msg_id, "Startup error.");
        return;
      }
      LogD(kClassName, __func__, "Started push stats timer: handle is %"
           PRIu64 ", duration is %s\n", tcp_stats_push_.timer_handle.id(),
           duration.ToString().c_str());

      // Record the necessary information for reporting TCP Proxy statistics.
      tcp_stats_push_.is_active    = true;
      tcp_stats_push_.client_id    = client_id;
      tcp_stats_push_.msg_id       = msg_id;
      tcp_stats_push_.interval_sec = interval;

      return;
    }

    remote_control_.SendPushErrorMessage(client_id, msg_id, err_msg);
    return;
  }

  LogE(kClassName, __func__, "Unknown remote control get message target: "
       "%s\n", target.c_str());
  err_msg = "Unknown target: " + target;
  remote_control_.SendPushErrorMessage(client_id, msg_id, err_msg);
}

//============================================================================
void TcpProxy::ProcessPushStopMessage()
{
  uint32_t client_id = 0;
  uint32_t msg_id = 0;
  string   target;
  uint32_t to_stop_count = 0;

  // Get the message.
  if (!remote_control_.GetPushStopMessage(client_id, msg_id, target, to_stop_count))
  {
    LogE(kClassName, __func__, "Error getting remote control push stop "
         "message.\n");
    return;
  }

  if (to_stop_count != 0)
  {
    if (to_stop_count != 1)
    {
      LogE(kClassName, __func__, "More than one stop message id in push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "More than one stop message id");
      return;
    }
    uint32_t to_stop_id = 0;
    if (!remote_control_.GetPushStopToStopId(0, to_stop_id))
    {
      LogE(kClassName, __func__, "Failed to get stop message id from push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "Couldn't access id at index 0");
      return;
    }
    if (tcp_stats_push_.is_active && to_stop_id != tcp_stats_push_.msg_id)
    {
      LogE(kClassName, __func__, "Unexpected stop message id in push stop "
           "message.\n");
      remote_control_.SendPushErrorMessage(client_id, msg_id,
                                           "Unexpexted stop message id.");
      return;
    }
  }

  LogD(kClassName, __func__, "Stopping statistics pushing upon request.\n");

  // Stop the pushes.
  tcp_stats_push_.is_active    = false;
  tcp_stats_push_.client_id    = 0;
  tcp_stats_push_.msg_id       = 0;
  tcp_stats_push_.interval_sec = 0.0;
}

//============================================================================
bool TcpProxy::ProcessSvcDefUpdateMsg(const string& key, const Value& val_obj,
                                      string& err_msg)
{
  LogW(kClassName, __func__, "Processing Service definition update "
       "message...\n");

  if (!(val_obj.IsString()))
  {
    err_msg = "Service update must contain exactly 1 value string.";
    return false;
  }

  // update the context cache for encoded states to be created in the future
  string  val = val_obj.GetString();
  if (key != "add_service")
  {
    LogW(kClassName, __func__, "Unsupported operation for Service.\n");
    err_msg = "Unsupported service operation.";
    return false;
  }

  char  svc_str[300];
  strncpy(&svc_str[0], val.c_str(), sizeof(svc_str) - 1);
  svc_str[sizeof(svc_str) - 1] = '\0';

  // Update the TCP Context from the received Service definition update
  // message.
  TcpContext*  context = NULL;
  if ((context = ParseService(&svc_str[0], TcpModAction)) != NULL)
  {
    // Check if it is a default utility definition.
    if (context->lo_port() == 0)
    {
      default_utility_def_ = context->util_fn_defn();
      LogD(kClassName, __func__, "Default utility function updated: %s\n",
                                  context->util_fn_defn().c_str());
      delete context;
      return true;
    }
    // Enable this service.
    if (ModService(context) == false)
    {
      LogW(kClassName, __func__, "Addition of service %s failed\n",
           val.c_str());
      err_msg = "Service definition update failed.";

      delete context;
      return false;
    }

    LogW(kClassName, __func__, "Service definition update applied: %s\n",
         val.c_str());

    // Update the Utility function definition in all existing TpSockets.
    socket_mgr_.ProcessSvcDefUpdate(context);

    delete context;
  }
  else
  {
    LogE(kClassName, __func__, "Failed to create context from remote control "
         "Service definition update message: %s\n", val.c_str());
    err_msg = "Unable to parse service update.";

    return false;
  }

  // Update the admission timers as the newly received Service definition may
  // have affected some of the admission timers.
  socket_mgr_.UpdateScheduledAdmissionEvents();

  return true;
}

//============================================================================
bool TcpProxy::ProcessFlowDefUpdateMsg(const string& key, const Value& val_obj,
                                       string& err_msg)
{
  LogW(kClassName, __func__, "Processing Flow definition update "
       "message...\n");

  if (!(val_obj.IsString()))
  {
    err_msg = "Flow update must contain exactly 1 value string.";

    return false;
  }

  // update the flow defn cache for encoded states to be created in the future
  if ((key != "add_flow") && (key != "del_flow") && (key != "off_flow") &&
      (key != "update_util"))
  {
    LogE(kClassName, __func__, "Unsupported operation for Flow defn:%s.\n",
            key.c_str());
    err_msg = "Unsupported flow operation.";

    return false;
  }
  string        val    = val_obj.GetString();
  List<string>  tokens;
  StringUtils::Tokenize(val, ";", tokens);

  // Perform additional message content validation to ensure that the correct
  // number of message parameters have been provided.
  if ((key == "add_flow") && ((tokens.size() != 5) && (tokens.size() != 6)))
  {
    LogW(kClassName, __func__, "Flow add command requires exactly 5 or 6 "
         "parameters. %zd parameters were received.\n", tokens.size());
    err_msg = "Flow add command requires exactly 5 or 6 parameters.";

    return false;
  }
  else if ((key == "update_util") && ((tokens.size() != 5)))
  {
    LogW(kClassName, __func__, "Update util command requires exactly 5"
         "parameters. %zd parameters were received.\n", tokens.size());
    err_msg = "Update util command requires exactly 5 parameters.";

    return false;
  }
  else if ((key == "del_flow") && (tokens.size() != 4))
  {
    LogW(kClassName, __func__, "Flow del command requires exactly 4 "
         "parameters. %zd parameters were received.\n", tokens.size());
    err_msg = "Flow del command requires exactly 4 parameters.\n";

    return false;
  }
  else if ((key == "off_flow") && (tokens.size() != 4))
  {
     LogW(kClassName, __func__, "off_flow command requires exactly 4 "
         "parameters. %zd parameters were received.\n", tokens.size());
    err_msg = "off_flow command requires exactly 4 parameters.\n";

    return false;
  }
  int8_t  num_tokens  = tokens.size();

  // Extract the values of the message tokens.
  string  token;
  tokens.Pop(token);
  uint16_t  src_port_nbo =
    static_cast<uint16_t>(htons(StringUtils::GetUint(token)));

  tokens.Pop(token);
  uint16_t  dst_port_nbo =
    static_cast<uint16_t>(htons(StringUtils::GetUint(token)));

  tokens.Pop(token);
  uint32_t  src_addr_nbo =
    static_cast<uint32_t>(StringUtils::GetIpAddr(token).address());

  tokens.Pop(token);
  uint32_t  dst_addr_nbo =
    static_cast<uint32_t>(StringUtils::GetIpAddr(token).address());

  // Always update the Flow definition cache in accordance with the message
  // operation. Also, update the matching flow if presently active.
  //
  // A single TCP Proxy flow is implemented as a pair of sockets in the TCP
  // Proxy, a LAN facing socket and a WAN facing socket. The match for a
  // received Flow definition should always find the LAN facing
  // socket. However, the utility function definition for the flow is stored
  // in the WAN facing socket (the IRON facing socket in this case). So, we
  // must modifiy the peer of the found socket.
  FourTuple  four_tuple(src_addr_nbo, src_port_nbo, dst_addr_nbo,
                        dst_port_nbo);
  Socket*  sock = socket_mgr_.GetSocket(four_tuple);

  if ((sock != NULL) && (sock->cfg_if_id() == LAN))
  {
    sock = sock->peer();
  }

  if (key == "add_flow")
  {
    string  utility_func_def  = "";
    if (num_tokens == 5)
    {
      // Save the provided utility function definition in the flow cache for
      // later use.
      tokens.PeekBack(utility_func_def);

      if (!flow_utility_def_cache_.Insert(four_tuple, utility_func_def))
      {
        LogE(kClassName, __func__, "Unable to add flow utility definition "
             "%s for four-tuple %s.\n", utility_func_def.c_str(),
             four_tuple.ToString().c_str());
      }
    }
    else
    {
      // Save the provided utility function definition in the flow cache for
      // later use.
      tokens.Peek(utility_func_def);


      if (!flow_utility_def_cache_.Insert(four_tuple, utility_func_def))
      {
        LogE(kClassName, __func__, "Unable to add flow utility definition "
             "%s for four-tuple %s.\n", utility_func_def.c_str(),
             four_tuple.ToString().c_str());
      }

      tokens.PeekBack(token);
      int8_t  dscp_value = StringUtils::GetInt(token);

      if (!context_dscp_cache_.Insert(four_tuple, dscp_value))
      {
        LogE(kClassName, __func__, "Unable to add DSCP value %d for "
             "four-tuple %s.\n", static_cast<int>(dscp_value),
             four_tuple.ToString().c_str());
      }
    }

    // Update the matching flow, if presently active. We will use the utility
    // function definition that was just received to do this.
    if (sock != NULL)
    {
      sock->ResetUtilityFn(utility_func_def, GetQueueDepths());
      Time  now = Time::Now();
      sock->UpdateScheduledAdmissionEvent(now);
    }
  }
  else if (key == "del_flow")
  {
    // Remove the flow from the flow cache.
    flow_utility_def_cache_.Erase(four_tuple);

    // Update the matching flow, if presently active. Since the Flow
    // definition has been deleted, we will set the utility definition for the
    // flow to the utility function defined for the matching Service
    // definition.
    if (sock != NULL)
    {
      sock->ResetUtilityFn(GetUtilityFnDef(ntohs(dst_port_nbo)),
                           GetQueueDepths());
      Time  now = Time::Now();
      sock->UpdateScheduledAdmissionEvent(now);
    }
  }
  else if ((key == "off_flow") && (sock != NULL))
  {
    sock->TurnFlowOff();
  }
  else if (key == "update_util")
  {
    string  key_val;
    tokens.PeekBack(key_val);
    List<string> update_tokens;
    StringUtils::Tokenize(key_val, ":", update_tokens);
    if (update_tokens.size() != 2)
    {
      LogE(kClassName, __func__, "Parameter %s must be of the form key:value.\n",
                                  key_val.c_str());
      return false;
    }

    if (update_tokens.Peek(token) && (token != "p"))
    {
      LogE(kClassName, __func__, "Unsupported parameter for update: %s.\n", token.c_str());
    }

    // Update the flow cache.
    string priority = "0";
    update_tokens.PeekBack(priority);
    string  utility_func_def  = "";
    if (!flow_utility_def_cache_.FindAndRemove(four_tuple, utility_func_def))
    {
      utility_func_def  = GetUtilityFnDef(ntohs(four_tuple.dst_port_nbo()));
    }

    string start_delim("p=");
    string end_delim(":");
    if (!StringUtils::Substitute(utility_func_def, start_delim, end_delim, priority))
    {
      LogE(kClassName, __func__, "Failed to substitute new priority value.\n");
      return false;
    }
    flow_utility_def_cache_.Insert(four_tuple, utility_func_def);

    // Update affected socket.
    if (sock != NULL)
    {
      sock->UpdatePriority(StringUtils::GetDouble(priority));
    }
  }
  return true;
}

//============================================================================
TcpContext* TcpProxy::ParseService(char* command, TcpActionType action)
{
  char*        p;
  string       util_fn = "";
  TcpContext*  context;

  LogD(kClassName, __func__, "Got command: %s\n", command);

  // Parse the port range settings

  if ((p = strtok(command, "-")) == NULL)
  {
    LogW(kClassName, __func__, "'-' separator missing from port range "
         "specification.\n");
    return (TcpContext*)NULL;
  }

  int lo_port = atoi(p);

  // Get the next token
  int8_t  dscp  = -1;

  if (action == TcpModAction)
  {
    if ((p = strtok(NULL,";")) == NULL)
    {
      LogW(kClassName, __func__, "Second parameter missing from port range "
           "specification.\n");
      return (TcpContext*)NULL;
    }
  }
  else // if (action == FECDelAction)
  {
    if ((p = strtok(NULL,";\n\t ")) == NULL)
    {
      LogW(kClassName, __func__, "Second parameter missing from port range "
           "specification.\n");
      return (TcpContext*)NULL;
    }
  }

  int hi_port = atoi(p);

  if ((lo_port <     0) ||
      (lo_port > 65535) ||
      (hi_port <     1) ||
      (hi_port > 65535) ||
      (lo_port > hi_port))
  {
    // Error out. Port settings are screwy
    LogW(kClassName, __func__, "Improper port range setting.\n");
    return (TcpContext*)NULL;
  }

  // If action is "mod", need remaining info

  if (action == TcpModAction)
  {
    // Get next token -- utility function string
    if ((p = strtok(NULL, ";")) == NULL)
    {
      LogW(kClassName, __func__, "Service definition does not contain "
           "utility function definition, using default.\n");
      if (default_utility_def_.length() !=0)
      {
        util_fn = default_utility_def_;
      }
      else
      {
        LogF(kClassName, __func__, "Default utility not specified.\n");
      }
    }
    else
    {
      util_fn = string(p);
    }

    // Get next token (if available) -- dscp value
    if ((p = strtok(NULL, ";")) != NULL)
    {
      // There is a string, look at it.
      string opt_tok = string(p);

      if (opt_tok.compare(0, 5, "dscp=") == 0)
      {
        // The string starts with dscp=.  Means specifying DSCP val.
        string dscp_str = opt_tok.substr(5, string::npos);

        if (dscp_str.empty())
        {
          // The value of DSCP is missing.
          LogF(kClassName, __func__,
               "DSCP token detected but no value specified in %s.\n",
               opt_tok.c_str());
          return NULL;
        }
        else
        {
          // There is a value for the DSCP.
          uint64_t dscp_val = StringUtils::GetUint64(string(dscp_str));

          // DSCP value cannot exceed 111 111 - 63)
          if ((dscp_val == INT_MAX) || (dscp_val >= (1 << 6)))
          {
            // The DSCP value is invalid.
            LogF(kClassName, __func__,
                 "DSCP value %s is invalid or exceeds 63.\n",
                 string(p).c_str());
            return NULL;
          }
          else
          {
            // The DSCP value is valid and does not exceed 63.  Use it.
            dscp = static_cast<int8_t>(dscp_val);
            LogD(kClassName, __func__,
                 "DSCP value set to %d.\n", dscp);
          }
        }
      }
      else
      {
        // The string starts with something unsupported.  Drop it.
        LogW(kClassName, __func__,
             "Unrecognized token %s.\n", opt_tok.c_str());
      }
    }
  }

  // If we are here, we successfully found all info needed for a context
  context = new TcpContext(lo_port, hi_port, util_fn, dscp);

  return context;
}

//============================================================================
bool TcpProxy::ModService(TcpContext* ref_context)
{
  // Insert into the collection of Service context information. See if we
  // already have this entry, in which case its a "mod" operation
  map<int, TcpContext*>::iterator  iter;
  if ((iter = svc_configs_.find(ref_context->lo_port())) !=
      svc_configs_.end())
  {
    TcpContext* cur_context = iter->second;

    // Make sure we have a match.
    if (cur_context->hi_port() == ref_context->hi_port())
    {
      // We have a match. Just overwrite the values.
      *cur_context = *ref_context;

      return true;
    }
    else
    {
      LogW(kClassName, __func__, "Inconsistent ports: existing port range "
           "(%u:%u) mismatch with requested port range (%u:%u).\n",
           cur_context->lo_port(), cur_context->hi_port(),
           ref_context->lo_port(), ref_context->hi_port());
      return false;
    }
  }
  else
  {
    // Looks like we don't already have this entry, in which case its an "add"
    // operation. First we copy the context and insert the copy for
    // consistent behavior.
    TcpContext* context = new (std::nothrow) TcpContext(
      ref_context->lo_port(), ref_context->hi_port(),
      ref_context->util_fn_defn(), ref_context->dscp());

    if (context == NULL)
    {
      LogF(kClassName, __func__, "Error allocating new TcpContext.\n");
      return false;
    }

    svc_configs_[context->lo_port()] = context;
    return true;
  }

  return true;
}

//============================================================================
bool TcpProxy::DelService(TcpContext* ref_context)
{
  // Retrieve from the collection of Service context information.
  map<int, TcpContext*>::iterator  iter;
  if ((iter = svc_configs_.find(ref_context->lo_port())) !=
      svc_configs_.end())
  {
    TcpContext* cur_context = iter->second;

    // Make sure we have a match.
    if (cur_context->hi_port() == ref_context->hi_port())
    {
      // We have a match. Delete the context that was saved and remove from
      // the entry from the map.
      delete cur_context;
      svc_configs_.erase(iter);

      return true;
    }
    else
    {
      LogW(kClassName, __func__, "Inconsistent ports: existing port range "
           "(%u:%u) mismatch with requested port range (%u:%u).\n",
           cur_context->lo_port(), cur_context->hi_port(),
           ref_context->lo_port(), ref_context->hi_port());
      return false;
    }
  }

  return true;
}
