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

#include "fifo.h"
#include "iron_constants.h"
#include "list.h"
#include "packet_pool_shm.h"
#include "edge_if.h"
#include "string_utils.h"
#include "shared_memory.h"
#include "shared_memory_if.h"
#include "tcp_proxy.h"
#include "tcp_proxy_opts.h"
#include "tcp_edge_if_config.h"
#include "unused.h"
#include "virtual_edge_if.h"

#include <string>

#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

using ::iron::BinMap;
using ::iron::Fifo;
using ::iron::List;
using ::iron::Log;
using ::iron::PacketPoolShm;
using ::iron::PACKET_OWNER_TCP_PROXY;
using ::iron::EdgeIf;
using ::iron::RemoteControlServer;
using ::iron::StringUtils;
using ::iron::SharedMemory;
using ::iron::SharedMemoryIF;
using ::iron::VirtualEdgeIf;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*           UNUSED(kClassName) = "tcp_proxy_main";

  /// The TCP Proxy.
  TcpProxy*             tcp_proxy = NULL;

  /// The edge interface.
  VirtualEdgeIf*        edge_if = NULL;

  /// Configuration for the edge interface.
  TcpEdgeIfConfig*      edge_if_config = NULL;

  /// The bin map.
  BinMap*               bin_map = NULL;

  /// TCP Proxy configuration information.
  TcpProxyConfig*       proxy_config = NULL;

  /// TCP Proxy packet pool.
  PacketPoolShm*        packet_pool = NULL;

  /// TCP Proxy weighted queue depths.
  SharedMemory*         weight_qd_shared_memory = NULL;

  /// Shared memory for the bin map.
  SharedMemory*         bin_map_shared_memory   = NULL;

  /// FIFOs between proxy and bpf.
  Fifo*                 bpf_to_tcp_pkt_fifo = NULL;
  Fifo*                 tcp_to_bpf_pkt_fifo = NULL;

  /// The remote control server.
  RemoteControlServer*  remote_control_server_ = NULL;
}


//============================================================================
void CleanUp()
{
  LogI(kClassName, __func__, "Cleaning up for shutdown...\n");

  if (tcp_proxy != NULL)
  {
    delete tcp_proxy;
    tcp_proxy = NULL;
  }

  if (edge_if != NULL)
  {
    delete edge_if;
    edge_if = NULL;
  }

  if (edge_if_config != NULL)
  {
    delete edge_if_config;
    edge_if_config = NULL;
  }

  if (proxy_config != NULL)
  {
    delete proxy_config;
    proxy_config = NULL;
  }

  if (packet_pool != NULL)
  {
    delete packet_pool;
    packet_pool = NULL;
  }

  if (weight_qd_shared_memory != NULL)
  {
    delete weight_qd_shared_memory;
    weight_qd_shared_memory = NULL;
  }

  if (bin_map_shared_memory != NULL)
  {
    bin_map_shared_memory->Detach();
    delete bin_map_shared_memory;
    bin_map_shared_memory = NULL;
  }

  if (bpf_to_tcp_pkt_fifo != NULL)
  {
    delete bpf_to_tcp_pkt_fifo;
    bpf_to_tcp_pkt_fifo = NULL;
  }

  if (tcp_to_bpf_pkt_fifo != NULL)
  {
    delete tcp_to_bpf_pkt_fifo;
    tcp_to_bpf_pkt_fifo = NULL;
  }

  if (remote_control_server_ != NULL)
  {
    delete remote_control_server_;
    remote_control_server_ = NULL;
  }

  LogI(kClassName, __func__, "Cleanup complete.\n");

  Log::Flush();
  Log::Destroy();
}

//============================================================================
void Finalize(int junk)
{
  Log::OnSignal();

  LogI(kClassName, __func__, "Terminating TCP Proxy\n");

  CleanUp();

  exit(0);
}

//============================================================================
void SetSigHandler()
{
  LogI(kClassName, __func__, "Initializing signal handler...\n");

  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    LogW(kClassName, __func__, "Problem setting signal handler for "
         "SIGINT.\n");
  }

  if (signal(SIGQUIT, Finalize) == SIG_ERR)
  {
    LogW(kClassName, __func__, "Problem setting signal handler for "
         "SIGQUIT.\n");
  }

  if (signal(SIGTERM, Finalize) == SIG_ERR)
  {
    LogW(kClassName, __func__, "Problem setting signal handler for "
         "SIGTERM.\n");
  }
}

//============================================================================
int
main(int argc, char** argv)
{
  TcpProxyOpts tcp_proxy_opts;
  tcp_proxy_opts.ParseArgs(argc, argv);

  LogI(kClassName, __func__, "Starting TCP Proxy.\n");

  // Set the default logging level.
  Log::SetDefaultLevel(tcp_proxy_opts.config_info().Get("Log.DefaultLevel",
                                                        "All", false));

  // Set the class level logging. The format for this configurable item is as
  // follows:
  //
  //  ClassName1=LogLevel1;ClassName2=LogLevel2;...;ClassNameN=LogLevelN
  string  class_levels = tcp_proxy_opts.config_info().Get("Log.ClassLevels",
                                                          "", false);

  List<string>  tokens;
  StringUtils::Tokenize(class_levels, ";", tokens);

  List<string>::WalkState tokens_ws;
  tokens_ws.PrepareForWalk();

  string  token;
  while (tokens.GetNextItem(tokens_ws, token))
  {
    if (token.find("=") == string::npos)
    {
      // This entry is syntactically incorrect, so move on to the next entry.
      LogW(kClassName, __func__, "Syntactically incorrect class log level: "
           "%s\n", token.c_str());

      continue;
    }

    List<string>  token_values;
    StringUtils::Tokenize(token, "=", token_values);

    string  token_name;
    string  token_value;

    token_values.Pop(token_name);
    token_values.Peek(token_value);

    LogI(kClassName, __func__, "Setting class %s logging level to %s.\n",
         token_name.c_str(), token_value.c_str());

    Log::SetClassLevel(token_name, token_value);
  }

  // Set the signal handlers for this process.
  SetSigHandler();

  proxy_config = new TcpProxyConfig();

  // Load the gateway configuration information.
  proxy_config->Initialize(tcp_proxy_opts.config_info());

  edge_if_config = new (std::nothrow) TcpEdgeIfConfig();
  if (!edge_if_config)
  {
    LogF(kClassName, __func__, "Error creating new TcpEdgeIfConfig.\n");
    return -1;
  }

  if (!edge_if_config->Initialize(tcp_proxy_opts.config_info()))
  {
    LogE(kClassName, __func__, "Edge interface initialization failed. "
         "Shutting down.\n");
    CleanUp();
    return -1;
  }

  edge_if = new (std::nothrow) EdgeIf(*edge_if_config);
  if (!edge_if)
  {
    LogF(kClassName, __func__, "Error creating new EdgeIf.\n");
    return -1;
  }

  packet_pool = new PacketPoolShm(PACKET_OWNER_TCP_PROXY);
  if (!packet_pool->Attach(iron::kPacketPoolSemKey,
                          kPacketPoolShmName))
  {
    LogE(kClassName, __func__, "Cannot continue: error attaching to "
         "shared memory for packet pool.\n");
    CleanUp();
    return -1;
  }
  LogI(kClassName, __func__, "Connected to shared memory for packet pool.\n");

  weight_qd_shared_memory = new SharedMemory();
  if (weight_qd_shared_memory == NULL)
  {
    LogF(kClassName, __func__, "Error allocating new SharedMemory.\n");
    CleanUp();
    return -1;
  }

  bin_map_shared_memory = new (std::nothrow) SharedMemory();
  if (bin_map_shared_memory == NULL)
  {
    LogF(kClassName, __func__, "Error allocating new SharedMemory.\n");
    CleanUp();
    return -1;
  }

  key_t w_key   = tcp_proxy_opts.config_info().GetUint("Tcp.BinMap.SemKey",
                               iron::kDefaultBinMapSemKey);
  string w_name  = tcp_proxy_opts.config_info().Get("Tcp.BinMap.ShmName",
                               kDefaultBinMapShmName);

  LogI(kClassName, __func__, "Attaching bin map shared memory...\n");

  uint32_t wait_count  = 0;

  while (true)
  {
    if (bin_map_shared_memory->Attach(w_key, w_name.c_str(), sizeof(BinMap)))
    {
      break;
    }

    sleep(1);

    ++wait_count;
    if (wait_count % 120 == 0)
    {
      LogW(kClassName, __func__, "... Waiting to attach to bin map shared "
           "memory.\n");
    }
    else
    {
      LogD(kClassName, __func__, "... Waiting to attach.\n");
    }
  }

  bin_map = reinterpret_cast<BinMap*>(bin_map_shared_memory->GetShmPtr());

  bpf_to_tcp_pkt_fifo    = new Fifo(kDefaultBpfToTcpPktFifoPath);
  tcp_to_bpf_pkt_fifo    = new Fifo(kDefaultTcpToBpfPktFifoPath);

  remote_control_server_ = new RemoteControlServer();

  // Start the TCP Proxy.
  tcp_proxy = new TcpProxy(*proxy_config, *packet_pool, *edge_if,
                           *bin_map,
                           *weight_qd_shared_memory,
                           bpf_to_tcp_pkt_fifo,
                           tcp_to_bpf_pkt_fifo,
                           *remote_control_server_);

  tcp_proxy->Initialize(tcp_proxy_opts.config_info());
  tcp_proxy->Start();

  CleanUp();
}
