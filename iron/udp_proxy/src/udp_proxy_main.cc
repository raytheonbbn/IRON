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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "bin_map.h"
#include "log.h"
#include "packet_pool_shm.h"
#include "edge_if.h"
#include "shared_memory.h"
#include "shared_memory_if.h"
#include "string_utils.h"
#include "timer.h"
#include "udp_edge_if_config.h"
#include "udp_proxy.h"
#include "udp_proxy_opts.h"
#include "unused.h"
#include "virtual_edge_if.h"

using ::iron::BinMap;
using ::iron::List;
using ::iron::Log;
using ::iron::Fifo;
using ::iron::PACKET_OWNER_UDP_PROXY;
using ::iron::PacketPoolShm;
using ::iron::EdgeIf;
using ::iron::SharedMemory;
using ::iron::SharedMemoryIF;
using ::iron::StringUtils;
using ::iron::Timer;
using ::iron::VirtualEdgeIf;
using ::std::string;

static const char cn[] = "udp_proxy_main";

static UdpProxyOpts options;

namespace
{
  UdpProxy*            udp_proxy               = NULL;
  FecStatePool*        fecstate_pool           = NULL;
  Timer*               timer                   = NULL;
  BinMap*              bin_map                 = NULL;
  VirtualEdgeIf*       edge_if                 = NULL;
  UdpEdgeIfConfig*     edge_if_config          = NULL;
  SharedMemory*        weight_qd_shared_memory = NULL;
  SharedMemory*        bin_map_shared_memory   = NULL;
  Fifo*                bpf_to_udp_pkt_fifo     = NULL;
  Fifo*                udp_to_bpf_pkt_fifo     = NULL;
  PacketPoolShm*       packet_pool             = NULL;
}

//============================================================================
/// \brief Clean up everything.
void CleanUp()
{
  LogI(cn, __func__, "Cleaning up for shutdown...\n");

  if (udp_proxy != NULL)
  {
    delete udp_proxy;
    udp_proxy = NULL;
  }

  if (fecstate_pool != NULL)
  {
    delete fecstate_pool;
    fecstate_pool = NULL;
  }

  if (timer != NULL)
  {
    delete timer;
    timer = NULL;
  }

  // TODO SD: detach shm and destroy in BPF.

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

  if (bpf_to_udp_pkt_fifo != NULL)
  {
    delete bpf_to_udp_pkt_fifo;
    bpf_to_udp_pkt_fifo = NULL;
  }

  if (udp_to_bpf_pkt_fifo != NULL)
  {
    delete udp_to_bpf_pkt_fifo;
    udp_to_bpf_pkt_fifo = NULL;
  }

  if (packet_pool != NULL)
  {
    delete packet_pool;
    packet_pool = NULL;
  }

  LogI(cn, __func__, "Cleanup complete.\n");

  Log::Flush();
  Log::Destroy();
}

//============================================================================
/// \brief Cleanly shutdown.
///
/// \param  junk  Ignored.
void Finalize(int junk)
{
  Log::OnSignal();

  LogI(cn, __func__, "Terminating UDP Proxy\n");

  if (udp_proxy != NULL)
  {
    udp_proxy->Stop();
  }

  LogI(cn, __func__, "Cleanup complete.\n");

  CleanUp();

  exit(0);
}

//============================================================================
/// \brief Set up handlers for various signals.
void SetSigHandler()
{
  static const char  UNUSED(mn[]) = "SetSigHandler";
  LogI(cn, mn, "Initializing signal handler...\n");
  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    LogW(cn, mn, "Problem setting signal handler for SIGINT\n");
  }
  if (signal(SIGQUIT, Finalize) == SIG_ERR)
  {
    LogW(cn, mn, "Problem setting signal handler for SIGQUIT\n");
  }
  if (signal(SIGTERM, Finalize) == SIG_ERR)
  {
    LogW(cn, mn, "Problem setting signal handler for SIGTERM\n");
  }
}

//============================================================================
/// \brief UDP Proxy main application.
///
/// \param  argc  The command line argument count, including the program
///               name.
/// \param  argv  An array of character arrays that contain the command line
///               arguments.
///
/// \return Zero on success, or non-zero on failure.
int main(int argc, char** argv)
{
  if (options.ParseArgs(argc,argv))
  {
    return -1;
  }

  Log::SetOutputFile(options.config_info_.Get("Log.File", ""), false);

  // Set logging options based on properties.
  Log::SetDefaultLevel(options.config_info_.Get(
                         "Log.DefaultLevel", "All", false));

  // Set class level logging.
  string class_levels = options.config_info_.Get("Log.ClassLevels", "", false);
  List<string>  tokens;
  StringUtils::Tokenize(class_levels, ";", tokens);

  List<string>::WalkState ws;
  ws.PrepareForWalk();

  string  token;

  while (tokens.GetNextItem(ws, token))
  {
    if (token.find("=") == string::npos)
    {
      continue;
    }

    List<string> token_values;
    StringUtils::Tokenize(token, "=", token_values);

    string  token_name;
    string  token_value;
    token_values.Pop(token_name);
    token_values.Peek(token_value);

    LogI(cn, __func__, "Setting class %s logging to %s\n", token_name.c_str(),
         token_value.c_str());
    Log::SetClassLevel(token_name, token_value);
  }

  // XXX
  // ZLog::Ignore(options.properties.get("zlog.ignore", NULL));
  // ZLog::MaxFileSize(options.properties.getInt("zlog.maxFileSize",0));
  // ZLog::MaxFileNum(options.properties.getInt("zlog.maxFileNum",0));
  // ZLog::LogChangeCommand(options.properties.get("zlog.changeCmd", NULL));

  LogI(cn, __func__, "Starting UDP Proxy.\n");

  // Set the signal handlers for this process right from the begining.
  SetSigHandler();

  packet_pool = new (std::nothrow) PacketPoolShm(PACKET_OWNER_UDP_PROXY);
  if (packet_pool == NULL)
  {
    LogF(cn, __func__, "Error allocating new PacketPoolShm.\n");
    return -1;
  }

  // Attach to shared memory packet pool
  if (!packet_pool->Attach(iron::kPacketPoolSemKey, kPacketPoolShmName))
  {
    LogE(cn, __func__, "Cannot continue: error attaching to shared "
         "memory for packet pool.\n");
    CleanUp();
    return -1;
  }
  LogI(cn, __func__, "Connected to shared memory for packet pool.\n");

  edge_if_config = new (std::nothrow) UdpEdgeIfConfig();
  if (!edge_if_config)
  {
    LogF(cn, __func__, "Error creating new UdpEdgeIfConfig.\n");
    return -1;
  }

  if (!edge_if_config->Initialize(options.config_info_))
  {
    LogE(cn, __func__, "Edge interface initialization failed. Shutting "
         "down.\n");
    CleanUp();
    return -1;
  }

  edge_if = new (std::nothrow) EdgeIf(*edge_if_config);
  if (!edge_if)
  {
    LogF(cn, __func__, "Error creating new EdgeIf.\n");
    return -1;
  }

  weight_qd_shared_memory = new (std::nothrow) SharedMemory();
  if (weight_qd_shared_memory == NULL)
  {
    LogF(cn, __func__, "Error allocating new SharedMemory.\n");
    return -1;
  }

  bin_map_shared_memory = new (std::nothrow) SharedMemory();
  if (bin_map_shared_memory == NULL)
  {
    LogF(cn, __func__, "Error allocating new SharedMemory.\n");
    return -1;
  }

  key_t w_key   = options.config_info_.GetUint("Udp.BinMap.SemKey",
                               iron::kDefaultBinMapSemKey);
  string w_name  = options.config_info_.Get("Udp.BinMap.ShmName", kDefaultBinMapShmName);

  LogI(cn, __func__, "Attaching bin map shared memory...\n");

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
      LogW(cn, __func__, "... Waiting to attach to bin map shared "
           "memory.\n");
    }
    else
    { 
      LogD(cn, __func__, "... Waiting to attach.\n");
    }
  }

  bin_map = reinterpret_cast<BinMap*>(bin_map_shared_memory->GetShmPtr());

  bpf_to_udp_pkt_fifo   = new (std::nothrow)
    Fifo(kDefaultBpfToUdpPktFifoPath);
  if (bpf_to_udp_pkt_fifo == NULL)
  {
    LogF(cn, __func__, "Error allocating new Fifo.\n");
    return -1;
  }

  udp_to_bpf_pkt_fifo   = new (std::nothrow)
    Fifo(kDefaultUdpToBpfPktFifoPath);
  if (udp_to_bpf_pkt_fifo == NULL)
  {
    LogF(cn, __func__, "Error allocating new Fifo.\n");
    return -1;
  }

  timer = new (std::nothrow) Timer();
  if (timer == NULL)
  {
    LogF(cn, __func__, "Error allocating new Fifo.\n");
    return -1;
  }

  fecstate_pool = new (std::nothrow) FecStatePool(*packet_pool);
  if (fecstate_pool == NULL)
  {
    LogF(cn, __func__, "Error allocating new FecStatePool.\n");
    return -1;
  }

  udp_proxy = new (std::nothrow) UdpProxy(*packet_pool, *edge_if,
                                          *bin_map,
                                          *fecstate_pool, *timer,
                                          *weight_qd_shared_memory,
                                          bpf_to_udp_pkt_fifo,
                                          udp_to_bpf_pkt_fifo);
  if (udp_proxy == NULL)
  {
    LogF(cn, __func__, "Error allocating new UdpProxy.\n");
  }

  if (udp_proxy->Configure(options.config_info_, NULL) == false)
  {
    CleanUp();
    return -1;
  }

  if (udp_proxy->InitSockets() == false)
  {
    CleanUp();
    return -1;
  }

  if (udp_proxy->AttachSharedMemory(options.config_info_) == false)
  {
    CleanUp();
    return -1;
  }

  udp_proxy->Start();

  CleanUp();

  exit(0);
}
