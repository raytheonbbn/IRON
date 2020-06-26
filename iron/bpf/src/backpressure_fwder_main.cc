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

#include "backpressure_fwder.h"
#include "bin_map.h"
#include "fifo.h"
#include "fifo_if.h"
#include "iron_constants.h"
#include "list.h"
#include "log.h"
#include "packet_pool_shm.h"
#include "shared_memory.h"
#include "string_utils.h"
#include "timer.h"
#include "unused.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>  // #include <cunistd> did not work


using ::iron::BinMap;
using ::iron::BPFwder;
using ::iron::ConfigInfo;
using ::iron::Fifo;
using ::iron::FifoIF;
using ::iron::List;
using ::iron::Log;
using ::iron::PACKET_OWNER_BPF;
using ::iron::PacketPoolShm;
using ::iron::SharedMemory;
using ::iron::StringUtils;
using ::iron::Timer;
using ::std::string;

namespace
{
  const  char*    UNUSED(cn)  = "backpressure_fwder_main";
  BPFwder*        bp_fwder    = NULL;
  Timer*          timer       = NULL;
  BinMap*         bin_map     = NULL;
  PacketPoolShm*  packet_pool = NULL;
  SharedMemory*   weight_qd_shared_memory = NULL;
  SharedMemory*   bin_map_shared_memory = NULL;
  FifoIF*         bpf_to_udp_pkt_fifo = NULL;
  FifoIF*         bpf_to_tcp_pkt_fifo = NULL;
  FifoIF*         udp_to_bpf_pkt_fifo = NULL;
  FifoIF*         tcp_to_bpf_pkt_fifo = NULL;
}

//============================================================================
/// \brief Clean up everything.
void CleanUp()
{
  LogI(cn, __func__, "Cleaning up for shutdown...\n");

  if (bp_fwder != NULL)
  {
    delete bp_fwder;
    bp_fwder = NULL;
  }

  if (timer != NULL)
  {
    delete timer;
    timer = NULL;
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
    bin_map_shared_memory->Destroy();
    delete bin_map_shared_memory;
    bin_map_shared_memory = NULL;
  }

  if (bpf_to_udp_pkt_fifo != NULL)
  {
    delete bpf_to_udp_pkt_fifo;
    bpf_to_udp_pkt_fifo = NULL;
  }

  if (bpf_to_tcp_pkt_fifo != NULL)
  {
    delete bpf_to_tcp_pkt_fifo;
    bpf_to_tcp_pkt_fifo = NULL;
  }

  if (udp_to_bpf_pkt_fifo != NULL)
  {
    delete udp_to_bpf_pkt_fifo;
    udp_to_bpf_pkt_fifo = NULL;
  }

  if (tcp_to_bpf_pkt_fifo != NULL)
  {
    delete tcp_to_bpf_pkt_fifo;
    tcp_to_bpf_pkt_fifo = NULL;
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

  LogI(cn, __func__, "Terminating Backpressure Forwarder\n");

  if (bp_fwder != NULL)
  {
    bp_fwder->Stop();
  }

  CleanUp();

  exit(0);
}

//============================================================================
/// \brief Set up handlers for the various signals that this process will
//         catch and handle.
void SetSignalHandler()
{
  LogI(cn, __func__, "Initializing signal handler...\n");

  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    LogE(cn, __func__, "Problem setting signal handler for SIGINT.\n");
  }

  if (signal(SIGQUIT, Finalize) == SIG_ERR)
  {
    LogE(cn, __func__, "Problem setting signal handler for SIGQUIT.\n");
  }

  if (signal(SIGTERM, Finalize) == SIG_ERR)
  {
    LogE(cn, __func__, "Problem setting signal handler for SIGTERM.\n");
  }
}

//============================================================================
/// \brief Print out the usage syntax.
///
/// \param  prog_name  The name of the program.
void Usage(const std::string& prog_name)
{
  fprintf(stderr,"\n");
  fprintf(stderr,"Usage:\n");
  fprintf(stderr,"  %s [options]\n", prog_name.c_str());
  fprintf(stderr,"\n");
  fprintf(stderr,"Options:\n");
  fprintf(stderr," -c <name>  The fully qualified name of the Backpressure\n");
  fprintf(stderr,"             Forwarder's configuration file.\n");
  fprintf(stderr," -l <name>  The fully qualified name of the Backpressure\n");
  fprintf(stderr,"            Forwarder's log file. Default behavior sends\n");
  fprintf(stderr,"             log statements to stdout.\n");
  fprintf(stderr," -d         Turn on debug logging.\n");
  fprintf(stderr," -h         Print out usage information.\n");
  fprintf(stderr,"\n");

  exit(2);
}

//============================================================================
/// \brief The main function that starts the Backpressure Forwarder.
///
/// \param  argc  The number of command line arguments.
/// \param  argv  The command line arguments.
///
/// \return 0 on success, 1 if a failure occurs.
int main(int argc, char** argv)
{
  extern int    optind;
  extern char*  optarg;
  int           c;
  bool          debug = false;
  ConfigInfo config_info;

  while ((c = getopt(argc, argv, "c:l:dh")) != -1)
  {
    switch (c)
    {
      case 'c':
        if (!config_info.LoadFromFile(optarg))
        {
          LogE(cn, __func__, "Error loading configuration file %s.\n",
               optarg);
          Usage(argv[0]);
          exit(1);
        }
        break;

      case 'l':
        Log::SetOutputFile(optarg, false);
        break;

      case 'd':
        debug = true;
        break;

      case 'h':
      default:
        Usage(argv[0]);
    }
  }

  // Set logging options based on properties.
  if(debug)
  {
    Log::SetDefaultLevel("FEWIAD");
  }
  else
  {
    Log::SetDefaultLevel(config_info.Get("Log.DefaultLevel", "All", false));
  }

  // Set class level logging.
  std::string class_levels = config_info.Get("Log.ClassLevels", "", false);
  List<string>  tokens;
  StringUtils::Tokenize(class_levels, ";", tokens);
  List<string>::WalkState token_ws;
  token_ws.PrepareForWalk();

  string  token;
  while (tokens.GetNextItem(token_ws, token))
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

    LogI(cn, __func__,
         "Setting class %s logging to %s.\n",
         token_name.c_str(), token_value.c_str());
    Log::SetClassLevel(token_name, token_value);
  }

  // Check for command line arguments. Currently we don't expect any.
  if (optind < argc)
  {
    Usage(argv[0]);
  }

  LogI(cn, __func__, "Starting Backpressure Forwarder.\n");

  // Set the signal handlers for this process right from the beginning.
  SetSignalHandler();

  // Create the packet pool,
  packet_pool = new PacketPoolShm(PACKET_OWNER_BPF);
  if (!packet_pool->Create(iron::kPacketPoolSemKey, kPacketPoolShmName))
  {
    LogF(cn, __func__, "Error initializing Packet Pool . Aborting...\n");
    exit(1);
  }

  // Create the manager of timers,
  timer = new Timer();

  // Create shared memory,
  weight_qd_shared_memory = new SharedMemory();
  bin_map_shared_memory   = new SharedMemory();

  // Set up the bin map in shared memory.
  key_t  sem_key  = config_info.GetUint("Bpf.BinMap.SemKey",
                                       iron:: kDefaultBinMapSemKey);
  string    name  = config_info.Get("Bpf.BinMap.ShmName",
                                    kDefaultBinMapShmName);

  if (!bin_map_shared_memory->Create(sem_key, name.c_str(), sizeof(BinMap)))
  {
    LogF(cn, __func__,
         "Failed to create the shared memory segment for weights.\n");
    return false;
  }

  LogD(cn, __func__, "Creating Shm segment of size %zu for bin map.\n",
                             sizeof(BinMap));

  bin_map = reinterpret_cast<BinMap*>(bin_map_shared_memory->GetShmPtr());

  memset(bin_map_shared_memory->GetShmPtr(), 0, sizeof(BinMap));

  // Initialize the BinMap.
  bin_map->Initialize(config_info);

  // Create FIFOs,
  bpf_to_udp_pkt_fifo = new Fifo(kDefaultBpfToUdpPktFifoPath);
  bpf_to_tcp_pkt_fifo = new Fifo(kDefaultBpfToTcpPktFifoPath);
  udp_to_bpf_pkt_fifo = new Fifo(kDefaultUdpToBpfPktFifoPath);
  tcp_to_bpf_pkt_fifo = new Fifo(kDefaultTcpToBpfPktFifoPath);

  // Create the Backpressure Forwarder,
  bp_fwder = new BPFwder(*packet_pool, *timer, *bin_map,
                         *weight_qd_shared_memory,
                         bpf_to_udp_pkt_fifo,
                         bpf_to_tcp_pkt_fifo,
                         udp_to_bpf_pkt_fifo,
                         tcp_to_bpf_pkt_fifo,
                         config_info);

  // initialize it, and
  if (!bp_fwder->Initialize())
  {
    LogF(cn, __func__, "Error initializing Backpressure "
         "Forwarder. Aborting...\n");
    exit(1);
  }

  // start it.
  bp_fwder->Start();

  CleanUp();

  exit(0);
}
