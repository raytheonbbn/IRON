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

#include "edge_if.h"
#include "log.h"
#include "mgms.h"
#include "mgms_edge_if_config.h"
#include "mgms_opts.h"
#include "packet_pool_heap.h"

#include <csignal>
#include <cstdlib>
#include <unistd.h>

using ::iron::EdgeIf;
using ::iron::Log;
using ::iron::PacketPoolHeap;
using ::iron::VirtualEdgeIf;

namespace
{
  /// Class name for logging.
  const char kClassName[] = "mgms_main";

  /// The Multicast Group Management Sniffer.
  Mgms*              mgms           = NULL;

  /// The edge interface. This will be utilized to sniff packets.
  VirtualEdgeIf*     edge_if        = NULL;

  /// Configuration for the edge interface.
  MgmsEdgeIfConfig*  edge_if_config = NULL;

  /// Multicast Group Management Sniffer packet pool (heap-based).
  PacketPoolHeap*    packet_pool    = NULL;
}

//============================================================================
// \brief Clean up everything.
void CleanUp()
{
  LogI(kClassName, __func__, "Cleaning up for shutdown...\n");

  if (mgms != NULL)
  {
    delete mgms;
    mgms = NULL;
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

  if (packet_pool != NULL)
  {
    delete packet_pool;
    packet_pool = NULL;
  }
}

//============================================================================
/// \brief Cleanly shutdown.
///
/// \param  junk  Ignored.
void Finalize(int junk)
{
  Log::OnSignal();

  LogI(kClassName, __func__, "Terminating Multicast Group Management "
       "Sniffer...\n");

  if (mgms != NULL)
  {
    mgms->Stop();
  }

  LogI(kClassName, __func__, "Cleanup complete.\n");

  CleanUp();

  exit(0);
}

//============================================================================
/// \brief Set up handlers for various signals.
void SetSigHandler()
{
  LogI(kClassName, __func__, "Initializing signal handler...\n");

  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    LogW(kClassName, __func__, "Problem setting signal handler for SIGINT\n");
  }
  if (signal(SIGQUIT, Finalize) == SIG_ERR)
  {
    LogW(kClassName, __func__, "Problem setting signal handler for SIGQUIT\n");
  }
  if (signal(SIGTERM, Finalize) == SIG_ERR)
  {
    LogW(kClassName, __func__, "Problem setting signal handler for SIGTERM\n");
  }
}

//============================================================================
int main(int argc, char** argv)
{
  MgmsOpts  mgms_opts;
  mgms_opts.ParseArgs(argc, argv);

  // Set the default logging level.
  Log::SetDefaultLevel(mgms_opts.config_info().Get("Log.DefaultLevel",
                                                   "All", false));

  LogI(kClassName, __func__, "Starting Multicast Group Management "
       "Sniffer...\n");

  // Set the signal handlers for this process.
  SetSigHandler();

  edge_if_config = new (std::nothrow) MgmsEdgeIfConfig();
  if (edge_if_config == NULL)
  {
    LogF(kClassName, __func__, "Error creating new MgmsEdgeIfConfig.\n");
    exit(-1);
  }

  if (!edge_if_config->Initialize(mgms_opts.config_info()))
  {
    LogE(kClassName, __func__, "Edge interface initialization failed. "
         "Aborting...\n");
    CleanUp();
    exit(-1);
  }

  edge_if = new (std::nothrow) EdgeIf(*edge_if_config);
  if (edge_if == NULL)
  {
    LogF(kClassName, __func__, "Error creating new EdgeIf.\n");
    exit(-1);
  }

  packet_pool = new (std::nothrow) PacketPoolHeap();
  if (packet_pool == NULL)
  {
    LogF(kClassName, __func__, "Error creating new PacketPoolHeap.\n");
    exit(-1);
  }
  packet_pool->Create(10);

  // Start the Multicast Group Management Sniffer.
  mgms = new (std::nothrow) Mgms(*edge_if, *packet_pool);
  if (mgms == NULL)
  {
    LogF(kClassName, __func__, "Error creating new Mgms.\n");
    exit(-1);
  }

  mgms->Initialize(mgms_opts.config_info());
  mgms->Start();

  CleanUp();
}
