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

#include "tcp_proxy_opts.h"
#include "log.h"
#include "socket.h"
#include "unused.h"

#include <cstdlib>
#include <getopt.h>

using ::iron::Log;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "TcpProxyOpts";
}

//============================================================================
TcpProxyOpts::TcpProxyOpts()
    : config_info_()
{
}

//============================================================================
TcpProxyOpts::TcpProxyOpts(int argc, char** argv)
{
  ParseArgs(argc, argv);
}

//============================================================================
TcpProxyOpts::~TcpProxyOpts()
{
}

//============================================================================
void TcpProxyOpts::Usage(const char* prog_name)
{
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [options]\n\n", prog_name);
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -c <name>       The fully qualified name of the TCP "
          "Proxy's configuration\n");
  fprintf(stderr, "                  file.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -I <dev>         Name of the LAN-side IF (e.g., "
          "eth1)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -l <name>       The fully qualified name of the TCP "
          "Proxy's log file.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -L <log levels> The log level as a string "
          "(e.g., FEWIAD).\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -d              Turn on debug logging. This is "
          "equivalent to -L FEWIAD\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "  -h              Print out usage information.\n");
  fprintf(stderr, "\n");

  exit(1);
}

//============================================================================
void TcpProxyOpts::ParseArgs(int argc, char** argv)
{
  int  c;

  while ((c = getopt(argc, argv, "c:I:i:l:L:dh")) != -1)
  {
    switch (c)
    {
      case 'c':
        if (!config_info_.LoadFromFile(optarg))
        {
          LogE(kClassName, __func__, "Error loading configuration "
               "information from file %s.\n", optarg);
          Usage(argv[0]);
        }
        break;

      case 'I':
        config_info_.Add("InboundDevName", optarg);
        break;

      case 'l':
        Log::SetOutputFile(optarg, false);
        break;

      case 'L':
        config_info_.Add("Log.DefaultLevel", optarg);
        break;

      case 'd':
        config_info_.Add("Log.DefaultLevel", "All");
        break;

      case 'h':
      default:
        Usage(argv[0]);
    }
  }
}
