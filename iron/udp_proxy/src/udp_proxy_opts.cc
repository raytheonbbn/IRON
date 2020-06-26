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

#include "udp_proxy_opts.h"
#include "log.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

using ::iron::Log;
using ::std::string;

namespace
{
  /// Class name for loggind.
  const char*  kClassName = "UdpProxyOpts";
}

//============================================================================
UdpProxyOpts::UdpProxyOpts()
    : config_info_()
{
}

//============================================================================
UdpProxyOpts::UdpProxyOpts(int argc, char** argv)
    : config_info_()
{
  ParseArgs(argc,argv);
}

//============================================================================
UdpProxyOpts::~UdpProxyOpts()
{
  // Nothing to destroy.
}

//============================================================================
int UdpProxyOpts::ParseArgs(int argc, char** argv)
{
  // Read the command line arguments.
  argc--;
  int     error    = 0;
  int     mark     = 1;
  bool    debug    = false;
  string  log_file = "";

  while (argc)
  {
    if (strcmp(argv[mark], "-v") == 0)
    {
      argc--; mark++;
    }
    else if (strcmp(argv[mark], "-d") == 0)
    {
      // Set a flag and do this after all options have been processed.
      debug = true;
      argc--; mark++;
    }
    else if ((strcmp(argv[mark], "-h") == 0) ||
	     (strcmp(argv[mark], "-H") == 0))
    {
      Usage(argv[0]);
      error++;
      return 1;
    }
    else if (strcmp(argv[mark], "-C") == 0)
    {
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "Control port number must follow -C\n");
        Usage(argv[0]);
        error++;
        return -1;
      }
      config_info_.Add("TCPControlPort", argv[mark]);
      argc--; mark++;
    }
    else if (strcmp(argv[mark], "-c") == 0)
    {
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "configInfo filename must follow -c\n");
        Usage(argv[0]);
        error++;
        return -1;
      }

      const char*  pname = argv[mark];
      if (!config_info_.LoadFromFile(pname))
      {
        LogE(kClassName, "parseArgs", "Error loading property file %s.\n",
             pname);
        Usage(argv[0]);
        error++;
        return -1;
      }

      argc--; mark++;
    }
    else if (strcmp(argv[mark], "-g") == 0)
    {
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "Garbage collection cleanup interval must follow "
                "-g\n");
        Usage(argv[0]);
        error++;
        return -1;
      }
      config_info_.Add("GCIntervalSec", argv[mark]);
      argc--; mark++;
    }
    else if (strcmp(argv[mark], "-k") == 0)
    {
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "Decoder Kleanup timeout value must follow -k\n");
        Usage(argv[0]);
        error++;
        return -1;
      }
      config_info_.Add("DecoderTimeoutSec", argv[mark]);
      argc--; mark++;
    }
    else if (strcmp(argv[mark], "-I") == 0)
    {
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "Inbound IF device name must follow -I\n");
        Usage(argv[0]);
        error++;
        return -1;
      }
      config_info_.Add("InboundDevName", argv[mark]);
      argc--; mark++;
    }
    else if (strcmp(argv[mark], "-l") == 0)
    {
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "Log filename must follow -l\n");
        Usage(argv[0]);
        error++;
        return -1;
      }
      log_file = argv[mark];
      argc--; mark++;
    }
    else if (strncmp(argv[mark], "-S", 2) == 0)
    {
      int lval = atoi(&argv[mark][2]);
      char servName[100];
      argc--; mark++;
      if (argc < 1)
      {
        fprintf(stderr, "Service parameters must follow -S%d\n", lval);
        Usage(argv[0]);
        error++;
        return -1;
      }

      // Note that this doesn't do any syntax checking whatsoever...
      snprintf(&servName[0], sizeof(servName) - 1, "Service%d", lval);
      config_info_.Add(&servName[0], argv[mark]);
      argc--; mark++;
    }
    else if (argv[mark][0] == '-')
    {
      fprintf(stderr, "Unrecognized flag %s\n", argv[mark]);
      Usage(argv[0]);
      error++;
      return -1;
    }
    else
    {
      fprintf(stderr, "Illegal parameter %s\n", argv[mark]);
      Usage(argv[0]);
      error++;
      return -1;
    }
  }

  // The command line -d overwrites the config file default log level.
  if (debug)
  {
    config_info_.Add("Log.DefaultLevel", "FEWIAD");
  }

  if (!log_file.empty())
  {
    config_info_.Add("Log.File", log_file);
  }

  return 0;
}

//============================================================================
void UdpProxyOpts::Usage(const char* progname)
{
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [options]\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "Options\n");
  fprintf(stderr, "   -h                 Help.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -d                 Turn debug logging on.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -c <cfg file>      configInfo file to load\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -C <control_port>  TCP port used to control the "
          "UDP proxy\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -g <time_secs>     Garbage Collection cleanup "
          "interval.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -u <time_usecs>    Period processing interval.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -k <time_secs>     Decoder state Kleanup timeout\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -I <dev>           Name of the LAN-side IF "
          "(e.g., eth1)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -l <log_file>      Name of the file to write log\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -S0 <loPort-hiPort;baseRate/totalRate;strict>\n");
  fprintf(stderr, "       ...            Service defs (max 16): port range,\n");
  fprintf(stderr, "       ...            default encoding rate, and\n");
  fprintf(stderr, "       ...            packet ordering requirements\n");
  fprintf(stderr, "   -S15 <loPort-hiPort;baseRate/totalRate;strict>\n");
  fprintf(stderr, "\n");
}
