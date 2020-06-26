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
#include "list.h"
#include "log.h"
#include "string_utils.h"
#include "timer.h"
#include "unused.h"

#include <csignal>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>           //getopt

using ::iron::Amp;
using ::iron::ConfigInfo;
using ::iron::List;
using ::iron::Log;
using ::iron::StringUtils;
using ::iron::Timer;
using ::std::string;

namespace
{
  Timer*      timer               = NULL;
  Amp*        amp                 = NULL;
  const char* UNUSED(kClassName)  = "AMP main";
}

///
/// Print out the usage syntax.
///
/// \param  prog_name  The name of the program.
///
void Usage(const std::string& prog_name)
{
  fprintf(stderr,"\n");
  fprintf(stderr,"Usage:\n");
  fprintf(stderr,"  %s [options]\n", prog_name.c_str());
  fprintf(stderr,"\n");
  fprintf(stderr,"Options:\n");
  fprintf(stderr," -c <name>  The fully qualified name of the system\n");
  fprintf(stderr,"             configuration file with control port information..\n");
  fprintf(stderr," -f <name>  The fully qualified name of the AMP command config\n");
  fprintf(stderr,"             file with the commands to be executed and the time\n");
  fprintf(stderr,"             they should be executed.\n");
  fprintf(stderr," -l <name>  The fully qualified name of the AMP's\n");
  fprintf(stderr,"            log file. Default behavior sends\n");
  fprintf(stderr,"             log statements to stdout.\n");
  fprintf(stderr," -d         Turn on debug logging.\n");
  fprintf(stderr," -h         Print out usage information.\n");
  fprintf(stderr,"\n");

  exit(2);
}
//============================================================================
///
/// Clean up everything.
///
void CleanUp()
{
  LogI(kClassName, __func__, "Cleaning up for shutdown...\n");

  if (amp != NULL)
  {
    delete amp;
    amp = NULL;
  }
  if (timer != NULL)
  {
    delete timer;
    timer = NULL;
  }

  LogI(kClassName, __func__, "Cleanup complete.\n");

  Log::Flush();
  Log::Destroy();
}

//============================================================================
///
/// Cleanly shutdown.
///
/// \param  junk  Ignored.
///
void Finalize(int junk)
{
  Log::OnSignal();

  LogI(kClassName, __func__, "Terminating Amp.\n");

  if (amp != NULL)
  {
    amp->Stop();
  }

  CleanUp();

  exit(0);
}

//============================================================================
///
/// Set up handlers for the various signals that this process will catch and
/// handle.
///
void SetSignalHandler()
{
  LogI(kClassName, __func__, "Initializing signal handler...\n");

  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Problem setting signal handler for SIGINT.\n");
  }

  if (signal(SIGQUIT, Finalize) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Problem setting signal handler for SIGQUIT.\n");
  }

  if (signal(SIGTERM, Finalize) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Problem setting signal handler for SIGTERM.\n");
  }
}

//=============================================================================
int main(int argc, char** argv)
{
  extern char*  optarg;
  int           c;
  ConfigInfo    config_info;
  bool          debug = false;
  string        cmd_file = "";

  while ((c = getopt(argc, argv, "c:f:l:dh")) != -1)
  {
    switch (c)
    {
      case 'c':
        if (!config_info.LoadFromFile(optarg))
        {
          LogE(kClassName, __func__, "Error loading configuration file %s.\n",
               optarg);
          Usage(argv[0]);
          exit(1);
        }
        break;
      case 'f':
        cmd_file = optarg;
        break;

      case 'l':
        if(!Log::SetOutputFile(optarg, false))
        {
          LogF(kClassName, __func__, "Unable to set log file %s,\n", optarg);
          exit(1);
        }
        break;

      case 'd':
        debug = true;
        break;

      case 'h':
      default:
        Usage(argv[0]);
    }
  }

  //
  // Set the signal handlers for this process right from the beginning.
  //
  SetSignalHandler();

  //
  // Set logging options based on properties.
  //
  if (debug)
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

    LogI(kClassName, __func__,
         "Setting class %s logging to %s.\n",
         token_name.c_str(), token_value.c_str());
    Log::SetClassLevel(token_name, token_value);
  }

  timer = new (std::nothrow) Timer();
  if (!timer)
  {
    LogF(kClassName, __func__,
         "Failed to allocate timer.\n");
    exit(0);
  }

  if (cmd_file != "")
  {
    amp = new (std::nothrow) Amp(*timer, cmd_file);
  }
  else
  {
    amp = new (std::nothrow) Amp(*timer);
  }

  if (!amp)
  {
    LogF(kClassName, __func__, "Unable to allocate memory for AMP.\n");
  }

  //
  // initialize it, and
  //

  if (!amp->Initialize(config_info))
  {
    LogF(kClassName, __func__, "Error initializing Amp. Aborting...\n");
    exit(1);
  }

  //
  // start it.
  //

  amp->Start();

  CleanUp();

  exit(0);
}
