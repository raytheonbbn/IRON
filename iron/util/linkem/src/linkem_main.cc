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

#include "linkem.h"
#include "log.h"
#include "unused.h"

#include <string>

#include <csignal>
#include <cstdlib>
#include <popt.h>

// The following is required if we wish to experiment further with memory
// locking.
// #include <sys/mman.h>

using ::iron::Log;
using ::std::string;

namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "linkem_main";

  /// The LinkEm.
  LinkEm*  linkem = NULL;
}

//============================================================================
void CleanUp()
{
  LogI(kClassName, __func__, "Cleaning up for shutdown...\n");

  if (linkem != NULL)
  {
    delete linkem;
    linkem = NULL;
  }

  // The following is required if we wish to experiment further with memory
  // locking.
  // munlockall();

  LogI(kClassName, __func__, "Cleanup complete.\n");

  Log::Flush();
  Log::Destroy();
}

//============================================================================
void Finalize(int sig_num)
{
  linkem->set_done(true);
}

//============================================================================
void FinalizeAbort(int sig_num)
{
  // Print out which signal was received and abort, which will generate a core
  // file.
  LogF(kClassName, __func__, "Rcvd. signal %d\n", sig_num);
}

//============================================================================
static void SetSignalHandlers()
{
  // The SIGINT signal will invoke a routine to clean up the LinkEm. All
  // signals whose default action is 'Term' (see man 7 signal for details)
  // invoke a routine that will generate a core file. This will enable us to
  // diagnose any issues when a "disappearing" LinkEm situation arises in
  // which, by default, no core file is generated.

  if (signal(SIGHUP, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGHUP signal handler.\n");
  }

  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGINT signal handler.\n");
  }

  if (signal(SIGPIPE, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGPIPE signal handler.\n");
  }

  if (signal(SIGALRM, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGALRM signal handler.\n");
  }

  if (signal(SIGUSR1, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGUSR1 signal handler.\n");
  }

  if (signal(SIGUSR2, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGUSR2 signal handler.\n");
  }

  if (signal(SIGPOLL, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGPOLL signal handler.\n");
  }

  if (signal(SIGPROF, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGPROF signal handler.\n");
  }

  if (signal(SIGVTALRM, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGVTALRM signal "
         "handler.\n");
  }

  if (signal(SIGSTKFLT, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGSTKFLT signal "
         "handler.\n");
  }

  if (signal(SIGIO, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGIO signal handler.\n");
  }

  if (signal(SIGPWR, FinalizeAbort) == SIG_ERR)
  {
    LogE(kClassName, __func__, "Error setting up SIGPWR signal handler.\n");
  }
}

//============================================================================
int main(int argc, const char *argv[])
{

  // Command line stuff.
  char*  if1              = NULL;
  char*  if2              = NULL;
  char*  config_file_name = NULL;
  char*  log_file_name    = NULL;
  char*  log_level        = NULL;
  int    port             = 3456;
  int    bypassValue      = 0x3; // Default to using the original ECN bits

  struct poptOption options[] = {
      { NULL, 'p',  POPT_ARG_INT,    &port, 0, "management listen port",
        "<port>"},
      { NULL, '1',  POPT_ARG_STRING, &if1,  0, "interface 1, e.g. eth0",
        "<if1>"},
      { NULL, '2',  POPT_ARG_STRING, &if2,  0, "interface 2, e.g. eth1",
        "<if2>"},
      { NULL, 'c',  POPT_ARG_STRING, &config_file_name,  0,
        "Config file name.", "<config_file_name>"},
      { NULL, 'l',  POPT_ARG_STRING, &log_file_name,  0,
        "The fully qualified name of the LinkEm log file.", "<name>"},
      { NULL, 'L',  POPT_ARG_STRING, &log_level,  0,
        "The log level as a string (e.g., FEWIAD).", "<log levels>"},
      { NULL, 'w', POPT_ARG_INT, &bypassValue, 0,
        "TOS bypass value: 0 disables bypass processing", 0},
      POPT_AUTOHELP POPT_TABLEEND
    };

  poptContext optCon;

  optCon = poptGetContext(NULL, argc, argv, options, 0);

  poptGetNextOpt(optCon);

  if ((if1 == NULL) || (if2 == NULL))
  {
    poptPrintUsage(optCon, stderr, 0);
    return 1;
  }

  // The following is required if we wish to experiment further with memory
  // locking.
  // mlockall(MCL_CURRENT | MCL_FUTURE);

  if (log_file_name != NULL)
  {
    iron::Log::SetOutputFile(log_file_name, false);
  }

  string  log_level_str = "FEWI";
  if (log_level != NULL)
  {
    log_level_str = log_level;
  }

  iron::Log::SetDefaultLevel(log_level_str);

  poptFreeContext(optCon);

  // Set the signal handlers for this process.
  SetSignalHandlers();

  // Create, configure, and start LinkEm.
  linkem = new (std::nothrow) LinkEm();
  if (linkem == NULL)
  {
    LogF(kClassName, __func__, "Error allocating LinkEm.\n");
  }

  linkem->set_mgmt_port(port);

  LogD(kClassName, __func__, "#1 if1=%s, if2=%s, m=%d, throttle=%f bits/s, "
       "delay=%d ms\n", if1, if2, model_name, throttle, delay);

  linkem->set_bypass_tos_value(bypassValue & 0xff);

  if (linkem->Initialize(if1, if2))
  {
    // Configure the LinkEm.
    if (!linkem->Configure(config_file_name))
    {
      LogF(kClassName, __func__, "Error configuring LinkEm.\n");
    }

    linkem->Start();
  }

  // Brige is done, cleanup.
  linkem->CleanupBridge();

  if (if1 != NULL)
  {
    free(if1);
    if1 = NULL;
  }

  if (if2 != NULL)
  {
    free(if2);
    if2 = NULL;
  }

  if (log_level != NULL)
  {
    free(log_level);
    log_level = NULL;
  }

  if (config_file_name != NULL)
  {
    free(config_file_name);
    config_file_name = NULL;
  }

  CleanUp();

  exit(0);
}
