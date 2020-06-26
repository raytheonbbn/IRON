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

#include "ftc.h"
#include "log.h"
#include "unused.h"

#include <csignal>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>           //getopt

using ::iron::FTC;
using ::iron::Log;
using ::std::string;

namespace
{
  FTC*        ftc                 = NULL;
  const char* UNUSED(kClassName)  = "FTC main";
}

//============================================================================
///
/// Clean up everything.
///
void CleanUp()
{
  LogI(kClassName, __func__, "Cleaning up for shutdown...\n");

  if (ftc != NULL)
  {
    delete ftc;
    ftc = NULL;
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

  LogI(kClassName, __func__, "Terminating FTC.\n");

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
  //
  // Set the signal handlers for this process right from the beginning.
  //
  SetSignalHandler();

  if (argc != 7)
  {
    LogF(kClassName, __func__, "Wrong number of arguments (%d). Usage: "
         "ftc saddr:sport daddr:dport size (bytes) deadline (seconds) "
         "AMP_addr priority\n", argc);
  }

  ftc = new (std::nothrow) FTC();

  if (!ftc)
  {
    LogF(kClassName, __func__, "Unable to allocate memory for FTC.\n");
  }

  //
  // Send the message to AMP.
  //

  ftc->ConfigureFt(argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);

  CleanUp();

  exit(0);
}
