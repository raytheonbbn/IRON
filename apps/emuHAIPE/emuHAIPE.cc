/* IRON: iron_headers */
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

#include "EmuHAIPEApp.hh"
#include "EmuHAIPEOpts.hh"
#include "ZLog.h"

static const char cn[] = "emuNet";

static EmuHAIPEApp* emuNet = NULL;
static EmuHAIPEOpts options;
//============================================================================
/**
 * Clean up everything.
 *
 * @param junk Ignored.
 */
void Finalize(int junk) 
{
#ifdef DEBUG
  static const char  mn[] = "Finalize";
#endif
  
  zlogI(cn, mn, ("Cleaning up...\n"));
  if (emuNet != NULL) {
    emuNet->stop();
    delete emuNet;
  }
  zlogI(cn, mn, ("Cleanup complete\n"));

  ZLog::File(NULL);
  
  _exit(0);
}

//============================================================================
/**
 * Set up handlers for various signals.
 */
void SetSigHandler()
{
  static const char  mn[] = "SetSigHandler";
  zlogI(cn, mn, ("Initializing signal handler...\n"));
  if (signal(SIGINT, Finalize) == SIG_ERR)
  {
    zlogE(cn, mn, ("Problem setting signal handler for SIGINT\n"));
  }
}

//============================================================================
/**
 * Targeter main application.
 *
 * @param argc The command line argument count, including the program name.
 *
 * @param argv An array of character arrays that contain the command line
 * arguments.
 *
 * @return Returns zero on success, or non-zero on failure.
 */
int main(int argc, char** argv)
{

  if (options.parseArgs(argc,argv)) {
    return(-1);
  }

  //
  // Set logging options based on properties.
  //
  ZLog::Level(options.properties.get("zlog.level", "All"));
//  ZLog::File(options.properties.get("zlog.file", NULL));/
//  ZLog::Ignore(options.properties.get("zlog.ignore", NULL));
//  ZLog::MaxFileSize(options.properties.getInt("zlog.maxFileSize",0));
//  ZLog::MaxFileNum(options.properties.getInt("zlog.maxFileNum",0));
//  ZLog::LogChangeCommand(options.properties.get("zlog.changeCmd", NULL));

  //
  // Set the signal handlers for this process right from the begining.
  //
  SetSigHandler();
  
  emuNet = new EmuHAIPEApp();

  emuNet->configure(options.properties,NULL);

  emuNet->initSockets();

  emuNet->plumb();
  
  emuNet->start();

  while(true) {
    sleep(10);
  }

  return(0);
}
