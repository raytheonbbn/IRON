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

// A NORM-based FTP daemon. This receives nftp control messages and starts an
// nftp receiver if the receiving node is in the destination list for the
// upcoming NORM-based file transfer.
//
// This is a modified version of the NORM example, normStreamRecv.cpp,
// distributed with the NORM source version 1.5.8.
//

// NOTE: We tried to set up signal handlers so the nftp daemon could be shut
// down properly when certain signals were received. However, we ran into some
// difficulty when we did this. We observed some very weird stack dumps with
// some free errors when the Nftpd object was deleted. The Nftpd object goes
// into a blocking NORM call in the Start() method, where NORM events are
// received. Due to time constraints, will not investigate this any
// further. We simply won't clean everything up nicely when the nftpd process
// is killed. This is not ideal but will work.
//
// TODO: Investigate if there is a non-blocking version of the
// NormGetNextEvent() call or figure out what that call is doing that is
// causing the weird observed behavior.

#include "nftp_defaults.h"
#include "nftpd.h"
#include "nftp_config_info.h"

#include <cstdio>
#include <cstdlib>
#include <getopt.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

//============================================================================
/// \brief Print out usage information.
void Usage()
{
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  nftpd [options]\n\n");
  fprintf(stderr, "Options:\n");
  fprintf(stderr, "  -B <bin_dir>     The location of the nftp binary.\n");
  fprintf(stderr, "                   Default: %s\n", DEFAULT_NFTP_BIN_DIR);
  fprintf(stderr, "  -i <if_name>     Multicast interface name.\n");
  fprintf(stderr, "                   Default: %s\n", DEFAULT_MCAST_IF_NAME);
  fprintf(stderr, "  -m <mcast_addr>  Multicast address.\n");
  fprintf(stderr, "                   Default: %s\n", DEFAULT_MCAST_ADDR_STR);
  fprintf(stderr, "  -p <port>        Multicast port.\n");
  fprintf(stderr, "                   Default: %d\n", DEFAULT_MCAST_DST_PORT);
  fprintf(stderr, "  -t               Direct nftp receiver to write files\n");
  fprintf(stderr, "                   to a temporary location during\n");
  fprintf(stderr, "                   transfer, then move to final\n");
  fprintf(stderr, "                   location when transfer completes.\n");
  fprintf(stderr, "  -v <virt_addr>   The host's virtual address.\n");
  exit(1);
}

//============================================================================
int main(int argc, char** argv)
{
  // The configuration information, as name value pairs.
  ConfigInfo  config_info;

  // Process the command-line options.
  int  c;
  while ((c = getopt(argc, argv, "B:i:m:p:tv:h")) != -1)
  {
    switch (c)
    {
      case 'B':
        config_info.Add("NftpBinDir", optarg);
        break;

      case 'i':
        config_info.Add("McastIfName", optarg);
        break;

      case 'm':
        config_info.Add("McastAddrStr", optarg);
        break;

      case 'p':
        config_info.Add("McastDstPort", optarg);
        break;

      case 't':
        config_info.Add("TempFilesOpt", "-t");
        break;

      case 'v':
        config_info.Add("VirtualAddrStr", optarg);
        break;

      case 'h':
      default:
        Usage();
    }
  }

  // Create the nftp daemon,
  Nftpd  nftpd;

  // initialize it, and
  if (!nftpd.Initialize(config_info))
  {
    fprintf(stderr, "[nftpd_main main] Error initializing nftp "
            "daemon. Aborting...\n");
    Usage();
  }

  // start it.
  nftpd.Start();

  exit(0);
}
