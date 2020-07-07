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

// This is a modified version of the NORM examples normFileRecv.cpp and
// normFileSend.cpp distributed with the NORM source version 1.5.8.


#include "nftp.h"
#include "nftp_defaults.h"
#include "nftp_gnat_net_if.h"

#include <string>

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <getopt.h>

using ::std::string;

//============================================================================
/// \brief  Prints out usage information.
void Usage()
{
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  nftpg -A <ip_addr> -S <file_name> [options] dst1:[path] "
          "[dst2:[path]] [dst3:[path]]\n");
  fprintf(stderr, "    ... [dstN:[path]]\n\n");
  fprintf(stderr, "  nftp -R <out_dir> -s <src_port> [options]\n\n");
  fprintf(stderr, "General Options:\n");
  fprintf(stderr, "  -i <if_name>     Multicast interface name.\n");
  fprintf(stderr, "                   Default: %s\n", DEFAULT_MCAST_IF_NAME);
  fprintf(stderr, "  -m <mcast_addr>  Destination multicast address for file "
          "transfer.\n");
  fprintf(stderr, "                   Note: This MUST match nftpd multicast "
          "address.\n");
  fprintf(stderr, "                   Default: %s\n", DEFAULT_MCAST_ADDR_STR);
  fprintf(stderr, "  -p <port>        Destination port for file transfer.\n");
  fprintf(stderr, "                   Note: This MUST match nftpd multicast "
          "port.\n");
  fprintf(stderr, "                   Default: %d\n", DEFAULT_MCAST_DST_PORT);
  fprintf(stderr, "  -h               Print out usage information.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Source Options:\n");
  fprintf(stderr, "  -A <ip_addr>     AMP IP Address.\n");
  fprintf(stderr, "  -c               Enable NORM TCP-friendly Congestion "
          "Control.\n");
  fprintf(stderr, "                   Default: Disabled\n");
  fprintf(stderr, "  -D <addr_list>   User-provided destination list for "
          "AMP.\n");
  fprintf(stderr, "  -f               Enable NORM Window-based Flow Control.\n");
  fprintf(stderr, "                   Default: Disabled\n");
  fprintf(stderr, "  -S <file_name>   Send the identified file.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Receiver Options:\n");
  fprintf(stderr, "  -a <src_addr>    The Source Specific Multicast (SSM) IP "
          "Address.\n");
  fprintf(stderr, "                   This indicates that only packets with "
          "this\n");
  fprintf(stderr, "                   source address are desired.\n");
  fprintf(stderr, "  -o <file_name>   Output file name.\n");
  fprintf(stderr, "  -R <out_dir>     Receive a file and place it in the "
          "output\n");
  fprintf(stderr, "                   directory.\n");
  fprintf(stderr, "  -s <src_port>    Source port for file transfer.\n");
  fprintf(stderr, "                   Only packets containing this source "
          "port\n");
  fprintf(stderr, "                   will be received.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "\n");

  exit(1);
}

//============================================================================
string FormatString(int size, const char* format, ...)
{
  char     format_str[size];
  va_list  vargs;

  if ((size < 2) || (format == NULL))
  {
    return "";
  }

  // Use vsnprintf(), which is made to take in the variable argument list.
  va_start(vargs, format);
  if (vsnprintf(format_str, size, format, vargs) > size)
  {
    fprintf(stdout, "[nftpg_main FormatString] String was truncated during "
            "formatting.\n");
  }
  va_end(vargs);

  return format_str;
}

//============================================================================
int main(int argc, char** argv)
{
  // The configuration information, as name value pairs.
  ConfigInfo  config_info;

  // Process the command-line options.
  int  c;
  while ((c = getopt(argc, argv, "A:a:cD:fi:m:o:p:R:S:s:h")) != -1)
  {
    switch (c)
    {
      case 'A':
        config_info.Add("AmpIpAddr", optarg);
        break;

      case 'a':
        config_info.Add("SrcAddrStr", optarg);
        break;

      case 'c':
        config_info.Add("EnableCc", "true");
        break;

      case 'D':
        config_info.Add("FileXfer.DstList", optarg);
        break;

      case 'f':
        config_info.Add("EnableFc", "true");
        break;

      case 'i':
        config_info.Add("McastIfName", optarg);
        break;

      case 'm':
        config_info.Add("McastAddr", optarg);
        break;

      case 'o':
        config_info.Add("OutputFileName", optarg);
        break;

      case 'p':
        config_info.Add("McastDstPort", optarg);
        break;

      case 'R':
        config_info.Add("Rcvr", "true");
        config_info.Add("OutputDir", optarg);
        break;

      case 'S':
        config_info.Add("Sndr", "true");
        config_info.Add("FilePath", optarg);
        break;

      case 's':
        config_info.Add("SrcPort", optarg);
        break;

      case 'h':
      default:
        Usage();
    }
  }

  // Get the command-line options, which contains the information for each
  // destination. Each option is of the form:
  //
  //   dst_name:[dst_path]
  size_t  num_dsts  = 0;
  for (; optind < argc; optind++)
  {
    config_info.Add(FormatString(64, "Dst%d", num_dsts), argv[optind]);
    num_dsts++;
  }

  // Add the number of destinations to the configuration information.
  int  rv;
  char  buf[16];
  rv = snprintf(buf, sizeof(buf), "%zd", num_dsts);

  if (rv <= 0)
  {
    fprintf(stderr, "[nftp_main main] Error converting integer %zd to a "
            "string.\n", num_dsts);
  }
  else
  {
    config_info.Add("NumDsts", buf);
  }

  // Create the nftp network interface,
  NftpGnatNetIf*  nftp_gnat_net_if = new (std::nothrow) NftpGnatNetIf();
  if (nftp_gnat_net_if == NULL)
  {
    fprintf(stderr, "[nftpg_main main] Error creating new NftpGnatNetIf.\n");
    exit(1);
  }

  // Create the nftp object,
  Nftp  nftp(nftp_gnat_net_if);

  // initialize it, and
  if (!nftp.Initialize(config_info))
  {
    fprintf(stderr, "[nftpg_main main] Error initializing nftp. "
            "Aborting...\n");
    Usage();
  }

  // start it.
  nftp.Start();

  // Exit successfully.
  exit(0);
}
