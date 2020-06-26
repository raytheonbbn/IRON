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
#include "EmuHAIPEOpts.hh"
#include "ZLog.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static const char  cn[] = "EmuHAIPEOpts";

/*==========================================================================*/

EmuHAIPEOpts::EmuHAIPEOpts()
{
  // Initialize the options to their default values.
  initialize();
}

EmuHAIPEOpts::EmuHAIPEOpts(int argc, char** argv)
{
  initialize();
  parseArgs(argc,argv);
}


EmuHAIPEOpts::~EmuHAIPEOpts()
{
}

void EmuHAIPEOpts::initialize() 
{
  verbose = 0;
  error   = 0;
}

//=============================================================================
void EmuHAIPEOpts::usage(const char* message ) 
{
  fprintf(stderr, "\n");
  fprintf(stderr, "emuHAIPE - Tool for emulating network effects due to HAIPE processing\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "  %s [options]\n", "emuHAIPE");
  fprintf(stderr, "\n");
  fprintf(stderr, "Options\n");
  fprintf(stderr, "   -h                 Help.\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -f <file>          Property file to load\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -a <IP_address>    IP address assigned to the VIF\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -B <dev>           Name of the black-side IF (e.g., eth2)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -b <IP_address>    Broadcast address assigned to the VIF\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -d <dev>           Name of the virtual IF (e.g., haipe0)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -e <0 or 1>        Flag indicating whether (1) or not (0) external plumbing will be used\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -i <ip_cmd>        ip command (e.g., /sbin/ip)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -m <mark>          Firewall mark used for routing\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -n <IP_netmask>    Netmask assigned to the VIF\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -o <num_ bytes>    HAIPE overhead (e.g., 60 bytes)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -R <dev>           Name of the red-side interface (e.g., eth1)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -r <table_id>      Alternate routing table ID (used for plumbing)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -s <ifconfig_cmd>  ifconfig command (e.g., /sbin/ifconfig)\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "   -t <iptables_cmd>  iptables command (e.g., /sbin/iptables)\n");
  fprintf(stderr, "\n");
}


/*==========================================================================*/
int EmuHAIPEOpts::parseArgs(int argc, char** argv)
{
  // Read the command line arguments.
  //
  argc--;
  int mark = 1;
  while (argc) {

    if (strcmp(argv[mark],"-V")==0) 
      {
	verbose = 1;
	argc--; mark++;
	
      } 

    else if ((strcmp(argv[mark], "-h") == 0) || 
	     (strcmp(argv[mark], "-H") == 0))
      {
	usage(argv[0]);
	error++;
	return 1;
      } 

    else if (strcmp(argv[mark],"-a")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "VIF IP address must follow -a\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("VIFAddress",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-B")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "Black-side device name must follow -l\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("BlackSide_PhyDevName",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-b")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "VIF broadcast address must follow -b\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("VIFBroadcast",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-d")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "Virtual IF device name must follow -d\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("VIFDevName",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-e")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "external plumbing flag value must follow -e\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("ExternalPlumbing",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-f")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "Property filename must follow -f\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }

	const char* pname = argv[mark];
	if (!properties.load(pname)) 
	  {
	    zlogE(cn, "parseArgs", ("Error loading property file %s.\n", pname));
	    usage(argv[0]);
	    error++;
	    return -1;
	  }

	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-i")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "ip command must follow -i\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("IPCmd",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-m")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "firewall mark value must follow -m\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("FirewallMark",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-n")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "VIF netmask must follow -n\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("VIFNetmask",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-o")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "HAIPE overhead in bytes must follow -o\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("HAIPE_Overhead",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-R")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "Red-side device name must follow -l\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("RedSide_PhyDevName",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-r")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "alternate routing table ID must follow -r\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("VIFAltTable",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-s")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "ifconfig command must follow -s\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("IFCmd",argv[mark]);
	argc--; mark++;
    } 

    else if (strcmp(argv[mark],"-t")==0) 
      {
	argc--; mark++;
	if (argc < 1) 
	  {
	    fprintf(stderr, "iptables command must follow -i\n");
	    usage(argv[0]);
	    error++;
	    return -1;
	  }
	properties.set("IPTablesCmd",argv[mark]);
	argc--; mark++;
    } 

    else if (argv[mark][0] == '-') 
      {
	fprintf(stderr, "Unrecognized flag %s\n",argv[mark]);
	usage(argv[0]);
	error++;
	return -1;
      }

    else 
      {
	fprintf(stderr, "Illegal parameter %s\n",argv[mark]);
	usage(argv[0]);
	error++;
	return -1;
      }
  }

  return 0;
}  
