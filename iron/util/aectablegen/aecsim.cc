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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "CalculateFECRate.h"
#include "CallocND.h"
#include "setupDofLookupTables.h"

#include "doflutparms.h"

int isrcvd(double actualper);


double
pertest[] = 
{0.100,0.200,0.300,0.400,0.500};

double
epstest[] = 
{0.005,0.010,0.015,0.020,0.025,0.030,
 0.035,0.040,0.045,0.050};

#define NPERTEST (sizeof(pertest)/sizeof(double))
#define NEPSTEST (sizeof(epstest)/sizeof(double))

int
main (int argc, char**argv)
{
  int    max_block_length = 40;
  double tgtPrecv         = 0.0;
  int    dof_to_send      = 0;
  int    nRounds          = 2;        // One xmit + (nRounds - 1) rexmits
  int    nTrials          = 10000000; // Number of runs used to evaluate algorithm

  int    maxRounds        = 20;    // Shouldn't need more than these to finish

  int    ***dof_lut_midgame = NULL;
  int    ***dof_lut_endgame = NULL;

  // This lut is used for all but the last round
  // and is indexed as nRcvd, kRcvd

  if ((dof_lut_midgame = (int ***)
       Calloc3D(MAXSRCPKTS+1,MAXSRCPKTS,MAXSRCPKTS,sizeof(int))) == NULL)
  {
    printf("Memory allocation failure\n");
    goto CleanupExit;
  }
  
  // This lut is used for the very last round 
  // and is also indexed as nRcvd, kRcvd

  if ((dof_lut_endgame = (int ***)
       Calloc3D(MAXSRCPKTS+1,MAXSRCPKTS,MAXSRCPKTS,sizeof(int))) == NULL)
  {
    printf("Memory allocation failure\n");
    goto CleanupExit;
  }

  for (int currNumSrcPkts = 1; currNumSrcPkts <= MAXSRCPKTS; currNumSrcPkts++)
  {
    // printf("******* Number of Source Packets: %d *********\n",currNumSrcPkts);
    for (int perindex=0; perindex<NPERTEST; perindex++)
    {
      // double per = pervals[perindex];
      double per = pertest[perindex];
      
      //printf("\n==============================\n");
      //printf("per is %f\n",per);
      
      for (nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	for (int pr=0; pr<NEPSTEST; pr++)
	{
	  // tgtPrecv = 1.0 - epsilon[pr];
	  tgtPrecv = 1.0 - epstest[pr];
	  
	  // The following block is only for informational purposes	
	  // Determine how many rounds would be needed if we use pure ARQ
	  int    arqCutover = 1;
	  double testPloss  = per;
	  while (testPloss > (1 - tgtPrecv))
	  {
	    testPloss  *= per;
	    arqCutover ++;
	  }
	  // printf("ARQ cutover occurs at %d rounds\n",arqCutover);
	  
	  // The following block is only for informational purposes
	  int mode = 0;
	  if (nRounds == 1)
	  {
	    mode = 1; // Pure FEC
	  }
	  else if (nRounds < arqCutover)
	  {
	    mode = 2; // Coded ARQ
	  }
	  else
	  {
	    mode = 3; // Pure ARQ
	  }
	  
	  setup_dof_lookup_tables(per, nRounds, tgtPrecv,
				  MAXSRCPKTS, dof_lut_midgame, dof_lut_endgame);
	
	  int success_count = 0; // Instrumentation variable
	  int tot_pkts_sent = 0; // Instrumentation variable
	  int tot_src_rcvd  = 0; // Instrumentation variable
	  int tot_fec_rcvd  = 0; // Instrumentation variable
	  int tot_dof_rcvd  = 0; // Instrumentation variable
	  int tot_ext_rcvd  = 0; // Instrumentation variable
	  
	  for (int trial = 0; trial<nTrials; trial++)
	  {
	    // printf("Trial %d\n",trial);
	    int src_rcvd = 0; // Algorithm variable
	    int fec_rcvd = 0; // Algorithm variable
	    int dof_rcvd = src_rcvd + fec_rcvd; // Algorithm variable
	    int round    = 0; // Algorithm variable
	    
	    int completedOnTime      = 0; // Instrumentation variable
	    int roundCompleted       = 0; // Instrumentation variable
	    int src_rcvd_final_round = 0; // Instrumentation variable
	    int fec_rcvd_final_round = 0; // Instrumentation variable
	    int dof_rcvd_final_round = 0; // Instrumentation variable
	    
	    for (round = 0; round<maxRounds; round++)
	    {
	      int dof_needed  = currNumSrcPkts - dof_rcvd; // Algorithm variable
	      int tot_to_send = 0;                         // Algorithm variable
	      int ins_to_send = 0;                         // Algorithm variable
	      
	      if (round < nRounds - 1)
	      {
		tot_to_send = dof_lut_midgame[currNumSrcPkts][src_rcvd][fec_rcvd];
	      }
	      else
	      {
		tot_to_send = dof_lut_endgame[currNumSrcPkts][src_rcvd][fec_rcvd];
	      }
	      
	      int src_to_send = 0;                    // Algorithm variable
	      int fec_to_send = 0;                    // Algorithm variable
	      
	      if (tot_to_send < (currNumSrcPkts - src_rcvd))
	      {
		src_to_send = tot_to_send;
		fec_to_send = 0;
	      }
	      else
	      {
		src_to_send = currNumSrcPkts - src_rcvd;
		fec_to_send = tot_to_send    - src_to_send;
	      }
	      
	      // printf("   Sending %d src and %d fec packets\n",src_to_send,fec_to_send);
	      
	      for (int i=0; i<src_to_send; i++)
	      {
		src_rcvd += isrcvd(per); // Models ACK/NACK from receiver
	      }
	      
	      for (int i=0; i<fec_to_send; i++)
	      {
		fec_rcvd += isrcvd(per); // Models ACK/NACK from receiver
	      }
	      
	      dof_rcvd  = src_rcvd + fec_rcvd;
	      
	      // Code below is for monitoring and loop control
	      
	      // printf("      Received %d src and %d fec pkts\n",src_rcvd,fec_rcvd);
	      
	      tot_pkts_sent += (src_to_send + fec_to_send);
	      
	      if (dof_rcvd >= currNumSrcPkts) // we are done when we have enough DOFs
	      {
		// Record if we finished within the alloted number of rounds
		if  (round < nRounds)
		{
		  completedOnTime = 1;
		  roundCompleted  = round;
		}
		// In any case, we are done. Receiver can decode/has all data needed
		break;
	      }
	      
	      if (round == nRounds - 1) // if we go past target nRounds, save srcs rcvd
	      {
		src_rcvd_final_round = src_rcvd;
		fec_rcvd_final_round = fec_rcvd;
		dof_rcvd_final_round = dof_rcvd;
	      }
	    }
	    
	    // End of the error control loop: gather statistics
	    
	    if (completedOnTime == 1)
	    {
	      // printf("   Completed in %d rounds\n",roundCompleted+1);
	      success_count++;
	      tot_src_rcvd += currNumSrcPkts;
	      tot_fec_rcvd += fec_rcvd;
	      tot_dof_rcvd += dof_rcvd;
	      tot_ext_rcvd += dof_rcvd - currNumSrcPkts;
	    }
	    else
	    {
	      // printf("   Did not complete after %d rounds\n",nRounds);
	      // printf("      Total src pkts received in nRounds: %d\n",
	      //	     src_rcvd_final_round);
	      // printf("      Completion took %d rounds\n",round);
	      tot_src_rcvd += src_rcvd_final_round;
	      tot_fec_rcvd += fec_rcvd_final_round;
	      tot_dof_rcvd += dof_rcvd_final_round;
	      tot_ext_rcvd += fec_rcvd_final_round;
	    }
	  }
	  
	  double achEff = (double)tot_src_rcvd /
	    (double)(tot_src_rcvd + tot_ext_rcvd);
	  
	  double achEps = 1.0 - (double)tot_src_rcvd /
	    (double)(nTrials*currNumSrcPkts);
	  
	  printf("%d %f %d %f %f %f %d %d %d\n",currNumSrcPkts,
		 per, nRounds,1.0 - tgtPrecv,
		 achEps,achEff,
		 achEps < 1.0 - tgtPrecv ? 1 : 0,
		 mode,
		 nRounds == 1 ? dof_lut_endgame[currNumSrcPkts][0][0] :
		 dof_lut_midgame[currNumSrcPkts][0][0]);
	}
      }
    }
  }
CleanupExit:

  if (dof_lut_midgame != NULL)
  {
    free(dof_lut_midgame);
    dof_lut_midgame = NULL;
  }

  if (dof_lut_endgame != NULL)
  {
    free(dof_lut_endgame);
    dof_lut_endgame = NULL;
  }
}

int isrcvd(double per)
{
  double draw = (double)rand() / (double)RAND_MAX;
  if (draw > per)
  {
    return 1;
  }
  return 0;
}
	      
