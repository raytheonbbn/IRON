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

#define dumpsearchvals 0

#define MAXSRCPKTS 10  
#define NTGTPRECV  14
#define NROUNDS     7
#define NPERS       9

double
pervals[NPERS]     = {0.1, 0.15, 0.2, 0.25, 0.3,
		      0.35, 0.4, 0.45, 0.5};

double
epsilon[NTGTPRECV] = {0.001, 0.002, 0.003, 0.004,
		      0.005,  0.010, 0.015, 0.020, 0.025,
		      0.030,  0.035, 0.040, 0.045, 0.050};
double
midgameparms[MAXSRCPKTS+1][NPERS][NROUNDS][NTGTPRECV];

double
endgameparms[MAXSRCPKTS+1][NPERS][NROUNDS][NTGTPRECV]; 

int
main (int argc, char**argv)
{
  int    max_block_length = 40;
  double mgprecv[]        = {0.0,
			     0.01,0.02, 0.04, 0.06, 0.08,
			     0.1, 0.12, 0.14, 0.16, 0.18,		     
			     0.2, 0.22, 0.24, 0.26, 0.28,		     
			     0.3, 0.32, 0.34, 0.36, 0.38,		     
			     0.4, 0.42, 0.44, 0.46, 0.48,		     
			     0.5, 0.52, 0.54, 0.56, 0.58,		     
			     0.6, 0.62, 0.64, 0.66, 0.68,
			     0.7, 0.72, 0.74, 0.76, 0.78,
			     0.8, 0.82, 0.84, 0.86, 0.88,
			     0.9, 0.92, 0.94, 0.96, 0.98};
  
  double effList[sizeof(mgprecv)/sizeof(double)];
  double mgpList[sizeof(mgprecv)/sizeof(double)];
  double egpList[sizeof(mgprecv)/sizeof(double)];
  int    nInList;
  
  double tgtPrecv         = 0.0;
  int    dof_to_send      = 0;
  int    maxRounds        = 20;   // Shouldn't need more than these to finish

  int    ***dof_lut_midgame = NULL;
  int    ***dof_lut_endgame = NULL;
  double ***state_prob     = NULL;

  double pktPrecv          = 0.0;
  double avgUsablePktsRcvd = 0.0;
  double avgPktsRcvd       = 0.0;
	      
// Clear our results arrays
  
  memset(&midgameparms[0][0][0][0],0,
	 (MAXSRCPKTS+1)*NPERS*NROUNDS*NTGTPRECV*sizeof(double));
  
  memset(&endgameparms[0][0][0][0],0,
	 (MAXSRCPKTS+1)*NPERS*NROUNDS*NTGTPRECV*sizeof(double));

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
  
  // The following table is used to compute prob of success at each round
  
  if ((state_prob = (double ***)Calloc3D
       ((maxRounds+1),UPSCALE*MAXSRCPKTS,
	UPSCALE*MAXSRCPKTS,sizeof(double))) == NULL)
  {
    printf("Memory allocation failure\n");
    exit (-1);
  }

  for (int currNumSrcPkts = 1; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
  {
    for (int perindex=0; perindex<NPERS; perindex++)
    {
      double per = pervals[perindex];
      
      for (int nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	for (int pr=0; pr<NTGTPRECV; pr++)
	{
	  tgtPrecv = 1.0 - epsilon[pr];
	  
	  // Reset our results tracking arrays
	  
	  memset(&effList[0],0,sizeof(effList));
	  memset(&mgpList[0],0,sizeof(mgpList));
	  memset(&egpList[0],0,sizeof(egpList));
	  nInList = 0;

	  double bestEff  = 0.0;
	  double corrEps  = 0.0;
	  int    corrMode = 0;
	  double corrTgt  = 0.0;
	  double corrPrcv = 0.0;
	  int    corrDof  = 0;
	  int    corrK    = 0;
	  double corrEGP  = 0.0;
	  
	  double corrFirstRoundPs = 0.0;
	  
	  for (int mgindex=0; mgindex<51; mgindex++)
	  {
	    double first_round_ps = 0;
	    double midgamePrecv = mgprecv[mgindex];
	    double endgamePrecv;
	    
	    //printf("\n==============================\n");
	    //printf("per is %f\n",per);
	    //printf("midgamePrecv is %f\n",midgamePrecv);
	    
	    // Determine what pure systematic FEC requires    
	    calculate_systematic_fec_dof_to_send (max_block_length, per,
						  tgtPrecv, currNumSrcPkts,
						  dof_to_send);
	    // printf("Number of FEC packets required for 1 round is: %d\n",
	    //        dof_to_send - currNumSrcPkts);
	    
	    // printf("   Pure FEC channel Efficiency is %2.5f "
	    //        "using %d fec pkts\n",
	    //	   (double)(currNumSrcPkts)/(double)(dof_to_send),
	    //	   dof_to_send - currNumSrcPkts);
	    
	    // Determine how many rounds would be needed if we use pure ARQ
	    int    arqCutover = 1;
	    double testPloss  = per;
	    while (testPloss > (1 - tgtPrecv))
	    {
	      testPloss  *= per;
	      arqCutover ++;
	    }
	    
	    // printf("ARQ cutover occurs at %d rounds\n",arqCutover);
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
	    
	    // Initialize the lookup tables to zero
	    
	    memset(&dof_lut_midgame[0][0][0],0,
		   (MAXSRCPKTS+1)*MAXSRCPKTS*MAXSRCPKTS*sizeof(int));
	    memset(&dof_lut_endgame[0][0][0],0,
		   (MAXSRCPKTS+1)*MAXSRCPKTS*MAXSRCPKTS*sizeof(int));
	    
	    int    bestK   = 0;
	    double bestEGP = 0.0;
	    double predEps = 0.0;
	    double predEff = 0.0;
	    
	    if (nRounds >= arqCutover)
	    {
	      for (int i=0; i<currNumSrcPkts; i++)
	      {
		for (int j=0; j<currNumSrcPkts-i; j++)
		{
		  dof_lut_midgame[currNumSrcPkts][i][j] = currNumSrcPkts - i;
		  dof_lut_endgame[currNumSrcPkts][i][j] = currNumSrcPkts - i;
		}
	      }
	      
	      // Initialize the state probability table to zero
	      
	      memset(&state_prob[0][0][0],0,
		     (maxRounds+1)*UPSCALE*MAXSRCPKTS*UPSCALE*MAXSRCPKTS*
		     sizeof(double));
	      
	      // Now assign a probability mass of 1 to the
	      // "nothing has been received" position at [0][0] for round 0
	      
	      state_prob[0][0][0] = 1.0;
	      
	      // Apply the lookup table to the state probabilities
	      // nRound-1 times to calculate the probability of success after
	      // nRounds -1 rounds
	      
	      // printf("   Prob of success sequence:\n");
	      
	      double prob_success = 0.0;
	      for (int i=0; i<nRounds-1; i++)
	      {
		prob_success += propagate_probabilities
		  (state_prob[i], dof_lut_midgame[currNumSrcPkts],
		   state_prob[i+1], per, currNumSrcPkts);
		
		if (i == 0)
		{
		  first_round_ps = prob_success;
		}
	      }
	      prob_success += propagate_probabilities
		(state_prob[nRounds-1], dof_lut_endgame[currNumSrcPkts],
		 state_prob[nRounds], per, currNumSrcPkts);
	      
	      // Calculate performance statistics
	      
	      // Calculate the average number of usable pkts received
	      // under systematic coding rules
	      
	      avgUsablePktsRcvd = 0.0;

	      // First the contributions for all states that have
	      // currNumSrcPkts or more packets
	      
	      for (int i=0; i<UPSCALE*currNumSrcPkts; i++)
	      {
		double rowMass = 0.0;
		int lowerlimit = (i <= currNumSrcPkts ? currNumSrcPkts - i : 0);
		for (int j=lowerlimit; j<UPSCALE*currNumSrcPkts; j++)
		{
		  rowMass += state_prob[nRounds][i][j];
		}
		avgUsablePktsRcvd +=currNumSrcPkts * rowMass;
	      }
	      
	      // Now add in contributions from systematic part of the table 
	      for (int i=0; i<currNumSrcPkts; i++)
	      {
		double rowMass = 0.0;
		for (int j=0; j<currNumSrcPkts-i; j++)
		{
		  rowMass += state_prob[nRounds][i][j];
		}
		avgUsablePktsRcvd += (double)(i) * rowMass;
	      }
	      pktPrecv = avgUsablePktsRcvd / (double)currNumSrcPkts;
	      
	      // Calculate the average number of pkts received
	      
	      avgPktsRcvd = 0.0;
	      for (int i=0; i<UPSCALE*currNumSrcPkts; i++)
	      {
		double rowMass = 0.0;
		for (int j=0; j<UPSCALE*currNumSrcPkts; j++)
		{
		  avgPktsRcvd += (double)(i + j) * state_prob[nRounds][i][j];
		}
	      }
	      
	      predEps = 1.0 - pktPrecv;
	      predEff = avgUsablePktsRcvd / avgPktsRcvd;
	      bestK   = 0;
	      bestEGP = pktPrecv;

	      effList[0] = predEff;
	      mgpList[0] = 0.0;
	      egpList[0] = bestEGP;
	      nInList++;
	    }
	    else
	    {
	      if (midgamePrecv < 0.01)
	      {
		for (int i=0; i<currNumSrcPkts; i++)
		{
		  for (int j=0; j<currNumSrcPkts-i; j++)
		  {
		    dof_lut_midgame[currNumSrcPkts][i][j] = currNumSrcPkts - i;
		  }
		}
	      }
	      else
	      {
		for (int nRcvd=0; nRcvd<currNumSrcPkts; nRcvd++)
		{
		  for (int kRcvd=0; kRcvd<currNumSrcPkts-nRcvd; kRcvd++)
		  {
		    calculate_conditional_simple_fec_dof_to_send
		      (max_block_length, per, midgamePrecv,
		       currNumSrcPkts, nRcvd, kRcvd,
		       dof_lut_midgame[currNumSrcPkts][nRcvd][kRcvd]);
		  }
		}
	      }
	      
	      // Initialize the state probability table to zero
	      
	      memset(&state_prob[0][0][0],0,
		     (maxRounds+1)*UPSCALE*MAXSRCPKTS*UPSCALE*MAXSRCPKTS*
		     sizeof(double));
	      
	      // Now assign a probability mass of one to the "nothing has been
	      // received" position at [0][0] for round 0
	      
	      state_prob[0][0][0] = 1.0;
	      
	      // Apply the midgame table to the current state nRound-1 times
	      // to calculate the probability of success after nRounds -1
	      // rounds
	      
	      double prob_success = 0.0;
	      
	      for (int i=0; i<nRounds-1; i++)
	      {
		prob_success += propagate_probabilities
		  (state_prob[i], dof_lut_midgame[currNumSrcPkts],
		   state_prob[i+1], per, currNumSrcPkts);
		
		if (i==0)
		{
		  first_round_ps = prob_success;
		}
	      }
	      
	      // Determine what we need to do at each endgame state to reach
	      // the tgtPrecv
	      
	      double baseEndgamePrecv;
	      if (tgtPrecv < prob_success)
	      {
		// printf("   prob_success is already greater than tgtPrecv\n");
		baseEndgamePrecv = 0.1;
	      }
	      else
	      {
		baseEndgamePrecv = (tgtPrecv - prob_success) /
		  (1 - prob_success);
	      }
	      
	      // printf("       baseEndGamePrecv is %1.4f\n",baseEndgamePrecv);
	      
	      bestK   = 0;
	      bestEGP = 0.0;
	      predEps = 1.0;
	      predEff = 0.0;
	    
	      for (int kkk=0; kkk<20; kkk++)
	      {
		memset(&state_prob[nRounds][0][0],0,
		       UPSCALE*MAXSRCPKTS*UPSCALE*MAXSRCPKTS*sizeof(double));
		
		double endgamePrecv = baseEndgamePrecv *
		  (1.0 - 0.005 * (double)kkk);
		
		for (int nRcvd=0; nRcvd<currNumSrcPkts; nRcvd++)
		{
		  for (int kRcvd=0; kRcvd<currNumSrcPkts-nRcvd; kRcvd++)
		  {
		    calculate_conditional_systematic_fec_dof_to_send
		      (max_block_length, per, endgamePrecv,
		       currNumSrcPkts, nRcvd, kRcvd,
		       dof_lut_endgame[currNumSrcPkts][nRcvd][kRcvd]);
		  }
		}

		//printf("endgamePrecv is %f, dof to send is %d\n",
		//       endgamePrecv,
		//       dof_lut_endgame[currNumSrcPkts][0][0]);
		       
		double ps = propagate_probabilities
		  (state_prob[nRounds-1], dof_lut_endgame[currNumSrcPkts],
		   state_prob[nRounds], per, currNumSrcPkts);

		// printf("Prob success is %f\n",ps);

		double totalMass = 0.0;
		for (int i=0; i<UPSCALE*currNumSrcPkts; i++)
		{
		  for (int j=0; j<UPSCALE*currNumSrcPkts; j++)
		  {
		    totalMass += state_prob[nRounds][i][j];
		  }
		}
		
		// printf("Total mass is %f\n",totalMass);
		
		// Calculate performance statistics
		
		// Calculate the average number of usable pkts received
		// under systematic coding rules
		
		double avgUsablePktsRcvd = 0.0;
		
		// First the contributions for all states that have
		// currNumSrcPkts or more packets
		
		for (int i=0; i<UPSCALE*currNumSrcPkts; i++)
		{
		  double rowMass = 0.0;
		  int lowerlimit = (i <= currNumSrcPkts ? currNumSrcPkts - i :
				    0);
		  for (int j=lowerlimit; j<UPSCALE*currNumSrcPkts; j++)
		  {
		    rowMass += state_prob[nRounds][i][j];
		  }
		  avgUsablePktsRcvd += currNumSrcPkts * rowMass;
		}
		
		// Now add in contributions from systematic part of the table 
		for (int i=0; i<currNumSrcPkts; i++)
		{
		  double rowMass = 0.0;
		  for (int j=0; j<currNumSrcPkts-i; j++)
		  {
		    rowMass += state_prob[nRounds][i][j];
		  }
		  avgUsablePktsRcvd += (double)(i) * rowMass;
		}
		double pktPrecv = avgUsablePktsRcvd / (double)currNumSrcPkts;

		// Calculate the average number of pkts received
		
		double avgPktsRcvd = 0.0;
		for (int i=0; i<UPSCALE*currNumSrcPkts; i++)
		{
		  double rowMass = 0.0;
		  for (int j=0; j<UPSCALE*currNumSrcPkts; j++)
		  {
		    avgPktsRcvd += (double)(i + j) * state_prob[nRounds][i][j];
		  }
		}
		
		double testEps = 1.0 - pktPrecv;
		double testEff = avgUsablePktsRcvd / avgPktsRcvd;
		
		// If no longer meeting delivery requirements: break	      
		if (testEps > (1.0 - tgtPrecv)) 
		{
		  break;
		}
		else
		{
		  if (testEff > predEff)
		  {
		    bestK   = kkk;
		    bestEGP = endgamePrecv;
		    predEps = testEps;
		    predEff = testEff;
		  }
		  else
		  {
		    //printf("Efficiency trajectory hiccup\n");
		  }		  
		}
		// printf("Packet Precv using a systematic code: %1.4f "
		//        "(epsilon is %1.4f)\n",
		//        pktPrecv,1.0-pktPrecv);
		// printf("Theoretical efficiency (AvgUsablePktsRcvd / "
		//        "AvgPktsRcvd) = %1.4f\n",
	        //       avgUsablePktsRcvd / avgPktsRcvd);
	      }
	    }

	    
	    // printf("   %f %d %f %f %f %d %d %d %f %f %d\n",
	    //  	 per, nRounds,1.0 - tgtPrecv,
	    //  	 predEps,predEff,
	    //  	 predEps < 1.0 - tgtPrecv ? 1 : 0,
	    //  	 mode,
	    //  	 nRounds == 1 ?
	    // 	 dof_lut_endgame[currNumSrcPkts][0][0] :
	    // 	 dof_lut_midgame[currNumSrcPkts][0][0],
	    //	 midgamePrecv,first_round_ps,bestK);

	    if (nInList == 0)
	    {
	      effList[0] = predEff;
	      mgpList[0] = nRounds == 1 ? bestEGP : midgamePrecv;
	      egpList[0] = bestEGP;
	      nInList++;
	    }
	    else
	    {
	      // See if this efficiency value is already in the list, in which
	      // case simply skip
	      
	      int found = 0;
	      for (int i=0; i<nInList; i++)
	      {
		if (predEff == effList[i])
		{
		  found = 1;
		  break;
		}
	      }

	      // If not already in the list, insert
	      if (!found)
	      {
		// Tack this on at the tail
		effList[nInList] = predEff;
		mgpList[nInList] = nRounds == 1 ? bestEGP : midgamePrecv;
		egpList[nInList] = bestEGP;
		nInList++;

		// Now bubble sort this up
		for (int i=nInList-1; i>0; i--)
		{
		  if (effList[i] > effList[i-1])
		  {
		    double tmp;
		    
		    tmp          = effList[i];
		    effList[i]   = effList[i-1];
		    effList[i-1] = tmp;

		    tmp          = mgpList[i];
		    mgpList[i]   = mgpList[i-1];
		    mgpList[i-1] = tmp;

		    tmp          = egpList[i];
		    egpList[i]   = egpList[i-1];
		    egpList[i-1] = tmp;
		  }
		}
	      }
	    }
	    
	    if (predEff > bestEff)
	    {
	      bestEff  = predEff;
	      corrEps  = predEps;
	      corrMode = mode;
	      corrDof  = 	nRounds == 1 ?
		dof_lut_endgame[currNumSrcPkts][0][0] :
		dof_lut_midgame[currNumSrcPkts][0][0];
	      corrTgt  = nRounds == 1 ? bestEGP : midgamePrecv;
	      corrFirstRoundPs = first_round_ps;
	      corrK    = bestK;
	      corrEGP  = bestEGP;
	    }
	  }
	  if (dumpsearchvals)
	  {
	    printf("%f %d %f %f %f %d %d %d %f %f %d %f\n",
		   per, nRounds,1.0 - tgtPrecv,
		   corrEps,bestEff,corrEps < 1.0 - tgtPrecv ? 1 : 0,
		   corrMode,corrDof,corrTgt,corrFirstRoundPs,corrK,corrEGP);
	  }

	  if ((bestEff != effList[0]) || (corrTgt != mgpList[0]) ||
	      (corrEGP != egpList[0]))
	  {
	    printf("Comparing: %f vs %f; %f vs %f, %f vs %f (mode %d)\n",
		   bestEff,effList[0],corrTgt,mgpList[0],corrEGP,
		   egpList[0],corrMode);
	    
	    printf("   Dumping list\n");
	    for (int i=0; i<nInList; i++)
	    {
	      printf("   %d: %f %f %f\n",i,effList[i],mgpList[i],egpList[i]);
	    }
	  }

	  // Test code to pick the second best value
	  // if ((nInList > 1) && (corrMode == 2))
	  // {
	  //  if ((currNumSrcPkts == 4) && (per == 0.1) && (nRounds == 2) &&
	  //	(tgtPrecv == 0.995))
	  //  {
	  //    printf("Picking 2nd choice for nSrc %d per %f nRnds %d "
	  //           "tgtPrecv %f\n",currNumSrcPkts,per,nRounds,tgtPrecv);
	  //    printf("   From: %f,%f to %f,%f\n",corrTgt,corrEGP,
	  //	     mgpList[1],egpList[1]);
	  //  }
	  //  corrTgt = mgpList[1];
	  //  corrEGP = egpList[1];
	  // }
	  
	  midgameparms[currNumSrcPkts][perindex][nRounds-1][pr] = corrTgt; 
	  endgameparms[currNumSrcPkts][perindex][nRounds-1][pr] = corrEGP;
	}
      }
    }
  }

  // Dump the tables
  printf("#define MAXSRCPKTS %d\n",MAXSRCPKTS);
  printf("#define NPERS %d\n",NPERS);
  printf("#define NROUNDS %d\n",NROUNDS);
  printf("#define NTGTPRECV %d\n",NTGTPRECV);
  printf("\n");

  printf("static double\npervals[NPERS] = \n{");
  for (int perindex=0; perindex<NPERS; perindex++)
  {
    printf("%1.3f",pervals[perindex]);
    if (perindex != NPERS-1)
    {
      printf(",");
    }
    if (perindex%5 == 4)
    {
      printf("\n ");
    }
  }
  printf("};\n\n");
  
  printf("static double\nepsilon[NTGTPRECV] = \n{");
  for (int pr=0; pr<NTGTPRECV; pr++)
  {
    printf("%1.3f",epsilon[pr]);
    if (pr != NTGTPRECV-1)
    {
      printf(",");
    }
    if (pr%5 == 4)
    {
      printf("\n ");
    }
  }
  printf("};\n\n");

  printf("static double\nmidgameparms[MAXSRCPKTS+1][NPERS]"
	 "[NROUNDS][NTGTPRECV] =\n");
  printf("{\n");
  for (int currNumSrcPkts=0; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
  {
    printf("  {\n");
    for (int perindex=0; perindex<NPERS; perindex++)
    {
      printf("    {\n");
      for (int nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	printf("      {");
	for (int pr=0; pr<NTGTPRECV/2; pr++)
	{
	  printf("%f,",midgameparms[currNumSrcPkts][perindex][nRounds-1][pr]);
	}
	printf("\n       ");
	for (int pr=NTGTPRECV/2; pr<NTGTPRECV-1; pr++)
	{
	  printf("%f,",midgameparms[currNumSrcPkts][perindex][nRounds-1][pr]);
	}
	printf("%f}",
	       midgameparms[currNumSrcPkts][perindex][nRounds-1][NTGTPRECV-1]);
	if (nRounds != NROUNDS)
	{
	  printf(",");
	}
	printf("\n");
      }
      printf("    }");
      if (perindex != NPERS-1)
      {
	printf(",");
      }
      printf("\n");
    }
    printf("  }");
    if (currNumSrcPkts != MAXSRCPKTS)
    {
      printf(",");
    }
    printf("\n");
  }
  printf("};\n");
  
  printf("\n");
  printf("static double\nendgameparms[MAXSRCPKTS+1][NPERS]"
	 "[NROUNDS][NTGTPRECV] =\n");
  printf("{\n");
  for (int currNumSrcPkts=0; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
  {
    printf("  {\n");
    for (int perindex=0; perindex<NPERS; perindex++)
    {
      printf("    {\n");
      for (int nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	printf("      {");
	for (int pr=0; pr<NTGTPRECV/2; pr++)
	{
	  printf("%f,",endgameparms[currNumSrcPkts][perindex][nRounds-1][pr]);
	}
	printf("\n       ");
	for (int pr=NTGTPRECV/2; pr<NTGTPRECV-1; pr++)
	{
	  printf("%f,",endgameparms[currNumSrcPkts][perindex][nRounds-1][pr]);
	}
	printf("%f}",
	       endgameparms[currNumSrcPkts][perindex][nRounds-1][NTGTPRECV-1]);
	if (nRounds != NROUNDS)
	{
	  printf(",");
	}
	printf("\n");
      }
      printf("    }");
      if (perindex != NPERS-1)
      {
	printf(",");
      }
      printf("\n");
    }
    printf("  }");
    if (currNumSrcPkts != MAXSRCPKTS)
    {
      printf(",");
    }
    printf("\n");
  }
  printf("};\n");

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

  if (state_prob != NULL)
  {
    free(state_prob);
    state_prob = NULL;
  }

}
	      
