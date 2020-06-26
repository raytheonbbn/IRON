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
//#include "altdoflutparms.h"

int
setup_dof_lookup_tables(double    per,
			int       nRounds,
			double    tgtPrecv,
			int       maxSrcPkts,
			int    ***dof_lut_midgame,
			int    ***dof_lut_endgame)
{
  if (maxSrcPkts != MAXSRCPKTS)
  {
    return -1;
  }
  
  int max_block_length = 40;

  // Determine how many rounds would be needed if we use pure ARQ
  int    arqCutover = 1;
  double testPloss  = per;
  while (testPloss > (1 - tgtPrecv))
  {
    testPloss  *= per;
    arqCutover ++;
  }

  // Clear the lookup tables
  
  memset(&dof_lut_midgame[0][0][0],0,
	 MAXSRCPKTS*MAXSRCPKTS*MAXSRCPKTS*sizeof(int));
  memset(&dof_lut_endgame[0][0][0],0,
	 MAXSRCPKTS*MAXSRCPKTS*MAXSRCPKTS*sizeof(int));
  
  if (nRounds >= arqCutover)
  {
    for(int currNumSrcPkts=1; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
    {
      for (int j=0; j<currNumSrcPkts; j++)
      {
	for (int k=0; k<currNumSrcPkts-j; k++)
	{
	  dof_lut_midgame[currNumSrcPkts][j][k] = currNumSrcPkts - j;
	  dof_lut_endgame[currNumSrcPkts][j][k] = currNumSrcPkts - j;
	}
      }
    }
  }
  else
  {
    int perindex = NPERS - 1;
    for (int i=0; i<NPERS; i++)
    {
      if (pervals[i] >= per)
      {
	perindex = i;
	break;
      }
    }

    int pr = NTGTPRECV - 1;
    for (int i=0; i<NTGTPRECV; i++)
    {
      if (tgtPrecv >= 1.0 - epsilon[i])
      {
	pr = i;
	break;
      }
    }

    for(int currNumSrcPkts=1; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
    {
    
      double midgamePrecv =
	midgameparms[currNumSrcPkts][perindex][nRounds-1][pr];
    
      // A midgamePrecv value of 0 signals that we should use an
      // ARQ-like midgame LUT
      
      if (midgamePrecv < 0.001)
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
      
      double endgamePrecv = endgameparms[currNumSrcPkts][perindex][nRounds-1][pr];
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
    }
  }
  
  return 0;
}
