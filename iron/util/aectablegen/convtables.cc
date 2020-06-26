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
#include <stdint.h>

#include "CalculateFECRate.h"
#include "CallocND.h"

#include "setupDofLookupTables.h"
#include "doflutparms.h"

uint8_t
midgametbl[MAXSRCPKTS][NPERS][NROUNDS][NTGTPRECV][MAXSRCPKTS][MAXSRCPKTS];

uint8_t
endgametbl[MAXSRCPKTS][NPERS][NROUNDS][NTGTPRECV][MAXSRCPKTS][MAXSRCPKTS]; 

int
main (int argc, char**argv)
{
  // Clear our results arrays
  
  memset(&midgametbl[0][0][0][0][0][0],0,
	 MAXSRCPKTS*NPERS*NROUNDS*NTGTPRECV*MAXSRCPKTS*
	 MAXSRCPKTS*sizeof(uint8_t));
  
  memset(&endgametbl[0][0][0][0][0][0],0,
	 MAXSRCPKTS*NPERS*NROUNDS*NTGTPRECV*MAXSRCPKTS*
	 MAXSRCPKTS*sizeof(uint8_t));

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

  for (int currNumSrcPkts = 1; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
  {
    for (int perindex=0; perindex<NPERS; perindex++)
    {
      double per = pervals[perindex];
      
      for (int nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	
	for (int pr=0; pr<NTGTPRECV; pr++)
	{
	  double tgtPrecv = 1.0 - epsilon[pr];
	  
	  setup_dof_lookup_tables(per, nRounds, tgtPrecv,
				  MAXSRCPKTS, dof_lut_midgame, dof_lut_endgame);
	
	  for (int i=0; i<MAXSRCPKTS; i++)
	  {
	    for (int j=0; j<MAXSRCPKTS; j++)
	    {
	      midgametbl[currNumSrcPkts-1][perindex][nRounds-1][pr][i][j] =
		(uint8_t)dof_lut_midgame[currNumSrcPkts][i][j]; 
	      endgametbl[currNumSrcPkts-1][perindex][nRounds-1][pr][i][j] =
		(uint8_t)dof_lut_endgame[currNumSrcPkts][i][j];
	    }
	  }
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

  printf("static uint8_t\nmidgametbl[MAXSRCPKTS][NPERS][NROUNDS][NTGTPRECV][MAXSRCPKTS][MAXSRCPKTS] =\n");
  printf("{\n");
  for (int currNumSrcPkts=1; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
  {
    printf("  {\n");
    for (int perindex=0; perindex<NPERS; perindex++)
    {
      printf("    {\n");
      for (int nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	printf("      {\n");
	for (int pr=0; pr<NTGTPRECV; pr++)
	{
	  printf("        {\n");
	  for (int i=0; i<MAXSRCPKTS; i++)
	  {
	    printf("          {");
	    for (int j=0; j<MAXSRCPKTS-1; j++)
	    {
	      printf("%2d,",midgametbl[currNumSrcPkts-1][perindex][nRounds-1][pr][i][j]);
	    }
	    printf("%2d}",midgametbl[currNumSrcPkts-1][perindex][nRounds-1][pr][i][MAXSRCPKTS-1]);
	    if (i != MAXSRCPKTS-1)
	    {
	      printf(",");
	    }
	    printf("\n");
	  }
	  printf("        }");
	  if (pr != NTGTPRECV-1)
	  {
	    printf(",");
	  }
	  printf("\n");
	}
	printf("      }");
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
  printf("static uint8_t\nendgametbl[MAXSRCPKTS][NPERS][NROUNDS][NTGTPRECV][MAXSRCPKTS][MAXSRCPKTS] =\n");
  printf("{\n");
  for (int currNumSrcPkts=1; currNumSrcPkts<=MAXSRCPKTS; currNumSrcPkts++)
  {
    printf("  {\n");
    for (int perindex=0; perindex<NPERS; perindex++)
    {
      printf("    {\n");
      for (int nRounds=1; nRounds<=NROUNDS; nRounds++)
      {
	printf("      {\n");
	for (int pr=0; pr<NTGTPRECV; pr++)
	{
	  printf("        {\n");
	  for (int i=0; i<MAXSRCPKTS; i++)
	  {
	    printf("          {");
	    for (int j=0; j<MAXSRCPKTS-1; j++)
	    {
	      printf("%2d,",endgametbl[currNumSrcPkts-1][perindex][nRounds-1][pr][i][j]);
	    }
	    printf("%2d}",endgametbl[currNumSrcPkts-1][perindex][nRounds-1][pr][i][MAXSRCPKTS-1]);
	    if (i != MAXSRCPKTS-1)
	    {
	      printf(",");
	    }
	    printf("\n");
	  }
	  printf("        }");
	  if (pr != NTGTPRECV-1)
	  {
	    printf(",");
	  }
	  printf("\n");
	}
	printf("      }");
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

}
	      
