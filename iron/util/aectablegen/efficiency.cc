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

double CalculateEfficiency(double per, double tgtPrecv, int nRounds,
                           int nSrcPkts);

static const int  PRINT_HEADER_FILE = 1;

int
main (int argc, char**argv)
{
  int      eps_idx  = 0;
  int      per_idx  = 0;
  int      n        = 0;
  int      k        = 0;
  double   per      = 0.0;
  double   tgtPrecv = 0.0;
  double   eff      = 0.0;

  if (PRINT_HEADER_FILE)
  {

    printf("// Indices: [Epsilon][PER][N][k]\n");
    printf("const uint8_t  kEfficiency[%d][%d][%d][%d] = {\n",
           NTGTPRECV, NPERS, NROUNDS, MAXSRCPKTS);
    for (eps_idx = 0; eps_idx < NTGTPRECV; eps_idx++)
    {
      tgtPrecv = (1.0 - epsilon[eps_idx]);
      printf("  {\n");
      for (per_idx = 0; per_idx < NPERS; per_idx++)
      {
        per = pervals[per_idx];
        printf("    {\n");
        for (n = 1; n <= NROUNDS; n++)
        {
          printf("      {");
          for (k = 1; k <= MAXSRCPKTS; k++)
          {
            eff = CalculateEfficiency(per, tgtPrecv, n, k);
            printf("%d%s", (int)((eff * 255.0) + 0.5),
                   ((k < MAXSRCPKTS) ? "," : ""));
          }
          printf("}%s\n", ((n < NROUNDS) ? "," : ""));
        }
        printf("    }%s\n", ((per_idx < (NPERS - 1)) ? "," : ""));
      }
      printf("  }%s\n", ((eps_idx < (NTGTPRECV - 1)) ? "," : ""));
    }
    printf("};\n");

  }
  else
  {

    for (eps_idx = 0; eps_idx < NTGTPRECV; eps_idx++)
    {
      tgtPrecv = (1.0 - epsilon[eps_idx]);
      for (per_idx = 0; per_idx < NPERS; per_idx++)
      {
        per = pervals[per_idx];
        for (n = 1; n <= NROUNDS; n++)
        {
          for (k = 1; k <= MAXSRCPKTS; k++)
          {
            eff = CalculateEfficiency(per, tgtPrecv, n, k);
            printf("Epsilon=%f PER=%f N=%d k=%d : eff=%f qe=%d\n",
                   epsilon[eps_idx], per, n, k, eff,
                   (int)((eff * 255.0) + 0.5));
          }
        }
      }
    }

  }

  return 0;
}

double CalculateEfficiency(double per, double tgtPrecv, int nRounds,
                           int nSrcPkts)
{
  int     ***dof_lut_midgame = NULL;
  int     ***dof_lut_endgame = NULL;
  double  ***state_prob      = NULL;

  // Make sure we're in bounds for the table lookups.
  if (nSrcPkts > MAXSRCPKTS)
  {
    nSrcPkts = MAXSRCPKTS;
  }

  // This lut is used for all but the last round and is indexed as nRcvd,
  // kRcvd.
  if ((dof_lut_midgame = (int ***)
       Calloc3D(MAXSRCPKTS+1,MAXSRCPKTS,MAXSRCPKTS,sizeof(int))) == NULL)
  {
    printf("Memory allocation failure\n");
    exit(-1);
  }

  // This lut is used for the very last round and is also indexed as nRcvd,
  // kRcvd.
  if ((dof_lut_endgame = (int ***)
       Calloc3D(MAXSRCPKTS+1,MAXSRCPKTS,MAXSRCPKTS,sizeof(int))) == NULL)
  {
    printf("Memory allocation failure\n");
    free(dof_lut_midgame);
    exit(-1);
  }

  // The following block is only for informational purposes Determine how many
  // rounds would be needed if we use pure ARQ.
  int     arqCutover = 1;
  double  testPloss  = per;

  while (testPloss > (1 - tgtPrecv))
  {
    testPloss  *= per;
    arqCutover ++;
  }

  int  mode = 0;

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

  setup_dof_lookup_tables(per, nRounds, tgtPrecv, MAXSRCPKTS, dof_lut_midgame,
                          dof_lut_endgame);

  // Now calculate the theroetical efficiency with this table.  The following
  // table is used to compute prob of success at each round.  Shouldn't need
  // more than MAXROUNDS to finish.
#define MAXROUNDS 20

  if ((state_prob = (double ***)Calloc3D
       ((MAXROUNDS + 1), (UPSCALE * nSrcPkts), (UPSCALE * nSrcPkts),
        sizeof(double))) == NULL)
  {
    printf("Memory allocation failure\n");
    free(dof_lut_midgame);
    free(dof_lut_endgame);
    exit(-1);
  }

  // Initialize the state probability table to zero.
  memset(&state_prob[0][0][0],0,
	 (MAXROUNDS+1)*UPSCALE*nSrcPkts*UPSCALE*nSrcPkts*sizeof(double));

  // Now assign a probability mass of one to the "nothing has been received"
  // position at [0][0] for round 0.
  state_prob[0][0][0] = 1.0;

  // Apply the midgame table to the starting state nRound-1 times to calculate
  // the penultimate state probabilities.
  double  prob_success = 0.0;

  for (int i = 0; i < (nRounds - 1); i++)
  {
    prob_success += propagate_probabilities
      (state_prob[i], dof_lut_midgame[nSrcPkts], state_prob[i+1], per,
       nSrcPkts);
  }

  double  residual_error = 0.0;

  for (int nRcvd = 0; nRcvd < nSrcPkts; nRcvd++)
  {
    for (int kRcvd = 0; kRcvd < (nSrcPkts - nRcvd); kRcvd++)
    {
      residual_error += state_prob[nRounds-1][nRcvd][kRcvd];
    }
  }

  // Calculate the final state probabilities based on the endgame LUT.
  prob_success += propagate_probabilities
    (state_prob[nRounds - 1], dof_lut_endgame[nSrcPkts], state_prob[nRounds],
     per, nSrcPkts);

  residual_error = 0.0;

  for (int nRcvd = 0; nRcvd < nSrcPkts; nRcvd++)
  {
    for (int kRcvd = 0; kRcvd < (nSrcPkts - nRcvd); kRcvd++)
    {
      residual_error += state_prob[nRounds][nRcvd][kRcvd];
    }
  }

  // Find a reasonable upper limit on the number of rows to print out.
  int rowlimit = nSrcPkts;

  for (int nRcvd = ((UPSCALE * nSrcPkts) - 1); nRcvd >= 0; nRcvd--)
  {
    double  rowmass = 0.0;

    for (int kRcvd = 0; kRcvd < (UPSCALE * nSrcPkts); kRcvd++)
    {
      rowmass += state_prob[nRounds][nRcvd][kRcvd];
    }

    if (rowmass > 0.00001)
    {
      // Found the first row with non-trivial probability mass.
      rowlimit = nRcvd;
      break;
    }
  }

  // Find a reasonable upper limit on the number of coulumns to print out.
  int  collimit = nSrcPkts;

  for (int nRcvd = ((UPSCALE * nSrcPkts) - 1); nRcvd >= 0; nRcvd--)
  {
    double  colmass = 0.0;

    for (int kRcvd = 0; kRcvd < (UPSCALE * nSrcPkts); kRcvd++)
    {
      colmass += state_prob[nRounds][kRcvd][nRcvd];
    }

    if (colmass > 0.00001)
    {
      // Found the first col with non-trivial probability mass.
      collimit = nRcvd;
      break;
    }
  }

  // Calculate the probability of receiving a usable packet under systematic
  // coding rules.
  double  avgUsablePktsRcvd = (nSrcPkts * prob_success);
  double  pktPrecv          = (avgUsablePktsRcvd / (double)nSrcPkts);

  for (int i = 0; i < nSrcPkts; i++)
  {
    double  rowMass = 0.0;

    for (int j = 0; j < (nSrcPkts - i); j++)
    {
      rowMass += state_prob[nRounds][i][j];
    }

    avgUsablePktsRcvd += ((double)(i) * rowMass);
  }

  pktPrecv = (avgUsablePktsRcvd / (double)nSrcPkts);

  double  unusable_prob       = 0.0;
  double  avgUnusablePktsRcvd = 0.0;

  for (int nRcvd = 0; nRcvd < (UPSCALE * nSrcPkts); nRcvd++)
  {
    for (int kRcvd = 0; kRcvd < (UPSCALE * nSrcPkts); kRcvd++)
    {
      double  prob = state_prob[nRounds][nRcvd][kRcvd];

      // Case 1: > nSrcPkts pkts rcvd: count excess
      if ((nRcvd + kRcvd) > nSrcPkts)
      {
	unusable_prob       += prob;
	avgUnusablePktsRcvd += (prob * (double)(nRcvd + kRcvd - nSrcPkts));
      }

      // Case 2: < nSrcPkts pkts rcvd: count FEC pkts
      if ((nRcvd + kRcvd) < nSrcPkts)
      {
	unusable_prob       += prob;
	avgUnusablePktsRcvd += (prob * (double)kRcvd);
      }
    }
  }

  // Calculate the average number of pkts received.
  double  avgPktsRcvd = 0.0;

  for (int i = 0; i < (UPSCALE * nSrcPkts); i++)
  {
    double  rowMass = 0.0;

    for (int j = 0; j < (UPSCALE * nSrcPkts); j++)
    {
      avgPktsRcvd += ((double)(i + j) * state_prob[nRounds][i][j]);
    }
  }

  // Calculate the theoretical efficiency.
  double  efficiency = (avgUsablePktsRcvd / avgPktsRcvd);

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

  return efficiency;
}