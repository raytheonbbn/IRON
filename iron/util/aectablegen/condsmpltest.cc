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

int isrcvd(double actualper);

#define origBlkSz 10
#define maxBlkSz  40

int
main (int argc, char**argv)
{
  double pervals[] = {0.1, 0.2, 0.3, 0.4, 0.5};
  double epsilon[] = {0.005, 0.010, 0.015, 0.020, 0.025,
		      0.030, 0.035, 0.040, 0.045, 0.050};
  double maxabsdiff = 0.0;
  
  double per;
  double tgtPrecv;
  int    nTrials  = 100000; // Number of trials used to evaluate algorithm

  for (int perindex=0; perindex<5; perindex++)
  {
    double per = pervals[perindex];

    for (int pr=0; pr<10; pr++)
    {
      tgtPrecv = 1.0 - epsilon[pr];
      
      int dts;
      calculate_conditional_simple_fec_dof_to_send (maxBlkSz, per,
						    tgtPrecv,origBlkSz,
						    0, 0, dts);

      int N = origBlkSz;
      int K = dts - origBlkSz;
      double firstRoundPs = compute_simple_fec_ps(N, K, per);
      
      printf("\n************** per: %f tgtPrecv: %f\n",per,tgtPrecv); 
      for (int nRcvd=0; nRcvd<origBlkSz; nRcvd++)
      {
	for (int kRcvd=0; kRcvd<origBlkSz-nRcvd; kRcvd++)
	{
	  int dof_to_send = 0;
	  double ps = calculate_conditional_simple_fec_dof_to_send
	    (maxBlkSz, per, tgtPrecv, origBlkSz, nRcvd, kRcvd, dof_to_send);
	  int src_to_send = 0;
	  int fec_to_send = 0;
	  
	  if (dof_to_send < (origBlkSz - nRcvd))
	  {
	    src_to_send = dof_to_send;
	    fec_to_send = 0;
	  }
	  else
	  {
	    src_to_send = origBlkSz   - nRcvd;
	    fec_to_send = dof_to_send - src_to_send;
	  }
	  
	  int successfulTrials = 0;
	  int tot_rcvd         = 0;
	  int tot_src_rcvd     = 0;
	  int tot_expected     = 0;
	  
	  for (int trial = 0; trial<nTrials; trial++)
	  {
	    int src_rcvd = nRcvd;
	    int fec_rcvd = kRcvd;
	    
	    for (int i=0; i<src_to_send; i++)
	    {
	      src_rcvd += isrcvd(per); // Models ACK/NACK from receiver
	    }
	    
	    for (int i=0; i<fec_to_send; i++)
	    {
	      fec_rcvd += isrcvd(per); // Models ACK/NACK from receiver
	    }
	    
	    tot_rcvd = src_rcvd + fec_rcvd;
	    
	    if (tot_rcvd >= origBlkSz)
	    {
	      tot_src_rcvd += origBlkSz;
	      successfulTrials ++;
	    }
	    
	    tot_expected += origBlkSz;
	  }
	  
	  double expps = (double)tot_src_rcvd/(double)tot_expected;
	  double absdiff = fabs(expps - ps) / ps;
	  if (absdiff > maxabsdiff)
	  {
	    maxabsdiff = absdiff;
	  }
	  printf("(%2d %2d) sending %2d: success rate is %f (theoretical is %f)\n",
		 nRcvd,kRcvd,dof_to_send,
		 (double)tot_src_rcvd/(double)tot_expected,ps);
	  printf("   composite: %f (frps: %f)\n",
		 firstRoundPs + (1 - firstRoundPs)*ps,firstRoundPs); 
	}
      }
    }
  }
  printf("Largest absolute difference is: %f percent\n",100.0*maxabsdiff);
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
	      
