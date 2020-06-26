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
#include "CalculateFECRate.h"

//============================================================================
double
calculate_systematic_fec_dof_to_send
	(int    max_total_pkts, 
	 double per,
	 double tgt_precv,
	 int    orig_src_pkts,
	 int&   dof_to_send)
{
  double ps; // Success probability given an FEC configuration
  int    K;
  
  if (tgt_precv >= 0.999)
  {
    tgt_precv = 0.999;
  }

  // Sanity check. If we can achieve the target rate without
  // FEC, short circuit the calculations and return

  if (tgt_precv < (1.0 - per))
  {
    dof_to_send = orig_src_pkts;
    return (1.0 - per);;
  }

  // We've already covered the K=0 (no FEC case) so start at K=1

  for (K=1; K<(max_total_pkts - orig_src_pkts); K++)
  {
    ps = compute_systematic_fec_ps(orig_src_pkts, K, per);

    if (ps >= tgt_precv)
    {
      break;
    }
  }

  dof_to_send = orig_src_pkts + K;
  
  if (ps < tgt_precv)
  {
    printf("Cannot achieve tgt receive probability with given constraints\n");
  }

  return(ps);
}

//============================================================================
double calculate_conditional_systematic_fec_dof_to_send
	(int    max_total_pkts, 
	 double per,
	 double tgt_precv,
	 int    orig_src_pkts,
	 int    src_pkts_rcvd,
	 int    fec_pkts_rcvd,
	 int&   dof_to_send)
{
  int dof_needed = orig_src_pkts - (src_pkts_rcvd + fec_pkts_rcvd);

  if (dof_needed < 1)
  {
    dof_to_send = 0;
    return (1.0);
  }
  
  if (tgt_precv >= 0.999)
  {
    tgt_precv = 0.999;
  }

  double ps; // Success probability given an FEC recv configuration

  // Start at a test value for dof_to_send of 1

  int dts=0;
  for (dts=1; dts < max_total_pkts; dts++)
  {
    ps = compute_conditional_systematic_fec_ps
      (orig_src_pkts, src_pkts_rcvd, fec_pkts_rcvd,
       dts, per);
    
    if (ps >= tgt_precv)
    {
      break;
    }
  }

  if (dts < dof_needed)
  {
    dof_to_send = dof_needed;
  }
  else
  {
    dof_to_send = dts;
  }
  
  if (ps < tgt_precv)
  {
    printf("Cannot achieve tgt receive probability with given constraints\n");
  }

  return(ps);
}

//============================================================================
double calculate_simple_fec_dof_to_send
	(int    max_total_pkts, 
	 double per,
	 double tgt_precv,
	 int    orig_src_pkts,
	 int&   dof_to_send)
{
  double ps; // Success probability given an FEC configuration
  
  if (tgt_precv >= 0.999)
  {
    tgt_precv = 0.999;
  }

  int K;
  for (K=0; K < max_total_pkts - orig_src_pkts; K++)
  {
    ps = compute_simple_fec_ps (orig_src_pkts, K, per);
    
    if (ps >= tgt_precv)
    {
      break;
    }
  }

  dof_to_send = orig_src_pkts + K;

  if (ps < tgt_precv)
  {
    printf("Cannot achieve tgt receive probability with given constraints\n");
  }

  return(ps);
}

//============================================================================
double calculate_conditional_simple_fec_dof_to_send
	(int    max_total_pkts, 
	 double per,
	 double tgt_precv,
	 int    orig_src_pkts,
	 int    orig_src_pkts_rcvd,
	 int    num_fec_pkts_rcvd,
	 int&   dof_to_send)
{
  int dof_needed = orig_src_pkts - (orig_src_pkts_rcvd + num_fec_pkts_rcvd);

  if (dof_needed < 1)
  {
    dof_to_send = 0;
    return (1.0);
  }

  double ps; // Success probability given an FEC configuration
  
  if (tgt_precv >= 0.999)
  {
    tgt_precv = 0.999;
  }

  // Start at a test value for dof_to_send of 0

  int dts;

  for (dts=1; dts < max_total_pkts - orig_src_pkts_rcvd; dts++)
  {
    ps = compute_conditional_simple_fec_ps
      (orig_src_pkts, orig_src_pkts_rcvd, num_fec_pkts_rcvd, dts,
       per);
    if (ps >= tgt_precv)
    {
      break;
    }
  }

  dof_to_send = dts;
    
  if (ps < tgt_precv)
  {
    //   printf("Cannot achieve tgt receive probability with given constraints\n");
  }

  return(ps);
}

//============================================================================
void
optimize_systematic_fec_rate
	(int    max_total_pkts, 
	 double per,
	 double tgt_precv,
	 int&   orig_src_pkts, 
	 int&   num_fec_pkts)
{
  int     N;     // Number of original packets
  int     K;     // Number of repair packets
  double  pRecv; // Target packet receive probability

  int     best_N; 
  int     best_K;

  int     backup_N;
  int     backup_K;
  double  pBest = per;

  double  ps;
  double  cur_eff;
  double  best_eff;
  
  pRecv = tgt_precv;

  if (pRecv >= 0.999)
  {
    pRecv = 0.999;
  }

  best_N   = 1;
  best_K   = 0;
  best_eff = 0.0;

  // Sanity check. If we can achieve the target rate without
  // FEC, short circuit the calculations and return

  if (pRecv < (1 - per))
  {
    orig_src_pkts = best_N;
    num_fec_pkts = best_K;

    printf("Best solution: is %d/%d code with efficiency of %2.5f\n",
	   orig_src_pkts, num_fec_pkts, (double)orig_src_pkts/(double)num_fec_pkts);
    return;
  }

  // Else setup the loops and proceed with the optimization

  backup_N = 1;
  backup_K = 0;

  pBest = 1 - per;
  
  // We've already covered the K=0 (no FEC case) so start at K=1

  for (K=1; K<max_total_pkts; K++)
  {
    for (N=1; N<=max_total_pkts-K; N++)
    {
      ps = compute_systematic_fec_ps(N, K, per);

      // printf("Computed success prob for N,K = (%d,%d): ps = %2.10f\n",N,K,ps);

      // Remember the current values of K and N if:
      //
      //   o The computed probability of success of delivering the packet
      //     is at or above the target receive probability
      //   o The computed efficiency is better than the previous computed 
      //     efficiency

      if (ps >= pRecv)
      {
	// Check the efficiency

        cur_eff = (double)N / (double)(K + N);
        
        if (cur_eff > best_eff)
        {
	  printf("  -- New best efficiency: %2.4f with %d/%d code\n",
		 cur_eff, N,N+K);

          best_N   = N;
          best_K   = K;

          best_eff = cur_eff;
        }
      }

      if (ps > pBest)
      {
        backup_N = N;
        backup_K = K;
        pBest    = ps;
      }
    }
  }

  if (pBest < pRecv)
  {
    orig_src_pkts =  N;
    num_fec_pkts =  K;

    printf("Cannot achieve tgt receive probability with given constraints\n");
    printf("Backup solution: is %d/%d code with efficiency of %2.5f\n",
	   orig_src_pkts, orig_src_pkts + num_fec_pkts,
	   (double)orig_src_pkts/(double)(orig_src_pkts + num_fec_pkts));
  }
  else
  {
    orig_src_pkts =  best_N;
    num_fec_pkts =  best_K;

    printf("Best solution: is %d/%d code with efficiency of %2.5f\n",
	   orig_src_pkts, orig_src_pkts + num_fec_pkts,
	   (double)orig_src_pkts/(double)(orig_src_pkts + num_fec_pkts));
  }
}

//============================================================================
double
compute_systematic_fec_ps(int N, int K, double per)
{
  // N is the number of source packets
  // K is the number of FEC packets
  // per is the packet error rate
  
  double sum = 0.0;

  // We are modeling a systematic code here, where we may have usable
  // source packets even if don't receieve enough total packets to
  // decode the FEC

  // Consider two cases:
  //   1st case: we receive >=N total pkts and can decode (normal FEC)
  //   2nd case: we receive  <N total pkts, some of which are src pkts

  // We compute the expected number of usable source pkts received
  // across the two cases, then divide by the number of source packets
  // to get the probability of successfully receiving a source packet
  
  // This first loop computes the probability that we receive at least 
  // N packets out of the N+K we send, then weights this contribution by N

  for (int i=N; i<=(N+K); i++)
  {
    sum += (double)N * combin(N + K, i) * pow(per, N + K - i)
      * pow(1.0 - per, i);
  }

  // This second loop sums over the probability that we receive exactly 
  // i source packets and less than N total packets out of the N+K
  // we send, for i between 0 and N-1. We then weight this by the number
  // source packets received, i

  for (int i=0; i<=(N-1); i++)
  {
    // This inner loop computes the probability of receiving no more than
    // N - i - 1 repair packets out of the K we send. Note that we cannot
    // receive more repair packets than we send, so limit appropriately 

    int Ji = K;
    if (Ji > (N - i - 1))
    {
      Ji = N - i - 1;
    }

    double inner_prob = 0;
    for (int j=0; j<=Ji; j++)
    {
      inner_prob += combin(K, j) * pow (per, K - j)
	* pow(1.0 - per, j);
    }

    // The right side of this expression computes the probability that
    // exactly i source packets are received and insufficient repair
    // packets are received to reconstruct more. 
    // 
    // This is then weighted by i to compute the expected number of 
    // source packets received in this situation

    sum += (double) i * combin(N, i) * pow(per, N - i)
	    * pow(1.0 - per, i) * inner_prob;
  }

  // Finally we divide by the number of source packets sent to determine
  // the expected number of source packets received.

  sum /= (double)N;

  return sum;
}

//============================================================================
double
compute_conditional_systematic_fec_ps(int N, int Nrcvd, int Krcvd, int DofToSend, double per)
{
  // N is the number of source packets in a block
  // Nrcvd is the number of source pkts received in previous rounds
  // Krcvd is the number of FEC pkts recvd in previous rounds
  // DofToSend is the number of pks to be retransmitted
  // per is the packet error rate
  
  double sum = 0.0;

  // Compute the degrees of freedom needed to completely decode
  int DofNeeded = N - (Nrcvd + Krcvd);

  // We are modeling a systematic code here, where we may have usable
  // source packets even if don't receieve enough total packets to
  // decode the FEC

  // Consider two cases:
  //   1st case: we receive >=N total pkts and can decode (normal FEC)
  //   2nd case: we receive  <N total pkts, some of which are src pkts

  // We compute the expected number of usable source pkts received
  // across the two cases, then divide by the number of source packets
  // to get the probability of successfully receiving a source packet
  
  // This first loop computes the probability that we receive at least 
  // N packets out of the Nrevc and Krecv we have, and the DofToSend we
  // send, then weights this contribution by N

  for (int i=DofNeeded; i<=DofToSend; i++)
  {
    sum += (double)N * combin(DofToSend, i) * pow(per, DofToSend - i)
      * pow(1.0 - per, i);
  }

  // NtoSend is the number of original/source packets we send out of
  // the DofToSend specified. We always send source packets
  // ahead of repair packets, since they can be used even when we
  // dont receive enough total packets to decode -- so we make
  // as many of the DofToSend packets source packets as possible

  int NtoSend = N - Nrcvd;
  if (NtoSend > DofToSend)
  {
    NtoSend = DofToSend;
  }

  // KtoSend is the number of repair packets we send, if any, out of
  // the total DofToSend. 
  
  int KtoSend = 0;
  if ((DofToSend - NtoSend) > 0)
  {
    KtoSend = DofToSend - NtoSend;
  }	

  // This second loop sums over the probability that we receive exactly 
  // i source packets and less than DofNeeded total packets given the
  // Nrevc + Krecv = DofToSend we have to send. , summing for i
  // between 0 and the minimum of NtoSend-1 and DofNeeded-1. We then
  // weight this by the number of source packets received = i + Nrecv

  int upperBound = NtoSend < DofNeeded ? NtoSend : DofNeeded;
  
  for (int i=0; i<upperBound; i++)
  {
    // This inner loop computes the probability of receiving no more than
    // DofNeeded - i - 1 repair packets out of the DofToSend we send. Note
    // that we cannot receive more repair packets than we send, so limit
    // appropriately

    double inner_prob = 1;
    if (KtoSend > 0)
    {
      inner_prob = 0;
      
      int Ji = KtoSend;
      if (Ji > (DofNeeded - i - 1))
      {
	Ji = DofNeeded - i - 1;
      }
      
      for (int j=0; j<=Ji; j++)
      {
	inner_prob += combin(KtoSend, j) * pow (per, KtoSend - j)
	  * pow(1.0 - per, j);
      }
    }

    // The right side of this expression computes the probability that
    // exactly i source packets are received out of the NtoSend we
    // send and insufficient repair are received packets are received
    // to reconstruct more. 
    // 
    // This is then weighted by i to compute the expected number of 
    // source packets received in this situation

    sum += (double) (i + Nrcvd) * combin(NtoSend, i) * pow(per, NtoSend - i)
	    * pow(1.0 - per, i) * inner_prob;
  }

  // Finally we divide by the number of source packets sent to determine
  // the expected number of source packets received.

  sum /= (double)N;

  return sum;
}

//============================================================================
double
compute_simple_fec_ps(int N, int K, double per)
{
  // N is the number of source packets
  // K is the number of FEC packets
  // per is the packet error rate
  
  double sum = 0.0;

  // We are modeling a non-systematic code here, so we have no 
  // packets if we don't receieve enough packets to decode the FEC

  // Compute the probability that we receive at least 
  // N packets out of the N+K we send

  for (int i=N; i<=(N+K); i++)
  {
    sum += combin(N + K, i) * pow(per, N + K - i)
      * pow(1.0 - per, i);
  }

  return sum;
}

//============================================================================
double
compute_conditional_simple_fec_ps(int N, int Nrcvd, int Krcvd, int DofToSend, double per)
{
  // N is the number of source packets in a block
  // Nrcvd is the number of source pkts received in previous rounds
  // Krcvd is the number of FEC pkts recvd in previous rounds
  // DofToSend is the number of pks to be retransmitted
  // per is the packet error rate
  
  double sum = 0.0;

  // Compute the degrees of freedom needed to completely decode
  int DofNeeded = N - (Nrcvd + Krcvd);

  // This loop computes the probability that we receive at least 
  // N packets out of the Nrevc and Krecv we have, and the DofToSend we
  // send, then weights this contribution by N

  for (int i=DofNeeded; i<=DofToSend; i++)
  {
    sum += combin(DofToSend, i) * pow(per, DofToSend - i)
      * pow(1.0 - per, i);
  }

  return sum;
}

//=============================================================================
double 
combin(int n, int m)
{
  double cnm = 1.0;
  int i;

  if (m*2 > n)
    m = n-m;

  for (i=1; i<=m; n--, i++)
    cnm = cnm * ((double)n / (double)i);

  return (cnm);
}

//=============================================================================
double
propagate_probabilities(double **prevState, int **dof_lut,
			double **nextState, double per, int origBlkSz)
{
  double completion_prob = 0.0;

  // Clear the nextState matrix
  for (int nRcvd=0; nRcvd<UPSCALE*origBlkSz; nRcvd++)
  {
    for (int kRcvd=0; kRcvd<UPSCALE*origBlkSz-nRcvd; kRcvd++)
    {
      nextState[nRcvd][kRcvd] = 0.0;
    }
  }

  // Consider each point in the retransmission matrix 
  for (int nRcvd=0; nRcvd<origBlkSz; nRcvd++)
  {
    for (int kRcvd=0; kRcvd<origBlkSz-nRcvd; kRcvd++)
    {
      // Spread the probability mass from this point to the upper right

      int dof_to_send = dof_lut[nRcvd][kRcvd];
      int n_to_send   = origBlkSz - nRcvd;

      if (n_to_send > dof_to_send)
      {
	n_to_send = dof_to_send;
      }
      
      int k_to_send = dof_to_send - n_to_send;

      if (k_to_send < 0)
      {
	printf("Bogus DOF Lookup Table value\n");
	printf("    dof_to_send %d n_to_send %d k_to_send %d\n",
	       dof_to_send,n_to_send,k_to_send);
	k_to_send = 0;
      }
      
      for (int i=0; i<=n_to_send; i++)
      {
	for (int j=0; j<=k_to_send; j++)
	{
	  double mass = prevState[nRcvd][kRcvd] *
	    combin(n_to_send,i) *
	    pow(per,    (double)(n_to_send - i)) *
	    pow(1.0-per,(double)i) *
	    combin(k_to_send,j) *
	    pow(per,    (double)(k_to_send - j)) *
	    pow(1.0-per,(double)j);

	  int pkts_rcvd = nRcvd + kRcvd + i + j;

	  if (pkts_rcvd >= origBlkSz)
	  {
	    completion_prob += mass;
	  }
	  if (((nRcvd + i) >= origBlkSz * UPSCALE) ||
	      ((kRcvd + i) >= origBlkSz * UPSCALE))
	  {
	    printf("Index out of range for next state table\n");
	    printf("Need to make UPSCALE larger in CalculateFECRate.h\n");
	    exit(-1);
	  }
	  nextState[nRcvd+i][kRcvd+j] += mass;
	}
      }
    }
  }

  // Add in any untransferred mass from the previous round
  for (int nRcvd=0; nRcvd<UPSCALE*origBlkSz; nRcvd++)
  {
    int klower = origBlkSz < nRcvd ? 0 : origBlkSz - nRcvd;
    for (int kRcvd=klower; kRcvd<UPSCALE*origBlkSz; kRcvd++)
    {
      nextState[nRcvd][kRcvd] += prevState[nRcvd][kRcvd];
    }
  }

  return (completion_prob);
}
