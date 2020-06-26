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

#ifndef CalculateFECRate_H
#define CalculateFECRate_H

#include <math.h>

#define UPSCALE 10

/**
 *  Single method returns the number of required FEC packets given the input
 *  parameters.
 *
 *  @param   max_total_pkts - maximum value that N+K can be set to.
 *  @param   per            - packet error rate
 *  @param   tgt_precv      - target receiver success probability
 *  @param   orig_src_pkts  - number of original source packets in an FEC block
 *  @param   dof_to_send    - calculated number of packets (src + fec) to send
 */
double calculate_systematic_fec_dof_to_send
	(int              max_total_pkts, 
	 double           per,
	 double           tgt_precv,
	 int              orig_src_pkts, 
	 int&             dof_to_send);

/**
 *  Single method returns the number of required packets to retransmit given the input
 *  parameters.
 *
 *  @param   max_total_pkts    - maximum value that N+K can be set to.
 *  @param   per               - packet error rate
 *  @param   tgt_precv         - target receiver success probability
 *  @param   orig_src_pkts     - number of original source packets in an FEC block
 *  @param   num_src_pkts_rcvd - number of source packets already received
 *  @param   num_fec_pkts_rcvd - number of FEC packets already received
 *  @param   dof_to_send       - calculated number of packets to retransmit (src + fec)
 */
double calculate_conditional_systematic_fec_dof_to_send
	(int              max_total_pkts, 
	 double           per,
	 double           tgt_precv,
	 int              orig_src_pkts,
	 int              num_src_pkts_rcvd,
	 int              num_fec_pkts_rcvd,
	 int&             dof_to_send);

/**
 *  Single method returns the number of required packets to retransmit given the input
 *  parameters.
 *
 *  @param   max_total_pkts    - maximum value that N+K can be set to.
 *  @param   per               - packet error rate
 *  @param   tgt_precv         - target receiver success probability
 *  @param   orig_src_pkts     - number of original source packets in an FEC block
 *  @param   num_src_pkts_rcvd - number of source packets already received
 *  @param   num_fec_pkts_rcvd - number of FEC packets already received
 *  @param   dof_to_send       - calculated number of packets to retransmit (src + fec)
 */

double calculate_conditional_simple_fec_dof_to_send
	(int    max_total_pkts, 
	 double per,
	 double tgt_precv,
	 int    orig_src_pkts,	 
	 int    num_src_pkts_rcvd,
	 int    num_fec_pkts_rcvd,
	 int&   dof_to_send);

/**
 *  Single method returns the number of source packets and the number of FEC 
 *  packets that best supports the given parameters.
 *
 *  @param   max_total_pkts - maximum value that N+K can be set to.
 *  @param   per            - packet error rate
 *  @param   tgt_precv      - target receiver success probability
 *  @param   num_src_pkts   - caluclated number of source packets
 *  @param   num_fec_pkts   - calculated number of FEC packets
 */
void optimize_systematic_fec_rate
	(int              max_total_pkts, 
	 double           per,
	 double           tgt_precv,
	 int&             num_src_pkts, 
	 int&             num_fec_pkts);

/**
 *  Computes probability of receiving a packet
 *
 *  @param   N    -  total number of packets to protect
 *  @param   K    -  total number of repair packets to send
 *  @param   per  -  packet loss rate
 *
 *  @return  - the probability of receiving the packet.
 */
static double compute_systematic_fec_ps(int N, int tgtK, double per);
  
/**
 *  Computes probability of receiving a packet, given other packets in an 
 *  FEC block have been received
 *
 *  @param   N         -  total number of (source) packets to protect
 *  @param   Nrcvd     -  total number of source packets already received
 *  @param   Krcvd     -  total number of repair (FEC) packets already received
 *  @param   DofToSend -  total number of packets to be sent (src pkts first)
 *  @param   per       -  packet loss rate
 *
 *  @return  - the probability of receiving the packet.
 */
static double compute_conditional_systematic_fec_ps(int N, int Nrcvd, int Krcvd, int DofToSend, double per);

/**
 *  Computes probability of receiving a packet with non-systematic FEC
 *
 *  @param   N    -  total number of packets to protect
 *  @param   K    -  total number of repair packets to send
 *  @param   per  -  packet loss rate
 *
 *  @return  - the probability of receiving the packet
 */
double compute_simple_fec_ps(int N, int K, double per);


/**
 *  Computes probability of receiving a packet, given other packets in an 
 *  FEC block have been received
 *
 *  @param   N         -  total number of (source) packets to protect
 *  @param   Nrcvd     -  total number of source packets already received
 *  @param   Krcvd     -  total number of repair (FEC) packets already received
 *  @param   DofToSend -  total number of packets to be sent (src pkts first)
 *  @param   per       -  packet loss rate
 *
 *  @return  - the probability of receiving the packet.
 */

double compute_conditional_simple_fec_ps
	(int N, int Nrcvd, int Krcvd, int DofToSend, double per);

/**
 * Compute the combinatorial "N choose M"
 *
 * @param N  - The superset size in N choose M
 * @param M  - The subset size in N choose M
 * 
 * @return   - The unordered combinations of N choose M
 */
static double combin(int n, int m);

/**
 * Update the state probability table given a retransmission matrix
 *
 * @param prevState  - The current set of state probabilities
 * @param dof_lut    - The retransmission matrix
 * @param nextState  - The updated set of state probabilities
 * @param per        - The packet probability of error
 * @param origBlkSz  - The no. of original source packets in the first FEC block
 * @param excessProb - Overdelivery probability
 * 
 */
double propagate_probabilities(double **prevState, int **dof_lut,
			       double **nextState, double  per,
			       int origBlkSz);

#endif // #define ComputeFECRate_H

//================================ End of File ===============================
