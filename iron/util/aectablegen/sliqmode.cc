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
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

#include <new>

#include "CalculateFECRate.h"
#include "CallocND.h"
#include "setupDofLookupTables.h"

#include "doflutparms.h"
#include "sliqmode.h"


/// Type definitions from SLIQ.
typedef uint8_t  FecRound;
typedef uint8_t  FecSize;

#define PRIFecRound  PRIu8
#define PRIFecSize   PRIu8

/// The special value for "out of rounds".
const FecRound  kOutOfRounds = 15;

/// The maximum FEC group length (source + encoded) in packets.  Set based
/// on the capabilities of the VdmFec class.  Cannot be greater than 32 due
/// to the FecGroupPktBitVec type.
const size_t  kMaxFecGroupLengthPkts = 31;

/// The maximum target packet receive probability.
const double  kMaxTgtPktRcvProb = 0.999;

/// The size of each set of triangle tables in the FEC lookup table in
/// number of elements.  These tables are stored as efficiently as possible.
/// The sizes of the tables add up as follows as k goes from 1 to 10:
/// 1+3+6+10+15+21+28+36+45+55 = 220.
const size_t  kFecTriTableSize = 220;

/// The size of each 4D FEC lookup table in number of elements.  The
/// dimensions are [p][k][sr][cr], where p is the PER, k is the number of
/// source packets per group, sr is the number of source packets received,
/// and cr is the number of coded packets received.  Note that [k][sr][cr]
/// is a series of triangle tables that are stored as efficiently as
/// possible.
const size_t  kFecTableSize = (kNumPers * kFecTriTableSize);

/// The minimum target number of rounds (N).
const FecRound  kMinN = 1;

/// The maximum target number of rounds (N).
const FecRound  kMaxN = kNumRounds;

/// The minimum number of FEC source packets in an FEC group (k).
const FecSize  kMinK = 1;

/// The maximum number of FEC source packets in an FEC group (k).
const FecSize  kMaxK = kNumSrcPkts;

/// The number of lookup tables, indexed directly by the target number of
/// rounds (N).  The valid range is 1 to kMaxTgtPktDelRnds.  The entry
/// for index 0 is not used.
const size_t  kNumLookupTables = (7 + 1);

/// The FEC mid-game lookup tables, indexed by the number of rounds (N).
/// Each entry points to a 4D table that is indexed used TableOffset().
uint8_t*  fec_midgame_tables_[kNumLookupTables];

/// The FEC end-game lookup tables, indexed by the number of rounds (N).
/// Each entry points to a 4D table that is indexed used TableOffset().
uint8_t*  fec_endgame_tables_[kNumLookupTables];


bool   CreateFecTables(double tgtPrecv);
bool   AllocateFecTables(FecRound n);
void   DeleteFecTables();
double CalculateConditionalSimpleFecDofToSend(
  int max_grp_len, double per, double tgt_p_recv, int num_src, int src_rcvd,
  int enc_rcvd, uint8_t& dof_to_send);
double CalculateConditionalSystematicFecDofToSend(
  int max_grp_len, double per, double tgt_p_recv, int num_src, int src_rcvd,
  int enc_rcvd, uint8_t& dof_to_send);
double ComputeConditionalSimpleFecPs(
  int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per);
double ComputeConditionalSystematicFecPs(
  int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per);
double Combination(int n, int k);
size_t TableOffset(size_t per_idx, FecSize k, FecSize sr, FecSize cr);
double CalculateEfficiency(double per, double tgtPrecv, int nRounds,
                           int nSrcPkts);


//============================================================================
int main(int argc, char**argv)
{
  if (argc < 7)
  {
    printf("Usage: sliqmode per tgtPrecv tgtLat maxRTT maxOWD maxPST\n");
    exit(0);
  }

  double  per      = atof(argv[1]);  // Packet error rate.
  double  tgtPrecv = atof(argv[2]);  // Target packet receive probability.
  double  tgtLat   = atof(argv[3]);  // Target packet delivery latency.
  double  maxRtt   = atof(argv[4]);  // Maximum round-trip time.
  double  maxOwd   = atof(argv[5]);  // Maximum local-to-remote one-way delay.
  double  maxPst   = atof(argv[6]);  // Maximum packet serialization time.

  double  eff = 0.0;

  // Map the Epsilon value into an Epsilon index for the FEC lookup tables.
  size_t  fec_epsilon_idx = 0;

  for (ssize_t sidx = (kNumEps - 1); sidx >= 0; --sidx)
  {
    if (tgtPrecv <= (1.0 - kEpsilon[sidx]))
    {
      fec_epsilon_idx = sidx;
      break;
    }
  }

  // -------------------------------------------------------------------------
  // Code from SLIQ's SentPktManager::UpdateFecTableParams() method.

  // Map the PER into a PER index for the FEC lookup tables.
  size_t  fec_per_idx = (kNumPers - 1);

  for (size_t i = 0; i < kNumPers; ++i)
  {
    if (kPerVals[i] >= per)
    {
      fec_per_idx = i;
      break;
    }
  }

  // The target number of rounds (N) is controlled by the specified packet
  // delivery time limit and the current RTT and OWD estimates.  Find the
  // target number of rounds that will meet the specified packet delivery time
  // limit.  There are three different scenarios that must be tested in order
  // to find N.

  // First, check if pure ARQ can be used with just a single round.  This is a
  // very easy test.  Use the exact target packet receive probability and the
  // exact PER estimate.
  if ((per <= 0.000001) || ((1.0 - per) >= tgtPrecv))
  {
    eff = CalculateEfficiency(per, tgtPrecv, 1, 1);

    printf("\nInputs:\n");
    printf("  PER:             %0.3f\n", per);
    printf("  Target Precv:    %0.3f\n", tgtPrecv);
    printf("  Target Latency:  %0.3f seconds\n", tgtLat);
    printf("  Maximum RTT:     %0.3f seconds\n", maxRtt);
    printf("  Maximum OWD:     %0.3f seconds\n", maxOwd);
    printf("  Maximum PST:     %0.6f seconds\n", maxPst);

    printf("\nResult:\n");
    printf("  SLIQ FEC Mode:       Pure ARQ\n");
    printf("  Rounds (N):          1\n");
    printf("  Source Packets (k):  1\n");
    printf("  Encoded Packets:     0\n");
    printf("  Efficiency:          %0.9f\n\n", eff);

    return 0;
  }

  // Second, determine how many rounds would be needed if pure ARQ is used.
  // This requires a loop.  Again, use the exact target packet receive
  // probability and the exact PER estimate.  Limit arq_cutover to the maximum
  // supported number of rounds for each FEC group (determined by the size of
  // the 4-bit round field in the Data Header, and the round value 15 reserved
  // for the "out of rounds" value).
  bool    valid_result = true;
  size_t  arq_cutover  = 1;
  double  test_eps     = (1.0 - tgtPrecv);
  double  test_p_loss  = per;

  while (test_p_loss > test_eps)
  {
    test_p_loss *= per;
    ++arq_cutover;

    if (arq_cutover >= kOutOfRounds)
    {
      valid_result = false;
      break;
    }
  }

  // Get the maximum RTT estimate and the maximum local-to-remote one-way
  // delay estimate.  These will be needed to make packet delivery time
  // estimates.
  double  max_rtt_sec     = maxRtt;
  double  max_ltr_owd_sec = maxOwd;

  // Only continue checking the pure ARQ case if the ARQ cutover value is
  // valid.
  if (valid_result)
  {
    // Pure ARQ can be used if there should be enough time to meet the packet
    // delivery deadline time.
    if (tgtLat > ((((double)arq_cutover - 1.0) * max_rtt_sec) +
                    max_ltr_owd_sec))
    {
      eff = CalculateEfficiency(per, tgtPrecv, arq_cutover, 1);

      printf("\nInputs:\n");
      printf("  PER:             %0.3f\n", per);
      printf("  Target Precv:    %0.3f\n", tgtPrecv);
      printf("  Target Latency:  %0.3f seconds\n", tgtLat);
      printf("  Maximum RTT:     %0.3f seconds\n", maxRtt);
      printf("  Maximum OWD:     %0.3f seconds\n", maxOwd);
      printf("  Maximum PST:     %0.6f seconds\n", maxPst);

      printf("\nResult:\n");
      printf("  SLIQ FEC Mode:       Pure ARQ\n");
      printf("  Rounds (N):          %zu\n", arq_cutover);
      printf("  Source Packets (k):  1\n");
      printf("  Encoded Packets:     0\n");
      printf("  Efficiency:          %0.9f\n\n", eff);

      return 0;
    }
  }

  // Create the FEC lookup tables.
  if (!CreateFecTables(tgtPrecv))
  {
    printf("Error creating FEC lookup tables.\n");
    exit(-1);
  }

  // Third, check if pure FEC (N=1) or coded ARQ (N>1) can be used.  The test
  // requires the maximum packet serialization time, which is computed using
  // the maximum packet size and the current connection send rate estimate.
  double  max_pst_sec = maxPst;

  // Find the target number of rounds (N) and number of source packets per
  // group (k) that maximizes efficiency while keeping the total worst case
  // delay within the packet delivery time limit.
  FecRound  opt_n   = 0;
  FecSize   opt_k   = 0;
  uint8_t   opt_eff = 0;

  for (FecRound n = kMinN; n <= kMaxN; ++n)
  {
    // Make sure the needed tables have been allocated.
    if ((fec_midgame_tables_[n] == NULL) ||
        (fec_endgame_tables_[n] == NULL))
    {
      printf("Error, missing FEC lookup tables for n %" PRIFecRound ".\n", n);
      continue;
    }

    for (FecSize k = kMinK; k <= kMaxK; ++k)
    {
      // Compute the total worst-case delay.
      size_t  idx        = TableOffset(fec_per_idx, k, 0, 0);
      double  mg_max_dof = fec_midgame_tables_[n][idx];
      double  eg_max_dof = fec_endgame_tables_[n][idx];
      double  twc_delay  =
        (((n - 1) * (((mg_max_dof + 1.0) * max_pst_sec) + max_rtt_sec)) +
         ((eg_max_dof * max_pst_sec) + max_ltr_owd_sec));

      if (twc_delay <= tgtLat)
      {
        uint8_t  eff =
          kEfficiency[fec_epsilon_idx][fec_per_idx][n - 1][k - 1];

        if (eff > opt_eff)
        {
          opt_n   = n;
          opt_k   = k;
          opt_eff = eff;
        }
      }
    }
  }

  // If there were no candidates found, then pure FEC (N=1) must be used with
  // one source packets per group (k=1).
  if (opt_n == 0)
  {
    opt_n = 1;
    opt_k = 1;
  }

  // Determine the number of encoded packets to be sent in the first round.
  FecSize  num_enc = 0;
  size_t   idx     = TableOffset(fec_per_idx, opt_k, 0, 0);

  if (opt_n > 1)
  {
    num_enc = ((FecSize)fec_midgame_tables_[opt_n][idx] - opt_k);
  }
  else
  {
    num_enc = ((FecSize)fec_endgame_tables_[opt_n][idx] - opt_k);
  }

  eff = CalculateEfficiency(per, tgtPrecv, opt_n, opt_k);

  printf("\nInputs:\n");
  printf("  PER:             %0.3f\n", per);
  printf("  Target Precv:    %0.3f\n", tgtPrecv);
  printf("  Target Latency:  %0.3f seconds\n", tgtLat);
  printf("  Maximum RTT:     %0.3f seconds\n", maxRtt);
  printf("  Maximum OWD:     %0.3f seconds\n", maxOwd);
  printf("  Maximum PST:     %0.6f seconds\n", maxPst);

  printf("\nResult:\n");
  printf("  SLIQ FEC Mode:       %s\n",
         ((opt_n == 1) ? "Pure FEC" : "Coded ARQ"));
  printf("  Rounds (N):          %" PRIFecRound "\n", opt_n);
  printf("  Source Packets (k):  %" PRIFecSize "\n", opt_k);
  printf("  Encoded Packets:     %" PRIFecSize "\n", num_enc);
  printf("  Efficiency:          %0.9f\n\n", eff);

  // Delete the FEC lookup tables.
  DeleteFecTables();

  return 0;
}

//============================================================================
bool CreateFecTables(double tgtPrecv)
{
  // Allocate only the necessary FEC lookup tables.
  FecRound  min_n = kMinN;
  FecRound  max_n = kMaxN;

  for (FecRound n = min_n; n <= max_n; ++n)
  {
    if (!AllocateFecTables(n))
    {
      printf("Error allocating FEC lookup tables at N=%" PRIFecRound ".\n",
             n);
      return false;
    }
  }

  // Get the value of Epsilon to use in the tables.
  size_t  fec_epsilon_idx = 0;

  for (ssize_t i = (kNumEps - 1); i >= 0; --i)
  {
    if (tgtPrecv <= (1.0 - kEpsilon[i]))
    {
      fec_epsilon_idx = i;
      break;
    }
  }

  double  eps = kEpsilon[fec_epsilon_idx];

  // Set the lookup tables.  Loop over all target number of rounds (N) values.
  for (FecRound n = kMinN; n <= kMaxN; ++n)
  {
    // Only populate the tables if they are allocated.
    if ((fec_midgame_tables_[n] == NULL) || (fec_endgame_tables_[n] == NULL))
    {
      continue;
    }

    // Loop over all PER (p) values.
    for (size_t per_idx = 0; per_idx < kNumPers; ++per_idx)
    {
      double  per = kPerVals[per_idx];

      // Determine how many rounds would be needed for pure ARQ.  Given that
      // per can be a maximum of 0.5 and eps can be a minimum of 0.001,
      // arq_cutover cannot be larger than 10.
      FecRound  arq_cutover = 1;
      double    test_p_loss = per;

      while (test_p_loss > eps)
      {
        test_p_loss *= per;
        ++arq_cutover;
      }

      if (n >= arq_cutover)
      {
        // Use pure ARQ.
        for (FecSize k = kMinK; k <= kMaxK; ++k)
        {
          for (FecSize sr = 0; sr < k; ++sr)
          {
            for (FecSize cr = 0; cr < (k - sr); ++cr)
            {
              size_t  idx = TableOffset(per_idx, k, sr, cr);

              fec_midgame_tables_[n][idx] = (uint8_t)(k - sr);
              fec_endgame_tables_[n][idx] = (uint8_t)(k - sr);
            }
          }
        }
      }
      else
      {
        for (FecSize k = kMinK; k <= kMaxK; ++k)
        {
          // Lookup the midgame probability of packet receive given the
          // current values.
          double  midgame_p_recv =
            kMidgameParms[k - 1][per_idx][n - 1][fec_epsilon_idx];

          // A midgame_p_recv value of 0.0 signals that we should use an
          // ARQ-like midgame lookup table.
          if (midgame_p_recv < 0.001)
          {
            for (FecSize sr = 0; sr < k; ++sr)
            {
              for (FecSize cr = 0; cr < (k - sr); ++cr)
              {
                size_t  idx = TableOffset(per_idx, k, sr, cr);

                fec_midgame_tables_[n][idx] = (k - sr);
              }
            }
          }
          else
          {
            for (FecSize sr = 0; sr < k; ++sr)
            {
              for (FecSize cr = 0; cr < (k - sr); ++cr)
              {
                size_t  idx = TableOffset(per_idx, k, sr, cr);

                CalculateConditionalSimpleFecDofToSend(
                  kMaxFecGroupLengthPkts, per, midgame_p_recv, k, sr, cr,
                  fec_midgame_tables_[n][idx]);
              }
            }
          }

          // Lookup the endgame probability of packet receive given the
          // current values.
          double  endgame_p_recv =
            kEndgameParms[k - 1][per_idx][n - 1][fec_epsilon_idx];

          for (FecSize sr = 0; sr < k; ++sr)
          {
            for (FecSize cr = 0; cr < (k - sr); ++cr)
            {
              size_t  idx = TableOffset(per_idx, k, sr, cr);

              CalculateConditionalSystematicFecDofToSend(
                kMaxFecGroupLengthPkts, per, endgame_p_recv, k, sr, cr,
                fec_endgame_tables_[n][idx]);
            }
          }
        } // end k loop
      } // end if pure ARQ
    } // end per_idx loop
  } // end n loop

  return true;
}

//============================================================================
bool AllocateFecTables(FecRound n)
{
  // Allocate the midgame and endgame FEC lookup tables for the specified
  // target number of rounds.
  fec_midgame_tables_[n] = new (std::nothrow) uint8_t[kFecTableSize];
  fec_endgame_tables_[n] = new (std::nothrow) uint8_t[kFecTableSize];

  if ((fec_midgame_tables_[n] == NULL) || (fec_endgame_tables_[n] == NULL))
  {
    return false;
  }

  memset(fec_midgame_tables_[n], 0, (kFecTableSize * sizeof(uint8_t)));
  memset(fec_endgame_tables_[n], 0, (kFecTableSize * sizeof(uint8_t)));

  return true;
}

//============================================================================
void DeleteFecTables()
{
  // Delete the arrays of information.
  for (size_t i = 0; i < kNumLookupTables; ++i)
  {
    if (fec_midgame_tables_[i] != NULL)
    {
      delete [] fec_midgame_tables_[i];
      fec_midgame_tables_[i] = NULL;
    }

    if (fec_endgame_tables_[i] != NULL)
    {
      delete [] fec_endgame_tables_[i];
      fec_endgame_tables_[i] = NULL;
    }
  }
}

//============================================================================
double CalculateConditionalSimpleFecDofToSend(
  int max_grp_len, double per, double tgt_p_recv, int num_src, int src_rcvd,
  int enc_rcvd, uint8_t& dof_to_send)
{
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  if (dof_needed < 1)
  {
    dof_to_send = 0;
    return 1.0;
  }

  // Success probability given an FEC configuration.
  double  ps = 0.0;

  if (tgt_p_recv >= kMaxTgtPktRcvProb)
  {
    tgt_p_recv = kMaxTgtPktRcvProb;
  }

  // Start at a test value for dof_to_send of 0.
  int  dts = 0;

  for (dts = 1; dts < (max_grp_len - src_rcvd); ++dts)
  {
    ps = ComputeConditionalSimpleFecPs(num_src, src_rcvd, enc_rcvd, dts, per);

    if (ps >= tgt_p_recv)
    {
      break;
    }
  }

  dof_to_send = dts;

  return ps;
}

//============================================================================
double CalculateConditionalSystematicFecDofToSend(
  int max_grp_len, double per, double tgt_p_recv, int num_src, int src_rcvd,
  int enc_rcvd, uint8_t& dof_to_send)
{
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  if (dof_needed < 1)
  {
    dof_to_send = 0;
    return 1.0;
  }

  if (tgt_p_recv >= kMaxTgtPktRcvProb)
  {
    tgt_p_recv = kMaxTgtPktRcvProb;
  }

  // Success probability given an FEC receive configuration.
  double  ps = 0.0;

  // Start at a test value for dof_to_send of 1.
  int  dts = 0;

  for (dts = 1; dts < max_grp_len; ++dts)
  {
    ps = ComputeConditionalSystematicFecPs(num_src, src_rcvd, enc_rcvd, dts,
                                           per);

    if (ps >= tgt_p_recv)
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

  return ps;
}

//============================================================================
double ComputeConditionalSimpleFecPs(
  int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per)
{
  double  sum = 0.0;

  // Compute the degrees of freedom needed to completely decode.
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  // This loop computes the probability that we receive at least num_src
  // packets out of the (src_rcvd + enc_rcvd) we have, and the dof_to_send we
  // send, then weights this contribution by num_src.
  for (int i = dof_needed; i <= dof_to_send; ++i)
  {
    sum += (Combination(dof_to_send, i) * pow(per, (dof_to_send - i)) *
            pow((1.0 - per), i));
  }

  return sum;
}

//============================================================================
double ComputeConditionalSystematicFecPs(
  int num_src, int src_rcvd, int enc_rcvd, int dof_to_send, double per)
{
  double  sum = 0.0;

  // Compute the degrees of freedom needed to completely decode.
  int  dof_needed = (num_src - (src_rcvd + enc_rcvd));

  // We are modeling a systematic code here, where we may have usable source
  // packets even if we don't receive enough total packets to decode the FEC.

  // Consider two cases:
  //   1st case: we receive >= num_src total pkts and can decode (normal FEC)
  //   2nd case: we receive  < num_src total pkts, some of which are src pkts
  //
  // We compute the expected number of usable source packets received across
  // the two cases, then divide by the number of source packets to get the
  // probability of successfully receiving a source packet.
  //
  // This first loop computes the probability that we receive at least num_src
  // packets out of the (src_rcvd + enc_rcvd) we have, and the dof_to_send we
  // send, then weights this contribution by num_src.
  for (int i = dof_needed; i <= dof_to_send; ++i)
  {
    sum += (static_cast<double>(num_src) * Combination(dof_to_send, i) *
            pow(per, (dof_to_send - i)) * pow((1.0 - per), i));
  }

  // src_to_send is the number of original/source packets we send out of the
  // dof_to_send specified.  We always send source packets ahead of repair
  // packets, since they can be used even when we don't receive enough total
  // packets to decode -- so we make as many of the dof_to_send packets source
  // packets as possible.
  int  src_to_send = (num_src - src_rcvd);

  if (src_to_send > dof_to_send)
  {
    src_to_send = dof_to_send;
  }

  // enc_to_send is the number of repair packets we send, if any, out of the
  // total dof_to_send.
  int  enc_to_send = 0;

  if ((dof_to_send - src_to_send) > 0)
  {
    enc_to_send = (dof_to_send - src_to_send);
  }

  // This second loop sums over the probability that we receive exactly i
  // source packets and less than num_src total packets given the (src_rcvd +
  // enc_rcvd) = dof_to_send we have to send, summing for i between 0 and the
  // minimum of src_to_send-1 and dof_needed-1.  We then weight this by the
  // number of source packets received = (i + src_rcvd).
  int  upper_bound = ((src_to_send < dof_needed) ? src_to_send : dof_needed);

  for (int i = 0; i < upper_bound; ++i)
  {
    // This inner loop computes the probability of receiving no more than
    // (dof_needed - i - 1) repair packets out of the dof_to_send we send.
    // Note that we cannot receive more repair packets than we send, so limit
    // appropriately.
    double  inner_prob = 1.0;

    if (enc_to_send > 0)
    {
      inner_prob = 0.0;

      int  j_i = enc_to_send;

      if (j_i > (dof_needed - i - 1))
      {
        j_i = (dof_needed - i - 1);
      }

      for (int j = 0; j <= j_i; ++j)
      {
        inner_prob += (Combination(enc_to_send, j) *
                       pow(per, (enc_to_send - j)) * pow((1.0 - per), j));
      }
    }

    // The right side of this expression computes the probability that exactly
    // i source packets are received out of the src_to_send we send and
    // insufficient repair packets are received to reconstruct more.
    //
    // This is then weighted by i to compute the expected number of source
    // packets received in this situation.
    sum += (static_cast<double>(i + src_rcvd) * Combination(src_to_send, i) *
            pow(per, (src_to_send - i)) * pow((1.0 - per), i) * inner_prob);
  }

  // Finally we divide by the number of source packets sent to determine the
  // expected number of source packets received.
  sum /= static_cast<double>(num_src);

  return sum;
}

//============================================================================
double Combination(int n, int k)
{
  double  cnk = 1.0;

  if ((k * 2) > n)
  {
    k = (n - k);
  }

  for (int i = 1; i <= k; n--, i++)
  {
    cnk = (cnk * (static_cast<double>(n) / static_cast<double>(i)));
  }

  return cnk;
}

//============================================================================
size_t TableOffset(size_t per_idx, FecSize k, FecSize sr, FecSize cr)
{
  static size_t  k_offset[11] = { 0, 0, 1, 4, 10, 20, 35, 56, 84, 120, 165 };
  static size_t  sr_corr[10]  = { 0, 0, 1, 3, 6, 10, 15, 21, 28, 36 };

  // Validate the parameters.
  if ((per_idx >= kNumPers) || (k < kMinK) || (k > kMaxK) || (sr >= k) ||
      (cr >= k) || ((sr + cr) >= k))
  {
    printf("Invalid FEC table index, per_idx=%zu k=%" PRIFecSize " sr=%"
           PRIFecSize " cr=%" PRIFecSize ".\n", per_idx, k, sr, cr);
    exit(-1);
  }

  // Compute the offset into the array of elements.
  size_t  offset = ((per_idx * kFecTriTableSize) + k_offset[k] +
                    ((size_t)sr * (size_t)k) -
                    sr_corr[sr] + (size_t)cr);

  if (offset >= kFecTableSize)
  {
    printf("Invalid result, table[%zu][%" PRIFecSize "][%" PRIFecSize "][%"
           PRIFecSize "] offset=%zu.\n", per_idx, k, sr, cr, offset);
    exit(-1);
  }

  return offset;
}

//============================================================================
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
