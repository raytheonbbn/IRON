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

#include "sliq_cc_interface.h"
#include "sliq_cc_copa.h"
#include "sliq_cc_copa2.h"
#include "sliq_cc_copa3.h"
#include "sliq_cc_cubic.h"
#include "sliq_cc_cubic_bytes.h"
#include "sliq_cc_fixed_rate.h"

#include "unused.h"

using ::sliq::CongCtrlInterface;
using ::sliq::CopaBeta1;
using ::sliq::CopaBeta2;
using ::sliq::Copa;
using ::sliq::Cubic;
using ::sliq::CubicBytes;
using ::sliq::FixedRate;
using ::iron::Log;
using ::iron::PacketPool;
using ::iron::RNG;
using ::iron::Timer;


namespace
{
  /// Class name for logging.
  const char*  UNUSED(kClassName) = "CongCtrlInterface";
}


//============================================================================
CongCtrlInterface* CongCtrlInterface::Create(
  EndptId conn_id, bool is_client, CcId cc_id, Connection& conn,
  Framer& framer, RttManager& rtt_mgr, RNG& rng, PacketPool& packet_pool,
  Timer& timer, const CongCtrl& cc_params)
{
  CongCtrlInterface*  cc_alg = NULL;

  switch (cc_params.algorithm)
  {
    case TCP_CUBIC_BYTES_CC:
    case TCP_RENO_BYTES_CC:
      cc_alg = new (std::nothrow)
        CubicBytes(conn_id, is_client, rtt_mgr,
                   (cc_params.algorithm == TCP_RENO_BYTES_CC));
      break;

    case TCP_CUBIC_CC:
      cc_alg = new (std::nothrow) Cubic(conn_id, is_client, rtt_mgr);
      break;

    case COPA1_CONST_DELTA_CC:
    case COPA1_M_CC:
      cc_alg = new (std::nothrow) CopaBeta1(conn_id, is_client, rng);
      break;

    case COPA2_CC:
      cc_alg = new (std::nothrow) CopaBeta2(conn_id, is_client, cc_id, conn,
                                            framer, packet_pool, timer);
      break;

    case COPA_CC:
      cc_alg = new (std::nothrow) Copa(conn_id, is_client, cc_id, conn,
                                       framer, packet_pool, timer);
      break;

    case FIXED_RATE_TEST_CC:
      cc_alg = new (std::nothrow) FixedRate(conn_id, is_client);
      break;

    case NO_CC:
    default:
      LogF(kClassName, __func__, "Error, must specify a congestion control "
           "type.\n");
  }

  if (cc_alg != NULL)
  {
    if (!cc_alg->Configure(cc_params))
    {
      delete cc_alg;
      cc_alg = NULL;
    }
  }

  return cc_alg;
}

//============================================================================
CongCtrlInterface::CongCtrlInterface(EndptId conn_id, bool is_client)
    : conn_id_(conn_id),
      is_client_(is_client),
      pkts_in_flight_(0),
      bytes_in_flight_(0),
      pipe_(0)
{}

//============================================================================
CongCtrlInterface::~CongCtrlInterface()
{}

//============================================================================
void CongCtrlInterface::ReportUnaPkt(StreamId stream_id, bool has_una_pkt,
                                     PktSeqNumber una_cc_seq_num)
{}

//============================================================================
bool CongCtrlInterface::RequireFastRto()
{
  return false;
}

//============================================================================
void CongCtrlInterface::UpdateCounts(int32_t pif_adj, int64_t bif_adj,
                                     int64_t pipe_adj)
{
  pkts_in_flight_  += pif_adj;
  bytes_in_flight_ += bif_adj;
  pipe_            += pipe_adj;
}
