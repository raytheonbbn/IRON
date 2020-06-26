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

#include "fec_context.h"
#include "itime.h"

#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>

using ::iron::Time;

//============================================================================
FECContext::FECContext()
    : lo_port_(1),
      hi_port_(65535),
      base_rate_(1),
      total_rate_(1),
      max_chunk_sz_(65535), // Max size IP pkt by default
      max_hold_time_(),
      in_order_(0),
      timeout_(0),
      time_to_go_(),
      time_to_go_valid_(false),
      dscp_(0),
      util_fn_defn_(),
      reorder_time_(Time(0)),
      dst_vec_(0)
{
  max_hold_time_.tv_sec     = 100;   // 100 seconds by default
  max_hold_time_.tv_usec    = 0;
}

//============================================================================
FECContext::FECContext(int loPort, int hiPort, int baseRate,
                       int totalRate, int maxChunkSz,
                       struct timeval maxHoldTime, bool inOrder,
                       time_t timeOut, const iron::Time& ttg, bool ttg_valid,
                       std::string util_fn_defn,
                       int8_t dscp, const iron::Time& reorder_time,
		       const iron::DstVec& dst_vec)
    : lo_port_(loPort),
      hi_port_(hiPort),
      base_rate_(baseRate),
      total_rate_(totalRate),
      max_chunk_sz_(maxChunkSz),
      max_hold_time_(maxHoldTime),
      in_order_(inOrder),
      timeout_(timeOut),
      time_to_go_(ttg),
      time_to_go_valid_(ttg_valid),
      dscp_(dscp),
      util_fn_defn_(util_fn_defn),
      reorder_time_(reorder_time),
      dst_vec_(dst_vec)
{
}

//============================================================================
FECContext::~FECContext()
{
  // Nothing to destroy.
}
