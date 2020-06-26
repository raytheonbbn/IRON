//============================================================================
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
//============================================================================

#include "pkt_info_pool.h"
#include "packet_pool.h"

using ::iron::Packet;
using ::iron::PacketPool;

namespace
{
  /// Class name for logging.
  const char*  kClassName = "PktInfoPool";
}

//============================================================================
PktInfoPool::PktInfoPool(PacketPool& packet_pool)
    : pool_(NULL),
      packet_pool_(packet_pool)
{
}

//============================================================================
PktInfoPool::~PktInfoPool()
{
  // Delete all of the PktInfo elements currently in the pool.
  while (pool_ != NULL)
  {
    PktInfo*  cur_pkt_info = pool_;
    pool_ = cur_pkt_info->next;

    if (cur_pkt_info->pkt != NULL)
    {
      packet_pool_.Recycle(cur_pkt_info->pkt);
      cur_pkt_info->pkt= NULL;
    }

    delete cur_pkt_info;
  }
}

//============================================================================
PktInfo* PktInfoPool::Get(Packet* pkt)
{
  PktInfo*  pkt_info;

  if (pool_)
  {
    pkt_info = pool_;
    pool_ = pkt_info->next;
  }
  else
  {
    pkt_info = new (std::nothrow) PktInfo();

    if (pkt_info == NULL)
    {
      LogF(kClassName, __func__, "Error allocating new PktInfo.\n");
    }
  }

  pkt_info->Reset();

  if (!pkt)
  {
    pkt = packet_pool_.Get();
  }

  pkt_info->pkt = pkt;

  return pkt_info;
}

//============================================================================
void PktInfoPool::Recycle(PktInfo* pkt_info)
{
  if (pkt_info->pkt != NULL)
  {
    packet_pool_.Recycle(pkt_info->pkt);
    pkt_info->pkt = NULL;
  }

  // This should cause core dumps if any buffers are corrupted
  pkt_info->rexmit_next = (PktInfo *)-1;
  pkt_info->rexmit_prev = (PktInfo *)-1;
  pkt_info->prev        = (PktInfo *)-1;

  pkt_info->next = pool_;
  pool_          = pkt_info;
}
