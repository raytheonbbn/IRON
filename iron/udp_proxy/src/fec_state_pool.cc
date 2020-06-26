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

#include "fec_state.h"
#include "fec_state_pool.h"
#include "log.h"

#include <stack>

using ::iron::Log;
using ::iron::PacketPool;
using ::std::string;

namespace
{
  const char* kClassName = "FecStatePool";
}

//============================================================================
FecStatePool::FecStatePool(PacketPool& packet_pool)
    : pool_(),
      packet_pool_(packet_pool)
{
  pthread_mutex_init(&pool_mutex_, NULL);
}

//============================================================================
FecStatePool::~FecStatePool()
{
  Purge();
  pthread_mutex_destroy(&pool_mutex_);
}

//============================================================================
void FecStatePool::Purge()
{
  // Remove all FecStates still in the stack.
  FecState*  fec_state = NULL;

  LogD(kClassName, __func__, "Purging fec_states from pool.\n");

  pthread_mutex_lock(&pool_mutex_);
  while (!pool_.empty())
  {
    fec_state = pool_.top();
    pool_.pop();
    delete fec_state;
  }
  pthread_mutex_unlock(&pool_mutex_);
}

//============================================================================
FecState* FecStatePool::Get()
{
  // Grab a stacked FecState or create one
  FecState*  fec_state;

  pthread_mutex_lock(&pool_mutex_);

  if (!pool_.empty())
  {
    fec_state = pool_.top();
    pool_.pop();
    pthread_mutex_unlock(&pool_mutex_);
    fec_state->Initialize();
  }
  else
  {
    pthread_mutex_unlock(&pool_mutex_);

    fec_state = new (std::nothrow) FecState(packet_pool_);
    if (!fec_state)
    {
      LogF(kClassName, __func__, "Could not allocate new FecState.\n");
      abort();
    }
  }

  return fec_state;
}

//============================================================================
void FecStatePool::Recycle(FecState* fec_state)
{
  // Push FecState back onto the stack.
  if (!fec_state)
  {
    LogF(kClassName, __func__, "FecState is NULL, cannot recycle.\n");
    return;
  }

  pthread_mutex_lock(&pool_mutex_);
  pool_.push(fec_state);
  pthread_mutex_unlock(&pool_mutex_);
}

//============================================================================
size_t FecStatePool::GetSize()
{
  // Get the number of FecStates in the stack.
  pthread_mutex_lock(&pool_mutex_);
  size_t pool_size = pool_.size();
  pthread_mutex_unlock(&pool_mutex_);

  return pool_size;
}
