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

/// \file latency_cache_shm.cc
///
/// The source file for LatencyCacheShm, which is responsible for storing
/// information about the minimum latency to every node in the destination.
//============================================================================

#include "latency_cache_shm.h"

#include "log.h"
#include "unused.h"

#include <climits>
#include <cstring>
#include <inttypes.h>
#include <string>
#include <unistd.h>

using ::iron::BinMap;
using ::iron::LatencyCacheShm;
using ::iron::SharedMemory;
using ::std::string;

namespace
{
  const char*  UNUSED(kClassName) = "LatencyCacheShm";
}

//============================================================================
LatencyCacheShm::LatencyCacheShm(BinMap& bin_map, ShmType role)
    : bin_map_(bin_map),
      min_latency_(),
      role_(role),
      shared_memory_(NULL),
      initialized_(false)
{
  // NOTE: min_latency_ is initialized in the Initialize function, because
  // it is a complex initialization with failure scenarios.
}

//============================================================================
LatencyCacheShm::~LatencyCacheShm()
{
  initialized_ = false;

  if (role_ == SHM_TYPE_LOCAL)
  {
    // This mode is not supported.  There is nothing to do.
  }
  else if (role_ == SHM_TYPE_CREATE)
  {
    if (shared_memory_ != NULL)
    {
      shared_memory_->Destroy();
      delete shared_memory_;
      shared_memory_ = NULL;
    }
  }
  else if (role_ == SHM_TYPE_ATTACH)
  {
    if (shared_memory_ != NULL)
    {
      shared_memory_->Detach();
      delete shared_memory_;
      shared_memory_ = NULL;
    }
  }
}

//============================================================================
bool LatencyCacheShm::Initialize()
{
  if (initialized_)
  {
    LogE(kClassName, __func__, "Already initialized.\n");
    return false;
  }

  // First, initialize the array in order to be able to get the shared memory
  // size required.
  if (!min_latency_.Initialize(bin_map_))
  {
    LogF(kClassName, __func__, "Unable to initialize minimum latency "
         "array.\n");
    return false;
  }

  // Allocate a shared memory object.
  shared_memory_ = new (std::nothrow) SharedMemory();

  if (shared_memory_ == NULL)
  {
    LogF(kClassName, __func__, "Unable to allocate SharedMemory.\n");
    return false;
  }

  // Set up the shared memory segment using the role and the size required by
  // the min_latency_ array.
  key_t   sem_key = kLatencyCacheSemKey;
  string  name    = kDefaultLatencyCacheShmName;
  size_t  bytes   = min_latency_.GetMemorySizeInBytes();

  if (role_ == SHM_TYPE_CREATE)
  {
    if (!shared_memory_->Create(sem_key, name.c_str(), bytes))
    {
      LogF(kClassName, __func__, "Failed to create shared memory segment.\n");
      return false;
    }
  }
  else if (role_ == SHM_TYPE_ATTACH)
  {
    bool      attached   = false;
    uint32_t  wait_count = 0;

    attached = shared_memory_->Attach(sem_key, name.c_str(), bytes);

    while (!attached)
    {
      sleep(1);
      ++wait_count;

      if (wait_count % 10 == 0)
      {
        if (wait_count % 120 == 0)
        {
          LogW(kClassName, __func__, "... Waiting to attach to latency cache "
               "shared memory (%" PRIu32 ").\n", wait_count);
        }
        else
        {
          LogD(kClassName, __func__, "... Waiting to attach.\n");
        }
      }

      attached = shared_memory_->Attach(sem_key, name.c_str(), bytes);
    }
  }
  else
  {
    LogF(kClassName, __func__, "Unsupported shared memory type for latency "
         "cache.\n");
    initialized_ = false;
    return false;
  }

  // Have the min_latency_ array use the shared memory segment.
  if (!min_latency_.SetShmDirectAccess(*shared_memory_))
  {
    LogF(kClassName, __func__, "Unable to set shared memory direct access "
         "for minimum latency array.\n");
    return false;
  }

  // If this object created the shared memory segment, then clear it before
  // using it.
  if (role_ == SHM_TYPE_CREATE)
  {
    min_latency_.Clear(0);
  }

  initialized_ = true;

  return true;
}
