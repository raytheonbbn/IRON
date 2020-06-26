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

/// \brief The IRON inter-process shared memory module.
///
/// Provides the IRON software with access to shared memory between separate
/// prcoesses on a single computer.

#include "pseudo_shared_memory.h"

#include "log.h"

#include <cstring>
#include <string.h>
#include <inttypes.h>


using ::iron::PseudoSharedMemory;
using ::iron::Log;

namespace
{
  const char* kClassName = "PseudoSharedMemory";
}


//============================================================================
PseudoSharedMemory::PseudoSharedMemory()
  : SharedMemoryIF(), created_(false), attach_count_(0), shm_size_(0),
    shm_ptr_(NULL)
{
  memset(shm_name_, 0, sizeof(shm_name_));
}

//============================================================================
PseudoSharedMemory::~PseudoSharedMemory()
{
  created_ = false;
  attach_count_ = 0;
  Cleanup();
}

//============================================================================
bool PseudoSharedMemory::Create(key_t key, const char* name, size_t size_bytes)
{
  if (created_)
  {
    LogE(kClassName, __func__, "PseudoSharedMemory already initialized.\n");
    return false;
  }
  if ((name == NULL) || (size_bytes < 1))
  {
    LogE(kClassName, __func__,
         "Illegal argument. No Name: %d, size_bytes: %zd\n",
         name == NULL, size_bytes);
    return false;
  }
  if (attach_count_ > 0)
  {
    if (strncmp(shm_name_, name, NAME_MAX) != 0)
    {
      LogE(kClassName, __func__, "Name already set (%s). Attempting to create "
           "with different name (%s)\n", shm_name_, name);
      return false;
    }
    if (shm_size_ != size_bytes)
    {
      LogE(kClassName, __func__, "Size already set (%zu). Attempting to create "
           "with different size (%zu)\n", shm_size_, size_bytes);
      return false;
    }
  }
  else
  {
    // Create the shared memory segment.
    strncpy(shm_name_, name, NAME_MAX);
    shm_name_[NAME_MAX - 1] = '\0';
    shm_size_ = size_bytes;

    // Creat the memory to be used
    shm_ptr_ = new uint8_t[shm_size_];
  }

  LogD(kClassName, __func__, "Created shared memory %s size %zu.\n",
       shm_name_, shm_size_);

  created_ = true;
  attach_count_++;

  return true;
}

//============================================================================
bool PseudoSharedMemory::Attach(key_t key, const char* name, size_t size_bytes)
{
  if ((name == NULL) || (size_bytes < 1))
  {
    LogE(kClassName, __func__,
         "Illegal argument. No Name: %d, size_bytes: %zd\n",
         name == NULL, size_bytes);
    return false;
  }
  if (IsInitialized())
  {
    if (strncmp(shm_name_, name, NAME_MAX) != 0)
    {
      LogE(kClassName, __func__, "Name already set (%s). Attempting to attach "
           "with different name (%s)\n", shm_name_, name);
      return false;
    }
    if (shm_size_ != size_bytes)
    {
      LogE(kClassName, __func__, "Size already set (%zu). Attempting to attach "
           "with different size (%zu)\n", shm_size_, size_bytes);
      return false;
    }
  }
  else
  {
    // Create the shared memory segment.
    strncpy(shm_name_, name, NAME_MAX);
    shm_name_[NAME_MAX - 1] = '\0';
    shm_size_ = size_bytes;

    // Creat the memory to be used
    shm_ptr_ = new uint8_t[shm_size_];
  }

  LogD(kClassName, __func__, "Attached shared memory %s size %zu.\n",
       shm_name_, shm_size_);

  attach_count_++;

  return true;
}

//============================================================================
bool PseudoSharedMemory::CopyToShm(const uint8_t* src_buf, size_t size_bytes,
                   size_t shm_offset_bytes)
#if not defined SHM_STATS
  const
#endif // not SHM_STATS
{
  if ((!IsInitialized()) || (src_buf == NULL) || (size_bytes < 1))
  {
    return false;
  }

  // Make sure the copy will not exceed the shared memory size.
  if ((shm_offset_bytes + size_bytes) > shm_size_)
  {
    LogE(kClassName, __func__, "Error, copy of size %zd will exceed shared "
         "memory offset %zd size %zd.\n", size_bytes, shm_offset_bytes,
         shm_size_);
    return false;
  }

  memcpy((shm_ptr_ + shm_offset_bytes), src_buf, size_bytes);

  return true;
}

//============================================================================
bool PseudoSharedMemory::CopyFromShm(uint8_t* dst_buf, size_t size_bytes,
                               size_t shm_offset_bytes)
#if not defined SHM_STATS
  const
#endif // not SHM_STATS
{
  if ((!IsInitialized()) || (dst_buf == NULL) || (size_bytes < 1))
  {
    return false;
  }

  // Make sure the copy will not exceed the shared memory size.
  if ((shm_offset_bytes + size_bytes) > shm_size_)
  {
    LogE(kClassName, __func__, "Error, copy of size %zd will exceed shared "
         "memory offset %zd size %zd.\n", size_bytes, shm_offset_bytes,
         shm_size_);
    return false;
  }

  memcpy(dst_buf, (shm_ptr_ + shm_offset_bytes), size_bytes);

  return true;
}

//============================================================================
uint8_t* PseudoSharedMemory::GetShmPtr(size_t shm_offset_bytes)
{
  if ((!IsInitialized()) || (shm_offset_bytes > shm_size_))
  {
    return NULL;
  }

  return (shm_ptr_ + shm_offset_bytes);
}

//============================================================================
bool PseudoSharedMemory::Lock()
{
  return IsInitialized();
}

//============================================================================
bool PseudoSharedMemory::Unlock()
{
  return IsInitialized();
}

//============================================================================
void PseudoSharedMemory::Destroy()
{
  created_ = false;
  attach_count_--;
  Cleanup();
}

//============================================================================
void PseudoSharedMemory::Detach()
{
  attach_count_--;
  Cleanup();
}

//============================================================================
void PseudoSharedMemory::Cleanup()
{
  if (!IsInitialized())
  {
    created_  = false;
    memset(shm_name_, 0, sizeof(shm_name_));
    shm_size_ = 0;
    if (shm_ptr_ != NULL)
    {
      delete[] shm_ptr_;
      shm_ptr_  = NULL;
    }
  }
}
