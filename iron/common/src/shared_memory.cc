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

#include "shared_memory.h"

#include "rng.h"
#include "log.h"
#include "unused.h"

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/mman.h>


using ::iron::SharedMemory;
using ::iron::Log;
using ::iron::RNG;


struct sembuf  SharedMemory::op_lock_[2] =
{
  { 0, 0, 0 },        // wait for semaphore #0 to become 0
  { 0, 1, SEM_UNDO }  // increment semaphore #0 by 1
};

struct sembuf  SharedMemory::op_unlock_[1] =
{
  { 0, -1, (IPC_NOWAIT | SEM_UNDO) }  // decrement semaphore #0 by 1
};


namespace
{
  const char*  UNUSED(kClassName) = "SharedMemory";
}


//============================================================================
SharedMemory::SharedMemory()
  : SharedMemoryIF(), init_(false), creator_(false), sem_key_(0), sem_id_(-1),
      shm_size_(0), shm_ptr_(NULL)
#ifdef SHM_STATS
    , num_lock_calls_(0), num_lock_waits_(0)
#endif // SHM_STATS
{
  memset(shm_name_, 0, sizeof(shm_name_));
}

//============================================================================
SharedMemory::~SharedMemory()
{
  if (init_)
  {
    if (creator_)
    {
      Destroy();
    }
    else
    {
      Detach();
    }
  }
}

//============================================================================
bool SharedMemory::Create(key_t key, const char* name, size_t size_bytes)
{
  if (init_)
  {
    LogE(kClassName, __func__, "SharedMemory already initialized.\n");
    return false;
  }
  if ((name == NULL) || (size_bytes < 1))
  {
    LogE(kClassName, __func__,
         "Illegal argument. No Name: %d, size_bytes: %zd\n",
         name == NULL, size_bytes);
    return false;
  }

  // Create the semaphore for locking the shared memory.
  sem_key_ = key;

  sem_id_ = semget(sem_key_, 1, (IPC_CREAT | 0666));

  if (sem_id_ < 0)
  {
    LogE(kClassName, __func__, "Error in semget: %s\n", strerror(errno));
    return false;
  }

  LogD(kClassName, __func__, "Created semaphore %d.\n",
       static_cast<int>(sem_key_));

  // Initialize the semaphore to one.  This effectively locks the semaphore.
  int  sem_val = 1;

  if (semctl(sem_id_, 0, SETVAL, sem_val) < 0)
  {
    LogE(kClassName, __func__, "Error in semctl: %s\n", strerror(errno));
    semctl(sem_id_, 0, IPC_RMID, NULL);
    sem_id_ = -1;
    return false;
  }

  // Create the shared memory segment.
  strncpy(shm_name_, name, NAME_MAX);
  shm_name_[NAME_MAX - 1] = '\0';
  shm_size_               = size_bytes;

  int  shm_fd = shm_open(shm_name_, (O_CREAT | O_TRUNC | O_RDWR), 0666);

  if (shm_fd < 0)
  {
    LogE(kClassName, __func__, "Error in shm_open (%s): %s\n", shm_name_,
	 strerror(errno));
    semctl(sem_id_, 0, IPC_RMID, NULL);
    sem_id_ = -1;
    return false;
  }

  // Size the shared memory segment.
  if (ftruncate(shm_fd, shm_size_) != 0)
  {
    LogE(kClassName, __func__, "Error in ftruncate (%s): %s\n", shm_name_,
	 strerror(errno));
    close(shm_fd);
    shm_unlink(shm_name_);
    semctl(sem_id_, 0, IPC_RMID, NULL);
    sem_id_ = -1;
    return false;
  }

  // Map the shared memory segment into this process's address space.
  shm_ptr_ = (uint8_t*)mmap(NULL, shm_size_, (PROT_READ | PROT_WRITE),
                            MAP_SHARED, shm_fd, 0);

  if (shm_ptr_ == MAP_FAILED)
  {
    LogE(kClassName, __func__, "Error in mmap: %s\n", strerror(errno));
    close(shm_fd);
    shm_unlink(shm_name_);
    shm_ptr_ = NULL;
    semctl(sem_id_, 0, IPC_RMID, NULL);
    sem_id_ = -1;
    return false;
  }

  // The shared memory file descriptor may be closed now.
  close(shm_fd);

  // Unlock the semaphore.
  if (semop(sem_id_, &(op_unlock_[0]), 1) < 0)
  {
    LogE(kClassName, __func__, "Error in semop: %s\n", strerror(errno));
    if (munmap(shm_ptr_, shm_size_) != 0)
    {
      LogE(kClassName, __func__, "Error in munmap: %s (name %s).\n",
           strerror(errno), shm_name_);
    }
    shm_unlink(shm_name_);
    shm_ptr_ = NULL;
    semctl(sem_id_, 0, IPC_RMID, NULL);
    sem_id_ = -1;
    return false;
  }

  LogD(kClassName, __func__, "Created shared memory %s size %zd.\n",
       shm_name_, shm_size_);

  init_    = true;
  creator_ = true;

  return true;
}

//============================================================================
bool SharedMemory::Attach(key_t key, const char* name, size_t size_bytes)
{
  if (init_)
  {
    LogE(kClassName, __func__, "SharedMemory already initialized.\n");
    return false;
  }
  if ((name == NULL) || (size_bytes < 1))
  {
    LogE(kClassName, __func__,
         "Illegal argument. No Name: %d, size_bytes: %zd\n",
         name == NULL, size_bytes);
    return false;
  }

  // Access the semaphore for locking the shared memory.
  if (sem_id_ < 0)
  {
    sem_key_ = key;

    sem_id_ = semget(sem_key_, 0, 0666);

    if (sem_id_ < 0)
    {
      LogD(kClassName, __func__, "semget: %s\n", strerror(errno));
      return false;
    }

    LogD(kClassName, __func__, "Accessed semaphore %d.\n",
         static_cast<int>(sem_key_));
  }

  // Access the shared memory segment.
  strncpy(shm_name_, name, NAME_MAX);
  shm_name_[NAME_MAX - 1] = '\0';
  shm_size_               = size_bytes;

  int  shm_fd = shm_open(shm_name_, O_RDWR, 0666);

  if (shm_fd < 0)
  {
    LogD(kClassName, __func__, "shm_open: %s\n", strerror(errno));
    return false;
  }

  // Map the shared memory segment into this process's address space.
  if (shm_ptr_ == NULL)
  {
    shm_ptr_ = (uint8_t*)mmap(NULL, shm_size_, (PROT_READ | PROT_WRITE),
                              MAP_SHARED, shm_fd, 0);

    if (shm_ptr_ == MAP_FAILED)
    {
      LogE(kClassName, __func__, "Error in mmap: %s\n", strerror(errno));
      close(shm_fd);
      shm_unlink(shm_name_);
      shm_ptr_ = NULL;
      return false;
    }
  }

  // The shared memory file descriptor may be closed now.
  close(shm_fd);

  LogD(kClassName, __func__, "Accessed shared memory %s size %zd.\n",
       shm_name_, shm_size_);

  init_    = true;
  creator_ = false;

  return true;
}

//============================================================================
bool SharedMemory::CopyToShm(const uint8_t* src_buf, size_t size_bytes,
                             size_t shm_offset_bytes)
#if not defined SHM_STATS
  const
#endif // not SHM_STATS
{
  if ((!init_) || (src_buf == NULL) || (size_bytes < 1))
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

  // Lock.
#ifdef SHM_STATS
  CheckLockContention();
#endif // SHM_STATS
  if (semop(sem_id_, &(op_lock_[0]), 2) < 0)
  {
    LogD(kClassName, __func__, "Error in semop (sem id %d): %s\n", sem_id_,
         strerror(errno));
    return false;
  }

  // Copy.
  memcpy((shm_ptr_ + shm_offset_bytes), src_buf, size_bytes);

  // Unlock.
  if (semop(sem_id_, &(op_unlock_[0]), 1) < 0)
  {
    LogD(kClassName, __func__, "Error in semop (sem id %d): %s\n", sem_id_,
         strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SharedMemory::CopyFromShm(uint8_t* dst_buf, size_t size_bytes,
                               size_t shm_offset_bytes)
#if not defined SHM_STATS
  const
#endif // not SHM_STATS
{
  if ((!init_) || (dst_buf == NULL) || (size_bytes < 1))
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

  // Lock.
#ifdef SHM_STATS
  CheckLockContention();
#endif // SHM_STATS
  if (semop(sem_id_, &(op_lock_[0]), 2) < 0)
  {
    LogD(kClassName, __func__, "Error in semop (sem id %d): %s\n", sem_id_,
         strerror(errno));
    return false;
  }

  // Copy.
  memcpy(dst_buf, (shm_ptr_ + shm_offset_bytes), size_bytes);

  // Unlock.
  if (semop(sem_id_, &(op_unlock_[0]), 1) < 0)
  {
    LogD(kClassName, __func__, "Error in semop (sem id %d): %s\n", sem_id_,
         strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
uint8_t* SharedMemory::GetShmPtr(size_t shm_offset_bytes)
{
  if ((!init_) || (shm_offset_bytes > shm_size_))
  {
    return NULL;
  }

  return (shm_ptr_ + shm_offset_bytes);
}

//============================================================================
bool SharedMemory::Lock()
{
  if (!init_)
  {
    return false;
  }

#ifdef SHM_STATS
  CheckLockContention();
#endif // SHM_STATS
  if (semop(sem_id_, &(op_lock_[0]), 2) < 0)
  {
    LogD(kClassName, __func__, "Error in semop (sem id %d): %s\n", sem_id_,
         strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
bool SharedMemory::Unlock()
{
  if (!init_)
  {
    return false;
  }

  if (semop(sem_id_, &(op_unlock_[0]), 1) < 0)
  {
    LogD(kClassName, __func__, "Error in semop (sem id %d): %s\n", sem_id_,
         strerror(errno));
    return false;
  }

  return true;
}

//============================================================================
void SharedMemory::Destroy()
{
  if (init_ && creator_)
  {
    // Lock the semaphore first.
    if (semop(sem_id_, &(op_lock_[0]), 2) < 0)
    {
      LogE(kClassName, __func__, "Error in semop: %s (name %s).\n",
           strerror(errno), shm_name_);
    }

    // Unmap and unlink the shared memory segment.
    if (munmap(shm_ptr_, shm_size_) != 0)
    {
      LogE(kClassName, __func__, "Error in munmap: %s (name %s).\n",
           strerror(errno), shm_name_);
    }

    if (shm_unlink(shm_name_) != 0)
    {
      LogE(kClassName, __func__, "Error in shm_unlink: %s (name %s).\n",
           strerror(errno), shm_name_);
    }

    // Remove the semaphore.
    if (semctl(sem_id_, 0, IPC_RMID, NULL) < 0)
    {
      LogE(kClassName, __func__, "Error in semctl: %s\n (name %s).",
           strerror(errno), shm_name_);
    }

    init_     = false;
    creator_  = false;
    sem_key_  = 0;
    sem_id_   = -1;
    memset(shm_name_, 0, sizeof(shm_name_));
    shm_size_ = 0;
    shm_ptr_  = NULL;
  }
}

//============================================================================
void SharedMemory::Detach()
{
  if (init_ && (!creator_))
  {
    // Unmap the shared memory segment.  There is no need to lock the
    // semaphore first, since shared memory will not be modified.
    if (munmap(shm_ptr_, shm_size_) != 0)
    {
      LogE(kClassName, __func__, "Error in munmap: %s\n", strerror(errno));
    }

    init_     = false;
    creator_  = false;
    sem_key_  = 0;
    sem_id_   = -1;
    memset(shm_name_, 0, sizeof(shm_name_));
    shm_size_ = 0;
    shm_ptr_  = NULL;
  }
}

#ifdef SHM_STATS
//============================================================================
void SharedMemory::CheckLockContention()
{
  ++num_lock_calls_;
  if (semctl(sem_id_, 0, GETVAL, NULL) == 1)
  {
    ++num_lock_waits_;
    LogW(kClassName, __func__, "(%s) Lock contention = %" PRIu32 "/%"
         PRIu32 ".\n", shm_name_, num_lock_waits_, num_lock_calls_);
  }
}
#endif // SHM_STATS
