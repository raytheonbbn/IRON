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

/// \brief The interface for IRON inter-process shared memory access.
///
/// Provides the IRON software with access to shared memory between separate
/// processes on a single computer.

#ifndef IRON_COMMON_SHARED_MEMORY_IF_H
#define IRON_COMMON_SHARED_MEMORY_IF_H

#include <stdint.h>
#include <sys/types.h>

namespace iron
{

  /// \brief An abstract shared memory interface.
  ///
  /// One process is responsible for creating the shared memory segment using
  /// the Create() method.  All other processes that need to access the shared
  /// memory segment call Attach() after the shared memory has been created.
  ///
  /// The CopyToShm() and CopyFromShm() methods are used to copy data into and
  /// out of the shared memory segment, handling the necessary locking and
  /// unlocking.
  ///
  /// If the shared memory needs to be accessed manually, then the
  /// GetShmPtr(), Lock(), and Unlock() methods may be used.  It is up to the
  /// callers of these methods to use them correctly.
  ///
  /// During shutdown, the process that created the shared memory segment must
  /// call Destroy(), and the other processes that are accessing the shared
  /// memory segment must call Detach().
  class SharedMemoryIF
  {

   public:

    /// \brief The default constructor.
    SharedMemoryIF() {};

    /// \brief The destructor.
    virtual ~SharedMemoryIF() {};

    /// \brief Create the shared memory segment.
    ///
    /// Only the process that is responsible for actually creating the common
    /// shared memory segment must call this method.  It creates the shared
    /// memory segment and allows the calling process to access it (the
    /// process does not need to call Attach()).
    ///
    /// This method does not block.
    ///
    /// \param  key         The key for identifying the semaphore used for
    ///                     locking and unlocking the shared memory.
    /// \param  name        The shared memory name.  Must be of the form
    ///                     "/name", with a leading "/" character followed by
    ///                     a unique name.
    /// \param  size_bytes  The size of the shared memory segment in bytes.
    ///
    /// \return  True on success, or false on error.  If this method has
    /// already been called, then false is returned.
    virtual bool Create(key_t key, const char* name, size_t size_bytes) = 0;

    /// \brief Access the shared memory segment.
    ///
    /// This method does not create the shared memory segment, it only
    /// accesses it after it has been created by one process calling
    /// Create().  It may fail until the process creating the shared memory
    /// segment has completed calling Create().
    ///
    /// This method does not block.
    ///
    /// \param  key         The key for identifying the semaphore used for
    ///                     locking and unlocking the shared memory.
    /// \param  name        The shared memory name.  Must be of the form
    ///                     "/name", with a leading "/" character followed by
    ///                     a unique name.
    /// \param  size_bytes  The size of the shared memory segment in bytes.
    ///
    /// \return  True on success, or false on error.  If this method has
    /// already been called, then false is returned.
    virtual bool Attach(key_t key, const char* name, size_t size_bytes) = 0;

    /// \brief Copy data into the shared memory segment.
    ///
    /// This method handles the necessary locking and unlocking of the shared
    /// memory segment for the caller.  This call may block until the shared
    /// memory can be accessed.
    ///
    /// \param  src_buf           The location of the source data to be copied
    ///                           into shared memory.
    /// \param  size_bytes        The size of the copy, in bytes.
    /// \param  shm_offset_bytes  The optional shared memory offset where the
    ///                           data will be copied to, in bytes.  Defaults
    ///                           to 0.
    ///
    /// \return  True on success, or false on error.
    virtual bool CopyToShm(const uint8_t* src_buf, size_t size_bytes,
                           size_t shm_offset_bytes = 0)
#if not defined SHM_STATS
      const
#endif // not SHM_STATS
      = 0;

    /// \brief Copy data out of the shared memory segment.
    ///
    /// This method handles the necessary locking and unlocking of the shared
    /// memory segment for the caller.  This call may block until the shared
    /// memory can be accessed.
    ///
    /// \param  dst_buf           The destination location where the data will
    ///                           be copied from shared memory.
    /// \param  size_bytes        The size of the copy, in bytes.
    /// \param  shm_offset_bytes  The optional shared memory offset where the
    ///                           data will be copied from, in bytes.
    ///                           Defaults to 0.
    ///
    /// \return  True on success, or false on error.
    virtual bool CopyFromShm(uint8_t* dst_buf, size_t size_bytes,
                             size_t shm_offset_bytes = 0)
#if not defined SHM_STATS
      const
#endif // not SHM_STATS
      = 0;

    /// \brief Retrieve a pointer into the shared memory segment.
    ///
    /// This method does not handle any locking or unlocking.  It is the
    /// callers responsiblity to access the shared memory at the appropriate
    /// time.  This call does not block.
    ///
    /// \param  shm_offset_bytes  The optional shared memory offset, in
    ///                           bytes.  Defaults to 0.
    ///
    /// \return  The pointer into shared memory on success, or NULL on error.
    virtual uint8_t* GetShmPtr(size_t shm_offset_bytes = 0) = 0;

    /// \brief Manually lock the shared memory segment.
    ///
    /// This call may block until the lock can be acquired.  If the lock has
    /// already been acquired by the process, then this call will block
    /// forever.
    ///
    /// \return  True on success, or false on error.
    virtual bool Lock() = 0;

    /// \brief Manually unlock the shared memory segment.
    ///
    /// This call does not block.
    ///
    /// \return  True on success, or false on error.  If not currently locked,
    /// then false is returned.
    virtual bool Unlock() = 0;

    /// \brief Destroy the shared memory segment.
    ///
    /// Only called by the process that created the shared memory segment via
    /// the Create() method.
    virtual void Destroy() = 0;

    /// \brief Detach from the shared memory segment.
    ///
    /// Only called by the processes that attached to the shared memory
    /// segment via the Attach() method.
    virtual void Detach() = 0;

    /// \brief Check if this instance has been initialized.
    ///
    /// \return  True if Create() or Attach() have been executed successfully,
    /// otherwise false.
    virtual bool IsInitialized() const = 0;

   private:

    /// \brief Copy constructor.
    SharedMemoryIF(const SharedMemoryIF& other);

    /// \brief Copy operator.
    SharedMemoryIF& operator=(const SharedMemoryIF& other);

  }; // class SharedMemoryIF

} // namespace iron

#endif // IRON_COMMON_SHARED_MEMORY_IF_H
