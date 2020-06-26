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

/// \brief The IRON bin indexable array shared memory header file.
///
/// Provides the IRON software with a simple array of copyable objects that is
/// stored in shared memory and accessible using a single, common, bin index
/// as provided by the BinMap.

#ifndef IRON_COMMON_BIN_INDEXABLE_ARRAY_SHM_H
#define IRON_COMMON_BIN_INDEXABLE_ARRAY_SHM_H

#include "bin_indexable_array.h"

namespace iron
{
  /// \brief Templated Bin Indexable Array Shared Memory class.
  ///
  /// Initialize by:
  /// - calling Initialize() passing the BinMap object,
  /// - setting up the SharedMemoryIF object using the size returned by
  ///   GetMemorySizeInBytes(), and
  /// - calling SetShmDirectAccess() passing the SharedMemoryIF object.
  ///
  /// Note that the shared memory must be locked and unlocked as necessary
  /// outside of this class when using Clear() or operator[]().
  template <class C>
  class BinIndexableArrayShm : public BinIndexableArray<C>
  {

   public:

    /// \brief Constructor.
    BinIndexableArrayShm()
        : BinIndexableArray<C>()
    {
      return;
    }

    /// \brief Destructor.
    virtual ~BinIndexableArrayShm()
    {
      // Stop the base class destructor from deleting any shared memory
      // pointer that may have been set up.
      this->array_ = NULL;
    }

    /// \brief Set the object for direct shared memory access.
    ///
    /// Must be called after a successful call to Initialize().  The object
    /// cannot be used until this call succeeds.
    ///
    /// \param  shm_if  Reference to the SharedMemoryIF.  Be sure that
    ///                 IsInitialized() returns true on this object before
    ///                 calling this method, or else this method will fail.
    ///
    /// \return  True on success, or false on error.
    virtual bool SetShmDirectAccess(SharedMemoryIF& shm_if)
    {
      if (!this->init_flag_)
      {
        LogE("BinIndexableArrayShm", __func__, "Not initialized yet.\n");
        return false;
      }

      if (!shm_if.IsInitialized())
      {
        LogE("BinIndexableArrayShm", __func__, "Shared memory not ready.\n");
        return false;
      }

      this->array_ = reinterpret_cast<C*>(shm_if.GetShmPtr());

      if (this->array_ == NULL)
      {
        LogE("BinIndexableArrayShm", __func__, "Array pointer error.\n");
        return false;
      }

      return true;
    }

    /// \brief Copy the entire array to shared memory.
    ///
    /// This method handles the necessary shared memory locking and unlocking.
    ///
    /// \param  shm_if  Reference to the SharedMemoryIF that is the
    ///                 destination of the copy.
    ///
    /// \return  True on success, or false on error.
    virtual bool CopyToShm(SharedMemoryIF& shm_if)
    {
      LogE("BinIndexableArrayShm", __func__, "Cannot copy from shared memory "
           "to shared memory.\n");
      return false;
    }

    /// \brief Copy the entire array to shared memory.
    ///
    /// This method handles the necessary shared memory locking and unlocking.
    ///
    /// \param  shm_if  Reference to the SharedMemoryIF that is the source of
    ///                 the copy.
    ///
    /// \return  True on success, or false on error.
    virtual bool CopyFromShm(SharedMemoryIF& shm_if)
    {
      LogE("BinIndexableArrayShm", __func__, "Cannot copy from shared memory "
           "to shared memory.\n");
      return false;
    }

   protected:

    /// \brief Allocate the internal array.
    ///
    /// \return  True on success, or false on failure.
    virtual bool AllocateArray()
    {
      // The array is not dynamically allocated, it is set to point at the
      // shared memory in SetShmDirectAccess().
      return true;
    }

  }; // end class BinIndexableArrayShm

} // namespace iron

#endif // IRON_COMMON_BIN_INDEXABLE_ARRAY_SHM_H
