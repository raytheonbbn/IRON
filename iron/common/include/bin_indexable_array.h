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

/// \brief The IRON bin indexable array header file.
///
/// Provides the IRON software with a simple array of copyable objects that is
/// accessible using a single, common, bin index as provided by the BinMap.

#ifndef IRON_COMMON_BIN_INDEXABLE_ARRAY_H
#define IRON_COMMON_BIN_INDEXABLE_ARRAY_H

#include "bin_map.h"
#include "log.h"
#include "shared_memory_if.h"

namespace iron
{
  /// \brief Templated Bin Indexable Array class.
  ///
  /// Initialize by calling Initialize() passing the BinMap object.
  template <class C>
  class BinIndexableArray
  {

   public:

    /// \brief Constructor.
    BinIndexableArray()
        : init_flag_(false),
          array_(NULL),
          idx_offset_0_(0),
          size_0_(0),
          idx_offset_1_(0),
          size_1_(0),
          idx_offset_2_(0),
          size_2_(0),
          null_elem_()
    {
      return;
    }

    /// \brief Destructor.
    virtual ~BinIndexableArray()
    {
      if (array_ != NULL)
      {
        delete [] array_;
        array_ = NULL;
      }
    }

    /// \brief Initialize the object.
    ///
    /// \param  bin_map  Reference to the BinMap.
    ///
    /// \return  True on success, or false on error.
    virtual bool Initialize(BinMap& bin_map)
    {
      if (init_flag_)
      {
        LogE("BinIndexableArray", __func__, "Already initialized.\n");
        return false;
      }

      idx_offset_0_ = bin_map.ucast_bin_idx_offset();
      size_0_       = bin_map.max_num_ucast_bin_idxs();
      idx_offset_1_ = bin_map.int_bin_idx_offset();
      size_1_       = bin_map.max_num_int_bin_idxs();
      idx_offset_2_ = bin_map.mcast_bin_idx_offset();
      size_2_       = bin_map.max_num_mcast_bin_idxs();

      if (((size_0_ + size_1_ + size_2_) < 1) ||
          (idx_offset_1_ < (idx_offset_0_ + size_0_)) ||
          (idx_offset_2_ < (idx_offset_1_ + size_1_)))
      {
        LogE("BinIndexableArray", __func__, "Invalid ranges: %" PRIBinIndex
             " - %zu, %" PRIBinIndex " - %zu, %" PRIBinIndex " - %zu\n",
             idx_offset_0_, (idx_offset_0_ + size_0_ - 1), idx_offset_1_,
             (idx_offset_1_ + size_1_ - 1), idx_offset_2_,
             (idx_offset_2_ + size_2_ - 1));
        return false;
      }

      if (!AllocateArray())
      {
        LogE("BinIndexableArray", __func__, "Array allocation error, size "
             "%zu elements.\n", (size_0_ + size_1_ + size_2_));
        return false;
      }

      init_flag_ = true;

      return true;
    }

    /// \brief Check if the array has been initialized.
    ///
    /// \return  True if the array has been initialized, or false otherwise.
    virtual bool IsInitialized() const
    {
      return init_flag_;
    }

    /// \brief Get the size of the internal array in bytes.
    ///
    /// Must be called after initialization succeeds.
    ///
    /// \return  The number of bytes used by the internal array on success, or
    ///          zero if not initialized yet.
    virtual size_t GetMemorySizeInBytes() const
    {
      return (init_flag_ ? ((size_0_ + size_1_ + size_2_) * sizeof(C)) : 0);
    }

    /// \brief Clear all arrays with the specified value.
    ///
    /// \param  val  A reference to the value used in clearing all elements.
    virtual void Clear(const C& val)
    {
      if ((init_flag_) && (array_ != NULL))
      {
        size_t  total_size = (size_0_ + size_1_ + size_2_);

        for (size_t i = 0; i < total_size; ++i)
        {
          array_[i] = val;
        }

        null_elem_ = val;
      }
    }

    /// \brief Overloaded [] operator for non-const objects.
    ///
    /// \param  index  The bin index of the desired element.
    ///
    /// \return  Reference to the array element for the bin index.
    virtual C& operator [](BinIndex index)
    {
      if ((init_flag_) && (array_ != NULL))
      {
        if ((index >= idx_offset_0_) && (index < (idx_offset_0_ + size_0_)))
        {
          return array_[index - idx_offset_0_];
        }
        else if ((index >= idx_offset_1_) &&
                 (index < (idx_offset_1_ + size_1_)))
        {
          return array_[size_0_ + index - idx_offset_1_];
        }
        else if ((index >= idx_offset_2_) &&
                 (index < (idx_offset_2_ + size_2_)))
        {
          return array_[size_0_ + size_1_ + index - idx_offset_2_];
        }
        else
        {
          LogW("BinIndexableArray", __func__, "Index (%" PRIBinIndex
               ") is out of bounds. Valid index ranges: %" PRIBinIndex
               " - %zu, %" PRIBinIndex " - %zu, %" PRIBinIndex " - %zu\n",
               index, idx_offset_0_, (idx_offset_0_ + size_0_ - 1),
               idx_offset_1_, (idx_offset_1_ + size_1_ - 1), idx_offset_2_,
               (idx_offset_2_ + size_2_ - 1));
        }
      }
      else
      {
        LogE("BinIndexableArray", __func__, "Not initialized yet.\n");
      }

      return null_elem_;
    }

    /// \brief Overloaded [] operator for const objects.
    ///
    /// \param  index  The bin index of the desired element.
    ///
    /// \return  Reference to the array element for the bin index.
    virtual const C& operator [](BinIndex index) const
    {
      if ((init_flag_) && (array_ != NULL))
      {
        if ((index >= idx_offset_0_) && (index < (idx_offset_0_ + size_0_)))
        {
          return array_[index - idx_offset_0_];
        }
        else if ((index >= idx_offset_1_) &&
                 (index < (idx_offset_1_ + size_1_)))
        {
          return array_[size_0_ + index - idx_offset_1_];
        }
        else if ((index >= idx_offset_2_) &&
                 (index < (idx_offset_2_ + size_2_)))
        {
          return array_[size_0_ + size_1_ + index - idx_offset_2_];
        }
        else
        {
          LogW("BinIndexableArray", __func__, "Index (%" PRIBinIndex
               ") is out of bounds. Valid index ranges: %" PRIBinIndex
               " - %zu, %" PRIBinIndex " - %zu, %" PRIBinIndex " - %zu\n",
               index, idx_offset_0_, (idx_offset_0_ + size_0_ - 1),
               idx_offset_1_, (idx_offset_1_ + size_1_ - 1), idx_offset_2_,
               (idx_offset_2_ + size_2_ - 1));
        }
      }
      else
      {
        LogE("BinIndexableArray", __func__, "Not initialized yet.\n");
      }

      return null_elem_;
    }

    /// \brief Copy the entire array to shared memory.
    ///
    /// This method handles the necessary shared memory locking and unlocking.
    ///
    /// \param  shm_if  Reference to the SharedMemoryIF that is the
    ///                 destination of the copy.
    ///
    /// \return  True on success, or false on error.
    virtual bool CopyToShm(SharedMemoryIF& shm_if) const
    {
      return shm_if.CopyToShm(reinterpret_cast<uint8_t*>(array_),
                              ((size_0_ + size_1_ + size_2_) * sizeof(C)), 0);
    }

    /// \brief Copy the entire array from shared memory.
    ///
    /// This method handles the necessary shared memory locking and unlocking.
    ///
    /// \param  shm_if  Reference to the SharedMemoryIF that is the source of
    ///                 the copy.
    ///
    /// \return  True on success, or false on error.
    virtual bool CopyFromShm(SharedMemoryIF& shm_if)
    {
      return shm_if.CopyFromShm(reinterpret_cast<uint8_t*>(array_),
                                ((size_0_ + size_1_ + size_2_) * sizeof(C)),
                                0);
    }

   protected:

    /// \brief Allocate the internal array.
    ///
    /// \return  True on success, or false on failure.
    virtual bool AllocateArray()
    {
      array_ = new (std::nothrow) C[size_0_ + size_1_ + size_2_];

      return (array_ != NULL);
    }

    /// The flag recording if the object is initialized or not.
    bool      init_flag_;

    /// The common array of elements.
    C*        array_;

   private:

    /// \brief Copy constructor.
    BinIndexableArray(const BinIndexableArray& a);

    /// \brief Copy operator.
    BinIndexableArray& operator=(const BinIndexableArray& a);

    /// Index offset of the first group of elements in the array.
    BinIndex  idx_offset_0_;

    /// Maximum size of the first group of elements in the array.
    size_t    size_0_;

    /// Index offset of the second group of elements in the array.
    BinIndex  idx_offset_1_;

    /// Maximum size of the second group of elements in the array.
    size_t    size_1_;

    /// Index offset of the third group of elements in the array.
    BinIndex  idx_offset_2_;

    /// Maximum size of the third group of elements in the array.
    size_t    size_2_;

    /// The NULL element to return when the "search" index is out of bounds.
    C         null_elem_;

  }; // end class BinIndexableArray

} // namespace iron

#endif // IRON_COMMON_BIN_INDEXABLE_ARRAY_H
