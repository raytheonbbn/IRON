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

/// \brief The IRON mash table header file.
///
/// Provides the IRON software with an efficient, templated mash table
/// implementation.

#ifndef IRON_COMMON_MASH_TABLE_H
#define IRON_COMMON_MASH_TABLE_H


#include "hash_table.h"
#include "list.h"

#include <cstdlib>

namespace iron
{

  /// \brief The template for a Mash table.
  ///
  /// A collection template for storing key/value pairs, looking them up
  /// by the key very efficiently and iterating over all the pairs quickly.
  /// Internal to the MashTable is a HashTable for quick look-up and a
  /// LinkedList is maintained in tandem for quick iteration. The linked list
  /// can be optionally ordered. The MashTable Supports storing multiple 
  /// key/value pairs for a given key.
  ///
  /// The number of buckets to be used in the internal HashTable is specified
  /// when the MashTable is initialized.  Each MashTable instance includes an
  /// internal pool of storage objects to minimize memory allocations and
  /// deallocations.
  ///
  /// The key class K must have a copy constructor, an operator=() method, a
  /// fast operator==() method, and a fast Hash() method.  The Hash() method
  /// must take no arguments and return a size_t which is the hashed key.
  /// This class will limit the hashed key to the number of buckets using
  /// the modulus operator.  It is up to the user to appropriately match the
  /// Hash() method output with the number of buckets used in the mash table.
  ///
  /// The value class V may be a built-in type or a class.  If it is a class,
  /// then it must have a copy constructor and an operator=() method.  If it
  /// is a pointer to dynamically allocated memory, then the user of this
  /// template is responsible for the management of this memory -- the mash
  /// table does not take ownership of the memory and will not automatically
  /// delete it for the user.
  ///
  /// Both the key and value class destructors cannot be relied upon to manage
  /// external memory.  This template creates internal storage objects
  /// containing the keys and values, and these storage elements may be reused
  /// many times before being deleted.  Any necessary memory management must
  /// be handled by the user of this template.

  template <class K, class V>
  class MashTable
  {

    // Forward declaration of the internal element structure.
    struct MTElem;

   public:

    /// \brief A class for maintaining state while walking a mash table.
    ///
    /// An object of this class must be initialized using either the
    /// constructor or the PrepareForWalk() method in order to prepare for a
    /// walk of the mash table.
    /// This is to be used only for iterating the mash table and the
    /// the mash table should not be modified while walking. 
    /// Items should be removed based on key, rather that using the WalkState
    /// as a reference point.  
    class WalkState
    {

     public:

      /// \brief The constructor.
      ///
      /// Either this constructor or the PrepareForWalk() method must be
      /// called before walking a mash table.
      inline WalkState()
          : ll_walk_state_()
      { }

      /// \brief The destructor.
      virtual ~WalkState()
      { }

      /// \brief Prepare the state for walking a mash table.
      ///
      /// Either the constructor or this method must be called before walking
      /// a mash table.
      inline void PrepareForWalk()
      {
        ll_walk_state_.PrepareForWalk();
      }

     private:

      /// The WalkState of the internal LinkedList, which points to the current
      /// element in a walk of the LinkedList. 
      typename List<V>::WalkState  ll_walk_state_;

      friend class MashTable;

    }; // end class WalkState

    /// \brief Constructor.
    MashTable()
        : hash_table_(), linked_list_(), mte_pool_(NULL)
    { 
    }

    /// \brief Destructor.
    /// Frees all internal memory used to implement the mash table. 
    /// Does not free any memory used by the elements being stored 
    /// in the mash table.
    virtual ~MashTable()
    {
      typename HashTable<K, MTElem*>::WalkState ws;
      MTElem* mte = NULL;
      K k; 
      while (hash_table_.GetNextPair(ws, k, mte))
      {
        linked_list_.Remove(mte->llelem);
        delete mte->llelem;
        delete mte;
      }

      while (mte_pool_ != NULL)
      {
        MTElem*  e = mte_pool_;
        mte_pool_  = e->next;
        delete e;
      }
    }

    /// \brief Initialize the mash table.
    ///
    /// Each mash table must be initialized once before use.
    ///
    /// \param  num_buckets  The number of buckets to use in the mash table.
    ///                      Must be greater than 1.
    ///
    /// \return  True on success, or false otherwise.
    bool Initialize(size_t num_buckets)
    {
      return hash_table_.Initialize(num_buckets);
    }

    /// \brief Insert a new key/value pair into the mash table.
    ///
    /// Does not replace any existing key/value pairs with the same key.  Any
    /// existing pairs having the same key will not be lost by this
    /// insertion. The value object will be inserted at the tail of the 
    /// LinkedList.
    ///
    /// \param  k  A reference to the key.
    /// \param  v  A reference to the value.
    ///
    /// \return  True if the key/value pair was added successfully.
    bool Insert(const K& k, const V& v)
    {
      typename List<V>::LLElem* lle = linked_list_.GetLle(v);
      if (lle == NULL)
      {
        return false;
      }

      MTElem*  mte = NULL;

      if (mte_pool_ == NULL)
      {
        mte = new (std::nothrow) MTElem(lle, v);

        if (mte == NULL)
        {
          linked_list_.Recycle(lle);
          return false;
        }
      }
      else
      {
        mte          = mte_pool_;
        mte_pool_    = mte->next;
        mte->llelem  = lle;
        mte->val     = v;
        mte->next    = NULL;
      }

      if (hash_table_.Insert(k, mte))
      {
        linked_list_.Push(lle);
        return true;
      }
      linked_list_.Recycle(lle);
      mte->next = mte_pool_;
      mte_pool_ = mte;
      return false;
    }

    /// \brief Find a value associated with a key in the mash table.
    ///
    /// If there are multiple key/value pairs with the specified key, it is
    /// not possible to know which value will be returned.
    ///
    /// \param  k  A reference to the key being requested.
    /// \param  v  A reference to a location where the value will be placed on
    ///            success.
    ///
    /// \return  True if the key/value pair was found.  Does not
    ///          update v if false is returned.
    bool Find(const K& k, V& v) const
    {
      MTElem* mte = NULL;
      if (hash_table_.Find(k,mte))
      {
        if (mte != NULL)
        {
          v = mte->val;
          return true;
        }
      }
      return false;
    }

    /// \brief Find a value associated with a key in the mash table and remove
    ///        it.
    ///
    /// Using this method does not remove all key/value pairs with the 
    /// specified key.  This method only removes the key/value pair that is 
    /// returned.
    ///
    /// If there are multiple key/value pairs with the specified key, it is
    /// not possible to know which value will be returned and removed.
    ///
    /// It is the caller's responsibility to free any dynamically allocated
    /// memory in the keys or values.
    ///
    /// \param  k  A reference to the key being requested.
    /// \param  v  A reference to a location where the value will be placed on
    ///            success.
    ///
    /// \return  True if the key/value pair was found and removed.
    bool FindAndRemove(const K& k, V& v)
    {
      MTElem* mte = NULL;
      if (hash_table_.FindAndRemove(k, mte))
      {
        linked_list_.Remove(mte->llelem);
        v = mte->val;
        linked_list_.Recycle(mte->llelem);
        mte->next = mte_pool_;
        mte_pool_ = mte;
        return true;
      }

      return false;        
    }

    /// \brief Get the number of key/value pairs with the specified key.
    ///
    /// \param  k  A reference to the key being requested.
    ///
    /// \return  The number of key/value pairs with the specified key.
    size_t Count(const K& k) const
    {
      return hash_table_.Count(k);
    }

    /// \brief Walk the mash table, returning the next value found.
    ///
    /// The WalkState object must be initialized using either its constructor
    /// or its PrepareForWalk() method before making a series of calls to this
    /// method. Any changes to the mash table during a walk, will invalidate 
    /// the walk.
    ///
    /// \param  ws  A reference to the walk state for this walk.
    /// \param  v The object that was popped.
    ///
    /// \return True if an object was just found, false otherwise.
    ///         The walk is complete when this method returns false.
    inline bool GetNextItem(WalkState& ws, V& v) const
    {
      return linked_list_.GetNextItem(ws.ll_walk_state_, v);
    }

    /// \brief Clear the mash table.
    ///
    /// It is the caller's responsibility to free any dynamically allocated
    /// memory in the keys or values.
    void Clear()
    {
      typename HashTable<K, MTElem*>::WalkState ws;
      MTElem* mte = NULL;
      K k; 
      while (hash_table_.GetNextPair(ws, k, mte))
      {
        linked_list_.Remove(mte->llelem);
        linked_list_.Recycle(mte->llelem);
        mte->next = mte_pool_;
        mte_pool_ = mte;
        hash_table_.EraseCurrentPair(ws);
      }
    }

    /// \brief Test if the mash table is currently empty.
    ///
    /// \return  True if the mash table is currently empty.
    bool Empty() const
    {
      return (linked_list_.size_ == 0);
    }

    /// \brief Get the current number of key/value pairs in the mash table.
    ///
    /// \return  The current number of key/value pairs in the mash table.
    size_t size() const
    {
      return linked_list_.size_;
    }

    /// \brief Get the number of buckets used in the internal mash table.
    ///
    /// \return  The number of buckets used in the internal mash table.
    size_t GetNumBuckets() const
    {
      return hash_table_.NumBuckets();
    }

   private:

    /// \brief Copy constructor.
    MashTable(const MashTable&);

    /// \brief Copy operator.
    MashTable& operator=(const MashTable&);

    /// \brief An internal structure for the mash table elements.
    struct MTElem
    {
      MTElem(typename List<V>::LLElem* lle, const V& v)
          : val(v), llelem(lle), next(NULL)
      { }

      ~MTElem()
      { }

      /// The mash table element value.
      V                         val;

      /// LinkedList element for this value.
      typename List<V>::LLElem* llelem;

      /// A pointer to another MTElem in the pool of recycled MTElems.
      MTElem*                   next;
    };

    /// The hash table. 
    HashTable<K, MTElem*> hash_table_; 

    /// The LinkedList.
    List<V>               linked_list_;

    /// The pool of mash table elements for reuse in a singly-linked list.
    MTElem*               mte_pool_;

  }; // end template MashTable

} // namespace iron

#endif // IRON_COMMON_MASH_TABLE_H
