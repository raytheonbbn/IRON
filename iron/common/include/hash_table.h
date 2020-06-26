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

/// \brief The IRON hash table header file.
///
/// Provides the IRON software with an efficient, templated hash table
/// implementation.

#ifndef IRON_COMMON_HASH_TABLE_H
#define IRON_COMMON_HASH_TABLE_H

#include <cstdlib>


namespace iron
{

  /// \brief The template for a hash table.
  ///
  /// A collection template for storing key/value pairs and looking them up
  /// by the key very efficiently.  Supports storing multiple key/value pairs
  /// for a given key.  It is possible to walk all of the key/value pairs,
  /// although this may not be very efficient depending on the number of
  /// buckets in use.
  ///
  /// The number of buckets to be used in the hash table is specified when the
  /// hash table is initialized.  Each hash table instance includes an
  /// internal pool of storage objects to minimize memory allocations and
  /// deallocations.
  ///
  /// The key class K must have a copy constructor, an operator=() method, a
  /// fast operator==() method, and a fast Hash() method.  The Hash() method
  /// must take no arguments and return a size_t which is the hashed key.
  /// This class will limit the hashed key to the number of buckets using
  /// the modulus operator.  It is up to the user to appropriately match the
  /// Hash() method output with the number of buckets used in the hash table.
  ///
  /// The value class V may be a built-in type or a class.  If it is a class,
  /// then it must have a copy constructor and an operator=() method.  If it
  /// is a pointer to dynamically allocated memory, then the user of this
  /// template is responsible for the management of this memory -- the hash
  /// table does not take ownership of the memory and will not automatically
  /// delete it for the user.
  ///
  /// Both the key and value class destructors cannot be relied upon to manage
  /// external memory.  This template creates internal storage objects
  /// containing the keys and values, and these storage elements may be reused
  /// many times before being deleted.  Any necessary memory management must
  /// be handled by the user of this template.
  template <class K, class V>
  class HashTable
  {

    // Forward declaration of the internal element structure.
    struct HTElem;

   public:

    /// \brief A class for maintaining state while walking a hash table.
    ///
    /// An object of this class must be initialized using either the
    /// constructor or the PrepareForWalk() method in order to prepare for a
    /// walk of the hash table.  Once the WalkState object is initialized, two
    /// types of walks are possible.
    /// - Walk all of the key/value pairs in order to examine each one.\n
    ///   This is done by calling the GetNextPair() method repeatedly on the\n
    ///   hash table with the same WalkState object.  This walk may\n
    ///   optionally call the EraseCurrentPair() method in order to erase\n
    ///   the key/value pair that was just returned from the hash table.
    /// - Walk all of the key/value pairs in order to erase each one.  This\n
    ///   is done by calling the EraseNextPair() method repeatedly on the\n
    ///   hash table with the same WalkState object.  As each pair is\n
    ///   returned, it is automatically erased from the hash table.
    class WalkState
    {

     public:

      /// \brief The constructor.
      ///
      /// Either this constructor or the PrepareForWalk() method must be
      /// called before walking a hash table.
      inline WalkState()
          : walk_index_(0), walk_elem_(NULL)
      { }

      /// \brief The destructor.
      virtual ~WalkState()
      { }

      /// \brief Prepare the state for walking a hash table.
      ///
      /// Either the constructor or this method must be called before walking
      /// a hash table.
      inline void PrepareForWalk()
      {
        walk_index_ = 0;
        walk_elem_  = NULL;
      }

     private:

      /// The current bucket index for the walk.
      size_t   walk_index_;

      /// The current hash table element for the walk.
      HTElem*  walk_elem_;

      friend class HashTable;

    }; // end class WalkState

    /// \brief Constructor.
    HashTable()
        : size_(0), num_buckets_(0), buckets_(NULL), pool_(NULL)
    { }

    /// \brief Destructor.
    virtual ~HashTable()
    {
      if (buckets_ != NULL)
      {
        for (size_t i = 0; i < num_buckets_; ++i)
        {
          while (buckets_[i] != NULL)
          {
            HTElem*  e  = buckets_[i];
            buckets_[i] = e->next;
            delete e;
          }
        }

        delete [] buckets_;
        buckets_ = NULL;
      }

      while (pool_ != NULL)
      {
        HTElem*  e = pool_;
        pool_      = e->next;
        delete e;
      }

      size_        = 0;
      num_buckets_ = 0;
    }

    /// \brief Initialize the hash table.
    ///
    /// Each hash table must be initialized once before use.
    ///
    /// \param  num_buckets  The number of buckets to use in the hash table.
    ///                      Must be greater than 1.
    ///
    /// \return  Returns true on success, or false otherwise.
    bool Initialize(size_t num_buckets)
    {
      if ((buckets_ != NULL) || (num_buckets < 2))
      {
        return false;
      }

      buckets_ = new (std::nothrow) HTElem*[num_buckets];

      if (buckets_ == NULL)
      {
        return false;
      }

      for (size_t i = 0; i < num_buckets; ++i)
      {
        buckets_[i] = NULL;
      }

      size_        = 0;
      num_buckets_ = num_buckets;

      return true;
    }

    /// \brief Insert a new key/value pair into the hash table.
    ///
    /// Does not replace any existing key/value pairs with the same key.  Any
    /// existing pairs having the same key will not be lost by this
    /// insertion.
    ///
    /// \param  k  A reference to the key.
    /// \param  v  A reference to the value.
    ///
    /// \return  Returns true if the key/value pair was added successfully.
    bool Insert(const K& k, const V& v)
    {
      if (buckets_ == NULL)
      {
        return false;
      }

      HTElem*  e = NULL;

      if (pool_ == NULL)
      {
        e = new (std::nothrow) HTElem(k, v);

        if (e == NULL)
        {
          return false;
        }
      }
      else
      {
        e      = pool_;
        pool_  = e->next;
        e->key = k;
        e->val = v;
      }

      size_t   i = (k.Hash() % num_buckets_);
      HTElem*  b = buckets_[i];

      if (b != NULL)
      {
        b->prev = e;
      }

      e->next     = b;
      e->prev     = NULL;
      buckets_[i] = e;
      ++size_;

      return true;
    }

    /// \brief Find a value associated with a key in the hash table.
    ///
    /// If there are multiple key/value pairs with the specified key, it is
    /// not possible to know which value will be returned.
    ///
    /// \param  k  A reference to the key being requested.
    /// \param  v  A reference to a location where the value will be placed on
    ///            success.
    ///
    /// \return  Returns true if the key/value pair was found.  Does not
    ///          update v if false is returned.
    bool Find(const K& k, V& v) const
    {
      if (buckets_ != NULL)
      {
        size_t  i = (k.Hash() % num_buckets_);

        for (HTElem* e = buckets_[i]; e != NULL; e = e->next)
        {
          if (e->key == k)
          {
            v = e->val;

            return true;
          }
        }
      }

      return false;
    }

    /// \brief Find a value associated with a key in the hash table and remove
    ///        it.
    ///
    /// Using this method is more efficient than using the Find() method
    /// followed by the Erase() method.  However, it does not remove all
    /// key/value pairs with the specified key, as Erase() does.  This method
    /// only removes the key/value pair that is returned.
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
    /// \return  Returns true if the key/value pair was found and removed.
    bool FindAndRemove(const K& k, V& v)
    {
      if (buckets_ != NULL)
      {
        size_t  i = (k.Hash() % num_buckets_);

        for (HTElem* e = buckets_[i]; e != NULL; e = e->next)
        {
          if (e->key == k)
          {
            v = e->val;

            if (e->next != NULL)
            {
              e->next->prev = e->prev;
            }

            if (e->prev != NULL)
            {
              e->prev->next = e->next;
            }

            if (e == buckets_[i])
            {
              buckets_[i] = e->next;
            }

            e->next = pool_;
            e->prev = NULL;
            pool_   = e;
            --size_;

            return true;
          }
        }
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
      size_t  cnt = 0;

      if (buckets_ != NULL)
      {
        size_t  i = (k.Hash() % num_buckets_);

        for (HTElem* e = buckets_[i]; e != NULL; e = e->next)
        {
          if (e->key == k)
          {
            ++cnt;
          }
        }
      }

      return cnt;
    }

    /// \brief Erase all key/value pairs with the specified key.
    ///
    /// It is the caller's responsibility to free any dynamically allocated
    /// memory in the keys or values.
    ///
    /// \param  k  A reference to the key being erased.
    ///
    /// \return  The number of key/value pairs that were erased.
    size_t Erase(const K& k)
    {
      size_t  cnt = 0;

      if (buckets_ != NULL)
      {
        size_t   i = (k.Hash() % num_buckets_);
        HTElem*  e = buckets_[i];

        while (e != NULL)
        {
          if (e->key == k)
          {
            HTElem*  re = e;

            e = re->next;

            if (re->next != NULL)
            {
              re->next->prev = re->prev;
            }

            if (re->prev != NULL)
            {
              re->prev->next = re->next;
            }

            if (re == buckets_[i])
            {
              buckets_[i] = re->next;
            }

            re->next = pool_;
            re->prev = NULL;
            pool_   = re;

            ++cnt;
            --size_;
          }
          else
          {
            e = e->next;
          }
        }
      }

      return cnt;
    }

    /// \brief Walk the hash table, returning the next key/value pair found.
    ///
    /// The WalkState object must be initialized using either its constructor
    /// or its PrepareForWalk() method before making a series of calls to this
    /// method.  The EraseCurrentPair() method may be used during the walk
    /// with this method.  Calls to EraseNextPair() cannot be used during a
    /// walk with this method.  Any changes to the hash table during a walk,
    /// except for EraseCurrentPair(), will invalidate the walk.
    ///
    /// \param  ws  A reference to the walk state for this walk.
    /// \param  k   A reference to a location where the next key will be
    ///             placed on success.
    /// \param  v   A reference to a location where the next value will be
    ///             placed on success.
    ///
    /// \return  Returns true if another key/value pair was found and
    ///          returned.  The walk is complete when this method returns
    ///          false.
    bool GetNextPair(WalkState& ws, K& k, V& v)
    {
      if (buckets_ != NULL)
      {
        if (ws.walk_elem_ != NULL)
        {
          HTElem*  e = ws.walk_elem_->next;

          if (e != NULL)
          {
            k = e->key;
            v = e->val;

            ws.walk_elem_ = e;

            return true;
          }

          ws.walk_index_ += 1;
        }

        for (size_t i = ws.walk_index_; i < num_buckets_; ++i)
        {
          HTElem*  e = buckets_[i];

          if (e != NULL)
          {
            k = e->key;
            v = e->val;

            ws.walk_index_ = i;
            ws.walk_elem_  = e;

            return true;
          }
        }
      }

      return false;
    }

    /// \brief Erase the current key/value pair while walking the hash table
    ///        using GetNextPair().
    ///
    /// It is the caller's responsibility to free any dynamically allocated
    /// memory in the keys or values returned by GetNextPair().
    ///
    /// \param  ws  A reference to the walk state for this walk.
    void EraseCurrentPair(WalkState& ws)
    {
      if (buckets_ != NULL)
      {
        if (ws.walk_elem_ != NULL)
        {
          HTElem*  e = ws.walk_elem_;

          ws.walk_elem_ = e->prev;

          if (e->next != NULL)
          {
            e->next->prev = e->prev;
          }

          if (e->prev != NULL)
          {
            e->prev->next = e->next;
          }

          if (e == buckets_[ws.walk_index_])
          {
            buckets_[ws.walk_index_] = e->next;
          }

          e->next = pool_;
          e->prev = NULL;
          pool_   = e;
          --size_;
        }
      }
    }

    /// \brief Erase the next key/value pair, which is returned, while walking
    ///        the hash table.
    ///
    /// The WalkState object must be initialized using either its constructor
    /// or its PrepareForWalk() method before making a series of calls to this
    /// method.  Calls to GetNextPair() and EraseNextPair() cannot be mixed
    /// during a walk with this method.  Any changes to the hash table during
    /// this walk (except for the erasing that is performed as part of this
    /// method) will invalidate the walk.
    ///
    /// It is the caller's responsibility to free any dynamically allocated
    /// memory in the keys or values.
    ///
    /// \param  ws  A reference to the walk state for this walk.
    /// \param  k   A reference to a location where the next key will be
    ///             placed on success.
    /// \param  v   A reference to a location where the next value will be
    ///             placed on success.
    ///
    /// \return  Returns true if another key/value pair was found and removed.
    ///          The walk is complete when this method returns false.
    bool EraseNextPair(WalkState& ws, K& k, V& v)
    {
      if (buckets_ != NULL)
      {
        for (size_t i = ws.walk_index_; i < num_buckets_; ++i)
        {
          HTElem*  e = buckets_[i];

          if (e != NULL)
          {
            k = e->key;
            v = e->val;

            buckets_[i] = e->next;

            e->next = pool_;
            e->prev = NULL;
            pool_   = e;
            --size_;

            ws.walk_index_ = i;

            return true;
          }
        }

        ws.walk_index_ = num_buckets_;
      }

      return false;
    }

    /// \brief Clear the entire hash table of key/value pairs.
    ///
    /// It is the caller's responsibility to free any dynamically allocated
    /// memory in the keys or values.
    void Clear()
    {
      if (buckets_ != NULL)
      {
        for (size_t i = 0; i < num_buckets_; ++i)
        {
          while (buckets_[i] != NULL)
          {
            HTElem*  e  = buckets_[i];
            buckets_[i] = e->next;
            e->next     = pool_;
            e->prev     = NULL;
            pool_       = e;
          }
        }
      }

      size_ = 0;
    }

    /// \brief Test if the hash table is currently empty.
    ///
    /// \return  True if the hash table is currently empty.
    bool IsEmpty() const
    {
      return (size_ == 0);
    }

    /// \brief Get the current number of key/value pairs in the hash table.
    ///
    /// \return  The current number of key/value pairs in the hash table.
    size_t Size() const
    {
      return size_;
    }

    /// \brief Get the number of buckets used in the hash table.
    ///
    /// \return  The number of buckets used in the hash table.
    size_t NumBuckets() const
    {
      return num_buckets_;
    }

   private:

    /// \brief Copy constructor.
    HashTable(const HashTable&);

    /// \brief Copy operator.
    HashTable& operator=(const HashTable&);

    /// \brief An internal structure for the hash table elements.
    struct HTElem
    {
      HTElem(const K& k, const V& v)
          : key(k), val(v), next(NULL), prev(NULL)
      { }

      ~HTElem()
      {
        next = NULL;
        prev = NULL;
      }

      /// The hash table element key.
      K        key;

      /// The hash table element value.
      V        val;

      /// The next element in the bucket's doubly-linked list.
      HTElem*  next;

      /// The previous element in the bucket's doubly-linked list.
      HTElem*  prev;
    };

    /// The current number of key/value pairs in the hash table.
    size_t    size_;

    /// The number of buckets.
    size_t    num_buckets_;

    /// The buckets, which is an array of pointers to doubly-linked lists.
    HTElem**  buckets_;

    /// The pool of hash table elements for reuse in a singly-linked list.
    HTElem*   pool_;

  }; // end template HashTable

} // namespace iron

#endif // IRON_COMMON_HASH_TABLE_H
