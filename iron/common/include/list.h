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

/// \brief The IRON non-ordered list header file.
///
/// Provides the IRON software with an efficient, templated non-ordered linked
/// list implementation.

#ifndef IRON_COMMON_LIST_H
#define IRON_COMMON_LIST_H

#include "stdio.h"
#include <string>

namespace iron
{
  /// \brief  The templated non-ordered Linked List class.  
  ///
  /// The linked list is not ordered.  Items should
  /// be added using the Push(), and pulled out using Peek() / Pop() for FIFO
  /// operation.  Use Push(), Peek() and PopBack() for LIFO operation.
  ///
  /// The item class destructors cannot be relied upon to manage
  /// external memory.  This template creates internal storage objects
  /// and manages the memory used by these internal storage objects.  
  /// Any necessary memory management of the items stored in the List
  /// must be handled by the user of this template.
  template <class C>
  class List
  {
    /// The link element definition.
    struct LLElem
    {
      /// Default constructor.
      LLElem(const C& c)
        : element(c), prev(NULL), next(NULL) { }

      /// The destructor.  It does not free the element.
      ~LLElem()
      {
        prev     = NULL;
        next     = NULL;
      }

      /// The element stored in the link.
      C       element;

      /// A pointer to the previous element.
      LLElem* prev;

      /// A pointer to the next element.
      LLElem* next;
      
    };

  public:
    /// \brief  A class for maintaining state while walking the linked list.
    ///
    /// An object of this class must be initialized using either the
    /// constructor or the PrepareForWalk() method in order to prepare for a
    /// walk of the linked list.  Once the WalkState object is initialized, walk
    /// all of the links in order to examine each one.
    /// This is done by calling the GetNextItem() method repeatedly on the
    /// linked list with the same WalkState object.
    class WalkState
    {
    public:
      /// \brief  Default constructor / initializer.
      inline WalkState()
        : walk_elem_(NULL)
      { }

      /// \brief  Copy constructor.
      inline WalkState(const WalkState& other)
      {
        walk_elem_  = other.walk_elem_;
      }

      /// Default destructor.
      virtual ~WalkState()
      { 
        walk_elem_  = NULL;
      }

      /// \brief  Check if the walk state is NULL as would happen if prepared 
      ///         by not started yet or at the end of the walk.
      ///
      /// \return True if NULL, false otherwise.
      inline bool IsNULL()
      {
        return walk_elem_ == NULL;
      }

      /// \brief Prepare the state for walking a hash table.
      ///
      /// Either the constructor or this method must be called before walking
      /// a linked list.
      inline void PrepareForWalk()
      {
        walk_elem_  = NULL;
      }

      /// \brief  Assignment operator.
      ///
      /// \param  other The other walkstate object to copy from.
      ///
      /// \return A reference to this object.
      WalkState& operator=(const WalkState& other)
      {
        if (this != &other)
        {
          walk_elem_  = other.walk_elem_;
        }
        return *this;
      }

      /// \brief  Equivalence operator.
      ///
      /// \param  other The other walk state object to compare to.
      ///
      /// \return True if same object, false otherwise.
      bool operator==(const WalkState& other) const
      {
        return walk_elem_ == other.walk_elem_;
      }

    private:
      /// The current link along the linked list in the walk.
      LLElem* walk_elem_;

      friend class List;
    };  // End WalkState

    /// \brief  The default constructor.
    List() : head_(NULL), tail_(NULL), size_(0), pool_(NULL) { }

    /// \brief  The default destructor.
    /// NOTE: It does NOT free / delete elements stored or pointed to in the
    ///       links.
    virtual ~List()
    {
      while (head_)
      {
        LLElem* next = head_->next;
        delete head_;
        head_ = next;
      }

      while (pool_ != NULL)
      {
        LLElem*  e = pool_;
        pool_  = e->next;
        delete e;
      }

      tail_ = NULL;
      size_ = 0;
    }

    /// \brief  Clear the list.
    /// NOTE: It does NOT free / delete elements stored or pointed to in the
    ///       links.
    inline void Clear()
    {
      while (head_)
      {
        LLElem* next = head_->next;
        Recycle(head_);
        head_ = next;
      }

      head_ = NULL;
      tail_ = NULL;
      size_ = 0;
    }

    /// \brief  The method to append a new item to the list.
    ///
    /// It does not take ownership of any memory in the element.
    /// The element is inserted at the tail of the list.
    /// 
    /// \param  element A reference to the element to store.
    ///
    /// \return true if success inserting, false otherwise.
    inline bool Push(const C& element)
    {
      LLElem* e = GetLle(element);
      if (e == NULL)
      {
        return false;
      }
      Push(e);
      return true;
    }

    /// \brief  The method to remove an item from the head of the list.
    ///
    /// It leaves ownership with the caller.
    ///
    /// \param  c The object that was popped.
    ///
    /// \return True if an object was just dequeued, false otherwise.
    inline bool Pop(C& c)
    {
      if (head_)
      {
        LLElem* e = head_;
        c         = e->element;

        Remove(e);
        Recycle(e);

        return true;
      }
      return false;
    }

    /// \brief  Pop the last element.
    ///
    /// \param  c The object that was popped.
    ///
    /// \return True if an object was just dequeued, false otherwise.
    inline bool PopBack(C& c)
    {
      if (tail_)
      {
        LLElem* e = tail_;
        c         = e->element;
    
        Remove(e);
        Recycle(e);

        return true;
      }
      return false;
    }

    /// \brief  Pop the element at a given location.
    /// This method will move the walk state to the element preceding the one 
    /// popped.
    ///
    /// \param  ws  The walk state indicating where to dequeue the element.
    /// \param  c The object that was popped.
    ///
    /// \return True if an object was just dequeued, false otherwise.
    inline bool PopAt(WalkState& ws, C& c)
    {
      LLElem* e = ws.walk_elem_;

      if (!e || (size_ == 0))
      {
        // If WS is invalid or this is called when we have no element.
        return false;
      }
    
      c             = e->element;
      ws.walk_elem_ = e->prev;

      Remove(e);
      Recycle(e);
      return true;
    }

    /// \brief  Get the next link along a walk.
    ///
    /// The walk state will advance by one element and look there.
    ///
    /// \param  ws  The walk state, which must have been initialized through
    ///             constructor or PrepareForWalk method.
    /// \param  c The object that was peeked.
    ///
    /// \return True if an object was just peeked, false otherwise.
    inline bool GetNextItem(WalkState& ws, C& c) const
    {
      if (ws.walk_elem_)
      {
        LLElem* e = ws.walk_elem_->next;
        if (e)
        {
          ws.walk_elem_ = e;
          c             = e->element;
          return true;
        }
      }
      else if (head_)
      {
        ws.walk_elem_ = head_;
        c             = head_->element;
        return true;
      }
      return false;
    }

    /// \brief  Peek the element at the head of the list.
    ///
    /// \param  c The object that was peeked.
    ///
    /// \return True if an object was just peeked, false otherwise.
    inline bool Peek(C& c)
    {
      if (size_ > 0)
      {
        c = head_->element;
        return true;
      }

      return false;
    }

    /// \brief  Peek the element at the tail of the list.
    ///
    /// \param  c The object that was peeked.
    ///
    /// \return True if an object was just peeked, false otherwise.
    inline bool PeekBack(C& c)
    {
      if (size_ > 0)
      {
        c = tail_->element;
        return true;
      }

      return false;
    }

    /// \brief  Peek the element at a given location.
    ///
    /// \param  ws  The walk state indicating where to dequeue the element.
    /// \param  c The object that was peeked.
    ///
    /// \return True if an object was just peeked, false otherwise.
    inline bool PeekAt(WalkState& ws, C& c)
    {
      if (!ws.walk_elem_ || (size_ == 0))
      {
        // If WS is invalid or this is called when we have no element.
        return false;
      }

      c = ws.walk_elem_->element;
      return true;
    }

    /// \brief  Check if an element is in the list.
    ///
    /// \param c The element being searched for.
    ///
    /// \return True if the element is found, false otherwise.
    inline bool IsMember(const C& c)
    {
      LLElem* e = Find(c);
      if (e != NULL)
      {
        return true;
      }
      return false;
    }
 
    /// \brief  Remove an element from the linked list.
    ///         
    /// If the element owns memory, this method does not free the 
    /// memory. It is up to the calling function to free the memory.
    ///
    /// \param  c The element to be removed.
    ///
    /// \return true if the element was found and removed, false otherwise.
    inline bool Remove(const C& c)
    {
      LLElem* e = Find(c);
      if (e != NULL)
      {
        Remove(e);
        Recycle(e);
        return true;
      }
      return false;
    }

    /// \brief  Remove an element along the linked list during a walk.
    ///
    /// If the element owns memory, this method does not free the 
    /// memory. It is up to the calling function to free the memory.
    /// Walk State, ws, will point to the previous element in the list
    /// after the element has been removed.   
    ///
    /// \param  ws  The walk state, which must have been initialized through 
    ///             constructor or PrepareForWalk method. It will point to the 
    ///             previous element in the list.
    ///
    /// \return true if the element was found and removed, false otherwise.
    inline bool RemoveInPlace(WalkState& ws)
    {
      LLElem* e = ws.walk_elem_;
      if (!e)
      {
        return false;
      }
      ws.walk_elem_ = ws.walk_elem_->prev;
      Remove(e);
      Recycle(e);
      return true;
    }

    /// \brief  Check if list is empty.
    ///
    /// \return True if empty, false otherwise.
    inline bool Empty() { return size_ == 0; };

    /// \brief Get the size of the linked list.
    ///
    /// \return The number of elements in the linked list.
    inline size_t size() { return size_; }

  private:
    /// \brief Copy constructor.
    List(const List&);

    /// \brief Copy operator.
    List& operator=(const List&);

    /// \brief  The method to append an LLElem to the linked list.
    ///
    /// It does not take ownership of any memory in the element.
    /// The element is inserted at the tail of the list.
    /// 
    /// \param  e A pointer to the element to store.
    inline void Push(LLElem* e)
    {
      if (!tail_)
      {
        head_ = e;
        tail_ = e;
      }
      else
      {
        tail_->next  = e;
        e->prev      = tail_;
        tail_        = e;
      }
      size_++;
    }

    /// \brief  Remove the first copy of an element from the linked list.
    ///         
    ///         The LLElem is not deleted, the calling function should
    ///         free the LLElem object if it is no longer in use.        
    ///
    /// \param  e The element to be removed.
    inline void Remove(LLElem* e)
    {
      if (e == head_)
      {
        head_ = e->next;
      }

      if (e == tail_)
      {
        tail_ = e->prev;
      }

      if (e->next)
      {
        e->next->prev = e->prev;
      }

      if (e->prev)
      {
        e->prev->next = e->next;
      }
      size_--;
      e->prev = NULL;
      e->next = NULL;
    }

    /// \brief Get the first LLElem for an element.
    /// 
    /// \param c The object being searched for. 
    /// 
    /// \return A pointer to the LLElem containing the object or NULL
    ///         if the object was not found.
    inline LLElem* Find(const C& c)
    {
      for (LLElem* e  = head_; e != NULL; e = e->next)
      {
        if (e->element == c)
        {
          return e;
        }
      }
      return NULL;
    }      

    /// \brief Get a new LLElem, either from the pool or a new allocation. 
    ///
    /// \return A pointer to an unused LLElem or NULL if a new element could
    ///         not be allocated. 
    inline LLElem* GetLle(const C& c)
    {
      LLElem*  e = NULL;

      if (pool_ == NULL)
      {
        e = new (std::nothrow) LLElem(c);
      }
      else
      {
        e          = pool_;
        pool_      = e->next;
        e->element = c;
        e->prev    = NULL;
        e->next    = NULL;
      }
      return e;
    }

    // \brief Return an LLElem to the pool for reuse.
    // \param e An unused LLElem which is to be recycled.
    inline void Recycle(LLElem* e)
    {
      e->next  = pool_;
      e->prev  = NULL;
      pool_    = e;
    }

    /// A pointer to the head of the linked list.
    LLElem* head_;

    /// A pointer to the tail of the linked list.
    LLElem* tail_;

    /// The number of elements in the linked list.
    size_t  size_;

    /// A pool for reusing LLElems.
    LLElem* pool_;

    template<class K, class V> friend class MashTable;
  };  // End List.

} // namespace iron.
#endif  // IRON_COMMON_LIST
