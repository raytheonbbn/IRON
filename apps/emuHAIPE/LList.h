/* IRON: iron_headers */
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
#ifndef LList_h
#define LList_h

#include <pthread.h>

#include "LListElem.h"

/**
 * \class LList
 * \ingroup common
 * 
 * Doubly linked list of elements.
 *
 * User defined object that are to be added to this linked list MUST inherit
 * from the LListElem base class, which provides all of the logic to link
 * elements together. Elements that are added to the linked list are owned by
 * the linked list. When an element is unlinked, the calling object assumes
 * ownership for the element's memory. 
 * 
 * Note that an element can only be part of one linked list at a time. If
 * there is a need to add a user defined object to more than one linked list,
 * the object implementation should not inherit from the LListElem base
 * class. Rather, the object should be wrapped in a special wrapper object
 * that does inherit from the LListElem base class. In this example, there
 * would be multiple wrapper classes, each of which has a reference to the
 * user defined object to be placed in the various linked lists.
 *
 * This class is thread-safe. As a result, the LListElem class does not have
 * to be thread-safe.
 * 
 */
class LList
{
public:

  /**
   * Default no-arg constructor.
   */
  LList();

  /**
   * Destructor.
   */
  virtual ~LList();

  /**
   * Return the number of elements in the linked-list
   */
  int size() const;

  /**
   * Add an element to the head of the linked list.
   *
   * @param elem The element to be added to the head of the linked list.
   */
  void addToHead(LListElem* elem);
  
  /**
   * Add an element to the tail of the linked list.
   *
   * @param elem The element to be added to the tail of the linked list.
   */
  void addToTail(LListElem* elem);

  /**
   * Get the element that is at the head of the linked list.
   *
   * @return Pointer to the element that is at the head of the linked list, or
   *         NULL if the linked list is empty.
   */
  LListElem* getHead();

  /**
   * Get the element that is at the head of the linked list.
   *
   * @return Pointer to the element that is at the head of the linked list, or
   *         NULL if the linked list is empty.
   */
  const LListElem* getHead() const;

  /**
   * Get the element that is at the tail of the linked list.
   *
   * @return Pointer to the element that is at the tail of the linked list, or
   *         NULL if the linked list is empty.
   */
  LListElem* getTail();

  /**
   * Get the element that is at the tail of the linked list.
   *
   * @return Pointer to the element that is at the tail of the linked list, or
   *         NULL if the linked list is empty.
   */
  const LListElem* getTail() const;

  /**
   * Insert an element into the linked list before the specified element.
   *
   * @param beforeElem  The element that the new element is to be inserted
   *                    before.
   * @param newElem     The element to be added to the linked list.
   */
  void insertBefore(LListElem* beforeElem, LListElem* newElem);

  /**
   * Remove the element that is at the head of the linked list. The element
   * will no longer be part of the linked list following this call. Also note
   * that when this method is invoked memory ownership of the object at the
   * head of the linked list is passed to the calling object (e.g., the caller
   * is responsible for deleting the element's memory of for passing ownership
   * on to another object).
   *
   * @return The element at the head of the linked list, or NULL if the linked
   *         list is empty.
   */
  LListElem* removeFromHead();

  /**
   * Remove the element that is at the tail of the linked list. The element
   * will no longer be part of the linked list following this call. Also note
   * that when this method is invoked memory ownership of the object at the
   * tail of the linked list is passed to the calling object (e.g., the caller
   * is responsible for deleting the element's memory of for passing ownership
   * on to another object).
   *
   * @return The element at the tail of the linked list, or NULL if the linked
   *         list is empty.
   */
  LListElem* removeFromTail();
  
  /**
   * Removes the element from the linked list. The element is not
   * destroyed. Rather, the element's linkages are broken so that it is no
   * longer a part of the linked list. Note that after this method is invoked,
   * memory ownership is passed to the calling object (e.g., the caller is
   * responsible for deleting the element's memory or for passing ownership on
   * to another object). 
   *
   * @param elem The element that is to be unlinked from the linked list.
   */
  void unlink(LListElem* elem);

private:

  /**
   * The head of the linked list.
   */
  LListElem*      head;
  
  /**
   * The tail of the linked list.
   */
  LListElem*      tail;

  /**
   * Mutex that protects modifications to the linkage of the linked list.
   */
  volatile pthread_mutex_t mutex;

  /**
   * Thread safe method to unlink an element in the linked list.
   *
   * @param elem The element to be unlinked from the linked list.
   */
  void lockedUnlink(LListElem* elem);

}; // end class LList

#endif // LList_h
