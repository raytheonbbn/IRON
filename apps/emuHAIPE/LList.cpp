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
#include <stdio.h>

#include "LList.h"
#include "ZLog.h"


//
// Class name to use in logging output.
//

static const char cn[] = "LList";


//============================================================================
LList::LList()
{

  //
  // Initialize the mutex that will protect the linked list.  The call never
  // fails.
  //
  pthread_mutex_init((pthread_mutex_t*)&mutex, NULL);

  //
  // Initially, the head and tail of the linked list are NULL.
  //
  
  head = NULL;
  tail = NULL;
}

//============================================================================
LList::~LList()
{
  LListElem* delElem;

  //
  // We will unlink and delete all objects stored in the linked list. We will
  // simply iteratively unlink and delete the head of the linked list until it
  // is NULL. We must remember the head element because unlink will modify
  // it.
  //

  delElem = head;
  
  while (delElem != NULL)
  {

    // 
    // Unlink the element and destroy it. Then get the next element to unlink
    // and delete. Note that this will lock the class mutex, but that should
    // be OK.
    //
    
    unlink(delElem);
    delete delElem;
    delElem = head;
  }

  //
  // Finally, we destroy the linked list mutex.
  //

  pthread_mutex_destroy((pthread_mutex_t*)&mutex);
}

//============================================================================

int LList::size() const
{
  int e = 0;
  const LListElem* elem = getHead();
  while (elem != NULL)
  {
    e++;
    elem = elem->getNext();
  }
  return e;
}

//============================================================================
void
LList::addToHead(LListElem* elem)
{
  static const char mn[] = "addToHead";
  
  if (elem == NULL)
  {
    return;
  }
  
  //
  // Lock the mutex because we will be changing the state of the linked list.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  if (elem->llist != NULL)
  {

    //
    // Remove element from linked list that it is currently a part of because
    // linked list does not allow LListElems to be in more than one linked
    // list at a time. If desired, build a wrapper around object to be placed
    // in multiple linked lists.
    //

    zlogW(cn, mn, ("Warning: Element part of different linked list. Element "
                   "is being removed from previous list.\n"));
    
    if (elem->llist == this)
    {

      //
      // We do this because we are unlinking from our linked list and we
      // already have the mutex locked.
      //

      elem->llist->lockedUnlink(elem);
    }
    else
    {

      //
      // To protect against a possible deadlock situation here, we unlock the
      // mutex prior to unlinking the element from another linked list. We
      // will lock it again following the unlink.
      //
      
      pthread_mutex_unlock((pthread_mutex_t*)&mutex);
      
      elem->llist->unlink(elem);

      pthread_mutex_lock((pthread_mutex_t*)&mutex);
    }
  }

  if (head == NULL)
  {

    //
    // This is the first element added to the linked list. We must adjust tail
    // also.
    //

    head = elem;
    tail = head;
  }
  else
  {

    //
    // The linked list is not empty, so we simply add the element to the head
    // of it.
    //

    elem->next = head;
    head->prev = elem;
    head       = elem;
  }
  
  //
  // Set the linked list that the element is a part of.
  //

  elem->llist = this;

  //
  // Finally, we unlock the mutex.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);
}

//============================================================================
void
LList::addToTail(LListElem* elem)
{
  static const char mn[] = "addToTail";
  
  if (elem == NULL)
  {
    return;
  }
  
  //
  // Lock the mutex because we will be changing the state of the linked list.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  if (elem->llist != NULL)
  {

    //
    // Remove element from linked list that it is currently a part of because
    // linked list does not allow LListElems to be in more than one linked
    // list at a time. If desired, build a wrapper around object to be placed
    // in multiple linked lists.
    //

    zlogW(cn, mn, ("Warning: Element part of different linked list. Element "
                   "is being removed from previous list.\n"));
    
    if (elem->llist == this)
    {

      //
      // We do this because we are unlinking from our linked list and we
      // already have the mutex locked.
      //

      elem->llist->lockedUnlink(elem);
    }
    else
    {

      //
      // To protect against a possible deadlock situation here, we unlock the
      // mutex prior to unlinking the element from another linked list. We
      // will lock it again following the unlink.

      pthread_mutex_unlock((pthread_mutex_t*)&mutex);
      
      elem->llist->unlink(elem);

      pthread_mutex_lock((pthread_mutex_t*)&mutex);
    }
  }

  if (tail == NULL)
  {

    //
    // This is the first element added to the linked list. We must adjust head
    // also.
    //

    tail = elem;
    head = tail;
  }
  else
  {

    //
    // The linked list is not empty, so we simply add the element to the end
    // of it.
    //

    tail->next = elem;
    elem->prev = tail;
    tail       = elem;
  }
  
  //
  // Set the linked list that the element is a part of.
  //

  elem->llist = this;

  //
  // Finally, we unlock the mutex.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);
}

//============================================================================
LListElem*
LList::getHead()
{
  LListElem* retElem;
  
  //
  // Lock the mutex in case the linked list is being modified.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  retElem = head;

  //
  // We must unlock the mutex before return the head of the linked list.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);

  return retElem;
}

//============================================================================
const LListElem*
LList::getHead() const
{
  const LListElem* retElem;
  
  //
  // Lock the mutex in case the linked list is being modified.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  retElem = head;

  //
  // We must unlock the mutex before return the head of the linked list.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);

  return retElem;
}

//============================================================================
LListElem*
LList::getTail()
{
  LListElem* retElem;
  
  //
  // Lock the mutex in case the linked list is being modified.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  retElem = tail;

  //
  // We must unlock the mutex before return the head of the linked list.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);

  return retElem;
}

//============================================================================
const LListElem*
LList::getTail() const
{
  const LListElem* retElem;
  
  //
  // Lock the mutex in case the linked list is being modified.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  retElem = tail;

  //
  // We must unlock the mutex before return the head of the linked list.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);

  return retElem;
}

//============================================================================
void
LList::insertBefore(LListElem* beforeElem, LListElem* newElem)
{
  static const char  mn[] = "insertBefore";

  if ((beforeElem == NULL) || (newElem == NULL))
  {
    return;
  }

  //
  // Lock the mutex because we will be changing the state of the linked list.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);
  
  if (newElem->llist != NULL)
  {

    //
    // Remove the new element from linked list that it is currently a part of
    // because linked list does not allow LListElems to be in more than one
    // linked list at a time. If desired, build a wrapper around object to be
    // placed in multiple linked lists.
    //

    zlogW(cn, mn, ("Warning: New element part of different linked "
                   "list. New element is being removed from previous "
                   "list.\n"));
    
    if (newElem->llist == this)
    {

      //
      // We do this because we are unlinking from our linked list and we
      // already have the mutex locked.
      //

      newElem->llist->lockedUnlink(newElem);
    }
    else
    {

      //
      // To protect against a possible deadlock situation here, we unlock the
      // mutex prior to unlinking the element from another linked list. We
      // will lock it again following the unlink.
      //

      pthread_mutex_unlock((pthread_mutex_t*)&mutex);
      
      newElem->llist->unlink(newElem);

      pthread_mutex_lock((pthread_mutex_t*)&mutex);
    }
  }

  if (beforeElem == head)
  {

    //
    // The element we are inserting before is the head element, so there will
    // be a new head.
    //

    newElem->next    = beforeElem;
    beforeElem->prev = newElem;
    head = newElem;
  }
  else
  {

    //
    // The element we are inserting is somewhere between the head and tail of
    // the linked list.
    //

    newElem->prev          = beforeElem->prev;
    newElem->next          = beforeElem;
    beforeElem->prev->next = newElem;
    beforeElem->prev       = newElem;
  }
  
  //
  // Set the linked list that the element is a part of.
  //

  newElem->llist = this;

  //
  // Finally, we unlock the mutex.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);
}

//============================================================================
void
LList::lockedUnlink(LListElem* elem)
{
  static const char mn[] = "lockedUnlink";
  
  //
  // NOTE: This method will simply break the linkages of the element to be
  // unlinked. Ownership of the memory is passed to the calling object, which
  // MUST either delete the memory of pass ownership to another object to
  // prevent a memory leak.
  //
  // We don't check the elem for NULL here because this method is called from
  // another method in this class that has already checked its value.
  //
  
  if (elem->llist == NULL)
  {
    zlogW(cn, mn,
          ("Unlink called for element that is not part of linked list.\n"));
    
    return;
  }

  if (elem->llist != this)
  {
    zlogE(cn, mn,
          ("Unlink called for element that is not part of this linked "
           "list.\n"));

    return;
  }

  //
  // Unlink the element. It may be the only element in the linked list, the
  // element at the head of the linked list, the element at the tail of the
  // linked list, or an element somewhere between the head and tail of the
  // linked list.
  //

  if (elem->prev == NULL)
  {
    if (elem->next == NULL)
    {

      //
      // The element that is being unlinked from the linked list is the only
      // element in the linked list. We must be sure to modify head and tail
      // also.

      head = NULL;
      tail = NULL;
    }
    else
    {
      
      //
      // The element is at the head of the linked list. We must be sure to
      // modify the head also.
      //

      elem->next->prev = NULL;
      head             = elem->next;
      elem->next       = NULL;
    }
  }
  else
  {
    if (elem->next == NULL)
    {

      //
      // The element is at the tail of the linked list. We must be sure to
      // modify the tail also.
      //

      elem->prev->next = NULL;
      tail             = elem->prev;
      elem->prev       = NULL;
    }
    else
    {

      //
      // The element is somewhere in between the head and tail of the linked
      // list. We will not modify head or tail.
      //
      
      elem->prev->next = elem->next;
      elem->next->prev = elem->prev;
      elem->next       = NULL;
      elem->prev       = NULL;
    }
  }

  //
  // Now, we set the linked list that the element is part of to NULL as it is
  // no longer a part of the linked list.
  //

  elem->llist = NULL;
}

//============================================================================
LListElem*
LList::removeFromHead()
{
  LListElem* rv;

  //
  // We are going to be modifying the internal state of the linked list so we
  // must lock the mutex.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);

  rv = head;

  if (rv != NULL)
  {

    //
    // We must unlink the element from the linked list.
    //

    lockedUnlink(rv);
  }

  //
  // Don't forget to unlock the mutex to prevent a deadlock situation.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);

  return rv;
}

//============================================================================
LListElem*
LList::removeFromTail()
{
  LListElem* rv;

  //
  // We are going to be modifying the internal state of the linked list so we
  // must lock the mutex.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);

  rv = tail;

  if (rv != NULL)
  {

    //
    // We must unlink the element from the linked list.
    //

    lockedUnlink(rv);
  }

  //
  // Don't forget to unlock the mutex to prevent a deadlock situation.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);

  return rv;
}

//============================================================================
void
LList::unlink(LListElem* elem)
{
  if (elem == NULL)
  {
    return;
  }
  
  //
  // NOTE: This method will simply break the linkages of the element to be
  // unlinked. Ownership of the memory is passed to the calling object, which
  // MUST either delete the memory of pass ownership to another object to
  // prevent a memory leak.
  //
  
  //
  // Lock the mutex because we will be changing the state of the linked list.
  //

  pthread_mutex_lock((pthread_mutex_t*)&mutex);

  lockedUnlink(elem);
  
  //
  // We are finished modifying the linked list, so we must unlock the mutex.
  //

  pthread_mutex_unlock((pthread_mutex_t*)&mutex);
}
