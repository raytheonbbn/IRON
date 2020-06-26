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
#include "HTable.h"

#include <stdio.h>
#include <string.h>

#include "ZLog.h"

//
// Class name to use in logging output.
//

static const char cn[] = "HTable";

//============================================================================
HTable::HTable()
{

  //
  // The default number of buckets is DEFAULT_BUCKET_COUNT.
  //
  
  numBuckets = DEFAULT_BUCKET_COUNT;
  
  //
  // Allocate the buckets.
  //
  
  buckets = new LList*[numBuckets];

  //
  // and initialize them to NULL.
  //
  
  memset(buckets, 0, numBuckets * sizeof(LList*));

  //
  // Initialize the mutex.  The call never fails.
  //

  pthread_mutex_init(&mutex, NULL);
}

//============================================================================
HTable::HTable(int nBuckets)
{

  //
  // Method name to use in logging output.
  //
  
  static const char mn[] = "HTable";
  
  if (nBuckets < 1)
  {

    //
    // Revert back to the default bucket count.
    //
    
    numBuckets = DEFAULT_BUCKET_COUNT;

    zlogW(cn, mn,
          ("Warning: Instructed to create hash table with invalid bucket count"
           " <%d>. Using default bucket count of <%d>.\n", nBuckets,
           DEFAULT_BUCKET_COUNT));
  }
  else
  {
    numBuckets = nBuckets;
  }
  
  //
  // Allocate the buckets
  //
  
  buckets = new LList*[numBuckets];

  //
  // and initialize them to NULL.
  //
  
  memset(buckets, 0, numBuckets * sizeof(LList*));

  //
  // Initialize the mutex.  The call never fails.
  //

  pthread_mutex_init(&mutex, NULL);
}

//============================================================================
HTable::~HTable()
{

  //
  // We need to delete all of the buckets and their contents.
  //

  for (int counter = 0; counter < numBuckets; counter++)
  {
    if (buckets[counter] != NULL)
    {
      delete buckets[counter];
      buckets[counter] = NULL;
    }
  }

  delete [] buckets;
  buckets = NULL;

  numBuckets = 0;

  //
  // Finally, we destroy the mutex.
  //

  pthread_mutex_destroy(&mutex);
}

//============================================================================
HTableElem*
HTable::get(HTableKey* key)
{
  HTableElem*  rv = NULL;
  
  if (key == NULL)
  {
    return rv;
  }
  
  //
  // We are getting a value from the hash table. We lock the mutex to ensure
  // that another thread of control is not modifying the state of the hash
  // table while we are in here.
  //

  pthread_mutex_lock(&mutex);

  //
  // First, we find the bucket from which to begin our search. We accomplish
  // this by invoking the hash method on the provided hash table key.
  //
  
  unsigned int targetBucket = key->hash() % numBuckets;

  rv = lockedGet(key, targetBucket);

  //
  // Don't forget to unlock the mutex.
  //

  pthread_mutex_unlock(&mutex);

  //
  // Now we can return the element that was asked for.
  //

  return rv;
}

//============================================================================
bool
HTable::put(HTableKey* key, HTableElem* elem)
{
  bool              rv   = false;
  static const char mn[] = "put";
  
  if ((key == NULL) || (elem == NULL))
  {
    return false;
  }

  //
  // We are going to be modifying the state of the hash table so we need to be
  // sure that we lock the mutex.
  //

  pthread_mutex_lock(&mutex);

  if (elem->hTable != NULL)
  {

    //
    // Remove the element from the hash table that it is part of before adding
    // it to this hash table.
    //

    zlogW(cn, mn, ("Warning: Element part of different hash table. Element is "
                   "being removed from previous hash table.\n"));

    if (elem->hTable == this)
    {

      //
      // We do this because we are removing the object from our hash table and
      // we already have the mutex locked. We remove it in case someone tries
      // to add the element with a new key, which could damage the internals
      // of the hash table.
      //

      elem->hTable->lockedRemove(elem->key);
    }
    else
    {

      //
      // To protect against a possible deadlock situation here, we unlock the
      // mutex prior to removing the element from another hash table. We will
      // lock it again following the remove.
      //

      pthread_mutex_unlock(&mutex);
      
      elem->hTable->remove(elem->key);

      pthread_mutex_lock(&mutex);
    }
  }

  rv = lockedPut(key, elem);

  //
  // Don't forget to unlock the mutex.
  //

  pthread_mutex_unlock(&mutex);

  return rv;
}

//============================================================================
HTableElem*
HTable::lockedGet(HTableKey* key, unsigned int bucket)
{
  HTableElem* rv = NULL;

  //
  // Now, we have to search the linked list at the target bucket location for
  // the matching element.
  //

  if (buckets[bucket] == NULL)
  {

    //
    // The key hashed to a bucket that was empty, so obviously the element is
    // not in the hashtable.
    //
    
    rv = NULL;
  }
  else
  {
    HTableElem* hte = (HTableElem*)buckets[bucket]->getHead();

    while (hte != NULL)
    {
      if (key->equals(hte->key))
      {

        //
        // We have found the matching element, so we can stop looking for it.
        //
      
        rv = hte;
        break;
      }

      hte = (HTableElem*)hte->getNext();
    }
  }

  return rv;
}

//============================================================================
bool
HTable::lockedPut(HTableKey* key, HTableElem* elem)
{

  //
  // We simply need to hash the key and call the lockedPut() method that takes
  // the bucket as a parameter.
  //

  unsigned int targetBucket = key->hash() % numBuckets;

  return lockedPut(key, elem, targetBucket);
}

//============================================================================
bool
HTable::lockedPut(HTableKey* key, HTableElem* elem, unsigned int bucket,
                  bool searchTable)
{
  if (searchTable)
  {

    //
    // We have to check to see if there is already an element in the hash table
    // that is associated with the specified key. If so, we return false
    // because we don't allow a key to have more than one element associated
    // with it.
    //

    if (lockedGet(key, bucket) != NULL)
    {

      //
      // There is already an element in the hash table associated with the
      // provided key, so we simply return false.
      //

      return false;
    }
  }
  
  //
  // The element isn't already in the hash table, so we find the appropriate
  // bucket to place the element in.
  //

  if (buckets[bucket] == NULL)
  {

    //
    // We need to create the linked list for this bucket.
    //

    buckets[bucket] = new LList();
  }

  //
  // Make a copy of the key and add it to the element that is being added to
  // the hash table. We need to do this because we need a deep copy of the key
  // associated with the element (as keys are typically temporary objects that
  // are destroyed after used to put an element into the hash table. We can do
  // this because we are a friend of the HTableElem class.
  //
  
  elem->key = key->copy();

  //
  // Store the reference to this hash table in the element that was just
  // added.
  //
  
  elem->hTable = this;

  //
  // Add the element to the linked list at the target bucket location.
  //
  
  buckets[bucket]->addToHead(elem);

  return true;
}

//============================================================================
HTableElem*
HTable::lockedRemove(HTableKey* key)
{
  
  //
  // We don't need to check the key for NULL because we have already done that
  // in another method in this class.
  //

  //
  // First, we need to find the appropriate bucket.
  //

  unsigned int targetBucket = key->hash() % numBuckets;
  
  //
  // and call lockedRemove() that takes the bucket as a parameter.
  //

  return lockedRemove(key, targetBucket);

}

//============================================================================
HTableElem*
HTable::lockedRemove(HTableKey* key, unsigned int bucket)
{
  HTableElem*  rv = NULL;
  
  //
  // We don't have to check the key for NULL because we have already done that
  // in another method in this class.
  //

  LList* bucketList = buckets[bucket];

  if (bucketList == NULL)
  {

    //
    // There are no elements in the target bucket.
    //
    
    return rv;
  }

  HTableElem* hte = (HTableElem*)bucketList->getHead();

  while (hte != NULL)
  {
    if (key->equals(hte->key))
    {

      //
      // Unlink the element from the linked list.
      //
      
      bucketList->unlink(hte);

      //
      // Remember the element that has been removed from the hash table. The
      // calling object is responsible for deleting the memory associated with
      // the element to avoid a memory leak.
      //
      
      rv = hte;

      //
      // We are removing the element, so we remove the reference to the hash
      // table from the element.
      //
      
      hte->hTable = NULL;

      //
      // Delete the key associated with the element to avoid a memory leak. We
      // do this because when the element was added to the hash table we made
      // a deep copy of it.
      //
      
      delete hte->key;
      hte->key = NULL;

      break;
    }

    //
    // Get the next element in the linked list.
    //
      
    hte = (HTableElem*)hte->getNext();
  }

  //
  // Return the element.
  //
  
  return rv;
}

//============================================================================
HTableElem*
HTable::remove(HTableKey* key)
{
  HTableElem* rv = NULL;
  
  if (key == NULL)
  {
    return rv;
  }

  //
  // We are going to be modifying the state of the hash table so we need to be
  // sure that we lock the mutex.
  //

  pthread_mutex_lock(&mutex);

  rv = lockedRemove(key);

  //
  // Don't forget to unlock the mutex.
  //

  pthread_mutex_unlock(&mutex); 

  //
  // Return the element.
  //
  
  return rv;
}

//============================================================================
HTableElem*
HTable::replace(HTableKey* key, HTableElem* elem)
{
  unsigned int targetBucket;
  HTableElem*  rv = NULL;

  if ((key == NULL) || (elem == NULL))
  {
    return rv;
  }

  //
  // We are going to be modifying the internal state of the hash table, so we
  // must lock the mutex before proceeding.
  //

  pthread_mutex_lock(&mutex);

  //
  // To replace an item, we simply have to call remove followed by put. We
  // call the private methods that take the target bucket as a parameter. We
  // do this so that we only have to compute the hash of the key one time,
  // instead of seperately in the remove() and put() methods.
  //

  targetBucket = key->hash() % numBuckets;

  //
  // Remove the element from the hash table that is currently associated with
  // the provided key.
  //

  rv = lockedRemove(key, targetBucket);

  //
  // Add the new element to the hash table.
  //

  lockedPut(key, elem, targetBucket, false);

  //
  // We have to unlock the mutex before returning the item that was replaced
  // in the hash table.
  //

  pthread_mutex_unlock(&mutex);

  return rv;
}
