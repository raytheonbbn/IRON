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
#ifndef HTable_h
#define HTable_h

#include <pthread.h>

#include "HTableElem.h"
#include "HTableKey.h"
#include "LList.h"

//
// The default number of buckets used by the hash table.
//

#define DEFAULT_BUCKET_COUNT 16

/**
 * \class HTable
 * \ingroup common
 * 
 * A basic hash table. User defined objects that are to be placed in the hash
 * table must inherit from the HTableElem class. The hash table assumes
 * ownership of the memory associated with the elements that are added. A user
 * defined object can only be in one hash table at a time.
 * 
 * This class is thread-safe. As a result, the HTableElem class does not have
 * to be thread-safe.
 *
 * @author Sean P. Griffin
 */
class HTable
{
public:

  /**
   * Default no-arg constructor. This creates a hash table with a default
   * number of 16 buckets.
   */
  HTable();

  /**
   * Constructor that creates a hash table with a user defined number of
   * buckets.
   *
   * @param nBuckets The number of buckets used in the hashtable
   *                 implementation. 
   */
  HTable(int nBuckets);

  /**
   * Destructor.
   */
  virtual ~HTable();

  /**
   * Retrieve an element from the hash table. Note: this does not remove the
   * element from the hash table.
   *
   * @param key The key that is associated with the element to be retrieved.
   *
   * @return    The retrieved element or NULL if the element is not in the hash
   *            table.
   */
  HTableElem* get(HTableKey* key);

  /**
   * Adds an element to the hash table. The hash table assumes ownership of
   * the object once added to the hash table. The calling object retains
   * ownership of the provided key.
   * <p>
   * The element will not be added to the hash table if the provided key is
   * already associated with another element in the hash table. If this method
   * returns false, the replace() method can be called which will replace the
   * existing element associated with the desired key.
   *
   * @param key  The key that is associated with the element to be added to
   *             the hash table.
   * @param elem The element that is being added to the hash table.
   *
   * @return True if the element is added to the hash table, false otherwise.
   */
  bool put(HTableKey* key, HTableElem* elem);

  /**
   * Remove an element from the hash table. Ownership of the memory associated
   * with the removed element is transferred to the calling object, which must
   * either delete it or pass it on to another object to prevent memory
   * leaks.
   *
   * @param key The key associated with the element to remove from the hash
   *            table. 
   *
   * @return    The removed element or NULL if the element is not in the hash
   *            table. 
   */
  HTableElem* remove(HTableKey* key);

  /**
   * Replaces the element in the hash table associated with the key with the
   * new element. Ownership of the memory associated with the element that is
   * being replaced is passed to the calling object, which is responsible for
   * deleting it or passing ownership on to another object.
   *
   * @param key  The key that is associated with the element to be added to
   *             the hash table.
   * @param elem The element that is being added to the hash table.
   *
   * @return The hash table element that has been replaced or NULL if there
   *         was no element with the specified key. The calling object assumes
   *         ownership of the memory for the replace object. To prevent memory
   *         leaks, the calling object should destroy the returned object.
   */
  HTableElem* replace(HTableKey* key, HTableElem* elem);

private:

  /**
   * Array of buckets. Each bucket is a linked list. Once hashed to a bucket,
   * an object is added to the head of the linked list on additions. For
   * searches, the linked list is linearly searched, once the appropriate one
   * is identified by a hash function.
   */
  LList**         buckets;

  /**
   * Mutex that ensures that modifications to the hash table are atomic
   * operations. This also prevents retrieving something from the hash table
   * if there is a modification to it in process.
   */
  pthread_mutex_t mutex;
  
  /**
   * The number of buckets used by the hash table. The default number is 16,
   * however this can be specified when the hash table is constructed.
   */
  int             numBuckets;

  /**
   * Thread safe method to get an element from the hash table.
   *
   * @param key    The key associated with the element to get from the hash
   *               table.
   * @param bucket The bucket where the element should be, if it is in the
   *               hash table.
   *
   * @return The element associated with the key, or NULL if there is no
   *         element in the hash table with the provided key.
   */
  HTableElem* lockedGet(HTableKey* key, unsigned int bucket);

  /**
   * Thread safe method to put an element into the hash table.
   *
   * @param key  The key associated with the element to put into the hash
   *             table.
   * @param elem The element to put into the hash table.
   *
   * @return True if the element was added to the hash table, false
   *         otherwise.
   */
  bool lockedPut(HTableKey* key, HTableElem* elem);

  /**
   * Thread safe method to put an element into the hash table.
   *
   * @param key         The key associated with the element to put into the
   *                    hash table.
   * @param elem        The element to put into the hash table.
   * @param bucket      The bucket into which the element should be placed.
   * @param searchTable Flag that indicates if we need to search the table for
   *                    an element that is associated with the provided
   *                    key. The default value for this parameter is true,
   *                    e.g., the table is searched for an element with the
   *                    provided key prior to inserting the new element.
   *
   * @return True if the element was added to the hash table, false
   *         otherwise.
   */
  bool lockedPut(HTableKey* key, HTableElem* elem, unsigned int bucket,
                 bool searchTable = true);

  /**
   * Thread safe method to remove an element in the hash table.
   *
   * @param key The key associated with the element to remove from the hash
   *            table.
   *            
   * @return The removed element or NULL if the element is not in the hash
   *         table.
   */
  HTableElem* lockedRemove(HTableKey* key);

  /**
   * Remove the element associated with the provided key. The target bucket
   * has already been determined so the key is not hashed in this method.
   *
   * @param key    The key associated with the element to be removed from the
   *               hash table.
   * @param bucket The bucket where the element should be located, if it is in
   *               the hash table.
   *
   * @return The element that has been removed from the hash table or NULL if
   *         there was no element associated with the key in the hash table.
   */
  HTableElem* lockedRemove(HTableKey* key, unsigned int bucket);

}; // end class HTable

#endif // HTable_h
