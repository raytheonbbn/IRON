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
#ifndef HTableElem_h
#define HTableElem_h

#include "HTableKey.h"
#include "LListElem.h"

class HTable;

/**
 * \class HTableElem
 * \ingroup common
 * 
 * Abstract base class for user defined objects that are to be placed in a
 * hash table.
 *
 * This class does not contain any user data. User defined classes that are to
 * be stored in a hash table should inherit from this class.
 *
 */
class HTableElem : public LListElem
{

  /**
   * The HTable class is a friend of this class. We want to hide the
   * implementation details of the HTableKey, e.g., we don't want to provide a
   * public interface to set or get the key. This will ensure that the
   * operation of the hash table is not corrupted by a bad key.
   */
  friend class HTable;

public:

  /**
   * Default no-arg constructor.
   */
  HTableElem();

  /**
   * Destructor.
   */
  virtual ~HTableElem();

private:

  /**
   * Pointer to the hash table to which this element is currently a member
   * of. This will allow us to clean up the memory and the hash table
   * correctly in the event that the element gets deleted prior to being
   * removed from the hashtable.
   */
  HTable*    hTable;

  /**
   * The hash table key that is associated with the hash table element.
   */
  HTableKey* key;

}; // end class HTableElem

#endif // HTableElem_h
