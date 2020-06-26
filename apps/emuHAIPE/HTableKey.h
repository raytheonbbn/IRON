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
#ifndef HTableKey_h
#define HTableKey_h

/**
 * \class HTableKey
 * \ingroup common
 * 
 * Abstract base class for hash table keys.
 *
 * A hash table key is associated with an element that is to be added to a
 * hash table. The key serves two functions:
 * 1) the hash() method is invoked to get to the appropriate hash table bucket
 *    and 
 * 2) the equals() method is invoked to find the element associated with the
 *    key. 
 *
 */
class HTableKey
{
public:

  /**
   * Destructor.
   */
  virtual ~HTableKey() { }

  /**
   * Creates a deep copy of the hash table key. Ownership of the memory that
   * is allocated for the copy is passed to the calling object. This is
   * necessary because hash table keys are typically temporary objects that
   * are created by objects to find an item in a hash table. The hash table
   * must remember the key associated with an object that is added, so it must
   * make a deep copy of the key because it will be destroyed by the object
   * that is adding the element to the hash table.
   *
   * @return A copy of the hash table key.
   */
  virtual HTableKey* copy() = 0;

  /**
   * Tests this hash table key with another one for equality.
   *
   * @param key The key to compare this key with.
   *
   * @return True if the keys are equal, false otherwise.
   */
  virtual bool equals(HTableKey* key) = 0;

  /**
   * Hash function that must be implemented by all hash table key
   * implementations. The return value will aid in finding the appropriate
   * hash table bucket that an element associate with the key resides in.
   *
   * @return An unsigned int that is the hash of the key.
   */
  virtual unsigned int hash() = 0;

private:

}; // end class HTableKey

#endif // HTableKey_h
