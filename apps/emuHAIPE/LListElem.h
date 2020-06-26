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
#ifndef LListElem_h
#define LListElem_h

class LList;

/**
 * \class LListElem
 * \ingroup common
 * 
 * This serves as the base class for any user created object that is to be
 * stored in a linked list.
 *
 * This class does not contain any user data. User defined classes that are to
 * be stored in a linked list should inherit from this class, which provides
 * the linkage required for doubly linked lists, namely a pointer to a
 * previous element and a pointer to the next element.
 *
 */
class LListElem
{

  /**
   * The LList class is a friend of this class. All modifications to the
   * linkage of the linked list should occur via the LList class. However, to
   * maintain the linkages and prevent other classes from modifying them, the 
   * LList class needs access to the private class level variables of the
   * LListElem class. By declaring the LList class as a friend, we don't have
   * to provide public set methods for the class variables, prev and next,
   * ensuring that modifications to the linkage of the linked list ONLY occur
   * via the LList class.
   */
  friend class LList;

public:

  /**
   * Default no-arg constructor.
   */
  LListElem();

  /**
   * Destructor.
   */
  virtual ~LListElem();

  /**
   * Get pointer to the element in the linked list that occurs after this
   * element.
   *
   * @return The element that occurs after this element in the linked list.
   */
  inline LListElem* getNext()
  {
    return next; 
  }
      
  /**
   * Get pointer to the element in the linked list that occurs after this
   * element.
   *
   * @return The element that occurs after this element in the linked list.
   */
  inline const LListElem* getNext() const
  {
    return next; 
  }
      
  /**
   * Get pointer to the element in the linked list that occurs before this
   * element.
   *
   * @return The element that occurs before this element in the linked list.
   */
  inline LListElem* getPrev() 
  {
    return prev; 
  }

  /**
   * Get pointer to the element in the linked list that occurs before this
   * element.
   *
   * @return The element that occurs before this element in the linked list.
   */
  inline const LListElem* getPrev() const
  {
    return prev; 
  }

private:

  /** 
   * Pointer the the linked list of elements. This will permit for the
   * unlinking of the current object in the event that it gets destroyed while
   * still linked to other objects.
   */
  LList*     llist;
  
  /**
   * Pointer to the next element in the linked list.
   */
  LListElem* next;

  /**
   * Pointer to the previous element in the linked list.
   */
  LListElem* prev;
  
}; // end class LListElem

#endif // LListElem_h
