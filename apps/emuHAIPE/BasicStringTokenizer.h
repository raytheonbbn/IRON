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
#ifndef BasicStringTokenizer_h
#define BasicStringTokenizer_h


#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "BasicString.h"


/**
 *
 * \class BasicStringTokenizer
 * \ingroup common
 *
 * A simple string tokenizer implementation.  This class wraps the strtok_r()
 * function for the safe tokenization of a BasicString.  By using strtok_r()
 * instead of strtok(), this class is re-entrant (the user can have multiple
 * BasicStringTokenizer objects in use at any given time).
 *
 * This class is thread-safe.
 *
 */
class BasicStringTokenizer
{
  
public:
  
  /**
   * Constructor.
   */
  BasicStringTokenizer();
  
  /**
   * Destructor.
   */
  virtual ~BasicStringTokenizer();
  
  /**
   * Check the tokenizer for signs of being initialized.
   *
   * @return Returns true if the tokenizer appears to be initialized, or false
   *         otherwise.
   */
  inline bool isInitialized() const
  {
    return((_delim != NULL) && (_string != NULL));
  }
  
  /**
   * Initialize the tokenizer with the BasicString to be processed and the
   * delimiter string.
   *
   * @param  s A reference to the BasicString to be tokenized.
   * @param  d The delimiter string to be used.
   *
   * @return Returns true on success, or false on failure.
   */
  bool init(BasicString& s, const char* d);
  
  /**
   * Unambiguously clear the tokenizer contents.
   */
  void clear(void);
  
  /**
   * Rewind the tokenizer to the beginning of the string.
   *
   * @return Returns true on success, or false on failure.
   */
  bool rewind(void);
  
  /**
   * Force the tokenizer to use a new delimiter.
   *
   * @param  d The new delimiter string to be used.
   *
   * @return Returns true on success, or false on failure.
   */
  bool setDelimiter(const char *d);
  
  /**
   * Get the next token using the current delimiter.  When the return value is
   * non-NULL, the memory pointed to is owned by this class and must not be
   * modified or freed.
   *
   * @return Returns a pointer to the next token, or NULL if one is not
   *         found.  Any referenced memory is owned by this class.
   */
  char* getNextToken(void);
  
  /**
   * Get the next token using the current delimiter.
   *
   * @param  b The BasicString that will contain the token string.
   *
   * @return Returns true on success, or false on failure.  If false is
   *         returned, the BasicString b is not modified in any way.
   */
  bool getNextToken(BasicString& b);
  
private:
  
  /**
   * A copy of the BasicString currently being used.  Allows the use of a
   * rewind function to restart the tokenizer on the same string.
   */
  BasicString   _copy;
  
  /**
   * The character string that will act as the delimiter.
   */
  char*        _delim;
  
  /*
   * The string to be consumed during tokenization.
   */
  char*        _string;
  
  /*
   * A pointer buffer to be used by the strtok_r() funtion.  See the
   * strtok_r() man page for more information.
   */
  char*        _ptrptr;
  
  /*
   * Call counter for strtok_r() to accommodate parameter idiosyncrasies.
   */
  int          _count;
  
}; // end class BasicStringTokenizer

#endif // BasicStringTokenizer_h
