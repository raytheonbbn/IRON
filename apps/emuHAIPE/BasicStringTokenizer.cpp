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
#include "BasicStringTokenizer.h"


//============================================================================
BasicStringTokenizer::BasicStringTokenizer()
    : _delim(NULL), _string(NULL), _ptrptr(NULL), _count(0)
{
}

//============================================================================
BasicStringTokenizer::~BasicStringTokenizer()
{
  this->clear();
}

//============================================================================
bool
BasicStringTokenizer::init(BasicString& s, const char* d)
{
  const char*  sPtr = s.ptr();
  int          sLen = s.length();
  int          dLen;
  
  //
  // Safety checks...
  //
  
  if ((sLen < 1) || (sPtr == NULL) || (d == NULL))
  {
    return(false);
  }
  
  if ((dLen = ::strlen(d)) < 1)
  {
    return(false);
  }
  
  //
  // End safety checks.  Start with a clean slate.
  //
  
  this->clear();
  
  //
  // Create a local copy of the BasicString for use in a rewind() call.
  //
  
  _copy = s;
  
  //
  // Create a local string to be used in the strtok_r() function.  It will be
  // consumed (modified).
  //
  
  if ((_string = new char[sLen + 1]) == NULL)
  {
    _copy.clear();
    return(false);
  }
  
  //
  // Copy the BasicString contents to the local string.
  //
  
  strcpy(_string, sPtr);
  
  //
  // Copy the delimiter also.
  //
  
  if ((_delim = new char[dLen + 1]) == NULL)
  {
    _copy.clear();
    delete [] _string;
    _string = NULL;
    return(false);
  }
  
  strcpy(_delim, d);
  
  //
  // Reset strtok_r() call counter.
  //
  
  _count = 0;
  
  return(true);
}

//============================================================================
char*
BasicStringTokenizer::getNextToken()
{
  char*  token;
  
  //
  // If the tokenizer was not initialized, there can be no tokens.
  //
  
  if (!this->isInitialized())
  {
    return(NULL);
  }
  
  //
  // If this is the first call, then specify _string as the first argument.
  // Otherwise, specify NULL.  See the strtok_r() man page for a complete
  // explanation.
  //
  
  if (_count == 0)
  {
    token = ::strtok_r(_string, _delim, &_ptrptr);
  }
  else
  {
    token = ::strtok_r(NULL, _delim, &_ptrptr);
  }
  
  _count++;
  
  return(token);
}

//============================================================================
bool
BasicStringTokenizer::getNextToken(BasicString& b)
{
  char*  token;
  
  //
  // Get the next token string.
  //
  
  token = this->getNextToken();
  
  if (token != NULL)
  {
    
    //
    // Success!  Set b to the returned token.
    //
    
    b = token;
    
    return(true);
  }
  
  return(false);
}

//============================================================================
bool
BasicStringTokenizer::setDelimiter(const char* d)
{
  int  len;
  
  //
  // First, check to see if the tokenizer has been initalized.
  //
  
  if (!isInitialized())
  {
    return(false);
  }
  
  //
  // Make sure that the new delimiter exists.
  //
  
  if ((d == NULL) || ((len = ::strlen(d)) < 1))
  {
    return(false);
  }
  
  //
  // Free the old delimiter.
  //
  
  if (_delim != NULL)
  {
    delete [] _delim;
  }
  
  //
  // Allocate storage for the new delimiter.
  //
  
  if ((_delim = new char[len + 1]) == NULL)
  {
    this->clear();
    return(false);
  }
  
  //
  // Store the new delimiter.
  //
  
  strcpy(_delim, d);
  
  return(true);
}

//============================================================================
bool
BasicStringTokenizer::rewind()
{
  
  //
  // First, check to see if the tokenizer has been initalized.
  //
  
  if (!isInitialized())
  {
    return(false);
  }
  
  //
  // Restore _string using our local copy and reset _count.  We do not need to
  // change _delim.
  //
  
  strcpy(_string, _copy.str());
  _ptrptr = NULL;
  _count  = 0;
  
  return(true);
}

//============================================================================
void
BasicStringTokenizer::clear()
{
  
  //
  // Free the memory allocated by the previous initialization.
  //
  
  if (_delim != NULL)
  {
    delete [] _delim;
    _delim = NULL;
  }
  
  if (_string != NULL)
  {
    delete [] _string;
    _string = NULL;
  }
  
  _ptrptr = NULL;
  
  _count = 0;
}
