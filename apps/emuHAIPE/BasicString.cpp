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
#include "BasicString.h"

char BasicString::_empty_string[2] = "\0";

//============================================================================
BasicString::BasicString()
    : _string(NULL), _len(0), _maxlen(0)
{
}

//============================================================================
BasicString::~BasicString()
{
  if (_string)
  {
    delete [] _string;
  }
}

//============================================================================
bool BasicString::init(int len)
{
  if (len < 1)
  {
    return(false);
  }
  
  if (_string)
  {
    delete [] _string;
  }
  
  _len = 0;
  
  if ((_string = new char[len + 1]) == NULL)
  {
    _maxlen = 0;
    return(false);
  }
  
  _maxlen    = len;
  _string[0] = '\0';
  
  return(true);
}

//============================================================================
BasicString::BasicString(const BasicString& x)
    : _string(NULL), _len(0), _maxlen(0)
{
  if (x._string)
  {
    if ((_string = new char[x._maxlen + 1]) == NULL)
    {
      return;
    }
    
    _len    = x._len;
    _maxlen = x._maxlen;
    
    ::strcpy(_string, x._string);
  }
}

//============================================================================
BasicString::BasicString(const char* c)
    : _string(NULL), _len(0), _maxlen(0)
{
  if (c)
  {
    _len = strlen(c);
    
    if ((_string = new char[_len + 1]) == NULL)
    {
      _len = 0;
      return;
    }
    
    _maxlen = _len;
    
    ::strcpy(_string, c);
  }
}

//============================================================================
BasicString& BasicString::operator=(const BasicString& x)
{
  
  //
  // If the argument x is this object, do nothing.
  //
  
  if (this == &x)
  {
    return(*this);
  }
  
  //
  // Copy the string, only reallocating memory if absolutely necessary.
  //
  
  if (x._string)
  {
    if ((_string) && (x._len <= _maxlen))
    {
      _len = x._len;
      ::strcpy(_string, x._string);
    }
    else
    {
      if (_string)
      {
        delete [] _string;
      }
      
      if ((_string = new char[x._maxlen + 1]) == NULL)
      {
        _len    = 0;
        _maxlen = 0;
        return(*this);
      }
      
      _len    = x._len;
      _maxlen = x._maxlen;
      
      ::strcpy(_string, x._string);
    }
  }
  else
  {
    if (_string)
    {
      _len       = 0;
      _string[0] = '\0';
    }
  }
  
  return(*this);
}

//============================================================================
BasicString& BasicString::operator=(const char* c)
{
  int  lenC;
  
  //
  // Copy the string, only reallocating memory if absolutely necessary.
  //
  
  if (c)
  {
    lenC = strlen(c);
    
    if ((_string) && (lenC <= _maxlen))
    {
      _len = lenC;
      ::strcpy(_string, c);
    }
    else
    {
      if (_string)
      {
        delete [] _string;
      }
      
      if ((_string = new char[lenC + 1]) == NULL)
      {
        _len    = 0;
        _maxlen = 0;
        return(*this);
      }
      
      _len    = lenC;
      _maxlen = lenC;
      
      ::strcpy(_string, c);
    }
  }
  else
  {
    if (_string)
    {
      _len       = 0;
      _string[0] = '\0';
    }
  }
  
  return(*this);
}

//============================================================================
bool BasicString::operator==(const BasicString& c) const
{
  if ((_string) && (c._string))
  {
    return(::strcmp(_string, c._string) == 0);
  }
  
  return(_string == c._string);
}

//============================================================================
bool BasicString::operator!=(const BasicString& c) const
{
  if ((_string) && (c._string))
  {
    return(::strcmp(_string, c._string) != 0);
  }
  
  return(_string != c._string);
}

//============================================================================
bool BasicString::operator==(const char* c) const
{
  if ((_string) && (c))
  {
    return(::strcmp(_string, c) == 0);
  }
  
  return(_string == c);
}

//============================================================================
bool BasicString::operator!=(const char* c) const
{
  if ((_string) && (c))
  {
    return(::strcmp(_string, c) != 0);
  }
  
  return(_string != c);
}

//============================================================================
bool BasicString::operator<(const char* c) const
{
  if ((_string) && (c))
  {
    return(::strcmp(_string, c) < 0);
  }
 
  // --- Otherwise, compare their addresses
  return _string < c;
}

//============================================================================
bool BasicString::operator<(const BasicString& s) const
{
  if ((_string) && (s.str()))
  {
    return(::strcmp(_string, s.str()) < 0);
  }
  
  // --- Otherwise, compare their addresses
  return _string < s.str();
}

//============================================================================
bool BasicString::strcasecmp(const BasicString& c) const
{
  if ((_string) && (c._string))
  {
    return(::strcasecmp(_string, c._string) == 0);
  }
  
  return(_string == c._string);
}

//============================================================================
void BasicString::clear()
{
  if (_string)
  {
    _len       = 0;
    _string[0] = '\0';
  }
}

//============================================================================
int BasicString::bsnprintf(int size, const char* format, ...)
{
  va_list  vargs;
  int      rv;
  
  if ((size < 2) || (format == NULL))
  {
    return(-1);
  }
  
  //
  // Only reallocate memory if absolutely necessary.
  //
  
  if ((_string == NULL) || ((_maxlen + 1) < size))
  {
    if (_string)
    {
      delete [] _string;
    }
    
    _len = 0;
    
    if ((_string = new char[size]) == NULL)
    {
      _maxlen = 0;
      return(-1);
    }
    
    _maxlen    = (size - 1);
    _string[0] = '\0';
  }
  
  //
  // Use vsnprintf(), which is made to take in the variable argument list.
  //
  
  va_start(vargs, format);
  rv = vsnprintf(_string, size, format, vargs);
  va_end(vargs);
  
  _len = strlen(_string);
  
  return(rv);
}

//============================================================================
void BasicString::swap(BasicString& a, BasicString& b)
{
  char*  tmp       = a._string;
  int    tmplen    = a._len;
  int    tmpmaxlen = a._maxlen;
  
  //
  // Make sure that a and b are different objects.
  //
  
  if (&a == &b)
  {
    return;
  }
  
  a._string = b._string;
  a._len    = b._len;
  a._maxlen = b._maxlen;
  
  b._string = tmp;
  b._len    = tmplen;
  b._maxlen = tmpmaxlen;
}

//============================================================================
bool BasicString::contains(const char* A) const
{
  if ((_string == NULL) || (A == NULL))
  {
    return(false);
  }
  
  if (::strstr(_string, A) == NULL)
  {
    return(false);
  }
  
  return(true);
}

//============================================================================
unsigned int BasicString::count(const char* A)
{
  int           lenA;
  int           offset;
  unsigned int  cnt;
  char*         strloc;
  
  if ((_string == NULL) || (A == NULL) || ((lenA = strlen(A)) < 1))
  {
    return(0);
  }
  
  //
  // Count the number of times A appears in _string.
  //
  
  for (offset = 0, cnt = 0;
       (strloc = ::strstr(&(_string[offset]), A)) != NULL;
       offset = ((int)(strloc - _string) + lenA))
  {
    cnt++;
  }
  
  return(cnt);
}

//============================================================================
bool BasicString::append(const char* A)
{
  char*  newString;
  int    lenA;
  int    newMaxLen;
  
  //
  // Append A to the string, only reallocating memory if absolutely
  // necessary.
  //
  
  if (A)
  {
    lenA = strlen(A);
    
    if (_string == NULL)
    {
      
      //
      // There is no existing string, so we must allocate a new string.
      // Allocate room for a 32 character string plus twice the append
      // length in case append() is called again.
      //
      
      _len    = lenA;
      _maxlen = (32 + (2 * lenA));
      
      if ((_string = new char[_maxlen + 1]) == NULL)
      {
        _len    = 0;
        _maxlen = 0;
        return(false);
      }
      
      ::strcpy(_string, A);
    }
    else
    {
      
      if ((_len + lenA) <= _maxlen)
      {
        
        //
        // There is room in the string for appending A without reallocation.
        // Make sure that the strings passed to strcat() do not overlap.
        //
        
        if ((A >= _string) && (A <= (_string + _maxlen - 1)))
        {
          return(false);
        }
        
        _len += lenA;
        ::strcat(_string, A);
      }
      else
      {
        
        //
        // There is not sufficient room in the string for appending A.
        // Allocate room for a string twice as long as the current string size
        // plus the append length in case append() is called again.
        //
        
        newMaxLen = (2 * (_maxlen + lenA));
        
        if ((newString = new char[newMaxLen + 1]) == NULL)
        {
          return(false);
        }
        
        _len    += lenA;
        _maxlen  = newMaxLen;
        
        ::strcpy(newString, _string);
        ::strcat(newString, A);
        
        delete [] _string;
        _string = newString;
      }
    }
  }
  
  return(true);
}

//============================================================================
bool BasicString::substitute(const char* A, const char* B)
{
  int    numA;
  int    newMaxLen;
  int    offset;
  int    ssOffset;
  int    ssLen;
  int    lenA;
  int    lenB;
  char*  strloc;
  char*  newString;
  
  if ((_string == NULL) || (A == NULL) || (B == NULL) || (A == B) ||
      (_string == A) || (_string == B) || ((lenA = strlen(A)) < 1))
  {
    return(false);
  }
  
  lenB = strlen(B);
  
  //
  // Count the number of times A appears in _string.
  //
  
  if ((numA = count(A)) == 0)
  {
    return(false);
  }
  
  //
  // Allocate a new _string based on the number of times A occurred as well as
  // the comparative sizes of A and B.
  //
  
  newMaxLen = _maxlen;
  
  if (lenB > lenA)
  {
    newMaxLen += (numA * (lenB - lenA));
  }
  
  if ((newString = new char[newMaxLen + 1]) == NULL)
  {
    return(false);
  }
  
  newString[0] = '\0';
  
  //
  // Build the new string, replacing every occurance of A with B.
  //
  
  offset = 0;
  
  while (true)
  {
    
    //
    // Find A starting at the current offset.
    //
    
    if ((strloc = ::strstr(&(_string[offset]), A)) == NULL)
    {
      break;
    }
    
    //
    // Append the substring starting at offset and ending at the character
    // before strloc to newString.
    //
    
    ssOffset = (int)(strloc - _string);
    ssLen    = (ssOffset - offset);
    
    if (ssLen > 0)
    {
      ::strncat(newString, &(_string[offset]), ssLen);
    }
    
    //
    // Append B to newString.
    //
    
    ::strcat(newString, B);
    
    //
    // Update the offset used for starting the next search.
    //
    
    offset = (ssOffset + lenA);
  }
  
  //
  // Append any trailing substring after the last replacement to newString.
  //
  
  ::strcat(newString, &(_string[offset]));
  
  //
  // Replace the string with the new string.
  //
  
  delete [] _string;
  
  _string = newString;
  _len    = strlen(_string);
  _maxlen = newMaxLen;
  
  return(true);
}

//============================================================================
bool BasicString::split(const char* A, bool firstOccFlag, BasicString& left,
                       BasicString& right) const
{
  int    lenA;
  int    lenLeft;
  char*  locA;
  
  if ((_string == NULL) || (_len < 1) || (A == NULL) || (this == &left) ||
      (this == &right) || (&left == &right) || ((lenA = strlen(A)) < 1) ||
      (lenA > _len))
  {
    return(false);
  }
  
  //
  // Find the first or last occurance.
  //
  
  if (lenA == 1)
  {
    if (firstOccFlag)
    {
      locA = ::strchr(_string, (int)A[0]);
    }
    else
    {
      locA = ::strrchr(_string, (int)A[0]);
    }
  }
  else
  {
    if (firstOccFlag)
    {
      locA = ::strstr(_string, A);
    }
    else
    {
      locA = findLastOccurance(A, lenA);
    }
  }
  
  if (locA == NULL)
  {
    return(false);
  }
  
  //
  // Copy left portion.  This gets messy as we try to avoid any memory
  // allocations and cannot modify this->_string.
  //
  
  if ((lenLeft = (int)(locA - _string)) > 0)
  {
    if ((left._string == NULL) || (lenLeft > left._maxlen))
    {
      if (left._string)
      {
        delete [] left._string;
      }
      
      left._maxlen = lenLeft;
      
      if ((left._string = new char[left._maxlen + 1]) == NULL)
      {
        left._len    = 0;
        left._maxlen = 0;
        return(false);
      }
    }
    
    left._len             = lenLeft;
    ::strncpy(left._string, _string, lenLeft);
    left._string[lenLeft] = '\0';
  }
  else
  {
    if (left._string)
    {
      left._len       = 0;
      left._string[0] = '\0';
    }
  }
  
  //
  // Copy the right portion.  This is easy as the right is already null
  // terminated in _string.
  //
  
  right = (const char*)&(locA[lenA]);
  
  return(true);
}

//============================================================================
bool BasicString::trimHead(const char* A, bool firstOccFlag, bool keepAFlag,
                          BasicString& result) const
{
  int    lenA;
  char*  locA;
  
  if ((_string == NULL) || (_len < 1) || (A == NULL) || (this == &result) ||
      ((lenA = strlen(A)) < 1) || (lenA > _len))
  {
    return(false);
  }
  
  //
  // Find the first or last occurance.
  //
  
  if (lenA == 1)
  {
    if (firstOccFlag)
    {
      locA = ::strchr(_string, (int)A[0]);
    }
    else
    {
      locA = ::strrchr(_string, (int)A[0]);
    }
  }
  else
  {
    if (firstOccFlag)
    {
      locA = ::strstr(_string, A);
    }
    else
    {
      locA = findLastOccurance(A, lenA);
    }
  }
  
  if (locA == NULL)
  {
    return(false);
  }
  
  //
  // Copy the right portion.  This is easy as the right is already null
  // terminated in _string.
  //
  
  if (keepAFlag)
  {
    result = (const char*)locA;
  }
  else
  {
    result = (const char*)&(locA[lenA]);
  }
  
  return(true);
}

//============================================================================
bool BasicString::trimTail(const char* A, bool firstOccFlag, bool keepAFlag,
                          BasicString& result) const
{
  int    lenA;
  int    lenLeft;
  char*  locA;
  
  if ((_string == NULL) || (_len < 1) || (A == NULL) || (this == &result) ||
      ((lenA = strlen(A)) < 1) || (lenA > _len))
  {
    return(false);
  }
  
  //
  // Find the first or last occurance.
  //
  
  if (lenA == 1)
  {
    if (firstOccFlag)
    {
      locA = ::strchr(_string, (int)A[0]);
    }
    else
    {
      locA = ::strrchr(_string, (int)A[0]);
    }
  }
  else
  {
    if (firstOccFlag)
    {
      locA = ::strstr(_string, A);
    }
    else
    {
      locA = findLastOccurance(A, lenA);
    }
  }
  
  if (locA == NULL)
  {
    return(false);
  }
  
  //
  // Copy left portion.  This gets messy as we try to avoid any memory
  // allocations and cannot modify this->_string.
  //
  
  lenLeft = (int)(locA - _string);
  
  if (keepAFlag)
  {
    lenLeft += lenA;
  }
  
  if (lenLeft > 0)
  {
    if ((result._string == NULL) || (lenLeft > result._maxlen))
    {
      if (result._string)
      {
        delete [] result._string;
      }
      
      result._maxlen = lenLeft;
      
      if ((result._string = new char[result._maxlen + 1]) == NULL)
      {
        result._len    = 0;
        result._maxlen = 0;
        return(false);
      }
    }
    
    result._len             = lenLeft;
    ::strncpy(result._string, _string, lenLeft);
    result._string[lenLeft] = '\0';
  }
  else
  {
    if (result._string)
    {
      result._len       = 0;
      result._string[0] = '\0';
    }
  }
  
  return(true);
}

//============================================================================
char *BasicString::findLastOccurance(const char* A, int lenA) const
{
  int   a;
  int   i;
  int   j;
  int   limit;
  char  lastChar;
  
  if ((A == NULL) || (lenA < 1))
  {
    return(NULL);
  }
  
  //
  // Go backward through _string looking for the last character of A.
  //
  
  limit    = (lenA - 1);
  lastChar = A[limit];
  
  for (i = (_len - 1); i >= limit; i--)
  {
    if (_string[i] == lastChar)
    {
      
      //
      // If A is a single character, we are done!
      //
      
      if (lenA == 1)
      {
        return(&_string[i]);
      }
      else
      {
        
        //
        // Continue backward to see if this is really A.
        //
        
        for (j = (i - 1), a = (limit - 1); a >= 0; j--, a--)
        {
          if (_string[j] != A[a])
          {
            break;
          }
          if (a == 0)
          {
            return(&_string[j]);
          }
        }
        
        //
        // Not A.  Continue where we left off.
        //
        
      }
    }
  }
  
  //
  // Couldn't find A.
  //
  
  return(NULL);
}

ostream& operator<<(ostream& out, const BasicString& bs) {
  return out << '"' << bs.str() << '"';
}

istream& operator>>(istream& in, BasicString& bs) {
#define BUFLEN 10
  char c, buf[BUFLEN];
  int pos = 0;                  // position in the internal buffer
  CHECK_NEXT_CHAR(in,'"');
  bs.init(BUFLEN);
  while (1) {
    if (!(in>>c)) INPUT_FAILED(in);
    if (c == '"') break;        // read till #\"
    if (pos == BUFLEN-1) {      // buffer is full
      buf[pos] = 0; bs.append(buf); // flush the buffer
      pos = 0;                  // reset the buffer position
    }
    buf[pos++] = c;             // append the character to the internal buffer
  }
  buf[pos] = 0; bs.append(buf); // flush the buffer
  return in;
#undef BUFLEN
}
