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
#ifndef BasicString_h
#define BasicString_h

#include <istream>
#include <ostream>
#include <iostream>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

using namespace std;

/* set failbit and return NULL - suitable for >> methods */
#define INPUT_FAILED(input_stream) do { \
  input_stream.setstate(ios::failbit); abort();/*return (istream*)NULL*/; \
 } while(0)

/* check that the next non-space character is indeed what is expected
   set failbit and return NULL on failure, so this is useful for >> methods */
#define CHECK_NEXT_CHAR(input_stream,expected) do {                          \
   char CHECK_NEXT_CHAR__char;                                               \
   if (!(input_stream >> CHECK_NEXT_CHAR__char)) INPUT_FAILED(input_stream); \
   if (CHECK_NEXT_CHAR__char != expected) INPUT_FAILED(input_stream);        \
 } while(0)

/* check that the next several characters in the stream
   constitute the given word */
#define CHECK_NEXT_WORD(input_stream,word)                              \
  for (char *CHECK_NEXT_WORD__char=word; *CHECK_NEXT_WORD__char;        \
       CHECK_NEXT_WORD__char++)                                         \
    CHECK_NEXT_CHAR(input_stream,*CHECK_NEXT_WORD__char)

/**
 *
 * \class BasicString
 * \ingroup common
 *
 * A simple string implementation.  Basically, this class wraps a pointer to a
 * dynamically allocated character array.  It includes some smarts in order to
 * improve efficiency.
 *
 * This class is not thread-safe.
 *
 * @author Brian DeCleene, Mark Keaton
 */
class BasicString
{
  
public:
  
  /**
   * Simple constructor for a null string.
   */
  BasicString();
  
  /**
   * Destructor.
   */
  virtual ~BasicString();
  
  /**
   * Initialize to an allocated, empty string of the specified size.
   *
   * @param len The string buffer length in characters, not including a
   *            terminating null character.
   *
   * @return Returns true on success, or false on failure.
   */
  bool init(int len);
  
  /**
   * Quick test to see if the string is null (empty).
   *
   * @return Returns true if the string is null (empty), or false otherwise.
   */
  inline bool isNull() const
  {
    return((_string == NULL) || (_len < 1));
  }
  
  /**
   * Quick test to see if the string is not null (not empty).
   *
   * @return Returns true if the string is not null (not empty), or false
   *         otherwise.
   */
  inline bool isNotNull() const
  {
    return((_string != NULL) && (_len > 0));
  }
  
  /**
   * Quick test to see if the string is set (i.e., not null, not empty).
   *
   * @return Returns true if the string is not null (not empty), or false
   *         otherwise.
   */
  inline bool isSet() const
  {
    return((_string != NULL) && (_len > 0));
  }
  
  /// Copy constructor.
  BasicString(const BasicString& x);
  
  /// Copy constructor from a const char pointer.
  BasicString(const char* c);
  
  /// Copy operator
  BasicString& operator=(const BasicString& x);
  
  /// Copy operator from a const char pointer
  BasicString& operator=(const char* c);
  
  /// Equal comparision operator
  bool operator==(const BasicString& c) const;
  
  /// Not equal comparision operator
  bool operator!=(const BasicString& c) const;
  
  /// Equal comparision operator
  bool operator==(const char* c) const;
  
  /// Not equal comparision operator
  bool operator!=(const char* c) const;
  
  /// LessThan comparison operator
  bool operator<(const BasicString& s) const;

  /// LessThan comparison operator
  bool operator<(const char* c) const;

  /// Equal comparision operator thatr is case insensitive.
  bool strcasecmp(const BasicString& c) const;
  

  /**
   * Clears out the string.
   */
  void clear();

  /**
   * Access the string as a constant char pointer.  Never returns NULL.
   *
   * @return A constant pointer to the string.  May return a pointer to an
   *         empty character array, or a pointer to a non-empty character
   *         array.  Never returns NULL.
   */
  inline const char* str() const
  {
    return((_string == NULL) ? _empty_string : _string);
  }
  
  /**
   * Access the string as a constant char pointer.  May return either NULL if
   * the string is unset or empty, or a constant char pointer to a non-empty
   * string.
   *
   * @return A constant pointer to the string.  May return a pointer to a
   *         non-empty character array, or NULL.
   */
  inline const char* ptr() const
  {
    return(((_string == NULL) || (_len < 1)) ? NULL : _string);
  }
  
  /**
   * Set the string using a printf family format.  The resulting string may be
   * truncated depending on the size specified.
   *
   * @param size   The expected maximum size of the resulting string in number
   *               of characters including the trailing null character.
   * @param format The printf family format to use including a variable
   *               argument list.  See printf(3).
   *
   * @return On success, the number of characters, not including the
   *         terminating null character, placed in the string if size was
   *         sufficient.  If the returned value is positive and greater than
   *         size, then the resulting string is truncated.  On error, a
   *         negative value is returned.
   */
  int bsnprintf(int size, const char* format, ...);
  
  /**
   * This method allows us to swap two strings without incurring the various
   * copies.
   *
   * @param a The first BasicString.
   * @param b The second BasicString.  Must not be the same BasicString object
   *          as a.
   */
  static void swap(BasicString& a, BasicString& b);
  
  /**
   * Return the current string length in number of characters not including
   * the terminating null character.
   *
   * @return The string length.
   */
  inline int length() const
  {
    return(_len);
  }
  
  /**
   * Return true if the provided string is somewhere within this string.
   *
   * @param A The string to search for.
   *
   * @return Returns true if the string A is currently in the string, false
   *         otherwise.
   */
  bool contains(const char* A) const;
  
  /**
   * Count the number of times the search string appears in this string.
   *
   * @param A The string to search for.
   *
   * @return Count of the number of times that the search string appears in
   *         this string.
   */
  unsigned int count(const char* A);

  /**
   * Append string A to the end of this string.
   *
   * @param A The string to append.  Must not be the result of c_str() on the
   *          current BasicString object.
   *
   * @return Returns true if A was appended, or false otherwise.
   */
  bool append(const char* A);
  
  /**
   * Append string A to the end of this string.
   *
   * @param A The string to append.  Must not be the result of c_str() on the
   *          current BasicString object.
   *
   * @return Returns true if A was appended, or false otherwise.
   */
  inline bool append(const BasicString& x) { return append(x.str()); }
  
  /**
   * Replace occurances of the first string with the second string.
   *
   * @param A The string to search for and replace with B.  Must not be the
   *          result of c_str() on the current BasicString object.
   * @param B The string to replace A.  Must not be the result of c_str() on
   *          the current BasicString object.
   *
   * @return Returns true if B was actually substituted for A at least once,
   *         or false otherwise.
   */
  bool substitute(const char* A, const char* B);
  
  /**
   * Split the string at either the first or last occurrence of the string A,
   * placing the string to the left of A in left, and the string to the right
   * of A in right.
   *
   * @param A            The string to search for.  Will not be contained in
   *                     either left or right if the split succeeds.
   * @param firstOccFlag If true, the split will occur at the first occurance
   *                     of A.  If false, the split will occur at the last
   *                     occurance of A.
   * @param left         A BasicString where the left portion will be placed.
   *                     Must not be the current BasicString object.
   * @param right        A BasicString where the right portion will be placed.
   *                     Must not be the current BasicString object or the same
   *                     BasicString object as left.
   *
   * @return Returns true if A was found and the split actually occurred, or
   *         false otherwise.
   */
  bool split(const char* A, bool firstOccFlag, BasicString& left,
             BasicString& right) const;
  
  /**
   * Trim off the beginning of the string at either the first or last
   * occurrence of string A.  The resulting ending of the string, which may or
   * may not include string A, is placed in result.
   *
   * @param A            The string to search for.
   * @param firstOccFlag If true, the trimming will occur at the first
   *                     occurance of A.  If false, the trimming will occur at
   *                     the last occurance of A.
   * @param keepAFlag    If true, then res will include string A.  If false,
   *                     then res will not include string A.
   * @param result       A BasicString where the resulting string will be
   *                     placed.  Must not be the current BasicString object.
   *
   * @return Returns true if A was found and the trimming actually occurred,
   *         or false otherwise.
   */
  bool trimHead(const char* A, bool firstOccFlag, bool keepAFlag,
                BasicString& result) const;
  
  /**
   * Trim off the ending of the string at either the first or last occurrence
   * of string A.  The resulting beginning of the string, which may or may not
   * include string A, is placed in result.
   *
   * @param A            The string to search for.
   * @param firstOccFlag If true, the trimming will occur at the first
   *                     occurance of A.  If false, the trimming will occur at
   *                     the last occurance of A.
   * @param keepAFlag    If true, then res will include string A.  If false,
   *                     then res will not include string A.
   * @param result       A BasicString where the resulting string will be
   *                     placed.  Must not be the current BasicString object.
   *
   * @return Returns true if A was found and the trimming actually occurred,
   *         or false otherwise.
   */
  bool trimTail(const char* A, bool firstOccFlag, bool keepAFlag,
                BasicString& result) const;

  /**
   * Print the string as a quoted sequence of characters
   */
  friend ostream& operator<<(ostream& out, const BasicString& bs);
  
  /**
   * Read the string as a quoted sequence of characters
   */
  friend istream& operator>>(istream& in, BasicString& bs);


  // ---------------------------------------------
  
private:
  
  /**
   * A method to implement the missing strrstr() call.
   *
   * @param A    The string to search for.
   * @param lenA The string length of A in number of characters not including
   *             the terminating null character
   *
   * @return A pointer to the last occurance of A if A is present, or NULL
   *         if A is not found.
   */
  char *findLastOccurance(const char* A, int lenA) const;
  
  /**
   * The character array of length (_maxlen + 1).
   */
  char*  _string;
  
  /**
   * The current string length in number of characters not including the
   * terminating null character.
   */
  int    _len;
  
  /**
   * The maximum string length, not including the terminating null character,
   * capable of being stored in _string.
   */
  int    _maxlen;
  
  /**
   * A static, empty string.  This is used to prevent c_str() from returning
   * NULL, which is annoying when used in the printf family of calls.
   */
  static char  _empty_string[2];
  
}; // end class BasicString

#endif // BasicString_hh
