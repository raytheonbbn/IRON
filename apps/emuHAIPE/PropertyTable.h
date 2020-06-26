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
#ifndef PropertyTable_h
#define PropertyTable_h

// This class is supported within windows.
#include "common_windows.h"

#include "HTable.h"

/**
 * \defgroup configParam Configuration Parameters
 *
 * Properties are specifed in the file as "key value".  As a result, the key
 * cannot include a space in its definition.  The value may contain any value
 * except that the leading whitespace is deleted.
 *
 * Comments may be inserted into the property file using the # marker.
 * 
 * Property files can also be nested using the "include" directive.  This
 * will load the specified file.  In each case, the last value associated
 * with the key is the one used while running.
 *
 * Parameters such as the location of files may be specified relative to
 * the location of the loaded property file by prepending a plus sign to
 * the value.  For example, a file "+foo.txt" denotes a file named foo.txt
 * that is colocated with the property file.  The value a file "foo.txt"
 * would represent a file that is located where the program was executed.
 *
 * Keywords that start with a plus sign, are considered additional items
 * on a list.  The line "+Foo bar" will increment the variable NumFoo and
 * then assign bar to the key "FooX" where X is the last number in the list.
 * So the first call will create Foo0 and NumFoo will equal 1.  On the second
 * call Foo1 will be added and NumFoo will equal 1.
 */

/**
 * \class PropertyTable
 * \ingroup common
 *
 * Support for accessing properties from a file.
 *
 * This class allows the program to fetch values from a property file rather
 * than hardcoding them into the source code.  Each request for a property
 * specifies the key to use to look up the value.  In addition, a default
 * value is specified that is used in the event that the key is not found.
 *
 * By convention, objects use the method "void
 * configure(PropertyTable& tbl, const char* key)" to initialize
 * themselvs.  The first parameter is the property file while the
 * second value is the key for the corresponding object.
 *
 */
class COMMON_API PropertyTable 
{
public:

  /**
   * Default no-arg constructor.
   */
  PropertyTable();

  /**
   * Constructor.
   *
   * @param fname The name of the file that contains the properties and their
   *              values.
   */
  PropertyTable(const char* fname);

  /**
   * Destructor.
   */
  virtual ~PropertyTable();
  
  /**
   * Sets a property value.  Note that any previous value assigned to the key
   * will be lost.
   *
   * @param key A pointer to the property key string.
   * @param val A pointer to the property value string.
   */
  void set(const char* key, const char* val);

  /**
   * Loads the base property file into the table.  The directory
   * location for the base property file is used as the directory base
   * from which all regular loads are fetched relative to.
   *
   * @param fname A pointer to the property file name string.
   *
   * @return Returns true if the property file is loaded successfully, or
   *         false otherwise.
   */
  bool load(const char* fname);

  /**
   *  Dump the property information to an output
   *  stream.  Format can be read using a load.
   */
  void save(const char* fname);

  /**
   *  Print the property information to stdout.
   */
  void print();

  /**
   * Fetch the string associated with the specified key.  If the key is not
   * defined, then use the specified default value.
   *
   * @param key A pointer to the property key string.
   * @param def A pointer to the property key default value in case it has not
   *            yet been set.  Optional.
   *
   * @return A pointer to the property value string.
   */
  const char* get(const char* key, const char* def=NULL);

  /**
   * Fetch the boolean associated with the specified key.  If the key is not
   * defined, then use the specified default value.
   *
   * @param key A pointer to the property key string.
   * @param def The property key default value in case it has not yet been
   *            set.
   *
   * @return The property value.
   */
  bool getBool(const char* key, const bool def);

  /**
   * Fetch the integer associated with the specified key.  If the key is not
   * defined, then use the specified default value.
   *
   * @param key A pointer to the property key string.
   * @param def The property key default value in case it has not yet been
   *            set.
   *
   * @return The property value.
   */
  int getInt(const char* key, const int def);

  /**
   * Fetch the double associated with the specified key.  If the key is not
   * defined, then use the specified default value.
   *
   * @param key A pointer to the property key string.
   * @param def The property key default value in case it has not yet been
   *            set.
   *
   * @return The property value.
   */
  double getDbl(const char* key, const double def);

  /** 
   *  Fetch the unsigned long associated with the specified
   *  key.  If the key is not defined, then use the 
   *  hardcoded default value.
   *
   * @param key A pointer to the property key string.
   * @param def The property key default value in case it has not yet been
   *            set.
   *
   * @return The property value.
   */
  unsigned long getULong(const char* key, const unsigned long def);

  /** 
   *  Fetch an Internet address associated with the specified
   *  key.  If the key is not defined, then use the default value.
   *  Address is in network byte order (NBO)
   *
   * @param key A pointer to the property key string.
   * @param def The property key default value in case it has not yet been
   *            set.
   *
   * @return The property value.
   */
  unsigned long getAddr(const char* key, const unsigned long def);

  /** 
   *  Fetch an Internet address associated with the specified
   *  key.  If the key is not defined, then use the default value.
   *  Address is in network byte order (NBO)
   *
   * @param key A pointer to the property key string.
   * @param def The property key default value in case it has not yet been
   *            set.
   *
   * @return The property value.
   */
  unsigned long getAddr(const char* key, const char *def);

protected:
  /**
   * Performs a local load of the key/value pairs contained
   * in the file.
   *
   * @param fname    Name of the file to load
   * @param relative true if the file's location is relative to the basedir
   * @return Returns true if the property file is loaded successfully, or
   *         false otherwise.
   */
  bool localLoad(const char* fname, bool relative);

private:
  /**
   * The path to the loaded property file for use in expanding "+" characters
   * in value fields.
   */
  char* baseDir;

  // ==========================================================

  /**
   * The hash table that stores the properties and their values.
   */
  HTable propertyTbl;
  
  /**
   * \class PTKey
   *
   * This nested class stores a string-based hash table key.
   *
   * This is a private nested class of the PropertyTable class because it is
   * only meant to support the PropertyTable class.
   *
   * @author Sean P. Griffin
   */
  class PTKey : public HTableKey
  {
    
  public:
    
    /**
     * Constructor.
     *
     * @param key The key's value.
     */
    PTKey(const char* key);
    
    /**
     * Destructor.
     */
    virtual ~PTKey();
    
    /**
     * Implementation of the copy method from the HTableKey base class.
     *
     * @return A copy of the hash table key.
     */
    HTableKey* copy();
    
    /**
     * Implementation of the equals method from the HTableKey base class.
     *
     * @param key The key to compare this key with.
     *
     * @return True if the keys are equal, false otherwise.
     */
    bool equals(HTableKey* key);
    
    /**
     * Get the value of the key.
     *
     * @return The value of the key.
     */
    inline const char* getKey()
    {
      return keyValue;
    }
    
    /**
     * Implementation of the hash method from the HTableKey base class.
     *
     * @return An unsigned int that is the hash of the key.
     */
    unsigned int hash();
    
  private:
    
    /**
     * The value of the key.
     */
    char* keyValue;
    
  }; // end class PTKey
  
  /**
   * \class PTElem
   *
   * A nested class for hash table elements that each contains a string.\
   *
   * This is intended to be used by the PropertyTable class only.  Therefore,
   * it is a private nested class.
   *
   * @author Sean P. Griffin
   */
  class PTElem : public HTableElem
  {
    
  public:
    
    /**
     * Constructor.
     *
     * @param val The value to be stored in this hash table element.
     */
    PTElem(const char* val);
    
    /**
     * Destructor.
     */
    virtual ~PTElem();
    
    /**
     * Get the value of the element.
     *
     * @return The value of the element.
     */
    inline const char* getValue()
    {
      return value;
    }
    
    /**
     * Set the value of the element.
     *
     * @param val The new value for the element.
     */
    void setValue(const char* val);
    
  private:
    
    /**
     * The value to be placed into a hash table.
     */
    char* value;
    
  }; // end class PTElem
};

/**
 * Macro used to declare a property value within the
 * code.  The macro may be expanded in different ways
 * to support different functions.
 */
#define DEFINE_PROPERTY(KEY,TYPE) /* */

#endif
