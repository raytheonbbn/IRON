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

#include "PropertyTable.h"
#include "ZLog.h"

#ifdef _WINDOWS
#define snprintf _snprintf
#include <Winsock2.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//
// Class names used for logging.
//
static const char  cn[]    = "PropertyTable";
static const char  ptkcn[] = "PropertyTable::PTKey";
static const char  ptecn[] = "PropertyTable::PTElem";

PropertyTable::PropertyTable() : baseDir(NULL)
{
}

PropertyTable::PropertyTable(const char* fname) : baseDir(NULL)
{
  load(fname);
}

PropertyTable::~PropertyTable()
{
  if (baseDir) delete [] baseDir;
}

//============================================================================
void PropertyTable::set(const char* key, const char* val)
{
  static const char  mn[] = "set";
  
  PTKey*   htKey;
  PTElem*  htElem;
  PTElem*  htOldElem;
  
  if ((key == NULL) || (val == NULL))
  {
    zlogE(cn, mn, ("Bad argument.\n"));
    return;
  }
  
  //
  // We need to create an appropriate key and element so that the information
  // can be added to the hash table.
  //
  
  if ((htKey  = new PTKey(key)) == NULL)
  {
    zlogE(cn, mn, ("Key memory allocation error.\n"));
    return;
  }
  
  if ((htElem = new PTElem(val)) == NULL)
  {
    zlogE(cn, mn, ("Element memory allocation error.\n"));
    delete htKey;
    return;
  }
  
  //
  // Replace any existing property with the same key in the hash table.
  //
  
  if ((htOldElem = (PTElem*)propertyTbl.replace(htKey, htElem)) != NULL)
  {
    zlogW(cn, mn, ("Warning, replacing property key %s value %s with new "
                   "value %s.\n", key, htOldElem->getValue(), val));
    delete htOldElem;
  }
  
  //
  // The memory allocated for the key must be deleted. The ownership of the
  // memory that was allocated for the element is passed to the hash table.
  //
  
  delete htKey;
}


bool PropertyTable::load(const char* fname)
{
  // Clear out the old base directory.
  if (baseDir) { delete [] baseDir; baseDir = NULL; }

  // Extract the directory from the file name.

  char* x = strrchr((char *)fname,'/');
  if (x != NULL) {
    baseDir = new char[(int)(x - fname)+1];
    strncpy(baseDir,fname,x-fname);
    baseDir[x-fname] = '\0';
    return localLoad((char*)(x+1),true);
  } else {
    return localLoad(fname,false);
  }
}

bool PropertyTable::localLoad(const char* fname, bool relative)
{
  static const char  mn[] = "localLoad";

  if (fname == NULL) {
    zlogW(cn,mn,
	  ("No property file specified\n"));
    return false;
  }

#define MAX_NAMELEN 512
  char fullName[MAX_NAMELEN];
  if (relative) {
    if (baseDir != NULL) {
      snprintf(fullName,MAX_NAMELEN,"%s/%s",baseDir,fname);
    } else {
      snprintf(fullName,MAX_NAMELEN,"%s",fname);
    }
  } else {
    strncpy(fullName,fname,MAX_NAMELEN);
  }

  FILE* ifile = fopen(fullName,"r");
  if (ifile == NULL) {
    zlogE(cn,mn,
	  ("Unable to open property file %s\n",fullName));
    return false;
  }

  char line[1024];
  char tokA[1024];
  char tokB[1024];
  int tailPos;
  while( fgets(line,1024,ifile) != NULL) {
    int x = strlen(line);
    if (x > 1) {
      line[x-1] = '\0';
      sscanf(line,"%s %n",tokA,&tailPos);
      if (tokA[0] == '#') {
	// Skip
      } else if (strcmp(tokA,"include") == 0) {
	sscanf(line+tailPos,"%s",tokB);
	if (tokB[0] == '+') {
	  localLoad(&tokB[1],true);
	} else {
	  localLoad(tokB,false);
	}

      } else {
	sscanf(line+tailPos,"%s",tokB);
	if (tokB[0] == '"') {
	  // Quoted token (may include spaces)
	  char* start = strchr(line+tailPos,'"');
	  strcpy(tokB,start+1);
	  char* end =  strchr(tokB,'"');
	  (*end) = '\0';
	}

	if (tokA[0] == '+') {
	  // Add an element to a list.
	  char* tokA1 = tokA+1;
	  char tmp0[1024];
	  char tmp1[1024];
	  snprintf(tmp0,1024,"Num%s",tokA1);
	  int cnt = getInt(tmp0,0);
	  snprintf(tmp1,1024,"%d",cnt+1);
	  set(tmp0,tmp1);
	  snprintf(tmp0,1024,"%s%d",tokA1,cnt);	
	  set(tmp0,tokB);
	} else {
	  set(tokA,tokB);
	}
      }
    }
  }

  fclose(ifile);
  return true;
}

void PropertyTable::save(const char* fname)
{
  static const char  mn[] = "save";

  if (fname == NULL) {
    zlogW(cn,mn,
	  ("No property file specified\n"));
    return;
  }

  FILE* ofile = fopen(fname,"w");
  if (ofile == NULL) {
    zlogE(cn,mn,
	  ("Unable to open property file %s\n",fname));
    return;
  }

  /**
   * \todo Implement save by writting to a file.
   */
#ifdef XXX
  std::map<std::string, std::string ,ltString>::iterator i 
    = propertyTbl.begin();
  while (i != propertyTbl.end()) {
    if (strchr((*i).second.c_str(),' ') != NULL) {
      fprintf(ofile,"%s \"%s\"\n",
	      (*i).first.c_str(),
	      (*i).second.c_str());
    } else {
      fprintf(ofile,"%s %s\n",
	      (*i).first.c_str(),
	      (*i).second.c_str());
    }
    i++;
  }
#endif
  fclose(ofile);
}

void PropertyTable::print()
{
  /**
   * \todo Implement print method.
   */
#ifdef XXX
  std::map<std::string, std::string ,ltString>::iterator i 
    = propertyTbl.begin();
  while (i != propertyTbl.end()) {
    printf("%s ==> %s\n",
	   (*i).first.c_str(),
	   (*i).second.c_str());
    i++;
  }
#endif
}

const char* PropertyTable::get(const char* key, const char* def)
{
  static const char  mn[] = "get";
  
  PTKey*  htKey;
  if (key == NULL)
  {
    return(def);
  }
  
  //
  // Find the requested key.  If it is not found, then return the default
  // value.
  //
  if ((htKey = new PTKey(key)) == NULL)
  {
    zlogE(cn, mn, ("Key memory allocation failure.\n"));
    return def;
  }
  
  PTElem* htElem = (PTElem*)propertyTbl.get(htKey);
  
  //
  // We are done with the key now, so free it.
  //
  
  delete htKey;
  
  if (htElem == NULL)
  {
    return def;
  }
  
  const char* v = htElem->getValue();
  
  if ((v != NULL) && (v[0] == '+'))
  {
    //
    // Create a place to build up the new value to place in the element.
    //
    char* nv;
    
    //
    // Resolve a parameter relative to the base directory of the property
    // file.
    //
    if (baseDir != NULL)
    {
      nv = new char[strlen(v) + strlen(baseDir) + 1];
      
      //
      // Prepend the base dir to the property value and remove the + from the
      // property value.
      //
      
      sprintf(nv, "%s/%s", baseDir, &v[1]);
    }
    else
    {
      nv = new char[strlen(v)];
      
      //
      // Simply remove the + from the property value.
      //
      
      sprintf(nv, "%s", &v[1]);
    }
    
    //
    // Now that we must be sure to set the new value for the element.
    //
    htElem->setValue(nv);
    
    delete [] nv;
  }
  
  //
  // Get the value from the element to return.
  //
  return htElem->getValue();
}

bool PropertyTable::getBool(const char* key, const bool def)
{
  bool rtn = def;
  const char* v = get(key);
  if (v != NULL) {
    if (strcmp(v,"true") == 0) { rtn = true; }
    else if (strcmp(v,"TRUE") == 0) { rtn = true; }
    else if (strcmp(v,"True") == 0) { rtn = true; }
    else { rtn = false; }
  }
  return rtn;
}

int PropertyTable::getInt(const char* key, const int def)
{
  int rtn = def;
  const char* v = get(key);
  if (v != NULL) {
    rtn = atoi(v);
  }
  return rtn;
}

double PropertyTable::getDbl(const char* key, const double def)
{
  double rtn = def;
  const char* v = get(key);
  if (v != NULL) {
    rtn = atof(v);
  }
  return rtn;
}

unsigned long PropertyTable::getULong(const char* key, const unsigned long def)
{
  unsigned long rtn = def;
  const char* v = get(key);
  if (v != NULL) {
    rtn = strtoul(v,NULL,0);
  }
  return rtn;
}

unsigned long PropertyTable::getAddr(const char* key, const unsigned long def)
{
  unsigned long rtn = def;
  const char* v = get(key);
  if (v != NULL) {
    rtn = inet_addr(v);
  }
  return rtn;
}

unsigned long PropertyTable::getAddr(const char* key, const char *def)
{
  unsigned long rtn;
  const char* v = get(key);
  if (v != NULL) {
    rtn = inet_addr(v);
  }
  else {
    if (def != NULL) {
	rtn = inet_addr(def);
      }
    else {
      rtn = 0;
    }
  }
  return rtn;
}

//============================================================================
//============================================================================
//============================================================================


PropertyTable::PTKey::PTKey(const char* key)
{

  //
  // Method name used for logging.
  //

  static const char mn[] = "PTKey";

  //
  // Store the key, if specified.
  //

  if (key == NULL)
  {
    zlogE(ptkcn, mn, ("No key specified.\n"));

    if ((keyValue = new char[4]) != NULL)
    {
      keyValue[0] = '\0';
    }
    else
    {
      zlogE(ptkcn, mn, ("Memory allocation failure.\n"));
    }
  }
  else
  {
    if ((keyValue = new char[strlen(key) + 1]) != NULL)
    {
      strcpy(keyValue, key);
    }
    else
    {
      zlogE(ptkcn, mn, ("Memory allocation failure.\n"));
    }
  }
}

PropertyTable::PTKey::~PTKey()
{

  //
  // Free all of the dynamically allocated memory.
  //

  if (keyValue != NULL)
  {
    delete [] keyValue;
    keyValue = NULL;
  }
}

HTableKey*
PropertyTable::PTKey::copy()
{

  //
  // Create a copy of this class and return it. Ownership of the memory is
  // passed to the calling object.
  //

  PTKey* rv = new PTKey(keyValue);

  return rv;
}

bool
PropertyTable::PTKey::equals(HTableKey* key)
{
  return (strcmp(keyValue, ((PTKey*)key)->getKey()) == 0);
}

unsigned int
PropertyTable::PTKey::hash()
{
  int           counter;
  int           len     = strlen(keyValue);
  unsigned int  keyHash = 0;
  
  for (counter = 0; counter < len; counter++)
  {
    
    //
    // The hash is simply the sum of the individual characters that make up
    // the key.
    //
    
    keyHash += keyValue[counter];
  }
  
  return keyHash;
}

PropertyTable::PTElem::PTElem(const char* val)
{
  value = NULL;
  
  setValue(val);
}

PropertyTable::PTElem::~PTElem()
{

  //
  // Free all of the dynamically allocated memory.
  //

  if (value != NULL)
  {
    delete [] value;
    value = NULL;
  }
}

void
PropertyTable::PTElem::setValue(const char* val)
{
  //
  // Method name used for logging.
  //

  static const char mn[] = "setValue";
  
  if (value != NULL)
  {

    //
    // There is already a value, so we must be sure to delete it before
    // setting it again to prevent memory leaks.
    //
    
    delete [] value;
  }

  //
  // Store the value, if specified.
  //

  if (val == NULL)
  {
    zlogE(ptecn, mn, ("No value specified.\n"));

    if ((value = new char[4]) != NULL)
    {
      value[0] = '\0';
    }
    else
    {
      zlogE(ptecn, mn, ("Memory allocation failure.\n"));
    }
  }
  else
  {
    if ((value = new char[strlen(val) + 1]) != NULL)
    {
      strcpy(value, val);
    }
    else
    {
      zlogE(ptecn, mn, ("Memory allocation failure.\n"));
    }
  }
}

