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
#include "ZLog.h"
#include <string.h>
#include <stdlib.h>

ZLog ZLog::stdZlog;

//============================================================================
ZLog::ZLog() : 
  mask(ZLOG_ALL), maskString(NULL),
  logFileBase(NULL), logFileName(NULL), logFile(stdout), logFileIndex(-1), 
  maxLogFileSize(0), maxLogFileNum(0), logFileChangeCmd(NULL),
  ignoreList(NULL) 
{
  if (pthread_mutex_init(&mutex, NULL) != 0)
  {
    perror("ZLog::init pthread_mutex_init error");
  }
  ZLog::clearIgnore();
  ZLog::logChangeCommand();
}

//============================================================================
ZLog::~ZLog() 
{
  lock();

  if (ignoreList != NULL) {
    free(ignoreList);
  }
  
  if (logFileName) { 
    fclose(logFile);
    delete [] logFileName; 
    logFileName = NULL; 
  }

  if (logFileBase) { 
    delete [] logFileBase; 
    logFileBase = NULL; 
  }

  if (logFileChangeCmd) { 
    delete [] logFileChangeCmd; 
    logFileChangeCmd = NULL; 
  }

  unlock();
  pthread_mutex_destroy(&mutex);
}

//============================================================================
void ZLog::maxFileSize(long s)
{
  maxLogFileSize = s;
}

//============================================================================
void ZLog::maxFileNum(int n)
{
  maxLogFileNum = n;
}

//============================================================================
void ZLog::level(const char* s)
{
  int  m = 0;
  char* ms = NULL;
  
  if (s == NULL)
  {
    return;
  }
  
  if (strcmp(s, "All") == 0)
  {
    m = ZLOG_ALL;
  }
  else
  {
    if (strchr(s, 'F')) { m |= ZLOG_F; }
    if (strchr(s, 'E')) { m |= ZLOG_E; }
    if (strchr(s, 'W')) { m |= ZLOG_W; }
    if (strchr(s, 'I')) { m |= ZLOG_I; }
    if (strchr(s, 'A')) { m |= ZLOG_A; }
    if (strchr(s, 'D')) { m |= ZLOG_D; }
    if (strchr(s, 'S')) { m |= ZLOG_S; }
    if (strchr(s, 'L')) { m |= ZLOG_LL; }

    ms = new char[strlen(s)+1];
    strcpy(ms,s);
  }
  
  mask = m;

  char* tmp = maskString;
  maskString = ms;
  delete [] tmp;
}

//============================================================================
void ZLog::file(const char* filename)
{
  if ((filename == NULL) && (logFile == stdout)) {
    return;
  } else if ((filename != NULL) && (logFileBase != NULL)) {
    if (strcmp(filename,logFileBase) == 0) {
      return;
    }
  }

  // New filename - change and swap the internal file details.
  delete [] logFileBase;
  if (filename != NULL) {
    logFileBase = new char[strlen(filename)+1];
    strcpy(logFileBase,filename);
  } else {
    logFileBase = NULL;
  }
  logFileIndex = -1;
  updateFile();
}

//============================================================================
void ZLog::updateFile()
{
  // Update the logFileIndex
  logFileIndex++;
  if ((maxLogFileNum > 0) &&
      (logFileIndex > maxLogFileNum)) {
    logFileIndex = 1;
  }


  // Construct the command to be run (if any) on the
  // change.
  char* cmd = NULL;
  if ((logFileChangeCmd) && (logFileName)) {
    cmd = new char[strlen(logFileChangeCmd) + strlen(logFileName) + 2];
    sprintf(cmd,logFileChangeCmd,logFileName);
  }

  // Calculate the new file name and generate a message
  // that the file is changing in the old file.
  char* tmpname = NULL;
  if ((logFileBase != NULL) &&
      (strlen(logFileBase) > 0)) {
    if (logFileIndex > 0) {
      int ms = strlen(logFileBase) + 32;
      tmpname = new char[ms];
      snprintf(tmpname,ms-1,"%s-%d",logFileBase,logFileIndex);
    } else {
      tmpname = new char[strlen(logFileBase)+1];
      strcpy(tmpname,logFileBase);
    }

    // Print a specially formatted warning message (that cannot
    // be blocked
    preamble("Z","ZLog","LogChange");
    zprintf ("WARNING: Logging file changed to %s\n",tmpname);

  } else {
    // Print a specially formatted warning message (that cannot
    // be blocked
    preamble("Z","ZLog","LogChange");
    zprintf ("WARNING: Logging file changed to stdout\n");
  }

  // Close the existing file (if appropriate).
  if (logFile != stdout) { 
    delete [] logFileName;
    logFileName = NULL;
    fclose(logFile); 
  }

  // Set the internal name of the file and open as appropriate.
  logFileName = tmpname;
  if (logFileName == NULL) { 
    logFile = stdout;
  } else {
    logFile = fopen(logFileName,"w");
  }

  // Execute the command if there is one.
  if (cmd) { 
    // Print a specially formatted warning message (that cannot
    // be blocked
    preamble("Z","ZLog","LogCommand");
    zprintf("Executing command over old logfile: \"%s\"\n",cmd);
    system(cmd); 
    delete [] cmd; 
  }
}

//============================================================================
void ZLog::logChangeCommand(const char* const cmd)
{
  if (cmd == NULL) {
    if (logFileChangeCmd) { delete [] logFileChangeCmd; }
    logFileChangeCmd = NULL;
    return;
  }
  logFileChangeCmd = (char*)realloc(logFileChangeCmd,
				    strlen(cmd) + 2);
  if (logFileChangeCmd != NULL) {
    strcpy(logFileChangeCmd,cmd);
  }
}

//============================================================================
void ZLog::clearIgnore()
{
  ignoreList = (char*)realloc(ignoreList,2);
  if (ignoreList != NULL) {
    strcpy(ignoreList,":");
  }
}

//============================================================================
void ZLog::ignore(const char* const context)
{
  if (context == NULL) return;
  ignoreList = (char*)realloc(ignoreList,
			      strlen(ignoreList) + strlen(context) + 2);
  if (ignoreList != NULL) {
    strcat(ignoreList,context);
    strcat(ignoreList,":");
  }
}

//============================================================================

void ZLog::zlog(const char* l, const char* c, const char* m, 
		const char* format, ...)
{
  if (((maskString == NULL) || (strstr(maskString,l))) &&
      (shouldShow(c))) {
    lock();
    checkFile();
    preamble(l,c,m);

    va_list argp;
    va_start(argp, format);
    vfprintf(logFile, format, argp);
    fflush(logFile);
    va_end(argp);

    unlock();
  }
}


