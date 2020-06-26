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
#ifndef _ZLOG_H_
#define _ZLOG_H_

#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#ifdef ZLOG_TIME
#include <sys/time.h>
#endif

// This class is supported within windows.
#include "common_windows.h"

/**
 * Logging levels.
 *
 *   F = Fatal:   Catastophic errors, execution will stop immediately.
 *   E = Error:   Serious errors, possible missing data or data corruption.
 *   W = Warning: System can continue operation without data loss.
 *   I = Info:    High level events concerning major functions.
 *   A = Analyis: Medium level events, i.e. subsystem startup and shutdown.
 *   D = Debug:   Low level events to help track algorithm execution.
 *   S = Status:  Health and status monitoring
 */
#define ZLOG_F    0x01
#define ZLOG_E    0x02
#define ZLOG_W    0x04
#define ZLOG_I    0x08
#define ZLOG_A    0x10
#define ZLOG_D    0x20
#define ZLOG_S    0x40
#define ZLOG_LL   0x80
#define ZLOG_ALL  0xff


/**
 * \class ZLog
 * \ingroup common
 *
 * A class for logging messages to stdout.
 *
 * Each log statement may be at one of six levels:
 *
 * - zlogF(): Catastophic errors, execution will stop immediately.
 * - zlogE(): Serious errors, possible missing data or data corruption.
 * - zlogW(): System can continue operation without data loss.
 * - zlogI(): High level events concerning major functions.
 * - zlogA(): Medium level events, i.e. subsystem startup and shutdown.
 * - zlogD(): Low level events to help track algorithm execution.
 * - zlogS(): Health and status events
 *
 * - zlogLL(): Special log events for Lincoln Labs
 *
 * The levels that are actually logged at run-time are controlled by a
 * mask, which may be set using level().  All six levels are available
 * for logging when compiled with the "-D DEBUG_LOGGING" preprocessor
 * flag.  When compiled without the "-D DEBUG_LOGGING" preprocessor
 * flag, only Fatal, Error and Warning logging is available.
 *
 * @author Brian DeCleene, Mark Keaton
 */
class COMMON_API ZLog
{
public:
  /**
   * Shared instances of the zlog services.  All logging runs through this
   * singleton to ensure a consistent common look and feel.
   */
  static ZLog stdZlog;

public:
  // ==================================================================
  // STATIC FUNCTIONS ON THE MASTER COMMON ZLOG SINGLETON

  /**
   * Function on common standard zlog singleton
   * See level
   */
  inline static void Level(const char* s)
  { stdZlog.level(s); }
  
  /**
   * Function on common standard zlog singleton
   * See maxFileSize
   */
  inline static void MaxFileSize(long s)
  { stdZlog.maxFileSize(s); }
  
  /**
   * Function on common standard zlog singleton
   * See maxFileNum
   */
  inline static void MaxFileNum(int n)
  { stdZlog.maxFileNum(n); }
  
  /**
   * Function on common standard zlog singleton
   * See logChangeCommand
   */
  inline static void LogChangeCommand(const char* const cmd)
  { stdZlog.logChangeCommand(cmd); }
  

  /**
   * Function on common standard zlog singleton
   * See file
   */
  inline static void File(const char* filename=NULL)
  { stdZlog.file(filename); }
  
  /**
   * Function on common standard zlog singleton
   * See clearIgnore
   */
  inline static void ClearIgnore() 
  { stdZlog.clearIgnore(); }
  
  /**
   * Function on common standard zlog singleton
   * See ignore
   */
  inline static void Ignore(const char* const context) 
  { stdZlog.ignore(context); }
  
  /**
   * Function on common standard zlog singleton
   * See shouldShow
   */
  inline static int ShouldShow(const char* const context) 
  { return stdZlog.shouldShow(context); }

  /**
   * Function on common standard zlog singleton
   * See getMask
   */
  inline static int GetMask() 
  { return(stdZlog.getMask()); }

  /**
   * Function on common standard zlog singleton
   * See compileBanner
   */
  inline static void CompileBanner(const char* l, const char* c, const char* m)
  { stdZlog.compileBanner(l,c,m); }


 public:
  // ==================================================================
  // NORMAL OPERATIONS

  /**
   * Set the levels to be logged.  By default, all available levels are
   * logged.
   *
   * @param s The levels to be logged in a string format.  Valid levels are
   *          any of the letters "FEWIAD" in any combination, or else the
   *          string "All".
   */
  void level(const char* s);
  
  /**
   * Set the maximum log file size.  If this is set to zero, then do not
   * split the log into separate files.  Otherwise, split the file into
   * separate files when the file size exceeds the specifed value.
   *
   * If the file is standard out, then this has no effect.
   * 
   * @param s Maximum log file size.
   */
  void maxFileSize(long s);
  
  /**
   * Set the maximum number of log files to construct beyond the initial log
   * file.  The log file index will rotate from 1 to n and repeat.  For example,
   * setting the value to 4 will create log files...
   *     something.log
   *     something.log-1
   *     something.log-2
   *     something.log-3
   *     something.log-4
   *     something.log-1
   *     something.log-2
   *     ...
   *
   * If this is set to zero, then there is no limit on the number of
   * supplemental log files to construct.
   *
   * @param n Maximum number of supplemental log files to construct.
   */
  void maxFileNum(int n);
  
  /**
   * Execute the specified command on the old logfile when
   * the log file changes.  This is useful to perform post
   * processing on the file.  The command is run using system
   * and, unless run in the background, will block subsequent
   * logging until complete.
   * 
   * The command may include a %s which will be replaced with
   * the name of the previous log file.
   *
   * \todo XXX This is a MAJOR security hole.  By editing the
   * configuration file, a user can cause the system to execute a
   * command with the same privlidges as the process.  Needs to be
   * addressed at a later time.
   *
   * @param cmd The command to run.
   */
  void logChangeCommand(const char* const cmd = NULL);
  

  /**
   * Set where the logging should be directed.  By default, logging is
   * directed to stdout.
   *
   * @param filename Name of the output file for the logging.  If this is
   *                 null, then use stdout.
   */
  void file(const char* filename=NULL);
  
  /**
   * Clear the ignore list.
   */
  void clearIgnore();
  
  /**
   * Add a class (i.e., context) to ignore during logging.
   *
   * @param context The context to ignore.
   */
  void ignore(const char* const context);
  
  /**
   * Get the current logging level mask.
   *
   * @return The current logging level mask in integer format.  This integer
   *         is created by ORing ZLOG_F through ZLOG_D together.
   */
  inline int getMask() const { return(mask); }


  /**
   * Get the current logging level mask.
   *
   * @return The current logging level mask in integer format.  This integer
   *         is created by ORing ZLOG_F through ZLOG_D together.
   */
  inline void compileBanner(const char* l, const char* c, const char* m)
  {
    zlog(l,c,m,"Compiled %s %s\n",__DATE__,__TIME__);
  }

  /**
   * Test to see if the context in question should be shown.
   */
  inline int shouldShow(const char* const context) 
  {
    int rtn = 0;

    if (ignoreList == NULL) {
      // This code should only get executed if either
      // a) the class was not initialized yet or
      // b) a realloc call failed.
      // In both cases, we want to ignore all logging
      // messages since the state of the intenal class
      // is suspect.
      return rtn;
    }

    char* tmp = new char[strlen(context)+3];
    sprintf(tmp,":%s:",context);
    if (strstr(ignoreList,tmp) == NULL) {
      rtn = 1;
    }
    delete [] tmp;
    return rtn;
  }

  /**
   * Update the internal file information to write to the specified
   * derived file name.
   *
   * @param filename Derived filename
   *                 
   */
  void updateFile();
  
  /**
   * Routine for generating the preamble to any message
   */
  inline void preamble(const char* l, const char* c, const char* m)
  {
#ifdef ZLOG_TIME
    struct timeval now;
    if (gettimeofday(&now, NULL) == 0) {
      double reportTime = now.tv_sec + now.tv_usec/1000000.0;
      zprintf("%f %s [%s::%s] ",reportTime,l,c,m);
    } else {
      zprintf("??? %s [%s::%s] ",l,c,m);
    }
#else
    zprintf("%s [%s::%s] ",l,c,m);
#endif
  }

  /**
   * Routine to perform the formated print so that all of the logging messages
   * have some same basic structure.
   */
  inline void zprintf(const char *format, ...)
  {
    va_list argp;
    va_start(argp, format);
    vfprintf(logFile, format, argp);
    fflush(logFile);
    va_end(argp);
  }
  
  /**
   * A generic routine for printing a log message.  The macros should
   * actually be used rather than this function so that they are 
   * appropriately stripped from the code as required.  However,
   * this may be used to construct spontanous levels that cannot
   * be stripped from execution.
   */
  void zlog(const char* l, const char* c, const char* m, 
	    const char* format, ...);
  
public:
  
  /**
   * The default constructor.
   */
  ZLog();
  

  /**
   * The default destructor
   */
  ~ZLog();
  
  /**
   * Lock the instance in order to make a grouped series of prints.
   */
  inline void lock() { pthread_mutex_lock(&mutex); };

  /**
   * Unlock the instance after making a grouped series of prints.
   */
  inline void unlock() { pthread_mutex_unlock(&mutex); };

  /**
   * Checks to see if we need to advance the file to a new file
   * when the size gets large.
   */
  inline void checkFile() {
    if ((maxLogFileSize) && (logFile != stdout)) {
      if (ftell(logFile) >= maxLogFileSize) {
	updateFile();
      }
    }
  }

private:
  /**
   * The logging level mask by bit mask (for fast comparisons
   * using the standard levels).
   */
  int mask;

  /**
   * The logging level mask by ASCII (for slower text-based
   * tests of the level).  Useful for non-standard levels.
   */
  char* maskString;

  /**
   * Base for the logfile name construction.  
   * Set to NULL if we are using stdout.
   */
  char* logFileBase;

  /**
   * Name for the current log file (derived from the
   * base and the other associated parameters).
   * 
   * When printing to stdout, this is NULL.
   */
  char* logFileName;

  /**
   * The output log file
   */
  FILE* logFile;
  
  /**
   * Index of the number of split log that have been created.
   * When the index is zero, we do not appends the index to the
   * file name.
   */
  int logFileIndex;

  /**
   * Size threshold for logfiles.  Split into a separate file
   * when the size exceeds this value.
   */
  long maxLogFileSize;

  /**
   * Maximum index for the supplemental log files.  Files will
   * rotate between 1 and n repeatidly.  If set to zero, then 
   * the number of files will continue ad-nauseum.
   */
  int maxLogFileNum;

  /**
   * Run the following command when the log file changes.
   * If set to null, do not run any command.
   */
  char* logFileChangeCmd;

  /**
   * List of classes to ignore during logging.
   */
  char* ignoreList;

  /**
   * Mutex to protect the 
   * and dequeues.
   */
  pthread_mutex_t  mutex;

}; // end class ZLog


/*
 * Logging definitions.
 *
 *   F = Fatal:   Catastophic errors, execution will stop immediately.
 *   E = Error:   Serious errors, possible missing data or data corruption.
 *   W = Warning: System can continue operation without data loss.
 *   I = Info:    High level events concerning major functions.
 *   A = Analyis: Medium level events, i.e. subsystem startup and shutdown.
 *   D = Debug:   Low level events to help track algorithm execution.
 *   S = Status:  Health and status events
 *
 * Levels F, E, W and S are always logged.  Levels I, A and D are only
 * logged if compiled with "-D DEBUG_LOGGING" and the levels are
 * explicitly set via level().
 *
 */

// ============================================================
/*
 * Logging definitions for the major problems (levels F, E, and W)
 */
#define zlogF(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_F) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("F",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#define zlogE(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_E) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("E",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#define zlogW(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_W) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("W",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#define zlogS(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_S) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("S",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#define zlogLL(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_LL) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("L",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#ifdef DEBUG_LOGGING

// ============================================================
/**
 * Additional logging levels when debug logging is enabled. If
 * DEBUG LOGGING is no enabled, these log levels are all
 * disabled.
 */

#define zlogI(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_I) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("I",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#define zlogA(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_A) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("A",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#define zlogD(C,M,S)  if ((ZLog::stdZlog.getMask()&ZLOG_D) && \
                          (ZLog::stdZlog.shouldShow(C))) { \
                        ZLog::stdZlog.lock(); \
                        ZLog::stdZlog.checkFile(); \
                        ZLog::stdZlog.preamble("D",C,M); \
                        ZLog::stdZlog.zprintf S; \
                        ZLog::stdZlog.unlock(); \
                      }

#else

#define zlogI(C,M,S)  /* */
#define zlogA(C,M,S)  /* */
#define zlogD(C,M,S)  /* */

#endif

#endif


