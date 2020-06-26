// IRON: iron_headers
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

/// \brief The IRON logging source file.
///
/// Provides the IRON software with a flexible logging capability.  May be
/// directed to stdout, stderr, or a file.  The logging levels to be output
/// are dynamically selectable.

#include "log.h"

#include "inttypes.h"

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/time.h>
#include <sys/uio.h>


using ::iron::Log;


//
// Uncomment for log messages to use relative times.  Leave commented out for
// log messages to use absolute times (better for correlating log files from
// multiple systems).
//

// #define LOG_RELATIVE_TIME 1

//
// If defined, LogF always aborts, and attempts to change whether LogF
// aborts will result in aborting as well.  The point is to make it
// clear to both humans and static analyzers that LogF cannot return.
//
#define LOGF_ALWAYS_ABORTS 1

//
// Static class members.
//

int                         Log::mask_           = (LOG_FATAL |
                                                    LOG_ERROR |
                                                    LOG_WARNING |
                                                    LOG_INFO);
int                         Log::cmask_cnt_      = 0;
std::map<std::string, int>  Log::cmask_map_;
FILE*                       Log::output_fd_      = stdout;
bool                        Log::start_time_set_ = false;
struct timeval              Log::start_time_     = {0, 0};
pthread_mutex_t             Log::mutex_          = PTHREAD_MUTEX_INITIALIZER;
#ifndef LOGF_ALWAYS_ABORTS
bool                        Log::logf_abort_     = true;
#endif // LOGF_ALWAYS_ABORTS
bool                        Log::logc_active_    = true;
std::string                 Log::output_file_name_ = "";

#ifdef LOG_MIN
#define MIN_LOG_HEADER "IRON COMPRESSED LOG"
#define START_TIME_FORMAT_ID 0
#define PREFIX_FORMAT_ID 1
#define DESTROY_FORMAT_ID 2
// Leave room for other internal log records 
#define FIRST_REGULAR_FORMAT_ID 100 
uint32_t                    Log::next_format_id_ = FIRST_REGULAR_FORMAT_ID;
char                        Log::outbuff_[OUTPUT_BUFFER_SIZE];
#endif

//============================================================================
void Log::SetDefaultLevel(const std::string& levels)
{
  Log::mask_ = Log::StringToMask(levels);
}

//============================================================================
std::string Log::GetDefaultLevel()
{
  char  mask_str[8];

  Log::MaskToString(Log::mask_, mask_str);

  return std::string(mask_str);
}

//============================================================================
void Log::SetClassLevel(const std::string& class_name,
                        const std::string& levels)
{
  Log::cmask_map_[class_name] = Log::StringToMask(levels);
  Log::cmask_cnt_             = Log::cmask_map_.size();
}

//============================================================================
void Log::SetOutputToStdOut()
{
  Log::SetNewFileDescriptor(stdout);
}

//============================================================================
void Log::SetOutputToStdErr()
{
  Log::SetNewFileDescriptor(stderr);
}

//============================================================================
bool Log::SetOutputFile(const std::string file_name, bool append)
{

  //
  // Attempt to open the output file.  If successful, then make the change.
  //

  FILE*  new_fd = fopen(file_name.c_str(), (append ? "a" : "w"));

  if (new_fd == NULL)
  {
    return false;
  }
  Log::output_file_name_ = file_name;

  Log::SetNewFileDescriptor(new_fd);

  return true;
}

//============================================================================
std::string Log::GetOutputFileName()
{
  return Log::output_file_name_;
}

//============================================================================
void Log::Flush()
{
  fflush(Log::output_fd_);
}

//============================================================================
bool Log::SetAbortOnFatalLogging(bool abort_flag)
{
#ifdef LOGF_ALWAYS_ABORTS
  abort();
  return true;
#else // LOGF_ALWAYS_ABORTS
  bool  old_setting = logf_abort_;
  logf_abort_       = abort_flag;
  return old_setting;
#endif // LOGF_ALWAYS_ABORTS
}

//============================================================================
bool Log::SetConfigLoggingActive(bool config_active)
{
  bool old_setting = logc_active_;
  logc_active_ = config_active;
  return old_setting;
}

//============================================================================
bool Log::WouldLog(Level level, const char* cn)
{
#ifndef DEBUG
  if (level == LOG_DEBUG)
  {
    // debug is compiled out for optimized
    return false;
  }
#endif

  if (level == LOG_CONFIG)
  {
    return logc_active_;
  }

  // Only check for a class name logging level if there is a class name and
  // there is at least one class name in the map.
  int mask = mask_;
  if (cmask_cnt_ > 0 && cn != NULL)
  {
    std::map<std::string, int>::iterator it = cmask_map_.find(std::string(cn));
    if (it != cmask_map_.end())
    {
      mask = (*it).second;
    }
  }
  return mask & level;
}
 
#ifdef LOG_MIN

//============================================================================
#define CLEAR_ALL_FOUND()                                               \
  do {                                                                  \
    percent_found = false;                                              \
    h_found = false;                                                    \
    hh_found = false;                                                   \
    l_found = false;                                                    \
    ll_found = false;                                                   \
    j_found = false;                                                    \
    z_found = false;                                                    \
    t_found = false;                                                    \
    L_found = false;                                                    \
  } while (0)

#define UNSUPPORTED_LEN_MODIFIER_FMT "Log::FormatTypes(): Error '%c' " \
  "length modifier not supported for '%c' conversion specifier.\n"     \
  "\tThe compressed log file may be corrupted from this point on."

void Log::FormatTypes(const char* format,
                      std::vector<Log::FormatType>* types)
{
  // This is a simplified implementation of format string parsing.
  // It does NOT validate format string. Things like extra length modifiers,
  // stray % characters with no matching conversion specifier, etc will
  // break this and lead to unspecified behavior.
  Log::FormatType t;
  bool percent_found = false;
  bool h_found = false;
  bool hh_found = false;
  bool l_found = false;
  bool ll_found = false;
  bool j_found = false;
  bool z_found = false;
  bool t_found = false;
  bool L_found = false;

  for (const char* curr = format; *curr != '\0'; curr++)
  {
    if (percent_found)
    {
      switch(*curr)
      {
        // ----- Literal %
      case '%':
        percent_found = false;
        break;
        // ----- Length Modifiers
      case 'h':
        if (h_found)
        {
          hh_found = true;
          h_found = false;
        } else {
          h_found = true;
        }
        break;
      case 'l':
        if (l_found)
        {
          ll_found = true;
          l_found = false;
        } else {
          l_found = true;
        }
        break;
      case 'j':
          j_found = true;
        break;
      case 'z':
          z_found = true;
        break;
      case 't':
          t_found = true;
        break;
      case 'L':
          L_found = true;
        break;
        // ----- Conversion Specifiers
      case 'c':
        if (l_found) {
          fprintf(stderr, UNSUPPORTED_LEN_MODIFIER_FMT, 'l', *curr);
          CLEAR_ALL_FOUND();
          break;
        }
        types->push_back(Log::FORMAT_INT);
        CLEAR_ALL_FOUND();
        break;
      case 's':
        if (l_found) {
          fprintf(stderr, UNSUPPORTED_LEN_MODIFIER_FMT, 'l', *curr);
          CLEAR_ALL_FOUND();
          break;
        }
        types->push_back(Log::FORMAT_CHARSTAR);
        CLEAR_ALL_FOUND();
        break;
      case 'd':
      case 'i':
        if (hh_found)
        {
          t = Log::FORMAT_SCHAR;
        }
        else if (h_found)
        {
          t = Log::FORMAT_SHORT;
        }
        else if (l_found)
        {
          t = Log::FORMAT_LONG;
        }
        else if (ll_found)
        {
          t = Log::FORMAT_LLONG;
        }
        else if (j_found)
        {
          t = Log::FORMAT_INTMAX;
        }
        else if (z_found)
        {
          t = Log::FORMAT_SSIZE;
        }
        else if (t_found)
        {
          t = Log::FORMAT_PTRDIFF;
        }
        else 
        {
          t = Log::FORMAT_INT;
        }
        types->push_back(t);
        CLEAR_ALL_FOUND();
        break;
      case 'o':
      case 'x':
      case 'X':
      case 'u':
        if (hh_found)
        {
          t = Log::FORMAT_UCHAR;
        }
        else if (h_found)
        {
          t = Log::FORMAT_USHORT;
        }
        else if (l_found)
        {
          t = Log::FORMAT_ULONG;
        }
        else if (ll_found)
        {
          t = Log::FORMAT_ULLONG;
        }
        else if (j_found)
        {
          t = Log::FORMAT_UINTMAX;
        }
        else if (z_found)
        {
          t = Log::FORMAT_SIZE;
        }
        else if (t_found)
        {
          fprintf(stderr, UNSUPPORTED_LEN_MODIFIER_FMT, 't', *curr);
          CLEAR_ALL_FOUND();
          break;
        }
        else 
        {
          t = Log::FORMAT_UINT;
        }
        types->push_back(t);
        CLEAR_ALL_FOUND();
        break;
      case 'f':
      case 'F':
      case 'e':
      case 'E':
      case 'a':
      case 'A':
      case 'g':
      case 'G':
        if (L_found) {
          fprintf(stderr, UNSUPPORTED_LEN_MODIFIER_FMT, 'l', *curr);
          CLEAR_ALL_FOUND();
          break;
        }
        types->push_back(Log::FORMAT_DOUBLE);
        CLEAR_ALL_FOUND();
        break;
      case 'p':
        types->push_back(Log::FORMAT_VOID);
        CLEAR_ALL_FOUND();
        break;
      case 'n':
        fprintf(stderr, "Log::FormatTypes(): Error %%n not supported.\n");
        CLEAR_ALL_FOUND();
        break;
      }
    }
    else if (*curr == '%')
    {
      percent_found = true;
    }
  }
}

//============================================================================
#define FAILED_WRITE "Log::WriteLogRecord: Error writing to log file. %s\n"

#define SERIALIZE_ARG(value_ptr, value_len, outbuff_idx)                \
  do {                                                                  \
    uint32_t value_size = static_cast<uint32_t>(value_len);             \
    memcpy(&Log::outbuff_[outbuff_idx], (char *)(&value_size),          \
           sizeof(value_size));                                         \
    outbuff_idx += sizeof(value_size);                                  \
    memcpy(&Log::outbuff_[outbuff_idx], (char *)(value_ptr),            \
           value_size);                                                 \
    outbuff_idx += value_size;                                          \
  } while (0)

#define SERIALIZE_VARARG(va_type, va_list, outbuff_idx)                 \
  do {                                                                  \
    va_type value = va_arg(va_list, va_type);                           \
    SERIALIZE_ARG(&value, sizeof(value), outbuff_idx);                  \
  } while (0)

// Many types are promoted to larger types when passed as varargs.
// This gets them from the arg list as the prmoted type, but writes
// them out as the actual type.
#define SERIALIZE_VARARG_PROMOTED(a_type, p_type, va_list, outbuff_idx) \
  do {                                                                  \
    p_type p_value = va_arg(va_list, p_type);                           \
    a_type a_value = static_cast<a_type>(p_value);                      \
    SERIALIZE_ARG(&a_value, sizeof(a_value), outbuff_idx);              \
  } while (0)

void Log::WriteLogRecord(uint32_t id, bool first_call,
                         std::vector<Log::FormatType>* types,
                         const char* format, ...)
{
  va_list args;
  va_start(args, format);

  Log::WriteLogRecordList(id, first_call, types, format, &args);

  va_end(args);
}

void Log::WriteLogRecordList(uint32_t id, bool first_call,
                             std::vector<Log::FormatType>* types,
                             const char* format, va_list *args)
{
  int record_fields = 1; // id

  if (first_call)
  {
    Log::FormatTypes(format, types);
    record_fields += 3; // format_length, format, arg_count
  }

  uint32_t format_args = static_cast<uint32_t>(types->size());
  int outbuff_idx = 0;
  memcpy(&Log::outbuff_[outbuff_idx], &id ,sizeof(id));
  outbuff_idx += sizeof(id);

  if (first_call)
  {
    uint32_t format_len = static_cast<uint32_t>(strlen(format)) + 1;
    memcpy(&Log::outbuff_[outbuff_idx], &format_len, sizeof(format_len));
    outbuff_idx += sizeof(format_len);

    memcpy(&Log::outbuff_[outbuff_idx], format, format_len);
    outbuff_idx += format_len;

    memcpy(&Log::outbuff_[outbuff_idx], &format_args, format_len);
    outbuff_idx += sizeof(format_args);
  }

  std::vector<Log::FormatType>::iterator iter;
  std::vector<Log::FormatType>::const_iterator end = types->end();
  for (iter = types->begin(); iter != end; ++iter)
  {
    switch(*iter)
    {
    case Log::FORMAT_INT:
      SERIALIZE_VARARG(int, *args, outbuff_idx);
      break;
    case Log::FORMAT_UINT:
      SERIALIZE_VARARG(unsigned int, *args, outbuff_idx);
      break;
    case Log::FORMAT_INTMAX:
      SERIALIZE_VARARG(intmax_t, *args, outbuff_idx);
      break;
    case Log::FORMAT_UINTMAX:
      SERIALIZE_VARARG(uintmax_t, *args, outbuff_idx);
      break;
    case Log::FORMAT_CHARSTAR:
      {
        char* value = va_arg(*args, char*);
        size_t value_len = strlen(value) + 1;
        SERIALIZE_ARG(value, value_len, outbuff_idx);
      }
      break;
    case Log::FORMAT_UCHAR:
      SERIALIZE_VARARG_PROMOTED(unsigned char, int, *args, outbuff_idx);
      break;
    case Log::FORMAT_SCHAR:
      SERIALIZE_VARARG_PROMOTED(signed char, int, *args, outbuff_idx);
      break;
    case Log::FORMAT_SHORT:
      SERIALIZE_VARARG_PROMOTED(short, int, *args, outbuff_idx);
      break;
    case Log::FORMAT_USHORT:
      SERIALIZE_VARARG_PROMOTED(unsigned short, int, *args, outbuff_idx);
      break;
    case Log::FORMAT_LONG:
      SERIALIZE_VARARG(long, *args, outbuff_idx);
      break;
    case Log::FORMAT_ULONG:
      SERIALIZE_VARARG(unsigned long, *args, outbuff_idx);
      break;
    case Log::FORMAT_LLONG:
      SERIALIZE_VARARG(long long, *args, outbuff_idx);
      break;
    case Log::FORMAT_ULLONG:
      SERIALIZE_VARARG(unsigned long long, *args, outbuff_idx);
      break;
    case Log::FORMAT_DOUBLE:
      SERIALIZE_VARARG(double, *args, outbuff_idx);
      break;
    case Log::FORMAT_LDOUBLE:
      SERIALIZE_VARARG(long double, *args, outbuff_idx);
      break;
    case Log::FORMAT_SIZE:
      SERIALIZE_VARARG(size_t, *args, outbuff_idx);
      break;
    case Log::FORMAT_SSIZE:
      SERIALIZE_VARARG(ssize_t, *args, outbuff_idx);
      break;
    case Log::FORMAT_PTRDIFF:
      SERIALIZE_VARARG(ptrdiff_t, *args, outbuff_idx);
      break;
    case Log::FORMAT_VOID:
      {
        void* value = va_arg(*args, void *);
        size_t value_len = sizeof(value);
        SERIALIZE_ARG(&value, value_len, outbuff_idx);
      }
      break;
    }
  }

#if DEBUG
  if (OUTPUT_BUFFER_SIZE < outbuff_idx)
  {
    fprintf(stderr, "Log::WriteLogRecord: Memory Overrun. Copied %d bytes" 
            "into output buffer of size %d\n", outbuff_idx, OUTPUT_BUFFER_SIZE);
  }
#endif

  ssize_t bytes_written;
  bytes_written = fwrite(Log::outbuff_, outbuff_idx, 1, Log::output_fd_);
  if (-1 == bytes_written)
  {
    fprintf(stderr, "Log::WriteLogRecord: Error writing to log file. %s\n",
            std::strerror(errno));
  }
}

//============================================================================
void Log::InternalLog(Log::Level level, const char* ln, const char* cn,
                      const char* mn, uint32_t* id, bool* first_call,
                      std::vector<Log::FormatType>* types,
                      const char* format, ...)
{
  va_list  args;
  bool     first_internal_call = !Log::start_time_set_;

  if (*first_call)
  {
    *id = Log::next_format_id_;
    Log::next_format_id_++;
  }

  va_start(args, format);

  if (WouldLog(level, cn))
  {

    //
    // Get the time to be logged.
    //

    struct timeval  curr_time;
    gettimeofday(&curr_time, 0);

    if (first_internal_call)
    {
      Log::start_time_ = curr_time;
    }

#ifdef LOG_RELATIVE_TIME

    //
    // Output the relative time since the start time with microsecond
    // accuracy.
    //

    time_t       diff_sec = (curr_time.tv_sec - Log::start_time_.tv_sec);
    suseconds_t  diff_usec;

    if (curr_time.tv_usec < Log::start_time_.tv_usec)
    {
      diff_usec = (1000000 + curr_time.tv_usec - Log::start_time_.tv_usec);
      diff_sec -= 1;
    }
    else
    {
      diff_usec = (curr_time.tv_usec - Log::start_time_.tv_usec);
    }

#else

    //
    // Output the absolute time with microsecond accuracy.
    //

    time_t       diff_sec  = curr_time.tv_sec;
    suseconds_t  diff_usec = curr_time.tv_usec;

#endif // LOG_RELATIVE_TIME

    int  err;
    if ((err = pthread_mutex_lock(&Log::mutex_)) != 0)
    {
      fprintf(stderr, "Log::InternalLog(): Error %d locking mutex.\n", err);
      va_end(args);

      // first_call is NOT changed here. This failure prevents any write to
      // the log file. If this was the first call, the format string still
      // needs to be written to the file.
      return;
    }

    //
    // If this is also the start time, then print out the current time in the
    // format "Fri Sep 13 00:00:00:000000 1986".
    //

    if (first_internal_call)
    {
      fprintf(Log::output_fd_, MIN_LOG_HEADER);

      //
      // Note that ctime_r() requires at least 26 characters, and we need to
      // allow space for microsecconds.
      //

      unsigned int  year;
      char          buf[40];
      char         *cptr;
      // Only called once, so types doesn't need to be static
      // and first_call can be hard coded to true.
      std::vector<Log::FormatType> types;

      ctime_r(&(curr_time.tv_sec), buf);
      cptr = &buf[strlen(buf) - 6];  // Get location right after seconds.
      sscanf(cptr, "%d", &year);
      sprintf(cptr, ":%06ld %d", diff_usec, year);  // Insert microseconds.

      Log::WriteLogRecord(START_TIME_FORMAT_ID, true, &types,
                          "%ld.%06ld Logging Started at: %s\n",
                          static_cast<long>(diff_sec),
                          static_cast<long>(diff_usec), buf);

      Log::start_time_set_ = true;
      // Flush the logging output - in optimized mode this might be the only
      // log message and we would want to know that the bpf ran.
      fflush(Log::output_fd_);
    }

    //
    // Log the message.
    //
    static std::vector<Log::FormatType> prefix_types;
    Log::WriteLogRecord(PREFIX_FORMAT_ID, first_internal_call,
                        &prefix_types,
                        "%ld.%06ld %s [%s::%s] ",
                        static_cast<long>(diff_sec),
                        static_cast<long>(diff_usec),
                        ln, cn, mn);
    Log::WriteLogRecordList(*id, *first_call, types, format, &args);

    if ((err = pthread_mutex_unlock(&Log::mutex_)) != 0)
    {
      fprintf(stderr, "Log::InternalLog(): Error %d unlocking mutex.\n", err);
    }

    // Set now that the message has been logged
    *first_call = false;
  }

  //
  // If necessary, dump core and exit.  Do not depend on whether
  // LOG_FATAL is in the mask.
  //

#ifdef LOGF_ALWAYS_ABORTS
  if (level == LOG_FATAL)
#else //LOGF_ALWAYS_ABORTS
  if (logf_abort_ && (level == LOG_FATAL))
#endif LOGF_ALWAYS_ABORTS
  {
    // Flush the logging output.
    fflush(Log::output_fd_);

    // Dump core and exit immediately.
    abort();
  }

  va_end(args);
}

#else // LOG_MIN

//============================================================================
void Log::InternalLog(Log::Level level, const char* ln, const char* cn,
                      const char* mn, const char* format, ...)
{
  va_list  args;
  va_start(args, format);

  if (WouldLog(level, cn))
  {

    //
    // Get the time to be logged.
    //

    struct timeval  curr_time;
    gettimeofday(&curr_time, 0);

    if (!Log::start_time_set_)
    {
      Log::start_time_ = curr_time;
    }

#ifdef LOG_RELATIVE_TIME

    //
    // Output the relative time since the start time with microsecond
    // accuracy.
    //

    time_t       diff_sec = (curr_time.tv_sec - Log::start_time_.tv_sec);
    suseconds_t  diff_usec;

    if (curr_time.tv_usec < Log::start_time_.tv_usec)
    {
      diff_usec = (1000000 + curr_time.tv_usec - Log::start_time_.tv_usec);
      diff_sec -= 1;
    }
    else
    {
      diff_usec = (curr_time.tv_usec - Log::start_time_.tv_usec);
    }

#else

    //
    // Output the absolute time with microsecond accuracy.
    //

    time_t       diff_sec  = curr_time.tv_sec;
    suseconds_t  diff_usec = curr_time.tv_usec;

#endif // LOG_RELATIVE_TIME

    int  err;
    if ((err = pthread_mutex_lock(&Log::mutex_)) != 0)
    {
      fprintf(stderr, "Log::InternalLog(): Error %d locking mutex.\n", err);
      va_end(args);
      return;
    }

    //
    // If this is also the start time, then print out the current time in the
    // format "Fri Sep 13 00:00:00:000000 1986".
    //

    if (!Log::start_time_set_)
    {
      //
      // Note that ctime_r() requires at least 26 characters, and we need to
      // allow space for microsecconds.
      //

      unsigned int  year;
      char          buf[40];
      char         *cptr;

      ctime_r(&(curr_time.tv_sec), buf);
      cptr = &buf[strlen(buf) - 6];  // Get location right after seconds.
      sscanf(cptr, "%d", &year);
      sprintf(cptr, ":%06ld %d", diff_usec, year);  // Insert microseconds.

      fprintf(Log::output_fd_, "%ld.%06ld Logging Started at: %s\n",
              static_cast<long>(diff_sec), static_cast<long>(diff_usec), buf);

      Log::start_time_set_ = true;
      // Flush the logging output - in optimized mode this might be the only
      // log message and we would want to know that the bpf ran.
      fflush(Log::output_fd_);
    }

    //
    // Log the message.
    //

    fprintf(Log::output_fd_, "%ld.%06ld %s [%s::%s] ",
            static_cast<long>(diff_sec), static_cast<long>(diff_usec), ln, cn,
            mn);
    vfprintf(Log::output_fd_, format, args);

    if ((err = pthread_mutex_unlock(&Log::mutex_)) != 0)
    {
      fprintf(stderr, "Log::InternalLog(): Error %d unlocking mutex.\n", err);
    }
  }

  //
  // If necessary, dump core and exit.  Do not depend on whether
  // LOG_FATAL is in the mask.
  //

#ifdef LOGF_ALWAYS_ABORTS
  if (level == LOG_FATAL)
#else // LOGF_ALWAYS_ABORTS
  if (logf_abort_ && (level == LOG_FATAL))
#endif // LOGF_ALWAYS_ABORTS
  {
    // Flush the logging output.
    fflush(Log::output_fd_);

    // Dump core and exit immediately.
    abort();
  }

  va_end(args);
}

#endif // LOG_MIN


//============================================================================
void Log::OnSignal()
{
  // Attempt to lock the mutex.  If it is not already locked, it will lock it
  // and return immediately.  If it is already locked, this will not block
  // and will return EBUSY.
  int  err = pthread_mutex_trylock(&Log::mutex_);

  // Now that we know that the mutex is locked, unlock it.
  if ((err = pthread_mutex_unlock(&Log::mutex_)) != 0)
  {
    fprintf(stderr, "Log::OnSignal(): Error %d unlocking mutex.\n", err);
  }
}

//============================================================================
void Log::Destroy()
{
  int  mask = Log::mask_;

  //
  // This method logs a message indicating application shutdown, but it cannot
  // call into the InternalLog() method.  This is because a signal might have
  // interrupted the InternalLog() method while the mutex lock was locked, and
  // calling back into the InternalLog() method would cause a deadlock.  Thus,
  // this method must log the message manually.
  //

  if (mask & iron::Log::LOG_INFO)
  {

    //
    // First, get the time to be logged.
    //

    struct timeval  curr_time;
    gettimeofday(&curr_time, 0);

    if (!Log::start_time_set_)
    {
      Log::start_time_ = curr_time;
    }

#ifdef LOG_RELATIVE_TIME

    //
    // Output the relative time since the start time with microsecond
    // accuracy.
    //

    time_t       diff_sec = (curr_time.tv_sec - Log::start_time_.tv_sec);
    suseconds_t  diff_usec;

    if (curr_time.tv_usec < Log::start_time_.tv_usec)
    {
      diff_usec = (1000000 + curr_time.tv_usec - Log::start_time_.tv_usec);
      diff_sec -= 1;
    }
    else
    {
      diff_usec = (curr_time.tv_usec - Log::start_time_.tv_usec);
    }

#else

    //
    // Output the absolute time with microsecond accuracy.
    //

    time_t       diff_sec  = curr_time.tv_sec;
    suseconds_t  diff_usec = curr_time.tv_usec;

#endif // LOG_RELATIVE_TIME

    //
    // Log a generic application shutdown message.
    //

#ifdef LOG_MIN
    static bool first_call = true;
    static std::vector<Log::FormatType> destroy_types;
    Log::WriteLogRecord(DESTROY_FORMAT_ID, first_call, &destroy_types,
                        "%ld.%06ld I [Log::Destroy] Application "
                        "shutdown.\n", static_cast<long>(diff_sec),
                        static_cast<long>(diff_usec));
    first_call = false;
#else
    fprintf(Log::output_fd_, "%ld.%06ld I [Log::Destroy] Application "
            "shutdown.\n", static_cast<long>(diff_sec),
            static_cast<long>(diff_usec));
#endif
  }

  //
  // If the current output file descriptor is not equal to stdout or stderr,
  // then we must close it without disrupting users of Log::output_fd_.
  //

  if ((Log::output_fd_ != stdout) && (Log::output_fd_ != stderr))
  {
    FILE*  old_fd    = Log::output_fd_;
    Log::output_fd_ = stdout;

    fflush(old_fd);
    fclose(old_fd);
  }

  fflush(Log::output_fd_);
}

//============================================================================
int Log::StringToMask(const std::string& levels)
{
  int          mask     = 0;
  const char*  mask_str = levels.c_str();

  //
  // Convert the string into a mask and store it as the default mask.
  //

  if (strcasecmp(mask_str, "all") == 0)
  {
    mask = LOG_ALL;
  }
  else if (strcasecmp(mask_str, "none") == 0)
  {
    mask = 0;
  }
  else
  {
    if (strchr(mask_str, 'F') || strchr(mask_str, 'f'))
    {
      mask |= LOG_FATAL;
    }
    if (strchr(mask_str, 'E') || strchr(mask_str, 'e'))
    {
      mask |= LOG_ERROR;
    }
    if (strchr(mask_str, 'W') || strchr(mask_str, 'w'))
    {
      mask |= LOG_WARNING;
    }
    if (strchr(mask_str, 'I') || strchr(mask_str, 'i'))
    {
      mask |= LOG_INFO;
    }
    if (strchr(mask_str, 'A') || strchr(mask_str, 'a'))
    {
      mask |= LOG_ANALYSIS;
    }
    if (strchr(mask_str, 'D') || strchr(mask_str, 'd'))
    {
      mask |= LOG_DEBUG;
    }
  }

  return mask;
}

//============================================================================
void Log::MaskToString(int mask, char* levels)
{
  int  i = 0;

  //
  // Convert the mask back into a string.
  //

  if (mask & LOG_FATAL)
  {
    levels[i++] = 'F';
  }

  if (mask & LOG_ERROR)
  {
    levels[i++] = 'E';
  }

  if (mask & LOG_WARNING)
  {
    levels[i++] = 'W';
  }

  if (mask & LOG_INFO)
  {
    levels[i++] = 'I';
  }

  if (mask & LOG_ANALYSIS)
  {
    levels[i++] = 'A';
  }

  if (mask & LOG_DEBUG)
  {
    levels[i++] = 'D';
  }

  levels[i] = '\0';
}

//============================================================================
void Log::SetNewFileDescriptor(FILE* new_fd)
{

  //
  // If the current output file descriptor is not equal to stdout or stderr,
  // then we must close it without disrupting users of Log::output_fd_.
  //

  FILE*  old_fd    = Log::output_fd_;
  Log::output_fd_ = new_fd;

  if ((old_fd != stdout) && (old_fd != stderr))
  {
    fflush(old_fd);
    fclose(old_fd);
  }
}
