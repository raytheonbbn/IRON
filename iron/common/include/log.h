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

/// \brief The IRON logging header file.
///
/// Provides the IRON software with an efficient, flexible logging capability.
/// May be directed to stdout, stderr, or a file.  The logging levels to be
/// output are dynamically selectable.

#ifndef IRON_COMMON_LOG_H
#define IRON_COMMON_LOG_H

#include <map>
#include <string>
#include <vector>
#include <cstdarg>

#include <sys/time.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __COVERITY__
// LogF is a macro that calls InternalLog(LOG_FATAL, ....), which
// calls abort.  However, Coverity does not infer that this happens,
// and thus has false positives for code errors after LogF returns.
// Work around this by adding an abort call directly into the LogF
// definition, when compiling for Coverity.

// Declare abort, cribbed from stdlib.h.  Obviously we should just
// include stdlib.h, but then files that include it will get a defect
// for a redundant include.  Since this is a hack to convince Coverity
// that LogF will not return, accept the ick.
extern "C" {
extern void abort (void) __THROW __attribute__ ((__noreturn__));
}
#define COVERITY_ABORT   ; abort()
#else // __COVERITY__
#define COVERITY_ABORT
#endif // __COVERITY__

// Macros for the actual logging functions.  Use these, not the InternalLog()
// method.  The end letter of the function name represents the level of the
// logging for the message (Fatal, Error, Warning, Information, Analysis, and
// Debug).
//
// The parameters are:
//
// \param  const char* cn      The class name string.
// \param  const char* mn      The method name string.
// \param  const char* format  The printf-style format string that specifies
//                             how subsequent arguments are converted for
//                             output.  See printf(3) for details.
//
// There are no return values from these functions.

#ifdef LOG_MIN

#define LOG_PRIV_INTERNAL_LOG(level, ln, cn, mn, format, ...)           \
  do {                                                                  \
    static uint32_t LOG_PRIV_id = 0;                                    \
    static bool LOG_PRIV_first_call = true;                             \
    static std::vector<iron::Log::FormatType> LOG_PRIV_format_types;    \
    iron::Log::InternalLog(level, ln, cn, mn,                           \
                           &LOG_PRIV_id, &LOG_PRIV_first_call,          \
                           &LOG_PRIV_format_types,                      \
                           format, ##__VA_ARGS__);                      \
  } while (0)

#define LogC(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_CONFIG, "C", cn, mn,             \
                           format, ##__VA_ARGS__)

#define LogF(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_FATAL, "F", cn, mn,              \
                           format, ##__VA_ARGS__) COVERITY_ABORT

#define LogE(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_ERROR, "E", cn, mn,              \
                           format, ##__VA_ARGS__)

#define LogW(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_WARNING, "W", cn, mn,            \
                           format, ##__VA_ARGS__)

#define LogI(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_INFO, "I", cn, mn,               \
                           format, ##__VA_ARGS__)

#define LogA(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_ANALYSIS, "A", cn, mn,           \
                           format, ##__VA_ARGS__)

#ifdef DEBUG

#define LogD(cn, mn, format, ...)                                       \
  LOG_PRIV_INTERNAL_LOG(iron::Log::LOG_DEBUG, "D", cn, mn,              \
                           format, ##__VA_ARGS__)

#else

#define LogD(cn, mn, format, ...)      /* */

#endif

#else // LOG_MIN

#define LogC(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_CONFIG, "C", cn, mn, format,    \
                         ##__VA_ARGS__)

#define LogF(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_FATAL, "F", cn, mn, format,     \
                         ##__VA_ARGS__) COVERITY_ABORT

#define LogE(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_ERROR, "E", cn, mn, format,     \
                         ##__VA_ARGS__)

#define LogW(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_WARNING, "W", cn, mn, format,   \
                         ##__VA_ARGS__)

#define LogI(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_INFO, "I", cn, mn, format,      \
                         ##__VA_ARGS__)

#define LogA(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_ANALYSIS, "A", cn, mn, format,  \
                         ##__VA_ARGS__)

#ifdef DEBUG


#define LogD(cn, mn, format, ...)                                       \
  iron::Log::InternalLog(iron::Log::LOG_DEBUG, "D", cn, mn, format,     \
                         ##__VA_ARGS__)

#else

#define LogD(cn, mn, format, ...)      /* */

#endif // DEBUG

#endif // LOG_MIN

#define WouldLogC(cn) iron::Log::WouldLog(iron::Log::LOG_CONFIG, cn)

#define WouldLogF(cn) iron::Log::WouldLog(iron::Log::LOG_FATAL, cn)

#define WouldLogE(cn) iron::Log::WouldLog(iron::Log::LOG_ERROR, cn)

#define WouldLogW(cn) iron::Log::WouldLog(iron::Log::LOG_WARNING, cn)

#define WouldLogI(cn) iron::Log::WouldLog(iron::Log::LOG_INFO, cn)

#define WouldLogA(cn) iron::Log::WouldLog(iron::Log::LOG_ANALYSIS, cn)

#ifdef DEBUG
#define WouldLogD(cn) iron::Log::WouldLog(iron::Log::LOG_DEBUG, cn)
#else
#define WouldLogD(cn) false
#endif // DEBUG


namespace iron
{

  /// \brief A class for logging messages to stdout, stderr, or a file.
  ///
  /// Each log statement may be at one of six levels:
  ///
  /// "C" = CONFIG:  Startup configuration settings, can't be disabled.
  /// "F" = Fatal:   Catastophic errors, execution will stop immediately.
  /// "E" = Error:   Serious errors, possible missing data or data corruption.
  /// "W" = Warning: System can continue operation without data loss.
  /// "I" = Info:    High level events concerning major functions.
  /// "A" = Analyis: Medium level events, i.e. subsystem startup and shutdown.
  /// "D" = Debug:   Low level events to help track algorithm execution.
  ///
  /// To generate a log message, use one of the logging preprocessor macros:
  ///
  ///   LogA("Widget", "SetWidth", "Setting the width to %d pixels.\n", w);
  ///
  /// The general format of the generated log message is:
  ///
  ///   \<time\> \<level\> \<class\>::\<method\> \<message\>
  ///
  /// The levels that are actually logged at run-time are controlled by a
  /// mask, which may be set using SetDefaultLevel() and SetClassLevel().  All
  /// six levels are available for logging when compiled with the "-D DEBUG"
  /// preprocessor flag.  When compiled without the "-D DEBUG" preprocessor
  /// flag, only the Fatal, Error and Warning logging levels are available --
  /// the Info, Analysis, and Debug logging levels are compiled out.
  class Log
  {

  public:

    /// The logging levels.  Used in the InternalLog() method.
    enum Level
    {
      LOG_FATAL    = 0x01,  ///< Catastophic errors, execution will stop
                            ///< immediately.
      LOG_ERROR    = 0x02,  ///< Serious errors, possible missing data or
                            ///< data corruption.
      LOG_WARNING  = 0x04,  ///< System can continue operation without data
                            ///< loss.
      LOG_INFO     = 0x08,  ///< High level events concerning major
                            ///< functions.
      LOG_ANALYSIS = 0x10,  ///< Medium level events, i.e. subsystem startup
                            ///< and shutdown.
      LOG_DEBUG    = 0x20,  ///< Low level events to help track algorithm
                            ///< execution.
      LOG_ALL      = 0x3f,  ///< All levels.
      LOG_CONFIG   = 0xff   ///< Startup configuration settings, can't be
                            /// disabled.
    };

    /// \brief Set the default logging levels.
    ///
    /// By default, only the "FEWI" levels are logged until this method is
    /// called.
    ///
    /// \param  levels  The levels to be logged in a string format.  Valid
    ///                 levels are any of the letters "FEWIAD" (case
    ///                 independent) in any combination, or else the strings
    ///                 "ALL" or "NONE" (case independent).
    static void SetDefaultLevel(const std::string& levels);

    /// \brief Get the current default logging levels in a string format.
    ///
    /// \return  Returns a string representation of the current default
    ///          logging levels.  The returned string will be of the form
    ///          "FEWIAD", with each letter representing a different logging
    ///          level and the presence of a letter signifying that the level
    ///          is currently being logged (the absence of a letter signifies
    ///          that the level is not currently being logged).
    static std::string GetDefaultLevel();

    /// \brief Set the logging level for a particular class.
    ///
    /// If a level is not specified for a class, then the default logging
    /// level (which may be set using SetDefaultLevel()) is used.
    ///
    /// \param  class_name  The class name.
    /// \param  levels      The levels to be logged in a string format.  Valid
    ///                     levels are any of the letters "FEWIAD" (case
    ///                     insensitive) in any combination, or else the
    ///                     string "ALL" (case independent).
    static void SetClassLevel(const std::string& class_name,
                              const std::string& levels);

    /// \brief Send the logging to stdout.
    static void SetOutputToStdOut();

    /// \brief Send the logging to stderr.
    static void SetOutputToStdErr();

    /// \brief Send the logging to an output file.
    ///
    /// \param  file_name  The output file name.
    /// \param  append     If set to true, the output file will be appended
    ///                    to.
    ///
    /// \return  Returns true on success, false otherwise.
    static bool SetOutputFile(const std::string file_name, bool append);

    /// \brief  Returns the name of the current output file.
    /// \return The name of the current output file name (if one has been
    ///         set). Empty string if none has been set.
    static std::string GetOutputFileName();

    /// \brief Check if a log message would be written for a specific
    /// level and class name.
    ///
    /// \param  level           The logging level for the message.
    /// \param  cn              The class name.
    ///
    /// \return  Returns true if the log message would be written.
    static bool WouldLog(Level level, const char* cn);

#ifdef LOG_MIN
    /// Variable type used for string formatting.
    enum FormatType
    {
      FORMAT_INT = 0,
      FORMAT_UINT,
      FORMAT_INTMAX,
      FORMAT_UINTMAX,
      FORMAT_CHARSTAR,
      FORMAT_UCHAR,
      FORMAT_SCHAR,
      FORMAT_SHORT,
      FORMAT_USHORT,
      FORMAT_LONG,
      FORMAT_ULONG,
      FORMAT_LLONG,
      FORMAT_ULLONG,
      FORMAT_DOUBLE,
      FORMAT_LDOUBLE,
      FORMAT_SIZE,
      FORMAT_SSIZE,
      FORMAT_PTRDIFF,
      FORMAT_VOID
    };

    /// \brief Log a message.
    ///
    /// Although this method can be called directly, it should really only be
    /// used by the LogF() through LogD() preprocessor macros.
    ///
    /// \param  level           The logging level for the message.
    /// \param  ln              The level name.
    /// \param  cn              The class name.
    /// \param  mn              The method name.
    /// \param  id              The unique id used for this format string.
    ///                         Updated by function.
    /// \param  first_call      True if the format string has been logged
    ///                         before. Updated by function.
    /// \param  format          The printf-style format string.
    ///
    /// \return  The id used for this format string.
    static void InternalLog(Level level, const char* ln, const char* cn,
                            const char* mn,
                            uint32_t* id, bool* first_call,
                            std::vector<FormatType>* types,
                            const char* format, ...);

#else

    /// \brief Log a message.
    ///
    /// Although this method can be called directly, it should really only be
    /// used by the LogF() through LogD() preprocessor macros.
    ///
    /// \param  level   The logging level for the message.
    /// \param  ln      The level name.
    /// \param  cn      The class name.
    /// \param  mn      The method name.
    /// \param  format  The printf-style format string.
    static void InternalLog(Level level, const char* ln, const char* cn,
                            const char* mn, const char* format, ...);

#endif // LOG_MIN

    /// \brief Change the abort on fatal log message setting.
    ///
    /// By default, any call to LogF() will cause the process to dump core and
    /// exit immediately.  Use this method to disable or re-enable this
    /// behavior.
    ///
    /// \param  abort_flag  If true, then any call to LogF() will cause the
    ///                     process to dump core and exit immediately.
    ///
    /// \return  Returns the previous setting.
    static bool SetAbortOnFatalLogging(bool abort_flag);

    /// \brief Change the config logging active setting.
    ///
    /// By default, any call to LogC() will write despite the default or class
    /// log level. Use this method to disable or re-enable this behavior.
    ///
    /// \param  config_active  If true, then any call to LogC() will write the
    ///                        message. Otherwise, calls to LogC() will not
    ///                        produce any output.
    ///
    /// \return  Returns the previous setting.
    static bool SetConfigLoggingActive(bool config_active);

    /// \brief Flush any logging output buffers.
    static void Flush();

    /// \brief Make sure that logging will still work after a signal occurs.
    ///
    /// This should be called <B>ONCE</B> at the start of a signal handler,
    /// before any logging takes place.  In the case where the signal
    /// interrupted a call into the logger, this method will release the
    /// internal mutex lock.
    static void OnSignal();

    /// \brief Prepare the logging for application shutdown.
    ///
    /// This method flushes any buffering of the logging strings and closes
    /// any logging output file.  This should only be called <B>ONCE</B>
    /// before the application's main process exits.
    static void Destroy();

  private:

    /// \brief The default constructor.
    Log() { }

    /// \brief The destructor.
    virtual ~Log() { }

    /// \brief Copy constructor.
    Log(const Log& other);

    /// \brief Copy operator.
    Log& operator=(const Log& other);

    /// \brief Convert a logging level string into a mask.
    static int StringToMask(const std::string& levels);

    /// \brief Convert a logging level mask to a string.
    static void MaskToString(int mask, char* levels);

    /// \brief Set a new output file descriptor.
    static void SetNewFileDescriptor(FILE* new_fd);

#ifdef LOG_MIN
#define OUTPUT_BUFFER_SIZE 65536
    /// A character buffer to use for packing the args for raw output
    static char outbuff_[OUTPUT_BUFFER_SIZE];

    /// \breif Extract the argument types from the format string.
    ///
    /// \param  format  The printf-style format string.
    /// \param  types   The location where the types will be stored.
    ///                 Assumed to be empty when passed in.
    static void FormatTypes(const char* format,
                             std::vector<FormatType>* types);

    /// \breif Write out the binary log record.
    static void WriteLogRecord(uint32_t id, bool first_call,
                               std::vector<FormatType>* types,
                               const char* format, ...);
    static void WriteLogRecordList(uint32_t id, bool first_call,
                               std::vector<FormatType>* types,
                               const char* format, va_list *args);
#endif

    /// The default logging level mask.
    static int                         mask_;

    /// The current number of class-level logging masks.
    static int                         cmask_cnt_;

    /// A map of class names to logging masks.
    static std::map<std::string, int>  cmask_map_;

    /// The output file descriptor cleanup object.
    static FILE*                       output_fd_;

    /// A flag recording if the start time is set or not.
    static bool                        start_time_set_;

    /// The start time for logging.
    static struct timeval              start_time_;

    /// A lock to prevent logging contention.
    static pthread_mutex_t             mutex_;

    /// A flag recording if a LogF() call should abort or not.
    static bool                        logf_abort_;

    /// A flag recording if a LogC() call should output or not.
    static bool                        logc_active_;

    /// The name of the current output file (if set).
    static std::string                 output_file_name_;

#ifdef LOG_MIN
    /// The id to be assigned the next unique format call.
    static uint32_t                    next_format_id_;
#endif


  }; // class Log

} // namespace iron

#endif // IRON_COMMON_LOG_H
