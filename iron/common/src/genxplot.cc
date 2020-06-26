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

/// \brief Source file for generating xplot graphs on the fly.
///
/// Provides utilities for adding data to a running xplot graph.

#include "genxplot.h"

#include "iron_constants.h"
#include "log.h"
#include "itime.h"

#include "inttypes.h"

#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <sys/time.h>
#include <sys/uio.h>

#include <limits>

using ::iron::GenXplot;
using ::iron::Log;
using ::iron::Time;

namespace
{
  const char  kClassName[] = "GenXplot";

#ifdef XPLOT
  // Map from XPLOT_MARK number to the string to be printed in the xplot
  // source file to generate the desired mark.
  const char* XPLOT_MARK_STR[] = {
    "x",      "dot",    "box",    "diamond", "utick",  "ltick",  "dtick",
    "rtick",  "vtick",  "uarrow", "darrow", "larrow",  "rarrow", "invisible"
  };
#endif // XPLOT
}

//============================================================================
GenXplot::GenXplot()
    : output_fd_(),
      line_started_(),
      line_previous_x_(),
      line_previous_y_(),
      line_key_entries_(),
      x_key_entries_(),
      max_y_(std::numeric_limits<int64_t>::min()),
      min_x_(std::numeric_limits<int64_t>::max()),
      convert_x_to_sec_(false)
{}

//============================================================================
GenXplot::~GenXplot()
{
  if (!output_fd_)
  {
    return;
  }
  uint64_t next_y = max_y_
    + (20 * line_key_entries_.size())
    + (20 * x_key_entries_.size());
  std::map<std::string,XPLOT_COLOR>::iterator it = line_key_entries_.begin();
  double new_min_x = 0;
  // If we have no entries at all, just start at x=0.
  if (min_x_ == std::numeric_limits<int64_t>::max())
  {
    min_x_ = 0;
  }
  else
  {
    min_x_ = static_cast<double>(min_x_) / 1e6;
  }

  while (it != line_key_entries_.end())
  {
    if (convert_x_to_sec_)
    {
      fprintf(output_fd_, "rtext %f %" PRId64 " %" PRIu8 "\n",
              new_min_x, next_y, it->second);
    }
    else
    {
      fprintf(output_fd_, "rtext %" PRId64 " %" PRId64 " %" PRIu8 "\n",
              min_x_, next_y, it->second);
    }
    fprintf(output_fd_, "--- %s\n", it->first.c_str());
    ++it;
    next_y += 20;
  }

  std::map<std::string,XPLOT_COLOR>::iterator it2 = x_key_entries_.begin();
  while (it2 != x_key_entries_.end())
  {
    if (convert_x_to_sec_)
    {
      fprintf(output_fd_, "rtext %f %" PRId64 " %" PRIu8 "\n",
              new_min_x, next_y, it2->second);
    }
    else
    {
      fprintf(output_fd_, "rtext %" PRId64 " %" PRId64 " %" PRIu8 "\n",
              min_x_, next_y, it2->second);
    }
    fprintf(output_fd_, "x  %s\n", it2->first.c_str());
    ++it2;
    next_y += 20;
  }

  //
  // If the current output file descriptor is not equal to stdout or stderr,
  // then we must close it without disrupting users of output_fd_.
  //

  if ((output_fd_ != stdout) && (output_fd_ != stderr))
  {
    FILE*  old_fd    = output_fd_;
    output_fd_ = stdout;

    fflush(old_fd);
    fclose(old_fd);
  }

  fflush(output_fd_);
}

//============================================================================
bool GenXplot::Initialize(const std::string& file_name,
                          const std::string& graph_name,
                          bool convert_x_to_sec)
{
#ifdef XPLOT
  convert_x_to_sec_ = convert_x_to_sec;

  // Write the file to the same directory where we're logging.
  std::string logfile = Log::GetOutputFileName();
  size_t pos = logfile.find_last_of('/');
  std::string newfile =
    logfile.substr(0, pos + 1).append(file_name);
  FILE*  new_fd = fopen(newfile.c_str(), "w");

  if (new_fd == NULL)
  {
    LogE(kClassName, __func__, "Error opening xplot file %s.\n",
         newfile.c_str());
    return false;
  }

  // The following lines allow re-initialization to change where the graph
  // prints.
  FILE*  old_fd    = output_fd_;
  output_fd_ = new_fd;

  if (old_fd && (old_fd != stdout) && (old_fd != stderr))
  {
    fflush(old_fd);
    fclose(old_fd);
  }

  if (convert_x_to_sec_)
  {
    fprintf(output_fd_, "double double\n");
  }
  else
  {
    fprintf(output_fd_, "signed signed\n");
  }
  fprintf(output_fd_, "title\n%s\n", graph_name.c_str());
#endif // XPLOT
  return true;
}

//============================================================================
void GenXplot::DrawLine(int64_t x1,
                        int64_t y1,
                        int64_t x2,
                        int64_t y2,
                        XPLOT_COLOR color)
{
#ifdef XPLOT
  if (x1 < min_x_)
  {
    min_x_ = x1;
  }
  if (x2 < min_x_)
  {
    min_x_ = x2;
  }
  if (y1 > max_y_)
  {
    max_y_ = y1;
  }
  if (y2 > max_y_)
  {
    max_y_ = y2;
  }
  if (convert_x_to_sec_)
  {
    double new_x1 = static_cast<double>(x1) / 1e6;
    double new_x2 = static_cast<double>(x2) / 1e6;
    fprintf(output_fd_,
            "line %f %" PRId64 " %f %" PRId64 " %" PRIu8 "\n",
            new_x1, y1, new_x2, y2,
            static_cast<XPLOT_COLOR>(color % NUM_COLORS));
  }
  else
  {
    fprintf(output_fd_,
            "line %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRIu8
            "\n", x1, y1, x2, y2,
            static_cast<XPLOT_COLOR>(color % NUM_COLORS));

  }
#endif // XPLOT
}

//============================================================================
void GenXplot::DrawVerticalLine(int64_t x,
                                XPLOT_COLOR color)
{
#ifdef XPLOT
  if (x < min_x_)
  {
    min_x_ = x;
  }
  if (convert_x_to_sec_)
  {
    double new_x = static_cast<double>(x) / 1e6;
    fprintf(output_fd_,
            "line %f %d %f %" PRId64 " %" PRIu8 "\n",
            new_x, 0, new_x, max_y_,
            static_cast<XPLOT_COLOR>(color % NUM_COLORS));
  }
  else
  {
    fprintf(output_fd_,
            "line %" PRId64 " %d %" PRId64 " %" PRId64 " %" PRIu8
            "\n", x, 0, x, max_y_,
            static_cast<XPLOT_COLOR>(color % NUM_COLORS));
  }
#endif // XPLOT
}

//============================================================================
void GenXplot::DrawPoint(int64_t x1,
                         int64_t y1,
                         XPLOT_COLOR color,
                         XPLOT_MARK  mark)
{
#ifdef XPLOT
  if (x1 < min_x_)
  {
    min_x_ = x1;
  }
  if (y1 > max_y_)
  {
    max_y_ = y1;
  }
  if (convert_x_to_sec_)
  {
    double new_x = static_cast<double>(x1) / 1e6;
    fprintf(output_fd_,
            "%s %f %" PRId64 " %" PRIu8 "\n",
            XPLOT_MARK_STR[mark], new_x, y1,
            static_cast<XPLOT_COLOR>(color % NUM_COLORS));
  }
  else
  {
    fprintf(output_fd_,
            "%s %" PRId64 " %" PRId64 " %" PRIu8 "\n",
            XPLOT_MARK_STR[mark], x1, y1,
            static_cast<XPLOT_COLOR>(color % NUM_COLORS));

  }
#endif // XPLOT
}

//============================================================================
void GenXplot::ContinueLine(uint8_t line_index,
                            int64_t new_x,
                            int64_t new_y,
                            XPLOT_COLOR color)
{
#ifdef XPLOT
  if (line_index > 15)
  {
    return;
  }
  if (new_x < min_x_)
  {
    min_x_ = new_x;
  }
  if (new_y > max_y_)
  {
    max_y_ = new_y;
  }
  if (line_started_[line_index])
  {
    DrawLine(line_previous_x_[line_index],
             line_previous_y_[line_index],
             new_x,
             new_y,
             static_cast<XPLOT_COLOR>(color % NUM_COLORS));
  }
  line_started_[line_index] = true;
  line_previous_x_[line_index] = new_x;
  line_previous_y_[line_index] = new_y;
#endif // XPLOT
}

//============================================================================
void GenXplot::ContinueTimeLine(uint8_t line_index,
                                int64_t new_val,
                                XPLOT_COLOR color)
{
#ifdef XPLOT
  uint64_t now_usec  = Time::GetNowInUsec() - iron::kStartTime;
  ContinueLine(line_index, now_usec, new_val,
               static_cast<XPLOT_COLOR>(color % NUM_COLORS));
#endif // XPLOT
}

//============================================================================
void GenXplot::AddLineToKey(XPLOT_COLOR color,
                            const std::string& label)
{
#ifdef XPLOT
  line_key_entries_[label] = static_cast<XPLOT_COLOR>(color % NUM_COLORS);
#endif // XPLOT
}

//============================================================================
void GenXplot::AddXToKey(XPLOT_COLOR color,
                         const std::string& label)
{
#ifdef XPLOT
  x_key_entries_[label] = static_cast<XPLOT_COLOR>(color % NUM_COLORS);
#endif // XPLOT
}

//============================================================================
void GenXplot::Flush()
{
#ifdef XPLOT
  fflush(output_fd_);
#endif // XPLOT
}
