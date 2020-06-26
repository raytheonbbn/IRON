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

#ifndef IRON_COMMON_STATS_H
#define IRON_COMMON_STATS_H

/// Support for accumulating and dumping stats from a process.

#include "itime.h"

#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#include <string>

#include <stdint.h>

namespace iron
{
  ///
  /// This is the base class for process-specific stats like BpfStats.
  /// It contains the basic stats methods and members, like the method to set
  /// or access the dump interval.
  ///
  class Stats
  {
    public:
    
    ///
    /// Default no-arg constructor sets the dump interval to 6s.
    ///
    Stats()
      : dump_ok_(false), last_dump_()
    { }

    ///
    /// Destructor.
    ///
    virtual ~Stats()
    {
      dump_ok_ = false;
    }

    ///
    /// \brief  The method that dumps the accumulated stats into the log file or
    ///         rapidJSON writer.
    ///
    /// \param  writer  The rapidJSON writer object to use to fill up the stats.
    ///                 It may be NULL, which means that nothing will be copied
    ///                 in that (non-existent) JSON object.
    /// Memory ownership: BPF Stats does not own the memory for the writer nor
    /// does it free it.
    ///
    virtual void WriteStats(rapidjson::Writer<rapidjson::StringBuffer>* writer
                            = NULL) = 0;

    ///
    /// \brief  The method that orders dumping the stats.
    ///
    virtual inline void StartDump()
    {
      dump_ok_ = true;
    }

    ///
    /// \brief  The method that order stopping the dumps.
    /// This does not stop the averaging / dump timer, but merely the writing
    /// to the log file.  That way, averages remain on constant bounderies.
    ///
    /// (No timer stop.)
    ///
    virtual inline void StopDump()
    {
      dump_ok_ = false;
    }

    ///
    /// \brief  The method to print the object.
    ///
    virtual std::string ToString() const = 0;

    protected:
    ///
    /// The state indicating whether to dump or not.  If this is false, dumps
    /// to the log file and in remote command gets will not take place.
    ///
    bool dump_ok_;

    /// The last time the dump occurred.  A dump may be triggered via the timer
    /// (every dump_interval_ms_) and via direct remote control requests.  If
    /// the timer expires but a dump occurred less than dump_interval_ms_ - 10%,
    /// for instance via rc request, the dump is rescheduled for next timer
    /// expiration.
    iron::Time last_dump_;

    private:
    ///
    /// Disallow the copy constructor.
    ///
    Stats(const Stats& other_stats);

    ///
    /// Disallow the copy operator.
    ///
    Stats& operator= (const Stats& other_stats);

  };    // End class
}       // End namespace
#endif  // End IRON_COMMON_STATS_H
