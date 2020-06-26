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

/// \brief Header file for utilities for generating xplot graphs.
///
/// Provides a simple interface for printing a graph (for analysis or
/// debugging purposes) as the software runs.

#ifndef IRON_COMMON_GENXPLOT_H
#define IRON_COMMON_GENXPLOT_H

#include <string>
#include <cstdarg>

#include <sys/time.h>
#include <stdint.h>
#include <pthread.h>

#include <map>

namespace iron
{
  /// Color names to match the numbers encoded in xplot. (This is for the
  /// colored on black graphs. The number-to-color map changes when converting
  /// to PS with colored on white.)
  enum XPLOT_COLOR
  {
    WHITE = 0,
    GREEN = 1,
    RED = 2,
    BLUE = 3,
    YELLOW = 4,
    PURPLE = 5,
    ORANGE = 6,
    MAGENTA = 7,
    PINK = 8,
    NUM_COLORS = 9  // 9 is gray, but it's too hard to read. Use % NUM_COLORS
                    // to get a valid color.
  };

  /// Types of marks that we can draw on an xplot graph.
  enum XPLOT_MARK
  {
    XPLOT_X = 0,
    XPLOT_DOT = 1,
    XPLOT_BOX = 2,
    XPLOT_DIAMOND = 3,
    XPLOT_UTICK = 4,
    XPLOT_LTICK = 5,
    XPLOT_DTICK = 6,
    XPLOT_RTICK = 7,
    XPLOT_VTICK = 8,
    XPLOT_UARROW = 9,
    XPLOT_DARROW = 10,
    XPLOT_LARROW = 11,
    XPLOT_RARROW = 12,
    XPLOT_INVISIBLE = 13
  };

  /// \brief A class for adding on-the-fly to an xplot graph in progress.
  ///
  /// To generate a log message, use one of the logging preprocessor macros:
  ///
  ///   LogA("Widget", "SetWidth", "Setting the width to %d pixels.\n", w);
  ///
  /// The general format of the generated log message is:
  ///
  ///   \<time\> \<level\> \<class\>::\<method\> \<message\>
  class GenXplot
  {

  public:

    /// \brief The default constructor.
    GenXplot();

    /// \brief The destructor.
    virtual ~GenXplot();

    /// \brief Send the graph data to a particular file.
    ///
    /// \param  file_name    The output file name.
    /// \param  graph_name   The title to print at the top of the graph.
    /// \param  convert_x_to_sec  True if the x values to be passed in are
    ///         uint64_t representing time in usec and we want to graph them
    ///         as seconds.
    ///
    /// \return  Returns true on success, false otherwise.
    bool Initialize(const std::string& file_name,
                    const std::string& graph_name,
                    bool convert_x_to_sec = false);

    /// \brief Flush the output buffer.
    void Flush();

    /// \brief Draw the specified line to the running xplot graph.
    ///
    /// \param   x1         The x value of the starting point.
    /// \param   y1         The y value of the starting point.
    /// \param   x2         The x value of the ending point.
    /// \param   y2         The y value of the ending point.
    /// \param   color      Xplot color code for the line.
    ///
    void DrawLine(
      int64_t x1, int64_t y1, int64_t x2, int64_t y2, XPLOT_COLOR color);

    /// \brief Draw a vertical line from 0 to max y at the given x.
    ///
    /// \param   x          The x coordinate of where to draw the line.
    /// \param   color      Xplot color code for the line.
    ///
    void DrawVerticalLine(int64_t x, XPLOT_COLOR color);

    /// \brief Draw the specified "X" point to the running xplot graph.
    ///
    /// \param   x1         The x value of the X.
    /// \param   y1         The y value of the X.
    /// \param   color      Xplot color code for the point.
    /// \param   mark       What type of mark to draw at this point.
    ///
    void DrawPoint(
      int64_t x1, int64_t y1, XPLOT_COLOR color, XPLOT_MARK mark=XPLOT_X);

    /// \brief Continue drawing the specified line by connecting a new point.
    ///
    /// \param   line_index Which line graph to add to.
    /// \param   new_x      The x value of the next point.
    /// \param   new_y      The y value of the next point.
    /// \param   color      Xplot color code for the line continuation.
    ///
    void ContinueLine(
      uint8_t line_index, int64_t new_x, int64_t new_y, XPLOT_COLOR color);

    /// \brief Add the specified value to the indicated time-based graph.
    ///
    /// \param   line_index Which line graph to add to.
    /// \param   new_val    The y value of the next point.
    /// \param   color      Xplot color code for the line continuation.
    ///
    void ContinueTimeLine(
      uint8_t line_index, int64_t new_val, XPLOT_COLOR color);

    /// \brief  Add a line to the graph's key.
    ///
    /// \param  color    The color of the line.
    /// \param  label    The label to be included in the key.
    void AddLineToKey(XPLOT_COLOR color, const std::string& label);

    /// \brief  Add an x to the graph's key.
    ///
    /// \param  color    The color of the x.
    /// \param  label    The label to be included in the key.
    void AddXToKey(XPLOT_COLOR color, const std::string& label);

    /// \brief  Get the maximum Y value seen so far.
    ///
    /// Useful for drawing vertical separation bars in the graph of an
    /// appropriate height.
    ///
    /// \return The maximum Y value seen so far.
    int64_t max_y()
    {
      return max_y_;
    }

  private:

    /// \brief Copy constructor.
    GenXplot(const GenXplot& other);

    /// \brief Copy operator.
    GenXplot& operator=(const GenXplot& other);

    /// The output file descriptor cleanup object.
    FILE*                       output_fd_;

    /// True if the specified line is already in progress. (If not, then the
    /// next point added to the line will be the starting point, not a
    /// continuation of the line.)
    bool line_started_[16];

    /// Previous X value on a continuing line.
    int64_t line_previous_x_[16];

    /// Previous Y value on a continuing line.
    int64_t line_previous_y_[16];

    /// The data to write into the key, once we know where to put it.
    /// The map key is the text for the graph key. The value is the color.
    std::map<std::string, XPLOT_COLOR> line_key_entries_;

    /// The data to write into the key, once we know where to put it.
    /// The map key is the text for the graph key. The value is the color.
    std::map<std::string, XPLOT_COLOR> x_key_entries_;

    /// Track the maximum y value graphed so we can draw the key just above
    /// this.
    int64_t max_y_;

    /// Track the minimum x value graphed so we can draw the key even with
    /// this.
    int64_t min_x_;

    /// True if x values passed in will be in usec and we want to convert to
    /// seconds when graphing.
    bool convert_x_to_sec_;
  }; // class GenXplot

} // namespace iron

#endif // IRON_COMMON_GENXPLOT_H
