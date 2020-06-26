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

#ifndef EmuHAIPEOpts_hh
#define EmuHAIPEOpts_hh

#include "PropertyTable.h"

// -----------------------------------------------------------------
// -----------------------------------------------------------------
/**
 *
 * \class EmuHAIPEOpts
 *
 * A simple class for managing the commnd line options for the
 * utility.
 * 
 * @author Multiple
 */
class EmuHAIPEOpts
{
public:
  /**
   * Default constructor.
   */
  EmuHAIPEOpts();

  /**
   * Constructor that parses the command line arguments.
   *
   * @param argc Count of the number of input argumanents
   * @param argv Input argument array
   */
  EmuHAIPEOpts(int argc, char** argv);

  /**
   * Default destructor.
   */
  ~EmuHAIPEOpts();

  /**
   * Routine for displaying the corresponding usage syntax associated
   * with the command line arguments.  
   *
   * @param message Usage message
   */
  void usage(const char* message);

  /**
   * Initialize the default settings their default values.
   */
  void initialize();

  /**
   * Routine for parsing the command line arguments.
   *
   * @param argc Count of the number of input argumanents
   * @param argv Input argument array
   *
   * @return non-zero value if there is a problem.
   */
  int parseArgs(int argc, char** argv);
  
public:
  /// Flag set to true if we want verbose logging.
  int verbose; 

  /// Set to a non-zero value if there is an error during
  /// the parsing of the options.
  int error;

  /// Information about the properties that have been loaded.
  PropertyTable properties;
};

#endif
