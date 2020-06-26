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

#ifndef IRON_TESTTOOLS_PORT_NUMBER_MGR_H
#define	IRON_TESTTOOLS_PORT_NUMBER_MGR_H

#include <string>

namespace iron {
  /// Hands out port numbers that should be available for use.
  ///
  /// The expectation is that this will only be used for test cases,
  /// where using the same port number could cause a collision
  /// with another instance of the test case.
  ///
  /// The use of CppUnit for testing prevents us from creating a single
  /// instance and passing it to each TestFixture class. As a result,
  /// this class must remain a singleton.
  ///
  /// There is no guarantee that the the ports are actually available.
  /// However, the implementation should be sufficient for testing purposes
  /// because:
  ///  - parallel execution of tests using the manager will only collide
  ///    if there is a read/write race on the tracking file.
  ///  - the range of ports handed out are unlikely to be used by normal
  ///    system operations.
  class PortNumberMgr
  {
   public:
    /// \brief  Get the singleton instance
    ///
    /// \return The singleton instance of port number
    static PortNumberMgr& GetInstance();

    /// \brief Retrieve a port number that is free to use.
    ///
    /// \return Port number that can be used.
    int NextAvailable();

    /// \brief Retrieve a port number that is free to use as a string.
    /// 
    /// Asserts that a port number was successfully retrieved.
    ///
    /// \return Port number that can be used.
    std::string NextAvailableStr();

   private:

    /// \brief Default no-arg constructor.
    PortNumberMgr();

    /// \brief Default destructor.
    virtual ~PortNumberMgr();

    /// \brief Copy constructor.
    PortNumberMgr(const PortNumberMgr& other);

    /// \brief Assignment operator.
    PortNumberMgr& operator=(const PortNumberMgr& other);

    void aquire_port_range(void);

    int get_free_chunk(void);

    void write_used_chunk(int chunk_used);

    void remove_used_chunk(int chunk_used);

    void release_port_range(void);

    void set_file_permissions(void);

    int chunk_;
    int next_;
    int min_;
    int max_;

    static const std::string USED_FILE;
    static const int MIN_PORT = 30000;
    static const int MAX_PORT = 32000;
    static const int PORTS_PER_CHUNK = 100;
    static const int MAX_CHUNKS = (MAX_PORT - MIN_PORT) / PORTS_PER_CHUNK;
  };
}

#endif	/* IRON_TESTTOOLS_PORT_NUMBER_MGR_H */
