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

/// \brief Create random names and keys to reduce collisions chance during
/// testing.

#ifndef IRON_TESTTOOLS_RANDOM_SHARED_MEMORY_H
#define IRON_TESTTOOLS_RANDOM_SHARED_MEMORY_H

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>

/// Max length of shared memory name
#define kRandomShmNameSize (NAME_MAX - 1)

/// Max length of shared memory key in characters
#define kRandomShmKeySize 10

namespace iron
{
  /// \brief Make values that can be passed to Create() that are unlikely to
  /// collide with other instances of the same code.
  ///
  /// Adds a random component to the values to reduce the chance of
  /// collisions. There is no guarantee that the result is unique.
  ///
  /// \param  base_name Name to be used as part of shared memory name.
  /// \param  name Location where the shared memory name should be placed.
  /// \param  name_size Size of the name buffer.
  /// \param  key Location where the shared memory key should be placed.
  void RandomShmNameAndKey(const char* base_name, char* name,
                           size_t name_size, key_t& key);

  /// \brief Make values that can be passed to Create() that are unlikely to
  /// collide with other instances of the same code.
  ///
  /// Adds a random component to the values to reduce the chance of
  /// collisions. There is no guarantee that the result is unique.
  ///
  /// \param  base_name Name to be used as part of shared memory name.
  /// \param  name Location where the shared memory name should be placed.
  /// \param  name_size Size of the name buffer.
  /// \param  key Location where the shared memory key should be placed.
  /// \param  key_size Size of the key buffer.
  void RandomShmNameAndKeyStr(const char* base_name, char* name,
                     size_t name_size, char* key, size_t key_size);
} // namespace iron

#endif // IRON_TESTTOOLS_RANDOM_SHARED_MEMORY_H
