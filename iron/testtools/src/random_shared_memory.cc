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

/// \brief The IRON inter-process shared memory module.
///
/// Provides the IRON software with access to shared memory between separate
/// prcoesses on a single computer.

#include "random_shared_memory.h"

#include "rng.h"

#include <cstdio>
#include <inttypes.h>

namespace iron
{
  // internal implmentation: writes to name, returns key as int
  static int32_t _RandomShmNameAndKey(const char* base_name, char* name,
                                      size_t name_size)
  {
    RNG rng;

    // control the range of values generated.
    int32_t key = 1000 + rng.GetInt(8000);
   
    snprintf(name, name_size, "/%s%" PRId32, base_name, key);
    return key;
  }

  void RandomShmNameAndKey(const char* base_name, char* name, size_t name_size,
                           key_t& key)
  {
    int32_t i_key = _RandomShmNameAndKey(base_name, name, name_size);
    key = static_cast<key_t>(i_key);
  }

  void RandomShmNameAndKeyStr(const char* base_name, char* name,
                              size_t name_size, char* key, size_t key_size)
  {
    int32_t i_key = _RandomShmNameAndKey(base_name, name, name_size);
    snprintf(key, key_size, "%" PRId32, i_key);
  }
}
