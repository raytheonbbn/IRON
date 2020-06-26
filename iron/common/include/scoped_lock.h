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

#ifndef IRON_COMMON_SCOPED_LOCK_H
#define IRON_COMMON_SCOPED_LOCK_H

///
/// Provides the IRON software with a common facility for managing mutexes.
///

#include <pthread.h>

namespace iron
{
  ///
  /// Encapsulates the manipulation of a mutex. When the object is created,
  /// the mutex is locked and remains locked until the created object is
  /// destroyed, at which point the mutex is unlocked. Since the locking and
  /// unlocking are done in the constructor and destructor, it is not
  /// necessary to have separate calls to lock and unlock the mutex. The
  /// following illustrates how this class is used:
  ///
  /// \code
  /// void ExampleClass::MethodThatNeedsToProtectDataAccess()
  /// {
  ///   ScopedLock sl(mutex_);
  ///
  ///   //
  ///   // Do some operations on the shared data here.
  ///   //
  ///
  /// }
  /// \endcode
  ///
  /// In the above example, when the MethodThatNeedsToProtectDataAccess()
  /// method is invoked a ScopedLock object is created with the ExampleClass
  /// member variable mutex_ as a parameter. The creation of the ScopedLock
  /// object locks mutex_. When the method end, the ScopedLock object falls
  /// out of scope and mutex_ is unlocked.
  ///
  class ScopedLock
  {
    public:
    
    ///
    /// Constructor.
    ///
    /// \param  mutex  Pointer to the mutex that the ScopedLock object will
    ///                operate on.
    ///
    explicit ScopedLock(pthread_mutex_t* mutex);

    ///
    /// Destructor.
    ///
    virtual ~ScopedLock();

    private:
    
    ///
    /// Default constructor. This is private so that we don't get a default
    /// implementation by the compiler.
    ///
    ScopedLock();

    ///
    /// Copy constructor. This is private so that we don't get a default
    /// implementation by the compiler.
    ///
    ScopedLock(const ScopedLock& other);

    ///
    /// Assignment operator. This is private so that we don't get a default
    /// implementation by the compiler.
    ///
    ScopedLock& operator=(const ScopedLock& other);

    ///
    /// The mutex that the scope lock operates on.
    ///
    pthread_mutex_t*  mutex_;
    
  }; // end class ScopedLock
} // namespace iron

#endif // IRON_COMMON_SCOPED_LOCK_H
