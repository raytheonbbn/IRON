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

#ifndef IRON_UTIL_LINKEM_FRAME_H
#define IRON_UTIL_LINKEM_FRAME_H

#include "iron_constants.h"

/// \brief Represents an ethernet frame that is to be bridged by LinkEm.
class Frame
{
  friend class FramePool;

  public:

  /// \brief Set the frame source interface.
  ///
  /// \param  src  The frame source interface.
  inline void set_src(int src)
  {
    src_ = src;
  }

  /// \brief Get the frame source interface.
  ///
  /// \return The frame source interface.
  inline int src() const
  {
    return src_;
  }

  /// \brief Set the frame destination interface.
  ///
  /// \param  dst  The frame destination interface.
  inline void set_dst(int dst)
  {
    dst_ = dst;
  }

  /// \brief Get the frame destination interface.
  ///
  /// \return The frame destination interface.
  inline int dst() const
  {
    return dst_;
  }

  /// \brief Get a pointer to the internal frame buffer.
  ///
  /// \return Pointer to the internal frame buffer.
  inline unsigned char* buffer()
  {
    return buffer_;
  }

  /// \brief Get the maximum size, in bytes, of the internal frame buffer.
  ///
  /// \return The maximum size, in bytes, of the internal frame buffer.
  inline size_t GetMaxSizeBytes() const
  {
    return iron::kMaxPacketSizeBytes;
  }

  /// \brief Set the length of the frame buffer.
  ///
  /// \param  len  The length of the frame buffer.
  inline void set_len(size_t len)
  {
    len_ = len;
  }

  /// \brief Get the length of the frame buffer.
  ///
  /// \return The length of the frame buffer.
  inline size_t len() const
  {
    return len_;
  }

  /// \brief Set the frame transmit time, in nanoseconds.
  ///
  /// \param  timestamp_nsec  The frame transmit timestamp, in nanoseconds.
  inline void set_xmit_timestamp_nsec(unsigned long long timestamp_nsec)
  {
    xmit_timestamp_nsec_ = timestamp_nsec;
  }

  /// \brief Get the frame transmit time, in nanoseconds.
  ///
  /// \return The frame transmit time, in nanonseconds.
  inline unsigned long long xmit_timestamp_nsec() const
  {
    return xmit_timestamp_nsec_;
  }

  /// \brief Determines if it is time to transmit the frame.
  ///
  /// \param  now_nsec  The current time, in nanoseconds.
  ///
  /// \return True if it is time to transmit the frame, false otherwise.
  bool IsTimeToTransmit(unsigned long long now_nsec) const;

  private:

  /// \brief Default no-arg constructor.
  Frame();

  /// \brief Destructor.
  virtual ~Frame();

  /// Copy constructor.
  Frame(const Frame& other);

  /// Copy operator.
  Frame& operator=(const Frame& other);

  /// The frame source interface.
  int                 src_;

  /// The frame destination interface.
  int                 dst_;

  /// The frame buffer.
  unsigned char       buffer_[iron::kMaxPacketSizeBytes];

  /// The length of the frame buffer.
  size_t              len_;

  /// The frame transmit timestamp, in nanoseconds.
  unsigned long long  xmit_timestamp_nsec_;

  /// Pointer to the next frame. This provides the linkage necessary to store
  /// the frame in a frame pool.
  Frame*              next_;
};

#endif // IRON_UTIL_LINKEM_FRAME_H
