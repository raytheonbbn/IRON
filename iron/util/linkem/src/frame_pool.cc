//============================================================================
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
//============================================================================

#include "frame_pool.h"

namespace
{
  /// Class name for logging.
  const char*  kClassName = "FramePool";
}

//============================================================================
FramePool::FramePool()
    : pool_(NULL)
{
}

//============================================================================
FramePool::~FramePool()
{
  // Delete all of the Frame elements currently in the pool.
  while (pool_ != NULL)
  {
    Frame*  cur_frame = pool_;
    pool_             = cur_frame->next_;

    delete cur_frame;
  }

  pool_ = NULL;
}

//============================================================================
Frame* FramePool::Get()
{
  Frame*  frame;

  if (pool_)
  {
    frame = pool_;
    pool_ = frame->next_;
    Reset(frame);
  }
  else
  {
    frame = new (std::nothrow) Frame();

    if (frame == NULL)
    {
      LogF(kClassName, __func__, "Error allocating new Frame.\n");
    }
  }

  return frame;
}

//============================================================================
void FramePool::Recycle(Frame* frame)
{
  frame->next_ = pool_;
  pool_        = frame;
}

//============================================================================
void FramePool::Reset(Frame* frame) const
{
  frame->src_                 = -1;
  frame->dst_                 = -1;
  frame->len_                 = 0;
  frame->xmit_timestamp_nsec_ = 0;
  frame->next_                = NULL;
}
