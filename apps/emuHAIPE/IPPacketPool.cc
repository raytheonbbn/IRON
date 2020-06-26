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
#include <iostream>
#include <string.h>
#include <pthread.h>

#include "IPPacket.hh"


pthread_mutex_t IPPacketPool::_poolMutex  = PTHREAD_MUTEX_INITIALIZER;


/**
 * get a buffer for a new IPPacket object
 * @return a pointer to the buffer
 */

void *IPPacketPool::NewIPPacket(void) 
{
  void *buffer = (void *) NULL;

  pthread_mutex_lock(&_poolMutex);
  
  if (_pool != (IPPacket *) NULL) 
    {
      buffer = _pool;
      _pool  = _pool->_next;
    } 
  else 
    {
      buffer = ::new char [sizeof(IPPacket)];
    }

  pthread_mutex_unlock(&_poolMutex);
  
  return buffer;
}

/**
 * return a IPPacket buffer to the pool
 * @param buffer a pointer to a buffer previously returned by
 * the NewIPPacket method
 */

void IPPacketPool::Recycle(void *buffer) 
{
  pthread_mutex_lock(&_poolMutex);
  
    IPPacket *packet = static_cast<IPPacket *> (buffer);
    packet->_next     = _pool;
    _pool             = packet;

  pthread_mutex_unlock(&_poolMutex);
}



