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
#include "FifoQueue.h"
  
#include <errno.h>
#include <sched.h>
#include <stdio.h>

#include "ZLog.h"

//
// Class name used for logging.
//

static const char cn[] = "FifoQueue";


//============================================================================
FifoQueue::FifoQueue()
{
  init(DEFAULT_NICE_THRESHOLD, DEFAULT_SIZE_LIMIT);
}

//============================================================================
FifoQueue::FifoQueue(unsigned int nt, unsigned int sl)
{
  init(nt, sl);
}

//============================================================================
FifoQueue::~FifoQueue()
{
  //
  // Destroy the mutex and condition variable.
  //
  pthread_mutex_destroy(&mutex);
  pthread_cond_destroy(&cond);
}

//============================================================================
void*
FifoQueue::dequeue()
{
  void* object;
  FifoQueueElem*  fqe;
  
  pthread_mutex_lock(&mutex);
  
  //
  // If the signalTermination() method has been called, then do not
  // attempt to dequeue.
  //
  if (signalTerminationActive)
  {
    signalTerminationActive = false;
    pthread_mutex_unlock(&mutex);
    return NULL;
  }
  
  if ((fqe = (FifoQueueElem*)queue.removeFromHead()) == NULL)
  {
    object = NULL;

  } else {
    //
    // Once we reach this point, we are assured that there is data in the
    // queue. Extract the data from the FifoQueueElem,
    //
    object = fqe->getObject();
  
    //
    // decrement the number of queued elements,
    //
    elemCount--;
  
    //
    // and place the FifoQueueElem in the privately managed pool so that it may
    // be reused. Prior to putting it in the pool, set the data in it to NULL.
    //
    fqe->setObject(NULL);
    
    wrapperPool.addToHead(fqe);
  }

  pthread_mutex_unlock(&mutex);
  return object;
}

//============================================================================
void*
FifoQueue::delayedDequeue()
{
  void* object;
  FifoQueueElem*  fqe;
  
  pthread_mutex_lock(&mutex);
  
  //
  // If the signalTermination() method has been called, then do not attempt to
  // dequeue.
  //
  
  if (signalTerminationActive)
  {
    signalTerminationActive = false;
    object = NULL;
    goto done;
  }
  
  while ((fqe = (FifoQueueElem*)queue.removeFromHead()) == NULL)
  {
    object = NULL;
    
    //
    // The queue is currently empty. Wait for data to be placed in the queue.
    // Check the signal termination flag after the wait to return if the
    // signalTermination() method has been called.
    //
    pthread_cond_wait(&cond, &mutex);
    
    if (signalTerminationActive)
    {
      signalTerminationActive = false;
      goto done;
    }
  }
  
  //
  // Once we reach this point, we are assured that there is data in the
  // queue. Extract the data from the FifoQueueElem,
  //
  object = fqe->getObject();
  
  //
  // decrement the number of queued elements,
  //
  elemCount--;
  
  //
  // and place the FifoQueueElem in the privately managed pool so that it may
  // be reused. Prior to putting it in the pool, set the data in it to NULL.
  //
  fqe->setObject(NULL);
  
  wrapperPool.addToHead(fqe);
  
done:
  pthread_mutex_unlock(&mutex);
  return object;
}

//============================================================================
bool
FifoQueue::enqueue(void* object)
{
  static const char  mn[] = "enqueue";
  
  bool            rv        = true;
  bool            yieldFlag = false;
  FifoQueueElem*  fqe;
  
  pthread_mutex_lock(&mutex);
  
  //
  // Check if the queue is full.  If it is, then give up the processor once
  // and fail.
  //
  
  if (elemCount >= sizeLimit)
  {
    rv        = false;
    yieldFlag = true;
    goto done;
  }
  
  //
  // We will try to get a previously allocated FifoQueueElem object from the
  // internally managed pool. If there are no elements in this pool, we will
  // allocate a new one. Once allocated, these objects are never destroyed.
  // They are placed in the pool when data is dequeued.
  //
  
  fqe = (FifoQueueElem*)wrapperPool.removeFromHead();
  
  if (fqe == NULL)
  {
    if ((fqe = new FifoQueueElem()) == NULL)
    {
      zlogE(cn, mn, ("FifoQueueElem memory allocation error.\n"));
      rv = false;
      goto done;
    }
  }
  
  //
  // Place the data to be enqueued in the queue element,
  //
  
  fqe->setObject(object);
  queue.addToTail(fqe);
  
  //
  // and increment the queued item count.
  //
  elemCount++;
  
  //
  // See if we need to yield the processor before we leave.
  //
  
  if (elemCount > niceThreshold)
  {
    yieldFlag = true;
  }
  
done:
  
  //
  // Notify any thread that is waiting (in the delayedDequeue method) that
  // there is now something in the queue. By design, only one thread will be
  // waiting on the condition variable. According to the pthread_cond_signal()
  // man page, it is slightly more efficient than pthread_cond_broadcast(), so
  // we use it here instead of pthread_cond_broadcast().
  //
  
  if (elemCount > 0)
  {
    pthread_cond_signal(&cond);
  }
  
  pthread_mutex_unlock(&mutex);
  
  if (yieldFlag)
  {
    if (sched_yield() != 0)
    {
      perror("FifoQueue::enqueue sched_yield error.");
      zlogE(cn, mn, ("sched_yield error.\n"));
    }
  }
  
  return(rv);
}

//============================================================================
void
FifoQueue::init(unsigned int nt, unsigned int sl)
{
  static const char  mn[] = "init";
  
  //
  // Initially the element count is set to 0.
  //
  
  elemCount = 0;
  
  niceThreshold           = nt;
  sizeLimit               = sl;
  signalTerminationActive = false;
  
  //
  // Finally, we initialize the mutex and condition variable.
  //
  
  if (pthread_mutex_init(&mutex, NULL) != 0)
  {
    perror("FifoQueue::init pthread_mutex_init error");
    zlogE(cn, mn, ("pthread_mutex_init error.\n"));
  }
  
  if (pthread_cond_init(&cond, NULL) != 0)
  {
    perror("FifoQueue::init pthread_cond_init error");
    zlogE(cn, mn, ("pthread_cond_init error.\n"));
  }
}

//============================================================================
void
FifoQueue::setQueueLimits(unsigned int nt, unsigned int sl)
{
  static const char  mn[] = "setQueueLimits";
  
  pthread_mutex_lock(&mutex);
  
  if ((sl < 1) || (nt > sl))
  {
    zlogW(cn, mn, ("Invalid limits: nt <%d>, sl <%d>. Using default "
                   "values.\n", nt, sl));
    
    niceThreshold = DEFAULT_NICE_THRESHOLD;
    sizeLimit     = DEFAULT_SIZE_LIMIT;
  }
  else
  {
    niceThreshold = nt;
    sizeLimit     = sl;
  }
  
  pthread_mutex_unlock(&mutex);
}

/*==========================================================================*/
void
FifoQueue::signalTermination()
{
  pthread_mutex_lock(&mutex);
  
  //
  // Set the signal termination flag and signal the condition variable. By
  // design, only one thread will be waiting on the condition variable.
  // According to the pthread_cond_signal man page, it is slightly more
  // efficient than pthread_cond_broadcast, so we use it here instead of
  // pthread_cond_broadcast.
  //
  
  signalTerminationActive = true;
  
  pthread_cond_signal(&cond);
  
  pthread_mutex_unlock(&mutex);
}

//============================================================================
FifoQueue::FifoQueueElem::FifoQueueElem() 
    : _object(NULL)
{
}

//============================================================================
FifoQueue::FifoQueueElem::~FifoQueueElem() 
{
  if (_object != NULL)
  {
      zlogW("FifleQueueEleme", "Destructor", 
	    ("Object not null!! -- Possible memory leak\n"));    
      _object = NULL;
  }
}
