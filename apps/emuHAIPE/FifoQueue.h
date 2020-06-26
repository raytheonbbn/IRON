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
#ifndef FifoQueue_h
#define FifoQueue_h

#include <pthread.h>

#include "LList.h"
#include "LListElem.h"

//
// The default queue nice threshold in number of NDF messages. When the number
// of NDF messages in the queue exceeds this value, a sched_yield() is
// performed after each enqueue operation to give other threads a chance to
// run and empty the queue. This value will be used if one is not provided.
//
#define DEFAULT_NICE_THRESHOLD    64

//
// The default queue size limit in number of enqueued objects. When
// the number of enqueued objects reaches this value, all enqueue calls
// will fail and a sched_yield() is performed after each enqueue
// operation to give other threads a chance to run and empty the
// queue. It will be up to the caller if the object is attempted
// to be enqueued again (lossless behavior) or dropped (lossy
// behavior). This value will be used if one is not provided.
//
#define DEFAULT_SIZE_LIMIT        128

/**
 * \class FifoQueue
 *
 * A First In First Out queue that will store objects received as void* 
 * pointers.
 *
 * The queue owns the objects when they are queued up. However, once
 * dequeued, the ownership is passed to the calling object.
 *
 * The queue has a configurable nice threshold. This value will dictate when
 * calling threads must relinquish the processor so queue processing threads
 * can access the processor to start draining the queue.
 *
 * The queue also has a configurable size limit. This value will dictate when
 * enqueues succeed or fail.
 *
 * This class is thread-safe. As a result, the objects to be queued up don't
 * have to be thread-safe.
 *
 * @author Sean P. Griffin, Mark Keaton
 */
class FifoQueue
{
public:
  
  /**
   * Default no-arg constructor.
   */
  FifoQueue();
  
  /**
   * Constructor that will initialize the queue threshold. The queue threshold
   * will dictate when calling threads should yield the processor to allow
   * queue processing threads access to the processor.
   *
   * @param nt The nice threshold value for the queue.
   * @param sl The queue's size limit.
   */
  FifoQueue(unsigned int nt, unsigned int sl);
  
  /*
   * Destructor.
   */
  virtual ~FifoQueue();
  
  /**
   * Return the number of elements in the fifo
   */
  inline int size() { return elemCount; }


  /**
   * Dequeue the elements that have been in the queue the longest, i.e., the
   * elements that were enqueued before all other elements.  This method
   * is non-blocking.  If there is no data in the queue, then NULL is 
   * returned as the object.
   *
   * @return Pointer to the object to dequeue.  May be set to NULL
   *         on return.
   */
  void* dequeue();

  /**
   * Dequeue the elements that have been in the queue the longest, i.e., the
   * elements that were enqueued before all other elements. This method will
   * try to block the calling thread until there is data to be dequeued. This
   * prevents queue processing threads from having to "poll" the queue for
   * data. The calling thread assumes ownership of the dequeued objects.
   * <p>
   * Note that this method may return NULL if the signalTermination()
   * method is called.
   *
   * @return Pointer to the object to dequeue.  May be set to NULL
   *         on return.
   */
  void* delayedDequeue();
  
  /**
   * Enqueue the elements to be stored in the queue. This places the elements
   * at the tail end of the queue, e.g., items already queued up will be
   * dequeued before the elements that are being added. The queue assumes
   * ownership for the elements that are being queued up.
   * <p>
   * If the action of enqueuing the objects pushes the queue size up to or
   * over the nice threshold value that has been set for the queue, then the
   * calling thread will be forced to relinquish the processor so that the
   * queue processing threads will have a chance to start draining the
   * queue. This behavior helps prevent the queues from becoming too large.
   * <p>
   * If the action of enqueuing the objects would push the queue size over the
   * size limit value that has been set for the queue, then the calling thread
   * will be forced to relinquish the processor and the enqueue will fail.
   *
   * @param object Pointer to the object to enqueue.
   *
   * @return Returns true if the enqueue operation succeeded, or false if it
   *         failed.
   */
  bool enqueue(void* object);
  
  /**
   * Set the queue's limits. These values control how threads are forced to
   * relinquish the processor and when enqueue operations fail because the
   * queue is too full.
   *
   * @param nt The nice threshold value for the queue.
   * @param sl The queue's size limit.
   */
  void setQueueLimits(unsigned int nt, unsigned int sl);
  
  /**
   * This should be called when a Thread of control that is using a FifoQueue
   * has been terminated.
   */
  void signalTermination();
  
private:
  
  /**
   * The elements in the FIFO queue are stored in the LList class.  Protected
   * by its own mutex lock.
   */
  LList            queue;
  
  /**
   * Pool of FifoQueueElem objects. This permits us to reuse the objects that
   * wrap the data that is added to the linked list of queued objects.
   * Protected by its own mutex lock.
   */
  LList            wrapperPool;
  
  /**
   * Tracks the number of elements that are queued.
   */
  unsigned int     elemCount;
  
  /**
   * The queue's threshold. When the number of enqueued elements exceeds this
   * value, the calling thread if forced to relinquish the processor.
   */
  unsigned int     niceThreshold;
  
  /**
   * The queue's size limit. Once reached, all enqueue operations will fail
   * until the queue size decreases.
   */
  unsigned int     sizeLimit;
  
  /**
   * A flag that is set to true when the Thread of control that is using a
   * FifoQueue has been terminated using the signalTermination() method.
   */
  bool             signalTerminationActive;
  
  /**
   * Mutex to protect the queue data. This will prevent concurrent enqueues
   * and dequeues.
   */
  pthread_mutex_t  mutex;
  
  /**
   * Queue condition variable. This allows us to wait for data to be enqueued
   * without having to poll the queue.
   */
  pthread_cond_t   cond;
  
  /**
   * Initialize the FIFO queue.
   *
   * @param nt The nice threshold value for the queue.
   * @param sl The queue's size limit.
   */
  void init(unsigned int nt, unsigned int sl);
  
  /**
   * \class FifoQueueElem
   * 
   * This class stores the data that is to be place into a FIFO queue.
   *
   * Since it is only intended to support the FifoQueue class, it is a private
   * nested class. These objects will be internally managed by the FifoQueue
   * class.
   *
   * @author Sean P. Griffin
   */
  class FifoQueueElem : public LListElem
  {
    
  public:
    
    /**
     * Default no-arg constructor.
     */
    FifoQueueElem();
    
    /**
     * Destructor.
     */
    virtual ~FifoQueueElem();
    
    /**
     * Get the object stored in the queue.
     *
     * @return The pointer to the object that is stored in the
     *         queue.
     */
    inline void* getObject()
    {
      return _object;
    }
    
    /**
     * Set the object that is to be stored in the queue.
     *
     * @param object The pointer to the object that is to be stored in the
     *               queue.
     */
    inline void setObject(void* o)
    {
      _object = o;
    }
    
  private:
    /**
     * Pointer to the object that is to be stored in the FifoQueue.
     */
    void* _object;
  }; // end class FifoQueueElem
  
}; // end class FifoQueue

#endif // FifoQueue_h
