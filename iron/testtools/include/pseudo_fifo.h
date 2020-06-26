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
/// processes on a single computer.

#ifndef IRON_TESTTOOLS_PSEUDO_FIFO_H
#define IRON_TESTTOOLS_PSEUDO_FIFO_H

#include "fifo_if.h"

#include <cstddef>
#include <vector>
#include <queue>
#include <stdint.h>
#include <sys/types.h>

#define BPF_FIFO_COUNT 4
#define BPF_FIFO_ARGS(fifos) fifos->at(0), fifos->at(1), fifos->at(2), \
                             fifos->at(3)

namespace iron
{

  /// \brief A class for inter-process signaling.
  ///
  /// Each of these unidirectional signaling channels is identified by a
  /// unique path name, and allows one or more send processes to communicate
  /// short messages to a single receive process.  Each of these processes has
  /// a Fifo object that is opened using the same path name.
  ///
  /// The receive process opens its Fifo object using OpenReceiver(), and each
  /// send process opens its Fifo object using OpenSender().  The
  /// OpenReceiver() method creates the underlying signaling channel, and the
  /// OpenSender() method calls will fail until this is created successfully.
  ///
  /// The receive process may access the Fifo object's file descriptor using
  /// the GetSocketDescriptor() or AddFileDescriptors() methods, allowing it
  /// to be added to the set of file descriptors that are being watched for
  /// read events using calls such as select(2).
  ///
  /// Each send process sends a short message to the receive process using
  /// Send().  As long as the messages are smaller than PIPE_BUF bytes, then
  /// the bytes will be sent as a contiguous sequence.  Once the receive
  /// process detects that the Fifo object is ready for reading, one or more
  /// of these messages are received using Recv().
  ///
  /// Before a send process calls Send(), it should call IsOpen() to make sure
  /// that the signaling channel is still open.  If it finds that it is not
  /// open, then it must call OpenSender() and have this call succeed before
  /// it calls Send().
  ///
  /// During shutdown, the destructor handles all of the clean up required.
  /// Since the process that called OpenReceiver() creates the underlying
  /// signaling channel (a file), the destructor for that process will tear
  /// down the signaling channel (remove the file).  Note that this tear down
  /// will not affect the behavior of any send process that has not yet called
  /// the destructor.
  ///
  /// Implemented using the heap for memory. This means that the memory
  /// is NOT accessible by other processes. If a single process requires
  /// access to the same instance must be passed to all components.
  /// There is NO locking, as the code is expected to be single threaded.
  class PseudoFifo : public FifoIF
  {

   public:

    struct Message
    {
      // Size of the message buffer.
      size_t size_bytes;
      // Message data.
      uint8_t* buf;

     // \brief Default constructor
     Message()
       : size_bytes(0), buf(NULL) { }
    };

    /// \brief The default constructor.
    PseudoFifo();

    /// \brief The destructor.
    virtual ~PseudoFifo();

    // Messages that were passed to Send().
    std::queue<Message> sent_messages;

    /// \brief Add a message to be received to the FIFO.
    ///
    /// Message will be added behind any messages that might currently be in
    /// the FIFO queue.
    ///
    /// \param  msg_buf     A pointer to a buffer where the short message to
    ///                     be sent is located.
    /// \param  size_bytes  The size of the short message to be sent in
    ///                     bytes.
    void InjectMsgToRecv(uint8_t* msg_buf, size_t size_bytes);

    // Standard VirtualTunIF Interface

    /// \brief Open the receive side.
    ///
    /// Only the one process that is the receive process for the unique path
    /// name passed into the Fifo constructor must call this method.  It
    /// creates the underlying signaling channel for that path.
    ///
    /// There is no Close() method.  The destructor handles all of the
    /// required cleanup.
    ///
    /// \return  True on success, or false on error.  If this method has
    ///          already been called, then false is returned.
    bool OpenReceiver();

    /// \brief Open the send side.
    ///
    /// Each process that is a send process for the unique path name passed
    /// into the Fifo constructor must call this method.  It attaches to the
    /// underlying signaling channel that is created by the process calling
    /// OpenReceiver().  Until a process calls OpenReceiver() on the path
    /// name, this method will fail and must be retried periodically.
    ///
    /// There is no Close() method.  The destructor handles all of the
    /// required cleanup.
    ///
    /// \return  True on success, or false on error.  If this method has
    ///          already been called, then false is returned.
    bool OpenSender();

    /// \brief Test if the object has been successfully opened.
    ///
    /// Useful for checking if OpenSender() has succeeded yet.
    ///
    /// \return  True if the object has been successfully opened, or false
    ///          otherwise.
    inline bool IsOpen() const
    {
      return opened_recv_ || opened_send_;
    };

    /// \brief Send a message to the receive process.
    ///
    /// Each process that is a send process uses this method for sending a
    /// short message (less than PIPE_BUF bytes) to the receiver process.  As
    /// long as the messages are smaller than PIPE_BUF bytes, then the bytes
    /// will be sent as a contiguous sequence.  Once the receive This call is
    /// non-blocking.
    ///
    /// Because this method can fail when the receive process closes the
    /// signaling channel, the caller must call IsOpen() first.  If IsOpen()
    /// reports that the signaling channel is open, then Send() may be
    /// called.  If IsOpen() reports that the signaling channel is not open,
    /// then the OpenSender() method must be called and must succeed before
    /// calling Send().
    ///
    /// \param  msg_buf     A pointer to a buffer where the short message to
    ///                     be sent is located.
    /// \param  size_bytes  The size of the short message to be sent in
    ///                     bytes.
    ///
    /// \return  True on success, or false on error.  If false is returned,
    ///          then none of the short message was sent.
    bool Send(uint8_t* msg_buf, size_t size_bytes);

    /// \brief Receive one or more messages from the send processes.
    ///
    /// The receive process uses this method for receiving one or more
    /// short messages from the send processes.  This call is non-blocking.
    ///
    /// \param  msg_buf     A pointer to a buffer where the received short
    ///                     messages will be placed.
    /// \param  size_bytes  The size of the received message buffer in bytes.
    ///
    /// \return  The number of bytes of short messages received.  May be
    ///          zero.
    size_t Recv(uint8_t* msg_buf, size_t size_bytes);

    /// \brief Check if the underlying file descriptor is in the set.
    ///
    /// \param fds File descriptor set to check.
    ///
    /// \return True if this fifo is in the set of file descriptors,
    ///         false otherwise. False will always be returned if this fifo
    ///         is not open.
    virtual bool InSet(fd_set* fds);

    /// \brief Add the underlying file descriptor to a mask.
    ///
    /// The receive process uses this method for adding the file to a fd_set
    /// file descriptor mask and updating the maximum file descriptor in the
    /// mask.  Typically, the called would use the maximum file descriptor and
    /// the fd_set file descriptor mask in a select() call.
    ///
    /// \param  max_fd    A reference to the maximum file descriptor value to
    ///                   be updated.
    /// \param  read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Create enough FIFOs to be used with the BPF.
    ///
    /// \return A newly created collection of FIFOs that can be used to when
    ///         initializing a BPF instance.
    static std::vector<PseudoFifo*>* BpfFifos();

    /// \brief Delete memory created when calling BpfFifos().
    ///
    /// \param fifos Collection of FIFOs that was returned by BpfFifos().
    static void DeleteBpfFifos(std::vector<PseudoFifo*>* fifos);

   private:

    /// \brief Copy constructor.
    PseudoFifo(const PseudoFifo& other);

    /// \brief Copy operator.
    PseudoFifo& operator=(const PseudoFifo& other);

    /// \brief Add a message to the end of a queue.
    ///
    /// \param  msgs        Queue that the message should be added to.
    /// \param  msg_buf     A pointer to a buffer where the short message to
    ///                     be sent is located.
    /// \param  size_bytes  The size of the short message to be sent in
    ///                     bytes.
    void InjectMsgTo(std::queue<Message>* msgs, uint8_t* msg_buf,
                     size_t size_bytes);

    /// \brief Delete each messages buffer and empty the queue.
    ///
    /// \param  msgs        Queue that should be cleared.
    void Clear(std::queue<Message>* msgs);

    /// The open flags.
    bool opened_send_;
    bool opened_recv_;

    // Message that have been sent and not received.
    std::queue<Message> messages_;

    // Unique id for tracking log messages.
    int id_;

    static int last_id_;

  }; // class PseudoFifo

} // namespace iron

#endif // IRON_TESTTOOLS_PSEUDO_FIFO_H
