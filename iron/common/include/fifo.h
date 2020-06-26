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

/// \brief The IRON inter-process signaling module.
///
/// Provides the IRON software with the capability for separate processes on a
/// single computer to wake each other up from their main processing loop
/// select() calls.  Short messages from the source process are passed in one
/// direction through to the receiver process.

#ifndef IRON_COMMON_FIFO_H
#define IRON_COMMON_FIFO_H

#include "fifo_if.h"

#include <limits.h>
#include <stdint.h>
#include <sys/select.h>
#include <sys/types.h>


// There are issues with the Linux fifo (named pipe) that causes the write
// side to block for very long periods of time.  As a work-around, use a
// stream-based UNIX socket instead.  To re-enable the use of real fifos,
// uncomment the following preprocessor definition.
// #define USE_REAL_FIFOS 1

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
  /// the AddFileDescriptors() method, allowing it to be added to the set of
  /// file descriptors that are being watched for read events using calls such
  /// as select(2).
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
  /// Implemented using UNIX FIFOs (named pipes) or stream-based UNIX sockets.
  class Fifo : public FifoIF
  {

   public:

    /// \brief The default constructor.
    ///
    /// \param  path_name  The unique path and file name (e.g. "/tmp/baz") for
    ///                    the signaling channel.
    Fifo(const char* path_name);

    /// \brief The destructor.
    virtual ~Fifo();

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
    virtual bool OpenReceiver();

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
    virtual bool OpenSender();

    /// \brief Test if the object has been successfully opened.
    ///
    /// Useful for checking if OpenSender() has succeeded yet.
    ///
    /// \return  True if the object has been successfully opened, or false
    ///          otherwise.
    inline bool IsOpen() const
    {
#ifdef USE_REAL_FIFOS
      return (fifo_fd_ >= 0);
#else
      return (recv_ ? (srv_sock_fd_ >= 0) : (fifo_fd_ >= 0));
#endif
    }

    /// \brief Send a message to the receive process.
    ///
    /// Each process that is a send process uses this method for sending a
    /// short message (less than PIPE_BUF bytes) to the receiver process.  As
    /// long as the messages are smaller than PIPE_BUF bytes, then the bytes
    /// will be sent as a contiguous sequence.  This call is non-blocking.
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

    /// \brief Add the underlying file descriptor to a mask.
    ///
    /// The receive process uses this method for adding the file to a fd_set
    /// file descriptor mask and updating the maximum file descriptor in the
    /// mask.  Typically, the caller would use the maximum file descriptor and
    /// the fd_set file descriptor mask in a select() call.
    ///
    /// \param  max_fd    A reference to the maximum file descriptor value to
    ///                   be updated.
    /// \param  read_fds  A reference to the read mask to be updated.
    void AddFileDescriptors(int& max_fd, fd_set& read_fds) const;

    /// \brief Check if the underlying file descriptor is in the set.
    ///
    /// \param  fds  A pointer to the file descriptor set to check.
    ///
    /// \return  True if this fifo is in the set of file descriptors, or false
    ///          otherwise.  False will always be returned if this fifo is not
    ///          open.
    bool InSet(fd_set* fds);

   protected:

    /// The FIFO file descriptor.  Exposed for testing purposes.
    int fifo_fd_;

   private:

    /// \brief Perform the steps to open the receive side of the FIFO.
    ///
    /// \return  True on success, or false on error.
    bool InternalOpenReceiver();

    /// \brief Copy constructor.
    Fifo(const Fifo& other);

    /// \brief Copy operator.
    Fifo& operator=(const Fifo& other);

    /// The receiver flag.
    bool  recv_;

    /// The FIFO path and file name.
    char  fifo_name_[NAME_MAX];

#ifndef USE_REAL_FIFOS
    /// The server UNIX socket file descriptor.
    int   srv_sock_fd_;
#endif

  }; // class Fifo

} // namespace iron

#endif // IRON_COMMON_FIFO_H
