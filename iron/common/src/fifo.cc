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

#include "fifo.h"

#include "itime.h"
#include "log.h"
#include "unused.h"

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>


using ::iron::Fifo;
using ::iron::Log;


namespace
{
  const char*  UNUSED(kClassName) = "Fifo";
}


#ifdef USE_REAL_FIFOS

//============================================================================
Fifo::Fifo(const char* path_name)
    : fifo_fd_(-1), recv_(false), fifo_name_()
{
  strncpy(fifo_name_, path_name, NAME_MAX);
  fifo_name_[NAME_MAX - 1] = '\0';
}

//============================================================================
Fifo::~Fifo()
{
  // Clean up.
  if (IsOpen())
  {
    close(fifo_fd_);

    if (recv_)
    {
      if (remove(fifo_name_) < 0)
      {
        LogE(kClassName, __func__, "Error in remove: %s.\n", strerror(errno));
      }
    }
  }

  recv_    = false;
  fifo_fd_ = -1;
  memset(fifo_name_, 0, sizeof(fifo_name_));
}

//============================================================================
bool Fifo::OpenReceiver()
{
  if (IsOpen())
  {
    return false;
  }

  if (!InternalOpenReceiver())
  {
    return false;
  }

  recv_ = true;

  return true;
}

//============================================================================
bool Fifo::OpenSender()
{
  if (IsOpen())
  {
    return false;
  }

  // Ignore SIGPIPE, which may be raised in calls to write().
  struct sigaction  act;

  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;

  if (sigaction(SIGPIPE, &act, NULL) < 0)
  {
    LogE(kClassName, __func__, "Error in sigaction() to ignore SIGPIPE: %s\n",
         strerror(errno));
    return false;
  }

  // Open the FIFO file for writing.
  fifo_fd_ = open(fifo_name_, (O_WRONLY | O_NONBLOCK));

  if (fifo_fd_ < 0)
  {
    LogD(kClassName, __func__, "Error in open(%s): %s\n", fifo_name_,
         strerror(errno));
    return false;
  }

  // Make sure that the file descriptor is set to non-blocking mode.
  if (fcntl(fifo_fd_, F_SETFL, O_NONBLOCK) < 0)
  {
    LogD(kClassName, __func__, "Error in fcntl(): %s\n", strerror(errno));
    close(fifo_fd_);
    fifo_fd_ = -1;
    return false;
  }

  LogI(kClassName, __func__, "Created send FIFO: %s\n", fifo_name_);

  recv_ = false;

  return true;
}

//============================================================================
bool Fifo::Send(uint8_t* msg_buf, size_t size_bytes)
{
  if ((fifo_fd_ < 0) || (msg_buf == NULL) || (size_bytes < 1))
  {
    return false;
  }

  ssize_t  bytes = write(fifo_fd_, msg_buf, size_bytes);

  if (bytes < 0)
  {
    if (errno == EPIPE)
    {
      // The receiver process has closed the FIFO.  There is no choice but to
      // close this end of the FIFO.  The caller will have to attempt to open
      // it again when possible.
      close(fifo_fd_);
      fifo_fd_ = -1;

      LogI(kClassName, __func__, "Receiver process closed FIFO %s.\n",
           fifo_name_);
    }
    else
    {
      LogE(kClassName, __func__, "Error in write on FIFO %s: %s.\n",
           fifo_name_, strerror(errno));
    }
    return false;
  }

  if (bytes != static_cast<ssize_t>(size_bytes))
  {
    LogE(kClassName, __func__, "Unable to write on FIFO %s, sent %zd of %zd "
         "bytes.\n", fifo_name_, bytes, size_bytes);
    return false;
  }

  LogD(kClassName, __func__, "Wrote %zd bytes on FIFO %s.\n", bytes,
       fifo_name_);

  return true;
}

//============================================================================
size_t Fifo::Recv(uint8_t* msg_buf, size_t size_bytes)
{
  if ((fifo_fd_ < 0) || (msg_buf == NULL) || (size_bytes < 1))
  {
    return 0;
  }

  ssize_t  bytes = read(fifo_fd_, msg_buf, size_bytes);

  if (bytes < 0)
  {
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
    {
      LogE(kClassName, __func__, "Error in read on FIFO %s: (%d) %s.\n",
           fifo_name_, errno, strerror(errno));
    }
    return 0;
  }

  if (bytes == 0)
  {
    // The last sender process has closed the FIFO.  There is no choice but to
    // close this end of the FIFO and reopen it.
    LogI(kClassName, __func__, "Last sender process closed FIFO %s, must "
         "close and reopen FIFO.\n", fifo_name_);
    close(fifo_fd_);
    fifo_fd_ = -1;
    InternalOpenReceiver();
    return 0;
  }

  LogD(kClassName, __func__, "Read %zd bytes on FIFO %s.\n", bytes,
       fifo_name_);

  return bytes;
}

//============================================================================
void Fifo::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
  if (IsOpen())
  {
    if (fifo_fd_ > max_fd)
    {
      max_fd = fifo_fd_;
    }

    FD_SET(fifo_fd_, &read_fds);
  }
}

//============================================================================
bool Fifo::InSet(fd_set* fds)
{
  if (IsOpen())
  {
    return FD_ISSET(fifo_fd_, fds);
  }
  return false;
}

//============================================================================
bool Fifo::InternalOpenReceiver()
{
  // Attempt to remove any old FIFO file.  This might fail, which is OK.
  if (remove(fifo_name_) == 0)
  {
    LogD(kClassName, __func__, "Removed old FIFO file: %s\n", fifo_name_);
  }

  // Create the FIFO file.
  if (mkfifo(fifo_name_, 0666) != 0)
  {
    LogE(kClassName, __func__, "Error in mkfifo(%s): %s\n", fifo_name_,
         strerror(errno));
    return false;
  }

  // Open the FIFO file for reading.
  fifo_fd_ = open(fifo_name_, (O_RDONLY | O_NONBLOCK));

  if (fifo_fd_ < 0)
  {
    LogE(kClassName, __func__, "Error in open(%s): %s\n", fifo_name_,
         strerror(errno));
    if (remove(fifo_name_) == 0)
    {
      LogD(kClassName, __func__, "Removed old FIFO file: %s\n", fifo_name_);
    }
    return false;
  }

  // Make sure that the file descriptor is set to non-blocking mode.
  if (fcntl(fifo_fd_, F_SETFL, O_NONBLOCK) < 0)
  {
    LogD(kClassName, __func__, "Error in fcntl(): %s\n", strerror(errno));
    if (remove(fifo_name_) == 0)
    {
      LogD(kClassName, __func__, "Removed old FIFO file: %s\n", fifo_name_);
    }
    close(fifo_fd_);
    fifo_fd_ = -1;
    return false;
  }

  LogI(kClassName, __func__, "Created receive FIFO: %s\n", fifo_name_);

  return true;
}

#else // !USE_REAL_FIFOS

//============================================================================
Fifo::Fifo(const char* path_name)
    : fifo_fd_(-1), recv_(false), fifo_name_(), srv_sock_fd_(-1)
{
  strncpy(fifo_name_, path_name, NAME_MAX);
  fifo_name_[NAME_MAX - 1] = '\0';
}

//============================================================================
Fifo::~Fifo()
{
  // Clean up.
  if (fifo_fd_ >= 0)
  {
    close(fifo_fd_);
  }

  if (recv_)
  {
    if (srv_sock_fd_ >= 0)
    {
      close(srv_sock_fd_);
    }

    if (remove(fifo_name_) < 0)
    {
      LogE(kClassName, __func__, "Error in remove: %s.\n", strerror(errno));
    }
  }

  recv_        = false;
  fifo_fd_     = -1;
  srv_sock_fd_ = -1;
  memset(fifo_name_, 0, sizeof(fifo_name_));
}

//============================================================================
bool Fifo::OpenReceiver()
{
  if (IsOpen())
  {
    return false;
  }

  // Remove any old UNIX socket file.
  remove(fifo_name_);

  // Open the server UNIX socket.
  srv_sock_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);

  if (srv_sock_fd_ < 0)
  {
    LogE(kClassName, __func__, "Error in socket(): %s\n", strerror(errno));
    return false;
  }

  // Bind the server UNIX socket to the file.
  struct sockaddr_un  addr;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, fifo_name_, sizeof(addr.sun_path) - 1);

  if (bind(srv_sock_fd_, reinterpret_cast<struct sockaddr*>(&addr),
           sizeof(addr)) < 0)
  {
    LogE(kClassName, __func__, "Error in bind(%s): %s\n", fifo_name_,
         strerror(errno));
    close(srv_sock_fd_);
    srv_sock_fd_ = -1;
    remove(fifo_name_);
    return false;
  }

  // Listen for connections.
  if (listen(srv_sock_fd_, 5) < 0)
  {
    LogE(kClassName, __func__, "Error in listen(): %s\n", strerror(errno));
    close(srv_sock_fd_);
    srv_sock_fd_ = -1;
    remove(fifo_name_);
    return false;
  }

  LogI(kClassName, __func__, "Created server UNIX socket: %s\n", fifo_name_);

  recv_ = true;

  return true;
}

//============================================================================
bool Fifo::OpenSender()
{
  if (IsOpen())
  {
    return false;
  }

  // Ignore SIGPIPE, which may be raised in calls to write().
  struct sigaction  act;

  memset(&act, 0, sizeof(act));
  act.sa_handler = SIG_IGN;

  if (sigaction(SIGPIPE, &act, NULL) < 0)
  {
    LogE(kClassName, __func__, "Error in sigaction() to ignore SIGPIPE: %s\n",
         strerror(errno));
    return false;
  }

  // Open the UNIX socket.
  fifo_fd_ = socket(AF_UNIX, SOCK_STREAM, 0);

  if (fifo_fd_ < 0)
  {
    LogE(kClassName, __func__, "Error in socket(): %s\n", strerror(errno));
    return false;
  }

  // Connect to the server's address.
  struct sockaddr_un  addr;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, fifo_name_, sizeof(addr.sun_path) - 1);

  if (connect(fifo_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  {
    LogD(kClassName, __func__, "Error in connect(): %s\n", strerror(errno));
    close(fifo_fd_);
    fifo_fd_ = -1;
    return false;
  }

  // Make sure that the file descriptor is set to non-blocking mode.
  if (fcntl(fifo_fd_, F_SETFL, O_NONBLOCK) < 0)
  {
    LogE(kClassName, __func__, "Error in fcntl(): %s\n", strerror(errno));
    close(fifo_fd_);
    fifo_fd_ = -1;
    return false;
  }

  LogI(kClassName, __func__, "Created client UNIX socket: %s\n", fifo_name_);

  recv_ = false;

  return true;
}

//============================================================================
bool Fifo::Send(uint8_t* msg_buf, size_t size_bytes)
{
  if (recv_ || (fifo_fd_ < 0) || (msg_buf == NULL) || (size_bytes < 1))
  {
    return false;
  }

  ssize_t  bytes = write(fifo_fd_, msg_buf, size_bytes);

  if (bytes < 0)
  {
    if (errno == EPIPE)
    {
      // The receiver process has closed their UNIX socket.  There is no
      // choice but to close this UNIX socket.  The caller will have to
      // attempt to open it again when possible.
      close(fifo_fd_);
      fifo_fd_ = -1;

      LogE(kClassName, __func__, "Receiver process closed UNIX socket %s.\n",
           fifo_name_);
    }
    else
    {
      LogE(kClassName, __func__, "Error in write on UNIX socket %s: %s.\n",
           fifo_name_, strerror(errno));
    }
    return false;
  }

  if (bytes != static_cast<ssize_t>(size_bytes))
  {
    LogE(kClassName, __func__, "Unable to write on UNIX socket %s, sent %zd "
         "of %zd bytes.\n", fifo_name_, bytes, size_bytes);
    return false;
  }

  LogD(kClassName, __func__, "Wrote %zd bytes on UNIX socket %s.\n", bytes,
       fifo_name_);

  return true;
}

//============================================================================
size_t Fifo::Recv(uint8_t* msg_buf, size_t size_bytes)
{
  if (recv_ && (fifo_fd_ < 0) && (srv_sock_fd_ >= 0))
  {
    // Accept a connection from the client.
    fifo_fd_ = accept(srv_sock_fd_, NULL, NULL);

    if (fifo_fd_ < 0)
    {
      LogE(kClassName, __func__, "Error in accept(): %s\n", strerror(errno));
      return 0;
    }

    // Make sure that the file descriptor is set to non-blocking mode.
    if (fcntl(fifo_fd_, F_SETFL, O_NONBLOCK) < 0)
    {
      LogE(kClassName, __func__, "Error in fcntl(): %s\n", strerror(errno));
      close(fifo_fd_);
      fifo_fd_ = -1;
      return 0;
    }

    LogD(kClassName, __func__, "Accepted connection from client to %s.\n",
         fifo_name_);
  }

  if (!recv_ || (fifo_fd_ < 0) || (msg_buf == NULL) || (size_bytes < 1))
  {
    return 0;
  }

  ssize_t  bytes = read(fifo_fd_, msg_buf, size_bytes);

  if (bytes < 0)
  {
    if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
    {
      LogE(kClassName, __func__, "Error in read on UNIX socket %s: (%d) "
           "%s.\n", fifo_name_, errno, strerror(errno));
    }
    return 0;
  }

  if (bytes == 0)
  {
    // The client has closed its UNIX socket.
    LogI(kClassName, __func__, "Client closed its UNIX socket to %s.\n",
         fifo_name_);
    close(fifo_fd_);
    fifo_fd_ = -1;
    return 0;
  }

  LogD(kClassName, __func__, "Read %zd bytes on UNIX socket %s.\n", bytes,
       fifo_name_);

  return bytes;
}

//============================================================================
void Fifo::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
  if (fifo_fd_ >= 0)
  {
    if (fifo_fd_ > max_fd)
    {
      max_fd = fifo_fd_;
    }

    FD_SET(fifo_fd_, &read_fds);
  }
  else if (recv_ && (srv_sock_fd_ >= 0))
  {
    if (srv_sock_fd_ > max_fd)
    {
      max_fd = srv_sock_fd_;
    }

    FD_SET(srv_sock_fd_, &read_fds);
  }
}

//============================================================================
bool Fifo::InSet(fd_set* fds)
{
  if (fifo_fd_ >= 0)
  {
    return FD_ISSET(fifo_fd_, fds);
  }

  if (recv_ && (srv_sock_fd_ >= 0))
  {
    return FD_ISSET(srv_sock_fd_, fds);
  }

  return false;
}

//============================================================================
bool Fifo::InternalOpenReceiver()
{
  return true;
}

#endif // USE_REAL_FIFOS
