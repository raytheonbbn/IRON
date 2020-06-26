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

#include "pseudo_fifo.h"

#include "log.h"

#include <cstring>

using ::iron::FifoIF;
using ::iron::PseudoFifo;
using ::iron::Log;

using ::std::queue;
using ::std::vector;

namespace
{
  const char* kClassName = "PseudoFifo";
}

int PseudoFifo::last_id_ = 0;

//============================================================================
PseudoFifo::PseudoFifo()
  : FifoIF(), opened_send_(false), opened_recv_(false), messages_(),
    id_(last_id_++)
{
  LogD(kClassName, __func__, "%d: Created.\n", id_);
}

//============================================================================
PseudoFifo::~PseudoFifo()
{
  opened_send_ = false;
  opened_recv_ = false;
  Clear(&messages_);
  Clear(&sent_messages);
  LogD(kClassName, __func__, "%d: Destroyed.\n", id_);
}

//============================================================================
bool PseudoFifo::OpenReceiver()
{
  if (opened_recv_)
  {
    LogE(kClassName, __func__, "%d: PseudoFifo already opened to receive.\n",
         id_);
    return false;
  }
  opened_recv_ = true;

  return true;
}

//============================================================================
bool PseudoFifo::OpenSender()
{
  if (opened_send_)
  {
    LogE(kClassName, __func__, "%d: PseudoFifo already opened to send.\n",
         id_);
    return false;
  }
  opened_send_ = true;

  return true;
}

//============================================================================
void PseudoFifo::InjectMsgToRecv(uint8_t* msg_buf, size_t size_bytes)
{
  InjectMsgTo(&messages_, msg_buf, size_bytes);
}

//============================================================================
bool PseudoFifo::Send(uint8_t* msg_buf, size_t size_bytes)
{
  if (!opened_send_)
  {
    LogE(kClassName, __func__, "%d: PseudoFifo is not open to send.\n", id_);
    return false;
  }

  InjectMsgTo(&messages_, msg_buf, size_bytes);
  InjectMsgTo(&sent_messages, msg_buf, size_bytes);

  return true;
}

//============================================================================
size_t PseudoFifo::Recv(uint8_t* msg_buf, size_t size_bytes)
{
  if (!opened_recv_)
  {
    LogE(kClassName, __func__, "%d: PseudoFifo is not open to receive.\n", id_);
    return 0;
  }
  if (messages_.empty())
  {
    LogE(kClassName, __func__, "%d: no messages to recv.\n", id_);
    return 0;
  }

  Message msg = messages_.front();
  if (msg.size_bytes > size_bytes)
  {
    LogW(kClassName, __func__, "%d: The entire message does not fit in the " \
                               "receive buffer.\n", id_);
  }
  else if (msg.size_bytes < size_bytes)
  {
    size_bytes = msg.size_bytes;
  }
  memcpy(msg_buf, msg.buf, size_bytes);
  delete[] msg.buf;
  messages_.pop();

  return size_bytes;
}

//============================================================================
void PseudoFifo::AddFileDescriptors(int& max_fd, fd_set& read_fds) const
{
}

//============================================================================
bool PseudoFifo::InSet(fd_set* fds)
{
  // We expect this to only be called after a call to Select() to check if
  // there is something ready to read, so return true if there is something to
  // read.
  return IsOpen() && !messages_.empty();
}

//============================================================================
void PseudoFifo::InjectMsgTo(queue<Message>* msgs, uint8_t* msg_buf,
                             size_t size_bytes)
{
  Message msg;
  msg.size_bytes = size_bytes;
  msg.buf = new uint8_t[size_bytes];
  memcpy(msg.buf, msg_buf, size_bytes);

  msgs->push(msg);
}

//============================================================================
void PseudoFifo::Clear(queue<Message>* msgs)
{
  while(!msgs->empty())
  {
    Message msg = msgs->front();
    delete[] msg.buf;
    msgs->pop();
  }
}

//============================================================================
vector<PseudoFifo*>* PseudoFifo::BpfFifos()
{
  vector<PseudoFifo*>* fifos = new vector<PseudoFifo*>();

  for (int i = 0; i < BPF_FIFO_COUNT; i++)
  {
    fifos->push_back(new PseudoFifo());
  }
  return fifos;
}

//============================================================================
void PseudoFifo::DeleteBpfFifos(std::vector<PseudoFifo*>* fifos)
{
  for (int i = 0; i < BPF_FIFO_COUNT; i++)
  {
    delete fifos->at(i);
  }
  delete fifos;
}