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

#ifndef RawIF_h
#define RawIF_h

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

extern "C" {
#include <linux/if.h>
};

class IPPacket;

/**
 *
 * \class RawIF
 *
 * Manage a raw packet socket
 * 
 */
class RawIF
{
public:
  /**
   * Creates and initializes the raw socket management object
   */
  RawIF();

  /**
   * Destructor.  Destroys the raw socket management object
   */
  virtual ~RawIF();

  /**
   * Opens the raw socket to start sending/receiving data.
   * 
   * @return Returns true if successful, false otherwise
   */
  bool open();

  /**
   * Closes the raw socket
   */
  void close();

  /// Accessor to retrieve the file descriptor associated with the raw socket (e.g., as needed for "select")
  inline int rawfd() const { return _rawfd; }

  /**
   * Writes a packet in a buffer to the raw socket
   *
   * @param qpkt Packet to be written
   */
  void send(const IPPacket &qpkt);

  /**
   * Writes a packet in a buffer to the raw socket
   *
   * @param qpkt Packet to be written
   */
  void send(const IPPacket *qpkt);

  /**
   * Reads a packet from the raw socket
   *
   * @param qpkt Packet to hold the results of the read
   */
  void recv(IPPacket &qpkt);

protected:
  /// File descriptor for the raw socket
  int _rawfd;
};

#endif /* RawIF_h */
