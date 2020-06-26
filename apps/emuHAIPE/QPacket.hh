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

#ifndef QPacket_h
#define QPacket_h

#include <iostream>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/igmp.h>

#include "QPacketPool.hh"

typedef unsigned char byte;
typedef unsigned char* byte_ptr;

// Encapsulated packet is ethernet frame plus our own headers
// MTU of 1550 + ethernet header length (ETH_HLEN = 14). We 
// round up to make sure (MAXTOTSIZE - MAXPKTSIZE) is divisible
// by 8, basically trying to avoid a few packet alignment problems

#define MAXTOTSIZE 2048
#define RAWMAXPKTSIZE 
#define MAXPKTSIZE ((1500 + ETH_HLEN + 7) & 0xfffffff8)
#define MAXHDRSIZE (MAXTOTSIZE - MAXPKTSIZE)

/**
 *
 * \class QPacket
 *
 * This class provides a container for buffering packets in a fifo
 * 
 * @author Multiple
 */
class QPacket 
{
  friend class QPacketPool;

public:
  /**
   * Default constructor.  
   */
  inline QPacket() 
  { 
    _header  = &_buffer[0];
    _hdrlen  = 0;
    
    _payload = _header;
    _paylen  = 0;
    
    _totlen  = _hdrlen + _paylen; 
    
    _nlsockfd  = -1; 
  }
  
  /**
   * Default destructor.  This is not virtual due to our QPacketPool class.
   */
  ~QPacket () { /* do nothing */ }

  /**
   * allocator and deallocator
   * @param size the size of an IntervalEntry object
   * @param mem a pointer to the memory buffer allocated for an 
   * IntervalEntry object
   * @return a pointer to a memory buffer large enough to hold an
   * IntervalEntry object
   */

  void *operator new (size_t size) 
  {
    if (_packetPool == (QPacketPool *) NULL) 
      {
	_packetPool = new QPacketPool();
      }
    
    return _packetPool->NewQPacket();
  }
  
  void operator delete (void *mem) 
  {
    if (mem != (void *) NULL) 
      {
	_packetPool->Recycle (mem);
      }
  }
  
  inline bool operator==(const QPacket& i) 
  { return ((_totlen == i._totlen) && (memcmp(_header,i._header,_totlen) == 0)); }
  
  /**
   * The current memory used 
   */
  inline int totlen() const { return _totlen; }
  
  /**
   * Maximum size of this buffer (upper bounds totlen value).
   */
  inline int maxSize() const { return MAXTOTSIZE; }
  
  /**
   * Maximum size of a packet in this buffer
   */
  inline int maxPktSize() const { return MAXPKTSIZE; }
  
  /**
   * Accessor to pull the source address out of an IP header
   */
  bool srcAddr (unsigned long &saddr) const; 

  /**
   * Accessor to pull the destination address out of an IP header
   */
  bool dstAddr (unsigned long &daddr) const; 

  /**
   * Accessor to pull the protocol out of an IP header
   */
  bool protocol (unsigned long &protocol) const; 

  // Base buffer accessor section

  /**
   * Get a pointer to the start of the memory block.  
   * Must be used with care.
   */
  inline byte* ptr() { return &_buffer[0]; }
  inline const byte* ptr() const { return &_buffer[0]; }

  /**
   * Cast the buffer into a pointer.
   */
  inline operator byte_ptr() { return _buffer; }

  // Payload accessor section

  /**
   * Get a pointer to the start of the payload.  
   * Must be used with care.
   */
  inline byte* payload() { return _payload; }
  inline const byte* payload() const { return _payload; }

  /**
   * Various parameters to keep track of encapsulation/decapsulation
   */
  inline int  paylen() const { return _paylen; }
  inline bool paylen(int c)  
  { if (_paylen <= MAXTOTSIZE - (_payload - _buffer)) 
    { _paylen=c; _totlen = _hdrlen + _paylen; return true; } return false; }

  /**
   * Function used to claim header bytes from the "payload" as part
   * of the staged decapsulation process
   */

  inline bool shrinkPayload(int c)
  { if ((c <= MAXTOTSIZE - (_payload - _buffer)) && (c >= 0)) 
    { _payload += c; _hdrlen += c; _paylen -= c; 
    _totlen   = _hdrlen + _paylen; return true; } return false; }

  // Header accessor section

  /**
   * Get a pointer to the start of the header.  
   * Must be used with care.
   */
  inline byte* header() { return _header; }
  inline const byte* header() const { return _header; }

  /**
   * Various parameters to keep track of encapsulation/decapsulation
   */
  inline int  hdrlen() const { return _hdrlen; }

  /**
   * Function used to grow the header as part of the staged 
   * encapsulation process
   */
  inline bool growHeader(int c)
  { if ((c <= (_header - _buffer)) && (c >= 0)) 
    { _header -= c; _hdrlen += c; _totlen = _hdrlen + _paylen; 
    return true; } return false; }

  /**
   * Function used to set the "read" position when pulling data 
   * from a red vif, in order to feed the encpasulation process
   * Causes the packet to be placed in the middle of the buffer
   */
  inline void setEncapReadPos()
  { _header  = &_buffer[MAXHDRSIZE]; 
    _hdrlen  = 0; 
    _payload = _header; 
    _paylen  = 0;
    _totlen  = _hdrlen + _paylen; }

  /**
   * Function used to set the "read" position when pulling data 
   * from a black vif, in order to feed the decpasulation process
   * Causes the packet to be placed at the head of the buffer
   */
  inline void setDecapReadPos()
  { _header  = &_buffer[0]; 
    _hdrlen  = 0; 
    _payload = _header; 
    _paylen  = 0;
    _totlen  = _hdrlen + _paylen; }

  /**
   * Function used to set the "read" number of bytes read after a 
   * read call on either type of vif (since we don't know how many
   * bytes we will get until we actually try to read 'em)
   */
  inline int setReadLen(int c)
  { if ((c <= MAXTOTSIZE) && (c >= 0))
    { _hdrlen = 0; 
      _paylen = c; 
      _totlen = _hdrlen + _paylen; 
      return true; }
  else { return false; }}

  /**
   * Prints the buffer pointer (along with total length and max size
   * information).
   */
  friend std::ostream& operator<<(std::ostream&, const QPacket& qpkt);

protected:
  int   _totlen;
  int   _paylen;
  int   _hdrlen;
  int   _nlsockfd; 
  byte  _buffer[MAXTOTSIZE];
  byte *_payload;
  byte *_header;
  QPacket *_next;
  static QPacketPool *_packetPool;
};

#endif /* QPacket_h */
