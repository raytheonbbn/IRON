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

#ifndef EmuHAIPEApp_hh
#define EmuHAIPEApp_hh

#include "IPPacket.hh"
#include "VirtIF.hh"
#include "RawIF.hh"
#include "PropertyTable.h"
#include "FifoQueue.h"
#include "Thread.h"
#include "BasicString.h"

#include <pthread.h>

#define USEALLIFS "all"


/**
 * \class EmuHAIPEApp
 *
 * This application performs packet encapsulation and
 * deencapsulation.
 *
 */
class EmuHAIPEApp
{
public:

  /**
   * Default constructor.
   */
  EmuHAIPEApp();

  /**
   * Destructor.
   */
  virtual ~EmuHAIPEApp();
  
  /**
   * Configure the services with their initial values.
   *
   * @param pt     A reference to the property table.
   * @param prefix The property prefix.
   *
   * @return Returns true on success, or false on error.
   */
  virtual bool configure(PropertyTable& pt, const char* prefix);

  /**
   * Overloaded start method. Launches a local thread as well for 
   * receiving/processing IP queue information.
   */
  virtual void start();

  /**
   * Shutdown the FEC Gateway
   */
  virtual void stop();

  /**
   *  Open the appropriate sockets for receiving and
   *  reinjecting packets.
   *
   * @return Returns true on success, or false on error.
   */
  bool initSockets();

  /**
   *  Plumb the path as needed to get the packets flowing
   *  through the gateway
   *
   * @return Returns true on success, or false on error.
   */
  bool plumb();

  /**
   *  Un-plumb the path to clean up stray routing rules
   *
   * @return Returns true on success, or false on error.
   */
  bool unplumb();

  /**
   * Routine to enable capture of packets from other gateways
   *
   * @return Returns true on success, or false on error.
   */
  bool enableCapture();

  /**
   * Routine to disble capture of packets from other gateways
   *
   * @return Returns true on success, or false on error.
   */
  bool disableCapture();
  
private:
  
  /*
   * convert an integer address to dot notation address
   */
  BasicString intToIP(int i);


  /*
   * Routine to strip off an ESP header
   *
   * @param   qpkt  : Pointer to the packet to modify
   * 
   */ 
  void removeHeader(IPPacket *qpkt);
  
  /*
   * Routine to add an ESP header
   *
   * @param   qpkt  : Pointer to the packet to modify
   * @param   seqno : monotonically increasing sequence number
   */

  void addHeader(IPPacket *qpkt, unsigned int seqno);

  /*
   * Routine to strip off "removeTrailer"
   *
   * @param   qpkt  : Pointer to the packet to modify
   * 
   */ 
  void removeTrailer(IPPacket *qpkt);
  
  /*
   * Routine to add "addTrailerion"
   *
   * @param   qpkt  : Pointer to the packet to modify
   * @param   delta : Size of the "addTrailerion" to add
   */
  void addTrailer(IPPacket *qpkt, int delta);

  /**
   *  fragment the packet into two.
   *
   *  @param   *qpkt    : Pointer to original packet to modify
   *  @param   *cpkt    : Pointer to second fragment
   *  @param    mtu      : Size of the largest fragment
     *
   * @return Returns true on success, or false on error.
   */
  bool fragmentIt(IPPacket *qpkt, IPPacket *(&cpkt), int mtu);

  /**
   *   Creates a haipe packet from the input and sends it out on
   *   the raw socket.
   *
   *   @param    qpkt  : pointer to the packet to send
   *
   * @return Returns true on success, or false on error.
   */   
  bool sendAsHaipePkt(IPPacket *qpkt);

  
  void dumpPacket(char *name, IPPacket *qpkt );
  
  // ======================================================`=====
  /**
   * Internal class for dispatching information from the packet
   * queue to the various asynchronous handlers.
   */
  class QHandler : public Thread, public Runnable {
  public:
    QHandler(EmuHAIPEApp* t) { ths = t; }
    virtual void start() { startThread(this); }
    virtual void stop() { stopThread(); }
    virtual void run() { ths->runQ(); }
  private:
    EmuHAIPEApp* ths;
  };
  QHandler qThread;

  /**
   * Routine that gathers the packet queue events.
   */
  friend class QHandler;
  void runQ();

private:
  // ===========================================================
  /**
   * Internal class for the decoding thread.
   */
  class DecapHandler : public Thread, public Runnable {
  public:
    DecapHandler(EmuHAIPEApp* t) { ths = t; }
    virtual void start() { startThread(this); }
    virtual void stop() { stopThread(); }
    virtual void run() { ths->runDecap(); }
  private:
    EmuHAIPEApp* ths;
  };
  DecapHandler decapThread;
  FifoQueue decapQueue;

  /**
   * Routine that gathers the IP QUEUE events.
   */
  friend class DecapHandler;
  void runDecap();

private:
  // ===========================================================
  /**
   * Internal class for the encoding thread.
   */
  class EncapHandler : public Thread, public Runnable {
  public:
    EncapHandler(EmuHAIPEApp* t) { ths = t; }
    virtual void start() { startThread(this); }
    virtual void stop() { stopThread(); }
    virtual void run() { ths->runEncap(); }
  private:
    EmuHAIPEApp* ths;
  };
  EncapHandler encapThread;
  FifoQueue encapQueue;

  /**
   * Routine that gathers the Queue events.
   */
  friend class EncapHandler;
  void runEncap();



private:
  /// Flag that is set when we should shutdown.
  bool halt;

  /// MUTEXes for accessing the various shared objects
  pthread_mutex_t _contextMutex;
  pthread_mutex_t _encStateMutex;
  pthread_mutex_t _decStateMutex;

  /// Specify the decap timeout for GC
  unsigned long _DecapTimeout;

  /// name of the Red side IF
  char _RedDevName[100];

  /// name of the Black side IF
  char _BlackDevName[100];

  /// name of the VIF
  char _VIFDevName[100];

  /// IP address assigned to the VIF
  char _VIFAddress[100];

  /// Netmask assgined to the VIF
  char _VIFNetmask[100];

  /// Broadcast address of the VIF
  char _VIFBroadcast[100];

  /// path to the iptables command
  char _IPTablesCmd[100];

  /// path to the ip command
  char _IPCmd[100];

  /// path to the ifconfig command
  char _IFCmd[100];

  /// firewall mark used for FECed packets
  int _FirewallMark;

  /// firewall mark used for FECed packets
  int _VIFAltTable;

  /// emulated HAIPE overhead
  unsigned long _overhead;
  
  /// flag indicating whether external plumbing will be provided
  unsigned long _externalPlumbing;
  
  /// The virtual interface
  VirtIF virtualIF;
  
  /// The raw socket interface.
  RawIF rawIF;
  
  /// The socket pair used for setting up and
  /// servicing the remote control IF
  int _listenSock;
  int _rcSock;


};

#endif
