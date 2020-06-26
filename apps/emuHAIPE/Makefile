emuHaipe: VirtIF.o      \
	RawIF.o         \
	IPPacket.o      \
	IPPacketPool.o  \
	EmuHAIPEOpts.o  \
	EmuHAIPEApp.o   \
	emuHAIPE.o      \
	ZLog.o          \
	PropertyTable.o \
	BasicString.o   \
	BasicStringTokenizer.o \
	FifoQueue.o     \
	HTable.o        \
	HTableElem.o    \
	LList.o         \
	LListElem.o     \
	Thread.o	
	cc -o emuHAIPE VirtIF.o RawIF.o IPPacket.o IPPacketPool.o EmuHAIPEOpts.o EmuHAIPEApp.o \
		emuHAIPE.o ZLog.o PropertyTable.o BasicString.o BasicStringTokenizer.o FifoQueue.o \
		HTable.o HTableElem.o LList.o LListElem.o Thread.o -lpthread -lstdc++

VirtIF.o: VirtIF.cc
	g++ -c $(CFLAGS) VirtIF.cc

RawIF.o: RawIF.cc
	g++ -c $(CFLAGS) RawIF.cc

IPPacket.o: IPPacket.cc
	g++ -c $(CFLAGS) IPPacket.cc

IPPacketPool.o: IPPacketPool.cc
	g++ -c $(CFLAGS) IPPacketPool.cc

EmuHAIPEOpts.o: EmuHAIPEOpts.cc
	g++ -c $(CFLAGS) EmuHAIPEOpts.cc

EmuHAIPEApp.o: EmuHAIPEApp.cc
	g++ -c $(CFLAGS) EmuHAIPEApp.cc

emuHAIPE.o: emuHAIPE.cc
	g++ -c $(CFLAGS) emuHAIPE.cc

ZLog.o: ZLog.cpp
	g++ -c $(CFLAGS) ZLog.cpp

PropertyTable.o: PropertyTable.cpp
	g++ -c $(CFLAGS) PropertyTable.cpp

BasicString.o: BasicString.cpp
	g++ -c $(CFLAGS) BasicString.cpp

BasicStringTokenizer.o: BasicStringTokenizer.cpp
	g++ -c $(CFLAGS) BasicStringTokenizer.cpp

FifoQueue.o: FifoQueue.cpp
	g++ -c $(CFLAGS) FifoQueue.cpp

HTable.o: HTable.cpp
	g++ -c $(CFLAGS) HTable.cpp

HTableElem.o: HTableElem.cpp
	g++ -c $(CFLAGS) HTableElem.cpp

LList.o: LList.cpp
	g++ -c $(CFLAGS) LList.cpp

LListElem.o: LListElem.cpp
	g++ -c $(CFLAGS) LListElem.cpp

Thread.o: Thread.cpp
	g++ -c $(CFLAGS) Thread.cpp

clean:
	rm *.o emuHAIPE
