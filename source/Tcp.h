#pragma once

#include <iostream>
#include <string>
#include <windows.h>

class Tcp
{
private:
	USHORT sourcePort;		// Source port
	USHORT destPort;		// Destination port
	UINT sequenceNumber;	// Sequence Number (SN)
	UINT ackNumber;			// Acknowledgment Number (ACK SN) (if ACK set)
	UCHAR offsetAndOther;	// Data offset(4) + Reserved(3) + NS(1)
	UCHAR flags;			// CWR, ECE, URG, ACK, PSH, RST, SYN, FIN
	USHORT windowSize;		// Window size
	USHORT checksum;		// Checksum
	USHORT urgentPointer;	// Urgent pointer (if URG set)
	std::string data;		// Data
	std::string segment;	// TCP packet
	bool checksumFlag;

	// pseudoheader for checksum calculating (some ip data)
	UCHAR sourceAddress[4];		// Source address
	UCHAR destAddress[4];		// Destination address
	UCHAR protocol;				// Protocol

	USHORT calculateChecksum(USHORT *, int);

public:
	Tcp();

	void setSourcePort(std::string &);
	void setDestPort(std::string &);
	void setSequenceNumber(std::string &);
	void setAckNumber(std::string &);
	void setDataOffset(std::string &);
	void setReserved(std::string &);
	void setNsFlag();
	void setCwrFlag();
	void setEceFlag();
	void setUrgFlag();
	void setAckFlag();
	void setPshFlag();
	void setRstFlag();
	void setSynFlag();
	void setFinFlag();
	void setWindowSize(std::string &);
	void setChecksum(std::string &);
	void setUrgentPointer(std::string &);
	void setData(std::string &);
	void setChecksumFlag(bool);
	std::string getSegment();
	void buildSegment();

	// methods for pseudoheader
	void setSourceIpAddress(std::string &);
	void setDestIpAddress(std::string &);
	void setProtocol(std::string &);

	void clear();
};