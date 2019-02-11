#pragma once

#include <iostream>
#include <windows.h>

class Icmp
{
private:
	UCHAR type;			// Type (echo reply, echo request)
	UCHAR code;			// Code 
	USHORT checksum;	// Checksum
	USHORT identifier;	// Identifier
	USHORT seqNumber;	// Sequence number
	std::string data;	// Data
	std::string packet;	// Icmp packet
	bool checksumFlag;

	USHORT calculateChecksum(USHORT *, int);
	void buildPacket();
public:
	Icmp();

	void setType(std::string &);
	void setCode(std::string &);
	void setChecksum(std::string &);
	void setIdentifier(std::string &);
	void setSequenceNumber(std::string &);
	void setData(std::string &);
	void setChecksumFlag(bool);
	std::string getPacket();
	void clear();
};
