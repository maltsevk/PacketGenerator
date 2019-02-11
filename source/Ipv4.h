#pragma once

#include <iostream>
#include <windows.h>

using namespace System::Windows::Forms;

class Ipv4
{
private:
	UCHAR versionAndIhl;		// Version (4 bits) + Internet header length (4 bits)
	UCHAR typeOfService;		// Type of service 
	USHORT totalLength;			// Total length 
	USHORT identification;		// Identification
	USHORT flagsAndOffset;		// Flags (3 bits) + Fragment offset (13 bits)
	UCHAR timeToLive;			// Time to live
	UCHAR protocol;				// Protocol
	USHORT headerChecksum;		// Header checksum
	UCHAR sourceAddress[4];		// Source address
	UCHAR destAddress[4];		// Destination address
	std::string data;			// Data
	std::string packet;			// Ip packet
	bool checksumFlag;

	USHORT calculateChecksum(USHORT *, int);

public:
	Ipv4();

	void setVersion(std::string &);
	void setInternetHeaderLength(std::string &);
	void setPrecedence(std::string &);
	void setEcn(std::string &);
	void setDelayFlag();
	void setReliabilityFlag();
	void setThroughputFlag();
	void setTotalLength(std::string &);
	void setIdentification(std::string &);
	void setReservedFlag();
	void setDfFlag();
	void setMfFlag();
	void setFragmentOffset(std::string &);
	void setTimeToLive(std::string &);
	void setProtocol(std::string &);
	void setHeaderChecksum(std::string &);
	void setSourceAddress(std::string &);
	void setDestAddress(std::string &);
	void setData(std::string &);
	void setChecksumFlag(bool);
	std::string getPacket();
	void buildFrame();
	void clear();
};