#pragma once

#include <iostream>
#include <windows.h>

class Udp
{
private:
	USHORT sourcePort;	// Source port
	USHORT destPort;	// Destination port
	USHORT length;		// Datagram length
	USHORT checksum;	// Checksum
	std::string data;	// Data
	std::string segment;// Udp segment
	bool checksumFlag;

	USHORT calculateChecksum(USHORT *, int);

public:
	Udp();

	void setSourcePort(std::string &);
	void setDestPort(std::string &);
	void setLength(std::string &);
	void setData(std::string &);
	void setChecksum(std::string &);
	void setChecksumFlag(bool);
	std::string getSegment();
	void buildSegment();
	void clear();
};