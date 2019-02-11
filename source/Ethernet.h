#pragma once

#include <iostream>
#include <pcap.h>

using namespace System::Windows::Forms;

class Ethernet 
{
private:
	// frame fields
	UCHAR destAddress[6];		// Destination address
	UCHAR sourceAddress[6];		// Source address
	USHORT etherType;			// Indicates which protocol is encapsulated in the payload
	std::string data;			// Data

	// other data
	std::string ethernetFrame;
	std::string adapterName;

	ULONG calculateCrc32(UCHAR *, ULONG);
	void buildFrame();

public:
	Ethernet();

	int sendFrame();
	void setDestMac(std::string &);
	void setSourceMac(std::string &);
	void setEthernetType(std::string &);
	void setAdapterName(std::string &);
	void setData(std::string & );
	std::string getFrame();
	void clear();
};