#pragma once

#include <iostream>
#include <string>
#include <windows.h>



class Arp
{
private:
	USHORT hardwareType;
	USHORT protocolType;
	UCHAR hardwareLength;
	UCHAR protocolLength;
	USHORT operation;
	UCHAR senderMacAddress[6];
	UCHAR senderIpAddress[4];
	UCHAR targetMacAddress[6];
	UCHAR targetIpAddress[4];
	
	std::string packet;

	void buildPacket();

public:
	Arp();

	void setSenderMacAddress(std::string &);
	void setSenderIpAddress(std::string &);
	void setTargetMacAddress(std::string &);
	void setTargetIpAddress(std::string &);
	std::string getPacket();
	void clear();
};