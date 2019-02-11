

#include "Arp.h"

Arp::Arp()
{
	hardwareType = 0x0001;	// Ethernet (1)
	protocolType = 0x0800;	// IPv4 (0x0800)
	hardwareLength = 0x06;	// Ethernet address length (6)
	protocolLength = 0x04;	// IPv4 length (4)
	operation = 0x01;		// request (1)
}

void Arp::setSenderMacAddress(std::string & sender_addr)
{
	char hexString[3] = { 0 };
	char * p;

	for (size_t i = 0; i < sender_addr.size(); i += 3) {
		hexString[0] = sender_addr[i];
		hexString[1] = sender_addr[i + 1];
		this->senderMacAddress[i / 3] = (char)strtol(hexString, &p, 16);
	}
}

void Arp::setSenderIpAddress(std::string & sender_addr)
{
	char numString[4] = { 0 };
	size_t i = 0, j, k = 0;

	while (i < sender_addr.size()) {
		j = 0;
		while (sender_addr[i] != '.' && i < sender_addr.size())
			numString[j++] = sender_addr[i++];

		this->senderIpAddress[k] = (UCHAR)atoi(numString);
		memset(numString, 0, sizeof(numString));

		i++; // skip '.'
		k++;
	}
}

void Arp::setTargetMacAddress(std::string & target_addr)
{
	char hexString[3] = { 0 };
	char * p;

	for (size_t i = 0; i < target_addr.size(); i += 3) {
		hexString[0] = target_addr[i];
		hexString[1] = target_addr[i + 1];
		this->targetMacAddress[i / 3] = (char)strtol(hexString, &p, 16);
	}
}

void Arp::setTargetIpAddress(std::string & target_addr)
{
	char numString[4] = { 0 };
	size_t i = 0, j, k = 0;

	while (i < target_addr.size()) {
		j = 0;
		while (target_addr[i] != '.' && i < target_addr.size())
			numString[j++] = target_addr[i++];

		this->targetIpAddress[k] = (UCHAR)atoi(numString);
		memset(numString, 0, sizeof(numString));

		i++; // skip '.'
		k++;
	}
}

std::string Arp::getPacket()
{
	this->buildPacket();
	return this->packet;
}

void Arp::buildPacket()
{
	packet.clear();

	packet += (char)(hardwareType >> 8);
	packet += (char)(hardwareType);
	packet += (char)(protocolType >> 8);
	packet += (char)(protocolType);
	packet += hardwareLength;
	packet += protocolLength;
	packet += (char)(operation >> 8);
	packet += (char)(operation);

	for (int i = 0; i < 6; i++)
		packet += senderMacAddress[i];

	for (int i = 0; i < 4; i++) 
		packet += senderIpAddress[i];

	for (int i = 0; i < 6; i++)
		packet += targetMacAddress[i];

	for (int i = 0; i < 4; i++)
		packet += targetIpAddress[i];
}

void Arp::clear()
{
	memset(senderMacAddress, 0, 6);
	memset(senderIpAddress, 0, 4);
	memset(targetMacAddress, 0, 6);
	memset(targetIpAddress, 0, 4);

	packet.clear();
}