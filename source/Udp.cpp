
#include "Udp.h"

Udp::Udp()
{
	this->sourcePort = 26;	
	this->destPort = 26;
	this->length = 10;
	this->checksum = 0;
	this->checksumFlag = true;
}

void Udp::setSourcePort(std::string & sourcePortString)
{
	this->sourcePort = (USHORT)atoi(sourcePortString.c_str());
}

void Udp::setDestPort(std::string & destPortString)
{
	this->destPort = (USHORT)atoi(destPortString.c_str());
}

void Udp::setLength(std::string & lengthString)
{
	this->length = (USHORT)atoi(lengthString.c_str());
}

void Udp::setData(std::string & data)
{
	this->data = data;
}

std::string Udp::getSegment()
{
	buildSegment();
	return this->segment;
}

void Udp::buildSegment()
{
	this->segment.clear();
	
	this->segment += (char)(this->sourcePort >> 8);
	this->segment += (char)this->sourcePort;
	this->segment += (char)(this->destPort >> 8);
	this->segment += (char)this->destPort;
	this->segment += (char)(this->length >> 8);
	this->segment += (char)this->length;
	this->segment += (char)(this->checksum >> 8);
	this->segment += (char)this->checksum;
	this->segment += this->data;

	if (this->checksumFlag == true) {
		USHORT checksum = calculateChecksum((USHORT *)segment.c_str(), segment.size());

		// write the bytes in reverse order
		this->segment[6] = (char)checksum;
		this->segment[7] = (char)(checksum >> 8);
	}
}

void Udp::setChecksum(std::string & checksumString)
{
	this->checksum = (USHORT)atoi(checksumString.c_str());
}

void Udp::clear()
{
	this->sourcePort = 26;
	this->destPort = 26;
	this->length = 10;
	this->checksum = 0;
	this->checksumFlag = true;
	this->data.clear();
	this->segment.clear();
}

USHORT Udp::calculateChecksum(USHORT *buffer, int size)
{
	unsigned long checksum = 0;
	while (size > 1) {
		checksum += *buffer++;
		size -= sizeof(unsigned short);
	}

	if (size)
		checksum += *(unsigned char*)buffer;

	checksum = (checksum >> 16) + (checksum & 0xFFFF);
	checksum += (checksum >> 16);

	return (unsigned short)(~checksum);
}

void Udp::setChecksumFlag(bool value)
{
	this->checksumFlag = value;
	if (value == false)
		this->checksum = 0;
}