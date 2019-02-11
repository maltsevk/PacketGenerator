
#include "Icmp.h"

USHORT Icmp::calculateChecksum(USHORT *buffer, int size)
{
	unsigned long checksum = 0;

	while (size > 1) {
		checksum += *(unsigned short *)buffer++;
		size -= 2;
	}

	if (size > 0)
		checksum += *(unsigned char *)buffer;

	while (checksum >> 16)
		checksum = (checksum & 0xffff) + (checksum >> 16);

	return (unsigned short)(~checksum);
}

void Icmp::buildPacket()
{
	this->packet.clear();

	this->packet += this->type;
	this->packet += this->code;
	this->packet += (char)(this->checksum >> 8);
	this->packet += (char)this->checksum;
	this->packet += (char)(this->identifier >> 8);
	this->packet += (char)this->identifier;
	this->packet += (char)(this->seqNumber >> 8);
	this->packet += (char)this->seqNumber;
	this->packet += this->data;

	if (this->checksumFlag == true) {
		USHORT checksum = calculateChecksum((USHORT *)this->packet.c_str(), this->packet.size());
		
		// write the bytes in reverse order
		this->packet[2] = (char)checksum;
		this->packet[3] = (char)(checksum >> 8);

		//FILE * file = fopen("C:\\Users\\1\\Desktop\\checksum.bin", "wb");
		//fwrite(buffer, 1, 3, file);
		//fclose(file);
	}
}

Icmp::Icmp()
{
	this->type = 0;
	this->code = 0;
	this->checksum = 0;
	this->identifier = 0;
	this->seqNumber = 0;
	checksumFlag = true;
}

void Icmp::setType(std::string & typeString)
{
	this->type = (typeString[0] == '0' ? 0 : 8);
}

void Icmp::setCode(std::string & codeString)
{
	this->code = (UCHAR)atoi(codeString.c_str());
}

void Icmp::setChecksum(std::string & checksumString)
{
	this->checksum = (USHORT)atoi(checksumString.c_str());
}

void Icmp::setIdentifier(std::string & identifierString)
{
	this->identifier = (USHORT)atoi(identifierString.c_str());
}

void Icmp::setSequenceNumber(std::string & seqNumberString)
{
	this->seqNumber = (USHORT)atoi(seqNumberString.c_str());
}

void Icmp::setData(std::string & data)
{
	this->data = data;
}

std::string Icmp::getPacket()
{
	this->buildPacket();
	return this->packet;
}

void Icmp::setChecksumFlag(bool value)
{
	this->checksumFlag = value;
	if (value == true)
		this->checksum = 0;
}

void Icmp::clear()
{
	this->type = 0;
	this->code = 0;
	this->checksum = 0;
	this->data.clear();
	this->packet.clear();
}