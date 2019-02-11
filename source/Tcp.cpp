
#include "Tcp.h"

Tcp::Tcp()
{
	this->sourcePort = 22;		
	this->destPort = 22;
	this->sequenceNumber = 1;
	this->ackNumber = 1;
	this->offsetAndOther = 0x50;
	this->flags = 0;
	this->windowSize = 1;
	this->checksum = 0;
	this->urgentPointer = 1;

	this->checksumFlag = true;
}

void Tcp::setSourcePort(std::string & sourcePortString)
{
	this->sourcePort = (USHORT)atoi(sourcePortString.c_str());
}

void Tcp::setDestPort(std::string & destPortString)
{
	this->destPort = (USHORT)atoi(destPortString.c_str());
}

void Tcp::setSequenceNumber(std::string & seqNumberString)
{
	this->sequenceNumber = (UINT)atoi(seqNumberString.c_str());
}

void Tcp::setAckNumber(std::string & ackNumberString)
{
	this->ackNumber = (UINT)atoi(ackNumberString.c_str());
}

void Tcp::setDataOffset(std::string & offsetString)
{
	UCHAR offset = atoi(offsetString.c_str());
	this->offsetAndOther &= ((offset << 4) | 0x0F);
	this->offsetAndOther |= ((offset << 4) & 0xF0);
}

void Tcp::setReserved(std::string & reservedString)
{
	UCHAR reserved = atoi(reservedString.c_str());
	this->offsetAndOther &= ((reserved << 1) | 0xF1);
	this->offsetAndOther |= ((reserved << 1) & 0x0E);
}

void Tcp::setNsFlag()
{
	this->offsetAndOther |= 0x01;
}

void Tcp::setCwrFlag()
{
	this->flags |= 0x80;
}

void Tcp::setEceFlag()
{
	this->flags |= 0x40;
}

void Tcp::setUrgFlag()
{
	this->flags |= 0x20;
}

void Tcp::setAckFlag()
{
	this->flags |= 0x10;
}

void Tcp::setPshFlag()
{
	this->flags |= 0x08;
}

void Tcp::setRstFlag()
{
	this->flags |= 0x04;
}

void Tcp::setSynFlag()
{
	this->flags |= 0x02;
}

void Tcp::setFinFlag()
{
	this->flags |= 0x01;
}

void Tcp::setWindowSize(std::string & windowSizeString)
{
	this->windowSize = (USHORT)atoi(windowSizeString.c_str());
}

void Tcp::setChecksum(std::string & checksumString)
{
	this->checksum = (USHORT)atoi(checksumString.c_str());
}

void Tcp::setUrgentPointer(std::string & urgentPointerString)
{
	this->urgentPointer = (USHORT)atoi(urgentPointerString.c_str());
}

void Tcp::setData(std::string & data)
{
	this->data = data;
}

std::string Tcp::getSegment()
{
	buildSegment();
	return this->segment;
}

void Tcp::buildSegment()
{
	segment.clear();

	this->segment += (char)(this->sourcePort >> 8);
	this->segment += (char)this->sourcePort;
	this->segment += (char)(this->destPort >> 8);
	this->segment += (char)this->destPort;
	this->segment += (char)(this->sequenceNumber >> 24);
	this->segment += (char)(this->sequenceNumber >> 16);
	this->segment += (char)(this->sequenceNumber >> 8);
	this->segment += (char)this->sequenceNumber;
	this->segment += (char)(this->ackNumber >> 24);
	this->segment += (char)(this->ackNumber >> 16);
	this->segment += (char)(this->ackNumber >> 8);
	this->segment += (char)this->ackNumber;
	this->segment += (char)this->offsetAndOther;
	this->segment += (char)this->flags;
	this->segment += (char)(this->windowSize >> 8);
	this->segment += (char)this->windowSize;
	this->segment += (char)(this->checksum >> 8);
	this->segment += (char)this->checksum;
	this->segment += (char)(this->urgentPointer >> 8);
	this->segment += (char)this->urgentPointer;

	// if SYN is set -> add tcp options (12 bytes)
	if (this->flags & 0x02) {
		char options[13] = {0x02, 0x04, 0x05, 0xB4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02, 0x00};
		this->segment += options;
	}

	this->segment += data;

	if (this->checksumFlag == true) {
		std::string pseudoHeader;
		USHORT tcpLength = (USHORT)segment.size();
		USHORT checksum;

		pseudoHeader += this->sourceAddress[0];
		pseudoHeader += this->sourceAddress[1];
		pseudoHeader += this->sourceAddress[2];
		pseudoHeader += this->sourceAddress[3];
		pseudoHeader += this->destAddress[0];
		pseudoHeader += this->destAddress[1];
		pseudoHeader += this->destAddress[2];
		pseudoHeader += this->destAddress[3];
		pseudoHeader += (char)0;
		pseudoHeader += this->protocol;
		pseudoHeader += (char)(tcpLength >> 8);
		pseudoHeader += (char)(tcpLength);

		checksum = calculateChecksum((USHORT *)(pseudoHeader + segment).c_str(), (pseudoHeader + segment).size());

		// write the bytes in reverse order (fill tcp header checksum)
		this->segment[16] = (char)checksum;
		this->segment[17] = (char)(checksum >> 8);
	}
}

void Tcp::clear()
{
	this->sourcePort = 22;
	this->destPort = 22;
	this->sequenceNumber = 1;
	this->ackNumber = 1;
	this->offsetAndOther = 0x50;
	this->flags = 0;
	this->windowSize = 1;
	this->checksum = 0;
	this->urgentPointer = 1;
	this->data.clear();
	this->segment.clear();
	this->checksumFlag = false;
}

void Tcp::setChecksumFlag(bool value)
{
	this->checksumFlag = value;
	if (value == true)
		this->checksum = 0;
}

USHORT Tcp::calculateChecksum(USHORT *buffer, int size)
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

void Tcp::setSourceIpAddress(std::string & sourceAddressString)
{
	char numString[4] = { 0 };
	size_t i = 0, j, k = 0;

	while (i < sourceAddressString.size()) {
		j = 0;
		while (sourceAddressString[i] != '.' && i < sourceAddressString.size())
			numString[j++] = sourceAddressString[i++];

		this->sourceAddress[k] = (UCHAR)atoi(numString);
		memset(numString, 0, sizeof(numString));

		i++; // skip '.'
		k++;
	}
}

void Tcp::setDestIpAddress(std::string & destAddressString)
{
	char numString[4] = { 0 };
	size_t i = 0, j, k = 0;

	while (i < destAddressString.size()) {
		j = 0;
		while (destAddressString[i] != '.' && i < destAddressString.size())
			numString[j++] = destAddressString[i++];

		this->destAddress[k] = (UCHAR)atoi(numString);
		memset(numString, 0, sizeof(numString));

		i++; // skip '.'
		k++;
	}
}

void Tcp::setProtocol(std::string & protocolString)
{
	this->protocol = (UCHAR)atoi(protocolString.c_str());
}