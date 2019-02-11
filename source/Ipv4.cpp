
#include "Ipv4.h"


USHORT Ipv4::calculateChecksum(USHORT *buffer, int size)
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

Ipv4::Ipv4()
{
	this->versionAndIhl = 0;
	this->typeOfService = 0;
	this->totalLength = 0;
	this->identification = 0;
	this->flagsAndOffset = 0;
	this->timeToLive = 0;
	this->protocol = 0;
	this->headerChecksum = 0;
	this->data = "";

	for (int i = 0; i < 4; i++)
		this->sourceAddress[i] = this->destAddress[i] = 0;

	this->checksumFlag = true;
}

void Ipv4::setVersion(std::string & versionString)
{
	UCHAR version = (UCHAR)atoi(versionString.c_str());
	this->versionAndIhl &= ((version << 4) | 0x0F);
	this->versionAndIhl |= ((version << 4) & 0xF0);
}

void Ipv4::setInternetHeaderLength(std::string & headerLengthString)
{
	UCHAR headerLength = (UCHAR)atoi(headerLengthString.c_str());
	this->versionAndIhl &= (headerLength | 0xF0);
	this->versionAndIhl |= (headerLength & 0x0F);
}

void Ipv4::setPrecedence(std::string & precedenceString)
{
	UCHAR precedence = (UCHAR)atoi(precedenceString.c_str());
	this->typeOfService &= ((precedence << 5) | 0x70);
	this->typeOfService |= ((precedence << 5) & 0x1F);
}

void Ipv4::setDelayFlag()
{
	this->typeOfService |= 0x10;
}

void Ipv4::setReliabilityFlag()
{
	this->typeOfService |= 0x08;
}

void Ipv4::setThroughputFlag()
{
	this->typeOfService |= 0x04;
}

void Ipv4::setEcn(std::string & ecnString)
{
	UCHAR ecn = (UCHAR)atoi(ecnString.c_str());
	this->typeOfService &= (ecn | 0xFC);
	this->typeOfService |= (ecn & 0x03);
}

void Ipv4::setTotalLength(std::string & totalLengthString)
{
	this->totalLength = (USHORT)atoi(totalLengthString.c_str());
}

void Ipv4::setIdentification(std::string & identificationString)
{
	this->identification = (USHORT)atoi(identificationString.c_str());
}

void Ipv4::setReservedFlag()
{
	this->flagsAndOffset |= 0x8000;
}

void Ipv4::setDfFlag()
{
	this->flagsAndOffset |= 0x4000;
}

void Ipv4::setMfFlag()
{
	this->flagsAndOffset |= 0x2000;
}

void Ipv4::setFragmentOffset(std::string & offsetString)
{
	USHORT offset = (USHORT)atoi(offsetString.c_str());
	this->flagsAndOffset &= (offset | 0xE000);
	this->flagsAndOffset |= (offset & 0x1FFF);
}

void Ipv4::setTimeToLive(std::string & timeToLiveString)
{
	this->timeToLive = (UCHAR)atoi(timeToLiveString.c_str());
}

void Ipv4::setHeaderChecksum(std::string & headerChecksumString)
{
	this->headerChecksum = (USHORT)atoi(headerChecksumString.c_str());
}

void Ipv4::setProtocol(std::string & protocolString)
{
	this->protocol = (UCHAR)atoi(protocolString.c_str());
}

void Ipv4::setDestAddress(std::string & dest_addr)
{
	char numString[4] = { 0 };
	size_t i = 0, j, k = 0;

	while (i < dest_addr.size()) {
		j = 0;
		while (dest_addr[i] != '.' && i < dest_addr.size())
			numString[j++] = dest_addr[i++];

		this->destAddress[k] = (UCHAR)atoi(numString);
		memset(numString, 0, sizeof(numString));

		i++; // skip '.'
		k++;
	}
}

void Ipv4::setSourceAddress(std::string & source_addr)
{
	char numString[4] = { 0 };
	size_t i = 0, j, k = 0;

	while (i < source_addr.size()) {
		j = 0;
		while (source_addr[i] != '.' && i < source_addr.size())
			numString[j++] = source_addr[i++];

		this->sourceAddress[k] = (UCHAR)atoi(numString);
		memset(numString, 0, sizeof(numString));

		i++; // skip '.'
		k++;
	}
}

void Ipv4::setData(std::string & data_)
{
	this->data.clear();
	this->data.resize(data_.size());
	this->data = data_;
}

std::string Ipv4::getPacket()
{
	this->buildFrame();
	return this->packet;
}

void Ipv4::buildFrame()
{
	this->packet.clear();

	this->packet += this->versionAndIhl;
	this->packet += this->typeOfService;
	this->packet += (char)(this->totalLength >> 8);
	this->packet += (char)this->totalLength;
	this->packet += (char)(this->identification >> 8);
	this->packet += (char)this->identification;
	this->packet += (char)(this->flagsAndOffset >> 8);
	this->packet += (char)this->flagsAndOffset;
	this->packet += this->timeToLive;
	this->packet += this->protocol;
	this->packet += (char)(this->headerChecksum >> 8);
	this->packet += (char)this->headerChecksum;
	this->packet += this->sourceAddress[0];
	this->packet += this->sourceAddress[1];
	this->packet += this->sourceAddress[2];
	this->packet += this->sourceAddress[3];
	this->packet += this->destAddress[0];
	this->packet += this->destAddress[1];
	this->packet += this->destAddress[2];
	this->packet += this->destAddress[3];

	if (this->checksumFlag == true) {
		USHORT checksum = calculateChecksum((USHORT *)packet.c_str(), packet.size());

		// write the bytes in reverse order
		this->packet[10] = (char)checksum;
		this->packet[11] = (char)(checksum >> 8);
	}

	this->packet += this->data;
}

void Ipv4::clear()
{
	this->versionAndIhl = 0;
	this->typeOfService = 0;
	this->totalLength = 0;
	this->identification = 0;
	this->flagsAndOffset = 0;
	this->timeToLive = 0;
	this->protocol = 0;
	this->headerChecksum = 0;

	this->data.clear();
	this->packet.clear();
}

void Ipv4::setChecksumFlag(bool value)
{
	this->checksumFlag = value;
	if (value == true)
		this->headerChecksum = 0;
}