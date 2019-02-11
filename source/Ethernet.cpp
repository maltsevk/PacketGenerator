
#include "Ethernet.h"

ULONG Ethernet::calculateCrc32(UCHAR *buffer, ULONG len)
{
	ULONG crc_table[256];
	ULONG crc;

	// build crc32 table
	for (int i = 0; i < 256; i++)
	{
		crc = i;
		for (int j = 0; j < 8; j++)
			crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;

		crc_table[i] = crc;
	}

	crc = 0xFFFFFFFFUL;

	while (len--)
		crc = crc_table[(crc ^ *buffer++) & 0xFF] ^ (crc >> 8);

	return crc ^ 0xFFFFFFFFUL;
};

Ethernet::Ethernet()
{
	this->etherType = 0x0800;

	for (int i = 0; i < 6; i++) {
		this->destAddress[i] = 0;
		this->sourceAddress[i] = 0;
	}
}

void Ethernet::setDestMac(std::string & dest_addr)
{
	char hexString[3] = { 0 };
	char * p;

	for (size_t i = 0; i < dest_addr.size(); i += 3) {
		hexString[0] = dest_addr[i];
		hexString[1] = dest_addr[i + 1];
		this->destAddress[i / 3] = (char)strtol(hexString, &p, 16);
	}
}

void Ethernet::setSourceMac(std::string & source_addr)
{
	char hexString[3] = { 0 };
	char * p;

	for (size_t i = 0; i < source_addr.size(); i += 3) {
		hexString[0] = source_addr[i];
		hexString[1] = source_addr[i + 1];
		this->sourceAddress[i / 3] = (char)strtol(hexString, &p, 16);
	}
}

void Ethernet::setAdapterName(std::string & name)
{
	this->adapterName = name;
}

void Ethernet::setEthernetType(std::string & ether_type)
{
	this->etherType = (USHORT)strtol(ether_type.c_str(), NULL, 16);

	char buffer[10] = { 0 };
	buffer[0] = (char)(this->etherType >> 8);
	buffer[1] = (char)this->etherType;
}

void Ethernet::setData(std::string & data_)
{
	this->data = data_;
}

void Ethernet::clear()
{
	memset(this->destAddress, 0, 6);
	memset(this->sourceAddress, 0, 6);
	this->etherType = 0;
	this->data.clear();
	this->ethernetFrame.clear();
	this->adapterName.clear();
}

void Ethernet::buildFrame()
{
	this->ethernetFrame.clear();

	for (int i = 0; i < 6; i++)
		this->ethernetFrame.push_back(destAddress[i]);

	for (int i = 0; i < 6; i++)
		this->ethernetFrame.push_back(sourceAddress[i]);

	this->ethernetFrame += (char)(etherType >> 8);
	this->ethernetFrame += (char)etherType;
	this->ethernetFrame += data;

	//ULONG checksum = this->calculateCrc32((UCHAR *)this->ethernetFrame.c_str(), this->ethernetFrame.size());
	//this->ethernetFrame += (char)checksum >> 24;
	//this->ethernetFrame += (char)checksum >> 16;
	//this->ethernetFrame += (char)checksum >> 8;
	//this->ethernetFrame += (char)checksum;
}

std::string Ethernet::getFrame()
{
	this->buildFrame();
	return this->ethernetFrame;
}

int Ethernet::sendFrame()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];

	this->buildFrame();

	// open the adapter
	if ((fp = pcap_open_live(this->adapterName.c_str(), 65536, 1, 1000, errbuf)) == NULL) {
		MessageBox::Show("Unable to open the adapter", "Error message");
		return 1;
	}

	if (pcap_sendpacket(fp, (u_char *)this->ethernetFrame.c_str(), ethernetFrame.size()) != 0) {
		MessageBox::Show("Error sending the packet", "Error message");
		return 1;
	}

	pcap_close(fp);

	//FILE *file = fopen("C:\\Users\\1\\Desktop\\frame.bin", "wb");
	//fwrite(this->ethernetFrame.c_str(), 1, ethernetFrame.size(), file);
	//fclose(file);

	return 0;
}