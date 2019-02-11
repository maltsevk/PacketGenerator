
#include "MyForm.h"

PacketGenerator::MyForm::MyForm(void)
{
	this->ethernetFrameQueue = new std::queue <Ethernet>;
	this->adaptersDescToInfo = new std::map <std::string, PacketGenerator::AdapterInfo>;

	InitializeComponent();
	initializeAdapterField();
}

PacketGenerator::MyForm::~MyForm()
{
	//delete this->ethernetFrameQueue;
	//delete this->adaptersDescToInfo;

	if (components)
		delete components;
}

int PacketGenerator::MyForm::addInterfacesListToAdapterBox()
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		MessageBox::Show("Error allocating memory needed to call GetAdaptersinfo", "Error message");
		return 1;
	}

	// make an initial call to GetAdaptersInfo to get the necessary size
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			MessageBox::Show("Error allocating memory needed to call GetAdaptersinfo", "Error message");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		while (pAdapter) {
			// save accordance of the description to name
			(*(this->adaptersDescToInfo))[std::string(pAdapter->Description)].name = std::string(pAdapter->AdapterName);

			// get adapter physical address
			std::string adapterAddress;
			char buffer[4] = { 0 };
			for (int i = 0; i < pAdapter->AddressLength; i++) {
				if (i == (pAdapter->AddressLength - 1))
					sprintf(buffer, "%.2X", (int)pAdapter->Address[i]);
				else
					sprintf(buffer, "%.2X:", (int)pAdapter->Address[i]);

				adapterAddress += buffer;
				memset(buffer, 0, 4);
			}

			// save adapter MAC, IP addressses and gateway IP 
			(*(this->adaptersDescToInfo))[std::string(pAdapter->Description)].macAddress = adapterAddress;
			(*(this->adaptersDescToInfo))[std::string(pAdapter->Description)].ipAddress = pAdapter->IpAddressList.IpAddress.String;
			(*(this->adaptersDescToInfo))[std::string(pAdapter->Description)].gatewayIpAddress = pAdapter->GatewayList.IpAddress.String;

			// add to list adapter description
			System::String^ tmpString = gcnew System::String(pAdapter->Description);
			this->comboBox1->Items->Add(tmpString);
			pAdapter = pAdapter->Next;
		}
	}

	if (pAdapterInfo)
		free(pAdapterInfo);

	return 0;
}

void PacketGenerator::MyForm::initializeAdapterField()
{
	addInterfacesListToAdapterBox();
	this->comboBox1->Text = this->comboBox1->Items[0]->ToString();
}

void PacketGenerator::MyForm::getEthernetDataFromFields(Ethernet & frame)
{
	std::string adapterDesc = (char *)(Marshal::StringToHGlobalAnsi(this->comboBox1->Text)).ToPointer();
	frame.setAdapterName("\\Device\\NPF_" + (*(this->adaptersDescToInfo))[adapterDesc].name);
	frame.setSourceMac(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox1->Text)).ToPointer()));
	frame.setDestMac(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox2->Text)).ToPointer()));
	frame.setEthernetType(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox3->Text)).ToPointer()));
}

void PacketGenerator::MyForm::getIpDataFromFields(Ipv4 & packet)
{
	// text fields
	packet.setVersion(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox10->Text)).ToPointer()));
	packet.setInternetHeaderLength(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox14->Text)).ToPointer()));
	packet.setPrecedence(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox8->Text)).ToPointer()));
	packet.setEcn(std::string((char *)(Marshal::StringToHGlobalAnsi(this->comboBox2->Text)).ToPointer()));
	packet.setTotalLength(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox11->Text)).ToPointer()));
	packet.setIdentification(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox13->Text)).ToPointer()));
	packet.setFragmentOffset(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox7->Text)).ToPointer()));
	packet.setTimeToLive(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox15->Text)).ToPointer()));
	packet.setProtocol(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox12->Text)).ToPointer()));
	packet.setSourceAddress(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox5->Text)).ToPointer()));
	packet.setDestAddress(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox6->Text)).ToPointer()));

	// flags
	if(this->checkBox1->Checked)
		packet.setDelayFlag();
	if (this->checkBox3->Checked)
		packet.setReliabilityFlag();
	if (this->checkBox2->Checked)
		packet.setThroughputFlag();
	if (this->checkBox5->Checked)
		packet.setReservedFlag();
	if (this->checkBox6->Checked)
		packet.setDfFlag();
	if (this->checkBox7->Checked)
		packet.setMfFlag();

	// checksum
	if (this->checkBox4->Checked) {
		packet.setChecksumFlag(true);
	}
	else {
		packet.setChecksumFlag(false);
		packet.setHeaderChecksum(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox9->Text)).ToPointer()));
	}
}

void PacketGenerator::MyForm::getTcpDataFromFields(Tcp & segment)
{
	// text fields
	segment.setSourcePort(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox16->Text)).ToPointer()));
	segment.setDestPort(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox17->Text)).ToPointer()));
	segment.setSequenceNumber(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox20->Text)).ToPointer()));
	segment.setAckNumber(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox21->Text)).ToPointer()));
	segment.setDataOffset(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox19->Text)).ToPointer()));
	segment.setReserved(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox24->Text)).ToPointer()));
	segment.setUrgentPointer(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox23->Text)).ToPointer()));
	segment.setWindowSize(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox22->Text)).ToPointer()));
	segment.setData(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox4->Text)).ToPointer()));

	// text fields for tcp pseudoheader
	segment.setSourceIpAddress(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox5->Text)).ToPointer()));
	segment.setDestIpAddress(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox6->Text)).ToPointer()));
	segment.setProtocol(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox12->Text)).ToPointer()));

	// flags
	if (this->checkBox9->Checked)
		segment.setNsFlag();
	if (this->checkBox10->Checked)
		segment.setCwrFlag();
	if (this->checkBox11->Checked)
		segment.setEceFlag();
	if (this->checkBox12->Checked)
		segment.setUrgFlag();
	if (this->checkBox13->Checked)
		segment.setAckFlag();
	if (this->checkBox14->Checked)
		segment.setPshFlag();
	if (this->checkBox15->Checked)
		segment.setRstFlag();
	if (this->checkBox16->Checked)
		segment.setSynFlag();
	if (this->checkBox17->Checked)
		segment.setFinFlag();

	// checksum
	if (this->checkBox8->Checked) {
		segment.setChecksumFlag(true);
	}
	else {
		segment.setChecksumFlag(false);
		segment.setChecksum(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox18->Text)).ToPointer()));
	}
}

void PacketGenerator::MyForm::getUdpDataFromFields(Udp & segment)
{
	// text fields
	segment.setSourcePort(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox25->Text)).ToPointer()));
	segment.setDestPort(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox26->Text)).ToPointer()));
	segment.setLength(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox27->Text)).ToPointer()));
	segment.setData(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox4->Text)).ToPointer()));

	// checksum
	if (this->checkBox18->Checked) {
		segment.setChecksumFlag(true);
	}
	else {
		segment.setChecksumFlag(false);
		segment.setChecksum(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox28->Text)).ToPointer()));
	}
}

void PacketGenerator::MyForm::getIcmpDataFromFields(Icmp & packet)
{
	// text fields
	packet.setType(std::string((char *)(Marshal::StringToHGlobalAnsi(this->comboBox3->Text)).ToPointer()));
	packet.setCode(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox30->Text)).ToPointer()));
	packet.setIdentifier(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox32->Text)).ToPointer()));
	packet.setSequenceNumber(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox31->Text)).ToPointer()));
	packet.setData(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox4->Text)).ToPointer()));

	// checksum
	if (this->checkBox19->Checked) {
		packet.setChecksumFlag(true);
	}
	else {
		packet.setChecksumFlag(false);
		packet.setChecksum(std::string((char *)(Marshal::StringToHGlobalAnsi(this->textBox29->Text)).ToPointer()));
	}
}

int PacketGenerator::MyForm::checkEthernetFields()
{
	Regex^ regex;
	MatchCollection^ matches;

	// check source MAC
	regex = gcnew Regex("([0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2}");
	matches = regex->Matches(this->textBox1->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect source MAC address.", "Error message");
		return 1;
	}

	// check destination MAC
	matches = regex->Matches(this->textBox2->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect source MAC address.", "Error message");
		return 1;
	}

	// check and set ethernet type
	regex = gcnew Regex("[0-9a-fA-F]{1,4}");
	matches = regex->Matches(this->textBox2->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect ethernet type.", "Error message");
		return 1;
	}

	return 0;
}

int PacketGenerator::MyForm::checkIpFields()
{
	Regex^ regex;
	MatchCollection^ matches;

	// check source ip address
	regex = gcnew Regex("([0-9]{1,3}[\\.]){3}[0-9]{1,3}");
	matches = regex->Matches(this->textBox5->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect source ip address.", "Error message");
		return 1;
	}

	// check destination ip address
	matches = regex->Matches(this->textBox6->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect destination ip address.", "Error message");
		return 1;
	}

	// check fragment offset
	regex = gcnew Regex("[0-9]{1,4}");
	matches = regex->Matches(this->textBox7->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect fragment offset.", "Error message");
		return 1;
	}

	// check version
	regex = gcnew Regex("[0-9]{1,2}");
	matches = regex->Matches(this->textBox10->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect version.", "Error message");
		return 1;
	}

	// check protocol
	regex = gcnew Regex("[0-9]{1,5}");
	matches = regex->Matches(this->textBox12->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect protocol.", "Error message");
		return 1;
	}

	// check identification
	matches = regex->Matches(this->textBox13->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect identification.", "Error message");
		return 1;
	}

	// check time to live
	regex = gcnew Regex("[0-9]{1,3}");
	matches = regex->Matches(this->textBox15->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect time to live.", "Error message");
		return 1;
	}

	// check precedence
	regex = gcnew Regex("[0-9]{1}");
	matches = regex->Matches(this->textBox8->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect precedence.", "Error message");
		return 1;
	}

	// check TL
	regex = gcnew Regex("[0-9]{1,5}");
	matches = regex->Matches(this->textBox11->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect total length.", "Error message");
		return 1;
	}

	// check IHL
	regex = gcnew Regex("[0-9]{1,2}");
	matches = regex->Matches(this->textBox14->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect internet header length.", "Error message");
		return 1;
	}

	// check checksum
	if (this->checkBox4->Checked == false) {
		regex = gcnew Regex("[0-9]{1,5}");
		matches = regex->Matches(this->textBox9->Text);
		if (matches->Count == 0) {
			MessageBox::Show("Incorrect checksum.", "Error message");
			return 1;
		}
	}

	return 0;
}

int PacketGenerator::MyForm::checkTcpFields()
{
	Regex^ regex;
	MatchCollection^ matches;

	regex = gcnew Regex("[0-9]{1,5}");
	matches = regex->Matches(this->textBox16->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect source port.", "Error message");
		return 1;
	}

	matches = regex->Matches(this->textBox17->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect destination port.", "Error message");
		return 1;
	}

	matches = regex->Matches(this->textBox19->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect data offset.", "Error message");
		return 1;
	}

	// check checksum
	if (this->checkBox8->Checked == false) {
		matches = regex->Matches(this->textBox18->Text);
		if (matches->Count == 0) {
			MessageBox::Show("Incorrect checksum.", "Error message");
			return 1;
		}
	}

	// sequence number
	regex = gcnew Regex("[0-9]{1,10}");
	matches = regex->Matches(this->textBox20->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect sequence number.", "Error message");
		return 1;
	}

	// ack number
	matches = regex->Matches(this->textBox21->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect ack number.", "Error message");
		return 1;
	}

	// window size
	regex = gcnew Regex("[0-9]{1,5}");
	matches = regex->Matches(this->textBox22->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect window size.", "Error message");
		return 1;
	}

	// urgent pointer
	matches = regex->Matches(this->textBox23->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect urgent pointer.", "Error message");
		return 1;
	}

	// reserved
	regex = gcnew Regex("[0-9]{1}");
	matches = regex->Matches(this->textBox24->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect reserved.", "Error message");
		return 1;
	}

	return 0;
}

int PacketGenerator::MyForm::checkUdpFields()
{
	Regex^ regex;
	MatchCollection^ matches;

	regex = gcnew Regex("[0-9]{1,5}");
	matches = regex->Matches(this->textBox25->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect source port.", "Error message");
		return 1;
	}

	matches = regex->Matches(this->textBox26->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect destination port.", "Error message");
		return 1;
	}

	matches = regex->Matches(this->textBox27->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect length.", "Error message");
		return 1;
	}

	// check checksum
	if (this->checkBox18->Checked == false) {
		matches = regex->Matches(this->textBox28->Text);
		if (matches->Count == 0) {
			MessageBox::Show("Incorrect checksum.", "Error message");
			return 1;
		}
	}

	return 0;
}

int PacketGenerator::MyForm::checkIcmpFields()
{
	Regex^ regex;
	MatchCollection^ matches;

	// check echo type
	if (this->comboBox3->Text != "0 (Echo reply)" && 
		this->comboBox3->Text != "8 (Echo request)") {
		MessageBox::Show("Incorrect ECHO type.", "Error message");
		return 1;
	}

	regex = gcnew Regex("[0-9]{1,5}");
	matches = regex->Matches(this->textBox31->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect sequence number.", "Error message");
		return 1;
	}

	matches = regex->Matches(this->textBox30->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect code.", "Error message");
		return 1;
	}

	matches = regex->Matches(this->textBox32->Text);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect identifier.", "Error message");
		return 1;
	}

	// check checksum
	if (this->checkBox19->Checked == false) {
		matches = regex->Matches(this->textBox29->Text);
		if (matches->Count == 0) {
			MessageBox::Show("Incorrect checksum.", "Error message");
			return 1;
		}
	}

	return 0;
}

int PacketGenerator::MyForm::checkIpAddress(String ^ ipAddress)
{
	Regex^ regex;
	MatchCollection^ matches;

	regex = gcnew Regex("([0-9]{1,3}[\\.]){3}[0-9]{1,3}");
	matches = regex->Matches(ipAddress);
	if (matches->Count == 0) {
		MessageBox::Show("Incorrect ip address.", "Error message");
		return 1;
	}

	return 0;
}

int PacketGenerator::MyForm::sendArpRequest(std::string & ipAddress)
{
	Ethernet frame;
	Arp packet;

	// fill ethernet fields
	std::string adapterDesc = (char *)(Marshal::StringToHGlobalAnsi(this->comboBox1->Text)).ToPointer();
	frame.setAdapterName("\\Device\\NPF_" + (*(this->adaptersDescToInfo))[adapterDesc].name);
	frame.setSourceMac((*(this->adaptersDescToInfo))[adapterDesc].macAddress);
	frame.setDestMac(std::string("FF:FF:FF:FF:FF:FF"));	// broadcast
	frame.setEthernetType(std::string("0806"));			// type: ARP (0x0806)

	// fill arp fields
	packet.setSenderMacAddress((*(this->adaptersDescToInfo))[adapterDesc].macAddress);
	packet.setSenderIpAddress((*(this->adaptersDescToInfo))[adapterDesc].ipAddress);
	packet.setTargetMacAddress(std::string("00:00:00:00:00:00"));
	packet.setTargetIpAddress(ipAddress);

	frame.setData(packet.getPacket());
	frame.sendFrame();

	return 0;
}

bool PacketGenerator::MyForm::compareIpAddresses(std::string & firstAddress, char * pSecondAddress)
{
	std::string secondAddress;

	for (int i = 0; i < 4; i++) {
		secondAddress += std::to_string((UCHAR)pSecondAddress[i]);
		if(i < 3)
			secondAddress += ".";
	}

	return (firstAddress == secondAddress ? true : false);
}

int PacketGenerator::MyForm::getAddressViaArp(std::string & adapterName, std::string & physAddress, std::string & ipAddress)
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	int count = 0;

	// open the adapter
	if ((fp = pcap_open_live(adapterName.c_str(), 65536, 1, 1000, errbuf)) == NULL) {
		MessageBox::Show("Unable to open the adapter", "Error message");
		return 1;
	}

	// send arp request to get MAC address
	sendArpRequest(ipAddress);

	// retrieve the packets
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {
		
		// if timeout elapsed
		if (res == 0) {

			if (count == 10) {
				MessageBox::Show("Can not get ARP reply.", "Error message");
				pcap_close(fp);
				return 1;
			}

			count++;
			continue;
		}

		// if it is arp reply and required ip
		if (pkt_data[12] == 0x08 && pkt_data[13] == 0x06 &&
			pkt_data[20] == 0x00 && pkt_data[21] == 0x02 &&
			compareIpAddresses(ipAddress, (char *)(pkt_data + 28))) {
			char buffer[4] = { 0 };
			for (int i = 0; i < 6; i++) {
				if (i == 5)
					sprintf(buffer, "%.2X", pkt_data[22 + i]);
				else
					sprintf(buffer, "%.2X:", pkt_data[22 + i]);

				physAddress += buffer;
				memset(buffer, 0, 4);
			}

			break;
		}
	}

	pcap_close(fp);

	if (res == -1) {
		MessageBox::Show("Error reading the packets", "Error message");
		return 1;
	}

	return 0;
}

System::Void PacketGenerator::MyForm::checkBox8_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
{
	this->textBox18->Enabled = this->checkBox8->Checked ? false : true;
}

System::Void PacketGenerator::MyForm::checkBox4_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
{
	this->textBox9->Enabled = this->checkBox4->Checked ? false : true;
}

System::Void PacketGenerator::MyForm::checkBox18_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
{
	this->textBox28->Enabled = this->checkBox18->Checked ? false : true;
}

System::Void PacketGenerator::MyForm::checkBox19_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
{
	this->textBox29->Enabled = this->checkBox19->Checked ? false : true;
}

System::Void PacketGenerator::MyForm::checkBox20_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
{
	if (checkBox20->Checked) {

		std::string adapterDesc = (char *)(Marshal::StringToHGlobalAnsi(this->comboBox1->Text)).ToPointer();
		std::string adapterName = "\\Device\\NPF_" + (*(this->adaptersDescToInfo))[adapterDesc].name;
		std::string sourceIpAddress = (char *)(Marshal::StringToHGlobalAnsi(this->textBox5->Text)).ToPointer();
		std::string sourceMac;

		// if adapter ip address and entered source ip address matched =>
		// => just set adapter mac
		if ((*(this->adaptersDescToInfo))[adapterDesc].ipAddress == sourceIpAddress) {
			sourceMac = (*(this->adaptersDescToInfo))[adapterDesc].macAddress;
		}
		else {
			// determine source MAC by source IP via ARP
			if (getAddressViaArp(adapterName, sourceMac, sourceIpAddress) > 0) {
				checkBox20->Checked = false;
				return;
			}
		}

		System::String^ destMacString = gcnew System::String(sourceMac.c_str());
		this->textBox1->Text = destMacString;
		this->textBox1->Enabled = false;
	}
	else {
		this->textBox1->Enabled = true;
	}
}

System::Void PacketGenerator::MyForm::checkBox21_CheckedChanged(System::Object^  sender, System::EventArgs^  e)
{
	if (checkBox21->Checked) {

		std::string adapterDesc = (char *)(Marshal::StringToHGlobalAnsi(this->comboBox1->Text)).ToPointer();
		std::string adapterName = "\\Device\\NPF_" + (*(this->adaptersDescToInfo))[adapterDesc].name;
		std::string destIpAddress = (*(this->adaptersDescToInfo))[adapterDesc].gatewayIpAddress;
		std::string destMac;

		// determine dest MAC by dest IP via ARP
		if (getAddressViaArp(adapterName, destMac, destIpAddress) > 0) {
			checkBox21->Checked = false;
			return;
		}

		System::String^ destMacString = gcnew System::String(destMac.c_str());
		this->textBox2->Text = destMacString;
		this->textBox2->Enabled = false;
	}
	else {
		this->textBox2->Enabled = true;
	}
}

System::Void PacketGenerator::MyForm::button2_Click(System::Object^  sender, System::EventArgs^  e)
{
	Ethernet frame;
	Ipv4 packet;

	// check all fields for correctness
	if (checkEthernetFields() > 0 || checkIpFields() > 0)
		return;

	getEthernetDataFromFields(frame);
	getIpDataFromFields(packet);

	if (this->tabControl1->SelectedIndex == 0) {
		// TCP
		if (checkTcpFields() > 0)
			return;

		Tcp segment;
		getTcpDataFromFields(segment);
		packet.setData(segment.getSegment());
	}
	else if (this->tabControl1->SelectedIndex == 1) {
		// UDP
		if (checkUdpFields() > 0)
			return;

		Udp segment;
		getUdpDataFromFields(segment);
		packet.setData(segment.getSegment());
	}
	else {
		// ICMP
		if (checkIcmpFields() > 0)
			return;

		Icmp icmpPacket;
		getIcmpDataFromFields(icmpPacket);
		packet.setData(icmpPacket.getPacket());
	}

	frame.setData(packet.getPacket());
	ethernetFrameQueue->push(frame);
}

System::Void PacketGenerator::MyForm::button3_Click(System::Object^  sender, System::EventArgs^  e)
{
	while (!ethernetFrameQueue->empty()) {
		ethernetFrameQueue->front().sendFrame();
		ethernetFrameQueue->pop();
	}

	MessageBox::Show("All messages from the queue have been sent.", "Success message");
}

void PacketGenerator::MyForm::InitializeComponent(void)
{
	this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
	this->groupBox4 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox3 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox2 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox20 = (gcnew System::Windows::Forms::CheckBox());
	this->textBox1 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox3 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox21 = (gcnew System::Windows::Forms::CheckBox());
	this->textBox2 = (gcnew System::Windows::Forms::TextBox());
	this->button2 = (gcnew System::Windows::Forms::Button());
	this->button3 = (gcnew System::Windows::Forms::Button());
	this->groupBox5 = (gcnew System::Windows::Forms::GroupBox());
	this->comboBox1 = (gcnew System::Windows::Forms::ComboBox());
	this->groupBox6 = (gcnew System::Windows::Forms::GroupBox());
	this->groupBox20 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox14 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox21 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox15 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox19 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox13 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox17 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox11 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox16 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox10 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox18 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox12 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox15 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox7 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox6 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox5 = (gcnew System::Windows::Forms::CheckBox());
	this->groupBox14 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox4 = (gcnew System::Windows::Forms::CheckBox());
	this->textBox9 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox11 = (gcnew System::Windows::Forms::GroupBox());
	this->groupBox13 = (gcnew System::Windows::Forms::GroupBox());
	this->comboBox2 = (gcnew System::Windows::Forms::ComboBox());
	this->groupBox12 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox8 = (gcnew System::Windows::Forms::TextBox());
	this->checkBox3 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox2 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox1 = (gcnew System::Windows::Forms::CheckBox());
	this->groupBox10 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox7 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox9 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox6 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox8 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox5 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox7 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox4 = (gcnew System::Windows::Forms::TextBox());
	this->tabControl1 = (gcnew System::Windows::Forms::TabControl());
	this->tabPage1 = (gcnew System::Windows::Forms::TabPage());
	this->groupBox31 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox24 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox30 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox23 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox29 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox22 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox28 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox17 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox16 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox15 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox14 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox13 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox12 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox11 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox10 = (gcnew System::Windows::Forms::CheckBox());
	this->checkBox9 = (gcnew System::Windows::Forms::CheckBox());
	this->groupBox27 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox21 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox26 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox20 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox25 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox19 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox24 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox8 = (gcnew System::Windows::Forms::CheckBox());
	this->textBox18 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox23 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox17 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox22 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox16 = (gcnew System::Windows::Forms::TextBox());
	this->tabPage2 = (gcnew System::Windows::Forms::TabPage());
	this->groupBox35 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox18 = (gcnew System::Windows::Forms::CheckBox());
	this->textBox28 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox34 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox27 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox33 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox26 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox32 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox25 = (gcnew System::Windows::Forms::TextBox());
	this->tabPage3 = (gcnew System::Windows::Forms::TabPage());
	this->groupBox40 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox32 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox39 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox31 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox38 = (gcnew System::Windows::Forms::GroupBox());
	this->comboBox3 = (gcnew System::Windows::Forms::ComboBox());
	this->groupBox37 = (gcnew System::Windows::Forms::GroupBox());
	this->textBox30 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox36 = (gcnew System::Windows::Forms::GroupBox());
	this->checkBox19 = (gcnew System::Windows::Forms::CheckBox());
	this->textBox29 = (gcnew System::Windows::Forms::TextBox());
	this->groupBox1->SuspendLayout();
	this->groupBox4->SuspendLayout();
	this->groupBox2->SuspendLayout();
	this->groupBox3->SuspendLayout();
	this->groupBox5->SuspendLayout();
	this->groupBox6->SuspendLayout();
	this->groupBox20->SuspendLayout();
	this->groupBox21->SuspendLayout();
	this->groupBox19->SuspendLayout();
	this->groupBox17->SuspendLayout();
	this->groupBox16->SuspendLayout();
	this->groupBox18->SuspendLayout();
	this->groupBox15->SuspendLayout();
	this->groupBox14->SuspendLayout();
	this->groupBox11->SuspendLayout();
	this->groupBox13->SuspendLayout();
	this->groupBox12->SuspendLayout();
	this->groupBox10->SuspendLayout();
	this->groupBox9->SuspendLayout();
	this->groupBox8->SuspendLayout();
	this->groupBox7->SuspendLayout();
	this->tabControl1->SuspendLayout();
	this->tabPage1->SuspendLayout();
	this->groupBox31->SuspendLayout();
	this->groupBox30->SuspendLayout();
	this->groupBox29->SuspendLayout();
	this->groupBox28->SuspendLayout();
	this->groupBox27->SuspendLayout();
	this->groupBox26->SuspendLayout();
	this->groupBox25->SuspendLayout();
	this->groupBox24->SuspendLayout();
	this->groupBox23->SuspendLayout();
	this->groupBox22->SuspendLayout();
	this->tabPage2->SuspendLayout();
	this->groupBox35->SuspendLayout();
	this->groupBox34->SuspendLayout();
	this->groupBox33->SuspendLayout();
	this->groupBox32->SuspendLayout();
	this->tabPage3->SuspendLayout();
	this->groupBox40->SuspendLayout();
	this->groupBox39->SuspendLayout();
	this->groupBox38->SuspendLayout();
	this->groupBox37->SuspendLayout();
	this->groupBox36->SuspendLayout();
	this->SuspendLayout();
	// 
	// groupBox1
	// 
	this->groupBox1->Controls->Add(this->groupBox4);
	this->groupBox1->Controls->Add(this->groupBox2);
	this->groupBox1->Controls->Add(this->groupBox3);
	this->groupBox1->Location = System::Drawing::Point(12, 74);
	this->groupBox1->Name = L"groupBox1";
	this->groupBox1->Size = System::Drawing::Size(509, 79);
	this->groupBox1->TabIndex = 2;
	this->groupBox1->TabStop = false;
	this->groupBox1->Text = L"Ethernet";
	// 
	// groupBox4
	// 
	this->groupBox4->Controls->Add(this->textBox3);
	this->groupBox4->Location = System::Drawing::Point(410, 21);
	this->groupBox4->Name = L"groupBox4";
	this->groupBox4->Size = System::Drawing::Size(93, 52);
	this->groupBox4->TabIndex = 6;
	this->groupBox4->TabStop = false;
	this->groupBox4->Text = L"Type (hex)";
	// 
	// textBox3
	// 
	this->textBox3->Location = System::Drawing::Point(6, 21);
	this->textBox3->Name = L"textBox3";
	this->textBox3->Size = System::Drawing::Size(81, 22);
	this->textBox3->TabIndex = 1;
	this->textBox3->Text = L"0800";
	// 
	// groupBox2
	// 
	this->groupBox2->Controls->Add(this->checkBox20);
	this->groupBox2->Controls->Add(this->textBox1);
	this->groupBox2->Location = System::Drawing::Point(6, 21);
	this->groupBox2->Name = L"groupBox2";
	this->groupBox2->Size = System::Drawing::Size(196, 52);
	this->groupBox2->TabIndex = 0;
	this->groupBox2->TabStop = false;
	this->groupBox2->Text = L"Source MAC";
	// 
	// checkBox20
	// 
	this->checkBox20->AutoSize = true;
	this->checkBox20->Location = System::Drawing::Point(132, 21);
	this->checkBox20->Name = L"checkBox20";
	this->checkBox20->Size = System::Drawing::Size(58, 21);
	this->checkBox20->TabIndex = 2;
	this->checkBox20->Text = L"auto";
	this->checkBox20->UseVisualStyleBackColor = true;
	this->checkBox20->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox20_CheckedChanged);
	// 
	// textBox1
	// 
	this->textBox1->Location = System::Drawing::Point(6, 21);
	this->textBox1->Name = L"textBox1";
	this->textBox1->Size = System::Drawing::Size(120, 22);
	this->textBox1->TabIndex = 0;
	this->textBox1->Text = L"A0:C5:89:83:EE:FB";
	// 
	// groupBox3
	// 
	this->groupBox3->Controls->Add(this->checkBox21);
	this->groupBox3->Controls->Add(this->textBox2);
	this->groupBox3->Location = System::Drawing::Point(208, 21);
	this->groupBox3->Name = L"groupBox3";
	this->groupBox3->Size = System::Drawing::Size(196, 52);
	this->groupBox3->TabIndex = 6;
	this->groupBox3->TabStop = false;
	this->groupBox3->Text = L"Destination MAC";
	// 
	// checkBox21
	// 
	this->checkBox21->AutoSize = true;
	this->checkBox21->Location = System::Drawing::Point(132, 21);
	this->checkBox21->Name = L"checkBox21";
	this->checkBox21->Size = System::Drawing::Size(58, 21);
	this->checkBox21->TabIndex = 2;
	this->checkBox21->Text = L"auto";
	this->checkBox21->UseVisualStyleBackColor = true;
	this->checkBox21->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox21_CheckedChanged);
	// 
	// textBox2
	// 
	this->textBox2->Location = System::Drawing::Point(6, 21);
	this->textBox2->Name = L"textBox2";
	this->textBox2->Size = System::Drawing::Size(120, 22);
	this->textBox2->TabIndex = 0;
	this->textBox2->Text = L"6C:19:8F:FD:0D:20";
	// 
	// button2
	// 
	this->button2->Location = System::Drawing::Point(285, 696);
	this->button2->Name = L"button2";
	this->button2->Size = System::Drawing::Size(119, 28);
	this->button2->TabIndex = 4;
	this->button2->Text = L"Add to queue";
	this->button2->UseVisualStyleBackColor = true;
	this->button2->Click += gcnew System::EventHandler(this, &MyForm::button2_Click);
	// 
	// button3
	// 
	this->button3->Location = System::Drawing::Point(410, 696);
	this->button3->Name = L"button3";
	this->button3->Size = System::Drawing::Size(109, 28);
	this->button3->TabIndex = 5;
	this->button3->Text = L"Send queue";
	this->button3->UseVisualStyleBackColor = true;
	this->button3->Click += gcnew System::EventHandler(this, &MyForm::button3_Click);
	// 
	// groupBox5
	// 
	this->groupBox5->Controls->Add(this->comboBox1);
	this->groupBox5->Location = System::Drawing::Point(12, 12);
	this->groupBox5->Name = L"groupBox5";
	this->groupBox5->Size = System::Drawing::Size(509, 56);
	this->groupBox5->TabIndex = 6;
	this->groupBox5->TabStop = false;
	this->groupBox5->Text = L"Network Adapter";
	// 
	// comboBox1
	// 
	this->comboBox1->FormattingEnabled = true;
	this->comboBox1->Location = System::Drawing::Point(6, 25);
	this->comboBox1->Name = L"comboBox1";
	this->comboBox1->Size = System::Drawing::Size(497, 24);
	this->comboBox1->TabIndex = 7;
	// 
	// groupBox6
	// 
	this->groupBox6->Controls->Add(this->groupBox20);
	this->groupBox6->Controls->Add(this->groupBox21);
	this->groupBox6->Controls->Add(this->groupBox19);
	this->groupBox6->Controls->Add(this->groupBox17);
	this->groupBox6->Controls->Add(this->groupBox16);
	this->groupBox6->Controls->Add(this->groupBox18);
	this->groupBox6->Controls->Add(this->groupBox15);
	this->groupBox6->Controls->Add(this->groupBox14);
	this->groupBox6->Controls->Add(this->groupBox11);
	this->groupBox6->Controls->Add(this->groupBox10);
	this->groupBox6->Controls->Add(this->groupBox9);
	this->groupBox6->Controls->Add(this->groupBox8);
	this->groupBox6->Location = System::Drawing::Point(12, 159);
	this->groupBox6->Name = L"groupBox6";
	this->groupBox6->Size = System::Drawing::Size(509, 262);
	this->groupBox6->TabIndex = 7;
	this->groupBox6->TabStop = false;
	this->groupBox6->Text = L"IPv4";
	// 
	// groupBox20
	// 
	this->groupBox20->Controls->Add(this->textBox14);
	this->groupBox20->Location = System::Drawing::Point(331, 203);
	this->groupBox20->Name = L"groupBox20";
	this->groupBox20->Size = System::Drawing::Size(55, 52);
	this->groupBox20->TabIndex = 11;
	this->groupBox20->TabStop = false;
	this->groupBox20->Text = L"IHL";
	// 
	// textBox14
	// 
	this->textBox14->Location = System::Drawing::Point(6, 21);
	this->textBox14->Name = L"textBox14";
	this->textBox14->Size = System::Drawing::Size(43, 22);
	this->textBox14->TabIndex = 1;
	this->textBox14->Text = L"5";
	// 
	// groupBox21
	// 
	this->groupBox21->Controls->Add(this->textBox15);
	this->groupBox21->Location = System::Drawing::Point(246, 87);
	this->groupBox21->Name = L"groupBox21";
	this->groupBox21->Size = System::Drawing::Size(74, 52);
	this->groupBox21->TabIndex = 10;
	this->groupBox21->TabStop = false;
	this->groupBox21->Text = L"TTL";
	// 
	// textBox15
	// 
	this->textBox15->Location = System::Drawing::Point(6, 21);
	this->textBox15->Name = L"textBox15";
	this->textBox15->Size = System::Drawing::Size(62, 22);
	this->textBox15->TabIndex = 1;
	this->textBox15->Text = L"128";
	// 
	// groupBox19
	// 
	this->groupBox19->Controls->Add(this->textBox13);
	this->groupBox19->Location = System::Drawing::Point(178, 87);
	this->groupBox19->Name = L"groupBox19";
	this->groupBox19->Size = System::Drawing::Size(62, 52);
	this->groupBox19->TabIndex = 10;
	this->groupBox19->TabStop = false;
	this->groupBox19->Text = L"ID";
	// 
	// textBox13
	// 
	this->textBox13->Location = System::Drawing::Point(6, 21);
	this->textBox13->Name = L"textBox13";
	this->textBox13->Size = System::Drawing::Size(50, 22);
	this->textBox13->TabIndex = 1;
	this->textBox13->Text = L"30486";
	// 
	// groupBox17
	// 
	this->groupBox17->Controls->Add(this->textBox11);
	this->groupBox17->Location = System::Drawing::Point(331, 145);
	this->groupBox17->Name = L"groupBox17";
	this->groupBox17->Size = System::Drawing::Size(55, 52);
	this->groupBox17->TabIndex = 10;
	this->groupBox17->TabStop = false;
	this->groupBox17->Text = L"TL";
	// 
	// textBox11
	// 
	this->textBox11->Location = System::Drawing::Point(6, 21);
	this->textBox11->Name = L"textBox11";
	this->textBox11->Size = System::Drawing::Size(43, 22);
	this->textBox11->TabIndex = 1;
	this->textBox11->Text = L"28";
	// 
	// groupBox16
	// 
	this->groupBox16->Controls->Add(this->textBox10);
	this->groupBox16->Location = System::Drawing::Point(6, 87);
	this->groupBox16->Name = L"groupBox16";
	this->groupBox16->Size = System::Drawing::Size(74, 52);
	this->groupBox16->TabIndex = 10;
	this->groupBox16->TabStop = false;
	this->groupBox16->Text = L"Version";
	// 
	// textBox10
	// 
	this->textBox10->Location = System::Drawing::Point(6, 21);
	this->textBox10->Name = L"textBox10";
	this->textBox10->Size = System::Drawing::Size(62, 22);
	this->textBox10->TabIndex = 1;
	this->textBox10->Text = L"4";
	// 
	// groupBox18
	// 
	this->groupBox18->Controls->Add(this->textBox12);
	this->groupBox18->Location = System::Drawing::Point(86, 87);
	this->groupBox18->Name = L"groupBox18";
	this->groupBox18->Size = System::Drawing::Size(86, 52);
	this->groupBox18->TabIndex = 9;
	this->groupBox18->TabStop = false;
	this->groupBox18->Text = L"Protocol";
	// 
	// textBox12
	// 
	this->textBox12->Location = System::Drawing::Point(6, 21);
	this->textBox12->Name = L"textBox12";
	this->textBox12->Size = System::Drawing::Size(74, 22);
	this->textBox12->TabIndex = 1;
	this->textBox12->Text = L"1";
	// 
	// groupBox15
	// 
	this->groupBox15->Controls->Add(this->checkBox7);
	this->groupBox15->Controls->Add(this->checkBox6);
	this->groupBox15->Controls->Add(this->checkBox5);
	this->groupBox15->Location = System::Drawing::Point(392, 145);
	this->groupBox15->Name = L"groupBox15";
	this->groupBox15->Size = System::Drawing::Size(110, 110);
	this->groupBox15->TabIndex = 6;
	this->groupBox15->TabStop = false;
	this->groupBox15->Text = L"Flags";
	// 
	// checkBox7
	// 
	this->checkBox7->AutoSize = true;
	this->checkBox7->Location = System::Drawing::Point(6, 83);
	this->checkBox7->Name = L"checkBox7";
	this->checkBox7->Size = System::Drawing::Size(49, 21);
	this->checkBox7->TabIndex = 2;
	this->checkBox7->Text = L"MF";
	this->checkBox7->UseVisualStyleBackColor = true;
	// 
	// checkBox6
	// 
	this->checkBox6->AutoSize = true;
	this->checkBox6->Location = System::Drawing::Point(6, 56);
	this->checkBox6->Name = L"checkBox6";
	this->checkBox6->Size = System::Drawing::Size(48, 21);
	this->checkBox6->TabIndex = 1;
	this->checkBox6->Text = L"DF";
	this->checkBox6->UseVisualStyleBackColor = true;
	// 
	// checkBox5
	// 
	this->checkBox5->AutoSize = true;
	this->checkBox5->Location = System::Drawing::Point(6, 29);
	this->checkBox5->Name = L"checkBox5";
	this->checkBox5->Size = System::Drawing::Size(91, 21);
	this->checkBox5->TabIndex = 0;
	this->checkBox5->Text = L"Reserved";
	this->checkBox5->UseVisualStyleBackColor = true;
	// 
	// groupBox14
	// 
	this->groupBox14->Controls->Add(this->checkBox4);
	this->groupBox14->Controls->Add(this->textBox9);
	this->groupBox14->Location = System::Drawing::Point(331, 87);
	this->groupBox14->Name = L"groupBox14";
	this->groupBox14->Size = System::Drawing::Size(172, 52);
	this->groupBox14->TabIndex = 5;
	this->groupBox14->TabStop = false;
	this->groupBox14->Text = L"Checksum";
	// 
	// checkBox4
	// 
	this->checkBox4->AutoSize = true;
	this->checkBox4->Checked = true;
	this->checkBox4->CheckState = System::Windows::Forms::CheckState::Checked;
	this->checkBox4->Location = System::Drawing::Point(108, 21);
	this->checkBox4->Name = L"checkBox4";
	this->checkBox4->Size = System::Drawing::Size(58, 21);
	this->checkBox4->TabIndex = 1;
	this->checkBox4->Text = L"auto";
	this->checkBox4->UseVisualStyleBackColor = true;
	this->checkBox4->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox4_CheckedChanged);
	// 
	// textBox9
	// 
	this->textBox9->Enabled = false;
	this->textBox9->Location = System::Drawing::Point(6, 21);
	this->textBox9->Name = L"textBox9";
	this->textBox9->Size = System::Drawing::Size(96, 22);
	this->textBox9->TabIndex = 0;
	this->textBox9->Text = L"65535";
	// 
	// groupBox11
	// 
	this->groupBox11->Controls->Add(this->groupBox13);
	this->groupBox11->Controls->Add(this->groupBox12);
	this->groupBox11->Controls->Add(this->checkBox3);
	this->groupBox11->Controls->Add(this->checkBox2);
	this->groupBox11->Controls->Add(this->checkBox1);
	this->groupBox11->Location = System::Drawing::Point(6, 145);
	this->groupBox11->Name = L"groupBox11";
	this->groupBox11->Size = System::Drawing::Size(314, 110);
	this->groupBox11->TabIndex = 4;
	this->groupBox11->TabStop = false;
	this->groupBox11->Text = L"Type of service";
	// 
	// groupBox13
	// 
	this->groupBox13->Controls->Add(this->comboBox2);
	this->groupBox13->Location = System::Drawing::Point(125, 21);
	this->groupBox13->Name = L"groupBox13";
	this->groupBox13->Size = System::Drawing::Size(71, 49);
	this->groupBox13->TabIndex = 4;
	this->groupBox13->TabStop = false;
	this->groupBox13->Text = L"ECN";
	// 
	// comboBox2
	// 
	this->comboBox2->FormattingEnabled = true;
	this->comboBox2->Items->AddRange(gcnew cli::array< System::Object^  >(4) { L"0", L"1", L"2", L"3" });
	this->comboBox2->Location = System::Drawing::Point(6, 19);
	this->comboBox2->Name = L"comboBox2";
	this->comboBox2->Size = System::Drawing::Size(52, 24);
	this->comboBox2->TabIndex = 5;
	this->comboBox2->Text = L"0";
	// 
	// groupBox12
	// 
	this->groupBox12->Controls->Add(this->textBox8);
	this->groupBox12->Location = System::Drawing::Point(9, 21);
	this->groupBox12->Name = L"groupBox12";
	this->groupBox12->Size = System::Drawing::Size(110, 49);
	this->groupBox12->TabIndex = 3;
	this->groupBox12->TabStop = false;
	this->groupBox12->Text = L"Precedence";
	// 
	// textBox8
	// 
	this->textBox8->Location = System::Drawing::Point(6, 19);
	this->textBox8->Name = L"textBox8";
	this->textBox8->Size = System::Drawing::Size(98, 22);
	this->textBox8->TabIndex = 0;
	this->textBox8->Text = L"0";
	// 
	// checkBox3
	// 
	this->checkBox3->AutoSize = true;
	this->checkBox3->Location = System::Drawing::Point(202, 48);
	this->checkBox3->Name = L"checkBox3";
	this->checkBox3->Size = System::Drawing::Size(90, 21);
	this->checkBox3->TabIndex = 2;
	this->checkBox3->Text = L"Reliability";
	this->checkBox3->UseVisualStyleBackColor = true;
	// 
	// checkBox2
	// 
	this->checkBox2->AutoSize = true;
	this->checkBox2->Location = System::Drawing::Point(202, 75);
	this->checkBox2->Name = L"checkBox2";
	this->checkBox2->Size = System::Drawing::Size(104, 21);
	this->checkBox2->TabIndex = 1;
	this->checkBox2->Text = L"Throughput";
	this->checkBox2->UseVisualStyleBackColor = true;
	// 
	// checkBox1
	// 
	this->checkBox1->AutoSize = true;
	this->checkBox1->Location = System::Drawing::Point(202, 21);
	this->checkBox1->Name = L"checkBox1";
	this->checkBox1->Size = System::Drawing::Size(66, 21);
	this->checkBox1->TabIndex = 0;
	this->checkBox1->Text = L"Delay";
	this->checkBox1->UseVisualStyleBackColor = true;
	// 
	// groupBox10
	// 
	this->groupBox10->Controls->Add(this->textBox7);
	this->groupBox10->Location = System::Drawing::Point(350, 21);
	this->groupBox10->Name = L"groupBox10";
	this->groupBox10->Size = System::Drawing::Size(153, 60);
	this->groupBox10->TabIndex = 3;
	this->groupBox10->TabStop = false;
	this->groupBox10->Text = L"Fragment Offset";
	// 
	// textBox7
	// 
	this->textBox7->Location = System::Drawing::Point(6, 21);
	this->textBox7->Name = L"textBox7";
	this->textBox7->Size = System::Drawing::Size(141, 22);
	this->textBox7->TabIndex = 0;
	this->textBox7->Text = L"0";
	// 
	// groupBox9
	// 
	this->groupBox9->Controls->Add(this->textBox6);
	this->groupBox9->Location = System::Drawing::Point(178, 21);
	this->groupBox9->Name = L"groupBox9";
	this->groupBox9->Size = System::Drawing::Size(166, 60);
	this->groupBox9->TabIndex = 2;
	this->groupBox9->TabStop = false;
	this->groupBox9->Text = L"Destination IP";
	// 
	// textBox6
	// 
	this->textBox6->Location = System::Drawing::Point(6, 21);
	this->textBox6->Name = L"textBox6";
	this->textBox6->Size = System::Drawing::Size(154, 22);
	this->textBox6->TabIndex = 0;
	this->textBox6->Text = L"195.209.230.198";
	// 
	// groupBox8
	// 
	this->groupBox8->Controls->Add(this->textBox5);
	this->groupBox8->Location = System::Drawing::Point(6, 21);
	this->groupBox8->Name = L"groupBox8";
	this->groupBox8->Size = System::Drawing::Size(166, 60);
	this->groupBox8->TabIndex = 1;
	this->groupBox8->TabStop = false;
	this->groupBox8->Text = L"Source IP";
	// 
	// textBox5
	// 
	this->textBox5->Location = System::Drawing::Point(6, 21);
	this->textBox5->MaxLength = 15;
	this->textBox5->Name = L"textBox5";
	this->textBox5->Size = System::Drawing::Size(154, 22);
	this->textBox5->TabIndex = 0;
	this->textBox5->Text = L"192.168.0.65";
	// 
	// groupBox7
	// 
	this->groupBox7->Controls->Add(this->textBox4);
	this->groupBox7->Location = System::Drawing::Point(12, 637);
	this->groupBox7->Name = L"groupBox7";
	this->groupBox7->Size = System::Drawing::Size(509, 53);
	this->groupBox7->TabIndex = 8;
	this->groupBox7->TabStop = false;
	this->groupBox7->Text = L"Data";
	// 
	// textBox4
	// 
	this->textBox4->Location = System::Drawing::Point(6, 21);
	this->textBox4->Name = L"textBox4";
	this->textBox4->Size = System::Drawing::Size(497, 22);
	this->textBox4->TabIndex = 0;
	// 
	// tabControl1
	// 
	this->tabControl1->Controls->Add(this->tabPage1);
	this->tabControl1->Controls->Add(this->tabPage2);
	this->tabControl1->Controls->Add(this->tabPage3);
	this->tabControl1->Location = System::Drawing::Point(12, 427);
	this->tabControl1->Name = L"tabControl1";
	this->tabControl1->SelectedIndex = 0;
	this->tabControl1->Size = System::Drawing::Size(509, 208);
	this->tabControl1->TabIndex = 9;
	// 
	// tabPage1
	// 
	this->tabPage1->Controls->Add(this->groupBox31);
	this->tabPage1->Controls->Add(this->groupBox30);
	this->tabPage1->Controls->Add(this->groupBox29);
	this->tabPage1->Controls->Add(this->groupBox28);
	this->tabPage1->Controls->Add(this->groupBox27);
	this->tabPage1->Controls->Add(this->groupBox26);
	this->tabPage1->Controls->Add(this->groupBox25);
	this->tabPage1->Controls->Add(this->groupBox24);
	this->tabPage1->Controls->Add(this->groupBox23);
	this->tabPage1->Controls->Add(this->groupBox22);
	this->tabPage1->Location = System::Drawing::Point(4, 25);
	this->tabPage1->Name = L"tabPage1";
	this->tabPage1->Padding = System::Windows::Forms::Padding(3);
	this->tabPage1->Size = System::Drawing::Size(501, 179);
	this->tabPage1->TabIndex = 0;
	this->tabPage1->Text = L"TCP";
	this->tabPage1->UseVisualStyleBackColor = true;
	// 
	// groupBox31
	// 
	this->groupBox31->Controls->Add(this->textBox24);
	this->groupBox31->Location = System::Drawing::Point(209, 120);
	this->groupBox31->Name = L"groupBox31";
	this->groupBox31->Size = System::Drawing::Size(92, 51);
	this->groupBox31->TabIndex = 13;
	this->groupBox31->TabStop = false;
	this->groupBox31->Text = L"Reserved";
	// 
	// textBox24
	// 
	this->textBox24->Location = System::Drawing::Point(6, 21);
	this->textBox24->Name = L"textBox24";
	this->textBox24->Size = System::Drawing::Size(80, 22);
	this->textBox24->TabIndex = 0;
	this->textBox24->Text = L"0";
	// 
	// groupBox30
	// 
	this->groupBox30->Controls->Add(this->textBox23);
	this->groupBox30->Location = System::Drawing::Point(108, 120);
	this->groupBox30->Name = L"groupBox30";
	this->groupBox30->Size = System::Drawing::Size(95, 51);
	this->groupBox30->TabIndex = 12;
	this->groupBox30->TabStop = false;
	this->groupBox30->Text = L"Ur. Pointer";
	// 
	// textBox23
	// 
	this->textBox23->Location = System::Drawing::Point(6, 21);
	this->textBox23->Name = L"textBox23";
	this->textBox23->Size = System::Drawing::Size(83, 22);
	this->textBox23->TabIndex = 0;
	this->textBox23->Text = L"0";
	// 
	// groupBox29
	// 
	this->groupBox29->Controls->Add(this->textBox22);
	this->groupBox29->Location = System::Drawing::Point(6, 120);
	this->groupBox29->Name = L"groupBox29";
	this->groupBox29->Size = System::Drawing::Size(96, 51);
	this->groupBox29->TabIndex = 11;
	this->groupBox29->TabStop = false;
	this->groupBox29->Text = L"Wind. Size";
	// 
	// textBox22
	// 
	this->textBox22->Location = System::Drawing::Point(6, 21);
	this->textBox22->Name = L"textBox22";
	this->textBox22->Size = System::Drawing::Size(84, 22);
	this->textBox22->TabIndex = 0;
	this->textBox22->Text = L"64240";
	// 
	// groupBox28
	// 
	this->groupBox28->Controls->Add(this->checkBox17);
	this->groupBox28->Controls->Add(this->checkBox16);
	this->groupBox28->Controls->Add(this->checkBox15);
	this->groupBox28->Controls->Add(this->checkBox14);
	this->groupBox28->Controls->Add(this->checkBox13);
	this->groupBox28->Controls->Add(this->checkBox12);
	this->groupBox28->Controls->Add(this->checkBox11);
	this->groupBox28->Controls->Add(this->checkBox10);
	this->groupBox28->Controls->Add(this->checkBox9);
	this->groupBox28->Location = System::Drawing::Point(307, 63);
	this->groupBox28->Name = L"groupBox28";
	this->groupBox28->Size = System::Drawing::Size(188, 108);
	this->groupBox28->TabIndex = 10;
	this->groupBox28->TabStop = false;
	this->groupBox28->Text = L"Flags";
	// 
	// checkBox17
	// 
	this->checkBox17->AutoSize = true;
	this->checkBox17->Location = System::Drawing::Point(124, 77);
	this->checkBox17->Name = L"checkBox17";
	this->checkBox17->Size = System::Drawing::Size(51, 21);
	this->checkBox17->TabIndex = 8;
	this->checkBox17->Text = L"FIN";
	this->checkBox17->UseVisualStyleBackColor = true;
	// 
	// checkBox16
	// 
	this->checkBox16->AutoSize = true;
	this->checkBox16->Location = System::Drawing::Point(124, 50);
	this->checkBox16->Name = L"checkBox16";
	this->checkBox16->Size = System::Drawing::Size(58, 21);
	this->checkBox16->TabIndex = 7;
	this->checkBox16->Text = L"SYN";
	this->checkBox16->UseVisualStyleBackColor = true;
	// 
	// checkBox15
	// 
	this->checkBox15->AutoSize = true;
	this->checkBox15->Location = System::Drawing::Point(124, 23);
	this->checkBox15->Name = L"checkBox15";
	this->checkBox15->Size = System::Drawing::Size(58, 21);
	this->checkBox15->TabIndex = 6;
	this->checkBox15->Text = L"RST";
	this->checkBox15->UseVisualStyleBackColor = true;
	// 
	// checkBox14
	// 
	this->checkBox14->AutoSize = true;
	this->checkBox14->Location = System::Drawing::Point(65, 77);
	this->checkBox14->Name = L"checkBox14";
	this->checkBox14->Size = System::Drawing::Size(58, 21);
	this->checkBox14->TabIndex = 5;
	this->checkBox14->Text = L"PSH";
	this->checkBox14->UseVisualStyleBackColor = true;
	// 
	// checkBox13
	// 
	this->checkBox13->AutoSize = true;
	this->checkBox13->Location = System::Drawing::Point(65, 50);
	this->checkBox13->Name = L"checkBox13";
	this->checkBox13->Size = System::Drawing::Size(57, 21);
	this->checkBox13->TabIndex = 4;
	this->checkBox13->Text = L"ACK";
	this->checkBox13->UseVisualStyleBackColor = true;
	// 
	// checkBox12
	// 
	this->checkBox12->AutoSize = true;
	this->checkBox12->Location = System::Drawing::Point(65, 23);
	this->checkBox12->Name = L"checkBox12";
	this->checkBox12->Size = System::Drawing::Size(61, 21);
	this->checkBox12->TabIndex = 3;
	this->checkBox12->Text = L"URG";
	this->checkBox12->UseVisualStyleBackColor = true;
	// 
	// checkBox11
	// 
	this->checkBox11->AutoSize = true;
	this->checkBox11->Location = System::Drawing::Point(6, 77);
	this->checkBox11->Name = L"checkBox11";
	this->checkBox11->Size = System::Drawing::Size(57, 21);
	this->checkBox11->TabIndex = 2;
	this->checkBox11->Text = L"ECE";
	this->checkBox11->UseVisualStyleBackColor = true;
	// 
	// checkBox10
	// 
	this->checkBox10->AutoSize = true;
	this->checkBox10->Location = System::Drawing::Point(6, 50);
	this->checkBox10->Name = L"checkBox10";
	this->checkBox10->Size = System::Drawing::Size(62, 21);
	this->checkBox10->TabIndex = 1;
	this->checkBox10->Text = L"CWR";
	this->checkBox10->UseVisualStyleBackColor = true;
	// 
	// checkBox9
	// 
	this->checkBox9->AutoSize = true;
	this->checkBox9->Location = System::Drawing::Point(6, 23);
	this->checkBox9->Name = L"checkBox9";
	this->checkBox9->Size = System::Drawing::Size(49, 21);
	this->checkBox9->TabIndex = 0;
	this->checkBox9->Text = L"NS";
	this->checkBox9->UseVisualStyleBackColor = true;
	// 
	// groupBox27
	// 
	this->groupBox27->Controls->Add(this->textBox21);
	this->groupBox27->Location = System::Drawing::Point(157, 63);
	this->groupBox27->Name = L"groupBox27";
	this->groupBox27->Size = System::Drawing::Size(144, 51);
	this->groupBox27->TabIndex = 9;
	this->groupBox27->TabStop = false;
	this->groupBox27->Text = L"Ack. Number";
	// 
	// textBox21
	// 
	this->textBox21->Location = System::Drawing::Point(6, 21);
	this->textBox21->Name = L"textBox21";
	this->textBox21->Size = System::Drawing::Size(130, 22);
	this->textBox21->TabIndex = 0;
	this->textBox21->Text = L"0";
	// 
	// groupBox26
	// 
	this->groupBox26->Controls->Add(this->textBox20);
	this->groupBox26->Location = System::Drawing::Point(6, 63);
	this->groupBox26->Name = L"groupBox26";
	this->groupBox26->Size = System::Drawing::Size(145, 51);
	this->groupBox26->TabIndex = 8;
	this->groupBox26->TabStop = false;
	this->groupBox26->Text = L"Seq. Number";
	// 
	// textBox20
	// 
	this->textBox20->Location = System::Drawing::Point(6, 21);
	this->textBox20->Name = L"textBox20";
	this->textBox20->Size = System::Drawing::Size(133, 22);
	this->textBox20->TabIndex = 0;
	this->textBox20->Text = L"1000";
	// 
	// groupBox25
	// 
	this->groupBox25->Controls->Add(this->textBox19);
	this->groupBox25->Location = System::Drawing::Point(224, 6);
	this->groupBox25->Name = L"groupBox25";
	this->groupBox25->Size = System::Drawing::Size(92, 51);
	this->groupBox25->TabIndex = 7;
	this->groupBox25->TabStop = false;
	this->groupBox25->Text = L"Offset";
	// 
	// textBox19
	// 
	this->textBox19->Location = System::Drawing::Point(6, 21);
	this->textBox19->Name = L"textBox19";
	this->textBox19->Size = System::Drawing::Size(80, 22);
	this->textBox19->TabIndex = 0;
	this->textBox19->Text = L"8";
	// 
	// groupBox24
	// 
	this->groupBox24->Controls->Add(this->checkBox8);
	this->groupBox24->Controls->Add(this->textBox18);
	this->groupBox24->Location = System::Drawing::Point(323, 6);
	this->groupBox24->Name = L"groupBox24";
	this->groupBox24->Size = System::Drawing::Size(172, 51);
	this->groupBox24->TabIndex = 6;
	this->groupBox24->TabStop = false;
	this->groupBox24->Text = L"Checksum";
	// 
	// checkBox8
	// 
	this->checkBox8->AutoSize = true;
	this->checkBox8->Checked = true;
	this->checkBox8->CheckState = System::Windows::Forms::CheckState::Checked;
	this->checkBox8->Location = System::Drawing::Point(108, 21);
	this->checkBox8->Name = L"checkBox8";
	this->checkBox8->Size = System::Drawing::Size(58, 21);
	this->checkBox8->TabIndex = 1;
	this->checkBox8->Text = L"auto";
	this->checkBox8->UseVisualStyleBackColor = true;
	this->checkBox8->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox8_CheckedChanged);
	// 
	// textBox18
	// 
	this->textBox18->Enabled = false;
	this->textBox18->Location = System::Drawing::Point(6, 21);
	this->textBox18->Name = L"textBox18";
	this->textBox18->Size = System::Drawing::Size(96, 22);
	this->textBox18->TabIndex = 0;
	this->textBox18->Text = L"65535";
	// 
	// groupBox23
	// 
	this->groupBox23->Controls->Add(this->textBox17);
	this->groupBox23->Location = System::Drawing::Point(115, 6);
	this->groupBox23->Name = L"groupBox23";
	this->groupBox23->Size = System::Drawing::Size(103, 51);
	this->groupBox23->TabIndex = 3;
	this->groupBox23->TabStop = false;
	this->groupBox23->Text = L"Dest. Port";
	// 
	// textBox17
	// 
	this->textBox17->Location = System::Drawing::Point(6, 21);
	this->textBox17->Name = L"textBox17";
	this->textBox17->Size = System::Drawing::Size(91, 22);
	this->textBox17->TabIndex = 0;
	this->textBox17->Text = L"80";
	// 
	// groupBox22
	// 
	this->groupBox22->Controls->Add(this->textBox16);
	this->groupBox22->Location = System::Drawing::Point(6, 6);
	this->groupBox22->Name = L"groupBox22";
	this->groupBox22->Size = System::Drawing::Size(103, 51);
	this->groupBox22->TabIndex = 2;
	this->groupBox22->TabStop = false;
	this->groupBox22->Text = L"Source Port";
	// 
	// textBox16
	// 
	this->textBox16->Location = System::Drawing::Point(6, 21);
	this->textBox16->Name = L"textBox16";
	this->textBox16->Size = System::Drawing::Size(91, 22);
	this->textBox16->TabIndex = 0;
	this->textBox16->Text = L"55166";
	// 
	// tabPage2
	// 
	this->tabPage2->Controls->Add(this->groupBox35);
	this->tabPage2->Controls->Add(this->groupBox34);
	this->tabPage2->Controls->Add(this->groupBox33);
	this->tabPage2->Controls->Add(this->groupBox32);
	this->tabPage2->Location = System::Drawing::Point(4, 25);
	this->tabPage2->Name = L"tabPage2";
	this->tabPage2->Padding = System::Windows::Forms::Padding(3);
	this->tabPage2->Size = System::Drawing::Size(501, 179);
	this->tabPage2->TabIndex = 1;
	this->tabPage2->Text = L"UDP";
	this->tabPage2->UseVisualStyleBackColor = true;
	// 
	// groupBox35
	// 
	this->groupBox35->Controls->Add(this->checkBox18);
	this->groupBox35->Controls->Add(this->textBox28);
	this->groupBox35->Location = System::Drawing::Point(322, 6);
	this->groupBox35->Name = L"groupBox35";
	this->groupBox35->Size = System::Drawing::Size(173, 51);
	this->groupBox35->TabIndex = 9;
	this->groupBox35->TabStop = false;
	this->groupBox35->Text = L"Checksum";
	// 
	// checkBox18
	// 
	this->checkBox18->AutoSize = true;
	this->checkBox18->Checked = true;
	this->checkBox18->CheckState = System::Windows::Forms::CheckState::Checked;
	this->checkBox18->Location = System::Drawing::Point(108, 21);
	this->checkBox18->Name = L"checkBox18";
	this->checkBox18->Size = System::Drawing::Size(58, 21);
	this->checkBox18->TabIndex = 1;
	this->checkBox18->Text = L"auto";
	this->checkBox18->UseVisualStyleBackColor = true;
	this->checkBox18->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox18_CheckedChanged);
	// 
	// textBox28
	// 
	this->textBox28->Enabled = false;
	this->textBox28->Location = System::Drawing::Point(6, 21);
	this->textBox28->Name = L"textBox28";
	this->textBox28->Size = System::Drawing::Size(96, 22);
	this->textBox28->TabIndex = 0;
	this->textBox28->Text = L"65535";
	// 
	// groupBox34
	// 
	this->groupBox34->Controls->Add(this->textBox27);
	this->groupBox34->Location = System::Drawing::Point(224, 6);
	this->groupBox34->Name = L"groupBox34";
	this->groupBox34->Size = System::Drawing::Size(92, 51);
	this->groupBox34->TabIndex = 8;
	this->groupBox34->TabStop = false;
	this->groupBox34->Text = L"Length";
	// 
	// textBox27
	// 
	this->textBox27->Location = System::Drawing::Point(6, 21);
	this->textBox27->Name = L"textBox27";
	this->textBox27->Size = System::Drawing::Size(80, 22);
	this->textBox27->TabIndex = 0;
	// 
	// groupBox33
	// 
	this->groupBox33->Controls->Add(this->textBox26);
	this->groupBox33->Location = System::Drawing::Point(115, 6);
	this->groupBox33->Name = L"groupBox33";
	this->groupBox33->Size = System::Drawing::Size(103, 51);
	this->groupBox33->TabIndex = 4;
	this->groupBox33->TabStop = false;
	this->groupBox33->Text = L"Dest. Port";
	// 
	// textBox26
	// 
	this->textBox26->Location = System::Drawing::Point(6, 21);
	this->textBox26->Name = L"textBox26";
	this->textBox26->Size = System::Drawing::Size(91, 22);
	this->textBox26->TabIndex = 0;
	// 
	// groupBox32
	// 
	this->groupBox32->Controls->Add(this->textBox25);
	this->groupBox32->Location = System::Drawing::Point(6, 6);
	this->groupBox32->Name = L"groupBox32";
	this->groupBox32->Size = System::Drawing::Size(103, 51);
	this->groupBox32->TabIndex = 3;
	this->groupBox32->TabStop = false;
	this->groupBox32->Text = L"Source Port";
	// 
	// textBox25
	// 
	this->textBox25->Location = System::Drawing::Point(6, 21);
	this->textBox25->Name = L"textBox25";
	this->textBox25->Size = System::Drawing::Size(91, 22);
	this->textBox25->TabIndex = 0;
	// 
	// tabPage3
	// 
	this->tabPage3->Controls->Add(this->groupBox40);
	this->tabPage3->Controls->Add(this->groupBox39);
	this->tabPage3->Controls->Add(this->groupBox38);
	this->tabPage3->Controls->Add(this->groupBox37);
	this->tabPage3->Controls->Add(this->groupBox36);
	this->tabPage3->Location = System::Drawing::Point(4, 25);
	this->tabPage3->Name = L"tabPage3";
	this->tabPage3->Size = System::Drawing::Size(501, 179);
	this->tabPage3->TabIndex = 2;
	this->tabPage3->Text = L"ICMP";
	this->tabPage3->UseVisualStyleBackColor = true;
	// 
	// groupBox40
	// 
	this->groupBox40->Controls->Add(this->textBox32);
	this->groupBox40->Location = System::Drawing::Point(84, 61);
	this->groupBox40->Name = L"groupBox40";
	this->groupBox40->Size = System::Drawing::Size(108, 50);
	this->groupBox40->TabIndex = 12;
	this->groupBox40->TabStop = false;
	this->groupBox40->Text = L"Identifier";
	// 
	// textBox32
	// 
	this->textBox32->Location = System::Drawing::Point(6, 21);
	this->textBox32->Name = L"textBox32";
	this->textBox32->Size = System::Drawing::Size(95, 22);
	this->textBox32->TabIndex = 0;
	this->textBox32->Text = L"1";
	// 
	// groupBox39
	// 
	this->groupBox39->Controls->Add(this->textBox31);
	this->groupBox39->Location = System::Drawing::Point(147, 6);
	this->groupBox39->Name = L"groupBox39";
	this->groupBox39->Size = System::Drawing::Size(170, 49);
	this->groupBox39->TabIndex = 11;
	this->groupBox39->TabStop = false;
	this->groupBox39->Text = L"Sequence Number";
	// 
	// textBox31
	// 
	this->textBox31->Location = System::Drawing::Point(5, 19);
	this->textBox31->Name = L"textBox31";
	this->textBox31->Size = System::Drawing::Size(158, 22);
	this->textBox31->TabIndex = 0;
	this->textBox31->Text = L"1";
	// 
	// groupBox38
	// 
	this->groupBox38->Controls->Add(this->comboBox3);
	this->groupBox38->Location = System::Drawing::Point(6, 6);
	this->groupBox38->Name = L"groupBox38";
	this->groupBox38->Size = System::Drawing::Size(135, 49);
	this->groupBox38->TabIndex = 10;
	this->groupBox38->TabStop = false;
	this->groupBox38->Text = L"Type";
	// 
	// comboBox3
	// 
	this->comboBox3->FormattingEnabled = true;
	this->comboBox3->Items->AddRange(gcnew cli::array< System::Object^  >(2) { L"0 (Echo reply)", L"8 (Echo request)" });
	this->comboBox3->Location = System::Drawing::Point(6, 19);
	this->comboBox3->Name = L"comboBox3";
	this->comboBox3->Size = System::Drawing::Size(123, 24);
	this->comboBox3->TabIndex = 5;
	this->comboBox3->Text = L"8 (Echo request)";
	// 
	// groupBox37
	// 
	this->groupBox37->Controls->Add(this->textBox30);
	this->groupBox37->Location = System::Drawing::Point(6, 61);
	this->groupBox37->Name = L"groupBox37";
	this->groupBox37->Size = System::Drawing::Size(72, 50);
	this->groupBox37->TabIndex = 9;
	this->groupBox37->TabStop = false;
	this->groupBox37->Text = L"Code";
	// 
	// textBox30
	// 
	this->textBox30->Location = System::Drawing::Point(6, 21);
	this->textBox30->Name = L"textBox30";
	this->textBox30->Size = System::Drawing::Size(60, 22);
	this->textBox30->TabIndex = 0;
	this->textBox30->Text = L"0";
	// 
	// groupBox36
	// 
	this->groupBox36->Controls->Add(this->checkBox19);
	this->groupBox36->Controls->Add(this->textBox29);
	this->groupBox36->Location = System::Drawing::Point(323, 6);
	this->groupBox36->Name = L"groupBox36";
	this->groupBox36->Size = System::Drawing::Size(170, 49);
	this->groupBox36->TabIndex = 7;
	this->groupBox36->TabStop = false;
	this->groupBox36->Text = L"Checksum";
	// 
	// checkBox19
	// 
	this->checkBox19->AutoSize = true;
	this->checkBox19->Checked = true;
	this->checkBox19->CheckState = System::Windows::Forms::CheckState::Checked;
	this->checkBox19->Location = System::Drawing::Point(108, 21);
	this->checkBox19->Name = L"checkBox19";
	this->checkBox19->Size = System::Drawing::Size(58, 21);
	this->checkBox19->TabIndex = 1;
	this->checkBox19->Text = L"auto";
	this->checkBox19->UseVisualStyleBackColor = true;
	this->checkBox19->CheckedChanged += gcnew System::EventHandler(this, &MyForm::checkBox19_CheckedChanged);
	// 
	// textBox29
	// 
	this->textBox29->Enabled = false;
	this->textBox29->Location = System::Drawing::Point(6, 19);
	this->textBox29->Name = L"textBox29";
	this->textBox29->Size = System::Drawing::Size(96, 22);
	this->textBox29->TabIndex = 0;
	this->textBox29->Text = L"65535";
	// 
	// MyForm
	// 
	this->AutoScaleDimensions = System::Drawing::SizeF(8, 16);
	this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
	this->ClientSize = System::Drawing::Size(533, 736);
	this->Controls->Add(this->tabControl1);
	this->Controls->Add(this->groupBox7);
	this->Controls->Add(this->groupBox6);
	this->Controls->Add(this->groupBox5);
	this->Controls->Add(this->button3);
	this->Controls->Add(this->button2);
	this->Controls->Add(this->groupBox1);
	this->Name = L"MyForm";
	this->Text = L"Packet Generator";
	this->groupBox1->ResumeLayout(false);
	this->groupBox4->ResumeLayout(false);
	this->groupBox4->PerformLayout();
	this->groupBox2->ResumeLayout(false);
	this->groupBox2->PerformLayout();
	this->groupBox3->ResumeLayout(false);
	this->groupBox3->PerformLayout();
	this->groupBox5->ResumeLayout(false);
	this->groupBox6->ResumeLayout(false);
	this->groupBox20->ResumeLayout(false);
	this->groupBox20->PerformLayout();
	this->groupBox21->ResumeLayout(false);
	this->groupBox21->PerformLayout();
	this->groupBox19->ResumeLayout(false);
	this->groupBox19->PerformLayout();
	this->groupBox17->ResumeLayout(false);
	this->groupBox17->PerformLayout();
	this->groupBox16->ResumeLayout(false);
	this->groupBox16->PerformLayout();
	this->groupBox18->ResumeLayout(false);
	this->groupBox18->PerformLayout();
	this->groupBox15->ResumeLayout(false);
	this->groupBox15->PerformLayout();
	this->groupBox14->ResumeLayout(false);
	this->groupBox14->PerformLayout();
	this->groupBox11->ResumeLayout(false);
	this->groupBox11->PerformLayout();
	this->groupBox13->ResumeLayout(false);
	this->groupBox12->ResumeLayout(false);
	this->groupBox12->PerformLayout();
	this->groupBox10->ResumeLayout(false);
	this->groupBox10->PerformLayout();
	this->groupBox9->ResumeLayout(false);
	this->groupBox9->PerformLayout();
	this->groupBox8->ResumeLayout(false);
	this->groupBox8->PerformLayout();
	this->groupBox7->ResumeLayout(false);
	this->groupBox7->PerformLayout();
	this->tabControl1->ResumeLayout(false);
	this->tabPage1->ResumeLayout(false);
	this->groupBox31->ResumeLayout(false);
	this->groupBox31->PerformLayout();
	this->groupBox30->ResumeLayout(false);
	this->groupBox30->PerformLayout();
	this->groupBox29->ResumeLayout(false);
	this->groupBox29->PerformLayout();
	this->groupBox28->ResumeLayout(false);
	this->groupBox28->PerformLayout();
	this->groupBox27->ResumeLayout(false);
	this->groupBox27->PerformLayout();
	this->groupBox26->ResumeLayout(false);
	this->groupBox26->PerformLayout();
	this->groupBox25->ResumeLayout(false);
	this->groupBox25->PerformLayout();
	this->groupBox24->ResumeLayout(false);
	this->groupBox24->PerformLayout();
	this->groupBox23->ResumeLayout(false);
	this->groupBox23->PerformLayout();
	this->groupBox22->ResumeLayout(false);
	this->groupBox22->PerformLayout();
	this->tabPage2->ResumeLayout(false);
	this->groupBox35->ResumeLayout(false);
	this->groupBox35->PerformLayout();
	this->groupBox34->ResumeLayout(false);
	this->groupBox34->PerformLayout();
	this->groupBox33->ResumeLayout(false);
	this->groupBox33->PerformLayout();
	this->groupBox32->ResumeLayout(false);
	this->groupBox32->PerformLayout();
	this->tabPage3->ResumeLayout(false);
	this->groupBox40->ResumeLayout(false);
	this->groupBox40->PerformLayout();
	this->groupBox39->ResumeLayout(false);
	this->groupBox39->PerformLayout();
	this->groupBox38->ResumeLayout(false);
	this->groupBox37->ResumeLayout(false);
	this->groupBox37->PerformLayout();
	this->groupBox36->ResumeLayout(false);
	this->groupBox36->PerformLayout();
	this->ResumeLayout(false);

}