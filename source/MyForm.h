#pragma once

#include <iostream>
#include <queue>
#include <map>
#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h> 

#include "Icmp.h"
#include "Tcp.h"
#include "Udp.h"
#include "Icmp.h"
#include "Ipv4.h"
#include "Arp.h"
#include "Ethernet.h"

#pragma comment(lib, "IPHLPAPI.lib")

using namespace System;
using namespace System::Windows::Forms;
using namespace System::ComponentModel;
using namespace System::Collections;
using namespace System::Data;
using namespace System::Drawing;
using namespace System::Text::RegularExpressions;
using namespace Runtime::InteropServices;

namespace PacketGenerator {

	typedef struct AdapterInfo
	{
		std::string name;
		std::string ipAddress;
		std::string macAddress;
		std::string gatewayIpAddress;
	} AdapterInfo;

	public ref class MyForm : public System::Windows::Forms::Form
	{
	public:
		MyForm(void);
		~MyForm();

	private:

		std::queue <Ethernet> *ethernetFrameQueue;
		std::map <std::string, AdapterInfo> *adaptersDescToInfo;
		
		System::Windows::Forms::GroupBox^  groupBox1;
		System::Windows::Forms::Button^  button2;
		System::Windows::Forms::Button^  button3;
		System::Windows::Forms::GroupBox^  groupBox3;
		System::Windows::Forms::TextBox^  textBox2;
		System::Windows::Forms::GroupBox^  groupBox4;
		System::Windows::Forms::TextBox^  textBox3;
		System::Windows::Forms::GroupBox^  groupBox2;
		System::Windows::Forms::TextBox^  textBox1;
		System::Windows::Forms::GroupBox^  groupBox5;
		System::Windows::Forms::ComboBox^  comboBox1;
		System::Windows::Forms::GroupBox^  groupBox6;
		System::Windows::Forms::GroupBox^  groupBox7;
		System::Windows::Forms::TextBox^  textBox4;
		System::Windows::Forms::TabControl^  tabControl1;
		System::Windows::Forms::TabPage^  tabPage1;
		System::Windows::Forms::TabPage^  tabPage2;
		System::Windows::Forms::TabPage^  tabPage3;
		System::Windows::Forms::GroupBox^  groupBox11;
		System::Windows::Forms::GroupBox^  groupBox12;
		System::Windows::Forms::TextBox^  textBox8;
		System::Windows::Forms::CheckBox^  checkBox3;
		System::Windows::Forms::CheckBox^  checkBox2;
		System::Windows::Forms::CheckBox^  checkBox1;
		System::Windows::Forms::GroupBox^  groupBox10;
		System::Windows::Forms::TextBox^  textBox7;
		System::Windows::Forms::GroupBox^  groupBox9;
		System::Windows::Forms::TextBox^  textBox6;
		System::Windows::Forms::GroupBox^  groupBox8;
		System::Windows::Forms::TextBox^  textBox5;
		System::Windows::Forms::ComboBox^  comboBox2;
		System::Windows::Forms::GroupBox^  groupBox13;
		System::Windows::Forms::GroupBox^  groupBox20;
		System::Windows::Forms::TextBox^  textBox14;
		System::Windows::Forms::GroupBox^  groupBox21;
		System::Windows::Forms::TextBox^  textBox15;
		System::Windows::Forms::GroupBox^  groupBox19;
		System::Windows::Forms::TextBox^  textBox13;
		System::Windows::Forms::GroupBox^  groupBox17;
		System::Windows::Forms::TextBox^  textBox11;
		System::Windows::Forms::GroupBox^  groupBox16;
		System::Windows::Forms::TextBox^  textBox10;
		System::Windows::Forms::GroupBox^  groupBox18;
		System::Windows::Forms::TextBox^  textBox12;
		System::Windows::Forms::GroupBox^  groupBox15;
		System::Windows::Forms::CheckBox^  checkBox7;
		System::Windows::Forms::CheckBox^  checkBox6;
		System::Windows::Forms::CheckBox^  checkBox5;
		System::Windows::Forms::GroupBox^  groupBox14;
		System::Windows::Forms::CheckBox^  checkBox4;
		System::Windows::Forms::TextBox^  textBox9;
		System::Windows::Forms::GroupBox^  groupBox31;
		System::Windows::Forms::TextBox^  textBox24;
		System::Windows::Forms::GroupBox^  groupBox30;
		System::Windows::Forms::TextBox^  textBox23;
		System::Windows::Forms::GroupBox^  groupBox29;
		System::Windows::Forms::TextBox^  textBox22;
		System::Windows::Forms::GroupBox^  groupBox28;
		System::Windows::Forms::GroupBox^  groupBox27;
		System::Windows::Forms::TextBox^  textBox21;
		System::Windows::Forms::GroupBox^  groupBox26;
		System::Windows::Forms::TextBox^  textBox20;
		System::Windows::Forms::GroupBox^  groupBox25;
		System::Windows::Forms::TextBox^  textBox19;
		System::Windows::Forms::GroupBox^  groupBox24;
		System::Windows::Forms::CheckBox^  checkBox8;
		System::Windows::Forms::TextBox^  textBox18;
		System::Windows::Forms::GroupBox^  groupBox23;
		System::Windows::Forms::TextBox^  textBox17;
		System::Windows::Forms::GroupBox^  groupBox22;
		System::Windows::Forms::TextBox^  textBox16;
		System::Windows::Forms::CheckBox^  checkBox15;
		System::Windows::Forms::CheckBox^  checkBox14;
		System::Windows::Forms::CheckBox^  checkBox13;
		System::Windows::Forms::CheckBox^  checkBox12;
		System::Windows::Forms::CheckBox^  checkBox11;
		System::Windows::Forms::CheckBox^  checkBox10;
		System::Windows::Forms::CheckBox^  checkBox9;
		System::Windows::Forms::CheckBox^  checkBox17;
		System::Windows::Forms::CheckBox^  checkBox16;
		System::Windows::Forms::GroupBox^  groupBox32;
		System::Windows::Forms::TextBox^  textBox25;
		System::Windows::Forms::GroupBox^  groupBox35;
		System::Windows::Forms::CheckBox^  checkBox18;
		System::Windows::Forms::TextBox^  textBox28;
		System::Windows::Forms::GroupBox^  groupBox34;
		System::Windows::Forms::TextBox^  textBox27;
		System::Windows::Forms::GroupBox^  groupBox33;
		System::Windows::Forms::TextBox^  textBox26;
		System::Windows::Forms::GroupBox^  groupBox39;
		System::Windows::Forms::TextBox^  textBox31;
		System::Windows::Forms::GroupBox^  groupBox38;
		System::Windows::Forms::ComboBox^  comboBox3;
		System::Windows::Forms::GroupBox^  groupBox37;
		System::Windows::Forms::TextBox^  textBox30;
		System::Windows::Forms::GroupBox^  groupBox36;
		System::Windows::Forms::CheckBox^  checkBox19;
		System::Windows::Forms::TextBox^  textBox29;
		System::Windows::Forms::CheckBox^  checkBox20;
		System::Windows::Forms::CheckBox^  checkBox21;
		System::Windows::Forms::GroupBox^  groupBox40;
		System::Windows::Forms::TextBox^  textBox32;

		// Обязательная переменная конструктора
		System::ComponentModel::Container ^components;

//#pragma region Windows Form Designer generated code

		void InitializeComponent(void);

//#pragma endregion
	
		System::Void checkBox8_CheckedChanged(System::Object^  sender, System::EventArgs^  e);
		System::Void checkBox4_CheckedChanged(System::Object^  sender, System::EventArgs^  e);
		System::Void checkBox18_CheckedChanged(System::Object^  sender, System::EventArgs^  e);
		System::Void checkBox19_CheckedChanged(System::Object^  sender, System::EventArgs^  e);

		// check box of source MAC changed
		System::Void checkBox20_CheckedChanged(System::Object^  sender, System::EventArgs^  e);

		// check box of destination MAC changed
		System::Void checkBox21_CheckedChanged(System::Object^  sender, System::EventArgs^  e);

		//  button: Add to queue
		System::Void button2_Click(System::Object^  sender, System::EventArgs^  e);

		// button: Send queue
		System::Void button3_Click(System::Object^  sender, System::EventArgs^  e);

		int addInterfacesListToAdapterBox();
		void initializeAdapterField();

		int checkEthernetFields();
		int checkIpFields();
		int checkTcpFields();
		int checkUdpFields();
		int checkIcmpFields();
		int checkIpAddress(String ^);

		void getEthernetDataFromFields(Ethernet &);
		void getIpDataFromFields(Ipv4 &);
		void getTcpDataFromFields(Tcp &);
		void getUdpDataFromFields(Udp &);
		void getIcmpDataFromFields(Icmp &);

		int sendArpRequest(std::string &);
		int getAddressViaArp(std::string &, std::string &, std::string &);
		bool compareIpAddresses(std::string &, char *);
	};
}
