
#include "MyForm.h"


[STAThread]
int main(array<String^>^ arg) 
{
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);

	PacketGenerator::MyForm form;
	Application::Run(%form);
	return 0;
}