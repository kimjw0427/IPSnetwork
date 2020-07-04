#include <stdio.h>
#include <windows.h>

int main(void){
	ShellExecute( NULL, "open", "cmd.exe", "/C cd IPS_network_ps1&&start start_cmd.bat > test.txt", "C://", SW_NORMAL );
}
