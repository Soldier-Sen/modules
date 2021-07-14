#include <stdio.h>
#include <stdlib.h>
#include "inifile.h"

int main(int argc, char *argv[])
{
	char *iniFile = argv[1];
	char model[32];
	IniGetProfileString("./hwcfg.ini", "config", "model", model, sizeof(model));
	int value;
	value = IniGetProfileInt("./hwcfg.ini", "config", "agcnight_value", -1);
	printf("agcnight_value:%d\n", value);

	return 0;
}
