#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "inifile.h"

#define LINE_SIZE 1024

char *jumpSpace(char *line)
{
	char *p = line;
	while(*p && isspace(*p)) p++;
	if(!*p || *p == ';' || *p == '#') return NULL;

	return p;
}

int findSection(FILE *fp, const char *section)
{
	int sectionFinded = FALSE;
	int sLen = strlen(section);
	char line[LINE_SIZE];
	while(fgets(line, LINE_SIZE, fp))
	{
		char *p;
		if((p = jumpSpace(line)) == NULL) continue;
		if(*p == '[' && strncasecmp(p+1, section, sLen) == 0 && p[sLen + 1] == ']') 
		{
			sectionFinded = TRUE;
			break;
		}
	}
	return sectionFinded;
}

int IniGetProfileString(const char *iniFile, const char *section, const char *key, char *value, int len)
{
	IF_POINTER_IS_NULL(iniFile, FAILURE);
	IF_POINTER_IS_NULL(section, FAILURE);
	IF_POINTER_IS_NULL(key, FAILURE);
	IF_POINTER_IS_NULL(value, FAILURE);

	FILE *fp = fopen(iniFile, "rb+");
	if(!fp)
	{
		_err("%s open fail\n", iniFile);
		return FAILURE;
	}

	int keyFinded = FALSE;
	int kLen = strlen(key);
	
	char *p, *pr;
	char line[LINE_SIZE];
	if(findSection(fp, section) == TRUE)
	{
		while(fgets(line, LINE_SIZE, fp))
		{
			if((p = jumpSpace(line)) == NULL) continue;
			if(strncasecmp(p, key, kLen)) continue;
		
			p += kLen;
			while(*p && isspace(*p)) p++;
			if(*p != '=') continue;
		
			// 跳过=后的空格
			p++;
			while(*p && isspace(*p)) p++;
		
			// 去掉尾部的空格
			pr = p + strlen(p) - 1;
			while(pr != p && isspace(*pr)) pr--;
			pr++;
		
			//取值, 范围：[p - pr]
			int min_len = (pr - p) > len ? len : (pr - p);
			memcpy(value, p, min_len);
			value[min_len] = '\0';
			printf("%s = %s\n", key, value);
			keyFinded = TRUE;
			break;
		}
	}		
	fclose(fp);

	return keyFinded;
}

int IniGetProfileInt(const char *iniFile, const char *section, const char *key, int defValue)
{
	char intvalue[24];
	if(IniGetProfileString(iniFile, section, key, intvalue, sizeof(intvalue)) == TRUE)
		return strtol(intvalue, NULL, 10);
	return defValue;
}

char *IniGetProfileSection(const char *iniFile, const char *section)
{
	
}

int IniSetProfileString(const char *iniFile, const char *section, const char *key, const char *value)
{
	IF_POINTER_IS_NULL(iniFile, FAILURE);
	IF_POINTER_IS_NULL(section, FAILURE);
	IF_POINTER_IS_NULL(key, FAILURE);
	IF_POINTER_IS_NULL(value, FAILURE);

}

int IniSetProfileInt(const char *iniFile, const char *section, const char *key, int value)
{
	char intvalue[24];
	sprintf(intvalue, "%d", value);
	return IniSetProfileString(iniFile, section, key, intvalue);
}

int IniSetProfileSection(const char *iniFile, const char *section, char *sectionValue)
{
	IF_POINTER_IS_NULL(iniFile, FAILURE);
	IF_POINTER_IS_NULL(section, FAILURE);
	IF_POINTER_IS_NULL(sectionValue, FAILURE);

}
