#ifndef _INI_FILE_H_
#define _INI_FILE_H_


#define TRUE	1
#define FALSE	0

#define SUCCESS 0
#define FAILURE -1

#define _dbg printf
#define _err printf

#define IF_POINTER_IS_NULL(p, errCode)	\
	do {									\
		if(!(p)) {							\
			printf("%s pointer[%s] is null \n", __func__, #p);	\
			return errCode;							\
		}										\
	}while(0)


int IniGetProfileString(const char *iniFile, const char *section, const char *key, char *value, int len);
int IniGetProfileInt(const char *iniFile, const char *section, const char *key, int def);
char *IniGetProfileSection(const char *iniFile, const char *section);
int IniSetProfileSection(const char *iniFile, const char *section, char *sectionValue);
int IniSetProfileString(const char *iniFile, const char *section,  const char *key, const char *value);
int IniSetProfileInt(const char *iniFile, const char *section, const char *key, int val);



#endif // end of _INI_FILE_H_