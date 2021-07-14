#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ctype.h>
#include <getopt.h>

#include <mbedtls/config.h>
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/md5.h>
#include <mbedtls/md.h>

#include "crypto.h"


static const unsigned int crc32tab[] = {
 0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
 0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
 0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
 0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
 0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
 0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
 0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
 0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
 0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
 0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
 0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
 0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
 0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
 0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
 0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
 0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
 0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
 0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
 0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
 0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
 0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
 0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
 0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
 0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
 0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
 0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
 0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
 0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
 0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
 0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
 0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
 0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
 0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
 0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
 0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
 0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
 0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
 0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
 0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
 0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
 0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
 0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
 0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
 0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
 0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
 0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
 0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
 0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
 0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
 0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
 0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
 0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
 0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
 0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
 0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
 0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
 0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
 0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
 0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
 0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
 0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
 0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
 0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
 0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};
 
 
static unsigned int crc32( const unsigned char *buf, unsigned int size)
{
     unsigned int i, crc;
     crc = 0xFFFFFFFF;
 
 
     for (i = 0; i < size; i++)
      crc = crc32tab[(crc ^ buf[i]) & 0xff] ^ (crc >> 8);
 
     return crc^0xFFFFFFFF;
}


static uint32_t crc32_table[256] =
{
 /*   0 -- */ 0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 
 /*   4 -- */ 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3, 
 /*   8 -- */ 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 
 /*  12 -- */ 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 
 /*  16 -- */ 0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 
 /*  20 -- */ 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7, 
 /*  24 -- */ 0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 
 /*  28 -- */ 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5, 
 /*  32 -- */ 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 
 /*  36 -- */ 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 
 /*  40 -- */ 0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 
 /*  44 -- */ 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59, 
 /*  48 -- */ 0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 
 /*  52 -- */ 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F, 
 /*  56 -- */ 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 
 /*  60 -- */ 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 
 /*  64 -- */ 0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 
 /*  68 -- */ 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433, 
 /*  72 -- */ 0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 
 /*  76 -- */ 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01, 
 /*  80 -- */ 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 
 /*  84 -- */ 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 
 /*  88 -- */ 0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 
 /*  92 -- */ 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65, 
 /*  96 -- */ 0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 
 /* 100 -- */ 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB, 
 /* 104 -- */ 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 
 /* 108 -- */ 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 
 /* 112 -- */ 0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 
 /* 116 -- */ 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F, 
 /* 120 -- */ 0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 
 /* 124 -- */ 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD, 
 /* 128 -- */ 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 
 /* 132 -- */ 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 
 /* 136 -- */ 0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 
 /* 140 -- */ 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1, 
 /* 144 -- */ 0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 
 /* 148 -- */ 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7, 
 /* 152 -- */ 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 
 /* 156 -- */ 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 
 /* 160 -- */ 0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 
 /* 164 -- */ 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B, 
 /* 168 -- */ 0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 
 /* 172 -- */ 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79, 
 /* 176 -- */ 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 
 /* 180 -- */ 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 
 /* 184 -- */ 0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 
 /* 188 -- */ 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D, 
 /* 192 -- */ 0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 
 /* 196 -- */ 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713, 
 /* 200 -- */ 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 
 /* 204 -- */ 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 
 /* 208 -- */ 0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 
 /* 212 -- */ 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777, 
 /* 216 -- */ 0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 
 /* 220 -- */ 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45, 
 /* 224 -- */ 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 
 /* 228 -- */ 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 
 /* 232 -- */ 0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 
 /* 236 -- */ 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9, 
 /* 240 -- */ 0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 
 /* 244 -- */ 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF, 
 /* 248 -- */ 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 
 /* 252 -- */ 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint32_t calc_crc32(uint32_t crc, char *buff, int len)
{
    //if (!have_table) make_table();
    int i;
    crc = ~crc;
    for (i = 0; i < len; i++)
        crc = (crc >> 8) ^ crc32_table[(crc ^ buff[i]) & 0xff];
    return ~crc;
}


#define NO_ARG				0
#define HAS_ARG				1

static struct option long_options[] = {
	{"mode", HAS_ARG, 0, 'm'},
	{"file", HAS_ARG, 0, 'f'},
	{"string", HAS_ARG, 0, 's'},
	{0, 0, 0, 0}
    
};

static const char *short_options = "f:m:s:";

void usage(void)
{
	int i;

	printf("\nmbedtls usage:\n");
	for (i = 0; i < sizeof(long_options) / sizeof(long_options[0]) - 1; i++) 
	{
		if (isalpha(long_options[i].val))
			printf("-%c ", long_options[i].val);
		else
			printf("   ");
		printf("--%s", long_options[i].name);

	}
	printf("\n");
}


#define AES_128_KEY_LEN  16
#define AES_256_KEY_LEN  32

// key: 35408382fef5a3decf784f74d3f1d97e
int load_key(const char *keyFile, unsigned char *key, int keyLen);
int load_file_data(const char *fileName, unsigned char **data, int *data_len);
int save_file(const char *path, const unsigned char *data, unsigned int size);

int main(int argc, char *argv[])
{
	int result = -1;
	unsigned char iv[16] = {0};
	//char msg[16+1] = "0123456789abcd";
	char msg[16+1] = {0};
	char buf[4096] = {0};
	char enc_buf[16+1] = {0};
	char dec_buf[16+1] = {0};
	char fileName[64] = "";
	struct timeval start, end;

	mbedtls_aes_context ctx;
	char mode[8] = {0};
	//mbedtls_base64_test();
	int ch;
	int option_index = 0;
	opterr = 0;
	while ((ch = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
	{
		switch (ch) 
		{
			case 'f':
				strncpy(fileName, optarg, sizeof(fileName) - 1);
				printf("optind = %d, optarg = %s, fileName = %s\n", optind, optarg, fileName);
				break;
			case 's':
				strncpy(msg, optarg, sizeof(msg) - 1);
				break;
			case 'm':
				strcpy(mode, optarg);
				printf("mode = %s\n", mode);
			//all_flag = 1;
				break;

			default:
			printf("unknown option found: %c\n", ch);
			return -1;
		}
	}
	mbedtls_aes_init(&ctx);

	int i = 0;
	if(strcmp(mode, "des") == 0)
	{
		unsigned char in_conent[16] = "hello!!!";
		unsigned char out[16] = {0};
		unsigned char iv[8] = {0};
		char des_key[MBEDTLS_DES_KEY_SIZE] = "5txcxyrl";
		mbedtls_des_context des_ctx;
		
		mbedtls_des_init(&des_ctx);
		
		mbedtls_des_setkey_enc(&des_ctx, des_key);
		mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, sizeof(in_conent), iv, in_conent, out);
		printf("out:%s\n", out);
		
		memset(iv, 0x0, sizeof(iv));
		char dec_string[16] = {0};
		mbedtls_des_setkey_dec(&des_ctx, des_key);
		mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_DECRYPT, sizeof(out), iv, out, dec_string);
		printf("dec_string:%s\n", dec_string);
		mbedtls_des_free(&des_ctx);
		
	}
	else if(strcmp(mode, "cbc-128") == 0)
	{
		const char iv[16] = {0x1e, 0x25, 0x77, 0xb8, 0x66, 0xc1, 0x10, 0x33,
							 0x93, 0x69, 0xcb, 0xa8, 0x2c, 0x54, 0xe5, 0xab
		};
		
		const char key[16] = {0x23, 0xac, 0x7b, 0x15, 0x0d, 0x89, 0x34, 0x92, 
							  0xf1, 0x19, 0x33, 0xde, 0xc8, 0x6a, 0x10, 0x55
		};

		int i = 0;
		char in[] = "6cf550f5da1db96b88fq1r"; //f
		int len = strlen(in);

		//_info("key:%s, iv:%s\n", key, iv);
		_info("in:%s, len=%d\n", in, len);
		for(i = 0; i < len; i++)
			printf("%02x", in[i]);
		printf("\n\n");

		unsigned char out[32];
		int oLen = 0;
		aes_encode_cbc128(in, len, out, &oLen, key, iv);
		_info("Aes_Encode_Cbc128 oLen:%d\n\n", oLen);
		for(i = 0; i < oLen; i++)
			printf("%02x", out[i]);
		printf("\n");

		int decode_len = base64_encode_len(out, oLen);
		printf("base64_encode_len :%d\n", decode_len);

		char d_out[32] = {0};
		int d_out_len;
		aes_decode_cbc128(out, oLen, d_out, &d_out_len, key, iv);
		_info("d_out_len:%d\n", d_out_len);
		for(i = 0; i < d_out_len; i++)
			printf("%02x", d_out[i]);
		printf("\n\n");

	}
	else if(strcmp(mode, "cbc-256") == 0)
	{
		unsigned char key[AES_256_KEY_LEN] = {0};
		char key_file_256[16] = "aes256.key";
		load_key(key_file_256, key, sizeof(key));
		mbedtls_aes_setkey_enc(&ctx, key, AES_256_KEY_LEN*8);
		
		int len = sizeof(msg) - 1;
		result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, len, iv, msg, enc_buf);
		//result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT,msg, enc_buf);
		printf("ENC: cbc_result = %d, 明文msg:[%s] -> 密文dec_buf:[%s]\n",result, msg, enc_buf);
		
		memset(iv, 0x0, sizeof(iv));
		mbedtls_aes_setkey_dec(&ctx, key, AES_256_KEY_LEN*8);
		result = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, len, iv, enc_buf, dec_buf);
		//result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT,msg, enc_buf);
		printf("DEC: 256 cbc_result = %d, [%s] -> dec = [%s]\n",result, enc_buf, dec_buf);
	}
	else if(strcmp(mode, "hamc-256") == 0)
	{
		char key[] = "6cea9f0814b50585";
		char devid[64] = "nJIaHNjATzbjxM1R6QRiNK7uC6T0D4MQN8rFowcljCQ";
		char random[32 + 1];
		char signature[64];
		char buffer[128];
		int i = 0;
		for(i=0; i<32; i++) {
			int idx = rand()%62;
			random[i] = idx<10?('0'+idx):(idx<36?('A'+idx-10):('a'+idx-36));
		}
		random[32] = '\0';
		printf("random:%s\n", random);

		sprintf(buffer, "%s:%d:%s", devid, time(NULL), random);
		printf("\nbuffer:%s, len:%d\n", buffer, strlen(buffer));
		calcSignature(buffer, strlen(buffer), signature, key);
		char b64Signature[64];
		int b64SignatureLen = sizeof(b64Signature);
		base64_encode(signature, 32, b64Signature, &b64SignatureLen);
		printf("\nb64Signature:%s, len = %d\n", b64Signature, b64SignatureLen);
	}
	else if(strcmp(mode, "crc32") == 0)
	{
		char key[] = "6cea9f0814b50585";
		int crc_value = 0;
		crc_value = crc32(key, strlen(key));
		printf("crc_value = %#x\n", crc_value);
		crc_value = calc_crc32(0, key, strlen(key));
		printf("crc_value = %#x\n", crc_value);
	}
	else if(strcmp(mode, "ecb") == 0)
	{
		//密钥长度可以选择256
		unsigned char key[AES_128_KEY_LEN] = {0};
		char key_file_128[16] = "aes128.key";
		load_key(key_file_128, key, sizeof(key));
		//加密
		mbedtls_aes_setkey_enc(&ctx, key, AES_128_KEY_LEN*8);
		result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, msg, enc_buf);
		printf("ENC: ecb result = %d, 明文msg:[%s] -> 密文dec_buf:[%s]\n",result, msg, enc_buf);
		//解密
		mbedtls_aes_setkey_dec(&ctx, key, AES_128_KEY_LEN*8);
		result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, enc_buf, dec_buf);
		printf("DEC: ecb result = %d, [%s] -> dec = [%s]\n",result, enc_buf, dec_buf);
	}
	else if(strcmp(mode, "md5") == 0)
	{
		unsigned char digest[16] = {0};
		mbedtls_md5_context md5_ctx;

		//求文件的MD5 值
		if(strlen(fileName) > 0)
		{
			int read_len = 0;
			FILE *fp = fopen(fileName, "rb");
			if(!fp){printf("fopen %s fail !", fileName);return -1;}

			gettimeofday(&start, NULL);
			mbedtls_md5_init(&md5_ctx);
			mbedtls_md5_starts_ret(&md5_ctx);
			while((read_len = fread(buf, 1, sizeof(buf), fp)) > 0){
				//printf("read_len = %d\n", read_len);
				mbedtls_md5_update_ret(&md5_ctx, buf, read_len);
			}
			mbedtls_md5_finish_ret(&md5_ctx, digest);
			gettimeofday(&end, NULL);
			fclose(fp);
			mbedtls_md5_free(&md5_ctx);
			float use_time = (end.tv_sec - start.tv_sec)*1000 + (end.tv_usec -start.tv_usec)/1000.0;
			printf("file %s use time: %.4f ms, digest:", fileName, use_time);
			for(i = 0; i< sizeof(digest); i++)
			{
				 printf("%02x", digest[i]);
			}
			printf("\n");
		}
		//求指定字符串的MD5 值
		if(strlen(msg) > 0)
		{
			mbedtls_md5_init(&md5_ctx);
			mbedtls_md5_starts_ret(&md5_ctx);

			mbedtls_md5_update_ret(&md5_ctx, msg, strlen(msg));
			mbedtls_md5_finish_ret(&md5_ctx, digest);
			mbedtls_md5_free(&md5_ctx);
			printf("string %s digest:", msg);
			for(i = 0; i< sizeof(digest); i++)
			{
				 printf("%02x", digest[i]);
			}
			printf("\n");
		}
		
	}

	
	mbedtls_aes_free( &ctx );
    return 0;
}

int mbedtls_base64_test()
{
	char *str = "ZXllcGx1c19oaHM=|VT8wNjozNTQ/Pzo7RT0/bEZsX1Q=";
	char k1[] = "ZXllcGx1c19oaHM=";
	char k2[] = "VT8wNjozNTQ/Pzo7RT0/bEZsX1Q=";
	char buf[32];
	int olen = 0;
	int ret = mbedtls_base64_decode(buf, 1, &olen, k1, strlen(k1));
	printf("<<------------->>\n"
		   "ret :%x\n"
		   "olen:%d\n"
		   "buf :%s\n",
		   ret*-1, olen, buf);
	return olen;
}

int load_key(const char *keyFile, unsigned char *key, int keyLen)
{
	int ret = -1;
	FILE *fp = fopen(keyFile, "rb");
	if(!fp)
	{
		perror("open key file");
		return -1;
	}
	ret = fread(key, 1, keyLen, fp);
	int i = 0;
	for(i = 0; i < keyLen; i++)
	{
		printf("%02x", key[i]);
	}
	printf("\n");
	fclose(fp);
	return ret;
}

int load_file_data(const char *fileName, unsigned char **data, int *data_len)
{
	int ret = -1;
	FILE *fp = fopen(fileName, "rb");
	if(!fp)
	{
		perror("open file");
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	*data_len = ftell(fp);
	rewind(fp);

	*data = (unsigned char *)malloc(*data_len);
	if(*data)
		ret = fread(*data, 1, *data_len, fp);
	fclose(fp);
	return ret;
}
int save_file(const char *path, const unsigned char *data, unsigned int size)
{
	int ret = 0;

	if(path == NULL){
		printf("%s, %d  --path is null\n", __func__, __LINE__);
		return -1;
	}
	//printf("====[%s: %s],size=%d ====\n\n",__func__, path, size);
	FILE *fp = fopen(path, "wb");
	if(fp == NULL) {
		perror("====open file===\n");
		return -1;
	}
	ret = fwrite(data, 1, size, fp);
	fclose(fp);
	return ret;	
}
