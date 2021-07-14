#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <error.h>
#include <errno.h>

#include <mbedtls/config.h>
#include <mbedtls/aes.h>
#include <mbedtls/des.h>
#include <mbedtls/md5.h>
#include <mbedtls/md.h>
#include <cjson/cJSON.h>

#include "crypto.h"


#pragma pack (1)		//结构作1字节对齐
/*
Wifi 模组与服务器之间的数据通信统一采用上图的格式， 由 header 和 payload 组成
*/
typedef struct {
	char version;			// Version: 1 字节， 协议版本号， 第一版写 1
	char type;				// Type:1 字节， 命令号， 0： 鉴权请求， 1： 鉴权回复， 2： 心跳包， 3： 唤醒包
	char flag;				//初始定义认证交互的`payload`字段采用`aes cbc 128`加密方式， 采用`PKCS7Padding`方式填充， `flag`为`0x1`， 低`4`位若是为`0`则表示不加密
	short payload_size;
}TuyaAuthHeader_t;

#pragma pack ()


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

#define TUYA_PAYLOAD_SUPPORT_ENC 0

#define TUYA_DEVID 		"6c22ae79d2335944a0swie"
#define TUYA_LOCAL_KEY 	"6d60779e653eac63"

static int tuya_ipc_device_id_get(char *devid, int *id_len)
{
	if(devid)
	{
		strcpy(devid, TUYA_DEVID);
		if(id_len) *id_len = strlen(TUYA_DEVID);
		return 0;
	}
	return -1;
}

static int tuya_ipc_local_key_get(char *local_key, int *key_len)
{
	if(local_key)
	{
		strcpy(local_key, TUYA_LOCAL_KEY);
		if(key_len) *key_len = strlen(TUYA_LOCAL_KEY);
		return 0;
	}	
	return -1;
}

static int g_debugEnable = 1;
void dump_buffer(unsigned char *buffer, int length, char *description)
{
    int i;

    if (g_debugEnable) 
    {
        for (i = 0; i < length; i++) {
        	if((i+1)%25 == 0)printf("\n");
            printf("%02X ", buffer[i]);
        }
        if(description) printf("  [%d], %s\n\n",length, description);
        else printf("\n\n");
    }
}




const char tuya_iv[16] = {0x1e, 0x25, 0x77, 0xb8, 0x66, 0xc1, 0x10, 0x33,
		             0x93, 0x69, 0xcb, 0xa8, 0x2c, 0x54, 0xe5, 0xab
};

const char tuya_key[16] = {0x23, 0xac, 0x7b, 0x15, 0x0d, 0x89, 0x34, 0x92, 
					  0xf1, 0x19, 0x33, 0xde, 0xc8, 0x6a, 0x10, 0x55
};


typedef enum {
	LP_TYPE_AUTH_REQUEST = 0,		// ipc向服务器发起认证请求
	LP_TYPE_AUTH_RESPONSE = 1,		// 服务器回复ipc认证请求
	LP_TYPE_HEARTBEAT = 2,			// 心跳
	LP_TYPE_WAKEUP = 3,				// 唤醒
}TuyaLpAuthType_t;

#define HEADER_LEN 5
#define REQUEST_IV_LEN 16
#define RESPONE_IV_LEN REQUEST_IV_LEN

#define TUYA_DEBUG_DUMP

typedef struct {
	int prepare;
	unsigned int utc_time;

	int devid_len;
	char local_devid[32];

	int encode_devid_len;
	char encode_devid[64];

	char random[32 + 1];

	int local_key_Len;
	char local_key[64];
	
	char request_iv[REQUEST_IV_LEN];

	int wakeup_data_Len;
	char wakeup_data[32];

	int keepalive_Len;
	char keepalive[64];
}tuya_auth_ctx_t;

tuya_auth_ctx_t g_tuya_auth = {0};

#define CHECK_TUYA_EXPR_IS_FALSE(expr, errstring) \
    do {                                                                  		\
        if (!(expr)) {                                                    		\
            printf("%s %d expr[%s] false. %s\n", __func__, __LINE__, #expr, (errstring));    \
            return -1;                                             		\
        }                                                                 		\
    } while (0)


		
void dump_auth_buffer(unsigned char *buffer, int length, char *description)
{
	int i;
#ifdef TUYA_DEBUG_DUMP
	for (i = 0; i < length; i++) {
		if((i+1)%25 == 0)printf("\n");
		printf("%02X ", buffer[i]);
	}
	if(description) printf("  [%d], %s\n\n", length, description);
	else printf("\n\n");
#endif
}


static void tuya_create_random_and_iv(char *random, char *iv)
{
	int i = 0;
	srand(time(NULL));
    for(i=0; i<32; i++) {
        int idx = rand()%62;
        random[i] = idx<10?('0'+idx):(idx<36?('A'+idx-10):('a'+idx-36));
    }
    random[32] = '\0';

    for(i=0; i < REQUEST_IV_LEN; i++) {
        char idx = rand()%100;
        iv[i] = idx;
    }
}

static void tuya_update_wakeup_pack(tuya_auth_ctx_t *ctx)
{
    // 对local key 进行crc计算
    int crc_local_key = crc32(ctx->local_key, ctx->local_key_Len);
    short crc_len = sizeof(crc_local_key);
    //printf("local_key=%s, local_key_Len=%d, crc:%#x, crc_len=%d\n", ctx->local_key, ctx->local_key_Len, crc_local_key, crc_len);

    unsigned char *buf = ctx->wakeup_data;
	buf[0] = 0x1;
	buf[1] = LP_TYPE_WAKEUP;
    buf[2] = 0x0;
    buf[3] = crc_len & 0xf0;
    buf[4] = crc_len & 0x0f;

	buf[5] = (crc_local_key >> 24) & 0xff;
    buf[6] = (crc_local_key >> 16) & 0xff;
    buf[7] = (crc_local_key >> 8) & 0xff;
    buf[8] = (crc_local_key >> 0) & 0xff;

    ctx->wakeup_data_Len = HEADER_LEN + crc_len;
}

static void tuya_update_keepalive_pack(tuya_auth_ctx_t *ctx)
{
	char *buf = ctx->keepalive;
	buf[0] = 0x1;
	buf[1] = LP_TYPE_HEARTBEAT;
    buf[2] = 0x0;
    buf[3] = 0;
    buf[4] = 0;

   	ctx->keepalive_Len = HEADER_LEN;
}

static int tuya_keepalive_device_id_encode(void)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(ctx->devid_len != 0, "need get devid first");
	
	int i = 0;
	
	unsigned char en_dev_id[64];
	int en_dev_id_len = sizeof(en_dev_id);
	aes_encode_cbc128(ctx->local_devid, ctx->devid_len, en_dev_id, &en_dev_id_len, tuya_key, tuya_iv);
	
	int decode_len = base64_encode_len(en_dev_id, en_dev_id_len);
	//printf("base64_encode_len :%d\n", decode_len);

	ctx->encode_devid_len = sizeof(ctx->encode_devid);
	
	if(decode_len > ctx->encode_devid_len || decode_len < 0)
	{
		printf("dest buffer len:%d, need len :%d \n", ctx->encode_devid_len, decode_len);
		return -1;
	}
	char b64EnBuff[64];
	int b64EnLen = sizeof(b64EnBuff);
	base64_encode(en_dev_id, en_dev_id_len, b64EnBuff, &b64EnLen);
    printf("base64_encode devid:%s, b64EnLen = %d\n", b64EnBuff, b64EnLen);

#if 0
	unsigned char b64DnBuff[64];
	int b64DnLen = sizeof(b64DnBuff);
	base64_decode(b64DnBuff, &b64DnLen, b64EnBuff, b64EnLen);
	
	char de_dev_id[64] = {0};
	int de_out_len = sizeof(de_dev_id);
	aes_decode_cbc128(b64DnBuff, b64DnLen, de_dev_id, &de_out_len, tuya_key, tuya_iv);
	printf("aes_decode_cbc128 de_out_len:%d\n", de_out_len);
	for(i = 0; i < de_out_len; i++) printf("%02x", de_dev_id[i]);
	printf("\n\n");
#endif
	memcpy(ctx->encode_devid, b64EnBuff, b64EnLen);
	ctx->encode_devid_len = b64EnLen;
	// 原始 devid 需要（aes_cbc_128 加密 pkcs7 的 padding） 再进行 base64 加密
	// 加密使用 tuya_iv 和 tuya_key
	//printf("devid:%s, len = %d\n\n", b64EnBuff, b64EnLen);
	return 0;
}


int  tuya_low_power_suppend_prepare(void)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	
	ctx->utc_time = time(NULL);
	tuya_create_random_and_iv(ctx->random, ctx->request_iv);
	
    ctx->utc_time = 1624003872;
    memset(ctx->request_iv, '1', REQUEST_IV_LEN);
    strcpy(ctx->random, "fa37JncCHryDsbzayy4cBWDxS22JjzhM");
	
	int ret = 0;
	ctx->local_key_Len = sizeof(ctx->local_key);
	ret = tuya_ipc_local_key_get(ctx->local_key, &ctx->local_key_Len);
	if(0 != ret)
	{
		printf("tuya_ipc_device_id_get failed, ret = %d\n", ret);
		ctx->local_key_Len = 0;
		return ret;
	}

	ctx->devid_len = sizeof(ctx->local_devid);
	ret = tuya_ipc_device_id_get(ctx->local_devid, &ctx->devid_len);
	if(0 != ret)
	{
		printf("tuya_ipc_device_id_get failed, ret = %d\n", ret);
		return ret;
	}

	tuya_keepalive_device_id_encode();

	tuya_update_keepalive_pack(ctx);

	tuya_update_wakeup_pack(ctx);

	ctx->prepare = 1;

#ifdef TUYA_DEBUG_DUMP
	printf("utc_time = %d\n", ctx->utc_time);
	printf("random   = %s\n", ctx->random);
	printf("local_key = %s\n", ctx->local_key);
	dump_auth_buffer(ctx->local_key, ctx->local_key_Len, "local key");

	printf("local_devid = %s\n", ctx->local_devid);
	dump_auth_buffer(ctx->local_devid, ctx->devid_len, "devid");
	
	dump_auth_buffer(ctx->request_iv, REQUEST_IV_LEN, "request_iv");

	dump_auth_buffer(ctx->encode_devid, ctx->encode_devid_len, "encode devid");

	dump_auth_buffer(ctx->keepalive, ctx->keepalive_Len, "keepalive pack");

	dump_auth_buffer(ctx->wakeup_data, ctx->wakeup_data_Len, "wakeup pack");
#endif
	return 0;
}


static int tuya_create_auth_signature(char *oSignature, int *oLen)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(ctx->prepare == 1, "suppend need prepare first");

	int ret = 0;

	char enDevid[64];
	int enDevid_len = sizeof(enDevid);
	ret = tuya_get_keepalive_encode_device_id(enDevid, &enDevid_len);
	CHECK_TUYA_EXPR_IS_FALSE(0 < ret, "tuya_get_keepalive_encode_device_id failed");

	char buffer[128];
	char signature[64];
	sprintf(buffer, "%s:%d:%s", enDevid, ctx->utc_time, ctx->random);
	//sprintf(buffer, "%s:%d:%s", ctx->local_devid, ctx->utc_time, ctx->random);
/*#ifdef TUYA_DEBUG_DUMP*/
	printf("devid:time:random -->> %s\n", buffer);
/*#endif*/
	calcSignature(buffer, strlen(buffer), signature, ctx->local_key);
	char b64Signature[64];
	int b64SignatureLen = sizeof(b64Signature);
	base64_encode(signature, 32, b64Signature, &b64SignatureLen);

	if(oSignature)
	{
		memcpy(oSignature, b64Signature, b64SignatureLen);
	}
#ifdef TUYA_DEBUG_DUMP
	printf("b64Signature: %s\n\n", b64Signature);
#endif
	if(oLen) *oLen = b64SignatureLen;
	return 0;
}



static int tuya_create_request_data(unsigned char *request_data, int *len)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(ctx->prepare == 1, "suppend need prepare first");

	cJSON *data = cJSON_CreateObject();

	char auth[128] = {0};
	char sinature[64] = {0};
	int sinature_len = sizeof(sinature);
	sprintf(auth, "time=%d,random=%s", ctx->utc_time, ctx->random);
	tuya_create_auth_signature(sinature, &sinature_len);

    cJSON_AddNumberToObject(data, "type", 1);
    cJSON_AddNumberToObject(data, "method", 1);
	cJSON_AddStringToObject(data, "authorization", auth);
	cJSON_AddStringToObject(data, "signature", sinature);

	char *body = cJSON_Print(data);
	int body_len = strlen(body);
	printf("%s[%d]\n", cJSON_Print(data), body_len);
	unsigned char en_dev_id[64];
	int en_dev_id_len = sizeof(en_dev_id);
	aes_encode_cbc128(body, body_len, request_data, len, ctx->local_key, ctx->request_iv);
	//dump_auth_buffer(request_data, *len, "tuya_create_request_data");
#if 0
	printf("request data len = %d\n", *len);

	char de_request_data[256] = {0};
	int de_request_data_len = sizeof(de_request_data);
	aes_decode_cbc128(request_data, *len, de_request_data, &de_request_data_len, ctx->local_key, ctx->request_iv);

	//printf("de_request_data:%s\n", de_request_data);
#endif
	cJSON_Delete(data);
	free(body);

	return 0;
}

int tuya_get_3861_auth_request_payload(char *payload, int *size)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(ctx->prepare == 1, "suppend need prepare first");

	int ret = 0;
	char *buf = payload;

	short payload_size = 0;
	payload_size += REQUEST_IV_LEN + 2;

	char enDevid[64];
	int enDevid_len = sizeof(enDevid);
	ret = tuya_get_keepalive_encode_device_id(enDevid, &enDevid_len);
	CHECK_TUYA_EXPR_IS_FALSE(0 < ret, "get encode devid failed");

	payload_size += enDevid_len + 2;
	
	char request_data[256] = {0};
	int request_data_len = sizeof(request_data);
	ret = tuya_create_request_data(request_data, &request_data_len);
	CHECK_TUYA_EXPR_IS_FALSE(0 == ret, "tuya_create_request_data failed");
	
	payload_size += request_data_len + 2;
	//printf("payload_size = %d[%#x]\n", payload_size, payload_size);

	int offset = 0;
	buf[0] = 0x1;
	buf[1] = LP_TYPE_AUTH_REQUEST;
	buf[2] = 0x0;
    buf[3] = (payload_size >> 8) & 0xff;
    buf[4] = (payload_size) & 0xff;
	dump_auth_buffer(buf, HEADER_LEN, "payload header");
	offset = HEADER_LEN;
	
	// fill ivlen and iv
	buf[offset] = (REQUEST_IV_LEN >> 8) & 0xff;
	buf[offset + 1] = REQUEST_IV_LEN & 0xff;
	offset += 2;
	memcpy(buf + offset, ctx->request_iv, REQUEST_IV_LEN);
	dump_auth_buffer(buf + offset - 2, REQUEST_IV_LEN + 2, "payload iv");
	offset += REQUEST_IV_LEN;
	
	// fill devid_len and devid
	buf[offset] = (enDevid_len >> 8) & 0xff;
	buf[offset + 1] = enDevid_len & 0xff;
	offset += 2;
	memcpy(buf + offset, enDevid, enDevid_len);
	dump_auth_buffer(buf + offset - 2, enDevid_len + 2, "payload devid");
	offset += enDevid_len;

	// fill request data and len
	buf[offset] = (request_data_len >> 8) & 0xff;
	buf[offset + 1] = request_data_len & 0xff;
	offset += 2;
	memcpy(buf + offset, request_data, request_data_len);
	dump_auth_buffer(buf + offset - 2, request_data_len + 2, "payload data");

	*size = payload_size + HEADER_LEN;
	dump_auth_buffer(buf, payload_size + HEADER_LEN, "payload");
	return 0;
}

int tuya_parse_respone_data(unsigned char *respone, int respone_len)
{
	dump_auth_buffer(respone, respone_len, "recv respone");

	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	
	int type = respone[1];
	int payload_size = respone[3] << 8 | respone[4];
#ifdef TUYA_DEBUG_DUMP
	printf("type = %d, payload_size = %d\n", type, payload_size);
#endif
	unsigned char *resp_payload = respone + HEADER_LEN;
	int offset = 0;
	int respone_iv_len = (resp_payload[offset] << 8) | resp_payload[offset+1];
	char respone_iv[respone_iv_len];
	offset += 2;
	memcpy(respone_iv, resp_payload + offset, respone_iv_len);
	offset += respone_iv_len;
	dump_auth_buffer(respone_iv, respone_iv_len, "recv respone iv");

	int devid_len = resp_payload[offset] << 8 | resp_payload[offset+1];
	char devid[64];
	offset += 2;
	memcpy(devid, resp_payload + offset, devid_len);
	dump_auth_buffer(devid, devid_len, "recv devid iv");
	offset += devid_len;

	int data_len = resp_payload[offset] << 8 | resp_payload[offset+1];
	char data[256];
	offset += 2;
	memcpy(data, resp_payload + offset, data_len);
	dump_auth_buffer(data, data_len, "recv payload data");
	offset += data_len;

	char decode_respone_data[256] = {0};
	int decode_respone_data_len = sizeof(decode_respone_data);
	aes_decode_cbc128(data, data_len, decode_respone_data, &decode_respone_data_len, ctx->local_key, respone_iv);

	printf("decode_respone_data_len=%d\n", decode_respone_data_len);

	cJSON *cjson = cJSON_Parse(decode_respone_data);
    if(cjson)
    {
		printf("%s\n", cJSON_Print(cjson));

		int err = -1;
		int interval = 30;
		char random[32] = {0};
		char authorization[64];
		char resp_signature[64];
        if(cJSON_HasObjectItem(cjson, "err")){
            err = cJSON_GetObjectItemCaseSensitive(cjson, "err")->valueint;
        }
        if(cJSON_HasObjectItem(cjson, "interval"))
            interval = cJSON_GetObjectItem(cjson, "interval")->valueint;
        if(cJSON_HasObjectItem(cjson, "random"))
            strcpy(random, cJSON_GetObjectItem(cjson, "random")->valuestring);
        if(cJSON_HasObjectItem(cjson, "authorization")) {
            strcpy(authorization, cJSON_GetObjectItem(cjson, "authorization")->valuestring);
        }
        if(cJSON_HasObjectItem(cjson, "signature")) {
        	strcpy(resp_signature, cJSON_GetObjectItem(cjson, "signature")->valuestring);
        }
        cJSON_Delete(cjson);

		printf("err       = %d\n", err);
		printf("interval  = %d\n", interval);
		printf("random    = %s [%d]\n", random, strcmp(random, ctx->random) == 0);
		printf("authorization = %s\n", authorization);
		printf("signature     = %s\n", resp_signature);

		int respone_time;
		char respone_random[32];
		sscanf(authorization, "time=%d,random=%s", &respone_time, respone_random);
		char buffer[128];
		char signature[64];
		sprintf(buffer, "%s:%d:%s", ctx->encode_devid, respone_time, respone_random);
//#ifdef TUYA_DEBUG_DUMP
		printf("devid:time:random -->> %s\n", buffer);
//#endif
		calcSignature(buffer, strlen(buffer), signature, ctx->local_key);
		char b64Signature[64];
		int b64SignatureLen = sizeof(b64Signature);
		base64_encode(signature, 32, b64Signature, &b64SignatureLen);
		printf("b64Signature:%s\n", b64Signature);
		return 0;
    }

	return -1;
}


int tuya_get_keepalive_encode_device_id(char *dest_buffer, int *len)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(dest_buffer != NULL, "dest buffer invaild");
	CHECK_TUYA_EXPR_IS_FALSE(ctx->prepare == 1, "suppend need prepare first");
	CHECK_TUYA_EXPR_IS_FALSE(*len >= ctx->encode_devid_len, "buffer len is too small");

	memcpy(dest_buffer, ctx->encode_devid, ctx->encode_devid_len);

	*len = ctx->encode_devid_len;
	return ctx->encode_devid_len;
}


int tuya_get_3861_keepAlivePack(char *buf, int size)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(ctx->prepare == 1, "suppend need prepare first");
	CHECK_TUYA_EXPR_IS_FALSE(size >= ctx->wakeup_data_Len, "buffer len is too small");

	memcpy(buf, ctx->keepalive, ctx->keepalive_Len);
	dump_auth_buffer(buf, size, "tuya 3861 keepalive pack");

	return ctx->keepalive_Len;
}

int tuya_get_3861_netpattern(char *buf, int size)
{
	tuya_auth_ctx_t *ctx = &g_tuya_auth;
	CHECK_TUYA_EXPR_IS_FALSE(ctx->prepare == 1, "suppend need prepare first");

	memcpy(buf, ctx->wakeup_data, ctx->wakeup_data_Len);
    
    dump_auth_buffer(buf, size, "tuya 3861 netpattern");
	
	return ctx->wakeup_data_Len;
}

int tuya_keepalive_auth(void *iData, int iLen, void *oResult, int *oLen)
{
	dump_auth_buffer(iData, iLen, "tuya auth request respone");
	
}


int setnoblock(int fd, int blk)
{
	int opt = fcntl(fd, F_GETFL, NULL);
	if(blk) opt |= O_NONBLOCK;
	else
		opt &= ~O_NONBLOCK;
	return fcntl(fd, F_SETFL, &opt);
}
int timed_fd_wait(int fd, unsigned int ms)
{
	fd_set rfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	tv.tv_sec = ms/1000;
	tv.tv_usec = (ms%1000)*1000;
	return select(fd+1, &rfds, NULL, NULL, &tv);
}

 
int client_connect(char *serIP,in_port_t serPort)
{
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		printf("socket Error!");
		return -1;
	}
 
	struct sockaddr_in serAddr;
	memset(&serAddr, 0, sizeof(serAddr));
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(serPort);
	
	int rtn = inet_pton(AF_INET, serIP, &serAddr.sin_addr.s_addr);
	if (rtn <= 0)
	{
		printf("inet_pton Error!");
		return -2;
	}
	///serAddr.sin_addr.s_addr = htonl(serAddr.sin_addr.s_addr);
	
 	setnoblock(sock, 1);
	rtn = connect(sock, (struct sockaddr *) &serAddr, sizeof(serAddr));
	printf("------------------connect %s:%d, ret = %d [%d] \n", inet_ntoa(serAddr.sin_addr), serPort, rtn, errno);
	if(rtn == 0){
		printf("connect SUCCESS !!!\n");
	}
	if (rtn < 0) {
		if(errno == EINPROGRESS)  // EINPROGRESS表示正在建立链接
		{
			if(timed_fd_wait(sock, 20000) > 0)
			{
				int err = 0;
				socklen_t optlen = sizeof(int);
				if(getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &optlen) == 0 && err == 0)
				{
					printf("connect SUCCESS !\n");
					sleep(1);
					return sock;
				}
			}
			printf("------------------connect ret = %d [%d] \n", rtn, errno);
		}
		return rtn;
	} 

	return sock;
}

void *keepalive_thread(void *args)
{
	int sock = (int)args;
	while(1)
	{
		char keepAlivePack[32] = {0};
		int keepAlivePackLen = sizeof(keepAlivePack);
		keepAlivePackLen = tuya_get_3861_keepAlivePack(keepAlivePack, keepAlivePackLen);
		int num = send(sock, keepAlivePack, keepAlivePackLen, 0);
		if (num <= 0)
		{
			printf("Send Error!!\n");
			return -4;
		}
		
		struct sockaddr_in skaddr = {0};
		socklen_t sk_len = sizeof(skaddr);
		getpeername(sock, (struct sockaddr*) &skaddr, &sk_len );
		printf("send sock:%d ip %s:%d\n",  sock, inet_ntoa(skaddr.sin_addr), ntohs(skaddr.sin_port));
		dump_buffer(keepAlivePack, keepAlivePackLen, "send keepalvie");

		sleep(3);
	}
}

void *keepalive_recv_thread(void *args)
{
	int sock = (int)args;
	while(1)
	{
		int ret = 0;
		if((ret = timed_fd_wait(sock, 5000)) > 0)
		{
			struct sockaddr_in skaddr = {0};
			socklen_t sk_len = sizeof(skaddr);
			getpeername(sock, (struct sockaddr*) &skaddr, &sk_len );
			printf("recv sock:%d ip %s:%d\n",  sock, inet_ntoa(skaddr.sin_addr), ntohs(skaddr.sin_port));
			char buffer[128] = {0};
			int len = recv(sock, buffer, 128, 0);
			dump_buffer(buffer, len, "recv keepalvie");
		}
		else if(ret == 0)
		{
			printf("recv timeout\n");
			continue;
		}
		else
		{
			printf("recv error, exit\n");
			perror("select");
		}
		sleep(3);
	}
}


int main(int argc, char *argv[])
{
	unsigned int a = 0x12345678;
	unsigned char *p = (unsigned char *)&a;
	printf("%x\n", *p);
	if(*p == 0x78) printf("Little-Endian\n"); 
	else if(*p == 0x12) printf("Big-Endian\n"); 
	
	if(argc < 3)
	{
		fprintf(stderr, "param invalid! \n  ./client <ip> <port>\n");
		//return -1;
	} 

	char* ip = "42.192.35.108";
	int port = 443;
	char* cmd = argv[3];
	printf("ip: %s port: %d \n", ip, port);


	tuya_low_power_suppend_prepare();

	char request_payload[256] = {0};
	int request_payload_len = sizeof(request_payload);
	tuya_get_3861_auth_request_payload(request_payload, &request_payload_len);

	save_file("request.data", request_payload, request_payload_len);

	int sock = client_connect(ip, port);

	int opt = 1;
	 if(setsockopt(sock, SOL_SOCKET,SO_REUSEADDR, (const void *) &opt, sizeof(opt))){
		perror("setsockopt");
		return -1;
	}

	int num = send(sock, request_payload, request_payload_len, 0);
	if (num <= 0)
	{
		printf("Send Error!!\n");
		return -4;
	}
	dump_auth_buffer(request_payload, request_payload_len, "send auth pack");
	printf("send len = %d[%d]\n", num, request_payload_len);
	char buffer[512] = {0};
	int time_out_ms = 3000;
	int ret = timed_fd_wait(sock, time_out_ms);
	if(ret > 0)
	{
		int len = recv(sock, buffer, sizeof(buffer), 0);
		printf("recv len = %d\n", len);
		tuya_parse_respone_data(buffer, len);
		save_file("respone.data", buffer, len);
		if(sock)
		{
			pthread_t send_tid, recv_tid;
			pthread_create(&send_tid, NULL, &keepalive_thread, sock);
			pthread_create(&recv_tid, NULL, &keepalive_recv_thread, sock);
		}
	}
	else if(ret == 0)
	{
		printf("timeout:%d\n", time_out_ms);
	}
	else
	{
		perror("recv");
	}

	while(1) sleep(1);

	return 0;
}

int save_file(char *file, char *data, int size)
{
	FILE *fp = fopen(file, "wb");
	if(!fp) 
	{
		printf("open %s fail\n", file);
		return -1;
	}
	fwrite(data, size, 1, fp);;

	fclose(fp);
	return 0;
}

