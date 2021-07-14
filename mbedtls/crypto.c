#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include <mbedtls/md.h>
#include "mbedtls/md5.h"
#include <math.h>
#include "crypto.h"


#define DES_BLOCK_SIZE 8

//原地加密
int DesEncryptInPlace(unsigned char *in, int *dataLen, unsigned char *key)
{
    int i = 0;
    int ret = -1;
    unsigned char iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    mbedtls_des_context des_ctx;
    unsigned char *in_cursor = in;
    unsigned char out_split[DES_BLOCK_SIZE] = {0};
    int inLen = *dataLen;
    if(!in || !dataLen || !key){
        printf("DesEncryptInPlace input param err!\n");
        return -1;
    }
    unsigned char block[DES_BLOCK_SIZE];
    int block_num = (inLen / DES_BLOCK_SIZE) + 1;
    int outLen = block_num * DES_BLOCK_SIZE;

    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_enc(&des_ctx, key);	
    int padding = DES_BLOCK_SIZE - (inLen % DES_BLOCK_SIZE);
    //_dbg("key:%s, padding:%d, inLen:%d, outLen:%d\n", key, padding, inLen, outLen);
    for(i = padding; i > 0; i--){ printf("%02x", in[outLen - i]); } printf("\n");
    memset(in_cursor + inLen, padding, padding);
    for(i = 0; i < block_num; i++)
    {
        memcpy(block, in_cursor, DES_BLOCK_SIZE);
        ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, DES_BLOCK_SIZE, iv, block, out_split);
        if(ret)
        {
            mbedtls_des_free(&des_ctx);
            return ret;
        }
        memcpy(in_cursor, out_split, DES_BLOCK_SIZE);
        in_cursor += DES_BLOCK_SIZE;
    }
    mbedtls_des_free(&des_ctx);
    *dataLen = outLen;
    return ret;
}

int desEncryptInPlace(unsigned char *in, int inLen, int *paddingLen, unsigned char *key)
{
    int i = 0;
    int ret = -1;
    unsigned char iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    mbedtls_des_context des_ctx;
    unsigned char *in_cursor = in;
    unsigned char out_split[DES_BLOCK_SIZE] = {0};

    if(!in || !paddingLen || !key){
        printf("desEncryptInPlace input param err!\n");
        return -1;
    }
    unsigned char block[DES_BLOCK_SIZE];
    int block_num = (inLen / DES_BLOCK_SIZE) + 1;
    int outLen = block_num * DES_BLOCK_SIZE;

    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_enc(&des_ctx, key);	
    int padding = outLen - inLen;
    //_dbg("padding:%d,inLen:%d,outLen:%d,end value:[%02x] addr:[%p]\n",padding, inLen, outLen,in_cursor[outLen - 1], &in_cursor[outLen - 1]);
    *paddingLen = padding;
    memset(in_cursor + inLen, padding, padding);
    printf("%p, padding:%d, padding data:%02x",&in_cursor[outLen -1], padding, in_cursor[outLen -1]);
    for(i = 0; i < block_num; i++)
    {
        memcpy(block, in_cursor, DES_BLOCK_SIZE);
        ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, DES_BLOCK_SIZE, iv, block, out_split);
        if(ret)
        {
            mbedtls_des_free(&des_ctx);
            return ret;
        }
        memcpy(in_cursor, out_split, DES_BLOCK_SIZE);
        in_cursor += DES_BLOCK_SIZE;
    }

    mbedtls_des_free(&des_ctx);
    return ret;
}

#if 1
int _DesEncryptInPlace(unsigned char *in, int inLen, unsigned char **wrapOut, int *wrapOutLen, unsigned char *key)
{
    int i = 0;
    int ret = -1;
    unsigned char iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    mbedtls_des_context des_ctx;

    if(!in || !wrapOut || !wrapOutLen){
        printf("input param err!\n");
        return -1;
    }

    unsigned char block[DES_BLOCK_SIZE];
    int normal_block_length = (inLen / DES_BLOCK_SIZE);

    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_enc(&des_ctx, key);	

    unsigned char *in_cursor = in;
    *wrapOutLen = (normal_block_length+1)*DES_BLOCK_SIZE - inLen;
    *wrapOut = (unsigned char *)malloc(*wrapOutLen);

    unsigned char out_split[DES_BLOCK_SIZE] = {0};
    for(i = 0; i < normal_block_length; i++)
    {
        memcpy(block, in_cursor, DES_BLOCK_SIZE);
        ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, DES_BLOCK_SIZE, iv, block, out_split);
        if(ret){
            mbedtls_des_free(&des_ctx);
            free(*wrapOut);
            return ret;
        }
        memcpy(in_cursor, out_split, DES_BLOCK_SIZE);
        in_cursor += DES_BLOCK_SIZE;
    }

    int padding = DES_BLOCK_SIZE - (inLen % DES_BLOCK_SIZE);
    if(padding != DES_BLOCK_SIZE){
        memcpy(block, in_cursor, inLen % DES_BLOCK_SIZE);
    }
    memset(block + inLen % DES_BLOCK_SIZE, padding, padding);
    ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, DES_BLOCK_SIZE, iv, block, out_split);

    if(padding != DES_BLOCK_SIZE){
        memcpy(in_cursor, out_split, inLen % DES_BLOCK_SIZE);
        in_cursor += inLen % DES_BLOCK_SIZE;
    }

    memcpy(*wrapOut, out_split + (inLen % DES_BLOCK_SIZE) , *wrapOutLen);


    mbedtls_des_free(&des_ctx);
    printf("padding:%d\n", padding);

    return ret;
}
#endif
int DesEncrypt(unsigned char *in, int inLen, unsigned char **out, int *outLen, unsigned char *key)
{
    unsigned char iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    mbedtls_des_context des_ctx;

    if(!in || !out || !outLen){
        printf("input param err!\n");
        return -1;
    }
    unsigned char block[DES_BLOCK_SIZE];

    int normal_block_length = (inLen / DES_BLOCK_SIZE);
    *outLen = (normal_block_length+1)*DES_BLOCK_SIZE;
    int i = 0;
    int ret;

    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_enc(&des_ctx, key);	

    unsigned char *in_cursor = in;
    *out = (unsigned char *)malloc((normal_block_length+1)*DES_BLOCK_SIZE);
    unsigned char *out_cursor = *out;
    for(i = 0; i < normal_block_length; i++)
    {
        memcpy(block, in_cursor, DES_BLOCK_SIZE);
        ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, DES_BLOCK_SIZE, iv, block, out_cursor);
        if(ret){
            mbedtls_des_free(&des_ctx);
            free(*out);
            return ret;
        }
        in_cursor += DES_BLOCK_SIZE;
        out_cursor += DES_BLOCK_SIZE;
    }

    int padding = DES_BLOCK_SIZE - (inLen % DES_BLOCK_SIZE);
    if(padding != DES_BLOCK_SIZE){
        memcpy(block, in_cursor, inLen % DES_BLOCK_SIZE);
    }
    memset(block + inLen % DES_BLOCK_SIZE, padding, padding);
    ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_ENCRYPT, DES_BLOCK_SIZE, iv, block, out_cursor);
    mbedtls_des_free(&des_ctx);
    //_dbg("padding:%d\n", padding);
    //_dbg(" ====> After DES Data: data[0]=%d, data[1]=%d, data[n-1]=%d, data[n-2]=%d,", (*out)[0], (*out)[1], (*out)[*outLen-2], (*out)[*outLen-1]);

    return ret;
}


int DesDecrypt(unsigned char *in, int inLen, char **out, int *outLen, unsigned char *key)
{
    int padding = 0;
    unsigned char iv[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    if(!in || !out || !outLen){
        printf("input param err!\n");
        return -1;
    }
    //_dbg(" ====> Before DES Decode Data: data[0]=%d, data[1]=%d, data[n-1]=%d, data[n-2]=%d,", in[0], in[1], in[inLen-2], in[inLen-1]);
    unsigned char *data = (unsigned char *)malloc(inLen);
    if(!data){printf("DesDecrypt malloc failed !\n");return -1;}
    mbedtls_des_context des_ctx;
    mbedtls_des_init(&des_ctx);
    mbedtls_des_setkey_dec(&des_ctx, key);
    int ret = mbedtls_des_crypt_cbc(&des_ctx, MBEDTLS_DES_DECRYPT, inLen, iv, in, data);
    mbedtls_des_free(&des_ctx);
    if(ret){
        printf("DES DECODE ERROR: %d\n", ret);
        return ret;
    }
    padding = (int)data[inLen - 1];
    //_dbg("padding:%d\n", padding);
    *outLen = inLen - padding;
    *out = data;
    return ret;
}


///< base64解码
int base64_decode_len(const unsigned char *src, int slen)
{
	int olen = 0;
	if(mbedtls_base64_decode(NULL, 0, &olen, src, slen) != 0)
		return -1;
	return olen;
}
int base64_decode(unsigned char *dst, int *dlen, const unsigned char *src, int slen)
{
	int olen = 0;
	int ret = mbedtls_base64_decode(dst, *dlen, &olen, src, slen);
	*dlen = olen;
	if(ret == 0) 
		return 0;
	else if(ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
		_err("dest buffer is too small\n");
	else
		_err("Invalid character in input\n");
	return ret;
}

///< base64编码
int base64_encode_len(const unsigned char *src, int slen)
{
	int olen = 0;
	int ret = mbedtls_base64_encode(NULL, 0, &olen, src, slen);

	return olen;
}
int base64_encode(const unsigned char *src, int slen, unsigned char *dst, int *dlen)
{
	int olen = *dlen;
	int ret = mbedtls_base64_encode(dst, dlen, &olen, src, slen);
	*dlen = olen;
	if(ret == 0) 
		return 0;
	else if(ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
		_err("dest buffer is too small\n");
	else
		_err("Invalid character in input\n");
	return ret;	
}


///< AES加密，nopadding方式
int aes_encode_cbc128(unsigned char *in, int inLen, unsigned char *out, int *oLen, unsigned char *key, const unsigned char *pIv)
{
	if(!in || !out || !oLen || !key || !pIv){
		_err("input param is null\n");
		return -1;
	}

	char iv[16];
	memcpy(iv, pIv, 16);

	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	
	int ret = mbedtls_aes_setkey_enc(&ctx, key, AES_128_KEY_LEN*8);
	if(ret == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH){
		_err("Invalid key length\n");
		mbedtls_aes_free(&ctx);
		return -1;
	}
	int i = 0;
	unsigned char in_block[AES_BLOCK_SIZE];
	unsigned char out_block[AES_BLOCK_SIZE];
	int block_num = inLen / AES_BLOCK_SIZE;

	*oLen = (block_num + 1) * AES_BLOCK_SIZE;
	
	int padding_len = *oLen - inLen;
	char *in_cucrsor = in;
	char *out_cucrsor = out;
	/// 处理16字节对齐的buf数据
	for(i = 0; i < block_num; i++)
	{
		memcpy(in_block, in_cucrsor, AES_BLOCK_SIZE);
		ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, AES_BLOCK_SIZE, iv, in_block, out_block);
		if(ret == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH){
			_err("Invalid data input length\n");
			mbedtls_aes_free(&ctx);
			return -1;
		}
		memcpy(out_cucrsor, out_block, AES_BLOCK_SIZE);
		out_cucrsor += AES_BLOCK_SIZE;
		in_cucrsor += AES_BLOCK_SIZE;
	}
	///处理末尾非16字节的数据对齐，补充对齐。
    if(padding_len != AES_BLOCK_SIZE){
        memcpy(in_block, in_cucrsor, inLen % AES_BLOCK_SIZE);
    }
    memset(in_block + inLen % AES_BLOCK_SIZE, padding_len, padding_len);
#if 0    
	printf("last block: ");
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		//if(i%25 == 0)printf("\n");
		printf("%02X ", in_block[i]);
	}
	printf("\n");
#endif
	mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, AES_BLOCK_SIZE, iv, in_block, out_block);
	memcpy(out_cucrsor, out_block, AES_BLOCK_SIZE);
	
	mbedtls_aes_free(&ctx);
#if 0
	printf("aes_encode_cbc128, oLen=%d, padding_len=%d\n", *oLen, padding_len);
	for (i = 0; i < *oLen; i++) {
		if(i%25 == 0)printf("\n");
		printf("%02X ", out[i]);
	}
	printf("\n\n");
#endif
	return 0;
}
///< AES加密, nopadding方式
int aes_decode_cbc128(unsigned char *in, int inLen, unsigned char *out, int *oLen, char *key, const char *pIv)
{
	char iv[16];
	memcpy(iv, pIv, 16);
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);

	int ret = mbedtls_aes_setkey_dec(&ctx, key, AES_128_KEY_LEN*8);
	if(ret == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH){
		_err("Invalid key length\n");
		return -1;	
	}

	int i = 0;
	unsigned char in_block[AES_BLOCK_SIZE];
	unsigned char out_block[AES_BLOCK_SIZE];
	int block_num = inLen / AES_BLOCK_SIZE;

	*oLen = inLen;
	
	int padding_len = 0;
	char *in_cucrsor = in;
	char *out_cucrsor = out;
	/// 处理16字节对齐的buf数据
	for(i = 0; i < block_num; i++)
	{
		memcpy(in_block, in_cucrsor, AES_BLOCK_SIZE);
		ret = mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, AES_BLOCK_SIZE, iv, in_block, out_block);
		if(ret == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH){
			_err("Invalid data input length\n");
			mbedtls_aes_free(&ctx);
			return -1;
		}
		memcpy(out_cucrsor, out_block, AES_BLOCK_SIZE);
		out_cucrsor += AES_BLOCK_SIZE;
		in_cucrsor += AES_BLOCK_SIZE;
	}
	padding_len = (int)out[inLen - 1];
	*oLen = *oLen - padding_len;
	out[*oLen] = 0;
#if 0	
	printf("aes_decode_cbc128 padding_len = %d, oLen = %d\n", padding_len, *oLen);
	///处理末尾非16字节的数据对齐，补充对齐。
	if(padding_len % AES_BLOCK_SIZE != 0)
	{
		memset(in_block, 0x0, AES_BLOCK_SIZE);
		memcpy(in_block, in_cucrsor, AES_BLOCK_SIZE - padding_len);
		mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, AES_BLOCK_SIZE, iv, in_block, out_block);
		memcpy(out_cucrsor, out_block, AES_BLOCK_SIZE);
	}
	
	///获取真实数据长度
	i = *oLen - 1;
	int k = 0;
	while(out[i--] == 0) k++;
	*oLen = *oLen - k;
	//_info("out:%s, olen=[%d]\n", out, *oLen);
#endif
	mbedtls_aes_free(&ctx);
	return 0;
}

///< 获取data中数据的MD5值
int MD5Data(char *data, int len, char *md5sum)
{
	if(!data || !len || !md5sum){
		_err("input param is null or len = 0");
		return -1;
	}

	unsigned char digest[16] = {0};
	char buf[2048] = {0};
	mbedtls_md5_context md5_ctx;
	mbedtls_md5_init(&md5_ctx);
	mbedtls_md5_starts_ret(&md5_ctx);
	int updata_len = 0;
	int buffer_len = sizeof(buf);
	if(buffer_len > len)
	{
		mbedtls_md5_update_ret(&md5_ctx, data, len);
	}
	else
	{
#if 0
		while(updata_len >= len)
		{
			memcpy(buf, data + updata_len, buffer_len);
			mbedtls_md5_update_ret(&md5_ctx, buf, buffer_len);
			updata_len += buffer_len;
		}
#endif
	}
	mbedtls_md5_finish_ret(&md5_ctx, digest);
	mbedtls_md5_free(&md5_ctx);
	int i;
	for(i = 0; i< sizeof(digest); i++)
	{
		 sprintf(&md5sum[i*2], "%02x", digest[i]);
	}
	_info("md5sum:%s\n", md5sum);	
}

///< 获取文件MD5值
int MD5File(char *fileName, char *md5sum)
{
	if(!fileName || !md5sum){
		_err("input param is null");
		return -1;
	}
	
	int read_len = 0;
	FILE *fp = fopen(fileName, "rb");
	if(!fp){_err("fopen %s fail !", fileName);return -1;}

	unsigned char digest[16] = {0};
	char buf[2048] = {0};
	mbedtls_md5_context md5_ctx;
	mbedtls_md5_init(&md5_ctx);
	mbedtls_md5_starts_ret(&md5_ctx);
	while((read_len = fread(buf, 1, sizeof(buf), fp)) > 0){
		mbedtls_md5_update_ret(&md5_ctx, buf, read_len);
	}
	fclose(fp);
	mbedtls_md5_finish_ret(&md5_ctx, digest);
	mbedtls_md5_free(&md5_ctx);
	int i;
	for(i = 0; i< sizeof(digest); i++)
	{
		 sprintf(&md5sum[i*2], "%02x", digest[i]);
	}
	return 0;
}

int calcSignature(const char *message, int msg_len, char *signature, const char *key)
{
    mbedtls_md_context_t md_ctx;
    unsigned char digest[40] = {0};
    /* hmac-sha256 */
    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&md_ctx, (const unsigned char*)key, strlen((const char*)key));

    mbedtls_md_hmac_update(&md_ctx, (const unsigned char*)message, msg_len);

    mbedtls_md_hmac_finish(&md_ctx, digest);
    mbedtls_md_free(&md_ctx);

	memcpy(signature, digest, 32);
    //int i = 0;
    //for(i = 0; i < 32; i++) sprintf(&signature[i*2], "%02x", digest[i]);
    return 0;
}

