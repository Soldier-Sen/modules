#ifndef __eh_crypt_h__
#define __eh_crypt_h__

#include "crypto.h"


#define _dbg	printf
#define _info 	printf
#define _warning(fmt, args...)	printf
#define _err(fmt, args...)		printf


/** 
 * @name DES加解密接口
 * @{ 
 */

/** DES加密功能接口
 * DesEncrypt -> Des encrypt, function's caller need call free(*out) to free buffer.
 * \param in 		待加密数据指针。
 * \param inLen 	待加密数据长度。
 * @inLen:	 	input data len. 
 * @out:		des encrypt's data, output.
 * @outLen:		output data len.
 * @key:		des crypt key.
 * @retval       0 ok
 * @retval       < 0 failed
 */
int DesEncrypt(unsigned char *in, int inLen, unsigned char **out, int *outLen, unsigned char *key);

/** DES解密功能接口
 * DesDecrypt -> Des decrypt, function's caller need call free(*out) to free buffer.
 * @in:	 		input data buf address, data to decrypt.
 * @inLen:	 	input data len. 
 * @out:		des decrypt's data, output.
 * @outLen:		output data len.
 * @key:		des crypt key.
 * @retval       0 ok
 * @retval       < 0 failed
 */
int DesDecrypt(unsigned char *in, int inLen, char **out, int *outLen, unsigned char *key);


int DesEncryptInPlace(unsigned char *in, int *dataLen, unsigned char *key);
int desEncryptInPlace(unsigned char *in, int inLen, int *paddingLen, unsigned char *key);

/**@}*/



/** 
 * @name base64编码/解码
 * @{ 
 */
 
/** 获取base64解码需要的buffer大小。
 * 返回解码需要的buffer大小，单位byte.
 * \param src 	base64编码的数据。
 * \param slen 	base64编码的数据长度。
 * \return > 0 解码需要的buffer大小; -1 输入参数错误。
 */
int base64_decode_len(const unsigned char *src, int slen);

/** base64解码。
 * \param dst   存放base64解码需要的buffer。
 * \param dlen  base64解码的buf的大小，调用完成会被修改为实际写入的字节数。
 * \param src   base64编码的数据。
 * \param slen  base64编码的数据长度。
 * \return 0 成功; < 0 失败。
 */
int base64_decode(unsigned char *dst, int *dlen, const unsigned char *src, int slen);

/** 获取base64编码需要的buffer大小。
 * 返回编码需要的buffer大小，单位byte.
 * \param src 	待base64编码的原数据。
 * \param slen 	待base64编码的原数据长度。
 * \return > 0 解码需要的buffer大小; -1 输入参数错误。
 */
int base64_encode_len(const unsigned char *src, int slen);

/** base64解码。
 * \param dst   存放base64解码需要的buffer。
 * \param dlen  base64解码的buf的大小，调用完成会被修改为实际写入的字节数。
 * \param src   base64编码的数据。
 * \param slen  base64编码的数据长度。
 * \return 0 成功; < 0 失败。
 */
int base64_encode(const unsigned char *src, int slen, unsigned char *dst, int *dlen);

/**@}*/


#define AES_128_KEY_LEN  16		///< AES CBC 128 密钥长度
#define AES_256_KEY_LEN  32		///< AES CBC 256 密钥长度

#define AES_BLOCK_SIZE	16		///< AES CBC 128数据块16字节对齐

/** AES CBC 128加密，nopadding填充方式。
 * \param in   	 待加密的数据buffer。
 * \param inLen  待加密的数据大小。
 * \param out    加密后的数据写入此buf。建议大小(inLen/AES_BLOCK_SIZE + 1)*AES_BLOCK_SIZE.
 * \param oLen   真实输出的加密数据长度。
 * \param key    对称密钥。
 * \param pIv    16字节的向量。
 * \return 0 成功; < 0 失败。
 */
int Aes_Encode_Cbc128(unsigned char *in, int inLen, unsigned char *out, int *oLen, char *key, const char *pIv);

/** AES CBC 128解密，nopadding填充方式。
 * \param in   	 待解密的数据buffer。
 * \param inLen  待解密的数据大小。
 * \param out    解密后的数据写入此buf。建议大小 = inLen.
 * \param oLen   真实输出的解密数据长度。
 * \param key    对称密钥。
 * \param pIv    16字节的向量。
 * \return 0 成功; < 0 失败。
 */
int Aes_Decode_Cbc128(unsigned char *in, int inLen, unsigned char *out, int *oLen, char *key, const char *pIv);


/** 获取文件MD5值。
 * \param fileName   待求MD5值的文件名，包括完整路径。
 * \param md5sum  	 返回的MD5值, 32位小写。
 * \return 0 成功; < 0 失败。
 */
int MD5File(char *fileName, char *md5sum);


#endif
