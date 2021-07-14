#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <cjson/cJSON.h>

void parse_client_feature_reqest(char *inString, char *outString)
{
	char *out;
	char uuid[16];
	cJSON *json, *body;
	
	json = cJSON_Parse(inString);
	if (json)
	{
		out = cJSON_Print(json);
		printf("%s\n",out); free(out);
		if(cJSON_HasObjectItem(json, "uuid"))
			strcpy(uuid, cJSON_GetObjectItem(json, "uuid")->string);

		cJSON *data = cJSON_GetObjectItem(json, "feature");
		int i, nItems = cJSON_GetArraySize(data);

		body = cJSON_CreateObject();
		cJSON_AddStringToObject(body, "uuid", uuid);
		cJSON *feature = cJSON_AddObjectToObject(body, "feature");
		for(i = 0; i < nItems; i++)
		{
			char *key = cJSON_GetArrayItem(data, i)->valuestring;
			//printf("i=%d, %s\n", i, key);
			char buf[16] = {0};
			//get_device_feature(key, buf, sizeof(buf));
			cJSON_AddStringToObject(feature, key, buf);
		}
		cJSON *set = cJSON_AddObjectToObject(body, "setting");
		data = cJSON_GetObjectItem(json, "setting");
		nItems = cJSON_GetArraySize(data);
		for(i = 0; i < nItems; i++)
		{
			char *key = cJSON_GetArrayItem(data, i)->valuestring;
			//printf("i=%d, %s\n", i, key);
			char buf[16] = {0};
			//get_device_feature(key, buf, sizeof(buf));
			cJSON_AddStringToObject(set, key, buf);
		}		
		cJSON_Delete(json);
		outString = cJSON_Print(body);
		cJSON_Delete(body);
		printf("%s\n", outString);
		
	}
}

void add_object_to_object()
{
	cJSON *body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "uuid", "123456789");
	cJSON *feature = cJSON_AddObjectToObject(body, "feature");
	cJSON_AddStringToObject(feature, "1111", "111000");
	cJSON_AddStringToObject(feature, "2222", "222000");

	printf("%s\n", cJSON_Print(body));

	return 0;
}
void add_array_to_object()
{
	cJSON *body = cJSON_CreateObject();
	cJSON_AddStringToObject(body, "uuid", "123456789");
	cJSON *feature = cJSON_AddArrayToObject(body, "feature");
	cJSON_AddStringToObject(feature, "1111", "111000");
	cJSON_AddStringToObject(feature, "2222", "222000");

	printf("%s\n", cJSON_Print(body));
	
}
void create_wifi_req()
{
	cJSON *body = cJSON_CreateObject();
	cJSON *wifi = cJSON_AddObjectToObject(body, "GET_WIFI_REQ");
	cJSON *ssid_array = cJSON_AddArrayToObject(wifi, "WifiSSID");
	cJSON *ssid = cJSON_AddObjectToObject(ssid_array, "WifiSSID");
	cJSON_AddStringToObject(ssid, "SSID", "111000");
	cJSON_AddNumberToObject(ssid, "Signal", 2);
	cJSON_AddNumberToObject(ssid, "InUse", 1);
	cJSON_AddNumberToObject(ssid, "Security", 2);

	ssid = cJSON_AddObjectToObject(ssid_array, "WifiSSID");
	cJSON_AddStringToObject(ssid, "SSID", "1111111");
	cJSON_AddNumberToObject(ssid, "Signal", 0);
	cJSON_AddNumberToObject(ssid, "InUse", 0);
	cJSON_AddNumberToObject(ssid, "Security", 1);


	cJSON_AddStringToObject(wifi, "Result", "成功");
	cJSON_AddNumberToObject(wifi, "code", 0);
	cJSON_AddStringToObject(wifi, "msg", "成功");
	printf("%s\n", cJSON_Print(body));
}

void create_request_data(int type, int method, char *auth, char *sinature)
{
	char date[32];

	
	cJSON *data = cJSON_CreateObject();

    cJSON_AddNumberToObject(data, "type", type);
    cJSON_AddNumberToObject(data, "method", method);
	cJSON_AddStringToObject(data, "authorization", auth);
	cJSON_AddStringToObject(data, "sinature", sinature);

	char *body = cJSON_Print(data);
	printf("len:%d\n%s\n", strlen(body), cJSON_Print(data));

	cJSON_Delete(data);
	free(body);
}

cJSON *create_respone_data(void)
{
	char date[32];

	char random[32 + 1] = "fa37JncCHryDsbzayy4cBWDxS22JjzhM";
	char sinature[64] = "nZf2WGzVWXSwXhdDXz8B8UsNYAgqRjhDdYB/ecO+N8c=";
	char auth[128] = {0};
	cJSON *data = cJSON_CreateObject();

	sprintf(auth, "time=%d,random=%s", time(NULL), random);
	cJSON_AddNumberToObject(data, "err", 0);
    cJSON_AddNumberToObject(data, "interval", 60);
    cJSON_AddStringToObject(data, "random", random);
	cJSON_AddStringToObject(data, "authorization", auth);
	cJSON_AddStringToObject(data, "sinature", sinature);

	char *body = cJSON_Print(data);
	printf("len:%d\n%s\n", strlen(body), cJSON_Print(data));

	//cJSON_Delete(data);
	return data;
}


int test_create_request_data(void)
{
	int type = 1;
	int method = 1;
	char auth[] = "111";
	char sinature[64] = "nZf2WGzVWXSwXhdDXz8B8UsNYAgqRjhDdYB/ecO+N8c=";

	create_request_data(type, method, auth, sinature);
}

int test_parse_respone_data(void)
{
	int err;
	int interval;
	char random[32+1];
	char authorization[64];
	char sinature[64];
	
	cJSON *data = create_respone_data();
    if(data)
    {
        if(cJSON_HasObjectItem(data, "err")){
            err = cJSON_GetObjectItemCaseSensitive(data, "err")->valueint;
        }
        if(cJSON_HasObjectItem(data, "interval"))
            interval = cJSON_GetObjectItem(data, "interval")->valueint;
        if(cJSON_HasObjectItem(data, "random"))
            strcpy(random, cJSON_GetObjectItem(data, "random")->valuestring);
        if(cJSON_HasObjectItem(data, "authorization")) {
        	strcpy(authorization, cJSON_GetObjectItem(data, "authorization")->valuestring);
        }
        if(cJSON_HasObjectItem(data, "sinature")) {
            strcpy(sinature, cJSON_GetObjectItem(data, "sinature")->valuestring);
        }

        cJSON_Delete(data);
    }
    printf("err      = %d\n"
    	   "interval = %d\n"
    	   "random   = %s\n"
    	   "authorization = %s\n"
    	   "sinature      = %s\n", 
    	   err, interval, random, authorization, sinature);
}

int main(int argc, char *argv[])
{	
	test_create_request_data(); 
	test_parse_respone_data();
	return 0;
	create_wifi_req(); return 0;
	add_array_to_object();//return 0;
	return 0;
}


