#include "ctr_acpkm.h"
#include "kdf_tree.h"
#include <string.h>
#include <stdlib.h>

void incSeqNum(uint8_t a[6])
{
	for (int i = 5; i >= 0; i--)
	{
		a[i]++;
		if (a[i] != 0)
		{
			break;
		}
	}
}

void getIV(uint8_t IV[16],uint8_t SeqNum[6])
{
    zero(IV,16);
    copy_s(SeqNum,0,IV,0,6);
}

int form_arr(uint8_t arr[],uint8_t mes[],int len,uint8_t SeqNum[6],uint8_t key[32])
{
    arr[0]=0x80; //ExternalKeyIdFlag=1 Version=000000000000000_2
    arr[1]=0x00; //
    arr[2]=0xF8; //CS
    arr[3]=0x80; //KeyId=10000000_2
    copy_s(SeqNum,0,arr,4,6); //SeqNUM
    uint8_t IV[16];
    getIV(IV,SeqNum);
    cript(mes,len,IV,key);
    copy_s(mes,0,arr,10,len); //payload
    uint8_t h[64];
    get512(arr,10+len,h);
    copy_s(h,0,arr,10+len,64);  //ICV 
    incSeqNum(SeqNum);
    return 1;
}

void get_key(uint8_t key[32],uint8_t pass[],int len)
{
    kdf_tree(key,pass,len,1,256);
}
