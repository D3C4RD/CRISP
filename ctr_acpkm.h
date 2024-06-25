#include "kuz.h"
#include "string.h"
uint8_t D1[16] = {
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F 
};
uint8_t D2[16] = {
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F
};

void copy(uint8_t a[], uint8_t b[], int n)
{
	for (int i = 0; i < n; i++)
	{
		a[i] = b[i];
	}
}

void ACPKM(uint8_t* key)
{
	uint8_t keys[10][BLOCK_SIZE];
	get_keys(key);
	uint8_t k1[16];
	copy(k1, D1, 16);
	uint8_t k2[16];
	copy(k2, D2, 16);
	E(k1);
	E(k2);
	copy(key, k1, 16);
	copy(key + 16, k2, 16);
}

void inc(uint8_t* a)
{
	for (int i = 0; i < 16; i++)
	{
		a[i]++;
		if (a[i] != 0)
		{
			break;
		}
	}
}

void x(uint8_t a[],uint8_t b[],int n)
{
	for(int i=0;i<n;i++)
	{
		a[i]^=b[i];
	}
}

void mode(uint8_t a[], uint8_t b[], uint8_t key[],int n)
{
	uint8_t temp[16];
	copy(temp, b, 16);
	get_keys(key);
	E(temp);
	x(a,temp,n);
	inc(b);
	//rint_rev(b);
}

int cript(uint8_t mes[],int len,uint8_t IV[16],uint8_t key[])
{
    if(len>1974)
    {
        printf("Message too long\n");
        return 0;
    }
    int i=0;
    for(i=0;i<len/16;i++)
    {
        mode(mes+(i*16),IV,key,16);
    }
    if(len%16!=0)
    {
        mode(mes+(16*i),IV,key,len%16);
    }
	return 1;
}