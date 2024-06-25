#include "stribog.h"

void Hmac256(uint8_t ret[],uint8_t K[],int Klen,uint8_t T[],int Tlen)
{
    uint8_t tK[64];
    zero(tK,64);
    copy_s(K,0,tK,0,Klen);
    //printf("padded key=\n\t");
    //print_arr(tK,64);
    uint8_t ipad[64];
    uint8_t opad[64];
    for(int i=0;i<64;i++)
    {
        ipad[i]=0x36;
        opad[i]=0x5C;
    }
    unsigned int ilen=64+Tlen;
    //printf("ilen=%d\n",ilen);
    uint8_t inner[ilen];
    XX(tK,ipad);
    copy_s(tK,0,inner,0,64);
    copy_s(T,0,inner,64,Tlen);
    //printf("inner=\n\t");
    //print_arr(inner,ilen);
    XX(tK,ipad);
    uint8_t innerh[32];
    zero(innerh,32);
    reverse(inner,ilen);
    get256(inner,ilen,innerh);
    //printf("innerh=\n\t");
    //print_arr(innerh,32);
    reverse(innerh,32);
    uint8_t outer[96];
    XX(tK,opad);
    copy_s(tK,0,outer,0,64);
    copy_s(innerh,0,outer,64,32);
    //printf("outer=\n\t");
    //print_arr(outer,96);
    reverse(outer,96);
    zero(ret,32);
    get256(outer,96,ret);
    reverse(ret,32);
    //print_arr(ret,32);
}

int test_hmac()
{
    uint8_t K[32]=
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t T[16]=
    {
        0x01, 0x26, 0xbd, 0xb8, 0x78, 0x00, 0xaf, 0x21,
		0x43, 0x41, 0x45, 0x65, 0x63, 0x78, 0x01, 0x00
    };
    uint8_t ret[32];
    uint8_t t[32]=
    {
        0xa1, 0xaa, 0x5f, 0x7d, 0xe4, 0x02, 0xd7, 0xb3,
        0xd3, 0x23, 0xf2, 0x99, 0x1c, 0x8d, 0x45, 0x34,
        0x01, 0x31, 0x37, 0x01, 0x0a, 0x83, 0x75, 0x4f,
        0xd0, 0xaf, 0x6d, 0x7c, 0xd4, 0x92, 0x2e, 0xd9
    };
    zero(ret,32);
    test_stribog();
    Hmac256(ret,K,32,T,16);
    
    printf("HMAC256 test:\n\t");
    print_arr(ret,32);
    if(!cmp(ret,t,32))
    {
        printf("test failed\n");
        return 0;
    }
    printf("test valid\n");
    return 1;
}