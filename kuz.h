#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#define BLOCK_SIZE 16

uint8_t PI[256] = {
	252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240, 219, 147,
46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66,
139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11,237, 152, 127, 212, 211,31,235, 52, 44, 81,
234, 200, 72, 171,242, 42, 104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19,
71, 156, 183, 93, 135, 21,161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50,
117, 25, 61,255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67,
201,215, 121,214, 246, 124, 34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78,
51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39,
94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228,
136, 217, 231, 137, 225, 27, 131,73, 76, 63, 248, 254, 141,83, 170, 144, 202, 216, 133, 97, 32, 113,
103, 164, 45, 43, 9, 91,203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180, 192,
209, 102, 175, 194, 57, 75, 99, 182
};

uint8_t revPI[256] = {
	 0xA5, 0x2D, 0x32,  0x8F, 0x0E, 0x30, 0x38,  0xC0,
0x54,  0xE6,  0x9E, 0x39, 0x55, 0x7E, 0x52,  0x91,
0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
0x21, 0x72,  0xA8,  0xD1, 0x29,  0xC6,  0xA4, 0x3F,
 0xE0, 0x27,  0x8D, 0x0C,  0x82,  0xEA,  0xAE,  0xB4,
 0x9A, 0x63, 0x49,  0xE5, 0x42,  0xE4, 0x15,  0xB7,
 0xC8, 0x06, 0x70,  0x9D, 0x41, 0x75, 0x19,  0xC9,
 0xAA,  0xFC, 0x4D,  0xBF, 0x2A, 0x73,  0x84,  0xD5,
 0xC3,  0xAF, 0x2B,  0x86,  0xA7,  0xB1,  0xB2, 0x5B,
0x46,  0xD3,  0x9F,  0xFD,  0xD4, 0x0F,  0x9C, 0x2F,
 0x9B, 0x43,  0xEF,  0xD9, 0x79,  0xB6, 0x53, 0x7F,
 0xC1,  0xF0, 0x23,  0xE7, 0x25, 0x5E,  0xB5, 0x1E,
 0xA2,  0xDF,  0xA6,  0xFE,  0xAC, 0x22,  0xF9,  0xE2,
0x4A,  0xBC, 0x35,  0xCA,  0xEE, 0x78, 0x05, 0x6B,
0x51,  0xE1, 0x59,  0xA3,  0xF2, 0x71, 0x56, 0x11,
0x6A,  0x89,  0x94, 0x65,  0x8C,  0xBB, 0x77, 0x3C,
0x7B, 0x28,  0xAB,  0xD2, 0x31,  0xDE,  0xC4, 0x5F,
 0xCC,  0xCF, 0x76, 0x2C,  0xB8,  0xD8, 0x2E, 0x36,
 0xDB, 0x69,  0xB3, 0x14,  0x95,  0xBE, 0x62,  0xA1,
0x3B, 0x16, 0x66,  0xE9, 0x5C, 0x6C, 0x6D,  0xAD,
0x37, 0x61, 0x4B,  0xB9,  0xE3,  0xBA,  0xF1,  0xA0,
 0x85,  0x83,  0xDA, 0x47,  0xC5,  0xB0, 0x33,  0xFA,
 0x96, 0x6F, 0x6E,  0xC2,  0xF6, 0x50,  0xFF, 0x5D,
 0xA9,  0x8E, 0x17, 0x1B,  0x97, 0x7D,  0xEC, 0x58,
 0xF7, 0x1F,  0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
0x45,  0x87,  0xDC,  0xE8, 0x4F, 0x1D, 0x4E, 0x04,
 0xEB,  0xF8,  0xF3, 0x3E, 0x3D,  0xBD,  0x8A,  0x88,
 0xDD,  0xCD, 0x0B, 0x13,  0x98, 0x02,  0x93,  0x80,
 0x90,  0xD0, 0x24, 0x34,  0xCB,  0xED,  0xF4,  0xCE,
 0x99, 0x10, 0x44, 0x40,  0x92, 0x3A, 0x01, 0x26,
0x12, 0x1A, 0x48, 0x68,  0xF5,  0x81,  0x8B,  0xC7,
 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C,  0xD7, 0x74
};

uint8_t l_vec[16] = {
	1, 148, 32, 133, 16, 194, 192, 1,
    251, 1, 192, 194, 16, 133, 32, 148
};

uint8_t lr_vec[16]= {
	148, 32, 133, 16, 194, 192, 1, 251,
	1, 192, 194, 16, 133, 32, 148, 1
};

uint8_t C[32][BLOCK_SIZE];

uint8_t r[16][16];
uint8_t L_table[16][16];
uint8_t LUT[16][256][16];

uint8_t rr[16][16];
uint8_t LR[16][16];
uint8_t LUTr[16][256][16];

uint8_t keys[10][BLOCK_SIZE];

void X(uint8_t a[],uint8_t b[])
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		a[i] ^= b[i];
	}
}

void S(uint8_t a[])
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		a[i] = PI[a[i]];
	}
}

void Sr(uint8_t a[])
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		a[i] = revPI[a[i]];
	}
}
uint8_t GF_mul(uint8_t a, uint8_t b)
{
	uint8_t c = 0;
	uint8_t flag;
	for (int i = 0; i < 8; i++)
	{
		if ((b&1) == 1)
		{
			c ^= a;
		}
		flag = a & 0x80;
		a <<= 1;
		if ((int8_t)flag < 0)
		{
			a ^= 0xc3;
		}
		b>>= 1;
	}
	return c;
}

void matrix_mul(uint8_t A[16][16],uint8_t B[16][16])
{
    uint8_t C[16][16];
    
    for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            C[i][j]=0;
        }
    }

    for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            for(int k=0;k<16;k++)
            {
                C[i][j]^=GF_mul(A[i][k],B[k][j]);
            }
        }
    }

    for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            A[i][j]=C[i][j];
        }
    }
}

void get_LUT()
{
	for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            if(j==i-1)
            {
                r[i][j]=0x01;
            }
            if(j==15)
            {
                r[i][j]=l_vec[i];
            }
        }
    }

	for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            L_table[i][j]=r[i][j];
        }
    }

	for(int i=1;i<16;i++)
	{
		matrix_mul(L_table,r);
	}

	for(int i=0;i<16;i++)
    {
        for(int j=0;j<256;j++)
        {
            for(int k=0;k<16;k++)
            {
                LUT[i][j][k]=GF_mul(L_table[i][k],j);
            }
        }
    }
}

void get_LUTr()
{
	for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            if(j==0)
            {
                rr[i][j]=lr_vec[i];
            }
            if(i+1==j)
            {
                rr[i][j]=0x01;
            }
        }
    }

	for(int i=0;i<16;i++)
    {
        for(int j=0;j<16;j++)
        {
            LR[i][j]=rr[i][j];
        }
    }

	for(int i=1;i<16;i++)
    {
        matrix_mul(LR,rr);
    }
    for(int i=0;i<16;i++)
    {
        for(int j=0;j<256;j++)
        {
            for(int k=0;k<16;k++)
            {
                LUTr[i][j][k]=GF_mul(LR[i][k],j);
            }
        }
    }
}

void L(uint8_t* a)
{
	uint8_t temp[16]={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	for(int i=0;i<16;i++)
	{
		X(temp,LUT[i][a[i]]);
	}
	for(int i=0;i<16;i++)
	{
		a[i]=temp[i];
	}
}

void T(uint8_t* a)
{
	uint8_t temp[16]={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	for(int i=0;i<16;i++)
	{
		X(temp,LUT[i][PI[a[i]]]);
	}
	for(int i=0;i<16;i++)
	{
		a[i]=temp[i];
	}
}

void Lr(uint8_t* a)
{
	uint8_t temp[16]={
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
	};
	for(int i=0;i<16;i++)
	{
		X(temp,LUTr[i][a[i]]);
	}
	for(int i=0;i<16;i++)
	{
		a[i]=temp[i];
	}
}

void print_block(uint8_t a[])
{
	for (int i = 0; i < BLOCK_SIZE; i++)
	{
		printf("%2x ", a[i]);
	}
	printf("\n");
}

void print_rev(uint8_t a[])
{
	for (int i = 15; i >= 0; i--)
	{
		printf("%2x", a[i]);
	}
	printf("\n");
}

void F(uint8_t* C, uint8_t* a1, uint8_t* a0)
{
	uint8_t temp[16];
	for (int i = 0; i < 16; i++)
	{
		temp[i] = a1[i];
	}
	X(a1, C);
	T(a1);
	X(a1, a0);
	for (int i = 0; i < 16; i++)
	{
		a0[i] = temp[i];
	}
}

void get_C()
{
	for(int i=0;i<32;i++)
	{
		for(int j=0;j<16;j++)
		{
			C[i][j]=0;
		}
		C[i][0]=i+1;
		L(C[i]);
		//print_rev(C[i]);
	}
	
}

void get_keys(uint8_t KEY[])
{
	get_C();
	for (int i = 0; i < 16; i++)
	{
		keys[1][i] = KEY[i];
	}
	for (int i = 16; i < 32; i++)
	{
		keys[0][i - 16] = KEY[i];
	}
	uint8_t temp[2][16];
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 16; j++)
		{
			temp[0][j] = keys[2 * i][j];
			temp[1][j] = keys[2 * i + 1][j];
		}
		for (int k = 0; k < 8; k++)
		{
			F(C[8 * i + k], temp[0], temp[1]);
		}
		for (int m = 0; m < 16; m++)
		{
			keys[2 * i + 2][m] = temp[0][m];
			keys[2 * i + 3][m] = temp[1][m];
		}
	}

}

void E(uint8_t* a)
{
	for (int i = 0; i < 9; i++)
	{
		X(a, keys[i]);
		T(a);
		//print_rev(a);
	}
	X(a, keys[9]);
}

void D(uint8_t* a)
{
	for(int i=9;i>0;i--)
	{
		X(a,keys[i]);
		Lr(a);
		Sr(a);
	}
	X(a,keys[0]);
}

int test()
{
	uint8_t KEY[32]={
		0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,
		0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x77,0x66,
		0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,
		0xcc,0xbb,0xaa,0x99,0x88
	};
	uint8_t a[16]={
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
		0x77,0x66,0x55,0x44,0x33,0x22,0x11
	};
	uint8_t test1[16]=
	{
		0xcd,0xed,0xd4,0xb9,0x42,0x8d,0x46,0x5a,0x30,
		0x24,0xbc,0xbe,0x90,0x9d,0x67,0x7f
	};
	uint8_t test2[16]=
	{
		0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
		0x77,0x66,0x55,0x44,0x33,0x22,0x11
	};
	get_LUT();
	printf("TEST:\n");
	printf("a=");
	print_rev(a);
	get_keys(KEY);
	E(a);
	printf("E_a=");
	print_rev(a);
	for(int i=0;i<16;i++)
	{
		if(a[i]!=test1[i])
		{
			return 0;
		}
	}
	get_LUTr();
	D(a);
	printf("a=");
	print_rev(a);
	for(int i=0;i<16;i++)
	{
		if(a[i]!=test2[i])
		{
			return 0;
		}
	}
	return 1;
}

