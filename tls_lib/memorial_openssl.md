# previously

```c
#ifndef HEADER_DH_H
#include <openssl/dh.h>
#endif

static DH *get_dh2236()
	{
	static unsigned char dh2236_p[]={
		0x0E,0xE2,0x36,0xDA,0xB8,0x47,0xB4,0x66,0x9A,0xA0,0x86,0xA8,
		0x1A,0x79,0xA6,0x2B,0xFD,0xFA,0xCB,0xB2,0x35,0x79,0x18,0x9F,
		0x18,0x4B,0x94,0x8D,0x3B,0x83,0xD5,0xCB,0x9F,0x0D,0x75,0x98,
		0x12,0xB9,0x5A,0x79,0x69,0xFB,0xE1,0x99,0xA9,0xC9,0xCF,0x2A,
		0x5E,0x03,0x5E,0x3A,0x24,0x5D,0x16,0x5D,0xCE,0x6D,0x0A,0x5E,
		0xB8,0x4D,0x90,0xAC,0x05,0xBA,0x5C,0x00,0x3B,0x5A,0xC6,0xC6,
		0x5F,0x77,0xD9,0xF6,0x18,0xED,0x54,0x40,0x23,0x1F,0x1C,0x8B,
		0x64,0x20,0x3E,0x6F,0xF8,0x3C,0xA0,0xCA,0x6A,0x9C,0x54,0x94,
		0x2D,0x8E,0xB2,0x74,0xD7,0xAA,0x05,0x88,0x68,0xBF,0x93,0x0A,
		0x76,0xD6,0xC2,0x47,0xAA,0xBC,0x19,0x77,0x7A,0x85,0x24,0xBB,
		0xC2,0xE0,0xB8,0x6E,0xBF,0x4C,0x80,0xE1,0xB5,0x9F,0x78,0x37,
		0xFD,0x06,0xF7,0x42,0x82,0x4B,0x67,0x6E,0xFA,0xA2,0xA0,0x6F,
		0x40,0xE0,0x19,0x60,0x9D,0xED,0x67,0x52,0x38,0x19,0xA5,0xD9,
		0x94,0xE2,0x67,0xE8,0x74,0xBB,0x35,0x27,0x11,0x0D,0x3E,0x70,
		0x02,0x55,0xA1,0x70,0x6B,0x2F,0x7A,0x65,0xCE,0xD4,0xD3,0xA6,
		0x0F,0x1B,0xFA,0xBF,0xA1,0xC4,0xF5,0xF6,0x18,0xEF,0xAF,0xF0,
		0x41,0xC7,0x57,0x83,0x1F,0xF3,0x4F,0xD1,0x18,0x31,0xB3,0x7B,
		0xE9,0x6D,0x8D,0x3F,0x75,0x09,0xD1,0x24,0x88,0x27,0xD5,0xC7,
		0x82,0x6C,0x69,0xFE,0x63,0x1F,0x83,0x55,0x6C,0x78,0x0B,0x15,
		0x41,0x50,0x09,0xA9,0x17,0x3B,0xE7,0x64,0xA9,0xF1,0xEE,0x0F,
		0xF7,0xA8,0x0B,0x49,0x2C,0xA9,0x5B,0x74,0x3B,0xD2,0xD3,0x04,
		0x6E,0x90,0x1E,0x3B,0x6B,0x58,0xFC,0x83,0x8F,0xB8,0x88,0x3A,
		0x9E,0x23,0xC7,0x48,0x12,0x88,0x24,0x8C,0x5D,0x8E,0x83,0x98,
		0x47,0x0D,0x01,0x43,
		};
	static unsigned char dh2236_g[]={
		0x02,
		};
	DH *dh;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh2236_p,sizeof(dh2236_p),NULL);
	dh->g=BN_bin2bn(dh2236_g,sizeof(dh2236_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		{ DH_free(dh); return(NULL); }
	return(dh);
}
```

