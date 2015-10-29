#include <stdio.h>

#define EXT_FC(fc)      (((fc) >> 8) & 0xff)

#define FC_VERSION(fc)      ((fc) & 0x3)
#define FC_TYPE(fc)			(((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc)      (((fc) >> 4) & 0xf)

#define	HOGE				0x0802

int main()
{
	printf("EXT_FC 0x%x\n", EXT_FC(HOGE));

	printf("FC_VERSION 0x%x\n", FC_VERSION(EXT_FC(HOGE)));
	printf("FC_TYPE 0x%x\n", FC_TYPE(EXT_FC(HOGE)));
	printf("FC_SUBTYPE 0x%x\n", FC_SUBTYPE(EXT_FC(HOGE)));

	return 0;
}	
