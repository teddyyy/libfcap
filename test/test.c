#include <stdio.h>

#define T_MGMT 			0x0
#define ST_BEACON       0x8
#define FC_MGMT_BEACON              ST_BEACON << 4 | T_MGMT << 2
#define FC_TYPE(fc)     (((fc) >> 2) & 0x3)

int main()
{
	printf("ST_BEACON 0x%x\n", ST_BEACON);
	printf("FC_MGMT_BEACON 0x%x\n", FC_MGMT_BEACON);

	printf("FC_TYPE 0x%x\n", FC_TYPE(FC_MGMT_BEACON));

	return 0;
}	
