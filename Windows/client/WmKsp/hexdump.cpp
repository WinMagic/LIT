/*
* Copyright (c) 2026 WinMagic Corp.
* This file is part of the WinMagic LIT reference project.
* This software is dual-licensed:
*
* 1. GNU Affero General Public License v3.0 (AGPL-3.0)
* 2. Commercial license available from WinMagic Corp.
*
* You may use this file under the terms of the AGPL-3.0 license
* included in the LICENSE file in the root of this repository.
*
* For commercial licensing options, OEM redistribution rights,
* proprietary use, or support agreements, please contact WinMagic.
*/
#include "Debug.h"

#define hexdump_putc(c) DEBUG_OUT(L"%c", c)

/*----------------------------------------------------------------------------*/
static void print_string(char* str)
{
	DEBUG_OUT(L"%S", str);
}
/*----------------------------------------------------------------------------*/
static const char hex[]="0123456789abcdef";
static void print_hex(unsigned int val, int bc )
{
	int i, c;
	for(i=0;i<bc;i++)
	{
		c=val>>(8*(bc-i)-4);
		hexdump_putc(hex[c&0xf]);
		c=val>>(8*(bc-i)-8);
		hexdump_putc(hex[c&0xf]);
	}
}
/*----------------------------------------------------------------------------*/
void hexdump(void *buf, int size)
{
	unsigned char *ptr=(unsigned char *)buf;
	char chars[17];
	int i, cnt=0;
	unsigned int offset=0;
	print_hex(offset, sizeof(offset));
	hexdump_putc(' ');
	for(i=0;i<size;i++)
	{
		print_hex(ptr[i], 1);
		hexdump_putc(' ');
		chars[cnt++]= ptr[i]>31 && ptr[i]<127 ? ptr[i] : '.';
		if(cnt==16)
		{
			chars[cnt]=0;
			print_string(chars);
			hexdump_putc('\n');

			if(i!=(size-1))
			{
				print_hex(offset+i+1, sizeof(offset));
				hexdump_putc(' ');
				cnt=0;
			}
		}
	}

	if(cnt!=16)
	{
		int n=(16-cnt)*3;

		for(i=0;i<n;i++)
		{
			hexdump_putc(' ');
		}

		chars[cnt]=0;
		print_string(chars);
		hexdump_putc('\n');
	}

	hexdump_putc('\n');
}
/*----------------------------------------------------------------------------*/
