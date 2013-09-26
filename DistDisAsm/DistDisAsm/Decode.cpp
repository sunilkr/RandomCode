#include <Windows.h>
#include <stdio.h>

#include "Decode.h"
#include "distorm.h"

#define MAX_INSTRUCTIONS 32

DWORD DecodeInstructions(PBYTE Code, DWORD Count, LPVOID VirtualAddress, LPSTR OutBuffer, int BuffSize)
{
	DWORD DecodedSize = 0;
	_DecodeResult res;
	_OffsetType offset = (ULONGLONG) VirtualAddress;
	_DecodedInst Instructions[MAX_INSTRUCTIONS];
	_DecodeType DecType = Decode32Bits;
	UINT DecodeCount = 0;

	res = distorm_decode(offset, Code, 50, DecType, Instructions, Count, &DecodeCount);
	
	if (res == DECRES_INPUTERR)
		printf("\n[!] Error encountered while decoding.");

	if (DecodeCount >= 0)
	{
		printf("\n[*] Decoded Instructions...");
		for (UINT i = 0; i < DecodeCount; i++)
		{
			printf("\n %0*I64x (%02d) %-24s %s %s", DecType != Decode64Bits ? 8 : 16, Instructions[i].offset, Instructions[i].size, 
													(PCHAR)Instructions[i].instructionHex.p, (PCHAR)Instructions[i].mnemonic.p, 
													(PCHAR)Instructions[i].operands.p);
			DecodedSize += Instructions[i].size;
		}
	}
	return DecodedSize;
}