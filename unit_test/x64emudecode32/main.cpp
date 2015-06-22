/*
*  x64 Software Emulator (x64emu)
*  Copyright (c) 2010-2012 Svetoslav Vassilev
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 3 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*  Svetoslav Vassilev <svetoslav.vassilev@gmail.com>
*/

#include <stdlib.h>
#include <stdio.h>

#ifdef ASSERT
#undef ASSERT
#define ASSERT
#endif

#include "ntifs.h"
#include "x64emu.h"
#include "registers.h"
#include "raisepanic.h"

void 
VmxRootPanicEx(
	const char* pFile,
	UINT32 lineNumber,
	const PANIC_PARAMS& params
	)
{
	DbgBreakPoint();
}

UINT_PTR g_Rip = 0;

UINT_PTR
GetGuestContextRegisterValue(
	void*			guestCtx,
	int				registerId)
{
	return (RIP_GUEST_ID == registerId) ? g_Rip : 0;
}

#pragma warning(disable: 4273)
extern "C"
VOID
RtlAssert(
    __in PVOID VoidFailedAssertion,
    __in PVOID VoidFileName,
    __in ULONG LineNumber,
    __in_opt PSTR MutableMessage
    )
{
	DbgBreakPoint();
}
#pragma warning(default: 4273)

struct SAMPLE_INSTRUCTION
{
	size_t Size;
	UINT8  Opcode[10];
	const char* Mnemonic;
};

const SAMPLE_INSTRUCTION samples[] = 
{
#include "opcodesamples.h"
};

int __cdecl
wmain(int argc, char argv[])
{
	X64_EMULATOR_CTX emu;
	X64_EMULATOR_RUNTIME emuRte;
	size_t err = 0;

	EmuInitRuntimeStruct(&emuRte,0,GetGuestContextRegisterValue);

	printf("Decoding a sample of %d 32 bit instructions\n", 
		ARRAYSIZE(samples));

	for (unsigned i = 0; i < ARRAYSIZE(samples); i++)
	{
		const SAMPLE_INSTRUCTION* pInstr = &samples[i];
		g_Rip = (UINT_PTR)&pInstr->Opcode[0];
		EmuInitEmulatorCtx(&emu, &emuRte, 0);
		emu.CpuState.IA32eX64 = false;
		EmuDecodeInstruction(&emu);
		if (emu.Instruction.InstructionLen != pInstr->Size)
		{
			printf("Found mismatch %s, actual length %d, decoded length %d\n", 
				pInstr->Mnemonic, pInstr->Size, emu.Instruction.InstructionLen);
			err++;
		}
	}

	if (err)
	{
		printf("Total number of incorrectly decoded instructions: %d\n", err);
	}
	else
	{
		printf("Success!\n");
	}

	return err;
}