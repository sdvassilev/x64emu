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
#include <crtdbg.h>
#define WIN32_MEAN_AND_LEAN
#include <windows.h>

#ifndef ASSERT
#define ASSERT _ASSERT
#endif

#include "registers.h"
#include "x64emu.h" 

bool g_is64bit = true;
bool g_verbose = false;

extern "C"
VOID
RtlAssert(
    __in PVOID VoidFailedAssertion,
    __in PVOID VoidFileName,
    __in ULONG LineNumber,
    __in_opt PSTR MutableMessage
    )
{
	DebugBreak();
}

void Usage()
{
	printf("Usage:\n");
	printf("\tx64disasm [-d <hex opcode stream>] [-i386] [-v]\n\n");
	printf("where:\n");
	printf("\t-d    When present the specified opcode stream will be disassembled\n");
	printf("\t-i386 The instruction stream is treated as 32-bit opcode\n");
	printf("\t-v    Verbose mode - print detailed info about the operands\n");
	printf("\nExamples: \n");
	printf("\tx64disasm -d c70425b000feff00000000\n");
	printf("\tx64disasm -d c70425b000feff00000000 -i386\n");
}

void PrintOperand(const X64_EMULATOR_CTX& emu, UINT32 idx)
{
	const X64_OPERAND* op = EmuGetOperand(const_cast<X64_EMULATOR_CTX*>(&emu),idx);
	printf("\tOperand %d: %s size %d\n",idx,EmuGetOperandTypeAsStr(op->Type),
		op->Size);
	printf("\tOperand %d: %s\n",idx,EmuGetOperandTypeAsStr(op->Type));
	if (OPERAND_TYPE_MEM == op->Type)
	{
		printf("\t\tAddress: %p\n",op->Op);
	}
	else
	{
		UINT64 val = op->OpAsInt64;
		val &= ((UINT64)1 << 8*op->Size) - 1;
		printf("\t\tValue: %I64d 0x%X\n",val,val);
	}
}

void PrintDecodedInstruction(X64_EMULATOR_CTX& emu)
{
	size_t instrLen = emu.Instruction.InstructionLen;
	const UINT8* pOpCode = reinterpret_cast<const UINT8*>(emu.CpuState.RipGuest.AsInt64);
	printf("%s\n", EmuGetDecodedMnemonic(&emu));
	if (g_verbose)
	{
		printf("\tOperand count: %d\n", emu.Instruction.Flags.OperandCount);
		printf("\tDefault operand size: %d\n", emu.Instruction.OperandSize);
		for (UINT32 i = 0; i < emu.Instruction.Flags.OperandCount; i++)
		{
			PrintOperand(emu, i);
		}
	}
}

bool DecodeInstructionStream(
	const UINT8* pInstr, 
	size_t streamLen)
{
	size_t remainingStreamLen = streamLen;
	UINT64 rip = (UINT64)pInstr;
	
	while (rip < (UINT_PTR)pInstr + streamLen)
	{
		X64_EMULATOR_CTX emu;
		EmuInitEmulatorCtxForDecode(&emu, rip, remainingStreamLen, g_is64bit);
		if (!EmuDecodeInstruction(&emu))
		{
			printf("ERROR: failed to decode instruction at offset 0x%I64x\n", rip);
			return false;
		}
		PrintDecodedInstruction(emu);
		rip += emu.Instruction.InstructionLen;
		remainingStreamLen -= emu.Instruction.InstructionLen;
		EmuCleanupEmulatorCtx(&emu);
	}
	return true;
}

bool FromStringToOpcode(const wchar_t* pStr, UINT8** ppOpcode)
{
	UINT8* pInstr = 0;
	bool ret = false;
	size_t len = wcslen(pStr);
	if (len%2 != 0)
	{
		printf("Even number of chars expected, received %d!\n", len);
		goto __return;;
	}
	pInstr = (UINT8*)malloc(len/2);
	ASSERT(pInstr); // should not really fail
	for (size_t i = 0; i < len/2; i++)
	{
		const wchar_t* curr = pStr + i*2;
		char ch;
		if (swscanf(curr, L"%01x", &ch) != 1)
		{
			printf("Error: Invalid hex nibble %c encountered at "
				"position %d\n", curr, i*2);
			goto __return;
		}
		pInstr[i] = ch<<4;
		curr++;
		if (swscanf(curr, L"%01x", &ch) != 1)
		{
			printf("Error: Invalid hex nibble %c encountered at "
				"position %d\n", curr, i*2);
			goto __return;
		}
		pInstr[i] |= ch;
	}
	ret = true;
	*ppOpcode = pInstr;
__return:
	if (!ret)
	{
		if (pInstr) {
			free(pInstr);
		}
	}
	return ret;
}

int __cdecl
wmain(int argc, wchar_t* argv[])
{
	int err = 0;
	UINT8* pInstr = 0;
	size_t instrLen = 0;
	for (int i = 1; i < argc; ++i)
	{
		if (!_wcsicmp(argv[i],L"-d"))
		{
			if (++i < argc && !pInstr)
			{
				instrLen = wcslen(argv[i]);
				if (instrLen % 2 != 0)
				{
					printf("Even number of chars expected, received %d!\n", instrLen);
					return -1;
				}
				
				if (!FromStringToOpcode(argv[i],&pInstr))
				{
					return -1;
				}
			}
			else
			{
				Usage();
				return -1;
			}
		}
		else if (!_wcsicmp(argv[i], L"-i386"))
		{
			g_is64bit = false;
		}
		else if (!_wcsicmp(argv[i], L"-v"))
		{
			g_verbose = true;
		}
		else
		{
			Usage();
			return -1;
		}
	}

	if (0 != pInstr) 
	{
		err = DecodeInstructionStream(pInstr, instrLen / 2) ? 0 : -1;
		free(pInstr);
	}
	else
	{
		Usage();
	}

	return err;
}
