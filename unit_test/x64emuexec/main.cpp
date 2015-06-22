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
#include <Windows.h>
#include <crtdbg.h>
#include <stdio.h>

#include <crtdbg.h>
#ifndef ASSERT
#define ASSERT _ASSERT
#endif

#include "opcodemap.h"
#include "x64emu.h" 

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

#ifndef ASSERT
#define ASSERT _ASSERT
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(x) (sizeof(x)/sizeof((x)[0]))
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

void DisplayRotatingBar()
{
	static char bars[] = {'|','/','-','\\'};
	static int idx = 0;
	putchar(8);
	putchar(bars[idx]);
	idx = ++idx & 0x3;
}

extern "C" void TestExecShell();

void InitEmuCtx(X64_EMULATOR_CTX*); // implemented in dsm.cpp

static const size_t s_TestInstrOffs = 7;
static const size_t s_MaxInstrLen = 15;
static const UINT8 s_Add_Byte_Ptr_0_AL [s_TestInstrOffs] = 
	{0x00, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00};
static const size_t s_TestExecShellLen = s_TestInstrOffs * 2 + s_MaxInstrLen;

struct TESTED_INSTRUCTION
{
	UINT8 OpCode[s_MaxInstrLen];
	size_t Length;
	const X64_OPERAND* pSrc;
	const X64_OPERAND* pDst;
	const X64_REGISTER* pRax; // used by cmpxchg
	const X64_REGISTER* pRbx; // used by cmpxchg8b
	const X64_REGISTER* pRcx; // used by cmpxchg8b
	const X64_REGISTER* pRdx; // used by cmpxchg8b
	const char* Mnemonic;
	UINT32	Displacement;
	size_t  DisplacementSize;
	size_t  LoopCount;
	bool	SkipSameRegOperands;
	bool    Error;
	bool	StringInstruction;
	bool	SkipRspRbpAsOperand;
};

CONTEXT g_CpuCtxTemp;
CONTEXT g_CpuCtxPost;
CONTEXT g_CpuCtxPre;
CONTEXT g_EmuCtxPost;
UINT8* g_WriteDest;
UINT8* g_WriteDestTemp;
UINT8* g_WriteDestEmu;
UINT8* g_SourceBuf;
TESTED_INSTRUCTION g_Instr;
X64_EMULATOR_CTX g_EmuCtx;
int g_ErrorCnt = 0;
INT64 g_TotalErrorCnt = 0;
INT64 g_TotalExecutedInstrCnt = 0;
int g_ExecutedInstrCnt = 0;
int g_SkippedInstrCnt = 0;
bool g_SkipInstruction = false;
RFLAGS g_Rflags = {0};
UINT32 g_RflagsMask = 0;

static UINT8* s_pTestExecShell = reinterpret_cast<UINT8*>(
		TestExecShell);
static DWORD64 s_ExecStart = *reinterpret_cast<DWORD64*>(&s_pTestExecShell);

void SetupPreCpuContext(CONTEXT*);
void SetupPostCpuContext(CONTEXT*);
void CompareEmuAndCpuStates();

void PrintOpcode()
{
	printf("Iteration %d, instr %s ", 
		g_ExecutedInstrCnt, g_Instr.Mnemonic);
	for (unsigned i = 0; i < g_Instr.Length; i++)
	{
		printf("%02x ", g_Instr.OpCode[i]);
	}
	printf("\n");
}


void OnError()
{
	printf("=============================================\n");
	printf("ERROR: ");
	PrintOpcode();
	printf("\t");
	g_Instr.Error = true;
}


LONG NTAPI
VectoredExceptionHandler(
	EXCEPTION_POINTERS* pExc)
{
	LONG exceptionCode = pExc->ExceptionRecord->ExceptionCode;

	if (exceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		// Make sure it's our breakpoint.  If not, pass on to other 
		// handlers
		
		if (pExc->ContextRecord->Rip == s_ExecStart)
		{
			SetupPreCpuContext(pExc->ContextRecord);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

		if (pExc->ContextRecord->Rip == 
			s_ExecStart + s_TestInstrOffs + g_Instr.Length)
		{
			SetupPostCpuContext(pExc->ContextRecord);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	if (pExc->ContextRecord->Rip >= s_ExecStart && 
		pExc->ContextRecord->Rip <= s_ExecStart + s_TestInstrOffs + s_MaxInstrLen)
	{
		OnError();
		printf("- incorrectly generated opcode\n");
		pExc->ContextRecord->Rip = s_ExecStart+s_TestExecShellLen;
		// fall thru - this is not a valid condition
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void AddInt32ToInstruction(UINT8* pInstr, INT32 int32, size_t size)
{
	size_t i = 0;
	if (1 == size)
	{
		pInstr[i] = (UINT8)int32;
	}
	else if (4 == size)
	{
		*reinterpret_cast<INT32*>(&pInstr[i]) = int32;
	}
}

void SetupPostCpuContext(
	CONTEXT* pCtx)
{

	g_CpuCtxPost = *pCtx;
	*pCtx = g_CpuCtxTemp;
	// move past the exception generating instruction
	pCtx->Rip = s_ExecStart+s_TestExecShellLen;
	EmuCommitCpuState(&g_EmuCtx);
	CompareEmuAndCpuStates();
}			

void SetupPreCpuContext(
	CONTEXT* pCtx)
{
	X64_EMULATOR_CTX emuCtx;
	DECODED_INSTRUCTION& instr = emuCtx.Instruction;
	
	g_SkipInstruction = true;
	
	g_CpuCtxPre = *pCtx;
	g_CpuCtxPre.Rip += s_TestInstrOffs;
	g_CpuCtxPre.EFlags &= ~g_RflagsMask;
	g_CpuCtxPre.EFlags |= g_RflagsMask & g_Rflags.AsUint32;
	g_EmuCtxPost = g_CpuCtxPre;
	InitEmuCtx(&emuCtx);
	emuCtx.CpuState.IA32eX64 = true;
	if (!EmuDecodeInstruction(&emuCtx))
	{
		++g_ErrorCnt;
		printf("ERROR: failed to decode %s\n!", g_Instr.Mnemonic);
		goto __end;
	}

	if (g_Instr.StringInstruction)
	{
		g_CpuCtxPre.Rdi = g_Instr.pDst->OpAsInt64;
		g_CpuCtxPre.Rsi = g_Instr.pSrc->OpAsInt64;
		if (instr.Flags.PrefixRepne || instr.Flags.PrefixRepz)
		{
			g_CpuCtxPre.Rcx = g_Instr.LoopCount;
		}
	}
	else
	{
		UINT32 regMask = 0;
		for (unsigned i = 0; i < instr.Flags.OperandCount; i++)
		{
			if (instr.Operands[i].Type == OPERAND_TYPE_REG)
			{
				UINT8 rIdx =  instr.Operands[i].Register;
				if (rIdx < R_FIRST_HIGH)
				{
					if (0 == ((1<<rIdx) & regMask))
					{
						// We do not want to overwrite any memory address that has 
						// already been set. Also do not overwrite RSP/RBP as it has
						// wider repercussions
						if (rIdx != R_RSP && rIdx != R_RBP)
						{
							*((DWORD64*)&g_CpuCtxPre.Rax + rIdx) = g_Instr.pSrc->OpAsInt64;
							if (rIdx != R_RAX && !(0x1 & regMask) && g_Instr.pRax)
							{
								g_CpuCtxPre.Rax = g_Instr.pRax->AsInt64;
							}
						}
						else if (g_Instr.SkipSameRegOperands || g_Instr.SkipRspRbpAsOperand)
						{
							goto __end;// go to the next one
						}
					}
					else if (g_Instr.SkipSameRegOperands)
					{
						goto __end;// go to the next one
					}
				}
				else if (rIdx < R_LAST_HIGH)
				{
					rIdx -= R_FIRST_HIGH;
					if (0 == ((1<<rIdx) & regMask))
					{
						DWORD64* pReg = (DWORD64*)&g_CpuCtxPre.Rax + rIdx;
						*((UINT8*)pReg + 1) = (UINT8)g_Instr.pSrc->OpAsInt64;
					}
				}
			}
			else if (instr.Operands[i].Type == OPERAND_TYPE_MEM)
			{
				if (instr.Flags.SibPresent)
				{
					if (instr.SibScale)
					{
						//
						// We always set the index to 1
						//
						*((DWORD64*)&g_CpuCtxPre.Rax + instr.SibIndex) = 1;
						regMask |= 1 << instr.SibIndex;
					}
					if (R_RBP == instr.SibBase)
					{
						if (0 == g_Instr.DisplacementSize)
						{
							goto __end;
						}
						if (0x0 == instr.ModrmMod)
						{
							DWORD64* pIdxReg = &g_CpuCtxPre.Rax + instr.SibIndex;
							regMask |= 1 << instr.SibIndex;
							*pIdxReg = g_Instr.pDst->OpAsInt64 - instr.Displacement;
							*pIdxReg /= instr.SibScale;
						}
						else
						{
							g_CpuCtxPre.Rbp = g_Instr.pDst->OpAsInt64 - instr.Displacement;
							if (instr.SibIndex == R_RBP)
							{
								g_CpuCtxPre.Rbp /= (instr.SibScale + 1);
							}
							else
							{
								DWORD64* pIdxReg = &g_CpuCtxPre.Rax + instr.SibIndex;
								regMask |= 1 << instr.SibIndex;
								*pIdxReg = 1; // set index to 1
								g_CpuCtxPre.Rbp -= *pIdxReg * instr.SibScale;
							}
						}
					}
					else if (R_RSP == instr.SibBase)
					{
						// for now skipping [RSP + xxxx] addressing modes
						goto __end;
					}
					else
					{
						DWORD64* pBaseReg = &g_CpuCtxPre.Rax + instr.SibBase;
						DWORD64* pIdxReg = &g_CpuCtxPre.Rax + instr.SibIndex;
						regMask |= 1 << instr.SibBase;
						regMask |= 1 << instr.SibIndex;
						if (pIdxReg == pBaseReg)
						{
							*pBaseReg = (g_Instr.pDst->OpAsInt64 - instr.Displacement) / 
								(instr.SibScale + 1);
						}
						else
						{
							*pIdxReg = 1; // set index to 1
							*pBaseReg = g_Instr.pDst->OpAsInt64 - instr.Displacement;
							*pBaseReg -= *pIdxReg * instr.SibScale;
						}
					}
				}
				else
				{
					if (instr.ModrmMod != 0x3)
					{
						DWORD64* pReg = &g_CpuCtxPre.Rax + instr.ModrmRm;
						if (0x0 == instr.ModrmMod && 0x5 == instr.ModrmRm)
						{
							if (instr.Displacement + g_CpuCtxPre.Rip + instr.InstructionLen != 
								g_Instr.pDst->OpAsInt64)
							{
								printf("\tIncorrectly generated opcode [rip+instrLen+disp32]\n");
								goto __end;
							}
						}
						else
						{
							regMask |= 1 << instr.ModrmRm;
							*pReg = g_Instr.pDst->OpAsInt64 - instr.Displacement;
						}
					}
				}
			}
		}
		if (g_Instr.pRax && g_Instr.pRbx && g_Instr.pRcx && g_Instr.pRdx)
		{
			//
			// must be cmpxchg8b
			//
			g_CpuCtxPre.Rax = g_Instr.pRax->AsInt64;
			g_CpuCtxPre.Rbx = g_Instr.pRbx->AsInt64;
			g_CpuCtxPre.Rcx = g_Instr.pRcx->AsInt64;
			g_CpuCtxPre.Rdx = g_Instr.pRdx->AsInt64;
		}
	}

	//
	// Now that we have modified the CPU ctx we can emulate the instruction
	//
	InitEmuCtx(&g_EmuCtx);
	g_EmuCtx.CpuState.IA32eX64 = true;
	if (!EmuDecodeInstruction(&g_EmuCtx))
	{
		++g_ErrorCnt;
		printf("ERROR: failed to decode %s\n!", g_Instr.Mnemonic);
		goto __end;
	}

	memcpy(g_WriteDestTemp, g_WriteDest, PAGE_SIZE);

	g_EmuCtx.CpuState.Rflags.InterruptF = 0;
	g_EmuCtx.CpuState.Rflags.ResumeF = 0;
	if (!EmuExecuteInstruction(&g_EmuCtx))
	{
		++g_ErrorCnt;
		OnError();
		printf("ERROR: failed to execute %s!\n", g_Instr.Mnemonic);
		goto __end;
	}

	memcpy(g_WriteDestEmu, g_WriteDest, PAGE_SIZE);
	memcpy(g_WriteDest, g_WriteDestTemp, PAGE_SIZE);
	
	g_SkipInstruction = false;

__end:
	if (!g_SkipInstruction)
	{
		g_CpuCtxTemp = *pCtx;
		*pCtx = g_CpuCtxPre;
	}
	else
	{
		//printf("Iteration %d, skipping opcode\n\t", g_ExecutedInstrCnt);
		//PrintOpcode();
		pCtx->Rip = s_ExecStart+s_TestExecShellLen;
		++g_SkippedInstrCnt;
	}
}

void CompareEmuAndCpuStates()
{
	//
	// Now compare the state of emulated CPU context and the state of the CPU
	// after the actual instruction execution
	//
	for (unsigned i = 0; i < X64_GPR_COUNT; i++)
	{
		if (*(&g_EmuCtxPost.Rax + i) != *(&g_CpuCtxPost.Rax + i))
		{
			OnError();
			printf("GPR %d is different emu: %I64x, cpu: %I64x\n",
				i, *(&g_EmuCtxPost.Rax + i), *(&g_CpuCtxPost.Rax + i));
			++g_ErrorCnt;
			goto __error_return;
		}
	}

	if (g_EmuCtxPost.Rip != g_CpuCtxPost.Rip)
	{
		OnError();
		printf("RIP is different emu: %I64x, cpu: %I64x\n",
			g_EmuCtxPost.Rip, g_CpuCtxPost.Rip);
		++g_ErrorCnt;
		goto __error_return;
	}

	RFLAGS fl;
	fl.AsUint32 = g_CpuCtxPost.EFlags;
	fl.InterruptF = fl.ResumeF = 0;
	g_CpuCtxPost.EFlags = fl.AsUint32;

	fl.AsUint32 = g_EmuCtxPost.EFlags;
	fl.InterruptF = fl.ResumeF = 0;
	g_EmuCtxPost.EFlags = fl.AsUint32;
	if (g_EmuCtxPost.EFlags != g_CpuCtxPost.EFlags)
	{
		OnError();
		printf("EFLAGS is different emu: 0x%08x, cpu: 0x%08x\n",
			g_EmuCtxPost.EFlags, g_CpuCtxPost.EFlags);
		++g_ErrorCnt;
		goto __error_return;
	}

	if (0 != memcmp(g_WriteDestEmu,g_WriteDest,PAGE_SIZE))
	{
		OnError();
		printf("Destination memory is different\n");
		++g_ErrorCnt;
		goto __error_return;
	}

__error_return:
	return;
}

bool TestGeneratedInstruction(
	const UINT8* pInstr,
	size_t instrLen,
	X64_OPERAND* pSrc, 
	X64_OPERAND* pDst,
	INT32 displacement,
	size_t displacementSize,
	size_t loopCount,
	bool skipSameRegOps)
{
	size_t bytesWritten = 0;
	memset(g_Instr.OpCode,0x90,sizeof(g_Instr.OpCode));
	memcpy(g_Instr.OpCode, pInstr, instrLen);
	g_Instr.pSrc = pSrc;
	g_Instr.pDst = pDst;
	g_Instr.Length = instrLen;
	g_Instr.Displacement = displacement;
	g_Instr.DisplacementSize = displacementSize;
	g_Instr.LoopCount = loopCount;
	g_Instr.SkipSameRegOperands = skipSameRegOps;
	g_Instr.Error = false;

	//
	// Write the opcode of the tested instruction
	//
	WriteProcessMemory(GetCurrentProcess(), 
		s_pTestExecShell + s_TestInstrOffs, 
		g_Instr.OpCode, 
		sizeof(g_Instr.OpCode), 
		&bytesWritten);
	ASSERT(bytesWritten == sizeof(g_Instr.OpCode));

	//
	// Setup the faulting instruction so we can capture the post context
	//
	WriteProcessMemory(GetCurrentProcess(), 
		s_pTestExecShell + s_TestInstrOffs + instrLen, 
		s_Add_Byte_Ptr_0_AL, 
		sizeof(s_Add_Byte_Ptr_0_AL), 
		&bytesWritten);
	ASSERT(bytesWritten == sizeof(s_Add_Byte_Ptr_0_AL));

	TestExecShell();  // this will trigger our vectored exception handler

	if (g_ExecutedInstrCnt % 20000 == 0)
	{
		DisplayRotatingBar();
	}
	++g_ExecutedInstrCnt;
	return !g_Instr.Error;
}

// Generate instruction
// Set-up the CPU context - src, dest registers

void _TestOpCodeWithModrm(
	UINT8 opCode[3], 
	size_t opCodeLen, 
	INT64 _src,
	INT64 _dst,
	size_t opSize,
	bool genPrefix,
	bool genRex,
	bool genDispl,
	bool lockPrefix = true,
	X64_OPERAND* pImmOp = 0,
	bool skipSameRegOperands = false,
	UINT8 subGroupId = 0xff)
{
	UINT8 instruction[15];
	UINT8 instrLen = 0;
	static const UINT8 prefixes[] = 
	{
		0, 
		OP_PREFIX_LOCK, 
		OP_PREFIX_REPNE, 
		OP_PREFIX_REPZ, 
		OP_PREFIX_OPSIZE_OVR, 
		OP_PREFIX_ADDRSIZE_OVR
	};
	INT32 displacements[] = 
	{
		0, -1, +1, 127, -128, -65535, 0x7fffffff, 
	};
	MODR_M_BYTE modrm;
	SIB_BYTE sib;
	REX_PREFIX rex;
	X64_OPERAND src;
	X64_OPERAND dst;
	INT64* pDestAddr = (INT64*)&g_WriteDest[PAGE_SIZE/2];
	src.Type = OPERAND_TYPE_REG;
	src.OpAsInt64 = _src;
	src.Size = opSize;
	dst.Type = OPERAND_TYPE_MEM;
	dst.Op = (INT8*)pDestAddr;
	dst.Size = opSize;

	if ((UINT64)dst.OpAsInt64 <= (UINT64)0xffffffff)
	{
		displacements[0] = (INT32)dst.OpAsInt64;
	}

	ASSERT(opCodeLen >= 1 && opCodeLen <= 3);

	memset(instruction, 0x90, sizeof(instruction));

	for (size_t pfx = 0; pfx < ARRAYSIZE(prefixes); pfx++)
	{
		if (!genPrefix && pfx > 0)
		{
			break;
		}
		if (prefixes[pfx]==OP_PREFIX_LOCK && !lockPrefix)
		{
			continue;
		}
		instrLen = 0;
		if (0 != prefixes[pfx])
		{
			instruction[instrLen++] = prefixes[pfx]; 
		}
		rex.AsByte = 0x0;
		for (size_t rexCnt = 0; rexCnt <= 16; rexCnt++)
		{
			if (rex.AsByte)
			{
				if (!genRex)
				{
					break;
				}
				instruction[instrLen++] = rex.AsByte;
				rex.AsByte++;
			}
			else
			{
				rex.AsByte = REX_PREFIX_BEGIN;
			}
			
			memcpy(&instruction[instrLen], opCode, opCodeLen);
			instrLen += opCodeLen;

			for (UINT16 i = 0x0; i < 255; i++)
			{
				modrm.AsByte = (UINT8)i;
				if (0x3 == modrm.Mod)
				{
					break;
				}
				if (subGroupId < 8 && modrm.Reg != subGroupId)
				{
					continue;
				}
				instruction[instrLen++] = (UINT8)i;
				for (UINT16 j = 0; j < 255; j++)
				{
					if (IsSibPresent(modrm))
					{
						instruction[instrLen++] = sib.AsByte = (UINT8)j;
					}

					for (size_t k = 0; k < ARRAYSIZE(displacements); k++)
					{
						size_t displSize = GetDisplacementSize(modrm);
						size_t immOpSize = 0;
						INT64 displ = displacements[k];
						bool skip = false;

						if (k > 0 && !genDispl)
						{
							break;
						}

						if (src.Type == OPERAND_TYPE_IMM)
						{
							immOpSize = src.Size;
						}
						else if (pImmOp)
						{
							immOpSize = pImmOp->Size;
						}

						if (displSize)
						{
							if (0 == modrm.Mod && R_RBP == modrm.Rm)
							{
								//
								// Addressing mode [displ32]. Do not forget to change 
								// this logic when we verify 32 bit compatibility mode!!!.
								// In 64 bit mode the address is [Rip+InstrLen+disp32]
								//
								displ = dst.OpAsInt64 - (s_ExecStart + 
									s_TestInstrOffs + instrLen + displSize + immOpSize);
								if (displ > (INT32)0x7fffffff || 
									displ < (INT32)0x80000000)
								{
									displSize = 0;
									skip = true;
								}
							}
						}

						if (displSize)
						{
							AddInt32ToInstruction(&instruction[instrLen], (INT32)displ, 
								displSize);
						}

						if (immOpSize)
						{
							AddInt32ToInstruction(
								&instruction[instrLen+displSize], 
								(UINT32)(src.Type == OPERAND_TYPE_IMM ? 
								src.OpAsInt64 : pImmOp->OpAsInt64), 
								immOpSize);
						}

						instrLen += displSize + immOpSize;

						if (!skip)
						{
							memset(g_WriteDest,0,sizeof(g_WriteDest));
							*pDestAddr = _dst;
							if (!TestGeneratedInstruction(
								instruction, 
								instrLen, 
								&src,
								&dst, 
								displacements[k], 
								displSize, 0, 
								skipSameRegOperands))
							{
								printf("\nGoing to next instruction\n\n");
							}
						}

						instrLen -= displSize + immOpSize;
						
						if (!displSize)
						{
							break;
						}

						if (modrm.Mod == 0 && modrm.Rm == R_RBP)
						{
							break; // no need to go over the rest of the displacements
						}
					}

					if (!IsSibPresent(modrm))
					{
						break;
					}
					--instrLen;
				}
				--instrLen;
			}
			instrLen -= opCodeLen;
			if (rex.AsByte != REX_PREFIX_BEGIN)
			{
				--instrLen;
			}
		}
	}
}

void TestStringOpcode(
	const UINT8* opCode,
	size_t opCodeLen,
	UINT8* pSrc,
	UINT8* pDest,
	size_t opSize,
	size_t loopCount,
	bool forward,
	bool genRex
	)
{
	X64_OPERAND srcOp, destOp;
	UINT8 instruction[15];
	UINT8 instrLen = 0;
	REX_PREFIX rex;
	static const UINT8 prefixes[] = 
	{
		0, 
		OP_PREFIX_REPNE, 
		OP_PREFIX_REPZ, 
		OP_PREFIX_OPSIZE_OVR, 
		OP_PREFIX_ADDRSIZE_OVR
	};

	printf("\n===>Testing opcode ");
	for (unsigned i = 0; i < opCodeLen; i++)
	{
		printf("%02X",  opCode[i]);
	}
	printf(" %s\n",g_Instr.Mnemonic);
	printf("Use forward:      %s\n", forward?"yes":"no");
	printf("Use REX:          %s\n", genRex?"yes":"no");

	//
	// make sure this routine will exit from only one point
	// or otherwise if this flag is not cleared the following instructions
	// will be messed up if they or not string operations.
	//
	g_Instr.StringInstruction = true;
	g_ExecutedInstrCnt = 0;
	g_SkippedInstrCnt = 0;
	g_ErrorCnt = 0;

	srcOp.Op = (INT8*)pSrc;
	srcOp.Size = opSize;
	destOp.Op = (INT8*)pDest;
	destOp.Size = opSize;
	
	g_Rflags.AsUint32 = 0;
	g_Rflags.DirectionF = forward ? 0 : 1;
	g_RflagsMask = g_Rflags.AsUint32;
	
	ASSERT(opCodeLen >= 1 && opCodeLen <= 3);

	memset(instruction, 0x90, sizeof(instruction));

	for (size_t pfx = 0; pfx < ARRAYSIZE(prefixes); pfx++)
	{
		instrLen = 0;
		if (0 != prefixes[pfx])
		{
			instruction[instrLen++] = prefixes[pfx]; 
		}
		rex.AsByte = 0x0;
		for (size_t rexCnt = 0; rexCnt <= 16; rexCnt++)
		{
			if (rex.AsByte)
			{
				if (!genRex)
				{
					break;
				}
				instruction[instrLen++] = rex.AsByte;
				rex.AsByte++;
			}
			else
			{
				rex.AsByte = REX_PREFIX_BEGIN;
			}
			
			memcpy(&instruction[instrLen], opCode, opCodeLen);
			instrLen += opCodeLen;

			if (!TestGeneratedInstruction(
				instruction, 
				instrLen, 
				&srcOp, 
				&destOp, 
				0, 
				0, 
				loopCount, 
				false))
			{
				printf("\nGoing to next instruction\n\n");
			}
						
			instrLen -= opCodeLen;
			if (rex.AsByte != REX_PREFIX_BEGIN)
			{
				--instrLen;
			}
		}
	}

	g_Instr.StringInstruction = false;

	putchar(8);
	printf("Executed instructions: %d\n", g_ExecutedInstrCnt);
	printf("Skipped instructions:  %d\n", g_SkippedInstrCnt);
	printf("ERRORS:                %d\n", g_ErrorCnt);
	g_TotalErrorCnt += g_ErrorCnt;
	g_TotalExecutedInstrCnt += g_ExecutedInstrCnt;
	printf("<===DONE\n");
}

void TestOneByteStringOpcode(
	UINT8 opCode,
	UINT8* pSrc,
	UINT8* pDest,
	size_t opSize,
	size_t loopCount,
	bool forward,
	bool genRex)
{
	TestStringOpcode(&opCode,1,pSrc,pDest,opSize,loopCount,forward,genRex);
}

void TestOpcodeWithModrm(
	UINT8* opCode, 
	size_t opCodeLen,
	INT64 _src, 
	INT64 _dst,
	UINT8 opSize,
	bool genPrefix,
	bool genRex,
	bool genDispl,
	bool lockPrefix = true,
	INT32 _immOp = 0,
	INT32 _immOpSize = 0,
	bool skipSameRegOperands = false,
	UINT8 subGroupId = 0xff)
{
	X64_OPERAND immOp;
	printf("\n===>Testing opcode ");
	for (unsigned i = 0; i < opCodeLen; i++)
	{
		printf("%02X",  opCode[i]);
	}
	printf(" %s\n",g_Instr.Mnemonic);
	printf("Mnemonic:         %s 0x%I64x 0x%I64x\n", g_Instr.Mnemonic, _dst, _src);
	printf("Use prefix:       %s\n", genPrefix?"yes":"no");
	printf("Use REX:          %s\n", genRex?"yes":"no");
	printf("Use displacement: %s\n", genDispl?"yes":"no");
	g_ExecutedInstrCnt = 0;
	g_SkippedInstrCnt = 0;
	g_ErrorCnt = 0;
	memset(&immOp,0,sizeof(immOp));
	if (_immOpSize)
	{
		immOp.Type = OPERAND_TYPE_IMM;
		immOp.OpAsInt64 = _immOp;
		immOp.Size = (UINT8)_immOpSize;
	}
	_TestOpCodeWithModrm(opCode,opCodeLen,_src,_dst,opSize,genPrefix,
		genRex,genDispl,lockPrefix,_immOpSize?&immOp:0,skipSameRegOperands,
		subGroupId);
	putchar(8);
	printf("Executed instructions: %d\n", g_ExecutedInstrCnt);
	printf("Skipped instructions:  %d\n", g_SkippedInstrCnt);
	printf("ERRORS:                %d\n", g_ErrorCnt);
	g_TotalErrorCnt += g_ErrorCnt;
	g_TotalExecutedInstrCnt += g_ExecutedInstrCnt;
	printf("<===DONE\n");
}

void TestOneByteOpcodeWithModrm(
	UINT8 opCode,
	INT64 _src, 
	INT64 _dst,
	UINT8 opSize,
	bool genPrefix,
	bool genRex,
	bool genDispl,
	bool skipSameRegOperands = false)
{
	TestOpcodeWithModrm(&opCode,1,_src,_dst,opSize,
		genPrefix,genRex,genDispl,true,0,0,skipSameRegOperands);
}

void TestOneByteGroupOpcode(
	UINT8 opCode,
	INT64 _src, 
	INT64 _dst,
	UINT8 opSize,
	bool genPrefix,
	bool genRex,
	bool genDispl,
	bool lockPrefix = true,
	INT32 _immOp = 0,
	INT32 _immOpSize = 0,
	bool skipSameRegOperands = false,
	UINT8 subGroupId = 0xff)
{
	TestOpcodeWithModrm(&opCode,1,_src,_dst,opSize,
		genPrefix,genRex,genDispl,lockPrefix,_immOp,_immOpSize,
		skipSameRegOperands, subGroupId);
}


void TestTwoByteOpcodeWithModrm(
	UINT8 _opCode,
	INT64 _src, 
	INT64 _dst,
	UINT8 opSize,
	bool genPrefix,
	bool genRex,
	bool genDispl,
	bool lockPrefix=true,
	INT32 immOp=0,
	INT32 immOpSize=0,
	bool skipSameRegOperands = false,
	UINT8 subGroupId = 0xff)
{
	UINT8 opCode[2];
	opCode[0] = 0x0f;
	opCode[1] = _opCode;
	TestOpcodeWithModrm(opCode,2,_src,_dst,opSize,
		genPrefix,genRex,genDispl,lockPrefix,immOp,immOpSize,
		skipSameRegOperands, subGroupId);
}


void TestAddExec()
{
	g_Instr.Mnemonic = "ADD";
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x01, 0x7fffffffffffffff, 
		0x7fffffffffffffff, 8,true,true,false);
	TestOneByteOpcodeWithModrm(0x01,-65536, -65536, 2,true,true,false);
	TestOneByteOpcodeWithModrm(0x00, -128, -1, 1, true, true,true);
	TestOneByteOpcodeWithModrm(0x00, 127, 1, 1, false,false,false);
	TestOneByteOpcodeWithModrm(0x00, -128, 127, 1, false,false,false);
	TestOneByteOpcodeWithModrm(0x00, 127, -128, 1, false,false,false);
	TestOneByteOpcodeWithModrm(0x00, -128, 127,1,false,false,false);
	
}

void TestXorExec()
{
	g_Instr.Mnemonic = "XOR";
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x31, 0x00ff00ff, 0xff00ff00, 8, true, true, false);
	TestOneByteOpcodeWithModrm(0x31, 0x00ff00ffff00ff00, 0x00ff00ffff00ff00, 4, 
		true, true, false);
	TestOneByteOpcodeWithModrm(0x31, 0x00ff00ffff00ff00, 0xff, 4, 
		true, true, false);
	TestOneByteOpcodeWithModrm(0x30, 0, 0xff, 1, false, true, true);
	TestOneByteOpcodeWithModrm(0x30, 0x55, 0xaa, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x30, 0x0f, 0xf0, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x30, 0, 0, false, 1, false, false);
	TestOneByteOpcodeWithModrm(0x30, 0x70, 0x0f, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x30, 0x00, 0x10, 1, false, false, false);
}

void TestOrExec()
{
	g_Instr.Mnemonic = "OR";
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x9, 0x00ff00ff, 0xff00ff00, 8, true, true, false);
	TestOneByteOpcodeWithModrm(0x9, 0x00ff00ffff00ff00, 0x00ff00ffff00ff00, 4, 
		true, true, false);
	TestOneByteOpcodeWithModrm(0x9, 0x00ff00ffff00ff00, 0xff, 4, 
		true, true, false);
	TestOneByteOpcodeWithModrm(0x8, 0, 0xff, 1, false, true, true);
	TestOneByteOpcodeWithModrm(0x8, 0x55, 0xaa, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x8, 0x0f, 0xf0, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x8, 0, 0, false, 1, false, false);
	TestOneByteOpcodeWithModrm(0x8, 0x70, 0x0f, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x8, 0x00, 0x10, 1, false, false, false);
}


void TestAndExec()
{
	g_Instr.Mnemonic = "AND";
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x21, 0x00ff00ff, 0xff00ff00, 8, true, true, false);
	TestOneByteOpcodeWithModrm(0x21, 0x00ff00ff, 0xff, 8, true, true, false);
	TestOneByteOpcodeWithModrm(0x21, 0x00ff00ffff00ff00, 0x00ff00ffff00ff00, 4, 
		true, true, false);
	TestOneByteOpcodeWithModrm(0x20, 0xff, 0xff, 1, false, true, true);
	TestOneByteOpcodeWithModrm(0x20, 0x55, 0xaa, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x20, 0xff, 0xf0, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x20, 0, 0, false, 1, false, false);
	TestOneByteOpcodeWithModrm(0x20, 0x70, 0xff, 1, false, false, false);
	TestOneByteOpcodeWithModrm(0x20, 0x10, 0x10, 1, false, false, false);
}

void TestSbbExec()
{
	g_Instr.Mnemonic = "SBB";
	g_RflagsMask = 0;
	//
	// Perform set of tests with carry flag set
	//
	g_Rflags.CarryF = 0x1;
	g_RflagsMask = g_Rflags.AsUint32;
	TestOneByteOpcodeWithModrm(0x18, 0x80, 0x80, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x18, 0x80, 0x7f, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x18, 0x80, 0x7e, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x18, 0x00, 0x00, 1, false, true, false);
	//
	// Same as above, only no carry
	//
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x18, 0x80, 0x80, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x18, 0x80, 0x7f, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x18, 0x80, 0x7e, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x18, 0x00, 0x00, 1, false, true, false);

	g_Rflags.CarryF = 0x1;
	g_RflagsMask = g_Rflags.AsUint32;
	TestOneByteOpcodeWithModrm(0x19, 0x80, 0x7f, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x19, 0x8000, 0x7fff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x19, 0x80000000, 0x7fffffff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x19, 0x8000000000000000, 0x7fffffffffffffff, 1, true, true, false);
	
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x19, 0x80, 0x7f, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x19, 0x8000, 0x7fff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x19, 0x80000000, 0x7fffffff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x19, 0x8000000000000000, 0x7fffffffffffffff, 1, true, true, false);

}

void TestSubExec()
{
	g_Instr.Mnemonic = "SUB";

	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x28, 0x80, 0x80, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x28, 0x80, 0x7f, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x28, 0x80, 0x7e, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x28, 0x00, 0x00, 1, false, true, false);
	
	TestOneByteOpcodeWithModrm(0x29, 0x80, 0x7f, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x29, 0x8000, 0x7fff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x29, 0x80000000, 0x7fffffff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x29, 0x8000000000000000, -10, 1, true, true, false);
	TestOneByteOpcodeWithModrm(0x29, 0x8000000000000000, 11, 1, true, true, false);
	TestOneByteOpcodeWithModrm(0x29, 0x8000000000000000, 0x7fffffffffffffff, 1, true, true, false);
}

void TestAddcExec()
{
	g_Instr.Mnemonic = "ADDC";

	//
	// Perform set of tests with carry flag set
	//
	g_Rflags.CarryF = 0x1;
	g_RflagsMask = g_Rflags.AsUint32;
	TestOneByteOpcodeWithModrm(0x10, 0x80, 0x80, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x10, 0x80, 0x7f, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x10, 0x80, 0x7e, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x10, 0x00, 0x00, 1, false, true, false);
	//
	// Same as above, only no carry
	//
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x10, 0x80, 0x80, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x10, 0x80, 0x7f, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x10, 0x80, 0x7e, 1, false, true, false);
	TestOneByteOpcodeWithModrm(0x10, 0x00, 0x00, 1, false, true, false);

	g_Rflags.CarryF = 0x1;
	g_RflagsMask = g_Rflags.AsUint32;
	TestOneByteOpcodeWithModrm(0x11, 0x80, 0x7f, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x11, 0x8000, 0x7fff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x11, 0x80000000, 0x7fffffff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x11, 0x8000000000000000, 0x7fffffffffffffff, 1, true, true, false);
	
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x11, 0x80, 0x7f, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x11, 0x8000, 0x7fff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x11, 0x80000000, 0x7fffffff, 1, true, false, false);
	TestOneByteOpcodeWithModrm(0x11, 0x8000000000000000, 0x7fffffffffffffff, 1, true, true, false);
}

void TestMovExec()
{
	g_Instr.Mnemonic = "MOV";
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x88,-1,-2,1,false,false,true);
	TestOneByteOpcodeWithModrm(0x89,-1,-2,4,false,false,true);
	TestOneByteOpcodeWithModrm(0x89,-1,-2,4,false,true,true);
	g_Instr.SkipRspRbpAsOperand = true;
	TestOneByteOpcodeWithModrm(0x8a,-1,-2,1,false,false,true);
	TestOneByteOpcodeWithModrm(0x8b,-1,-2,4,false,false,true);
	TestOneByteOpcodeWithModrm(0x8b,-1,-2,4,false,true,true);
	g_Instr.SkipRspRbpAsOperand = false;
}

void RandomizePage(UINT8* pPage)
{
	for (int i = 0; i < PAGE_SIZE/sizeof(int); i++)
	{
		*(UINT32*)(pPage + i) = rand();
	}
}

void TestStosExec()
{
	g_Instr.Mnemonic = "STOS";
	RandomizePage(g_SourceBuf);
	TestOneByteStringOpcode(0xaa, g_SourceBuf,
		g_WriteDest, 1, PAGE_SIZE, true, false);
	TestOneByteStringOpcode(0xaa, g_SourceBuf,
		g_SourceBuf+1, 1, PAGE_SIZE-1, true, false);
	TestOneByteStringOpcode(0xaa, g_SourceBuf,
		g_WriteDest, 1, PAGE_SIZE, true, true);
	TestOneByteStringOpcode(0xaa, g_SourceBuf + PAGE_SIZE - 1, 
		g_WriteDest + PAGE_SIZE - 1, 1, PAGE_SIZE, false, false);
	TestOneByteStringOpcode(0xaa, g_SourceBuf + PAGE_SIZE - 1, 
		g_WriteDest + PAGE_SIZE - 1, 1, PAGE_SIZE, false, true);

	TestOneByteStringOpcode(0xab, g_SourceBuf,
		g_WriteDest, 4, PAGE_SIZE/sizeof(UINT32), true, false);
	
	TestOneByteStringOpcode(0xab, 
		g_SourceBuf,
		g_SourceBuf+sizeof(UINT32), 
		4, 
		(PAGE_SIZE-sizeof(UINT32))/sizeof(UINT32), 
		true, 
		false);
	
	TestOneByteStringOpcode(0xab, g_SourceBuf,
		g_WriteDest, 4, PAGE_SIZE/sizeof(UINT64), true, true);
	
	TestOneByteStringOpcode(0xab, 
		g_SourceBuf,
		g_SourceBuf+sizeof(UINT64), 
		4, 
		(PAGE_SIZE-sizeof(UINT64))/sizeof(UINT64), 
		true, 
		false);

	TestOneByteStringOpcode(0xab, 
		g_SourceBuf + PAGE_SIZE - sizeof(UINT64), 
		g_WriteDest + PAGE_SIZE - sizeof(UINT64), 
		4, 
		PAGE_SIZE/sizeof(UINT64), 
		false, 
		true);
}

void TestMovsExec()
{
	g_Instr.Mnemonic = "MOVS";
	RandomizePage(g_SourceBuf);
	TestOneByteStringOpcode(0xa4, g_SourceBuf,
		g_WriteDest, 1, PAGE_SIZE, true, false);
	TestOneByteStringOpcode(0xa4, g_SourceBuf,
		g_SourceBuf+1, 1, PAGE_SIZE-1, true, false);
	TestOneByteStringOpcode(0xa4, g_SourceBuf,
		g_WriteDest, 1, PAGE_SIZE, true, true);
	TestOneByteStringOpcode(0xa4, g_SourceBuf + PAGE_SIZE - 1, 
		g_WriteDest + PAGE_SIZE - 1, 1, PAGE_SIZE, false, false);
	TestOneByteStringOpcode(0xa4, g_SourceBuf + PAGE_SIZE - 1, 
		g_WriteDest + PAGE_SIZE - 1, 1, PAGE_SIZE, false, true);

	TestOneByteStringOpcode(0xa5, g_SourceBuf,
		g_WriteDest, 4, PAGE_SIZE/sizeof(UINT32), true, false);
	TestOneByteStringOpcode(0xa5, 
		g_SourceBuf,
		g_SourceBuf+sizeof(UINT32), 
		4, 
		(PAGE_SIZE-sizeof(UINT32))/sizeof(UINT32), 
		true, 
		false);
	TestOneByteStringOpcode(0xa5, g_SourceBuf,
		g_WriteDest, 4, PAGE_SIZE/sizeof(UINT64), true, true);
	TestOneByteStringOpcode(0xa5, 
		g_SourceBuf,
		g_SourceBuf+sizeof(UINT64), 
		4, 
		(PAGE_SIZE-sizeof(UINT64))/sizeof(UINT64), 
		true, 
		false);
	TestOneByteStringOpcode(0xa5, 
		g_SourceBuf + PAGE_SIZE - sizeof(UINT64), 
		g_WriteDest + PAGE_SIZE - sizeof(UINT64), 
		4, 
		PAGE_SIZE/sizeof(UINT64), 
		false, 
		true);

}

void TestSetCcExec()
{
	g_Rflags.AsUint32 = 0;
	g_Rflags.OverflowF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETO";
	TestTwoByteOpcodeWithModrm(0x90,0,0,1,false,false,false);
	g_Rflags.OverflowF = 0;
	TestTwoByteOpcodeWithModrm(0x90,0,0,1,false,false,false);

	g_Instr.Mnemonic = "SETNO";
	g_Rflags.OverflowF = 1;
	TestTwoByteOpcodeWithModrm(0x91,0,0,1,false,false,false);
	g_Rflags.OverflowF = 0;
	TestTwoByteOpcodeWithModrm(0x91,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.CarryF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETB";
	TestTwoByteOpcodeWithModrm(0x92,0,0,1,false,false,false);
	g_Rflags.CarryF = 0;
	TestTwoByteOpcodeWithModrm(0x92,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.CarryF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETAE";
	TestTwoByteOpcodeWithModrm(0x93,0,0,1,false,false,false);
	g_Rflags.CarryF = 0;
	TestTwoByteOpcodeWithModrm(0x93,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.ZeroF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETE";
	TestTwoByteOpcodeWithModrm(0x94,0,0,1,false,false,false);
	g_Rflags.ZeroF = 0;
	TestTwoByteOpcodeWithModrm(0x94,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.ZeroF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETNE";
	TestTwoByteOpcodeWithModrm(0x95,0,0,1,false,false,false);
	g_Rflags.ZeroF = 0;
	TestTwoByteOpcodeWithModrm(0x95,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.ZeroF = 1;
	g_Rflags.CarryF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETBE";
	TestTwoByteOpcodeWithModrm(0x96,0,0,1,false,false,false);
	g_Rflags.ZeroF = 0;
	g_Rflags.CarryF = 1;
	TestTwoByteOpcodeWithModrm(0x96,0,0,1,false,false,false);
	g_Rflags.ZeroF = 1;
	g_Rflags.CarryF = 0;
	TestTwoByteOpcodeWithModrm(0x96,0,0,1,false,false,false);
	g_Rflags.ZeroF = 0;
	g_Rflags.CarryF = 0;
	TestTwoByteOpcodeWithModrm(0x96,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.ZeroF = 1;
	g_Rflags.CarryF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETA";
	TestTwoByteOpcodeWithModrm(0x97,0,0,1,false,false,false);
	g_Rflags.ZeroF = 0;
	g_Rflags.CarryF = 1;
	TestTwoByteOpcodeWithModrm(0x97,0,0,1,false,false,false);
	g_Rflags.ZeroF = 1;
	g_Rflags.CarryF = 0;
	TestTwoByteOpcodeWithModrm(0x97,0,0,1,false,false,false);
	g_Rflags.ZeroF = 0;
	g_Rflags.CarryF = 0;
	TestTwoByteOpcodeWithModrm(0x97,0,0,1,false,false,false);


	g_Rflags.AsUint32 = 0;
	g_Rflags.SignF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETS";
	TestTwoByteOpcodeWithModrm(0x98,0,0,1,false,false,false);
	g_Rflags.SignF = 0;
	TestTwoByteOpcodeWithModrm(0x98,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.SignF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETNS";
	TestTwoByteOpcodeWithModrm(0x99,0,0,1,false,false,false);
	g_Rflags.SignF = 0;
	TestTwoByteOpcodeWithModrm(0x99,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.ParityF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETP";
	TestTwoByteOpcodeWithModrm(0x9a,0,0,1,false,false,false);
	g_Rflags.ParityF = 0;
	TestTwoByteOpcodeWithModrm(0x9a,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.ParityF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETNP";
	TestTwoByteOpcodeWithModrm(0x9b,0,0,1,false,false,false);
	g_Rflags.ParityF = 0;
	TestTwoByteOpcodeWithModrm(0x9b,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.SignF = 1;
	g_Rflags.OverflowF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETL";
	TestTwoByteOpcodeWithModrm(0x9c,0,0,1,false,false,false);
	g_Rflags.SignF = 0;
	g_Rflags.OverflowF = 1;
	TestTwoByteOpcodeWithModrm(0x9c,0,0,1,false,false,false);
	g_Rflags.SignF = 1;
	g_Rflags.OverflowF = 0;
	TestTwoByteOpcodeWithModrm(0x9c,0,0,1,false,false,false);
	g_Rflags.SignF = 0;
	g_Rflags.OverflowF = 0;
	TestTwoByteOpcodeWithModrm(0x9c,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.SignF = 1;
	g_Rflags.OverflowF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETNL";
	TestTwoByteOpcodeWithModrm(0x9d,0,0,1,false,false,false);
	g_Rflags.SignF = 0;
	g_Rflags.OverflowF = 1;
	TestTwoByteOpcodeWithModrm(0x9d,0,0,1,false,false,false);
	g_Rflags.SignF = 1;
	g_Rflags.OverflowF = 0;
	TestTwoByteOpcodeWithModrm(0x9d,0,0,1,false,false,false);
	g_Rflags.SignF = 0;
	g_Rflags.OverflowF = 0;
	TestTwoByteOpcodeWithModrm(0x9d,0,0,1,false,false,false);

	g_Rflags.AsUint32 = 0;
	g_Rflags.SignF = 1;
	g_Rflags.OverflowF = 1;
	g_Rflags.ZeroF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETLE";
	for (unsigned i = 0; i < 8; i++)
	{
		g_Rflags.SignF = i & 0x1;
		g_Rflags.OverflowF = (i & 0x2) >> 1;
		g_Rflags.ZeroF = (i & 0x4) >> 2;
		TestTwoByteOpcodeWithModrm(0x9e,0,0,1,false,false,false);
	}

	g_Rflags.AsUint32 = 0;
	g_Rflags.SignF = 1;
	g_Rflags.OverflowF = 1;
	g_Rflags.ZeroF = 1;
	g_RflagsMask = g_Rflags.AsUint32;
	g_Instr.Mnemonic = "SETG";
	for (unsigned i = 0; i < 8; i++)
	{
		g_Rflags.SignF = i & 0x1;
		g_Rflags.OverflowF = (i & 0x2) >> 1;
		g_Rflags.ZeroF = (i & 0x4) >> 2;
		TestTwoByteOpcodeWithModrm(0x9f,0,0,1,false,false,false);
	}
}

void TestShldExec()
{
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "SHLD";
	TestTwoByteOpcodeWithModrm(0xa5,0x8234,0x8000,2,true,
		true,false,false);
	TestTwoByteOpcodeWithModrm(0xa5,0x82340000,0xffffffff,4,false,
		true,false,false);
	TestTwoByteOpcodeWithModrm(0xa5,0x82340000,0xffffffff,4,false,
		true,false,false);
	TestTwoByteOpcodeWithModrm(0xa4,0x8234,0x8000,2,true,
		true,false,false,1,1);
	TestTwoByteOpcodeWithModrm(0xa4,0x82340000,0xffffffff,4,false,
		true,false,false,32,1);
	TestTwoByteOpcodeWithModrm(0xa4,0x82340000,0xffffffff,4,false,
		true,false,false,24,1);
}

void TestShrdExec()
{
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "SHRD";
	TestTwoByteOpcodeWithModrm(0xad,0x8234,0x8000,2,true,
		true,false,false);
	TestTwoByteOpcodeWithModrm(0xad,0x82340000,0xffffffff,4,false,
		true,false,false);
	TestTwoByteOpcodeWithModrm(0xad,0x82340000,0xffffffff,4,false,
		true,false,false);
	TestTwoByteOpcodeWithModrm(0xac,0x8234,0x8000,2,true,
		true,false,false,1,1);
	TestTwoByteOpcodeWithModrm(0xac,0x82340000,0xffffffff,4,false,
		true,false,false,32,1);
	TestTwoByteOpcodeWithModrm(0xac,0x82340000,0xffffffff,4,false,
		true,false,false,24,1);
}

void TestBtXxxExec()
{
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "BTXX";
	TestTwoByteOpcodeWithModrm(0xbb, 0xff, 7, 2,  true, true, false,false,0,0,true);
	TestTwoByteOpcodeWithModrm(0xbb, 0xff, 513, 4, true, true,false,false,0,0,true);
	TestTwoByteOpcodeWithModrm(0xab, 0xff, 7, 2,  true, true, false,false,0,0,true);
	TestTwoByteOpcodeWithModrm(0xab, 0xff, 513, 4, true, true,false,false,0,0,true);
	TestTwoByteOpcodeWithModrm(0xb3, 0xff, 7, 2,  true, true, false,false,0,0,true);
	TestTwoByteOpcodeWithModrm(0xb3, 0xff, 513, 4, true, true,false,false,0,0,true);
}

void TestRolExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "ROL";
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,0);
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,0);
	TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,0);
}

void TestRorExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "ROR";
	TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,1);
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,1);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,1);
}

void TestRclExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "RCL";
	TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,2);
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,2);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,2);
}

void TestRcrExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "RCR";
	TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,3);
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,3);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,3);
}

void TestShlExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "SHL";
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,4);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,4);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,4);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,4);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,4);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,4);
		TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,4);
	TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,6); // SAL - the same as SHL
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,4);
}

void TestShrExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "SHR";
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,5);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,5);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,5);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,5);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,5);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,5);
		TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,5);
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,5);
}

void TestSarExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "SAR";
	TestOneByteGroupOpcode(0xd3,0x8234,0x8000,2,true,
		true,false,false,0,0,false,7);
	TestOneByteGroupOpcode(0xc0,0x8234,0x8000,2,true,
		true,false,false,16,1,false,7);
	TestOneByteGroupOpcode(0xd2,0x8234,0x8000,2,true,
		true,false,false,0,0,false,7);
	TestOneByteGroupOpcode(0xd1,0x8234,0x8000,2,true,
		true,false,false,0,0,false,7);
	TestOneByteGroupOpcode(0xd0,0x8234,0x8000,2,true,
		true,false,false,0,0,false,7);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,7);
	TestOneByteGroupOpcode(0xd0,0x82340000,0xffffffff,4,false,
		true,false,false,0,0,false,7);
	TestOneByteGroupOpcode(0xc1,0x8234,0x8000,2,true,
		true,false,false,27,1,false,7);
}

void TestNotExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "NOT";
	TestOneByteGroupOpcode(0xf6,0,0,4,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xf6,0,-1,4,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xf6,0,0x80000000,4,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xf6,0,0x7fffffff,4,true,
		true,false,false,0,0,false,2);
	TestOneByteGroupOpcode(0xf6,0,0x8000000000000000,8,true,
		true,false,false,0,0,false,2);
}

void TestNegExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "NEG";
	TestOneByteGroupOpcode(0xf6,0,0,4,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,-1,-1,4,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,0,0x80000000,4,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,0,0x7fffffff,4,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,0,0x7f,4,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,0,0x8000000000000000,8,true,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,0,-1,8,false,
		true,false,false,0,0,false,3);
	TestOneByteGroupOpcode(0xf6,0,0xf000000000000000,8,false,
		true,false,false,0,0,false,3);
}

void TestIncExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "INC";
	TestOneByteGroupOpcode(0xfe,0,0,4,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,-1,-1,4,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,0,0x80000000,4,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,0,0x7fffffff,4,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,0,0x7f,4,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,0,0x8000000000000000,8,true,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,0,-1,8,false,
		true,false,false,0,0,false,0);
	TestOneByteGroupOpcode(0xfe,0,0xf000000000000000,8,false,
		true,false,false,0,0,false,0);
}

void TestDecExec()
{	
	g_RflagsMask = 0;
	g_Instr.Mnemonic = "DEC";
	TestOneByteGroupOpcode(0xfe,0,0,4,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,-1,-1,4,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,0,0x80000000,4,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,0,0x7fffffff,4,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,0,0x7f,4,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,0,0x8000000000000000,8,true,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,0,-1,8,false,
		true,false,false,0,0,false,1);
	TestOneByteGroupOpcode(0xfe,0,0xf000000000000000,8,false,
		true,false,false,0,0,false,0);
}

void TestMovbeExec()
{
	UINT8 opCode[4];
	opCode[0] = 0x0f;
	opCode[1] = 0x38;
	opCode[2] = 0xf1;

	g_RflagsMask = 0;
	g_Instr.Mnemonic = "MOVBE";

	//
	// CPU can't recognize instruction - may be not supported on my core 2 duo!
	//
    
	//TestOpcodeWithModrm(opCode,3,0x00112233,0,4,
	//	false,true,false,false);
}

void TestXaddExec()
{
	g_Instr.Mnemonic = "XADD";
	g_Instr.SkipRspRbpAsOperand = true;
	g_RflagsMask = 0;
	TestTwoByteOpcodeWithModrm(0xC0, -128, -1, 1, false, true, true);
	TestTwoByteOpcodeWithModrm(0xC0, 127, 1, 1, false,false,false);
	TestTwoByteOpcodeWithModrm(0xC0, -128, 127, 1, false,false,false);
	TestTwoByteOpcodeWithModrm(0xC0, 127, -128, 1, false,false,false);
	TestTwoByteOpcodeWithModrm(0xC0, -128, 127,1,false,false,false);
	
	TestTwoByteOpcodeWithModrm(0xC1, 0x7fffffffffffffff, 
		0x7fffffffffffffff, 8,true,true,false);
	TestTwoByteOpcodeWithModrm(0xC1,-65536, -65536, 2,true,true,false);
	TestTwoByteOpcodeWithModrm(0xC1, 0x80000000, 0x7fffffff, 4, false,true,false);
	g_Instr.SkipRspRbpAsOperand = false;
}


void TestXchgExec()
{
	g_Instr.Mnemonic = "XCHG";
	g_Instr.SkipRspRbpAsOperand = true;
	g_RflagsMask = 0;
	TestOneByteOpcodeWithModrm(0x87, 0x7fffffffffffffff, 
		0x7fffffffffffffff, 8,true,true,false);
	TestOneByteOpcodeWithModrm(0x87,-65536, -65536, 2,true,true,false);
	TestOneByteOpcodeWithModrm(0x87, 0x80000000, 0x7fffffff, 4, false,true,false);

	TestOneByteOpcodeWithModrm(0x86, -128, -1, 1, false, true, true);
	TestOneByteOpcodeWithModrm(0x86, 127, 1, 1, false,false,false);
	TestOneByteOpcodeWithModrm(0x86, -128, 127, 1, false,false,false);
	TestOneByteOpcodeWithModrm(0x86, 127, -128, 1, false,false,false);
	TestOneByteOpcodeWithModrm(0x86, -128, 127,1,false,false,false);
	g_Instr.SkipRspRbpAsOperand = false;
}

void TestCmpxchgExec()
{
	X64_REGISTER acum;
	g_Instr.Mnemonic = "CMPXCHG";
	g_Instr.SkipRspRbpAsOperand = true;
	g_RflagsMask = 0;
	g_Instr.pRax = &acum;
	
	acum.AsInt64 = 17;
	TestTwoByteOpcodeWithModrm(0xb0, 18, 
		acum.AsInt64, 1,false,false,false);
	TestTwoByteOpcodeWithModrm(0xb0, 18, 
		acum.AsInt64-1, 1,false,false,false);

	acum.AsInt64 = -5000000;
	TestTwoByteOpcodeWithModrm(0xb1, 5000000, 
		acum.AsInt64, 8,true,true,true);
	TestTwoByteOpcodeWithModrm(0xb1, 5000000, 
		acum.AsInt64+1, 8,true,true,true);
	TestTwoByteOpcodeWithModrm(0xb1,-65536, acum.AsInt64, 2,true,true,false);

	g_Instr.SkipRspRbpAsOperand = false;
	g_Instr.pRax = 0;
}

void TestCmpxchg8bExec()
{
	X64_REGISTER rax;
	X64_REGISTER rbx;
	X64_REGISTER rcx;
	X64_REGISTER rdx;
	X64_OPERAND dstOp;
	X64_OPERAND dummySrc;
	UINT8 opCode[4];
	MODR_M_BYTE modrm;
	
	g_Instr.Mnemonic = "CMPXCHG8B";
	
	g_RflagsMask = 0;
	modrm.Mod = 0;
	modrm.Reg = 1;
	modrm.Rm = R_RSI;

	g_Instr.pRax = &rax;
	g_Instr.pRbx = &rbx;
	g_Instr.pRcx = &rcx;
	g_Instr.pRdx = &rdx;

	memset(&dummySrc,0,sizeof(dummySrc));
	memset(&dstOp,0,sizeof(dstOp));
	dstOp.Op = (INT8*)&g_WriteDest[PAGE_SIZE/2];
	
	//
	// 64 bit version
	//
	opCode[0] = 0x0f;
	opCode[1] = 0xc7;
	opCode[2] = modrm.AsByte;

	memset(&rax,0,sizeof(rax));
	memset(&rbx,0,sizeof(rbx));
	memset(&rcx,0,sizeof(rcx));
	memset(&rdx,0,sizeof(rdx));

	printf("\n===>Testing opcode ");
	for (unsigned i = 0; i < 3; i++)
	{
		printf("%02X",  opCode[i]);
	}
	printf(" %s\n\n",g_Instr.Mnemonic);

	rax.AsInt32 = 42;
	rdx.AsInt32 = -42;
	rbx.AsInt32 = 41;
	rcx.AsInt32 = -41;

	
	memset(g_WriteDest,0,PAGE_SIZE);
	dstOp.Size = 8;
	*dstOp.OpAsPtr64 = (UINT64)rax.AsInt64 + ((UINT64)rdx.AsInt64 << 32);
	TestGeneratedInstruction(opCode, 3, &dummySrc, &dstOp, 0, 0, 0, false);

	memset(g_WriteDest,0,PAGE_SIZE);
	dstOp.Size = 8;
	dstOp.OpAsPtr64[0] = (UINT64)rax.AsInt64 + ((UINT64)rdx.AsInt64 << 32) - 10;
	TestGeneratedInstruction(opCode, 3, &dummySrc, &dstOp, 0, 0, 0, false);

	//
	// 128 bit version
	//
	opCode[0] = 0x48; // REX.W
	opCode[1] = 0x0f;
	opCode[2] = 0xc7;
	opCode[3] = modrm.AsByte;

	printf("\n===>Testing opcode ");
	for (unsigned i = 0; i < 4; i++)
	{
		printf("%02X",  opCode[i]);
	}
	printf(" %s\n\n",g_Instr.Mnemonic);


	rax.AsInt64 = 42;
	rdx.AsInt64 = -42;
	rbx.AsInt64 = 41;
	rcx.AsInt64 = -41;

	memset(g_WriteDest,0,PAGE_SIZE);
	dstOp.Size = 16;
	dstOp.OpAsPtr64[0] = rax.AsInt64;
	dstOp.OpAsPtr64[1]  = rdx.AsInt64;
	TestGeneratedInstruction(opCode, 4, &dummySrc, &dstOp, 0, 0, 0, false);

	dstOp.OpAsPtr64[0]--;
	memset(g_WriteDest,0,PAGE_SIZE);
	TestGeneratedInstruction(opCode, 4, &dummySrc, &dstOp, 0, 0, 0, false);

	g_Instr.pRax = 0;
	g_Instr.pRbx = 0;
	g_Instr.pRcx = 0;
	g_Instr.pRdx = 0;
}

int __cdecl
wmain(int argc, char argv[])
{
	HANDLE h = AddVectoredExceptionHandler(1, VectoredExceptionHandler);

	g_WriteDest = (UINT8*)VirtualAlloc(0,PAGE_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
	g_WriteDestEmu = (UINT8*)VirtualAlloc(0,PAGE_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
	g_WriteDestTemp = (UINT8*)VirtualAlloc(0,PAGE_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
	g_SourceBuf = (UINT8*)VirtualAlloc(0,PAGE_SIZE,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

	memset(&g_Instr,0,sizeof(g_Instr));

	TestMovExec();
	TestBtXxxExec();
	TestCmpxchg8bExec();
	TestCmpxchgExec();
	TestXchgExec();
	TestXaddExec();
	TestMovbeExec();
	TestRorExec();
	TestRcrExec();
	TestRclExec();
	TestRolExec();
	TestMovsExec();
	TestStosExec();
	TestIncExec();
	TestDecExec();
	TestNegExec();
	TestNotExec();
	TestSarExec();
	TestShrExec();
	TestShlExec();
	TestShrdExec();
	TestShldExec();
	TestSetCcExec();
	TestXorExec();
	TestAndExec();
	TestSubExec();
	TestSbbExec();
	TestAddcExec();
	TestOrExec();
	TestAddExec();
	
	RemoveVectoredExceptionHandler(h);
	
	printf("Total number of instructions executed: %I64d\n", g_TotalExecutedInstrCnt);
	printf("Total error count: %I64d\n", g_TotalErrorCnt);

	VirtualFree(g_WriteDest, PAGE_SIZE, MEM_RELEASE);
	VirtualFree(g_WriteDestEmu, PAGE_SIZE, MEM_RELEASE);
	VirtualFree(g_WriteDestTemp, PAGE_SIZE, MEM_RELEASE);
	VirtualFree(g_SourceBuf, PAGE_SIZE, MEM_RELEASE);
	
	return (int)g_TotalErrorCnt;
}
