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

#include "ntifs.h"
#include "x64emu.h"
#include "raisepanic.h"
#include "registers.h"

void 
VmxRootPanicEx(
	const char* pFile,
	UINT32 lineNumber,
	const PANIC_PARAMS& params
	)
{
	DbgBreakPoint();
}

extern CONTEXT g_CpuCtxPre;
extern CONTEXT g_EmuCtxPost;

UINT_PTR
GetGuestContextRegisterValue(
	void*			ctx,
	int				registerId)
{
	switch (registerId)
	{
	case RAX_GUEST_ID:
		return g_CpuCtxPre.Rax;
	case RCX_GUEST_ID:
		return g_CpuCtxPre.Rcx;
	case RDX_GUEST_ID:
		return g_CpuCtxPre.Rdx;
	case RBX_GUEST_ID:
		return g_CpuCtxPre.Rbx;
	case RSP_GUEST_ID:
		return g_CpuCtxPre.Rsp;
	case RBP_GUEST_ID:
		return g_CpuCtxPre.Rbp;
	case RSI_GUEST_ID:
		return g_CpuCtxPre.Rsi;
	case RDI_GUEST_ID:
		return g_CpuCtxPre.Rdi;
	case R8_GUEST_ID :
		return g_CpuCtxPre.R8;
	case R9_GUEST_ID:
		return g_CpuCtxPre.R9;
	case R10_GUEST_ID:
		return g_CpuCtxPre.R10;
	case R11_GUEST_ID:
		return g_CpuCtxPre.R11;
	case R12_GUEST_ID:
		return g_CpuCtxPre.R12;
	case R13_GUEST_ID:
		return g_CpuCtxPre.R13;
	case R14_GUEST_ID:
		return g_CpuCtxPre.R14;
	case R15_GUEST_ID:
		return g_CpuCtxPre.R15;
	case RIP_GUEST_ID:
		return g_CpuCtxPre.Rip;
	case CR0_GUEST_ID:
	case CR3_GUEST_ID:
	case CR4_GUEST_ID:
		ASSERT(false);
		return 0;
	case RFLAGS_GUEST_ID:
		return g_CpuCtxPre.EFlags;
	case ES_GUEST_ID:
		return g_CpuCtxPre.SegEs;
	case CS_GUEST_ID:
		return g_CpuCtxPre.SegCs;
	case SS_GUEST_ID:
		return g_CpuCtxPre.SegSs;
	case DS_GUEST_ID:
		return g_CpuCtxPre.SegDs;
	case FS_GUEST_ID:
		return g_CpuCtxPre.SegFs;
	case GS_GUEST_ID:
		return g_CpuCtxPre.SegGs;
	}
	ASSERT(false);
	return 0;
}

void
SetGuestContextRegisterValue(
	void*			ctx,
	int				registerId,
	UINT64				registerValue
	)
{
	switch (registerId)
	{
	case RAX_GUEST_ID:
		g_EmuCtxPost.Rax = registerValue;
		break;
	case RCX_GUEST_ID:
		 g_EmuCtxPost.Rcx = registerValue;
		 break;
	case RDX_GUEST_ID:
		 g_EmuCtxPost.Rdx = registerValue;
		 break;
	case RBX_GUEST_ID:
		 g_EmuCtxPost.Rbx = registerValue;
		 break;
	case RSP_GUEST_ID:
		 g_EmuCtxPost.Rsp = registerValue;
		 break;
	case RBP_GUEST_ID:
		 g_EmuCtxPost.Rbp = registerValue;
		 break;
	case RSI_GUEST_ID:
		 g_EmuCtxPost.Rsi = registerValue;
		 break;
	case RDI_GUEST_ID:
		 g_EmuCtxPost.Rdi = registerValue;
		 break;
	case R8_GUEST_ID :
		 g_EmuCtxPost.R8 = registerValue;
		 break;
	case R9_GUEST_ID:
		 g_EmuCtxPost.R9 = registerValue;
		 break;
	case R10_GUEST_ID:
		 g_EmuCtxPost.R10 = registerValue;
		 break;
	case R11_GUEST_ID:
		 g_EmuCtxPost.R11 = registerValue;
		 break;
	case R12_GUEST_ID:
		 g_EmuCtxPost.R12 = registerValue;
		 break;
	case R13_GUEST_ID:
		 g_EmuCtxPost.R13 = registerValue;
		 break;
	case R14_GUEST_ID:
		 g_EmuCtxPost.R14 = registerValue;
		 break;
	case R15_GUEST_ID:
		 g_EmuCtxPost.R15 = registerValue;
		 break;
	case RIP_GUEST_ID:
		 g_EmuCtxPost.Rip = registerValue;
		 break;
	case CR0_GUEST_ID:
	case CR3_GUEST_ID:
	case CR4_GUEST_ID:
		ASSERT(false);
		break;
	case RFLAGS_GUEST_ID:
		 g_EmuCtxPost.EFlags = (ULONG)registerValue;
		 break;
	case ES_GUEST_ID:
		 g_EmuCtxPost.SegEs = (USHORT)registerValue;
		 break;
	case CS_GUEST_ID:
		 g_EmuCtxPost.SegCs = (USHORT)registerValue;
		 break;
	case SS_GUEST_ID:
		 g_EmuCtxPost.SegSs = (USHORT)registerValue;
		 break;
	case DS_GUEST_ID:
		 g_EmuCtxPost.SegDs = (USHORT)registerValue;
		 break;
	case FS_GUEST_ID:
		 g_EmuCtxPost.SegFs = (USHORT)registerValue;
		 break;
	case GS_GUEST_ID:
		 g_EmuCtxPost.SegGs = (USHORT)registerValue;
		 break;
	}
}

void InitEmuCtx(X64_EMULATOR_CTX* pEmu)
{
	X64_EMULATOR_RUNTIME rte;
	EmuInitRuntimeStruct(&rte,0,
		GetGuestContextRegisterValue,
		SetGuestContextRegisterValue);
	EmuInitEmulatorCtx(pEmu, &rte, 0);
}