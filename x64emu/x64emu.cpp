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

#include "ntifs.h"
#include "x64emu.h"
#include "opcodemap.h"
#include "registers.h"
#ifdef SUPERCELL
#include "isr.h"
#include "vmxroot_debug.h"
#endif
#include <stdio.h>

#pragma warning(disable:4127)

#define EMU_PANIC(p) RAISE_PANIC(pEmu->RaisePanic,p)

void DecodeError(X64_EMULATOR_CTX*);
void DecodePrefix(X64_EMULATOR_CTX*);
void DecodeRex(X64_EMULATOR_CTX*);
void DecodeOpCode(X64_EMULATOR_CTX*);
void DecodeModrm(X64_EMULATOR_CTX*);
void DecodeSib(X64_EMULATOR_CTX*);
void DecodeDisplacement(X64_EMULATOR_CTX*);
void DecodeImmediateOp(X64_EMULATOR_CTX*);
void ResolveOperands(X64_EMULATOR_CTX*, bool mnemonic);

static INT64 GetIntFromInstruction(X64_EMULATOR_CTX*, size_t size);
static void ResolveModrmMemoryOperand(X64_EMULATOR_CTX*, size_t, bool);
static void ResolveModrmRegisterOperand(X64_EMULATOR_CTX*, size_t, bool);
static void ResolveSibMemoryOperand(X64_EMULATOR_CTX*, size_t, bool);
static bool IsIn64BitMode(X64_EMULATOR_CTX*);
static bool MapRipToVmxRoot(X64_EMULATOR_CTX*, UINT32 bytesToMap);
static bool MapOperandsToVmxRoot(X64_EMULATOR_CTX*);
static void UnmapOperandsFromVmxRoot(X64_EMULATOR_CTX*);

#if 0
static const char* 
GetRegisterAsString(
	const DECODED_INSTRUCTION& instr, 
	size_t r);
#endif

static const char* 
GetRegisterAsString(
	size_t reg,
	size_t opSize);

static size_t // number of chars copied
sscpy(
	OUT char* dest, 
	IN OUT size_t destCapacity, // including terminating NULL 
	IN const char* src, 
	IN size_t srcLen = 0);
static void 
MnemonicConcat(
	DECODED_INSTRUCTION& instr,
	const char* str,
	size_t strLen = 0);
static void 
MnemonicConcatPtrBegin(
	DECODED_INSTRUCTION& instr,
	size_t operandSize);
static void
MnemonicConcatPtrEnd(
	DECODED_INSTRUCTION& instr);
static void
AddHexNumberToMnemonic(
	DECODED_INSTRUCTION& instr,
	UINT64 num,
	size_t sizeofNum = 0,
	bool hexId = true,
	bool align = false);
__inline void
AddPtrToMnemonic(
	X64_EMULATOR_CTX* emu,
	INT64 ptr,
	bool hexId = false);
static void 
AddDisplacementToMnemonic(
	DECODED_INSTRUCTION& instr);
static void 
AddSibOperandToMnemonic(
	X64_EMULATOR_CTX* emu,
	UINT8 reg,
	size_t operandSize);
static void
AddImmediateOpToMnemonic(
	DECODED_INSTRUCTION& instr,
	size_t opIdx);

typedef void (*StringOpT)(
	X64_EMULATOR_CTX* pEmu, 
	size_t count);

static bool 
StringInstructionExecShell(
	X64_EMULATOR_CTX* pEmu, 
	StringOpT fwdOp, 
	StringOpT retreatOp,
	bool setEsi
	);

static bool IsMandatoryPrefixPresent(X64_EMULATOR_CTX*,UINT8);

OpDecodeT s_DecodeStateHandlers[DECODE_STATE_LAST] = 
{
	DecodeError,
	DecodePrefix,
	DecodeRex,
	DecodeOpCode,
	DecodeModrm,
	DecodeSib,
	DecodeDisplacement,
	DecodeImmediateOp
};

static void NullRaisePanic(
	const char* pFile,
	UINT32 lineNo,
	const PANIC_PARAMS& params
	)
{
	UNREFERENCED_PARAMETER(pFile);
	UNREFERENCED_PARAMETER(lineNo);
	UNREFERENCED_PARAMETER(params);
	ASSERT(false);
}

static bool 
NullMapVaRange(
	void*				guestCtx,
	UINT_PTR			guestVA,
	UINT32				guestBytes,
	bool				code, // true - code; false - data
	UINT_PTR			*vmxrootVA)
{
	UNREFERENCED_PARAMETER(guestCtx);
	UNREFERENCED_PARAMETER(code);
	UNREFERENCED_PARAMETER(guestBytes);
	*vmxrootVA = guestVA;
	return true;
}

static void
NullUnmapVaRange(
	void*		guestCtx,
	UINT_PTR	vmxrootVA,
	UINT_PTR	vmxrootBytes
	)
{
	UNREFERENCED_PARAMETER(guestCtx);
	UNREFERENCED_PARAMETER(vmxrootVA);
	UNREFERENCED_PARAMETER(vmxrootBytes);
}

static UINT_PTR
NullGetRegisterValue(
	void* guestCtx,
	int	registerId
	)
{
	UNREFERENCED_PARAMETER(guestCtx);
	UNREFERENCED_PARAMETER(registerId);
	return 0;
}

static void
NullSetRegisterValue(
	void* guestCtx,
	int		registerId,
	UINT64	registerValue
	)
{
	UNREFERENCED_PARAMETER(guestCtx);
	UNREFERENCED_PARAMETER(registerId);
	UNREFERENCED_PARAMETER(registerValue);
}

static void ResetRip(X64_EMULATOR_CTX* pEmu)
{	
	pEmu->CpuState.Rip = pEmu->CpuState.RipOrig;
}
 
bool EmuInitEmulatorCtx(
	X64_EMULATOR_CTX* pEmu,
	const X64_EMULATOR_RUNTIME* rte,
	UINT32 instructionStreamLength)
{
	ASSERT(pEmu);
	ASSERT(rte);
	X64_CPU_STATE& cpu = pEmu->CpuState;

	memset(pEmu,0,sizeof(*pEmu));

	pEmu->GuestCtx = rte->GuestCtx;
	pEmu->MapVaRange = rte->MapVaRange ? rte->MapVaRange : NullMapVaRange;
	pEmu->UnmapVaRange = rte->UnmapVaRange ? rte->UnmapVaRange : NullUnmapVaRange;
	pEmu->GetRegisterValue = rte->GetRegisterValue ? rte->GetRegisterValue : 
		NullGetRegisterValue;
	pEmu->SetRegisterValue = rte->SetRegisterValue ? rte->SetRegisterValue : 
		NullSetRegisterValue;
	pEmu->RaisePanic = rte->RaisePanic ? rte->RaisePanic : NullRaisePanic;

	cpu.Gpr[R_RAX].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RAX_GUEST_ID);
	cpu.Gpr[R_RCX].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RCX_GUEST_ID);
	cpu.Gpr[R_RDX].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RDX_GUEST_ID);
	cpu.Gpr[R_RBX].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RBX_GUEST_ID);
	cpu.Gpr[R_RSP].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RSP_GUEST_ID);
	cpu.Gpr[R_RBP].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RBP_GUEST_ID);
	cpu.Gpr[R_RSI].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RSI_GUEST_ID);
	cpu.Gpr[R_RDI].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,RDI_GUEST_ID);
	cpu.Gpr[R_R8].AsInt64  = pEmu->GetRegisterValue(rte->GuestCtx,R8_GUEST_ID);
	cpu.Gpr[R_R9].AsInt64  = pEmu->GetRegisterValue(rte->GuestCtx,R9_GUEST_ID);
	cpu.Gpr[R_R10].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,R10_GUEST_ID);
	cpu.Gpr[R_R11].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,R11_GUEST_ID);
	cpu.Gpr[R_R12].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,R12_GUEST_ID);
	cpu.Gpr[R_R13].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,R13_GUEST_ID);
	cpu.Gpr[R_R14].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,R14_GUEST_ID);
	cpu.Gpr[R_R15].AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx,R15_GUEST_ID);
	
	cpu.Rflags.AsUint32 = (UINT32)pEmu->GetRegisterValue(rte->GuestCtx,RFLAGS_GUEST_ID);

	cpu.SegRegs[R_CS-R_FIRST_SEG].AsUint16 = (UINT16)pEmu->GetRegisterValue(rte->GuestCtx,CS_GUEST_ID);
	cpu.SegRegs[R_DS-R_FIRST_SEG].AsUint16 = (UINT16)pEmu->GetRegisterValue(rte->GuestCtx,DS_GUEST_ID);
	cpu.SegRegs[R_SS-R_FIRST_SEG].AsUint16 = (UINT16)pEmu->GetRegisterValue(rte->GuestCtx,SS_GUEST_ID);
	cpu.SegRegs[R_ES-R_FIRST_SEG].AsUint16 = (UINT16)pEmu->GetRegisterValue(rte->GuestCtx,ES_GUEST_ID);
	cpu.SegRegs[R_FS-R_FIRST_SEG].AsUint16 = (UINT16)pEmu->GetRegisterValue(rte->GuestCtx,FS_GUEST_ID);
	cpu.SegRegs[R_GS-R_FIRST_SEG].AsUint16 = (UINT16)pEmu->GetRegisterValue(rte->GuestCtx,GS_GUEST_ID);

	if (0 == cpu.RipOrig.AsPtr8)
	{
		cpu.RipGuest.AsInt64 = pEmu->GetRegisterValue(rte->GuestCtx, RIP_GUEST_ID);
		if (!MapRipToVmxRoot(pEmu, instructionStreamLength))
		{
			return false;
		}
	}

	//
	// For now set the CPU in 64 bit only
	//
	cpu.IA32eX64 = true;

	ResetRip(pEmu);
	return true;
}

#ifdef SUPERCELL
bool EmuInitEmulatorCtxFromInterruptCtx(
	X64_EMULATOR_CTX* pEmu,
	PINTERRUPT_CONTEXT	intRegs)
{
	X64_CPU_STATE *cpu = &(pEmu->CpuState);
	memset(pEmu,0,sizeof(X64_EMULATOR_CTX));
	
	pEmu->MapVaRange = NullMapVaRange;
	pEmu->UnmapVaRange = NullUnmapVaRange;
	pEmu->GetRegisterValue = NullGetRegisterValue;
	pEmu->SetRegisterValue = NullSetRegisterValue;

	cpu->Gpr[RAX_GUEST_ID].AsInt64 = intRegs->rax;
	cpu->Gpr[RCX_GUEST_ID].AsInt64 = intRegs->rcx;
	cpu->Gpr[RDX_GUEST_ID].AsInt64 = intRegs->rdx;
	cpu->Gpr[RBX_GUEST_ID].AsInt64 = intRegs->rbx;
	cpu->Gpr[RSP_GUEST_ID].AsInt64 = intRegs->userrsp;
	cpu->Gpr[RSI_GUEST_ID].AsInt64 = intRegs->rsi;
	cpu->Gpr[RDI_GUEST_ID].AsInt64 = intRegs->rdi;
	cpu->Gpr[R8_GUEST_ID].AsInt64 = intRegs->r8;
	cpu->Gpr[R9_GUEST_ID].AsInt64 = intRegs->r9;
	cpu->Gpr[R10_GUEST_ID].AsInt64 = intRegs->r10;
	cpu->Gpr[R11_GUEST_ID].AsInt64 = intRegs->r11;
	cpu->Gpr[R12_GUEST_ID].AsInt64 = intRegs->r12;
	cpu->Gpr[R13_GUEST_ID].AsInt64 = intRegs->r13;
	cpu->Gpr[R14_GUEST_ID].AsInt64 = intRegs->r14;
	cpu->Gpr[R15_GUEST_ID].AsInt64 = intRegs->r15;

	cpu->SegRegs[R_CS-R_FIRST_SEG].AsUint16 = (UINT16)intRegs->cs;
	cpu->SegRegs[R_SS-R_FIRST_SEG].AsUint16 = (UINT16)intRegs->ss;
	cpu->Rflags.AsUint32 = (UINT32)intRegs->rflags;
	cpu->RipGuest.AsInt64 = intRegs->rip;
	// not mapped.
	cpu->RipOrig.AsInt64 = intRegs->rip;

	ResetRip(pEmu);
	return true;
}
#endif

bool EmuInitEmulatorCtxForDecode(
	X64_EMULATOR_CTX* pEmu,
	UINT64		rip,
	UINT32 instructionStreamLength,
	bool x64)
{
	X64_CPU_STATE *cpu = &(pEmu->CpuState);
	memset(pEmu,0,sizeof(X64_EMULATOR_CTX));

	pEmu->MapVaRange = NullMapVaRange;
	pEmu->UnmapVaRange = NullUnmapVaRange;
	pEmu->GetRegisterValue = NullGetRegisterValue;
	pEmu->SetRegisterValue = NullSetRegisterValue;

	// not mapped.
	cpu->IA32eX64 = x64;
	cpu->RipGuest.AsInt64 = cpu->RipOrig.AsInt64 = rip;
	cpu->RipMappedLen = !!instructionStreamLength ? instructionStreamLength : 
		MAX_INSTRUCTION_LEN;

	ResetRip(pEmu);
	return true;
}

void
EmuCleanupEmulatorCtx(
	X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->CpuState.RipOrig.AsUInt64)
	{
		pEmu->UnmapVaRange(pEmu->GuestCtx,
			static_cast<UINT_PTR>(pEmu->CpuState.RipOrig.AsUInt64),
			pEmu->CpuState.RipMappedLen);
	}
	UnmapOperandsFromVmxRoot(pEmu);
}

bool EmuDecodeInstruction(X64_EMULATOR_CTX* pEmu)
{
	pEmu->DecodeState = DECODE_STATE_PREFIX;
	memset(&pEmu->Instruction,0,sizeof(pEmu->Instruction));
	while (pEmu->DecodeState != DECODE_STATE_DONE && 
		pEmu->DecodeState != DECODE_STATE_ERROR)
	{
		s_DecodeStateHandlers[pEmu->DecodeState](pEmu);
	}

	if (DECODE_STATE_ERROR == pEmu->DecodeState) {
		return false;
	}

	pEmu->Instruction.InstructionLen = static_cast<UINT8>(
		pEmu->CpuState.Rip.AsInt64 - pEmu->CpuState.RipOrig.AsInt64);
	ResolveOperands(pEmu,false);
	pEmu->Instruction.Flags.InstructionDecoded = 1;
	return true;
}

inline UINT8 GetRipByte(X64_EMULATOR_CTX* pEmu)
{
	return *pEmu->CpuState.Rip.AsPtr8;
}

inline bool AdvanceRip(X64_EMULATOR_CTX* pEmu) 
{
	X64_CPU_STATE& cpuState = pEmu->CpuState;
	if (cpuState.Rip.AsUInt64 + 1 == cpuState.RipOrig.AsUInt64 + cpuState.RipMappedLen) {
		// cant advance any further
		pEmu->DecodeState = DECODE_STATE_ERROR;
		return false;
	}
	pEmu->CpuState.Rip.AsPtr8++;
	return true;
}

inline void RetreatRip(X64_EMULATOR_CTX* pEmu) {pEmu->CpuState.Rip.AsPtr8--;}

void DecodeError(X64_EMULATOR_CTX* pEmu)
{
	EMU_PANIC((PANIC_X64EMU_ERROR));
}

void DecodePrefix(X64_EMULATOR_CTX* pEmu)
{
	DECODED_FLAGS& dfl = pEmu->Instruction.Flags;
	bool inPrefix = true;
	for (unsigned i = 0; i < 4 && inPrefix; i++)
	{
		UINT8 opByte = GetRipByte(pEmu);
		switch(opByte)
		{
		case OP_PREFIX_LOCK:
		case OP_PREFIX_REPNE:
		case OP_PREFIX_REPZ:
		case OP_PREFIX_CS_OVR:
		case OP_PREFIX_SS_OVR:
		case OP_PREFIX_DS_OVR:
		case OP_PREFIX_ES_OVR:
		case OP_PREFIX_FS_OVR:
		case OP_PREFIX_GS_OVR:
		case OP_PREFIX_OPSIZE_OVR:
		case OP_PREFIX_ADDRSIZE_OVR:
		{
			dfl.PrefixLen++;
			if (!AdvanceRip(pEmu)) {
				return;
			}
			switch(opByte)
			{
			case OP_PREFIX_LOCK:
				dfl.PrefixLock = 1;
				break;
			case OP_PREFIX_REPNE:
				dfl.PrefixRepne = 1;
				break;
			case OP_PREFIX_REPZ:
				dfl.PrefixRepz = 1;
				break;
			case OP_PREFIX_CS_OVR:
			case OP_PREFIX_SS_OVR:
			case OP_PREFIX_DS_OVR:
			case OP_PREFIX_ES_OVR:
			case OP_PREFIX_FS_OVR:
			case OP_PREFIX_GS_OVR:
				dfl.PrefixNotIntersting = 1;
				break;
			case OP_PREFIX_OPSIZE_OVR:
				dfl.PrefixOpSizeOvr = 1;
				break;
			case OP_PREFIX_ADDRSIZE_OVR:
				dfl.PrefixAddrSizeOvr = 1;
				break;
			}
			break;
		}
		default:
			inPrefix = false;
		}
	}
	pEmu->DecodeState = DECODE_STATE_REX;
}

void DecodeRex(X64_EMULATOR_CTX* pEmu)
{
	if (IsIn64BitMode(pEmu))
	{
		UINT8 opByte = GetRipByte(pEmu);
		if (opByte >= REX_PREFIX_BEGIN && opByte <= REX_PREFIX_END)
		{
			pEmu->Instruction.Flags.RexPresent = 1;
			pEmu->Instruction.Rex.AsByte = opByte;
			if (!AdvanceRip(pEmu)) {
				return;
			}
		}
	}
	pEmu->DecodeState = DECODE_STATE_OPCODE;
}

void DecodeOpCode(X64_EMULATOR_CTX* pEmu)
{
	const OPCODE_ENTRY* pOp;
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	UINT8 opCode[3] = {0};
	UINT8 opByte;
	UINT8 oprndCnt = 0;
	const UINT16* pOpAttr = 0;
	UINT8 prefix = 0;
	size_t addrSize;
	UINT8 entryType;

	//
	// The code below assumes that the s_OpcodeTable_xxx are correctly populated
	//

	//
	// Get the first entry from the 1 byte opcode table and walk the tables until 
	// we find terminal or invalid entry
	//
	opByte = opCode[0] = GetRipByte(pEmu);
	pOp = &s_OpcodeMap_1[opByte];
	entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
	instr.Flags.OpCodeLen = 1;

	while (!IsEtTerminal(entryType) && entryType != ET_INV)
	{
		const OPCODE_ENTRY* pTable;
		MODR_M_BYTE modrm;

		pTable = reinterpret_cast<const OPCODE_ENTRY*>(pOp->Handler);
		switch (entryType)
		{
		case ET_JMP2B: case ET_JMP3B:
			ASSERT(instr.Flags.OpCodeLen < 3);
			if (!AdvanceRip(pEmu)) {
				return;
			}
			opByte = opCode[instr.Flags.OpCodeLen] = GetRipByte(pEmu);
			instr.Flags.OpCodeLen++;
			pOp = &pTable[opByte];
			entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
			break;
		
		case ET_JMPGR: case ET_JMPMOD: case ET_JMPMOD_RM:
			if (!AdvanceRip(pEmu)) {
				return;
			}
			modrm.AsByte = GetRipByte(pEmu);
			RetreatRip(pEmu);
			instr.Flags.ModRmPresent = 1;
			if(entryType == ET_JMPMOD)
			{
				pOp = (modrm.Mod != 3) ? &pTable[0] : &pTable[1];
				entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
			}
			else if (entryType == ET_JMPMOD_RM)
			{
				pOp = &pTable[modrm.Rm];
				entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
			}
			else
			{
				instr.Flags.OpCodeExtended = 1;
				if (pOp->OprndCnt)
				{
					//
					// The operands are specified by the jump to group entry,
					// that is why we save pointers to them here.
					//
					oprndCnt = pOp->OprndCnt;
					pOpAttr = &pOp->OprndAttr1;
				}
				pOp = &pTable[modrm.Reg];
				entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
			}
			break;

		case ET_JMPPFX:
			{
				if (instr.Flags.PrefixLen > 0)
				{
					prefix = pEmu->CpuState.RipOrig.AsPtr8[instr.Flags.PrefixLen - 1];
				}
				instr.Flags.MandatoryPrefix = 1;
				switch (prefix)
				{
				default:
				case 0:
					instr.Flags.MandatoryPrefix = 0;
					pOp = &pTable[0];
					break;
				case OP_MANDATORY_PREFIX_1:
					pOp = &pTable[1];
					break;
				case OP_MANDATORY_PREFIX_2:
					pOp = &pTable[2];
					break;
				case OP_MANDATORY_PREFIX_3:
					pOp = &pTable[3];
					break;
				}
				if (pOp->TypeAndFlags == ET_INV)
				{
					instr.Flags.MandatoryPrefix = 0;
					pOp = &pTable[0];
				}
				entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
			}
			break;

		case ET_JMPX86_X64:
			pOp = IsIn64BitMode(pEmu) ? &pTable[1] : &pTable[0];
			entryType = pOp->TypeAndFlags & ET_TYPE_MASK;
			break;

		case ET_JMPFPU:
			pEmu->DecodeState = DECODE_STATE_DONE;
			pEmu->Instruction.Flags.FpuInstruction = 1;
			return; // TODO:
		
		default:
			ASSERT(false);
		}
	}

	if (pOp->TypeAndFlags == ET_INV)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid opcode", opCode[0], 
			opCode[1], opCode[2]));
		return;
	}

	if (!AdvanceRip(pEmu)) {
		return;
	}

	pEmu->Instruction.OpcodeEntry = pOp;

	//
	// Set the operand size
	//
	if (pEmu->CpuState.IA32eX64 && 
		IsEtOpSizeForcedTo64Bit(pOp->TypeAndFlags))
	{
		instr.OperandSize = 8;
	}
	else if (instr.Flags.RexPresent && 
		instr.Rex.W)
	{
		instr.OperandSize = 8;
	}
	else if ((!instr.Flags.MandatoryPrefix ||
		prefix != OP_PREFIX_OPSIZE_OVR) &&
		instr.Flags.PrefixOpSizeOvr)
	{
		instr.OperandSize = 2;
	}
	else
	{
		if (pEmu->CpuState.IA32eX64 && IsEtDefaultOpSize64Bit(pOp->TypeAndFlags))
		{
			//
			// Instruction with default 64 bit operand - push,pop,etc
			//
			instr.OperandSize = 8;
		}
		else
		{
			instr.OperandSize = 4; // default is 4 bytes, even on x64
		}
	}

	//
	// Set the default address size
	//
	addrSize = IsIn64BitMode(pEmu) ? 8 : 4;
	if (instr.Flags.PrefixAddrSizeOvr)
	{
		addrSize /= 2;
	}
	instr.AddressSize = (UINT8)addrSize;

	if (0 == pOpAttr)
	{
		ASSERT(0 == oprndCnt);
		oprndCnt = pOp->OprndCnt;
		pOpAttr = &pOp->OprndAttr1;
	}

	for (unsigned i = 0; i < oprndCnt; i++)
	{
		UINT16 opAttr = pOpAttr[i];
		if (opAttr & OPRND_TYPE_REG)
		{
			size_t rIdx = opAttr & OPRND_REG_MASK; 
			UINT8 rSize = static_cast<UINT8>(OPRND_REG_GET_SIZE(opAttr));
			ASSERT(16 == rSize || 8 == rSize || 4 == rSize || 
				2 == rSize || 1 == rSize || 0 == rSize);

			if ((opAttr & OPRND_REG_REX_B_BIT) && instr.Flags.RexPresent)
			{
				if (R_IS_HIGH(rIdx))
				{
					rIdx -= R_FIRST_HIGH;
					if (opCode[0] >= 0xb4 && opCode[0] <= 0xb7)
					{
						//
						// special handling for "mov ah/r12, Ib", where the ext
						// register is not GPR + 8
						// 
						rIdx += 4;
					}
				}
				rIdx |= instr.Rex.B << 3;
			}

			//
			// Since we have all the info we resolve fully here the reg operand
			//
			instr.Operands[i].Type = OPERAND_TYPE_REG;
			instr.Operands[i].Register = rIdx;
			instr.Operands[i].Size = (rSize > 0) ? rSize : instr.OperandSize;
			if (rIdx < X64_GPR_COUNT)
			{
				instr.Operands[i].Op = pEmu->CpuState.Gpr[rIdx].AsPtr8;
			}
			else if (rIdx <= R_LAST_HIGH)
			{
				instr.Operands[i].OpAsInt64 = *(&pEmu->CpuState.Gpr[
					rIdx-X64_GPR_COUNT].AsInt8 + 1);
			}
			else
			{
				ASSERT(rIdx <= R_GS);
				instr.Operands[i].OpAsInt64 = 
					pEmu->CpuState.SegRegs[rIdx-R_FIRST_SEG].AsUint16;
			}		
		}
		else if (opAttr & OPRND_TYPE_NUM)
		{
			instr.Operands[i].Type = OPERAND_TYPE_IMPLIED_NUM;
			instr.Operands[i].OpAsInt8 = OP_ATTR_NUM_GET_NUM(opAttr);
			instr.Operands[i].Size = 1;
		}
		else
		{
			UINT16 addrMethod = opAttr & ADDRM_MASK;
			UINT16 oprndType = OPRND_GET_TYPE(opAttr);
			
			instr.Flags.ModRmPresent |= OpAttrIsModrmNeeded(opAttr);

			switch (oprndType)
			{
			case OPRND_a:
				if (IsIn64BitMode(pEmu))
				{
					EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid operand type"));
				} // no break
			case OPRND_v:
				instr.Operands[i].Size = instr.OperandSize;
				break;
			case OPRND_b:
				instr.Operands[i].Size = 1;
				break;
			case OPRND_c:
				EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid operand type"));
				break;
			case OPRND_d: case OPRND_si:
				instr.Operands[i].Size = 4;
				break;
			case OPRND_dq: case OPRND_pd: case OPRND_ps:
				instr.Operands[i].Size = 16;
				break;
			case OPRND_p:
				//
				// Used by far jumps. The immediate op contains 2 bytes of 
				// segment selector followed by 2,4,8 bytes of absolute address
				//
				if (4 == instr.OperandSize)
				{
					instr.Operands[i].Size = 6; // 2 + 4
				}
				else if (8 == instr.OperandSize)
				{
					instr.Operands[i].Size = 10; // 2 + 8
				}
				else
				{
					instr.Operands[i].Size = 4; // 2 + 2
				}
				break;
			case OPRND_pi: case OPRND_q: case OPRND_sd: case OPRND_ss:
				instr.Operands[i].Size = 8;
				break;
			case OPRND_w:
				instr.Operands[i].Size = 2;
				break;
			case OPRND_y:
				if (8 == instr.OperandSize)
				{
					instr.Operands[i].Size = 8;
				}
				else
				{
					instr.Operands[i].Size = 4;
				}
				break;
			case OPRND_z:
				if (2 == instr.OperandSize)
				{
					instr.Operands[i].Size = 2;
				}
				else
				{
					instr.Operands[i].Size = 4;
					instr.Flags.ImmediateOpSignX = 1;
				}
				break;
			case OPRND_s:
				if (IsIn64BitMode(pEmu))
				{
					instr.Operands[i].Size  = 10; // 8 + 2
				}
				else
				{
					instr.Operands[i].Size  = 6; // 8 + 2
				}
				break;
			default: ASSERT(false);
			}

			switch (addrMethod)
			{
			case ADDRM_A:
				instr.Flags.ImmediateOp = 1;
				instr.Operands[i].Type = OPERAND_TYPE_DA;
				break;
			case ADDRM_C: case ADDRM_D: case ADDRM_G: case ADDRM_N: case ADDRM_P:
			case ADDRM_R: case ADDRM_S: case ADDRM_U: case ADDRM_V:
				// the register will be resolved after we get MODR/M
				instr.Operands[i].Type = OPERAND_TYPE_REG; 
				break;
			case ADDRM_E: case ADDRM_M: case ADDRM_Q: case ADDRM_W:
				instr.Operands[i].Type = OPERAND_TYPE_MEM;
				break;
			case ADDRM_F:
				instr.Operands[i].Type = OPERAND_TYPE_REG;
				instr.Operands[i].OpAsInt64 = pEmu->CpuState.Rflags.AsUint32;
				instr.Operands[i].Register = R_RFLAGS;
				break;
			case ADDRM_IX:
				instr.Flags.ImmediateOpSignX = 1; // fall through
			case ADDRM_I:
				instr.Flags.ImmediateOp = 1;
				instr.Operands[i].Type = OPERAND_TYPE_IMM;
				break;
			case ADDRM_O:
				instr.Flags.ImmediateOp = 1;
				instr.Operands[i].Size = static_cast<UINT8>(addrSize);
				instr.Operands[i].Type = OPERAND_TYPE_IMM;
				break;
			case ADDRM_J:
				instr.Flags.ImmediateOp = 1;
				if (OPRND_z == oprndType)
				{
					//
					// Force to 4 bytes
					//
					instr.Operands[i].Size = 4;
				}
				instr.Operands[i].Type = OPERAND_TYPE_REL_OFFS;
				break;
			case ADDRM_X: case ADDRM_Y:
				instr.Operands[i].Type = OPERAND_TYPE_MEM;
				instr.Operands[i].OpAsInt64 = 
					pEmu->CpuState.Gpr[addrMethod == ADDRM_X?R_RSI:R_RDI].AsInt64;
				if (!IsIn64BitMode(pEmu)) {
					instr.Operands[i].OpAsInt64 &= 0xffffffff;
				}
				instr.Flags.StringOp = 1;
				break;
			default: ASSERT(false);
			}
		}
	}

	pEmu->Instruction.Flags.OperandCount = oprndCnt;
	pEmu->Instruction.OpCode[0] = opCode[0];
	pEmu->Instruction.OpCode[1] = opCode[1];
	pEmu->Instruction.OpCode[2] = opCode[2];

	pEmu->DecodeState = DECODE_STATE_MODRM;
}

void DecodeModrm(X64_EMULATOR_CTX* pEmu)
{
	MODR_M_BYTE modrm;
	
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	if (!instr.Flags.ModRmPresent)
	{
		pEmu->DecodeState = DECODE_STATE_IMM;
		return;
	}

	modrm.AsByte = GetRipByte(pEmu);

	instr.DisplacementSize = static_cast<UINT8>(GetDisplacementSize(modrm));

	instr.Modrm = modrm;
	instr.ModrmMod = modrm.Mod;
	instr.ModrmReg = modrm.Reg;
	instr.ModrmRm = modrm.Rm;

	if (instr.Flags.RexPresent)
	{
		instr.ModrmReg |= instr.Rex.R << 3;
		
		//
		// Special REX byte cases, where the REX.B bit is not decoded
		//
		if (!(modrm.Mod != 0x3 && modrm.Rm == 0x4 || 
			modrm.Mod == 0x0 && modrm.Rm == 0x5))
		{
			instr.ModrmRm |= instr.Rex.B << 3;
		}
	}

	if (IsSibPresent(modrm))
	{
		instr.Flags.SibPresent = 1;
		pEmu->DecodeState = DECODE_STATE_SIB;
	}
	else if (instr.DisplacementSize)
	{
		pEmu->DecodeState = DECODE_STATE_DISPL;
	}
	else
	{
		pEmu->DecodeState = DECODE_STATE_IMM;
	}

	AdvanceRip(pEmu);
}

void DecodeSib(X64_EMULATOR_CTX* pEmu)
{
	//
	// Assumes it is invoked only if needed
	//
	SIB_BYTE sib;
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	ASSERT(instr.Flags.SibPresent);
	sib.AsByte = GetRipByte(pEmu);

	//
	// RSP can't be used as an index register, but if REX is present
	// and Rex.X is set, then R12 is used as an index.
	//
	if (sib.Index != R_RSP || instr.Flags.RexPresent && instr.Rex.X)
	{
		instr.SibIndex = sib.Index;
		instr.SibScale = 1 << sib.Scale;
	}
	instr.SibBase = sib.Base;
	if (instr.Flags.RexPresent)
	{
		//
		// Special case when base is RBP and ModrmMod is 0 - ther is no SibBase,
		// the effective address is [Scaled Index + disp32] and  in this case Rex.B 
		// is ignored! If [ScaledIndex + R13] needs to be used than ModrmMod has to 
		// be set to 1 or 2 and 0 displacement should be used
		//
		if (!(R_RBP == sib.Base && 0x0 == instr.ModrmMod))
		{
			instr.SibBase |= instr.Rex.B << 3;
		}
		instr.SibIndex |= instr.Rex.X << 3;
	}

	if (R_RBP == sib.Base)
	{
		if (0x0 == instr.ModrmMod ||
			0x2 == instr.ModrmMod)
		{
			instr.DisplacementSize = 4;
		}
		else
		{
			ASSERT(0x1 == instr.ModrmMod);
			instr.DisplacementSize = 1;
		}
	}

	if (instr.DisplacementSize)
	{
		pEmu->DecodeState = DECODE_STATE_DISPL;
	}
	else
	{
		pEmu->DecodeState = DECODE_STATE_IMM;
	}
	AdvanceRip(pEmu);
}

void DecodeDisplacement(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	if (instr.DisplacementSize)
	{
		instr.Displacement = GetIntFromInstruction(
			pEmu, instr.DisplacementSize);
	}
	pEmu->DecodeState = DECODE_STATE_IMM;
}

void DecodeImmediateOp(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	if (instr.Flags.ImmediateOp)
	{
		ASSERT(instr.Flags.OperandCount > 0);
		const INT8 lastOpIdx = (INT8)instr.Flags.OperandCount;
		for (INT8 opIdx = 0; opIdx < lastOpIdx; opIdx++)
		{
			if (!IsOperandImmediate(instr.Operands[opIdx].Type))
			{
				continue;
			}
			size_t sizeToGet = instr.Operands[opIdx].Size;
			ASSERT(sizeToGet == 1 || sizeToGet == 2 || sizeToGet == 4 ||
				sizeToGet == 6 || sizeToGet == 8);
			INT64 i64;
			if ((instr.Operands[opIdx].Type == OPERAND_TYPE_DA &&
				instr.Operands[opIdx].Size > sizeof(INT16)) ||
				instr.Operands[opIdx].Size == sizeof(INT32) + sizeof(INT16) ||
				instr.Operands[opIdx].Size == sizeof(INT64) + sizeof(INT16))
			{
				i64 = GetIntFromInstruction(pEmu, sizeof(UINT16));
				instr.Operands[opIdx].SegmentSelector = static_cast<INT16>(i64);
				sizeToGet -= sizeof(UINT16);
			}
			i64 = GetIntFromInstruction(pEmu, sizeToGet);
			instr.Operands[opIdx].OpAsInt64 = i64;
			if (instr.Flags.ImmediateOpSignX)
			{
				// sign extended immediate operand
				if (IsEtDefaultOpSize64Bit(instr.OpcodeEntry->TypeAndFlags)){
					instr.Operands[opIdx].Size = 8;
				} else if (opIdx > 0) {
					instr.Operands[opIdx].Size = instr.Operands[opIdx-1].Size;
				}
			}
			if (IsAddressingModeO(instr.OpcodeEntry,opIdx))
			{
				//
				// Now that we've obtained the immediate operand, have to
				// change the opType to memory
				//
				instr.Operands[opIdx].Type = OPERAND_TYPE_MEM;
			}
		}
	}
	pEmu->DecodeState = DECODE_STATE_DONE;
}

void ResolveOperands(
	X64_EMULATOR_CTX* pEmu,
	bool mnemonic)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;

	//
	// Here we set-up pointers to registers and memory locations
	// in case MODR/M & SIB bytes are present or there is an immediate
	// op.
	//
	for (size_t i = 0; i < instr.Flags.OperandCount; i++)
	{
		if (mnemonic && i > 0) {
			MnemonicConcat(instr,",",1);
		}
		if (instr.Flags.ModRmPresent)
		{
			if (OPERAND_TYPE_MEM == instr.Operands[i].Type)
			{
				ResolveModrmMemoryOperand(pEmu, i, mnemonic);
			}
			else if (OPERAND_TYPE_REG == instr.Operands[i].Type)
			{
				if (!instr.Flags.OpCodeExtended)
				{
					ResolveModrmRegisterOperand(pEmu, i, mnemonic);
				} 
				else if (mnemonic) 
				{
					ASSERT(instr.Flags.InstructionDecoded);
					MnemonicConcat(instr,
						GetRegisterAsString(instr.Operands[i].Register,
						instr.Operands[i].Size));
				}
			}
			else if (mnemonic) 
			{
				if (OPERAND_TYPE_IMM == instr.Operands[i].Type)
				{
					AddImmediateOpToMnemonic(instr,i);
				}
				else if (OPERAND_TYPE_IMPLIED_NUM == instr.Operands[i].Type)
				{
					AddHexNumberToMnemonic(instr,instr.Operands[i].OpAsInt8,
						1,true,false);
				}
			}
		}
		else if (OPERAND_TYPE_REL_OFFS == instr.Operands[i].Type)
		{
			// offset relative to rip/eip
			if (0 == instr.Flags.InstructionDecoded)
			{
				instr.Operands[i].Size = instr.OperandSize;
				instr.Operands[i].OpAsInt64 = pEmu->CpuState.RipOrig.AsUInt64 + 
					instr.Operands[i].OpAsInt64 + instr.InstructionLen;
				instr.Operands[i].OpAsInt64Guest = instr.Operands[i].OpAsInt64;
			}
			if (mnemonic) {
				AddPtrToMnemonic(pEmu,instr.Operands[i].OpAsInt64Guest);
			}
		} 
		else if (mnemonic)
		{
			if (IsOpAttrRflags(instr.OpcodeEntry,i)) {
				break; // pushfq/popfq
			}
			if (OPERAND_TYPE_DA == instr.Operands[i].Type ||
				OPERAND_TYPE_MEM == instr.Operands[i].Type)
			{
				if (IsOpAttrRsiString(instr.OpcodeEntry,i))
				{
					MnemonicConcatPtrBegin(instr,instr.Operands[i].Size);
					MnemonicConcat(instr,GetRegisterAsString(R_RSI,instr.AddressSize));
				}
				else if (IsOpAttrRdiString(instr.OpcodeEntry,i))
				{
					MnemonicConcatPtrBegin(instr,instr.Operands[i].Size);
					MnemonicConcat(instr,GetRegisterAsString(R_RDI,
						instr.AddressSize));
				}
				else
				{
					size_t opSize = instr.Operands[i].Size;
					if (i > 0) {
						opSize = instr.Operands[i-1].Size;
					} else if (instr.Flags.OperandCount > 0) {
						opSize = instr.Operands[i+1].Size;
					}
					MnemonicConcatPtrBegin(instr,opSize);
					AddPtrToMnemonic(pEmu,instr.Operands[i].OpAsInt64Guest,true);
				}
				MnemonicConcatPtrEnd(instr);
			}
			else if (OPERAND_TYPE_IMM == instr.Operands[i].Type)
			{
				AddImmediateOpToMnemonic(instr,i);
			}
			else if (OPERAND_TYPE_REG == instr.Operands[i].Type)
			{
				MnemonicConcat(instr,
					GetRegisterAsString(instr.Operands[i].Register,
					instr.Operands[i].Size));
			}
			else if (OPERAND_TYPE_IMPLIED_NUM == instr.Operands[i].Type)
			{
				AddHexNumberToMnemonic(instr,instr.Operands[i].OpAsInt8,
					1,true,false);
			}
			else
			{
				ASSERT(false);
			}
		}

		if (0 == instr.Flags.InstructionDecoded)
		{
			//
			// Store a copy of the operand, we may need it in case it gets
			// mapped to vmx root and we need it to construct the instruction
			// mnemonic
			//
			instr.Operands[i].OpAsInt64Guest = instr.Operands[i].OpAsInt64;
		}
	}
}

void ResolveModrmMemoryOperand(
	X64_EMULATOR_CTX* pEmu, 
	size_t opIdx,
	bool mnemonic)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	X64_OPERAND& op = instr.Operands[opIdx];
	ASSERT(opIdx < ARRAYSIZE(instr.Operands));
	ASSERT(instr.Flags.ModRmPresent);

	//
	// Special case for disp32
	//
	X64_CPU_STATE& cpu = pEmu->CpuState;
	if (0x0 == instr.ModrmMod && 0x5 == instr.ModrmRm)
	{
		//
		// disp32 has 2 different meaning depending on whether the CPU is in
		// 32 or 64 bit mode. In 32 bit mode disp32 is taken as an absolute
		// address, while in 64 it is sign added to the RIP value of the next
		// instruction
		//
		if (0 == instr.Flags.InstructionDecoded)
		{
			if (IsIn64BitMode(pEmu))
			{
				op.Op = cpu.RipGuest.AsPtr8 + instr.InstructionLen +
					instr.Displacement;
			}
			else
			{
				op.OpAsInt64 = instr.Displacement;
			}
			op.OpAsInt64Guest = op.OpAsInt64;
		}
		if (mnemonic) 
		{
			MnemonicConcatPtrBegin(instr,op.Size);
			AddPtrToMnemonic(pEmu,op.OpAsInt64Guest);
			MnemonicConcatPtrEnd(instr);
		}
		goto __return;
	}

	if (instr.Flags.SibPresent)
	{
		ResolveSibMemoryOperand(pEmu, opIdx, mnemonic);
		goto __return;
	}

	if (instr.ModrmMod != 0x3)
	{
		if (0 == instr.Flags.InstructionDecoded)
		{
			op.Op = cpu.Gpr[instr.ModrmRm].AsPtr8 + 
				instr.Displacement;
		}
		if (mnemonic)
		{
			MnemonicConcatPtrBegin(instr,op.Size);
			MnemonicConcat(
				instr,
				GetRegisterAsString(instr.ModrmRm,instr.AddressSize));
			if (instr.Displacement) 
			{
				MnemonicConcat(instr,(instr.Displacement > 0) ? "+" : "-",1);
				AddHexNumberToMnemonic(instr,
					(instr.Displacement > 0) ? instr.Displacement : -instr.Displacement,
					instr.DisplacementSize,
					true);
			}
			MnemonicConcatPtrEnd(instr);
		}
	}
	else
	{
		//
		// Not really a memory operand, but a register
		//
		if (0 == instr.Flags.InstructionDecoded)
		{
			if (1 == op.Size && 
				instr.ModrmRm >= 4 && 
				instr.ModrmRm <= 7)
			{
				// AH, CH, DH, BH
				op.OpAsInt64 = *(&cpu.Gpr[instr.ModrmRm-4].AsInt8 + 1);
				op.Register = instr.ModrmRm - 4 + R_FIRST_HIGH;
			}
			else
			{
				op.OpAsInt64 = cpu.Gpr[instr.ModrmRm].AsInt64;
				op.Register = instr.ModrmRm;
			}
			op.Type = OPERAND_TYPE_REG;
		}
		if (mnemonic) {
			MnemonicConcat(instr,GetRegisterAsString(op.Register,op.Size));
		}
	}

__return:
	return;
}

void ResolveModrmRegisterOperand(
	X64_EMULATOR_CTX* pEmu, 
	size_t opIdx,
	bool mnemonic)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	ASSERT(opIdx < ARRAYSIZE(instr.Operands));
	ASSERT(instr.Flags.ModRmPresent);
	X64_OPERAND& op = instr.Operands[opIdx];
	X64_CPU_STATE& cpu = pEmu->CpuState;
	const OPCODE_ENTRY* pOpEntry = reinterpret_cast<const OPCODE_ENTRY*>(
		pEmu->Instruction.OpcodeEntry);

	ASSERT(pOpEntry);
	ASSERT(opIdx < pOpEntry->OprndCnt);
	if (*(&pOpEntry->OprndAttr1 + opIdx) & OPRND_TYPE_REG) {
		goto __mnemonic; // no need to resolve
	}

	if (instr.Flags.InstructionDecoded) {
		goto __mnemonic;
	}
	
	if (1 == op.Size && 
		instr.ModrmReg >= R_RSP && 
		instr.ModrmReg <= R_RDI && 
		!instr.Flags.RexPresent)
	{
		// AH, CH, DH, BH
		op.OpAsInt64 = *(&cpu.Gpr[instr.ModrmReg-R_RSP].AsInt8 + 1);
		op.Register = (instr.ModrmReg-4) + R_FIRST_HIGH;
	}
	else if (IsAddressingMode(instr.OpcodeEntry,opIdx,ADDRM_S))
	{
		ASSERT(op.Size == sizeof(INT16));
		op.OpAsInt64 = cpu.SegRegs[instr.ModrmReg].AsUint16;
		op.Register = (instr.ModrmReg & ~(instr.Rex.R << 3)) + R_FIRST_SEG;
		if (0 == opIdx || OPERAND_TYPE_MEM == instr.Operands[0].Type)
		{
			for (size_t i = 0; i < instr.Flags.OperandCount; i++) {
				instr.Operands[i].Size = 2;
			}
		}
	}
	else // TODO: MMX/XMMX registers
	{
		op.OpAsInt64 = cpu.Gpr[instr.ModrmReg].AsInt64;
		op.Register = instr.ModrmReg;
	}

__mnemonic:
	if (mnemonic) {
		MnemonicConcat(
			instr,
			GetRegisterAsString(instr.Operands[opIdx].Register,
			instr.Operands[opIdx].Size));
	}
}

void ResolveSibMemoryOperand(
	X64_EMULATOR_CTX* pEmu, 
	size_t opIdx,
	bool mnemonic)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	ASSERT(opIdx < ARRAYSIZE(instr.Operands));
	ASSERT(instr.Flags.SibPresent);
	X64_OPERAND& op = instr.Operands[opIdx];
	X64_CPU_STATE& cpu = pEmu->CpuState;
	INT64 scaledIdx = cpu.Gpr[instr.SibIndex].AsInt64 * instr.SibScale; 

	//
	// Calcs the memory operand field based on the formula
	// 	Gpr[SibBase] + Gpr[SibIndex] * SibScale
	//

	if (0x5 == instr.SibBase)
	{
		//
		// Special handling for EBP base
		//
		if (0x0 == instr.ModrmMod)
		{
			if (0 == instr.Flags.InstructionDecoded)
			{
				op.OpAsInt64 = instr.Displacement;
				op.Op += scaledIdx;
			}
			if (mnemonic)
			{
				MnemonicConcatPtrBegin(instr,op.Size);
				if (instr.SibScale)
				{
					MnemonicConcat(instr,GetRegisterAsString(instr.SibIndex,instr.AddressSize));
					MnemonicConcat(instr,"*",1);
					AddHexNumberToMnemonic(instr,instr.SibScale,1,true);
					AddDisplacementToMnemonic(instr);
				}
				else
				{
					AddPtrToMnemonic(pEmu,instr.Displacement,true);
				}
				MnemonicConcatPtrEnd(instr);
			}
		}
		else
		{
			if (0 == instr.Flags.InstructionDecoded)
			{
				op.Op = cpu.Gpr[R_RBP].AsPtr8;
				op.Op += instr.Displacement + scaledIdx;
			}
			if (mnemonic)
			{
				AddSibOperandToMnemonic(pEmu,R_RBP,op.Size);
			}
		}
	}
	else
	{
		if (0 == instr.Flags.InstructionDecoded)
		{
			op.Op = cpu.Gpr[instr.SibBase].AsPtr8;
			op.Op += scaledIdx + instr.Displacement;
		}
		if (mnemonic)
		{
			AddSibOperandToMnemonic(pEmu,instr.SibBase,op.Size);
		}
	}
}

INT64 GetIntFromInstruction(X64_EMULATOR_CTX* pEmu, size_t size)
{
	INT64 i64;
	switch(size)  // Sign extend the value
	{
	case sizeof(INT8):
		i64 = *pEmu->CpuState.Rip.AsPtr8;
		break;
	case sizeof(INT16):
		i64 = *pEmu->CpuState.Rip.AsPtr16;
		break;
	case sizeof(INT32):
		i64 = *pEmu->CpuState.Rip.AsPtr32;
		break;
	case sizeof(INT64):
		i64 = *pEmu->CpuState.Rip.AsPtr64;
		break;
	default:
		ASSERT(false);
		i64 = 0;
	}
	pEmu->CpuState.Rip.AsPtr8 += size;
	return i64;
}

bool MapRipToVmxRoot(X64_EMULATOR_CTX* pEmu, UINT32 additionalBytesToMap)
{
	//
	// We can't know how long the instruciton is w/o looking at the memory pointed
	// by RIP. It is perfectly valid situation to not be able to map if the page 
	// fault is due to executable page. Also the instruciton may be contained 
	// within one page and start at an address where remaining bytes in the page 
	// are less than the max instruction size. That is why we try to map as much 
	// as we can starting with the max instruction length. It is up to the caller
	// to decide whether a failure should trigger an internal error or not.
	//

	X64_CPU_STATE& cpu = pEmu->CpuState;
	UINT32 newMappedLen = 0;
	if (cpu.RipMappedLen)
	{
		ASSERT(cpu.RipOrig.AsPtr8);
		pEmu->UnmapVaRange(pEmu->GuestCtx, 
			static_cast<UINT32>(cpu.RipOrig.AsUInt64), cpu.RipMappedLen);
		newMappedLen = cpu.RipMappedLen;
		cpu.RipMappedLen = 0;
		cpu.RipOrig.AsUInt64 = 0;
	}

	if (0 != additionalBytesToMap) {
		if (pEmu->MapVaRange(pEmu->GuestCtx,
			static_cast<UINT_PTR>(cpu.RipGuest.AsUInt64),
			additionalBytesToMap,
			true,
			reinterpret_cast<UINT_PTR*>(&cpu.RipOrig.AsUInt64)))
		{
			cpu.RipMappedLen = additionalBytesToMap;
		}
		goto __return;
	}
	
	//
	// If additionalBytesToMap is not specified we will try to map
	// as much as we can starting with the max instruction length
	//
	additionalBytesToMap = MAX_INSTRUCTION_LEN;
	do {
		newMappedLen += additionalBytesToMap;
		if (pEmu->MapVaRange(pEmu->GuestCtx,
			static_cast<UINT_PTR>(cpu.RipGuest.AsUInt64),
			newMappedLen,
			true,
			reinterpret_cast<UINT_PTR*>(&cpu.RipOrig.AsUInt64)))
		{
			cpu.RipMappedLen = newMappedLen; 
			break;
		}
		newMappedLen -= additionalBytesToMap;
	} while (--additionalBytesToMap > 0);

__return:
	return !!cpu.RipMappedLen;
}

void
OpCopyData(
	UINT8* pDest,		// vmx root address
	const UINT8* pSrc,	// vmx root address
	size_t size)
{	
	switch (size)
	{
	case 1:
		*pDest = *pSrc;
		break;
	case 2:
		*((UINT16*)pDest) = *((UINT16*)pSrc);
		break;
	case 4:
		*((UINT32*)pDest) = *((UINT32*)pSrc);
		break;
	case 8:
		*((UINT64*)pDest) = *((UINT64*)pSrc);
		break;
	case 16:
		*((UINT64*)pDest) = *((UINT64*)pSrc);
		*((UINT64*)pDest + 1) = *((UINT64*)pSrc + 1);
		break;
	default:
		ASSERT(false);
	}
}

bool IsIn64BitMode(X64_EMULATOR_CTX* p)
{ 
	// todo:
	return p->CpuState.IA32eX64;
}

static void UnmapOperandsFromVmxRoot(
	X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	for (size_t i = 0; i < instr.Flags.OperandCount; i++)
	{
		if (instr.Operands[i].MappedToVmxRoot)
		{
			ASSERT(OPERAND_TYPE_MEM == instr.Operands[i].Type);
			pEmu->UnmapVaRange(pEmu->GuestCtx,
				static_cast<UINT_PTR>(instr.Operands[i].OpAsInt64),
				instr.Operands[i].Size);
		}
	}
}

static bool MapOperandsToVmxRoot(
	X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	for (size_t i = 0; i < instr.Flags.OperandCount; i++)
	{
		if (instr.Operands[i].MappedToVmxRoot) {
			continue;
		}
		if (OPERAND_TYPE_MEM == instr.Operands[i].Type ||
			OPERAND_TYPE_DA == instr.Operands[i].Type)
		{
			UINT_PTR guestVa = (UINT_PTR)instr.Operands[i].Op;
			UINT_PTR vmxRootVa;
			if (!pEmu->MapVaRange(pEmu->GuestCtx,
				guestVa,
				(UINT32)instr.Operands[i].Size,
				false,
				&vmxRootVa))
			{
				return false;
			}
			ASSERT(instr.Operands[i].OpAsInt64 == 
				instr.Operands[i].OpAsInt64Guest);
			instr.Operands[i].OpAsInt64 = vmxRootVa;
			instr.Operands[i].MappedToVmxRoot = 1;
		}
	}
	return true;
}

bool EmuExecuteInstruction(
	X64_EMULATOR_CTX* pEmu)
{
	bool ret = false;
	if (pEmu->DecodeState == DECODE_STATE_DONE && 
		pEmu->Instruction.OpcodeEntry)
	{
		const OPCODE_ENTRY* pEntry = reinterpret_cast<const OPCODE_ENTRY*>(
			pEmu->Instruction.OpcodeEntry);
		if (pEntry->Handler && MapOperandsToVmxRoot(pEmu))
		{
			OpExecuteT exec = static_cast<OpExecuteT>(pEntry->Handler);
			ret = exec(pEmu);
		}
	}
	return ret;
}

void
EmuCommitCpuState(
	X64_EMULATOR_CTX* pEmu)
{
	const X64_OPERAND& op = pEmu->Instruction.Operands[0];
	if (op.Type == OPERAND_TYPE_REG)
	{
		if (op.Register < R_FIRST_HIGH)
		{
			if (4 == op.Size) {
				pEmu->CpuState.Gpr[op.Register].AsInt64 = 0;
			}
			memcpy(&pEmu->CpuState.Gpr[op.Register].AsInt8,
				&op.OpAsInt8, op.Size);
		}
		else if (op.Register <= R_LAST_HIGH)
		{
			X64_REGISTER* reg = &pEmu->CpuState.Gpr[op.Register-R_FIRST_HIGH]; 
			*(&reg->AsInt8+1) = op.OpAsInt8;
		}
		else if (op.Register < R_LAST_SEG)
		{
			pEmu->CpuState.SegRegs[op.Register-R_FIRST_SEG].AsUint16 = 
				op.OpAsInt16;
		}
	}

	for (unsigned i = 0; i < ARRAYSIZE(pEmu->CpuState.Gpr); i++)
	{
		pEmu->SetRegisterValue(pEmu->GuestCtx,
			i, pEmu->CpuState.Gpr[i].AsInt64);
	}
	UINT_PTR rip = static_cast<UINT_PTR>(pEmu->CpuState.RipGuest.AsInt64);
	rip += pEmu->Instruction.InstructionLen;
	pEmu->SetRegisterValue(pEmu->GuestCtx, RIP_GUEST_ID, rip);
	pEmu->CpuState.Rflags.TrapF = 0;
	pEmu->CpuState.Rflags.InterruptF = 0;
	pEmu->SetRegisterValue(pEmu->GuestCtx, 
		RFLAGS_GUEST_ID,pEmu->CpuState.Rflags.AsUint32);
}

bool
EmuIsAtomicInstruction(
	X64_EMULATOR_CTX* pEmu)
{
	const OPCODE_ENTRY* pOp = reinterpret_cast<const OPCODE_ENTRY*>(
		pEmu->Instruction.OpcodeEntry);
	if (IsEtAtomic(pOp->TypeAndFlags) && 
		(pOp->Handler == XCHG_Exec || pEmu->Instruction.Flags.PrefixLock))
	{
		return true;
	}
	return false;
}

bool
EmuIsAtomicCmpExchange(
	X64_EMULATOR_CTX* pEmu)
{
	const OPCODE_ENTRY* pOp = reinterpret_cast<const OPCODE_ENTRY*>(
		pEmu->Instruction.OpcodeEntry);
	return pOp->Handler == CMPXCHG8B_Exec ||
		pOp->Handler == CMPXCHG_Exec;
}

bool 
EmuAtomicExchangeHappened(
	X64_EMULATOR_CTX* pEmu)
{
	return EmuIsAtomicCmpExchange(pEmu) && 
		!!(pEmu->CpuState.Rflags.ZeroF);
}

bool
EmuCanEmulateInstruction(
	X64_EMULATOR_CTX* pEmu)
{	
	const OPCODE_ENTRY* pOp = reinterpret_cast<const OPCODE_ENTRY*>(
		pEmu->Instruction.OpcodeEntry);
	return !!pOp->Handler;
}

static size_t // number of chars copied
sscpy(
	OUT char* dest, 
	IN OUT size_t destCapacity, // including terminating NULL 
	IN const char* src, 
	IN size_t srcLen)
{
	size_t copyLen = 0;
	if (0 != dest && destCapacity > 0 && 0 != src)
	{
		if (0 == srcLen) {
			srcLen = strlen(src);
		}
		copyLen = min(srcLen,destCapacity-1);
		memcpy(dest,src,copyLen*sizeof(*dest));
		dest[copyLen] = '\0';
	}
	return copyLen;
}

const char* GetRegisterAsString(
	const DECODED_INSTRUCTION& instr,
	size_t r)
{
	size_t opSize = instr.OperandSize;
	return GetRegisterAsString(r,opSize);
}

static const char* 
GetRegisterAsString(
	size_t reg,
	size_t opSize)
{
	static const char* regStr = "r_invalid";
	static const char* regNames[R_LAST][4] = 
	{
		{"rax", "eax",  "ax",   "al"},
		{"rcx", "ecx",  "cx",   "cl"},
		{"rdx", "edx",  "dx",   "dl"},
		{"rbx", "ebx",  "bx",   "bl"},
		{"rsp", "esp",  "sp",   "spl"},
		{"rbp", "ebp",  "bp",   "bpl"},
		{"rsi", "esi",  "si",   "sil"},
		{"rdi", "edi",  "di",   "dil"},
		{"r8",  "r8d",  "r8w",  "r8b"},
		{"r9",  "r9d",  "r9w",  "r9b"},
		{"r10", "r10d", "r10w", "r10b"},
		{"r11", "r11d", "r11w", "r11b"},
		{"r12", "r12d", "r12w", "r12b"},
		{"r13", "r13d", "r13w", "r13b"},
		{"r14", "r14d", "r14w", "r14b"},
		{"r15", "r15d", "r15w", "r15b"},
		{"ah",  "ah",   "ah",   "ah"},
		{"ch",  "ch",   "ch",   "ch"},
		{"dh",  "dh",   "dh",   "dh"},
		{"bh",  "bh",   "bh",   "bh"},
		{"es",  "es",   "es",   "es"},
		{"cs",  "cs",   "cs",   "cs"},
		{"ss",  "ss",   "ss",   "ss"},
		{"ds",  "ds",   "ds",   "ds"},
		{"fs",  "fs",   "fs",   "fs"},
		{"gs",  "gs",   "gs",   "gs"},
		{"rflags","rflags","rflags","rflags"}
	};
	
	if (reg < R_LAST)
	{
		switch (opSize)
		{
		case 16:
			break; // TODO
		case 8:
			regStr = regNames[reg][0];
			break;
		case 4:
			regStr = regNames[reg][1];
			break;
		case 2:
			regStr = regNames[reg][2];
			break;
		case 1:
			regStr = regNames[reg][3];
			break;
		default:
			ASSERT(false);
		}
	} 
   return regStr;
}

void MnemonicConcat(
	DECODED_INSTRUCTION& instr,
	const char* str,
	size_t strLen)
{
	char* dest = &instr.Mnemonic[0] + instr.MnemonicLength;
	size_t copyLen = sscpy(
		dest,
		ARRAYSIZE(instr.Mnemonic)-instr.MnemonicLength,
		str,
		strLen);
	instr.MnemonicLength += (UINT16)copyLen;
	ASSERT(instr.MnemonicLength < ARRAYSIZE(instr.Mnemonic));
}

void MnemonicConcatPtrBegin(
	DECODED_INSTRUCTION& instr,
	size_t operandSize)
{
	if (!strcmp(reinterpret_cast<const OPCODE_ENTRY*>(
		instr.OpcodeEntry)->Mnemonic,"lea"))
	{
		MnemonicConcat(instr, "[", 1);
		return;
	}
	switch (operandSize)
	{
	case 1:
		MnemonicConcat(instr, "byte ptr [", 10);
		break;
	case 2:
		MnemonicConcat(instr, "word ptr [", 10);
		break;
	case 4:
		MnemonicConcat(instr, "dword ptr [", 11);
		break;
	case 8:
		MnemonicConcat(instr, "qword ptr [", 11);
		break;
	case 6:
	case 10:
		MnemonicConcat(instr, "fword ptr [", 11);
		break;
	case 16:
		MnemonicConcat(instr, "xmmword ptr [", 13);
		break;
	default: ASSERT(false);
	}
}

void
MnemonicConcatPtrEnd(
	DECODED_INSTRUCTION& instr)
{
	MnemonicConcat(instr,"]",1);
}

void
_AddHexNumberToMnemonic(
	DECODED_INSTRUCTION& instr,
	UINT64 num,
	size_t sizeofNum)
{
	ASSERT(ARRAYSIZE(instr.Mnemonic) >= instr.MnemonicLength);
	size_t capacity = ARRAYSIZE(instr.Mnemonic)-instr.MnemonicLength;
	if (capacity) 
	{
		int len = 0;
		char* dest = &instr.Mnemonic[0] + instr.MnemonicLength;
		switch (sizeofNum)
		{
		case 8:
			len = _snprintf(dest, capacity-1, "%016I64x", num);
			break;
		case 4:
			len = _snprintf(dest, capacity-1, "%08x", num);
			break;
		case 2:
			len = _snprintf(dest, capacity-1, "%04x", num);
			break;
		case 1:
			len = _snprintf(dest, capacity-1, "%02x", num);
			break;
		default:
			len = _snprintf(dest, capacity-1, "%I64x", num);
		}
		if (-1 == len) {
			len = 0;
		}
		ASSERT((size_t)len < capacity);
		instr.MnemonicLength += (UINT16)len;
		instr.Mnemonic[instr.MnemonicLength] = 0;
	}
}

void
AddHexNumberToMnemonic(
	DECODED_INSTRUCTION& instr,
	UINT64 _num,
	size_t sizeofNum,
	bool hexId,
	bool align)
{	
	size_t num = static_cast<size_t>(_num);
	if (sizeofNum && sizeofNum != sizeof(num)) {
		num &= ((UINT64)1<<(sizeofNum*8)) - 1;
	}
	if (hexId && num > 0)
	{
		//
		// Add leading zero if the first nibble is greater than 9
		//
		int i = sizeof(num)*8-4;
		while (i >= 0)
		{
			if ((num>>i)&0xf) {
				if (((num>>i)&0xf) > 0x9) {
					if (!align || (i == (sizeof(num)*8-4))) {
						MnemonicConcat(instr,"0",1);
					}
				}
				break;
			}
			i -= 4;
		}
	}

	_AddHexNumberToMnemonic(instr,num, align ? sizeofNum : 0);
	
	if (hexId && num > 9) {
		MnemonicConcat(instr,"h",1);
	}
}

void
AddPtrToMnemonic(
	X64_EMULATOR_CTX* emu,
	INT64 ptr,
	bool hexId)
{
	AddHexNumberToMnemonic(
		emu->Instruction,
		(UINT64)ptr,
		emu->Instruction.AddressSize,
		hexId,
		true);
}

void AddSibOperandToMnemonic(
	X64_EMULATOR_CTX* emu,
	UINT8 reg,
	size_t operandSize)
{
	DECODED_INSTRUCTION& instr = emu->Instruction;

	MnemonicConcatPtrBegin(instr,operandSize);
	MnemonicConcat(
		instr,
		GetRegisterAsString(reg,instr.AddressSize));
	if (instr.SibScale)
	{
		MnemonicConcat(instr,"+",1);
		MnemonicConcat(instr,GetRegisterAsString(
			instr.SibIndex,
			instr.AddressSize));
		if (instr.SibScale > 1)
		{
			MnemonicConcat(instr,"*",1);
			AddHexNumberToMnemonic(instr,instr.SibScale,1,true);
		}
	}
	AddDisplacementToMnemonic(instr);
	MnemonicConcatPtrEnd(instr);
}

void AddDisplacementToMnemonic(
	DECODED_INSTRUCTION& instr)
{
	if (instr.DisplacementSize && instr.Displacement)
	{
		if (instr.MnemonicLength > 0 && instr.Mnemonic[instr.MnemonicLength] != '[') {
			MnemonicConcat(instr,(instr.Displacement > 0) ? "+" : "-",1);
		}
		AddHexNumberToMnemonic(instr,
			(instr.Displacement > 0) ? instr.Displacement : -instr.Displacement,
			instr.DisplacementSize,
			true);
	}
}

void
AddImmediateOpToMnemonic(
	DECODED_INSTRUCTION& instr,
	size_t opIdx)
{
	AddHexNumberToMnemonic(
		instr,
		instr.Operands[opIdx].OpAsInt64,
		instr.Operands[opIdx].Size,
		true);
}

const char* 
EmuGetDecodedMnemonic(
	X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction; 
	ASSERT(instr.OpcodeEntry);
	if (0 == instr.Flags.InstructionDecoded) 
	{
		EmuDecodeInstruction(pEmu);
	}
	if (0 == instr.Flags.DecodedMnemonic)
	{	
		// Add address pointed to by RIP
		AddHexNumberToMnemonic(
			instr,
			pEmu->CpuState.RipGuest.AsInt64,
			IsIn64BitMode(pEmu) ? 8 : 4,
			false,
			true);
		MnemonicConcat(instr," ");
		
		// Add opcode
		const UINT8* opCode = (const UINT8*)(pEmu->CpuState.RipOrig.AsInt64 ?
			pEmu->CpuState.RipOrig.AsPtr8 : pEmu->CpuState.RipGuest.AsPtr8);
		for (size_t i = 0; i < instr.InstructionLen; i++)
		{
			AddHexNumberToMnemonic(
				instr,
				opCode[i],
				1,
				false,
				true);
		}
		MnemonicConcat(instr," ",1);

		if (instr.Flags.PrefixLock) 
		{
			MnemonicConcat(instr,"lock",4);
			MnemonicConcat(instr," ", 1);
		} 
		else if (instr.Flags.PrefixRepne) 
		{
			MnemonicConcat(instr,"repne",5);
			MnemonicConcat(instr," ", 1);
		} 
		else if (instr.Flags.PrefixRepz) 
		{
			MnemonicConcat(instr,"rep",3);
			MnemonicConcat(instr," ", 1);
		}
		
		// Add actual mnemonic from the opcode table
		const char* mnemonic = reinterpret_cast<const OPCODE_ENTRY*>(
			instr.OpcodeEntry)->Mnemonic;
		ASSERT(mnemonic);
		MnemonicConcat(instr,mnemonic);
		// Add operands
		if (instr.Flags.OperandCount > 0)
		{
			MnemonicConcat(instr," ",1);
			ResolveOperands(pEmu,true);
		}
		
		instr.Flags.DecodedMnemonic = 1;
	}
	return instr.Mnemonic;
}


static const UINT8 s_ParityTable[256] = 
{
  //000	001	010	011	100	101	110	111	1000 1001 1010 1011 1100 1101 1110 1111
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //0000
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//0001
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//0010
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //0011
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//0100
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //0101
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //0110
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//0111
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//1000
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //1001
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //1010
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//1011
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //1100
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//1101
	0,	1,	1,  0,  1,  0,  0,  1,	1,   0,   0,   1,   0,   1,   1,   0,	//1110
	1,	0,	0,	1,	0,	1,	1,	0,	0,   1,   1,   0,   1,   0,   0,   1,   //1111
};

inline bool IsSpanningPagesFwd(const void* p, size_t size)
{
	ASSERT(p);
	ASSERT(size);
	UINT_PTR ptr = *reinterpret_cast<UINT_PTR const *>(&p);
	if (size > PAGE_SIZE || ((ptr >> PAGE_SHIFT) != ((ptr+size-1) >> PAGE_SHIFT)))
	{
		return true;
	}
	return false;
}

inline bool IsSpanningPagesBack(UINT8* p, size_t size)
{
	ASSERT(p);
	ASSERT(size);
	UINT_PTR ptr = *reinterpret_cast<UINT_PTR const *>(&p);
	if (size > PAGE_SIZE || ((ptr >> PAGE_SHIFT) != ((ptr-size-1) >> PAGE_SHIFT)))
	{
		return true;
	}
	return false;
}

typedef void (*OpExecHelperT) (X64_EMULATOR_CTX* pEmu);

template<class T>
inline void SetStatusFlagsAfterAdd(
	RFLAGS& rfl,
	const T& op1,
	const T& op2,
	const UINT8 cf,
	const T& res)
{
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T max = static_cast<T>(-1);
#pragma warning (default:4309)	
	rfl.CarryF = (((UINT64)max-(UINT64)op1) < (UINT64)op2) ? 1 : 0;
	if (!rfl.CarryF)
	{
		if (((UINT64)max-(UINT64)op1)-(UINT64)op2 < cf)
		{
			rfl.CarryF = 1;
		}
	}
	if (op2 + cf < op2)
	{
		rfl.OverflowF = 1;
	}
	else
	{
		rfl.OverflowF = !((msb&op1)^(msb&(op2+cf)));
		rfl.OverflowF &= !!((msb&op1) ^ (msb&res));
	}
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
	rfl.AdjustF = (((UINT8)0xf-(UINT8)(op1&0xf)) < (UINT8)(op2&0xf)) ? 1 : 0;
	if (!rfl.AdjustF)
	{
		if (((UINT8)0xf-(UINT8)(op1&0xf))-(UINT8)(op2&0xf) < cf)
		{
			rfl.AdjustF = 1;
		}
	}
}

template<class T>
inline void SetStatusFlagsAfterSub(
	RFLAGS& rfl,
	T op1,
	T op2,
	const UINT8 cf,
	const T& res)
{
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
#pragma warning (default:4309)	
	
	rfl.CarryF = 0;
	if ((UINT64)op1 < (UINT64)op2 || (UINT64)op1 -(UINT64)op2 < cf)
	{
		rfl.CarryF = 1;
	}
	rfl.OverflowF = 0;
	if (op2 + cf < op2)
	{
		rfl.OverflowF = 1;
	}
	else
	{
		T _op2 = op2+cf;
		if ((msb&op1)^(msb&_op2))
		{
			if ((msb&op1) ^ (msb&res))
			{
				rfl.OverflowF = 1;
			}
		}
	}
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
	rfl.AdjustF = 0;
	if ((UINT8)(op1&0xf) < (UINT8)(op2&0xf) ||
		(UINT8)(op1&0xf)-(UINT8)(op2&0xf) < cf)
	{
		rfl.AdjustF = 1;
	}
}


template <class T>
void  ADD_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1 + op2;
	SetStatusFlagsAfterAdd(rfl, op1, op2, 0, res);
}

bool ADD_Exec(X64_EMULATOR_CTX* pEmu) 
{
	static OpExecHelperT s_Helpers[] = 
	{
		0, ADD_Helper<INT8>, 
		ADD_Helper<INT16>, 0,
		ADD_Helper<INT32>, 0,0,0,
		ADD_Helper<INT64>
	};

	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}

	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}

	s_Helpers[opSize](pEmu);
	return true;
}

template <class T>
void  ADDC_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = 
		op1 + op2 + (UINT8)rfl.CarryF;
	SetStatusFlagsAfterAdd(rfl, op1, op2, rfl.CarryF, res);
}

bool ADDC_Exec(X64_EMULATOR_CTX* pEmu) 
{
	static OpExecHelperT s_Helpers[] = 
	{
		0, ADDC_Helper<INT8>, 
		ADDC_Helper<INT16>, 0,
		ADDC_Helper<INT32>, 0,0,0,
		ADDC_Helper<INT64>
	};

	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}

	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}

	s_Helpers[opSize](pEmu);
	return true;
}


template <class T>
void  OR_Helper(X64_EMULATOR_CTX* pEmu)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
#pragma warning (default:4309)
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1 | op2;
	rfl.OverflowF = rfl.CarryF = 0;
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
}

bool OR_Exec(X64_EMULATOR_CTX* pEmu)
{	
	static OpExecHelperT s_Helpers[] = 
	{
		0, OR_Helper<INT8>, 
		OR_Helper<INT16>, 0,
		OR_Helper<INT32>, 0,0,0,
		OR_Helper<INT64>
	};
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}
	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}
	s_Helpers[opSize](pEmu);
	return true;
}

template <class T>
void  SBB_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = 
		op1 - (op2 + (UINT8)rfl.CarryF);
	SetStatusFlagsAfterSub(rfl, op1, op2, rfl.CarryF, res);
}

bool SBB_Exec(X64_EMULATOR_CTX* pEmu)
{
	static OpExecHelperT s_Helpers[] = 
	{
		0, SBB_Helper<INT8>, 
		SBB_Helper<INT16>, 0,
		SBB_Helper<INT32>, 0,0,0,
		SBB_Helper<INT64>
	};
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}
	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}
	s_Helpers[opSize](pEmu);
	return true;
}

template <class T>
void  SUB_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1 - op2;
	SetStatusFlagsAfterSub(rfl, op1, op2, 0, res);
}

bool SUB_Exec(X64_EMULATOR_CTX* pEmu)
{
	static OpExecHelperT s_Helpers[] = 
	{
		0, SUB_Helper<INT8>, 
		SUB_Helper<INT16>, 0,
		SUB_Helper<INT32>, 0,0,0,
		SUB_Helper<INT64>
	};
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}
	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}
	s_Helpers[opSize](pEmu);
	return true;
}

template <class T>
void  AND_Helper(X64_EMULATOR_CTX* pEmu)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
#pragma warning (default:4309)
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1 & op2;
	rfl.OverflowF = rfl.CarryF = 0;
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
}

bool AND_Exec(X64_EMULATOR_CTX* pEmu)
{	
	static OpExecHelperT s_Helpers[] = 
	{
		0, AND_Helper<INT8>, 
		AND_Helper<INT16>, 0,
		AND_Helper<INT32>, 0,0,0,
		AND_Helper<INT64>
	};
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}
	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}
	s_Helpers[opSize](pEmu);
	return true;
}

template <class T>
void  XOR_Helper(X64_EMULATOR_CTX* pEmu)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
#pragma warning (default:4309)
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1 ^ op2;
	rfl.OverflowF = rfl.CarryF = 0;
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
}

bool XOR_Exec(X64_EMULATOR_CTX* pEmu)
{	
	static OpExecHelperT s_Helpers[] = 
	{
		0, XOR_Helper<INT8>, 
		XOR_Helper<INT16>, 0,
		XOR_Helper<INT32>, 0,0,0,
		XOR_Helper<INT64>
	};
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM ||
		opSize > ARRAYSIZE(s_Helpers) || !s_Helpers[opSize])
	{
		ASSERT(false);
		return false;
	}
	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize))
	{
		return false;
	}
	s_Helpers[opSize](pEmu);
	return true;
}

bool MOV_Exec(X64_EMULATOR_CTX* pEmu)
{
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Flags.OperandCount != 2) 
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,
			"2 operands expected",
			pEmu->Instruction.Flags.OperandCount));
		return false;
	}
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM ||
		pEmu->Instruction.Operands[1].Type == OPERAND_TYPE_MEM) 
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,
			"Unexpected operand types",
			pEmu->Instruction.Operands[0].Type,
			pEmu->Instruction.Operands[1].Type));
		return false;
	}
	if (IsSpanningPagesFwd(pEmu->Instruction.Operands[0].Op, opSize)) {
		return false;
	}

	if (OPERAND_TYPE_REG == pEmu->Instruction.Operands[1].Type)
	{
		memcpy(pEmu->Instruction.Operands[0].Op,
			&pEmu->Instruction.Operands[1].OpAsInt64,
			opSize);
	}
	else
	{
		ASSERT(OPERAND_TYPE_IMM == pEmu->Instruction.Operands[1].Type);
		memcpy(pEmu->Instruction.Operands[0].Op,
			&pEmu->Instruction.Operands[1].OpAsInt64,
			opSize);
	}
	return true;
}

bool MOV_2Reg_Exec(X64_EMULATOR_CTX* pEmu)
{
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	if (pEmu->Instruction.Flags.OperandCount != 2) 
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,
			"2 operands expected",
			pEmu->Instruction.Flags.OperandCount));
		return false;
	}
	ASSERT(OPERAND_TYPE_REG == pEmu->Instruction.Operands[0].Type);
	if (OPERAND_TYPE_MEM == pEmu->Instruction.Operands[1].Type)
	{
		memcpy(&pEmu->Instruction.Operands[0].Op,
			pEmu->Instruction.Operands[1].Op,
			opSize);
	}
	else if (OPERAND_TYPE_IMM == pEmu->Instruction.Operands[1].Type ||
		OPERAND_TYPE_REG == pEmu->Instruction.Operands[1].Type)
	{
		memcpy(&pEmu->Instruction.Operands[0].Op,
			&pEmu->Instruction.Operands[1].OpAsInt64,
			opSize);
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,
			"Unexpected operand type",
			pEmu->Instruction.Operands[1].Type));
		return false;
	}
	return true;
}

void MOVS_Fwd(X64_EMULATOR_CTX* pEmu, size_t count)
{
	memmove(pEmu->Instruction.Operands[0].Op,
		pEmu->Instruction.Operands[1].Op,
		pEmu->Instruction.Operands[0].Size * count);
}

void MOVS_Rev(X64_EMULATOR_CTX* pEmu, size_t count)
{
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	while (count-- != 0)
	{
		memcpy(pEmu->Instruction.Operands[0].Op,
			pEmu->Instruction.Operands[1].Op, opSize);
		pEmu->Instruction.Operands[0].Op -= opSize;
		pEmu->Instruction.Operands[1].Op -= opSize;
	}
}

bool MOVS_Exec(X64_EMULATOR_CTX* pEmu)
{
	return StringInstructionExecShell(pEmu, MOVS_Fwd, MOVS_Rev, true);
}

bool SETO_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = pEmu->CpuState.Rflags.OverflowF;
	return true;
}

bool SETNO_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = !pEmu->CpuState.Rflags.OverflowF;
	return true;
}

bool SETB_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = pEmu->CpuState.Rflags.CarryF;
	return true;
}

bool SETAE_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = !pEmu->CpuState.Rflags.CarryF;
	return true;
}

bool SETE_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = pEmu->CpuState.Rflags.ZeroF;
	return true;
}
bool SETNE_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = !pEmu->CpuState.Rflags.ZeroF;
	return true;
}
bool SETBE_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = 
		static_cast<UINT8>(pEmu->CpuState.Rflags.CarryF | 
		pEmu->CpuState.Rflags.ZeroF);
	return true;
}
bool SETA_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = 
		static_cast<UINT8>(!pEmu->CpuState.Rflags.CarryF & 
		!pEmu->CpuState.Rflags.ZeroF);
	return true;
}
bool SETS_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = pEmu->CpuState.Rflags.SignF;
	return true;
}
bool SETNS_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = !pEmu->CpuState.Rflags.SignF;
	return true;
}
bool SETP_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = pEmu->CpuState.Rflags.ParityF;
	return true;
}
bool SETNP_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = !pEmu->CpuState.Rflags.ParityF;
	return true;
}
bool SETL_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = 
		static_cast<UINT8>(pEmu->CpuState.Rflags.SignF ^
		pEmu->CpuState.Rflags.OverflowF);
	return true;
}
bool SETNL_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = 
		static_cast<UINT8>(!!(pEmu->CpuState.Rflags.SignF ==
		pEmu->CpuState.Rflags.OverflowF));
	return true;
}
bool SETLE_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = static_cast<UINT8>(
		(pEmu->CpuState.Rflags.SignF ^
		pEmu->CpuState.Rflags.OverflowF) |
		pEmu->CpuState.Rflags.ZeroF);
	return true;
}
bool SETG_Exec(X64_EMULATOR_CTX* pEmu)
{
	if (pEmu->Instruction.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		return false;
	}
	*pEmu->Instruction.Operands[0].Op = 
		!!(pEmu->CpuState.Rflags.SignF ==
		pEmu->CpuState.Rflags.OverflowF) &
		!pEmu->CpuState.Rflags.ZeroF;
	return true;
}

template <class T>
void  SHLD_Helper(X64_EMULATOR_CTX* pEmu, T shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	T res;
	if (shift < bitCnt)
	{
		res = (op1 << shift) | (op2 >> (bitCnt-shift));
		//
		// Carry flag is set to the last bit that falls out of the dest/op1
		//
		rfl.CarryF = !!(op1 & (static_cast<T>(1) << (bitCnt-shift)));
	}
	else
	{
		//
		// According to the Intel manual this case should yield undefined results,
		// but actually the CPU acts very predictably - op2 is shifted entirely into
		// op1 and then the result is op1 shifted by shift-bitCnt.
		//
		T _shift = shift - bitCnt;
		res = (op2 << _shift) | (op1 >> (bitCnt-_shift));
		rfl.CarryF = !!(op2 & (static_cast<T>(1) << (bitCnt-_shift)));
	}
	*reinterpret_cast<T*>(instr.Operands[0].Op) = res;
	
	//
	// Overflow flag is set only if there is a sign change and count is 1
	//
	//rfl.OverflowF = 0;
	if (1 == shift)
	{
		rfl.OverflowF = !!((res&msb)^(op1&msb));
	}

	//
	// Sign, Zero & Parity flags are business as usual
	//
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
}

bool SHLD_Exec(X64_EMULATOR_CTX* pEmu)
{
	UINT8 count;
	size_t opSize;
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	if (instr.Flags.OperandCount != 3)
	{
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG ||
		instr.Operands[2].Type != OPERAND_TYPE_IMM)
	{
		return false;
	}
	count = (UINT8)((instr.Flags.RexPresent && instr.Rex.W) ? 
		(instr.Operands[2].OpAsInt64 & 0x3f) : 
		(instr.Operands[2].OpAsInt64 & 0x1f));
	if (0 == count)
	{
		return true; // nop
	}
	opSize = instr.Operands[0].Size;
	if (opSize == sizeof(UINT16))
	{
		SHLD_Helper<UINT16>(pEmu, count);
	}
	else if (opSize == sizeof(UINT32))
	{
		SHLD_Helper<UINT32>(pEmu, count);
	}
	else if (opSize == sizeof(UINT64))
	{
		SHLD_Helper<UINT64>(pEmu, count);
	}
	else
	{
		return false;
	}
	return true;
}

bool SHLD_CL_Exec(X64_EMULATOR_CTX* pEmu)
{
	UINT8 count;
	size_t opSize;
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	if (instr.Flags.OperandCount != 3)
	{
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG)
	{
		return false;
	}
	count = pEmu->CpuState.Gpr[R_RCX].AsInt8;
	count = (instr.Flags.RexPresent && instr.Rex.W) ? (count & 0x3f) : 
		(count & 0x1f);
	opSize = instr.Operands[0].Size;
	if (0 == count)
	{
		return true; // nop
	}
	if (opSize == sizeof(UINT16))
	{
		SHLD_Helper<UINT16>(pEmu, count);
	}
	else if (opSize == sizeof(UINT32))
	{
		SHLD_Helper<UINT32>(pEmu, count);
	}
	else if (opSize == sizeof(UINT64))
	{
		SHLD_Helper<UINT64>(pEmu, count);
	}
	else
	{
		return false;
	}
	return true;
}

template <class T>
void  SHRD_Helper(X64_EMULATOR_CTX* pEmu, UINT8 shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	T op2 = static_cast<T>(instr.Operands[1].OpAsInt64);
	T res;
	if (shift < bitCnt)
	{
		res = (op1 >> shift) | (op2 << (bitCnt-shift));
		//
		// Carry flag is set to the last bit that falls out of the dest/op1
		//
		rfl.CarryF = !!(op1 & (static_cast<T>(1) << (shift-1)));
	}
	else
	{
		//
		// According to the Intel manual this case should yield undefined results,
		// but actually the CPU acts very predictably - op2 is shifted entirely into
		// op1 and then the result is op1 shifted by shift-bitCnt.
		//
		T _shift = shift-bitCnt;
		res = (op2 >> _shift) | (op1 << (bitCnt-_shift));
		rfl.CarryF = !!(op2 & (static_cast<T>(1) << (_shift-1)));
	}
	*reinterpret_cast<T*>(instr.Operands[0].Op) = res;
	
	//
	// Overflow flag is set only if there is a sign change and count is 1
	//
	rfl.OverflowF = 0;
	if (1 == shift)
	{
		rfl.OverflowF = !!((res&msb)^(op1&msb));
	}

	//
	// Sign, Zero & Parity flags are business as usual
	//
	rfl.SignF = !!(msb&res);
	rfl.ParityF = s_ParityTable[res&0xff];
	rfl.ZeroF = !res;
}


bool _SHRD_Exec(X64_EMULATOR_CTX* pEmu, const size_t _count)
{
	size_t opSize;
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	UINT8 count = (UINT8)((instr.Flags.RexPresent && instr.Rex.W) ? 
		(_count & 0x3f) : (_count & 0x1f));
	if (0 == count)
	{
		return true; // nop
	}
	opSize = instr.Operands[0].Size;
	if (opSize == sizeof(UINT16))
	{
		SHRD_Helper<UINT16>(pEmu, count);
	}
	else if (opSize == sizeof(UINT32))
	{
		SHRD_Helper<UINT32>(pEmu, count);
	}
	else if (opSize == sizeof(UINT64))
	{
		SHRD_Helper<UINT64>(pEmu, count);
	}
	else
	{
		return false;
	}
	return true;
}

bool SHRD_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	if (instr.Flags.OperandCount != 3)
	{
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG ||
		instr.Operands[2].Type != OPERAND_TYPE_IMM)
	{
		return false;
	}
	return _SHRD_Exec(pEmu, static_cast<size_t>(instr.Operands[2].OpAsInt64));
}

bool SHRD_CL_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	if (instr.Flags.OperandCount != 3)
	{
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG)
	{
		return false;
	}
	return _SHRD_Exec(pEmu, pEmu->CpuState.Gpr[R_RCX].AsInt8);
}

INT64
EmuGetRepeatCount(
	X64_EMULATOR_CTX* pEmu)
{
	INT64 count = 1;
	const DECODED_INSTRUCTION& instr = pEmu->Instruction;
	
	//
	// In 64 bit mode the counter is RCX if REX.W is set; for
	// all the rest of the cases it is ECX
	//
	if (instr.Flags.PrefixRepne || instr.Flags.PrefixRepz)
	{
		if (instr.Flags.RexPresent && instr.Rex.W)
		{
			if ((count = pEmu->CpuState.Gpr[R_RCX].AsInt64) < 0)
			{
				count = MAXINT64 + count + 1;
			}
		}
		else
		{
		    if ((count = pEmu->CpuState.Gpr[R_RCX].AsInt32) < 0)
			{
				count = MAXINT32 + static_cast<INT32>(count) + 1;
			}
		}
	}
	return count;
}

bool StringInstructionExecShell(
	X64_EMULATOR_CTX* pEmu, 
	StringOpT fwdOp, 
	StringOpT retreatOp,
	bool setEsi)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	INT64 count = EmuGetRepeatCount(pEmu);
	bool decRcx = !!(instr.Flags.PrefixRepne || instr.Flags.PrefixRepz);
	
	ASSERT (instr.Operands[0].Type == OPERAND_TYPE_MEM);
	ASSERT (!setEsi || instr.Operands[1].Type == OPERAND_TYPE_MEM);

	//
	// If Eflags.DF is 0, then we advance RSI/RDI forward, else we do
	// so backwards
	//
	if (0 == pEmu->CpuState.Rflags.DirectionF && 
		IsSpanningPagesFwd(instr.Operands[0].Op, static_cast<size_t>(opSize * count)))
	{
		return false;
	}
	if (0 == pEmu->CpuState.Rflags.DirectionF && 
		IsSpanningPagesFwd(instr.Operands[0].Op, static_cast<size_t>(opSize * count)))
	{
		return false;
	}

	if (0 == pEmu->CpuState.Rflags.DirectionF)
	{
		fwdOp(pEmu, static_cast<size_t>(count));
		if (setEsi)
		{
			pEmu->CpuState.Gpr[R_RSI].AsInt64 += opSize * count;
		}
		pEmu->CpuState.Gpr[R_RDI].AsInt64 += opSize * count;
	}
	else
	{
		retreatOp(pEmu, static_cast<size_t>(count));
		if (setEsi)
		{
			pEmu->CpuState.Gpr[R_RSI].AsInt64 -= opSize* count;
		}
		pEmu->CpuState.Gpr[R_RDI].AsInt64 -= opSize* count;
	}
	if (decRcx)
	{
		pEmu->CpuState.Gpr[R_RCX].AsInt64 = 0;
	}
	return true;
}


INT8* BitTestExecCommon(X64_EMULATOR_CTX* pEmu, INT8* pBit)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	INT64 bitOffset;
	INT8* pBitBase;
	INT8 bit;
	 
	ASSERT (instr.Operands[0].Type == OPERAND_TYPE_MEM);
	ASSERT (instr.Operands[1].Type == OPERAND_TYPE_REG ||
		instr.Operands[1].Type == OPERAND_TYPE_IMM);

	bitOffset = instr.Operands[1].OpAsInt64;
	if (opSize == sizeof(INT16))
	{
		 bitOffset &= 0xffff;
	}
	else if (opSize == sizeof(INT32))
	{
		bitOffset &= 0xffffffff;
	}
	pBitBase = instr.Operands[0].Op + bitOffset/8;
	bit = 1 << (bitOffset & 0x7);
	pEmu->CpuState.Rflags.CarryF = !!(*pBitBase & bit);
	*pBit = bit;
	return pBitBase;
}

bool BTR_Exec(X64_EMULATOR_CTX* pEmu)
{
	INT8 bit;
	INT8* pBitBase = BitTestExecCommon(pEmu, &bit);
	*pBitBase &= ~bit;
	return true;
}

bool BTC_Exec(X64_EMULATOR_CTX* pEmu)
{
	INT8 bit;
	INT8* pBitBase = BitTestExecCommon(pEmu, &bit);
	*pBitBase ^= bit;
	return true;
}

bool BTS_Exec(X64_EMULATOR_CTX* pEmu)
{
	INT8 bit;
	INT8* pBitBase = BitTestExecCommon(pEmu, &bit);
	*pBitBase |= bit;
	return true;
}

bool BT_Exec(X64_EMULATOR_CTX* pEmu)
{
	INT8 dummy;
	BitTestExecCommon(pEmu, &dummy);
	return true;
}

template <class T>
void  ROL_Helper(X64_EMULATOR_CTX* pEmu, const T _shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	T shift = _shift % bitCnt;
	if (shift>=0 && _shift)
	{
		DECODED_INSTRUCTION& instr=pEmu->Instruction;
		RFLAGS& rfl = pEmu->CpuState.Rflags;
		T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
		T loMask = (static_cast<T>(1) << (bitCnt-shift)) - 1;
		T hiMask = ~loMask;
		T res = ((op1 & loMask) << shift) | ((op1 & hiMask) >> (bitCnt-shift));
		*reinterpret_cast<T*>(instr.Operands[0].Op) = res;
		rfl.CarryF = !!(res & 0x1);
		if (1 == shift)
		{
			rfl.OverflowF = (!!(res&msb)) ^ rfl.CarryF;
		}
	}
}

bool ROL_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	UINT8 shift = 0;
	
	switch(instr.OpCode[0])
	{
	case 0xd0:
	case 0xd1:
		shift = 1;
		break;
	case 0xd2:
	case 0xd3:
		shift = pEmu->CpuState.Gpr[R_RCX].AsInt8;
		break;
	case 0xc1:
	case 0xc0:
		if (instr.Flags.OperandCount != 2)
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,
				"Invalid operand count when executing ROL_Exec 0xc1",
				instr.Flags.OperandCount));
		}
		shift = static_cast<UINT8>(instr.Operands[1].OpAsInt64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,
			"Executing ROL_Exec with unknown opcode!", 
			instr.OpCode[0]));
		return false;
	}

	if (opSize == sizeof(UINT8))
	{
		ROL_Helper<UINT8>(pEmu,shift);
	}
	else if (opSize == sizeof(UINT16))
	{
		ROL_Helper<UINT16>(pEmu,shift);
	}
	else if (opSize == sizeof(UINT32))
	{
		ROL_Helper<UINT32>(pEmu,shift);
	}
	else if (opSize == sizeof(UINT64))
	{
		ROL_Helper<UINT64>(pEmu,shift);
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"ROL_Exec - invalid opSize",opSize));
		return false;
	}
	return true;
}

template <class T>
void  ROR_Helper(X64_EMULATOR_CTX* pEmu, const T _shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	T shift = _shift % bitCnt;

	//
	// There seems to be discrepancy between what I see executed by the CPU and
	// the Intel manual. The latter clearly shows in the pseudo code that if the
	// shift (they call it tempCount) is 0 no instruction is executed, but it 
	// seems that the CF mimics the MSB of the destination if the original 
	// _shift (the Intel manual calls it "count") is not 0. For example for 1B
	// opsize if the _shift is 0x10, the resultant shif should be 0 due to the
	// modulus 8 and in this case according to the manual no op should be 
	// executed. The silicon seems to behave differently.
	//
	if (shift>=0 && _shift)
	{
		DECODED_INSTRUCTION& instr=pEmu->Instruction;
		RFLAGS& rfl = pEmu->CpuState.Rflags;
		T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
		T loMask = (static_cast<T>(1) << shift) - 1;
		T hiMask = ~loMask;
		T res = ((op1 & loMask) << (bitCnt-shift)) | ((op1 & hiMask) >> shift);
		*reinterpret_cast<T*>(instr.Operands[0].Op) = res;
		rfl.CarryF = !!(res & msb);
		if (1 == shift)
		{
			rfl.OverflowF = !!(res&msb)^!!(res&(msb>>1));
		}
	}
}

bool ROR_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	UINT8 shift = 0;
	switch(instr.OpCode[0])
	{
	case 0xd0:
	case 0xd1:
		shift = 1;
		break;
	case 0xd2:
	case 0xd3:
		shift = pEmu->CpuState.Gpr[R_RCX].AsInt8;
		break;
	case 0xc1:
	case 0xc0:
		if (instr.Flags.OperandCount != 2)
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,
				"Invalid operand count when executing ROL_Exec 0xc1",
				instr.Flags.OperandCount));
		}
		shift = static_cast<UINT8>(instr.Operands[1].OpAsInt64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,
			"Executing ROL_Exec with unknown opcode!", 
			instr.OpCode[0]));
		return false;
	}

	if (opSize == sizeof(UINT8))
	{
		ROR_Helper<UINT8>(pEmu,shift);
	}
	else if (opSize == sizeof(UINT16))
	{
		ROR_Helper<UINT16>(pEmu,shift);
	}
	else if (opSize == sizeof(UINT32))
	{
		ROR_Helper<UINT32>(pEmu,shift);
	}
	else if (opSize == sizeof(UINT64))
	{
		ROR_Helper<UINT64>(pEmu,shift);
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"ROR_Exec - invalid opSize",opSize));
		return false;
	}
	return true;
}

template <class T>
void  RCL_Helper(X64_EMULATOR_CTX* pEmu, const T shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	if (shift>0)
	{
		DECODED_INSTRUCTION& instr=pEmu->Instruction;
		RFLAGS& rfl = pEmu->CpuState.Rflags;
		T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
		T lastBitToFallOut = static_cast<T>(1) << (bitCnt-shift);
		T loMask = lastBitToFallOut - 1;
		T hiMask = ~((lastBitToFallOut<<1)-1);
		T res = ((op1 & loMask) << shift) | ((op1 & hiMask) >> (bitCnt-shift+1));
		if (rfl.CarryF)
		{
			res |= static_cast<T>(1) << (shift-1);
		}
		rfl.CarryF = !!(op1&lastBitToFallOut);
		*reinterpret_cast<T*>(instr.Operands[0].Op) = res;
		if (1 == shift)
		{
			rfl.OverflowF = (!!(res&msb)) ^ rfl.CarryF;
		}
	}
}

bool RCL_Exec(X64_EMULATOR_CTX* pEmu)
{	
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	UINT8 shift = 0;
	
	switch(instr.OpCode[0])
	{
	case 0xd0:
	case 0xd1:
		shift = 1;
		break;
	case 0xd2:
	case 0xd3:
		shift = pEmu->CpuState.Gpr[R_RCX].AsInt8;
		break;
	case 0xc1:
	case 0xc0:
		if (instr.Flags.OperandCount != 2)
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid operand count when executing ROL_Exec 0xc1",
				instr.Flags.OperandCount));
		}
		shift = static_cast<UINT8>(instr.Operands[1].OpAsInt64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"Executing ROL_Exec with unknown opcode!", 
			instr.OpCode[0]));
		return false;
	}

	if (opSize == sizeof(UINT8))
	{
		RCL_Helper<UINT8>(pEmu,(shift & 0x1f)%9);
	}
	else if (opSize == sizeof(UINT16))
	{
		RCL_Helper<UINT16>(pEmu,(shift & 0x1f)%17);
	}
	else if (opSize == sizeof(UINT32))
	{
		RCL_Helper<UINT32>(pEmu,(shift & 0x1f)%32);
	}
	else if (opSize == sizeof(UINT64))
	{
		RCL_Helper<UINT64>(pEmu, shift&0x3f);
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"RCL_Exec - invalid opSize",opSize));
		return false;
	}
	return true;
}

template <class T>
void  RCR_Helper(X64_EMULATOR_CTX* pEmu, const T shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	if (shift>0)
	{
		DECODED_INSTRUCTION& instr=pEmu->Instruction;
		RFLAGS& rfl = pEmu->CpuState.Rflags;
		T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
		T lastBitToFallOut = static_cast<T>(1) << (shift-1);
		T loMask = lastBitToFallOut - 1;
		T hiMask = ~((lastBitToFallOut<<1)-1);
		T res = ((op1 & loMask) << (bitCnt-shift+1)) | ((op1 & hiMask) >> shift);
		if (rfl.CarryF)
		{
			res |= static_cast<T>(1) << (bitCnt-shift);
		}
		rfl.CarryF = !!(op1&lastBitToFallOut);
		*reinterpret_cast<T*>(instr.Operands[0].Op) = res;
		if (1 == shift)
		{
			rfl.OverflowF = !!(res&msb)^!!(res&(msb>>1));
		}
	}
}

bool RCR_Exec(X64_EMULATOR_CTX* pEmu)
{	
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	UINT8 shift = 0;
	
	switch(instr.OpCode[0])
	{
	case 0xd0:
	case 0xd1:
		shift = 1;
		break;
	case 0xd2:
	case 0xd3:
		shift = pEmu->CpuState.Gpr[R_RCX].AsInt8;
		break;
	case 0xc1:
	case 0xc0:
		if (instr.Flags.OperandCount != 2)
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid operand count when executing ROL_Exec 0xc1",
				instr.Flags.OperandCount));
		}
		shift = static_cast<UINT8>(instr.Operands[1].OpAsInt64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"Executing ROL_Exec with unknown opcode!", 
			instr.OpCode[0]));
		return false;
	}

	if (opSize == sizeof(UINT8))
	{
		RCR_Helper<UINT8>(pEmu,(shift & 0x1f)%9);
	}
	else if (opSize == sizeof(UINT16))
	{
		RCR_Helper<UINT16>(pEmu,(shift & 0x1f)%17);
	}
	else if (opSize == sizeof(UINT32))
	{
		RCR_Helper<UINT32>(pEmu, shift&0x1f);
	}
	else if (opSize == sizeof(UINT64))
	{
		RCR_Helper<UINT64>(pEmu, shift&0x3f);
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"RCR_Exec - invalid opSize",opSize));
		return false;
	}
	return true;
}

template <class T>
void  SHL_Helper(X64_EMULATOR_CTX* pEmu, const T shift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	if (shift>0)
	{
		DECODED_INSTRUCTION& instr=pEmu->Instruction;
		RFLAGS& rfl = pEmu->CpuState.Rflags;
		T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
		T lastBitToFallOut = bitCnt>shift ? 
			(static_cast<T>(1) << (bitCnt-shift)) : 0;
		T res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1<<shift;
		rfl.CarryF = !!(op1 & lastBitToFallOut);
		if (1 == shift)
		{
			rfl.OverflowF = (!!(res&msb)) ^ rfl.CarryF;
		}
		rfl.SignF = !!(msb&res);
		rfl.ParityF = s_ParityTable[res&0xff];
		rfl.ZeroF = !res;
	}
}

bool SHL_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	UINT8 shift = 0;
	switch(instr.OpCode[0])
	{
	case 0xd0:
	case 0xd1:
		shift = 1;
		break;
	case 0xd2:
	case 0xd3:
		shift = pEmu->CpuState.Gpr[R_RCX].AsInt8;
		break;
	case 0xc1:
	case 0xc0:
		if (instr.Flags.OperandCount != 2)
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid operand count when executing ROL_Exec 0xc1",
				instr.Flags.OperandCount));
		}
		shift = static_cast<UINT8>(instr.Operands[1].OpAsInt64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"Executing ROL_Exec with unknown opcode!", 
			instr.OpCode[0]));
		return false;
	}

	if (opSize == sizeof(UINT8))
	{
		SHL_Helper<UINT8>(pEmu,shift&0x1f);
	}
	else if (opSize == sizeof(UINT16))
	{
		SHL_Helper<UINT16>(pEmu,shift&0x1f);
	}
	else if (opSize == sizeof(UINT32))
	{
		SHL_Helper<UINT32>(pEmu,shift&0x1f);
	}
	else if (opSize == sizeof(UINT64))
	{
		SHL_Helper<UINT64>(pEmu,shift&0x3f);
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"SHL_Exec - invalid opSize",opSize));
		return false;
	}
	return true;
}

template <class T>
void  SHR_Helper(X64_EMULATOR_CTX* pEmu, const T shift, bool logicalShift)
{	
#pragma warning (disable:4309)
	static const T msb = static_cast<T>(1)<<(sizeof(T)*8-1);
	static const T bitCnt = static_cast<T>(sizeof(T)*8);
#pragma warning (default:4309)
	if (shift>0)
	{
		DECODED_INSTRUCTION& instr=pEmu->Instruction;
		RFLAGS& rfl = pEmu->CpuState.Rflags;
		T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
		T lastBitToFallOut = 0;
		T res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1>>shift;
		rfl.CarryF = 0;
		if (bitCnt > shift)
		{
			lastBitToFallOut = static_cast<T>(1) << (shift-1);
		}
		else if (!logicalShift)
		{
			lastBitToFallOut = msb;
		}
		rfl.CarryF = !!(op1 & lastBitToFallOut);
		if (1 == shift)
		{
			rfl.OverflowF = logicalShift ? !!(op1&msb) : 0;
		}
		rfl.SignF = !!(msb&res);
		rfl.ParityF = s_ParityTable[res&0xff];
		rfl.ZeroF = !res;
	}
}

bool _SHR_Exec(X64_EMULATOR_CTX* pEmu, bool logicalShift)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	UINT8 shift = 0;
	switch(instr.OpCode[0])
	{
	case 0xd0:
	case 0xd1:
		shift = 1;
		break;
	case 0xd2:
	case 0xd3:
		shift = pEmu->CpuState.Gpr[R_RCX].AsInt8;
		break;
	case 0xc1:
	case 0xc0:
		if (instr.Flags.OperandCount != 2)
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,"Invalid operand count when executing ROL_Exec 0xc1",
				instr.Flags.OperandCount));
		}
		shift = static_cast<UINT8>(instr.Operands[1].OpAsInt64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"Executing ROL_Exec with unknown opcode!", 
			instr.OpCode[0]));
		return false;
	}
	if (opSize == sizeof(UINT8))
	{
		if (logicalShift)
		{
			SHR_Helper<UINT8>(pEmu,shift&0x1f,true);
		}
		else
		{
			SHR_Helper<INT8>(pEmu,shift&0x1f,false);
		}
	}
	else if (opSize == sizeof(UINT16))
	{
		if (logicalShift)
		{
			SHR_Helper<UINT16>(pEmu,shift&0x1f,true);
		}
		else
		{
			SHR_Helper<INT16>(pEmu,shift&0x1f,false);
		}
	}
	else if (opSize == sizeof(UINT32))
	{
		if (logicalShift)
		{
			SHR_Helper<UINT32>(pEmu,shift&0x1f,true);
		}
		else
		{
			SHR_Helper<INT32>(pEmu,shift&0x1f,false);
		}
	}
	else if (opSize == sizeof(UINT64))
	{
		if (logicalShift)
		{
			SHR_Helper<UINT64>(pEmu,shift&0x3f,true);
		}
		else
		{
			SHR_Helper<INT64>(pEmu,shift&0x3f,false);
		}
	}
	else
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"SHL_Exec - invalid opSize",opSize));
		return false;
	}
	return true;
}

bool SHR_Exec(X64_EMULATOR_CTX* pEmu)
{
	return _SHR_Exec(pEmu,true);
}

bool SAR_Exec(X64_EMULATOR_CTX* pEmu)
{
	return _SHR_Exec(pEmu,false);
}

template <class T>
void NEG_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = -op1;
	SetStatusFlagsAfterSub<T>(rfl,0,op1,0,res);
	rfl.CarryF = !rfl.ZeroF; // fix-up the carry flag
}

bool NEG_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	switch (opSize)
	{
	case sizeof(INT8):
		NEG_Helper<INT8>(pEmu);
		break;
	case sizeof(INT16):
		NEG_Helper<INT16>(pEmu);
		break;
	case sizeof(INT32):
		NEG_Helper<INT32>(pEmu);
		break;
	case sizeof(INT64):
		NEG_Helper<INT64>(pEmu);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"NEG_Exec - invalid OP size", opSize));
		return false;
	}
	return true;
}

bool NOT_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	switch (opSize)
	{
	case sizeof(INT8):
		*instr.Operands[0].OpAsPtr8 = ~(*instr.Operands[0].OpAsPtr8);
		break;
	case sizeof(INT16):
		*instr.Operands[0].OpAsPtr16 = ~(*instr.Operands[0].OpAsPtr16);
		break;
	case sizeof(INT32):
		*instr.Operands[0].OpAsPtr32 = ~(*instr.Operands[0].OpAsPtr32);
		break;
	case sizeof(INT64):
		*instr.Operands[0].OpAsPtr64 = ~(*instr.Operands[0].OpAsPtr64);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"NOT_Exec - invalid OP size", opSize));
		return false;
	}
	return true;
}

template <class T>
void INC_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1+1;
	INT8 carryF = rfl.CarryF;
	SetStatusFlagsAfterAdd<T>(rfl,op1,1,0,res);
	rfl.CarryF = carryF; // fix-up the carry flag
}

bool INC_Exec(X64_EMULATOR_CTX* pEmu)
{	
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	switch (opSize)
	{
	case sizeof(INT8):
		INC_Helper<INT8>(pEmu);
		break;
	case sizeof(INT16):
		INC_Helper<INT16>(pEmu);
		break;
	case sizeof(INT32):
		INC_Helper<INT32>(pEmu);
		break;
	case sizeof(INT64):
		INC_Helper<INT64>(pEmu);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"INC_Exec - invalid OP size", opSize));
		return false;
	}
	return true;
}

template <class T>
void DEC_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T op1 = *reinterpret_cast<T*>(instr.Operands[0].Op);
	const T& res = *reinterpret_cast<T*>(instr.Operands[0].Op) = op1-1;
	INT8 carryF = rfl.CarryF;
	SetStatusFlagsAfterSub<T>(rfl,op1,1,0,res);
	rfl.CarryF = carryF; // fix-up the carry flag
}

bool DEC_Exec(X64_EMULATOR_CTX* pEmu)
{	
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;
	switch (opSize)
	{
	case sizeof(INT8):
		DEC_Helper<INT8>(pEmu);
		break;
	case sizeof(INT16):
		DEC_Helper<INT16>(pEmu);
		break;
	case sizeof(INT32):
		DEC_Helper<INT32>(pEmu);
		break;
	case sizeof(INT64):
		DEC_Helper<INT64>(pEmu);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"INC_Exec - invalid OP size", opSize));
		return false;
	}
	return true;
}

void STOS_Fwd(X64_EMULATOR_CTX* pEmu, size_t count)
{
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	while (count-- != 0)
	{
		memcpy(pEmu->Instruction.Operands[0].Op,
			&pEmu->CpuState.Gpr[R_RAX].AsInt8, opSize);
		pEmu->Instruction.Operands[0].Op += opSize;
	}
}

void STOS_Rev(X64_EMULATOR_CTX* pEmu, size_t count)
{
	size_t opSize = pEmu->Instruction.Operands[0].Size;
	while (count-- != 0)
	{
		memcpy(pEmu->Instruction.Operands[0].Op,
			&pEmu->CpuState.Gpr[R_RAX].AsInt8, opSize);
		pEmu->Instruction.Operands[0].Op -= opSize;
	}
}

bool STOS_Exec(X64_EMULATOR_CTX* pEmu)
{
	return StringInstructionExecShell(pEmu, STOS_Fwd, STOS_Rev, false);
}
	
bool MOVBE_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	size_t opSize = instr.Operands[0].Size;

	if (instr.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"MOVBE_Exec - wrong operand type", 
			instr.Operands[0].Type));
		return false;
	}

	if (instr.Operands[1].Type != OPERAND_TYPE_REG)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"MOVBE_Exec - wrong operand type", 
			instr.Operands[1].Type));
		return false;
	}

	INT8* pDest = instr.Operands[0].OpAsPtr8;
	INT8* pSrc = reinterpret_cast<INT8*>(&instr.Operands[1].OpAsInt64);

	switch (opSize)
	{
	case sizeof(INT16):
		pDest[0] = pSrc[1];
		pDest[1] = pSrc[0];
		break;
	case sizeof(INT32):
		pDest[0] = pSrc[3];
		pDest[1] = pSrc[2];
		pDest[2] = pSrc[1];
		pDest[3] = pSrc[0];
		break;
	case sizeof(INT64):
		pDest[0] = pSrc[7];
		pDest[1] = pSrc[6];
		pDest[2] = pSrc[5];
		pDest[3] = pSrc[4];
		pDest[4] = pSrc[3];
		pDest[5] = pSrc[2];
		pDest[6] = pSrc[1];
		pDest[7] = pSrc[0];
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"INC_Exec - invalid OP size", opSize));
		return false;
	}
	return true;
}

bool XADD_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	if (instr.Flags.OperandCount != 2)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"XADD_Exec - invalid operand count", 
			instr.Flags.OperandCount));
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"XADD_Exec - invalid operand types",
			instr.Operands[0].Type, instr.Operands[1].Type));
		return false;
	}
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	UINT8 reg = instr.Operands[1].Register;

	//
	// Some interesting behavior from the silicon side - if the opSize is 32 bit,
	// then it seems that the MSB 32 bit of the source register are cleared and
	// the LSB 32 bits are set to the original value of the destination. If the
	// opSize is 8 or 16 bits than it seems that the MSB (64-opSize) bits are
	// preserverd and the LSB opSize bits are set to the original value of the
	// destination. I am certain there is more elegant way to express the behavior
	// described before, but I am going slightly as this is taking too long!.
	//
	switch (instr.Operands[0].Size)
	{
	case sizeof(INT8):
		{
			INT8 op1 = *reinterpret_cast<INT8*>(instr.Operands[0].Op);
			INT8 op2 = instr.Operands[1].OpAsInt8;
			const INT8 res = *reinterpret_cast<INT8*>(instr.Operands[0].Op) = op1+op2;
			if (reg >= R_FIRST_HIGH)
			{
				reg -= R_FIRST_HIGH;
				pEmu->CpuState.Gpr[reg].AsInt16 = 
					(static_cast<UINT16>((static_cast<UINT8>(op1)))<<8) | 
					(static_cast<UINT8>(pEmu->CpuState.Gpr[reg].AsInt8));
			}
			else
			{
				pEmu->CpuState.Gpr[reg].AsInt8 = op1;
			}
			SetStatusFlagsAfterAdd<INT8>(rfl,op1,op2,0,res);
		}
		break;
	case sizeof(INT16):
		{
			INT16 op1 = *reinterpret_cast<INT16*>(instr.Operands[0].Op);
			INT16 op2 = instr.Operands[1].OpAsInt16;
			const INT16 res = *reinterpret_cast<INT16*>(instr.Operands[0].Op) = op1+op2;
			pEmu->CpuState.Gpr[reg].AsInt16 = op1;
			SetStatusFlagsAfterAdd<INT16>(rfl,op1,op2,0,res);
		}
		break;
	case sizeof(INT32):
		{
			INT32 op1 = *reinterpret_cast<INT32*>(instr.Operands[0].Op);
			INT32 op2 = instr.Operands[1].OpAsInt32;
			const INT32 res = *reinterpret_cast<INT32*>(instr.Operands[0].Op) = op1+op2;
			pEmu->CpuState.Gpr[reg].AsInt64 = static_cast<UINT32>(op1);
			SetStatusFlagsAfterAdd<INT32>(rfl,op1,op2,0,res);
		}
		break;
	case sizeof(INT64):
		{
			INT64 op1 = *reinterpret_cast<INT64*>(instr.Operands[0].Op);
			INT64 op2 = instr.Operands[1].OpAsInt64;
			const INT64 res = *reinterpret_cast<INT64*>(instr.Operands[0].Op) = op1+op2;
			pEmu->CpuState.Gpr[reg].AsInt64 = op1;
			SetStatusFlagsAfterAdd<INT64>(rfl,op1,op2,0,res);
		}
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"XADD_Exec - invalid OP size", instr.Operands[0].Size));
		return false;
	}
	return true;
}

bool XCHG_Exec(X64_EMULATOR_CTX* pEmu)
{
	//
	// Note: this instruction always activates the CPU's locking protocol if
	// one of the operands references memory location. As we know that the 
	// DSM code that invokes us will hold the DSM page lock, we do not have
	// to implement any locking here. If we decide to 
	//

	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	if (instr.Flags.OperandCount != 2)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"XCHG_Exec - invalid operand count", 
			instr.Flags.OperandCount));
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"XCHG_Exec - invalid operand types",
			instr.Operands[0].Type, instr.Operands[1].Type));
		return false;
	}

	
	UINT8 reg = instr.Operands[1].Register;
	switch (instr.Operands[0].Size)
	{
	case sizeof(INT8):
		{
			INT8 tmp = *(instr.Operands[0].Op);
			if (reg >= R_FIRST_HIGH)
			{
				reg -= R_FIRST_HIGH;
				*(instr.Operands[0].Op) = pEmu->CpuState.Gpr[reg].AsInt16 >> 8;
				pEmu->CpuState.Gpr[reg].AsInt16 = 
					(static_cast<UINT16>((static_cast<UINT8>(tmp)))<<8) | 
					(static_cast<UINT8>(pEmu->CpuState.Gpr[reg].AsInt8));
			}
			else
			{
				*(instr.Operands[0].Op) = pEmu->CpuState.Gpr[reg].AsInt8;
				pEmu->CpuState.Gpr[reg].AsInt8 = tmp;
			}
		}
		break;
	case sizeof(INT16):
		{
			UINT16 tmp = *(instr.Operands[0].OpAsPtr16);
			*(instr.Operands[0].OpAsPtr16) = pEmu->CpuState.Gpr[reg].AsInt16;
			pEmu->CpuState.Gpr[reg].AsInt16 = tmp;
		}
		break;
	case sizeof(INT32):
		{
			UINT32 tmp = *(instr.Operands[0].OpAsPtr32);
			*(instr.Operands[0].OpAsPtr32) = pEmu->CpuState.Gpr[reg].AsInt32;
			pEmu->CpuState.Gpr[reg].AsInt64 = tmp;
		}
		break;
	case sizeof(INT64):
		{
			UINT64 tmp = *(instr.Operands[0].OpAsPtr64);
			*(instr.Operands[0].OpAsPtr64) = pEmu->CpuState.Gpr[reg].AsInt64;
			pEmu->CpuState.Gpr[reg].AsInt64 = tmp;
		}
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"XADD_Exec - invalid OP size", instr.Operands[0].Size));
		return false;
	}
	return true;
}

template <class T>
void CMPXCHG_Helper(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr=pEmu->Instruction;
	RFLAGS& rfl = pEmu->CpuState.Rflags;
	T* op1 = reinterpret_cast<T*>(instr.Operands[0].Op);
	T* acum = reinterpret_cast<T*>(&pEmu->CpuState.Gpr[R_RAX].AsInt64);
	const T res = *acum - *op1;
	SetStatusFlagsAfterSub<T>(rfl,*acum,*op1,0,res);
	if (res)
	{
		*acum = *op1;
#pragma warning(disable:4127)
		if (sizeof(T) == sizeof(INT32))			
#pragma warning(default:4127)
		{
			*reinterpret_cast<UINT64*>(acum) &= 0x00000000ffffffff;
		}
	}
	else
	{
		*op1 = static_cast<T>(instr.Operands[1].OpAsInt64);
	}
}

bool CMPXCHG_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	if (instr.Flags.OperandCount != 2)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG_Exec - invalid operand count", 
			instr.Flags.OperandCount));
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM ||
		instr.Operands[1].Type != OPERAND_TYPE_REG)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG_Exec - invalid operand types",
			instr.Operands[0].Type, instr.Operands[1].Type));
		return false;
	}
	switch (instr.Operands[0].Size)
	{
	case sizeof(INT8):
		CMPXCHG_Helper<INT8>(pEmu);
		break;
	case sizeof(INT16):
		CMPXCHG_Helper<INT16>(pEmu);
		break;
	case sizeof(INT32):
		CMPXCHG_Helper<INT32>(pEmu);
		break;
	case sizeof(INT64):
		CMPXCHG_Helper<INT64>(pEmu);
		break;
	default:
		EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG_Exec - invalid OP size", 
			instr.Operands[0].Size));
		return false;
	}
	return true;
}

bool CMPXCHG8B_Exec(X64_EMULATOR_CTX* pEmu)
{
	DECODED_INSTRUCTION& instr = pEmu->Instruction;
	
	if (instr.Flags.OperandCount != 1)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG8B - invalid operand count", 
			instr.Flags.OperandCount));
		return false;
	}
	if (instr.Operands[0].Type != OPERAND_TYPE_MEM)
	{
		EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG8B - invalid operand types",
			instr.Operands[0].Type));
		return false;
	}

	if (instr.Flags.RexPresent && instr.Rex.W)
	{
		INT64* pDest = instr.Operands[0].OpAsPtr64;
		if (0 != (instr.Operands[0].OpAsInt64 & 0xf))
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG8B - dest not 16 byte aligned", 
				instr.Operands[0].OpAsInt64));
			return false;
		}
		if (pEmu->CpuState.Gpr[R_RAX].AsInt64 == pDest[0] && 
			pEmu->CpuState.Gpr[R_RDX].AsInt64 == pDest[1])
		{
			pDest[0] = pEmu->CpuState.Gpr[R_RBX].AsInt64;
			pDest[1] = pEmu->CpuState.Gpr[R_RCX].AsInt64;
			pEmu->CpuState.Rflags.ZeroF = 1;
		}
		else
		{
			pEmu->CpuState.Gpr[R_RAX].AsInt64 = pDest[0];
			pEmu->CpuState.Gpr[R_RDX].AsInt64 = pDest[1];
			pEmu->CpuState.Rflags.ZeroF = 0;
		}
	}
	else
	{
		INT32* pDest = instr.Operands[0].OpAsPtr32;
		if (0 != (instr.Operands[0].OpAsInt32 & 0x7))
		{
			EMU_PANIC((PANIC_X64EMU_ERROR,"CMPXCHG8B - dest not 8 byte aligned", 
				instr.Operands[0].OpAsInt64));
			return false;
		}
		if (pEmu->CpuState.Gpr[R_RAX].AsInt32 == pDest[0] && 
			pEmu->CpuState.Gpr[R_RDX].AsInt32 == pDest[1])
		{
			pDest[0] = pEmu->CpuState.Gpr[R_RBX].AsInt32;
			pDest[1] = pEmu->CpuState.Gpr[R_RCX].AsInt32;
			pEmu->CpuState.Rflags.ZeroF = 1;
		}
		else
		{
			pEmu->CpuState.Gpr[R_RAX].AsInt64 = static_cast<UINT32>(pDest[0]);
			pEmu->CpuState.Gpr[R_RDX].AsInt64 = static_cast<UINT32>(pDest[1]);
			pEmu->CpuState.Rflags.ZeroF = 0;
		}
	}

	return true;
}


//
// BEGIN Instructions to be implemented when we have more time
// to indulge into fully supporting SIMD/MMX and FP instructions
//
bool MOVLPD_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVLPS_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVHPD_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVHPS_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVNTPS_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVNTPD_Exec(X64_EMULATOR_CTX*){return false;}
bool CVTPPD2PI_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVDQ_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVQ_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVNTI_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVNTQ_Exec(X64_EMULATOR_CTX*){return false;}
bool MOVNTDQ_Exec(X64_EMULATOR_CTX*){return false;}
bool PEXTRB_Exec(X64_EMULATOR_CTX*){return false;}
bool PEXTRW_Exec(X64_EMULATOR_CTX*){return false;}
bool PEXTRDQ_Exec(X64_EMULATOR_CTX*){return false;}
bool EXTRACTPS_Exec(X64_EMULATOR_CTX*){return false;}
//
// END Instructions to be implemented when we have more time
//

//
// BEGIN do not need to emulate - acquire memory exclusively
// It almost seems that holding memory exclusively for these instructions is
// the better choice.
//
bool SMSW_Exec(X64_EMULATOR_CTX*){return false;}
bool SIDT_Exec(X64_EMULATOR_CTX*){return false;}
bool SGDT_Exec(X64_EMULATOR_CTX*){return false;}
bool STR_Exec(X64_EMULATOR_CTX*){return false;}
bool SLDT_Exec(X64_EMULATOR_CTX*){return false;}
bool ARPL_Exec(X64_EMULATOR_CTX*){return false;}
bool PUSH_Exec(X64_EMULATOR_CTX*){return false;}
bool POP_Exec(X64_EMULATOR_CTX*){return false;}
bool PUSHA_Exec(X64_EMULATOR_CTX*){return false;}
bool POPA_Exec(X64_EMULATOR_CTX*){return false;}
bool INS_Exec(X64_EMULATOR_CTX*){return false;}
bool CALLF_Exec(X64_EMULATOR_CTX*){return false;}
bool CALL_Exec(X64_EMULATOR_CTX*){return false;}
bool CALLN_Exec(X64_EMULATOR_CTX*){return false;}
bool PUSHF_Exec(X64_EMULATOR_CTX*){return false;}
bool ENTER_Exec(X64_EMULATOR_CTX*){return false;}
bool INTR_Exec(X64_EMULATOR_CTX*){return false;}
bool INTR3_Exec(X64_EMULATOR_CTX*){return false;}
bool INTRO_Exec(X64_EMULATOR_CTX*){return false;}
bool OUT_Exec(X64_EMULATOR_CTX*){return false;}
bool VMREAD_Exec(X64_EMULATOR_CTX*){return false;}
//
// END do not need to emulate
//