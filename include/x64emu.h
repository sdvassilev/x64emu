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

//
//
// This header contains necessary public definitions and function prototypes
// for the implementation of stripped down x64 software emulator. All the
// logic assumes that the guest CPU operates in IA-32e mode, where both 64 & 
// 32 bit of operation are supportted. The main purpose of the software 
// emulation is to execute instuctions that write data to
// a page which is not held exclusively by this node. That said a certain
// attempt was made to implement full blown decode logic to the extent where
// we will know whether or not we have to emulate the faulting instruction.
// The actual execution logic is stripped down to the subset of instructions
// that have to be emulated.
//

#ifndef X64EMU_H
#define X64EMU_H

#ifdef __cplusplus
extern "C" {
#endif

#include "raisepanic.h"

#pragma warning (disable: 4201)

	union MODR_M_BYTE
	{
		struct
		{
			UINT8	Rm : 3;
			UINT8	Reg : 3;
			UINT8	Mod : 2;
		};
		UINT8 AsByte;
	};

	inline size_t GetDisplacementSize(const MODR_M_BYTE& modrm)
	{
		if (modrm.Mod == 0x0 && modrm.Rm == 0x5 ||
			modrm.Mod == 0x2)
		{
			return 4;
		}
		else if (modrm.Mod == 0x1)
		{
			return 1;
		}
		return 0;
	}

	inline bool IsSibPresent(const MODR_M_BYTE& modrm)
	{
		return modrm.Mod != 0x3 && modrm.Rm == 0x4;
	}

	union SIB_BYTE
	{
		struct
		{
			UINT8 Base : 3;
			UINT8 Index : 3;
			UINT8 Scale : 2;
		};
		UINT8 AsByte;
	};

	static const UINT8 REX_PREFIX_BEGIN = 0x40;
	static const UINT8 REX_PREFIX_END = 0x4F;
	static const UINT8 REX_PREFIX_B = 0x1;
	static const UINT8 REX_PREFIX_X = 0x2;
	static const UINT8 REX_PREFIX_R = 0x4;
	static const UINT8 REX_PREFIX_W = 0x8;
	union REX_PREFIX
	{
		struct
		{
			UINT8 B : 1;
			UINT8 X : 1;
			UINT8 R : 1;
			UINT8 W : 1;
			UINT8 Const : 4; // always 0100b / 0x4
		};
		UINT8 AsByte;
	};

	struct DECODED_FLAGS
	{
		UINT32 PrefixLen : 2;
		UINT32 PrefixLock : 1;
		UINT32 PrefixRepne : 1;
		UINT32 PrefixRepz : 1;
		UINT32 PrefixOpSizeOvr : 1;
		UINT32 PrefixAddrSizeOvr : 1;
		UINT32 PrefixNotIntersting : 1;
		UINT32 MandatoryPrefix : 1;
		UINT32 RexPresent : 1;
		UINT32 OpCodeLen : 2;
		UINT32 OperandCount : 3;
		UINT32 ModRmPresent : 1;
		UINT32 SibPresent : 1;
		UINT32 InstructionDecoded : 1;
		UINT32 WriteOp : 1;
		UINT32 OpCodeExtended : 1;
		UINT32 FpuInstruction : 1;
		UINT32 ImmediateOp : 1;
		UINT32 DecodedMnemonic : 1;
		UINT32 ImmediateOpSignX : 1;
		UINT32 StringOp : 1;
	};

	union X64_SEG_REGISTER
	{
		UINT16 AsUint16;
		struct
		{
			UINT16 Cpl : 2; // Current privilege level
			UINT16 Ldt : 1; // 0 - Gdt; 1 - Ldt
			UINT16 Index : 13; // Index in the descriptor table
		};
	};

	struct X64_SEG_DESCRIPTOR
	{
		union
		{
			struct
			{
				UINT32	Base23_26 : 8;
				UINT32	Type : 4;
				UINT32  SysDescr : 1;
				UINT32	Dpl : 2;
				UINT32	Present : 1;
				UINT32	SegLimit19_16 : 4;
				UINT32  Avl : 1;
				UINT32	L : 1; // 64 bit code segment
				UINT32	D_B : 1; // Def operation size 0 = 16, 1 = 32
				UINT32  G : 1;
				UINT32	Base31_24 : 8;
			};
			UINT32 Lo;
		};
		union
		{
			struct
			{
				UINT32 SegLimit : 16;
				UINT32 Base15_00 : 16;
			};
			UINT32 Hi;
		};
	};

	static const UINT8 OPERAND_TYPE_REG = 0;
	static const UINT8 OPERAND_TYPE_MEM = 1;
	static const UINT8 OPERAND_TYPE_IMM = 2;
	static const UINT8 OPERAND_TYPE_DA = 3;
	static const UINT8 OPERAND_TYPE_REL_OFFS = 4;
	static const UINT8 OPERAND_TYPE_IMPLIED_NUM = 5;

	inline bool IsOperandImmediate(const UINT8 op)
	{
		return op == OPERAND_TYPE_IMM || op == OPERAND_TYPE_DA ||
			op == OPERAND_TYPE_REL_OFFS;
	}

	struct X64_OPERAND
	{
		union
		{
			INT8*	Op;
			struct
			{
				union
				{
					INT64 OpAsInt64;
					INT32 OpAsInt32;
					INT16 OpAsInt16;
					INT8  OpAsInt8;
				};
				INT16 SegmentSelector;
			};
			union
			{
				INT8*  OpAsPtr8;
				INT16* OpAsPtr16;
				INT32* OpAsPtr32;
				INT64* OpAsPtr64;
			};
		};
		union
		{
			INT8* OpGuest;
			INT64 OpAsInt64Guest;
		};
		struct
		{
			UINT8 Type : 3;
			UINT8 Register : 5; // valid only for OPERAND_TYPE_REG
		};
		UINT8 Size;
		UINT8 MappedToVmxRoot;
	};

	union RFLAGS
	{
		UINT32	AsUint32;
		struct
		{
			UINT32	CarryF : 1;  //0
			UINT32  Reserved : 1;  //1
			UINT32  ParityF : 1;  //2
			UINT32  Reserved2 : 1;  //3
			UINT32	AdjustF : 1;	//4
			UINT32  Reserved3 : 1;  //5
			UINT32  ZeroF : 1;  //6
			UINT32  SignF : 1;	//7
			UINT32	TrapF : 1;  //8
			UINT32	InterruptF : 1;	//9
			UINT32	DirectionF : 1;	//10
			UINT32	OverflowF : 1;	//11
			UINT32	IOPL : 2;  //12-13
			UINT32	NestedTask : 1;  //14
			UINT32	Reserved4 : 1;	//15
			UINT32	ResumeF : 1;	//16
			UINT32	VirtualM : 1;  //17
			UINT32	AlignCheck : 1;	//18
			UINT32	VIF : 1;	//19
			UINT32	VIP : 1;	//20
			UINT32	ID : 1;	//21
			UINT32	Reserved5 : 10; //22-31 always 0

		};
	};

#pragma warning (default: 4201)

	enum DECODE_STATE
	{
		DECODE_STATE_ERROR,
		DECODE_STATE_PREFIX,
		DECODE_STATE_REX,
		DECODE_STATE_OPCODE,
		DECODE_STATE_MODRM,
		DECODE_STATE_SIB,
		DECODE_STATE_DISPL,
		DECODE_STATE_IMM,
		DECODE_STATE_DONE,
		DECODE_STATE_LAST = DECODE_STATE_DONE
	};

	struct OPCODE_ENTRY;
	static const size_t X64_MAX_MNEMONIC_LENGTH = 95; // not certain, but seems reasonable
	struct DECODED_INSTRUCTION
	{
		INT64			Displacement;
		X64_OPERAND 	Operands[4]; // memory ops contain pointers to guest context
		DECODED_FLAGS	Flags;
		const OPCODE_ENTRY*	OpcodeEntry;
		UINT8 			OperandSize; //1,2,4,8 bytes
		UINT8			DisplacementSize;
		REX_PREFIX		Rex;
		MODR_M_BYTE		Modrm;
		UINT8			ModrmMod; // Effective MOD
		UINT8			ModrmReg; // Effective Reg
		UINT8			ModrmRm; // Effective R/m
		SIB_BYTE		Sib;
		UINT8			SibScale; // Effective Sib fields
		UINT8			SibIndex;
		UINT8			SibBase;
		UINT8			InstructionLen;
		UINT8			OpCode[3];
		UINT8			AddressSize;
		char			Mnemonic[X64_MAX_MNEMONIC_LENGTH + 1];
		UINT16			MnemonicLength;
	};

	static const size_t X64_GPR_COUNT = 16;
	static const size_t X64_SEGR_COUNT = 6;

	union X64_REGISTER
	{
		INT8 	AsInt8;
		INT16 	AsInt16;
		INT32 	AsInt32;
		INT64	AsInt64;
		UINT64  AsUInt64;
		INT8* 	AsPtr8;
		INT16* 	AsPtr16;
		INT32* 	AsPtr32;
		INT64*	AsPtr64;
	};

	struct X64_CPU_STATE
	{
		X64_REGISTER  		Gpr[X64_GPR_COUNT];
		X64_REGISTER  		Rip; 		// Mapped to VMX context
		RFLAGS  	  		Rflags;
		X64_REGISTER  		RipOrig; 	// Mapped to VMX context
		X64_REGISTER  		RipGuest;
		UINT32		  		RipMappedLen;
		X64_SEG_REGISTER  	SegRegs[X64_SEGR_COUNT];
		bool				IA32eX64;

		//
		// Not certain if we are going to need the rest of them
		//
	};

	typedef bool(*EmuMapVaRangeT)(
		IN void* guestCtx,
		IN UINT_PTR	guestVA,
		IN UINT32 guestBytes,
		IN bool	code,		// true - code; false - data
		OUT UINT_PTR* vmxrootVA
		);

	typedef void
		(*EmuUnmapVaRangeT)(
		IN void*    guestCtx,
		IN UINT_PTR	vmxrootVA,
		IN UINT_PTR	vmxrootBytes
		);

	typedef UINT_PTR
		(*EmuGetRegisterValueT)(
		IN void* guestCtx,
		IN int	registerId
		);

	typedef void
		(*EmuSetRegisterValueT)(
		IN void*	guestCtx,
		IN int		registerId,
		IN UINT64	registerValue
		);

	typedef PanicHandlerT EmuRaisePanicT;

	typedef struct _X64_EMULATOR_RUNTIME
	{
		//
		// x64 emu run-time support routines, which are expected to be 
		// implemented by the x64emu client. GetRegisterValue is the only mandatory 
		// routine and in case the lib user wants to perform only instruction 
		// decoding, there is no need in filling the rest. MapVaRange is also used 
		// for instruction decoding in order to map the code to memory range 
		// accessible by the environment in which x64emu runs. If Map/UnmapVaRange 
		// are not provided, then they are stubbed internally as a NULL routines, 
		// i.e. x64emu will assume that the address space pointed to by CPU 
		// registersis is accessible in the x64 emu execution env, which is the case 
		// for all the unit tests running in user-land.
		//
		// The run-time environment is per emulator context and not global, thus 
		// allowing for multiple emulator contexts to run in paralel - each one of
		// them in their own bubble.
		//

		//
		// Set to whatever context the lib client wants to be passed to the routines
		// below. x64emu does not interpret this field.
		//
		void*				 GuestCtx;

		EmuGetRegisterValueT GetRegisterValue;
		EmuSetRegisterValueT SetRegisterValue;
		EmuMapVaRangeT		 MapVaRange;
		EmuUnmapVaRangeT	 UnmapVaRange;
		EmuRaisePanicT		 RaisePanic;
	} X64_EMULATOR_RUNTIME;

	__inline void EmuInitRuntimeStruct(
		OUT X64_EMULATOR_RUNTIME* xert,
		IN void*				guestCtx,
		IN EmuGetRegisterValueT getRegisterValue,
		IN EmuSetRegisterValueT setRegisterValue = 0,
		IN EmuMapVaRangeT		mapVaRange = 0,
		IN EmuUnmapVaRangeT		unmapVaRange = 0,
		IN EmuRaisePanicT		raisePanic = 0
		)
	{
		ASSERT(getRegisterValue);
		memset(xert, 0, sizeof(*xert));
		xert->GuestCtx = guestCtx;
		xert->GetRegisterValue = getRegisterValue;
		xert->SetRegisterValue = setRegisterValue;
		xert->MapVaRange = mapVaRange;
		xert->UnmapVaRange = unmapVaRange;
		xert->RaisePanic = raisePanic;
	}

	struct X64_EMULATOR_CTX
	{
		DECODED_INSTRUCTION		Instruction;
		DECODE_STATE			DecodeState;
		X64_CPU_STATE			CpuState;

		//
		// Run-time dependencies
		//
		void*					GuestCtx;
		EmuGetRegisterValueT	GetRegisterValue;
		EmuSetRegisterValueT	SetRegisterValue;
		EmuMapVaRangeT			MapVaRange;
		EmuUnmapVaRangeT		UnmapVaRange;
		EmuRaisePanicT			RaisePanic;
	};

	bool
		EmuInitEmulatorCtx(
		IN OUT X64_EMULATOR_CTX*,
		IN const X64_EMULATOR_RUNTIME*,
		IN OPTIONAL UINT32 instructionStreamLength
		);

	typedef struct _INTERRUPT_CONTEXT *PINTERRUPT_CONTEXT;

#ifdef SUPERCELL
	bool
		EmuInitEmulatorCtxFromInterruptCtx(
		X64_EMULATOR_CTX*,
		PINTERRUPT_CONTEXT); // safe only for decoding
#endif

	bool
		EmuInitEmulatorCtxForDecode(
		IN OUT X64_EMULATOR_CTX*,
		IN UINT64 rip,
		IN OPTIONAL UINT32 instructionStreamLength);

	void
		EmuCleanupEmulatorCtx(
		IN OUT X64_EMULATOR_CTX*);

	bool
		EmuDecodeInstruction(
		IN OUT X64_EMULATOR_CTX*);

	bool
		EmuExecuteInstruction(
		IN OUT X64_EMULATOR_CTX*);

	void
		EmuCommitCpuState(
		IN X64_EMULATOR_CTX*);

	bool
		EmuIsMemoryStoreInstruction(
		X64_EMULATOR_CTX*);

	bool
		EmuIsAtomicInstruction(
		X64_EMULATOR_CTX*);

	bool
		EmuIsAtomicCmpExchange(
		X64_EMULATOR_CTX*);

	bool
		EmuAtomicExchangeHappened(
		X64_EMULATOR_CTX*);

	bool
		EmuCanEmulateInstruction(
		X64_EMULATOR_CTX*);

	void
		OpCopyData(
		UINT8* pDest,		// vmx root address
		const UINT8* pSrc,	// vmx root address
		size_t size
		);

	const char*
		EmuGetDecodedMnemonic(
		X64_EMULATOR_CTX* pEmu
		);

	INT64
		EmuGetRepeatCount(
		X64_EMULATOR_CTX*);

	__inline const char*
		EmuGetOperandTypeAsStr(
		UINT32 type)
	{
		const char* asStr[] = { "OPERAND_TYPE_REG", "OPERAND_TYPE_MEM",
			"OPERAND_TYPE_IMM", "OPERAND_TYPE_DA", "OPERAND_TYPE_REL_OFFS" };
		return type < ARRAYSIZE(asStr) ? asStr[type] : "OPERAND_TYPE_INVALID";
	}

	__inline UINT8 EmuGetOperandType(
		const X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(opIdx < ARRAYSIZE(pEmu->Instruction.Operands));
		return pEmu->Instruction.Operands[opIdx].Type;
	}

	__inline bool EmuIsOperandReg(
		const X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(opIdx < ARRAYSIZE(pEmu->Instruction.Operands));
		return OPERAND_TYPE_REG == pEmu->Instruction.Operands[opIdx].Type;
	}

	_inline bool EmuIsOperandImm(
		const X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(opIdx < ARRAYSIZE(pEmu->Instruction.Operands));
		return OPERAND_TYPE_IMM == pEmu->Instruction.Operands[opIdx].Type;
	}

	_inline bool EmuIsOperandMem(
		const X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(opIdx < ARRAYSIZE(pEmu->Instruction.Operands));
		return OPERAND_TYPE_MEM == pEmu->Instruction.Operands[opIdx].Type;
	}

	__inline bool EmuIsOperandGpr(
		const X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(opIdx < ARRAYSIZE(pEmu->Instruction.Operands));
		return OPERAND_TYPE_REG == pEmu->Instruction.Operands[opIdx].Type &&
			pEmu->Instruction.Operands[opIdx].Register < X64_GPR_COUNT;
	}

	__inline X64_REGISTER* EmuGetGprOperand(
		X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		if (EmuIsOperandGpr(pEmu, opIdx)) {
			return &pEmu->CpuState.Gpr[pEmu->Instruction.Operands[opIdx].Register];
		}
		return 0;
	}

	__inline X64_OPERAND* EmuGetOperand(
		X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(opIdx < ARRAYSIZE(pEmu->Instruction.Operands));
		return &pEmu->Instruction.Operands[opIdx];
	}

	__inline INT64 EmuGetOperandAsInt64(
		X64_EMULATOR_CTX* pEmu,
		UINT32 opIdx)
	{
		ASSERT(!EmuIsOperandMem(pEmu, opIdx));
		return pEmu->Instruction.Operands[opIdx].OpAsInt64;
	}

#ifdef __cplusplus
} // extern "C" {
#endif

#endif X64EMU_H
