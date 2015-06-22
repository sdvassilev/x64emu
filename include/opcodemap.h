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

#ifndef OPCODEMAP_H
#define OPCODEMAP_H

#include "x64emu.h"

//
// General Purpose Register Indexes
//
static const size_t R_RAX = 0;
static const size_t R_RCX = 1;
static const size_t R_RDX = 2;
static const size_t R_RBX = 3;
static const size_t R_RSP = 4;
static const size_t R_RBP = 5;
static const size_t R_RSI = 6;
static const size_t R_RDI = 7;
static const size_t R_R8  = 8;
static const size_t R_R9  = 9;
static const size_t R_R10 = 10;
static const size_t R_R11 = 11;
static const size_t R_R12 = 12;
static const size_t R_R13 = 13;
static const size_t R_R14 = 14;
static const size_t R_R15 = 15;

#define R_AX R_RAX
#define R_CX R_RCX
#define R_DX R_RDX
#define R_BX R_RBX
#define R_SP R_RSP
#define R_BP R_RBP
#define R_SI R_RSI
#define R_DI R_RDI

//
// GPR High byte registers - it is important they are GPR index + 16
//
static const size_t R_FIRST_HIGH = 16;
static const size_t R_AH  = 16;
static const size_t R_CH  = 17;
static const size_t R_DH  = 18;
static const size_t R_BH  = 19;
static const size_t R_LAST_HIGH = R_BH;

#define R_IS_HIGH(r) (((r) >= R_FIRST_HIGH) && ((r) <= R_LAST_HIGH))

//
// Segment registers indexes
//
static const size_t R_FIRST_SEG = R_LAST_HIGH + 1;
static const size_t R_ES  = R_FIRST_SEG;
static const size_t R_CS  = 21;
static const size_t R_SS  = 22;
static const size_t R_DS  = 23;
static const size_t R_FS  = 24;
static const size_t R_GS  = 25;
static const size_t R_LAST_SEG = R_GS;

static const size_t R_RFLAGS = 26;

static const size_t R_LAST	 = 27;

//
// x86/x64 instruction cannot exceed 15 bytes
//
static const UINT8 MAX_INSTRUCTION_LEN = 15;

static const UINT8 OP_ESC			= 0x0F;

//
// Op prefixes
//
// Group 1 - lock/rep prefixes
//
static const UINT8 OP_PREFIX_LOCK			= 0xF0;
static const UINT8 OP_PREFIX_REPNE			= 0xF2;
static const UINT8 OP_PREFIX_REPZ			= 0xF3;
//
// Group 2 - segment override prefixes & branch hints
//
static const UINT8 OP_PREFIX_CS_OVR			= 0x2E;
static const UINT8 OP_PREFIX_SS_OVR			= 0x36;
static const UINT8 OP_PREFIX_DS_OVR			= 0x3E;
static const UINT8 OP_PREFIX_ES_OVR			= 0x26;
static const UINT8 OP_PREFIX_FS_OVR			= 0x64;
static const UINT8 OP_PREFIX_GS_OVR			= 0x65;
static const UINT8 OP_PREFIX_BR_NOT_TAKEN	= 0x2E; // only with Jcc instr
static const UINT8 OP_PREFIX_BR_TAKEN		= 0x3E; // only with Jcc instr
//
// Group 3 - operand size override
//
static const UINT8 OP_PREFIX_OPSIZE_OVR		= 0x66;
//
// Group 4 - address size override
//
static const UINT8 OP_PREFIX_ADDRSIZE_OVR	= 0x67;

//
// Mandatory prefixes used with 2,3 byte opcodes
//
static const UINT8 OP_MANDATORY_PREFIX_1 = 0x66;
static const UINT8 OP_MANDATORY_PREFIX_2 = 0xF3;
static const UINT8 OP_MANDATORY_PREFIX_3 = 0xF2;

inline bool OpIsMandatoryPrefix(const UINT8 opByte)
{
	return opByte == OP_MANDATORY_PREFIX_1 ||
		opByte == OP_MANDATORY_PREFIX_2 ||
		opByte == OP_MANDATORY_PREFIX_3;
}

inline bool OpIsTwoByte(const UINT8* pOp)
{
	return *pOp == OP_ESC ||
		(OpIsMandatoryPrefix(*pOp) && pOp[1] == OP_ESC);
}

//
// Codes for addressing methods from IA-32 Dev Manual, vol 2-B
//
static const UINT8 ADDRM_BITS = 6;
static const UINT16 ADDRM_MODRM_BIT = (1 << (ADDRM_BITS-1));
static const UINT16 ADDRM_MASK = (1 << ADDRM_BITS) - 1;

static const UINT16 ADDRM_A = 0x00;                   // direct address, address of OP is in the instr - far JMP (EA)
static const UINT16 ADDRM_C = 0x01 | ADDRM_MODRM_BIT; // ModrmReg selects control reg
static const UINT16 ADDRM_D = 0x02 | ADDRM_MODRM_BIT; // ModrmReg selects debug reg
static const UINT16 ADDRM_E = 0x03 | ADDRM_MODRM_BIT; // Modrm follows and R/M specifies memory or reg
static const UINT16 ADDRM_F = 0x04;                   // RFlags
static const UINT16 ADDRM_G = 0x05 | ADDRM_MODRM_BIT; // ModrmReg selects general register
static const UINT16 ADDRM_I = 0x06;                   // Immediate operand encoded in the instruction
static const UINT16 ADDRM_J = 0x07; 				  // Instr contains relative offset to be added to E/RIP - JMP (E9)
static const UINT16 ADDRM_M = 0x08 | ADDRM_MODRM_BIT; // ModrmRm may refer only to memory (LES,LDS,CMPXCHG8)
static const UINT16 ADDRM_N = 0x09 | ADDRM_MODRM_BIT; // ModrmRm selects packed quadword MMX register
static const UINT16 ADDRM_O = 0x0A; 				  // No Modrm byte. The operand offs is encoded in the instruction - MOV(A0-A3)
static const UINT16 ADDRM_P = 0x0B | ADDRM_MODRM_BIT; // ModrmReg selects packed quadword MMX register
static const UINT16 ADDRM_Q = 0x0C | ADDRM_MODRM_BIT; // Modrm present. Operand is either MMX reg or mem op
static const UINT16 ADDRM_R = 0x0D | ADDRM_MODRM_BIT; // R/M byte may refer only to general reg MOV (0F20-0F23)
static const UINT16 ADDRM_S = 0x0E | ADDRM_MODRM_BIT; // ModrmReg selects a segment register
static const UINT16 ADDRM_U = 0x0F | ADDRM_MODRM_BIT; // R/M byte selects 128 bit XMM register
static const UINT16 ADDRM_V = 0x10 | ADDRM_MODRM_BIT; // ModrmReg selects 128 bit XMM reg
static const UINT16 ADDRM_W = 0x11 | ADDRM_MODRM_BIT; // ModrmRm specifies 128 bit XMM register or memory
static const UINT16 ADDRM_X = 0x12; // Memory addressed by DS:rSI register pair (MOVS,CMPS,OUTS)
static const UINT16 ADDRM_Y = 0x13; // Memory addressed by ES:rDI register pair (MOVS,CMPS,SCAS)
static const UINT16 ADDRM_IX= 0x14; // Same as ADDRM_I, but the operand is sign extended

//
// Codes for operand types from IA-32 Dev Manual
//
static const UINT16 OPRND_a  = 0x01; // two one/double-word operands in memory (BOUND only)
static const UINT16 OPRND_b  = 0x02; // Byte, regardless of op-size attr
static const UINT16 OPRND_c  = 0x03; // Byte or word, depending on operand size attr
static const UINT16 OPRND_d  = 0x04; // Doubleword, regardless of op-size attr
static const UINT16 OPRND_dq = 0x05; // Double quadword
static const UINT16 OPRND_p  = 0x06; // 32,48,80-bit pointer, depending on op-size attr
static const UINT16 OPRND_pd = 0x07; // 128 bit packed double-precision floating-point data
static const UINT16 OPRND_pi = 0x08; // Quadword MMX reg - mm0
static const UINT16 OPRND_ps = 0x09; // 128 bit packed single precision floating-point data
static const UINT16 OPRND_q  = 0x0A; // Quadword, regardless of op-size attr
static const UINT16 OPRND_s  = 0x0B; // 6 or 10 byte pseudo-descriptor
static const UINT16 OPRND_sd = 0x0C; // Scalar element of a 128 bit double precision floating data
static const UINT16 OPRND_ss = 0x0D; // Scalar element of a 128 bit single precision floating data
static const UINT16 OPRND_si = 0x0E; // Doubleword integer register - EAX
static const UINT16 OPRND_v  = 0x0F; // Single/double/quad word depending on op-size attr
static const UINT16 OPRND_w	 = 0x10; // Word regardless of op-size attr
static const UINT16 OPRND_y  = 0x11; // Double/quadword depending on op-size attr
static const UINT16 OPRND_z  = 0x12; // Word for 16-bit operand size or doubleword for 32 or 64 bit operand-size

static const UINT8 OPRND_BITS = 5;
static const UINT16 OPRND_MASK = ((1<<(ADDRM_BITS+OPRND_BITS))-1) & ~ADDRM_MASK;
#define OPRND_GET_TYPE(a) (((a)&OPRND_MASK)>>ADDRM_BITS)

//
// Superscripts/additional flags specified in the opcode tables IA-32 Dev Manual 
//
#define ADDNF_1A  0x00 // Bits 5,4,3 in modrm used as opcode extension
#define ADDNF_1B  0x01 // use 0F0B/0FB9h to generate #UD
#define ADDNF_1C  0x02 // If the instruction has variations, modrm byte specifies it
#define ADDNF_i64 0x03 // Invalid instruction for 64 bit mode 40-4F
#define ADDNF_o64 0x04 // Instruction available only in 64 bit mode
#define ADDNF_d64 0x05 // If in 64-bit mode, the instruction defaults to 64-bit operand size
#define ADDNF_f64 0x06 // Operand size forced to 64-bit, when in 64-bit mode (prefixes ignored)

#define MAKE_ADDRM(ADDRM,OPRND) (ADDRM | (OPRND << ADDRM_BITS))


//
// Format of the operand attrib when referring to register.
// If none of the size bits is set than the operand size attr controls
// the width of the register. The lower 5 bits specify the register, the
// next 4 the size (1,2,4,8 bytes)
//
static const UINT16 OPRND_TYPE_REG 		= 0x8000; // Register is specified in the opcode
static const UINT8 OPRND_REG_SIZE_SHIFT = 5;
static const UINT16 OPRND_REG_REX_B_BIT = 0x0400; // REX.B has to be considered

static const UINT16 OPRND_REG_MASK = 0x1f;
static const UINT16 OPRND_REG_SIZE_MASK = 0x1e0;
#define OPRND_REG_GET_SIZE(attr) (((attr) & OPRND_REG_SIZE_MASK) >> OPRND_REG_SIZE_SHIFT)

#define OP_ATTR_R(R) (OPRND_TYPE_REG | (R))
#define OP_ATTR_R_EX(R) (OP_ATTR_R(R) | OPRND_REG_REX_B_BIT)
#define OP_ATTR_R_SIZE(S) ((S)<<OPRND_REG_SIZE_SHIFT)
#define OP_ATTR_R_8B(R) (OP_ATTR_R(R) | OP_ATTR_R_SIZE(8))
#define OP_ATTR_R_8B_EX(R) (OP_ATTR_R_8B(R) | OPRND_REG_REX_B_BIT)
#define OP_ATTR_R_4B(R) (OP_ATTR_R(R) | OP_ATTR_R_SIZE(4))
#define OP_ATTR_R_2B(R) (OP_ATTR_R(R) | OP_ATTR_R_SIZE(2))
#define OP_ATTR_R_1B(R) (OP_ATTR_R(R) | OP_ATTR_R_SIZE(1))
#define OP_ATTR_R_EX_1B(R) (OP_ATTR_R_1B(R) | OPRND_REG_REX_B_BIT)

static const UINT16 OPRND_TYPE_NUM = 0x4000;
#define OP_ATTR_NUM(N) (OPRND_TYPE_NUM | N) // N must be 1 byte
#define OP_ATTR_NUM_GET_NUM(op) (static_cast<UINT8>(op & 0xff))

inline bool OpAttrIsModrmNeeded(UINT16 attr)
{
	return !(attr & (OPRND_TYPE_REG|OPRND_TYPE_NUM)) &&
		!!(attr & ADDRM_MODRM_BIT);
}

static const UINT8 ET_INV     		= 0x0; 	// Ooops - invalid opcode
static const UINT8 ET_JMPGR   		= 0x1; 	// jumps/points to a row in the group table
static const UINT8 ET_JMPPFX  		= 0x2; 	// jumps/points to an entry in a prefix table
static const UINT8 ET_JMPMOD  		= 0x3; 	// jumps/points to an entry in a table offset by ModrmMod
static const UINT8 ET_JMPX86_X64 	= 0x4;  // jumps/points x86_x64 table - opcode different in x64
static const UINT8 ET_JMPFPU		= 0x5;  // jump to the FPU instruction
static const UINT8 ET_JMP3B			= 0x6;  // jump to 3 byte opcode table
static const UINT8 ET_JMPMOD_RM  	= 0x7; 	// jumps/points to an entry in a table offset by ModrmRm (bits 2,1,0)
static const UINT8 ET_JMP2B			= 0x8;	// jumps to 2 byte opcode table
static const UINT8 ET_TERM    		= 0x9; 	// terminal entry - contains operands and exec handler
static const UINT8 ET_TX32 	 		= 0xa; 	// terminal entry - valid only in 32 bit mode
static const UINT8 ET_TX64 	 		= 0xb; 	// terminal entry - valid only in 64 bit mode

//
// ET_FLAGS
//
static const UINT8 ET_ATOMIC		= 0x20; // can be preceded by LOCK prefix
static const UINT8 ET_DEFOP64		= 0x40; // def operand is 64 even w/o rex.w
static const UINT8 ET_FORCEOP64		= 0x80; // operand size is forced to 64 (when in 64bit mode)

static const UINT8 ET_TERMATOM		= ET_TERM | ET_ATOMIC;
static const UINT8 ET_TERMDOP64		= ET_TERM | ET_DEFOP64;
static const UINT8 ET_TERMFOP64		= ET_TERM | ET_FORCEOP64;

static const UINT8 ET_TYPE_MASK		= 0x1f;
static const UINT8 ET_FLAG_MASK		= 0xe0;

inline bool IsEtAtomic(UINT8 et) { return !!(et & ET_ATOMIC); }

inline bool IsEtTerminal(UINT8 _et) 
{ 
	UINT8 et = _et & ET_TYPE_MASK;
	return et == ET_TERM || et == ET_TX32 || et == ET_TX64 || 
		et == ET_TERMDOP64 || et == ET_TERMFOP64; 
}

inline bool IsEtDefaultOpSize64Bit(UINT8 et)
{
	return !!(et & ET_DEFOP64);
}

inline bool IsEtOpSizeForcedTo64Bit(UINT8 et)
{
	return !!(et & ET_FORCEOP64);
}

struct X64_EMULATOR_CTX;

struct OPCODE_ENTRY
{
	UINT8 TypeAndFlags;
	const void* Handler;  //either exec handler or entry/row in different table 
	const char* Mnemonic;
	UINT8  OprndCnt;
	UINT16 OprndAttr1;
	UINT16 OprndAttr2;
	UINT16 OprndAttr3;

	static UINT16 GetOpAttr(const OPCODE_ENTRY* op, size_t idx)
	{
		ASSERT(idx <= 2);
		return *(&op->OprndAttr1+idx);
	}
};

inline bool 
IsAddressingMode(
	const void* opEntry,
	size_t idx,
	UINT16 addrMode)
{
	if (idx <= 2) 
	{
		UINT16 attr = *(&(((OPCODE_ENTRY*)opEntry)->OprndAttr1) + idx);
		return !(attr & (OPRND_TYPE_REG|OPRND_TYPE_NUM)) &&
			!!((attr & ADDRM_MASK) == addrMode);
	}
	return false;
}

inline bool 
IsAddressingModeO(
	const void* opEntry,
	size_t idx)
{
	return IsAddressingMode(opEntry,idx,ADDRM_O);
}

inline bool
IsOpAttrRflags(
	const void* opEntry,
	size_t idx)
{
	return IsAddressingMode(opEntry,idx,ADDRM_F);
}

inline bool 
IsOpAttrRsiString(
	const void* opEntry,
	size_t idx)
{
	return IsAddressingMode(opEntry,idx,ADDRM_X);
}

inline bool 
IsOpAttrRdiString(
	const void* opEntry,
	size_t idx)
{
	return IsAddressingMode(opEntry,idx,ADDRM_Y);
}


typedef bool (*OpExecuteT)(X64_EMULATOR_CTX*);
typedef void (*OpDecodeT)(X64_EMULATOR_CTX*);

bool ADD_Exec(X64_EMULATOR_CTX*);
bool OR_Exec(X64_EMULATOR_CTX*);
bool ADDC_Exec(X64_EMULATOR_CTX*);
bool PUSH_Exec(X64_EMULATOR_CTX*);
bool SBB_Exec(X64_EMULATOR_CTX*);
bool AND_Exec(X64_EMULATOR_CTX*);
bool SUB_Exec(X64_EMULATOR_CTX*);
bool XOR_Exec(X64_EMULATOR_CTX*);
bool POP_Exec(X64_EMULATOR_CTX*);
bool PUSHA_Exec(X64_EMULATOR_CTX*);
bool POPA_Exec(X64_EMULATOR_CTX*);
bool ARPL_Exec(X64_EMULATOR_CTX*);
bool INS_Exec(X64_EMULATOR_CTX*);
bool XCHG_Exec(X64_EMULATOR_CTX*);
bool MOV_Exec(X64_EMULATOR_CTX*);
bool MOVS_Exec(X64_EMULATOR_CTX*);
bool CALLF_Exec(X64_EMULATOR_CTX*);
bool CALL_Exec(X64_EMULATOR_CTX*);
bool CALLN_Exec(X64_EMULATOR_CTX*);
bool PUSHF_Exec(X64_EMULATOR_CTX*);
bool ENTER_Exec(X64_EMULATOR_CTX*);
bool INTR_Exec(X64_EMULATOR_CTX*);
bool INTR3_Exec(X64_EMULATOR_CTX*);
bool INTRO_Exec(X64_EMULATOR_CTX*);
bool OUT_Exec(X64_EMULATOR_CTX*);
bool MOVLPD_Exec(X64_EMULATOR_CTX*);
bool MOVLPS_Exec(X64_EMULATOR_CTX*);
bool MOVHPD_Exec(X64_EMULATOR_CTX*);
bool MOVHPS_Exec(X64_EMULATOR_CTX*);
bool MOVNTPS_Exec(X64_EMULATOR_CTX*);
bool MOVNTPD_Exec(X64_EMULATOR_CTX*);
bool CVTPPD2PI_Exec(X64_EMULATOR_CTX*);
bool MOVDQ_Exec(X64_EMULATOR_CTX*);
bool MOVQ_Exec(X64_EMULATOR_CTX*);
bool VMREAD_Exec(X64_EMULATOR_CTX*);
bool SETO_Exec(X64_EMULATOR_CTX*);
bool SETNO_Exec(X64_EMULATOR_CTX*);
bool SETB_Exec(X64_EMULATOR_CTX*);
bool SETAE_Exec(X64_EMULATOR_CTX*);
bool SETE_Exec(X64_EMULATOR_CTX*);
bool SETNE_Exec(X64_EMULATOR_CTX*);
bool SETBE_Exec(X64_EMULATOR_CTX*);
bool SETA_Exec(X64_EMULATOR_CTX*);
bool SETS_Exec(X64_EMULATOR_CTX*);
bool SETNS_Exec(X64_EMULATOR_CTX*);
bool SETP_Exec(X64_EMULATOR_CTX*);
bool SETNP_Exec(X64_EMULATOR_CTX*);
bool SETL_Exec(X64_EMULATOR_CTX*);
bool SETNL_Exec(X64_EMULATOR_CTX*);
bool SETLE_Exec(X64_EMULATOR_CTX*);
bool SETG_Exec(X64_EMULATOR_CTX*);
bool SHLD_Exec(X64_EMULATOR_CTX*);
bool SHLD_CL_Exec(X64_EMULATOR_CTX*);
bool SHRD_Exec(X64_EMULATOR_CTX*);
bool SHRD_CL_Exec(X64_EMULATOR_CTX*);
bool BTS_Exec(X64_EMULATOR_CTX*);
bool CMPXCHG_Exec(X64_EMULATOR_CTX*);
bool BTR_Exec(X64_EMULATOR_CTX*);
bool BTC_Exec(X64_EMULATOR_CTX*);
bool XADD_Exec(X64_EMULATOR_CTX*);
bool MOVNTI_Exec(X64_EMULATOR_CTX*);
bool MOVNTQ_Exec(X64_EMULATOR_CTX*);
bool MOVNTDQ_Exec(X64_EMULATOR_CTX*);
bool PEXTRB_Exec(X64_EMULATOR_CTX*);
bool PEXTRW_Exec(X64_EMULATOR_CTX*);
bool PEXTRDQ_Exec(X64_EMULATOR_CTX*);
bool EXTRACTPS_Exec(X64_EMULATOR_CTX*);
bool ROL_Exec(X64_EMULATOR_CTX*);
bool ROR_Exec(X64_EMULATOR_CTX*);
bool RCL_Exec(X64_EMULATOR_CTX*);
bool RCR_Exec(X64_EMULATOR_CTX*);
bool SHL_Exec(X64_EMULATOR_CTX*);
bool SHR_Exec(X64_EMULATOR_CTX*);
bool SAR_Exec(X64_EMULATOR_CTX*);
bool NEG_Exec(X64_EMULATOR_CTX*);
bool NOT_Exec(X64_EMULATOR_CTX*);
bool INC_Exec(X64_EMULATOR_CTX*);
bool DEC_Exec(X64_EMULATOR_CTX*);
bool SLDT_Exec(X64_EMULATOR_CTX*);
bool STR_Exec(X64_EMULATOR_CTX*);
bool STOS_Exec(X64_EMULATOR_CTX*);
bool SGDT_Exec(X64_EMULATOR_CTX*);
bool SIDT_Exec(X64_EMULATOR_CTX*);
bool SMSW_Exec(X64_EMULATOR_CTX*);
bool CMPXCHG8B_Exec(X64_EMULATOR_CTX*);
bool MOVBE_Exec(X64_EMULATOR_CTX*);

//
// handlers for instrucitons that do not modify memory
//
bool BT_Exec(X64_EMULATOR_CTX*);
bool MOV_2Reg_Exec(X64_EMULATOR_CTX*); // MOV that does not write to memory


#define Eb MAKE_ADDRM(ADDRM_E,OPRND_b)
#define Gb MAKE_ADDRM(ADDRM_G,OPRND_b)
#define Gw MAKE_ADDRM(ADDRM_G,OPRND_w)
#define Mw MAKE_ADDRM(ADDRM_M,OPRND_w)
#define Ms MAKE_ADDRM(ADDRM_M,OPRND_s)
#define Ev MAKE_ADDRM(ADDRM_E,OPRND_v)
#define Ep MAKE_ADDRM(ADDRM_E,OPRND_p)
#define Ew MAKE_ADDRM(ADDRM_E,OPRND_w)
#define Gv MAKE_ADDRM(ADDRM_G,OPRND_v)
#define Mv MAKE_ADDRM(ADDRM_M,OPRND_v)
#define Gd MAKE_ADDRM(ADDRM_G,OPRND_d)
#define Ib MAKE_ADDRM(ADDRM_I,OPRND_b)
#define Ibx MAKE_ADDRM(ADDRM_IX,OPRND_b)
#define Iv MAKE_ADDRM(ADDRM_I,OPRND_v)
#define Iz MAKE_ADDRM(ADDRM_I,OPRND_z)
#define Iw MAKE_ADDRM(ADDRM_I,OPRND_w)
#define Ma MAKE_ADDRM(ADDRM_M,OPRND_a)
#define Yb MAKE_ADDRM(ADDRM_Y,OPRND_b)
#define Yz MAKE_ADDRM(ADDRM_Y,OPRND_z)
#define Xz MAKE_ADDRM(ADDRM_X,OPRND_z)
#define Yv MAKE_ADDRM(ADDRM_Y,OPRND_v)
#define Xv MAKE_ADDRM(ADDRM_X,OPRND_v)
#define Xb MAKE_ADDRM(ADDRM_X,OPRND_b)
#define Jb MAKE_ADDRM(ADDRM_J,OPRND_b)
#define Sw MAKE_ADDRM(ADDRM_S,OPRND_w)
#define Ew MAKE_ADDRM(ADDRM_E,OPRND_w)
#define Ap MAKE_ADDRM(ADDRM_A,OPRND_p)
#define Fv MAKE_ADDRM(ADDRM_F,OPRND_v)
#define Ob MAKE_ADDRM(ADDRM_O,OPRND_b)
#define Ov MAKE_ADDRM(ADDRM_O,OPRND_v)
#define Gz MAKE_ADDRM(ADDRM_G,OPRND_z)
#define Mp MAKE_ADDRM(ADDRM_M,OPRND_p)
#define Jz MAKE_ADDRM(ADDRM_J,OPRND_z)
#define Vps MAKE_ADDRM(ADDRM_V,OPRND_ps)
#define Vdq MAKE_ADDRM(ADDRM_V,OPRND_dq)
#define Udq MAKE_ADDRM(ADDRM_U,OPRND_dq)
#define Qpi MAKE_ADDRM(ADDRM_Q,OPRND_pi)
#define Wps MAKE_ADDRM(ADDRM_W,OPRND_ps)
#define Wdq MAKE_ADDRM(ADDRM_W,OPRND_dq)
#define Vpd MAKE_ADDRM(ADDRM_V,OPRND_pd)
#define Wpd MAKE_ADDRM(ADDRM_W,OPRND_pd)
#define Vss MAKE_ADDRM(ADDRM_V,OPRND_ss)
#define Wss MAKE_ADDRM(ADDRM_W,OPRND_ss)
#define Vsd MAKE_ADDRM(ADDRM_V,OPRND_sd)
#define Wsd MAKE_ADDRM(ADDRM_W,OPRND_sd)
#define Vq MAKE_ADDRM(ADDRM_V,OPRND_q)
#define Uq MAKE_ADDRM(ADDRM_U,OPRND_q)
#define Wq MAKE_ADDRM(ADDRM_W,OPRND_q)
#define Mq MAKE_ADDRM(ADDRM_M,OPRND_q)
#define Mdq MAKE_ADDRM(ADDRM_M,OPRND_dq)
#define Rd MAKE_ADDRM(ADDRM_R,OPRND_d)
#define Cd MAKE_ADDRM(ADDRM_C,OPRND_d)
#define Dd MAKE_ADDRM(ADDRM_D,OPRND_d)
#define Ey MAKE_ADDRM(ADDRM_E,OPRND_y)
#define Mps MAKE_ADDRM(ADDRM_M,OPRND_ps)
#define Mpd MAKE_ADDRM(ADDRM_M,OPRND_pd)
#define Ppi MAKE_ADDRM(ADDRM_P,OPRND_pi)
#define Gy MAKE_ADDRM(ADDRM_G,OPRND_y)
#define My MAKE_ADDRM(ADDRM_M,OPRND_y)
#define Ups MAKE_ADDRM(ADDRM_U,OPRND_ps)
#define Upd MAKE_ADDRM(ADDRM_U,OPRND_pd)
#define Pq MAKE_ADDRM(ADDRM_P,OPRND_q)
#define Qd MAKE_ADDRM(ADDRM_Q,OPRND_d)
#define Qq MAKE_ADDRM(ADDRM_Q,OPRND_q)
#define Pd MAKE_ADDRM(ADDRM_P,OPRND_d)
#define Ey MAKE_ADDRM(ADDRM_E,OPRND_y)
#define Ed MAKE_ADDRM(ADDRM_E,OPRND_d)
#define Vy MAKE_ADDRM(ADDRM_V,OPRND_y)
#define Ry MAKE_ADDRM(ADDRM_R,OPRND_y)
#define Nq MAKE_ADDRM(ADDRM_N,OPRND_q)
#define Mb MAKE_ADDRM(ADDRM_M,OPRND_b)
#define Md MAKE_ADDRM(ADDRM_M,OPRND_d)
#define Rv MAKE_ADDRM(ADDRM_R,OPRND_v)

#define OP_eAX OP_ATTR_R(R_RAX)
#define OP_rAX OP_eAX
#define OP_RAX OP_ATTR_R_8B(R_RAX)
#define OP_EAX OP_ATTR_R_4B(R_RAX)
#define OP_AX OP_ATTR_R_2B(R_RAX)
#define OP_DX OP_ATTR_R_2B(R_RDX)
#define OP_AL OP_ATTR_R_1B(R_RAX)
#define OP_CL OP_ATTR_R_1B(R_RCX)
#define OP_DL OP_ATTR_R_1B(R_RDX)
#define OP_BL OP_ATTR_R_1B(R_RBX)
#define OP_AH OP_ATTR_R_1B_(R_AH)
#define OP_ES OP_ATTR_R_2B(R_ES)
#define OP_CS OP_ATTR_R_2B(R_CS)
#define OP_SS OP_ATTR_R_2B(R_SS)
#define OP_DS OP_ATTR_R_2B(R_DS)
#define OP_FS OP_ATTR_R_2B(R_FS)
#define OP_GS OP_ATTR_R_2B(R_GS)
#define OP_eCX OP_ATTR_R(R_RCX)
#define OP_eDX OP_ATTR_R(R_RDX)
#define OP_eBX OP_ATTR_R(R_RBX)
#define OP_eSP OP_ATTR_R(R_RSP)
#define OP_eBP OP_ATTR_R(R_RBP)
#define OP_eSI OP_ATTR_R(R_RSI)
#define OP_eDI OP_ATTR_R(R_RDI)
#define OP_xrAX OP_ATTR_R_EX(R_AX)
#define OP_xrCX OP_ATTR_R_EX(R_CX)
#define OP_xrDX OP_ATTR_R_EX(R_DX)
#define OP_xrBX OP_ATTR_R_EX(R_BX)
#define OP_xrSP OP_ATTR_R_EX(R_SP)
#define OP_xrBP OP_ATTR_R_EX(R_BP)
#define OP_xrSI OP_ATTR_R_EX(R_SI)
#define OP_xrDI OP_ATTR_R_EX(R_DI)
#define OP_xAL OP_ATTR_R_EX_1B(R_AX)
#define OP_xCL OP_ATTR_R_EX_1B(R_CX)
#define OP_xDL OP_ATTR_R_EX_1B(R_DX)
#define OP_xBL OP_ATTR_R_EX_1B(R_BX)
#define OP_xAH OP_ATTR_R_EX_1B(R_AH)
#define OP_xCH OP_ATTR_R_EX_1B(R_CH)
#define OP_xDH OP_ATTR_R_EX_1B(R_DH)
#define OP_xBH OP_ATTR_R_EX_1B(R_BH)

#define OP_NUM1 OP_ATTR_NUM(1)

const OPCODE_ENTRY s_GroupTable_Gr6_Mod_0[2] = 
{
	{ET_TERM, NULL, 	"sldt",	1, Mw}, //SLDT_Exec
	{ET_TERM, NULL, 	"sldt",	1, Rv}, //SLDT_Exec
};

const OPCODE_ENTRY s_GroupTable_Gr6_Mod_1[2] = 
{
	{ET_TERM, NULL, 	"str",	1, Mw}, //STR_Exec
	{ET_TERM, NULL, 	"str",	1, Rv}, //STR_Exec
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_0_Rm[8] =
{
									// Mod R/M bits 2,1,0
	{ET_INV},						// 000
	{ET_TERM, NULL, "vmcall", 0}, 	// 001
	{ET_TERM, NULL, "vmlaunch", 0}, // 010
	{ET_TERM, NULL, "vmresume", 0}, // 011
	{ET_TERM, NULL, "vmxoff", 0}, 	// 100
	{ET_INV},{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_0[2] = 
{
	{ET_TERM, NULL, 	"sgdt",	1, Ms}, // SGDT_Exec
	{ET_JMPMOD_RM, s_GroupTable_Gr7_Mod_0_Rm,"",0}
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_1_Rm[8] =
{
									// Mod R/M bits 2,1,0
	{ET_TERM, NULL, "monitor", 0}, 	// 000
	{ET_TERM, NULL, "mwait", 0}, 	// 001
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_1[2] = 
{
	{ET_TERM, NULL, 	"sidt",	1, Ms}, // SIDT_Exec
	{ET_JMPMOD_RM, s_GroupTable_Gr7_Mod_1_Rm,"",0}
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_2_Rm[8] =
{
									// Mod R/M bits 2,1,0
	{ET_TERM, NULL, "xgetbv", 0}, 	// 000
	{ET_TERM, NULL, "xsetbv", 0}, 	// 001
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_2[2] = 
{
	{ET_TERM, SIDT_Exec, 	"lgdt",	1, Ms},
	{ET_JMPMOD_RM, s_GroupTable_Gr7_Mod_2_Rm,"",0}
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_3[2] = 
{
	{ET_TERM, SIDT_Exec, 	"lidt",	1, Ms},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_4[2] = 
{
	{ET_TERM, NULL, 	"smsw",	1, Mw},
	{ET_TERM, NULL, 	"smsw",	1, Rv},
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_7_Rm[8] =
{
									// Mod R/M bits 2,1,0
	{ET_TERM, NULL, "swapgs", 0}, 	// 000
	{ET_TERM, NULL, "rdtscp", 0}, 	// 001
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},
};

const OPCODE_ENTRY s_GroupTable_Gr7_Mod_7[2] = 
{
	{ET_TERM, NULL, 	"invlpg",	1, Mb},
	{ET_JMPMOD_RM, s_GroupTable_Gr7_Mod_7_Rm,"",0}
};

const OPCODE_ENTRY s_GroupTable_Gr9_Mod6_Pfx[4] = 
{
	{ET_TERM, NULL, 	"vmptrld", 1, Mq},	// Prefix 00
	{ET_TERM, NULL, 	"vmclear", 1, Mq},	// Prefix 66
	{ET_TERM, NULL, 	"vmxon",   1, Mq},	// Prefix f2
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr9_Mod_6[2] = 
{
	{ET_JMPMOD_RM, s_GroupTable_Gr9_Mod6_Pfx,"",0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr9_Mod7_Pfx[4] = 
{
	{ET_TERM, NULL, 	"vmptrst", 1, Mq},	// Prefix 00
	{ET_INV},								// Prefix 66
	{ET_TERM, NULL, 	"vmptrst", 1, Mq},	// Prefix f2
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr9_Mod_7[2] = 
{
	{ET_JMPMOD_RM, s_GroupTable_Gr9_Mod7_Pfx,"",0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr12_Mod_Pfx[4] = 
{
	{ET_TERM, NULL, "psrlw", 2, Nq, Ib},	// Prefix 00
	{ET_TERM, NULL, "psrlw", 2, Udq,Ib},	// Prefix 66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr12_Mod[2] = 
{
	{ET_INV},
	{ET_JMPMOD_RM, s_GroupTable_Gr12_Mod_Pfx,"",0}
};

#define s_GroupTable_Gr13_Mod s_GroupTable_Gr12_Mod
#define s_GroupTable_Gr14_Mod s_GroupTable_Gr12_Mod

const OPCODE_ENTRY s_GroupTable_Gr14_Mod3_Pfx[4] = 
{
	{ET_INV},								// Prefix 00
	{ET_TERM, NULL, "psrldq", 2, Udq,Ib},	// Prefix 66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr14_Mod3[2] = 
{
	{ET_INV},
	{ET_JMPMOD_RM, s_GroupTable_Gr14_Mod3_Pfx,"",0}
};

#define s_GroupTable_Gr14_Mod7 s_GroupTable_Gr14_Mod3

const OPCODE_ENTRY s_GroupTable_Gr15_Mod0[2] = 
{
	{ET_TERM, NULL, "fxsave", 0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod1[2] = 
{
	{ET_TERM, NULL, "fxrstor", 0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod2[2] = 
{
	{ET_TERM, NULL, "ldmxcsr", 0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod3[2] = 
{
	{ET_TERM, NULL, "stmxcsr", 0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod4[2] = 
{
	{ET_TERM, NULL, "XSAVE", 0},
	{ET_INV}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod5[2] = 
{
	{ET_TERM, NULL, "XRSTOR", 0},
	{ET_TERM, NULL, "lfence", 0}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod6[2] = 
{
	{ET_INV},
	{ET_TERM, NULL, "lfence", 0}
};

const OPCODE_ENTRY s_GroupTable_Gr15_Mod7[2] = 
{
	{ET_INV},
	{ET_TERM, NULL, "mfence", 0}
};

const OPCODE_ENTRY s_GroupTable_Gr16_Mod0[2] = 
{
	{ET_TERM, NULL, "prefetch", 1, Mb},
	{ET_INV},
};

#define s_GroupTable_Gr16_Mod1 s_GroupTable_Gr16_Mod0
#define s_GroupTable_Gr16_Mod2 s_GroupTable_Gr16_Mod0
#define s_GroupTable_Gr16_Mod3 s_GroupTable_Gr16_Mod0

const OPCODE_ENTRY s_GroupTable[16][8] = 
{
	// Group 1, opcode 80-83					// ModR/M bits 5,4,3 
	{
		{ET_TERMATOM,ADD_Exec, 	"add",	0}, // 000
		{ET_TERMATOM,OR_Exec, 	"or", 	0}, // 001
		{ET_TERMATOM,ADDC_Exec, "adc", 0}, // 010
		{ET_TERMATOM,SBB_Exec, 	"sbb", 	0}, // 011
		{ET_TERMATOM,AND_Exec, 	"and", 	0}, // 100
		{ET_TERMATOM,SUB_Exec, 	"sub", 	0}, // 101
		{ET_TERMATOM,XOR_Exec, 	"xor", 	0}, // 110
		{ET_TERM, NULL, 		"cmp", 	0}, // 111
	},
	// Group 1A, opcode 8f
	{
		{ET_TERMDOP64, NULL,    "pop",	1, Ev},  // 000 POP_Exec
		{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV}
	},
	// Group 2, opcode c0,c1,d0,d1,d2,d3
	{
		{ET_TERM, ROL_Exec, 	"rol",	0}, // 000
		{ET_TERM, ROR_Exec, 	"ror", 	0}, // 001
		{ET_TERM, RCL_Exec, 	"rcl", 	0}, // 010
		{ET_TERM, RCR_Exec, 	"rcr", 	0}, // 011
		{ET_TERM, SHL_Exec, 	"shl", 	0}, // 100
		{ET_TERM, SHR_Exec, 	"shr", 	0}, // 101
		{ET_TERM, SHL_Exec, 	"sal", 	0}, // 110
		{ET_TERM, SAR_Exec, 	"sar", 	0}, // 111
	},
	// Group 3 - 1, opcode f6
	{
		{ET_TERM, NULL, 		"test",	2, Eb, Ib}, // 000
		{ET_TERM, NULL, 		"test",	2, Eb, Ib}, // 001 
		{ET_TERMATOM,NOT_Exec, 	"not", 	1, Eb}, 	// 010
		{ET_TERMATOM,NEG_Exec, 	"neg", 	1, Eb}, 	// 011
		{ET_TERM, NULL, 		"mul", 	1, Eb}, 	// 100
		{ET_TERM, NULL, 		"imul", 1, Eb}, 	// 101
		{ET_TERM, NULL, 		"div",  1, Eb}, 	// 110
		{ET_TERM, NULL, 		"idiv", 1, Eb}, 	// 111
	},
	// Group 3 - 2, opcode f7
	{
		{ET_TERM, NULL, 		"test",	2, Ev, Iz}, // 000
		{ET_TERM, NULL, 		"test",	2, Ev, Iz}, // 001 
		{ET_TERMATOM,NOT_Exec, 	"not", 	1, Ev}, 	// 010
		{ET_TERMATOM,NEG_Exec, 	"neg", 	1, Ev}, 	// 011
		{ET_TERM, NULL, 		"mul", 	1, Ev}, 	// 100
		{ET_TERM, NULL, 		"imul", 1, Ev}, 	// 101
		{ET_TERM, NULL, 		"div",  1, Ev}, 	// 110
		{ET_TERM, NULL, 		"idiv", 1, Ev}, 	// 111
	},	
	// Group 4, opcode ff
	{
		{ET_TERMATOM,INC_Exec, 	"inc",	1, Eb}, // 000
		{ET_TERMATOM,DEC_Exec, 	"dec", 	1, Eb}, // 001
		{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV}
	},
	// Group 5, opcode ff
	{
		{ET_TERMATOM,INC_Exec, 	"inc",	1, Ev}, // 000
		{ET_TERMATOM,DEC_Exec, 	"dec", 	1, Ev}, // 001
		{ET_TERMFOP64, NULL, 	"call", 1, Ev}, // 010 CALLN_Exec
		{ET_TERM, NULL, 		"call", 1, Ep}, // 011 CALLF_Exec
		{ET_TERMFOP64, NULL, 	"jmp",  1, Ev}, // 100
		{ET_TERM, NULL, 		"jmp",  1, Ep}, // 101
		{ET_TERMDOP64, NULL,    "push", 1, Ev}, // 110
		{ET_INV}
	},
	// Group 6, opcode 0x0f00
	{
		{ET_JMPMOD, s_GroupTable_Gr6_Mod_0, ""},	// 000
		{ET_JMPMOD, s_GroupTable_Gr6_Mod_1, ""},	// 001
		{ET_TERM, NULL, 		"lldt", 1, Ew},	 	// 010
		{ET_TERM, NULL, 		"ltr", 	1, Ew},	 	// 011
		{ET_TERM, NULL, 		"verr", 1, Ew},	 	// 100
		{ET_TERM, NULL, 		"verw", 1, Ew},	 	// 101
		{ET_TERM, NULL,         "jmpe", 0},			// 110 - jmp to IA-64 - only for testing
		{ET_INV},
	},
	// Group 7, opcode 0x0f01
	{
		{ET_JMPMOD, s_GroupTable_Gr7_Mod_0, ""},	// 000
		{ET_JMPMOD, s_GroupTable_Gr7_Mod_1, ""},	// 001
		{ET_JMPMOD, s_GroupTable_Gr7_Mod_2, ""},	// 010
		{ET_JMPMOD, s_GroupTable_Gr7_Mod_3, ""},	// 011
		{ET_JMPMOD, s_GroupTable_Gr7_Mod_4, ""},	// 100
		{ET_INV},									// 101
		{ET_TERM,   NULL,		"lmsw", 1, Ew},		// 110
		{ET_JMPMOD, s_GroupTable_Gr7_Mod_7, ""},	// 111
	},
	// Group 8, opcode 0x0fba	
	{
		{ET_INV},{ET_INV},{ET_INV},{ET_INV},
		{ET_TERM, BT_Exec,		"bt",  2, Ev, Ib},	//100
		{ET_TERMATOM,BTS_Exec,	"bts", 2, Ev, Ib},	//101
		{ET_TERMATOM,BTR_Exec,	"btr", 2, Ev, Ib},	//110
		{ET_TERMATOM,BTC_Exec,	"btc", 2, Ev, Ib},	//111
	},
	// Group 9, opcode 0x0fc7
	{
		{ET_INV},										  // 000
		{ET_TERMATOM, CMPXCHG8B_Exec, "cmpxchg8b", 1, Mq},// 001
		{ET_INV},{ET_INV},{ET_INV},{ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr9_Mod_6},			  // 110
		{ET_JMPMOD, s_GroupTable_Gr9_Mod_7},			  // 111
	},
	// Group 12, opcode 0x0f71
	{
		{ET_INV}, {ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr12_Mod},				// 010
		{ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr12_Mod},				// 100
		{ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr12_Mod},				// 110
		{ET_INV},
	},
	// Group 13, opcode 0x0f72
	{
		{ET_INV}, {ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr13_Mod},				// 010
		{ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr13_Mod},				// 100
		{ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr13_Mod},				// 110
		{ET_INV},
	},
	// Group 14, opcode 0x0f73
	{
		{ET_INV}, {ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr14_Mod},				// 010
		{ET_JMPMOD, s_GroupTable_Gr14_Mod3},			// 011
		{ET_INV},{ET_INV},
		{ET_JMPMOD, s_GroupTable_Gr14_Mod},				// 110
		{ET_JMPMOD, s_GroupTable_Gr14_Mod7},			// 111
	},
	// Group 15, opcode 0x0fae
	{
		{ET_JMPMOD, s_GroupTable_Gr15_Mod0},	// 000
		{ET_JMPMOD, s_GroupTable_Gr15_Mod1},	// 001
		{ET_JMPMOD, s_GroupTable_Gr15_Mod2},	// 010
		{ET_JMPMOD, s_GroupTable_Gr15_Mod3},	// 011
		{ET_JMPMOD, s_GroupTable_Gr15_Mod4},	// 100
		{ET_JMPMOD, s_GroupTable_Gr15_Mod5},	// 101
		{ET_JMPMOD, s_GroupTable_Gr15_Mod6},	// 110
		{ET_JMPMOD, s_GroupTable_Gr15_Mod7},	// 111
	},
	// Group 16, opcode 0x0f18
	{
		{ET_JMPMOD, s_GroupTable_Gr16_Mod0},	// 000
		{ET_JMPMOD, s_GroupTable_Gr16_Mod1},	// 001
		{ET_JMPMOD, s_GroupTable_Gr16_Mod2},	// 010
		{ET_JMPMOD, s_GroupTable_Gr16_Mod3},	// 011
		{ET_INV}, {ET_INV},{ET_INV}, {ET_INV}
	}
};

const OPCODE_ENTRY s_FpuTable[1] = {{0}};

//
// Symbolic consts for groups for indexing into the group table
//
#define GRP_1		&s_GroupTable[0][0]
#define GRP_1A		&s_GroupTable[1][0]
#define GRP_2		&s_GroupTable[2][0]
#define GRP_3_1		&s_GroupTable[3][0]
#define GRP_3_2		&s_GroupTable[4][0]
#define GRP_4		&s_GroupTable[5][0]
#define GRP_5		&s_GroupTable[6][0]
#define GRP_6		&s_GroupTable[7][0]
#define GRP_7		&s_GroupTable[8][0]
#define GRP_8		&s_GroupTable[9][0]
#define GRP_9		&s_GroupTable[10][0]
#define GRP_10		0 // Empty line in the table, so we skip it
#define GRP_11		0 // Handled by the 1 byte opcode table, so we consider it empty
#define GRP_12	   	&s_GroupTable[11][0]	
#define GRP_13	   	&s_GroupTable[12][0]
#define GRP_14	   	&s_GroupTable[13][0]
#define GRP_15		&s_GroupTable[14][0]
#define GRP_16		&s_GroupTable[15][0]


const OPCODE_ENTRY s_OpcodeMap_0x63[2] = 
{
	{ET_TX32, NULL, 	"arpl",   2, Ew,  Gw}, 		//63 - 32 bit ARPL_Exec
	{ET_TX64, NULL, 	"movsxd", 2, Gv,  Ev}, 		//63 - 64 bit
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x10[] = // opcode 0f10
{
	{ET_TERM, NULL,			"movups",2, Vps,  Wps},			//pfx=00
	{ET_TERM, NULL,			"movupd",2, Vpd,  Wpd},			//pfx=66
	{ET_TERM, NULL,			"movuss",2, Vss,  Wss},			//pfx=f3
	{ET_TERM, NULL,			"movuss",2, Vsd,  Wsd},			//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x11[] = // opcode 0f11
{
	{ET_TERM, NULL,			"movups",2, Wps,  Vps},			//pfx=00
	{ET_TERM, NULL,			"movupd",2, Wpd,  Vpd},			//pfx=66
	{ET_TERM, NULL,			"movuss",2, Wss,  Vss},			//pfx=f3
	{ET_TERM, NULL,			"movuss",2, Wsd,  Vsd},			//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x12[] = // opcode 0f12
{
	{ET_TERM, NULL,			"movlps",2, Vq,   Uq},			//pfx=00
	{ET_TERM, NULL,			"movlpd",2, Vq,   Mq},			//pfx=66
	{ET_TERM, NULL,			"movlsdup",2, Vq, Wq},			//pfx=f3
	{ET_TERM, NULL,			"movddup", 2, Vq, Wq},			//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x13[] = // opcode 0f13
{
	{ET_TERM, NULL,			"movlps",2, Mq,   Vq},			//pfx=00 TODO: MOVLPS_Exec
	{ET_TERM, NULL,			"movlpd",2, Mq,   Vq},			//pfx=66 TODO: MOVLPD_Exec
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x14[] = // opcode 0f14
{
	{ET_TERM, NULL,			"unpckls",2, Vps,  Wq},			//pfx=00
	{ET_TERM, NULL,			"unpckld",2, Vpd,  Wq},			//pfx=66
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x15[] = // opcode 0f15
{
	{ET_TERM, NULL,			"unpckhps",2, Vps,  Wq},		//pfx=00
	{ET_TERM, NULL,			"unpckhpd",2, Vpd,  Wq},		//pfx=66
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x16[] = // opcode 0f16
{
	{ET_TERM, NULL,			"movhps",2,   Vq,   Mq},		//pfx=00 movlhps Vq Uq ??
	{ET_TERM, NULL,			"movhpd",2,   Vq,   Mq},		//pfx=66
	{ET_TERM, NULL,			"movshdup",2, Vq,   Wq},		//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x17[] = // opcode 0f17
{
	{ET_TERM, NULL,			"movhps",2, Mq,   Vq},			//pfx=00 TODO: MOVHPS_Exec
	{ET_TERM, NULL,			"movhpd",2, Mq,   Vq},			//pfx=66 TODO: MOVHPD_Exec
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};


const OPCODE_ENTRY s_OpcodeMapPfx_0x28[] = // opcode 0f28
{
	{ET_TERM, NULL,			"movaps",2, Vps,  Wps},			//pfx=00
	{ET_TERM, NULL,			"movapd",2, Vpd,  Wpd},			//pfx=66
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x29[] = // opcode 0f29
{
	{ET_TERM, NULL,			"movaps",2, Wps,  Vps},			//pfx=00
	{ET_TERM, NULL,			"movapd",2, Wpd,  Vpd},			//pfx=66
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x2a[] = // opcode 0f2a
{
	{ET_TERM, NULL,			"cvtpi2ps", 2, Vps,  Qpi},		//pfx=00
	{ET_TERM, NULL,			"cvtpi2pd", 2, Vpd,  Qpi},		//pfx=66
	{ET_TERM, NULL,			"cvtsi2ss", 2, Vss,  Ey},		//pfx=f3
	{ET_TERM, NULL,			"cvtsi2sd", 2, Vsd,  Ey},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x2b[] = // opcode 0f2b
{
	{ET_TERM, NULL,			"movntps",2, Mps,   Vps},		//pfx=00 TODO: MOVNTPS_Exec
	{ET_TERM, NULL,			"movntpd",2, Mpd,   Vpd},		//pfx=66 TODO: MOVNTPD_Exec
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x2c[] = // opcode 0f2c
{
	{ET_TERM, NULL,			"cvttps2pi", 2, Ppi, Wps},		//pfx=00
	{ET_TERM, NULL,			"cvttpd2pi", 2, Ppi, Wpd},		//pfx=66
	{ET_TERM, NULL,			"cvttss2si", 2, Gy,  Wss},		//pfx=f3
	{ET_TERM, NULL,			"cvttsd2si", 2, Gy,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x2d[] = // opcode 0f2d
{
	{ET_TERM, NULL,				"cvtps2pi", 2, Ppi, Wps},	//pfx=00
	{ET_TERM, NULL,				"cvtpd2pi", 2, Qpi, Wpd},	//pfx=66 TODO: CVTPPD2PI_Exec
	{ET_TERM, NULL,				"cvtss2si", 2, Gy,  Wss},	//pfx=f3
	{ET_TERM, NULL,				"cvtsd2si", 2, Gy,  Wsd},	//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x2e[] = // opcode 0f2e
{
	{ET_TERM, NULL,				"ucomiss", 2, Vss,   Wss},	//pfx=00
	{ET_TERM, NULL,				"ucomisd", 2, Vsd,   Wsd},	//pfx=66
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x2f[] = // opcode 0f2f
{
	{ET_TERM, NULL,				"comiss", 2, Vss,   Wss},	//pfx=00
	{ET_TERM, NULL,				"comisd", 2, Vsd,   Wsd},	//pfx=66
	{ET_INV}, 												//pfx=f3
	{ET_INV}, 												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x50[] = // opcode 0f50
{
	{ET_TERM, NULL,				"movmskps", 2, Gy,  Ups},	//pfx=00
	{ET_TERM, NULL,				"movmskpd", 2, Gy,  Upd},	//pfx=66
	{ET_INV}, {ET_INV}, 									//pfx=f3..f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x51[] = // opcode 0f51
{
	{ET_TERM, NULL,				"sqrtps",  2, Wps,  Vps},	//pfx=00
	{ET_TERM, NULL,				"sqrtpd",  2, Wpd,  Vpd},	//pfx=66
	{ET_TERM, NULL,				"sqrtss",  2, Vss,  Wss},	//pfx=f3
	{ET_TERM, NULL,				"sqrtsd",  2, Vsd,  Wsd},	//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x52[] = // opcode 0f52
{
	{ET_TERM, NULL,				"rsqrtps", 2, Wps,  Vps},	//pfx=00
	{ET_INV},												//pfx=66
	{ET_TERM, NULL,				"rsqrtss", 2, Vss,  Wss},	//pfx=f3
	{ET_INV},												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x53[] = // opcode 0f53
{
	{ET_TERM, NULL,				"rcpps", 2, Wps,  Vps},		//pfx=00
	{ET_INV},												//pfx=66
	{ET_TERM, NULL,				"rcpss", 2, Vss,  Wss},		//pfx=f3
	{ET_INV},												//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x54[] = // opcode 0f54
{
	{ET_TERM, NULL,				"andps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"andpd", 2, Wpd,  Vpd},		//pfx=66
	{ET_INV}, {ET_INV}, 									//pfx=f3..f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x55[] = // opcode 0f55
{
	{ET_TERM, NULL,				"andnps", 2, Vps,  Wps},	//pfx=00
	{ET_TERM, NULL,				"andnpd", 2, Wpd,  Vpd},	//pfx=66
	{ET_INV}, {ET_INV}, 									//pfx=f3..f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x56[] = // opcode 0f56
{
	{ET_TERM, NULL,				"orps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"orpd", 2, Wpd,  Vpd},		//pfx=66
	{ET_INV}, {ET_INV}, 									//pfx=f3..f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x57[] = // opcode 0f57
{
	{ET_TERM, NULL,				"xorps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"xorpd", 2, Wpd,  Vpd},		//pfx=66
	{ET_INV}, {ET_INV}, 									//pfx=f3..f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x58[] = // opcode 0f58
{
	{ET_TERM, NULL,				"addps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"addpd", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL,				"addss", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,				"addsd", 2, Vsd,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x59[] = // opcode 0f59
{
	{ET_TERM, NULL,				"mulps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"mulpd", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL,				"mulss", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,				"mulsd", 2, Vsd,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x5a[] = // opcode 0f5a
{
	{ET_TERM, NULL,	"cvtps2pd", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,	"cvtpd2ps", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL, "cvtss2sd", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,	"cvtsd2ss", 2, Vss,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x5b[] = // opcode 0f5b
{
	{ET_TERM, NULL,	"cvtdq2ps", 2, Vps,  Wdq},		//pfx=00
	{ET_TERM, NULL,	"cvtps2dq", 2, Vdq,  Wps},		//pfx=66
	{ET_TERM, NULL, "cvttps2dq",2, Vdq,  Wps},		//pfx=f3
	{ET_INV},										//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x5c[] = // opcode 0f5c
{
	{ET_TERM, NULL,				"subps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"subpd", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL,				"subss", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,				"subsd", 2, Vsd,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x5d[] = // opcode 0f5d
{
	{ET_TERM, NULL,				"minps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"minpd", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL,				"minss", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,				"minsd", 2, Vsd,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x5e[] = // opcode 0f5e
{
	{ET_TERM, NULL,				"divps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"divpd", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL,				"divss", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,				"divsd", 2, Vsd,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x5f[] = // opcode 0f5f
{
	{ET_TERM, NULL,				"maxps", 2, Vps,  Wps},		//pfx=00
	{ET_TERM, NULL,				"maxpd", 2, Vpd,  Wpd},		//pfx=66
	{ET_TERM, NULL,				"maxss", 2, Vss,  Wss},		//pfx=f3
	{ET_TERM, NULL,				"maxsd", 2, Vsd,  Wsd},		//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x60[] = // opcode 0f60
{
	{ET_TERM, NULL,		"punpcklbw", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"punpcklbw", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x61[] = // opcode 0f61
{
	{ET_TERM, NULL,		"punpcklwd", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"punpcklwd", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x62[] = // opcode 0f62
{
	{ET_TERM, NULL,		"punpckldq", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"punpckldq", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x63[] = // opcode 0f63
{
	{ET_TERM, NULL,		"packsswb", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"packsswb", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x64[] = // opcode 0f64
{
	{ET_TERM, NULL,		"pcmpgtb", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"pcmpgtb", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x65[] = // opcode 0f65
{
	{ET_TERM, NULL,		"pcmpgtw", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"pcmpgtw", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x66[] = // opcode 0f66
{
	{ET_TERM, NULL,		"pcmpgtd", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"pcmpgtd", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x67[] = // opcode 0f67
{
	{ET_TERM, NULL,		"packuswb", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"packuswb", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x68[] = // opcode 0f68
{
	{ET_TERM, NULL,		"punpckhbw", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"punpckhbw", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x69[] = // opcode 0f69
{
	{ET_TERM, NULL,		"punpckhwd", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"punpckhwd", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x6a[] = // opcode 0f6a
{
	{ET_TERM, NULL,		"punpckhdq", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"punpckhdq", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x6b[] = // opcode 0f6b
{
	{ET_TERM, NULL,		"packssdw", 2, Pq,  Qd},	//pfx=00
	{ET_TERM, NULL,		"packssdw", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x6c[] = // opcode 0f6c
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL,		"punpcklqdq", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x6d[] = // opcode 0f6d
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL,		"punpckhqdq", 2, Vdq, Wdq},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x6e[] = // opcode 0f6e
{
	{ET_TERM, NULL,		"movdq", 2, Pd, Ey},	//pfx=00
	{ET_TERM, NULL,		"movdq", 2, Vy, Ey},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x6f[] = // opcode 0f6f
{
	{ET_TERM, NULL,		"movq", 	2, Pq, 	Qq},	//pfx=00
	{ET_TERM, NULL,		"movdqa", 	2, Vdq, Wdq},	//pfx=66
	{ET_INV},
	{ET_TERM, NULL,		"movdqu", 	2, Vdq, Wdq},	//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x70[] = // opcode 0f70
{
	{ET_TERM, NULL,		"pshufw", 3, Pq, Qq, Ib},	//pfx=00
	{ET_TERM, NULL,		"pshufd", 3, Vdq,Wdq,Ib},	//pfx=66
	{ET_TERM, NULL,		"pshufhw",3, Vdq,Wdq,Ib},	//pfx=f3
	{ET_TERM, NULL,		"pshuflw",3, Vdq,Wdq,Ib},	//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x74[] = // opcode 0f74
{
	{ET_TERM, NULL,		"pcmpeqb", 	2, Pq, 	Qq},	//pfx=00
	{ET_TERM, NULL,		"pcmpeqb", 	2, Vdq, Wdq},	//pfx=66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x75[] = // opcode 0f75
{
	{ET_TERM, NULL,		"pcmpeqw", 	2, Pq, 	Qq},	//pfx=00
	{ET_TERM, NULL,		"pcmpeqw", 	2, Vdq, Wdq},	//pfx=66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x76[] = // opcode 0f76
{
	{ET_TERM, NULL,		"pcmpeqd", 	2, Pq, 	Qq},	//pfx=00
	{ET_TERM, NULL,		"pcmpeqd", 	2, Vdq, Wdq},	//pfx=66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x7c[] = // opcode 0f7c
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL,		"haddpd", 	2, Vpd, Wpd},	//pfx=66
	{ET_INV}, 
	{ET_TERM, NULL,		"haddps", 	2, Vps, Wps},	//pfx=f3
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x7d[] = // opcode 0f7d
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL,		"hsubpd", 	2, Vpd, Wpd},	//pfx=66
	{ET_INV}, 
	{ET_TERM, NULL,		"hsubps", 	2, Vps, Wps},	//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x7e[] = // opcode 0f7e
{
	{ET_TERM, NULL,			"movdq", 	2, Ey, 	Pd}, //pfx=00 TODO: MOVDQ_Exec
	{ET_TERM, NULL,			"movdq", 	2, Ey, 	Vy}, //pfx=66 TODO: MOVDQ_Exec
	{ET_TERM, NULL,			"movq", 	2, Vq, 	Wq}, //pfx=f3
	{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x7f[] = // opcode 0f7f
{
	{ET_TERM, NULL,		"movq", 	2, Qq, 	Pq}, //pfx=00
	{ET_TERM, NULL,		"movdqa", 	2, Wdq, Vdq}, //pfx=66
	{ET_TERM, NULL,		"movdqu", 	2, Wdq, Vdq}, //pfx=f3
	{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xb8[] = // opcode 0f7f
{
	{ET_TERM, NULL,		"jmpe", 	0}, 		  //pfx=00 - reserved for emulator on IPF?
	{ET_TERM, NULL,		"POPCNT", 	2, Gv, Ev},   //pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xc2[] = // opcode 0fc2
{
	{ET_TERM, NULL,		"cmpps",  3, Vps, Wps, Ib}, //pfx=00
	{ET_TERM, NULL,		"cmppd",  3, Vpd, Wpd, Ib}, //pfx=66
	{ET_TERM, NULL,		"cmpss",  3, Vss, Wss, Ib}, //pfx=f3
	{ET_TERM, NULL,		"cmpsd",  3, Vsd, Wsd, Ib}, //pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xc4[] = // opcode 0fc4
{
	{ET_TERM, NULL,		"pinsrw",  3, Pq, Ry, Ib}, //pfx=00
	{ET_TERM, NULL,		"pinsrw",  3, Vdq, Ry, Ib}, //pfx=66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xc5[] = // opcode 0fc5
{
	{ET_TERM, NULL,		"pextrw",  3, Gd, Nq, Ib}, //pfx=00
	{ET_TERM, NULL,		"pextrw",  3, Gd, Nq, Ib}, //pfx=66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xc6[] = // opcode 0fc6
{
	{ET_TERM, NULL,		"shufps",  3, Vps, Wps, Ib}, //pfx=00
	{ET_TERM, NULL,		"shufpd",  3, Vpd, Wpd, Ib}, //pfx=66
	{ET_INV}, {ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd0[] = // opcode 0fd0
{
	{ET_INV},									   //pfx=00
	{ET_TERM, NULL,		"addsubpd",  2, Vpd, Wpd}, //pfx=66
	{ET_INV},									   //pfx=f3
	{ET_TERM, NULL,		"addsubps",  2, Vps, Wps}, //pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd1[] = // opcode 0fd1
{
	{ET_TERM, 0,	"psrlw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, 0,	"psrlw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd2[] = // opcode 0fd2
{
	{ET_TERM, NULL,	"psrld", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"psrld", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd3[] = // opcode 0fd3
{
	{ET_TERM, NULL,	"psrlq", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"psrlq", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd4[] = // opcode 0fd4
{
	{ET_TERM, NULL,	"paddq", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"paddq", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd5[] = // opcode 0fd5
{
	{ET_TERM, NULL,	"pmullw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pmullw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd6[] = // opcode 0fd6
{
	{ET_INV},
	{ET_TERM, NULL,			"movq", 	2, Wq, 	Vq}, //pfx=66 TODO: MOVQ_Exec
	{ET_TERM, NULL,			"movq2dq", 	2, Vdq, Nq}, //pfx=f3
	{ET_TERM, NULL,			"movdq2q", 	2, Pq,  Uq}, //pfx=f2
};


const OPCODE_ENTRY s_OpcodeMapPfx_0xd7[] = // opcode 0fd7
{
	{ET_TERM, NULL,	"pmobmskb", 2, Gd, 	Nq}, //pfx=00
	{ET_TERM, NULL,	"pmobmskb", 2, Gd, 	Udq}, //pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd8[] = // opcode 0fd8
{
	{ET_TERM, NULL,	"psubusb", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"psubusb", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xd9[] = // opcode 0fd9
{
	{ET_TERM, NULL,	"psubusw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"psubusw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xda[] = // opcode 0fda
{
	{ET_TERM, NULL,	"pminub", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pminub", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xdb[] = // opcode 0fd8
{
	{ET_TERM, NULL,	"pand", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pand", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xdc[] = // opcode 0fdb
{
	{ET_TERM, NULL,	"paddusb", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"paddusb", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xdd[] = // opcode 0fdc
{
	{ET_TERM, NULL,	"paddusw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"paddusw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xde[] = // opcode 0fde
{
	{ET_TERM, NULL,	"pmaxub", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pmaxub", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xdf[] = // opcode 0fd8
{
	{ET_TERM, NULL,	"pandn", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pandn", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe0[] = 
{
	{ET_TERM, NULL,	"pavgb", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pavgb", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe1[] = 
{
	{ET_TERM, NULL,	"paraw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"paraw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe2[] = 
{
	{ET_TERM, NULL,	"parad", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"parad", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe3[] = 
{
	{ET_TERM, NULL,	"pavgw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pavgw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe4[] = 
{
	{ET_TERM, NULL,	"pmulhuw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pmulhuw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe5[] = 
{
	{ET_TERM, NULL,	"pmulhw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pmulhw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe6[] =
{
	{ET_INV},
	{ET_TERM, NULL,		"cvtpd2dq", 2, Vdq, Wpd}, //pfx=66
	{ET_TERM, NULL,		"cvtdq2pd", 2, Vdq, Wpd}, //pfx=f3
	{ET_TERM, NULL,		"cvtpd2dq", 2, Vdq, Wpd}, //pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe7[] =
{
	{ET_TERM, NULL,			"movntq", 2, Mq, Pq}, //pfx=00 TODO: MOVNTQ_Exec
	{ET_TERM, NULL,			"movntdq", 2, Mdq, Vdq}, //pfx=66 TODO: MOVNTDQ_Exec
	{ET_INV},{ET_INV},
};


const OPCODE_ENTRY s_OpcodeMapPfx_0xe8[] = 
{
	{ET_TERM, NULL,	"psubsb", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"psubsb", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xe9[] = 
{
	{ET_TERM, NULL,	"psubsw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"psubsw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xea[] = 
{
	{ET_TERM, NULL,	"pminsw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pminsw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xf0[] = 
{
	{ET_INV}, {ET_INV}, {ET_INV},
	{ET_TERM, NULL,	"Iddqu", 2, Vdq, Mdq},//pfx=f2
};

const OPCODE_ENTRY s_OpcodeMapPfx_0xf7[] = 
{
	{ET_TERM, NULL,	"maskmovq", 2, Pq, 	Nq}, //pfx=00
	{ET_TERM, NULL,	"maskmovdqu",2, Vdq, Udq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_pxxxx_Pq_Qq[] = 
{
	{ET_TERM, NULL,	"pminsw", 	2, Pq, 	Qq}, //pfx=00
	{ET_TERM, NULL,	"pminsw", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x38_0x01[] = 
{
	{ET_TERM, NULL,	"pxxxxx", 	2, Vdq, Wdq},//pfx=66
	{ET_INV},{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x38_0x20[] = 
{
	{ET_INV},
	{ET_TERM, NULL,	"pxxxxx", 2, Vdq, Udq},//pfx=66
	{ET_INV},{ET_INV},
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x38_0x2a[] = 
{
	{ET_INV},
	{ET_TERM, NULL,	"movntdqa", 2, Vdq, Mdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x38_0x80[] = 
{
	{ET_INV},
	{ET_TERM, NULL,	"invxxx", 2, Gy, Mdq},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x38_0xf0[] = 
{
	{ET_TERM, NULL,	"movbe", 2, Gy, My},//pfx=00
	{ET_TERM, NULL,	"movbe", 2, Gw, Mw},//pfx=66
	{ET_INV},
	{ET_TERM, NULL,	"crc32", 2, Gd, Eb},//pfx=f2
	//
	// NOTE: there is another where 66 & f2 are both present, which is crc32 Gd,Eb
	// We do not handle it here, because we do not care
	//
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x38_0xf1[] = 
{
	{ET_TERM, MOVBE_Exec,	"movbe", 2, My, Gy},//pfx=00
	{ET_TERM, MOVBE_Exec, 	"movbe", 2, Mw, Gw},//pfx=66
	{ET_INV},
	{ET_TERM, NULL,			"crc32", 2, Gd, Ey},//pfx=f2
	//
	// NOTE: there is another where 66 & f2 are both present, which is crc32 Gd,Ew
	// We do not handle it here, because we do not care
	//
};


const OPCODE_ENTRY s_OpcodeMap_3_0x38[] = // first two bytes are 0f38
{
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//00
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//01
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//02
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//03
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//04
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//05
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//06
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//07
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//08
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//09
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//0a
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//0b
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},				//0c..0f
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//10
	{ET_INV},{ET_INV},{ET_INV},							//11..13
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//14
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//15
	{ET_INV},											//16
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//17
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},				//18..1b
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},			//1c
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},			//1d
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},			//1e
	{ET_INV},											//1f
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//20
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//21
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//22
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//23
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//24
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//25
	{ET_INV},{ET_INV},									//26..27
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//28
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//29
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//2a
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x2a},				//2b
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},				//2c..2f
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//30
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//31
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//32
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//33
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//34
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x20},				//35
	{ET_INV},											//36
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//37
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//38
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//39
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//3a
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//3b
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//3c
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//3d
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//3e
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//3f
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//40
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//41
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},					//42..47
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//48..4f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//50..57
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//58..5f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//60..67
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//68..6f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//70..77
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//78..7f
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x80},				//80
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x80},				//81
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},					//82..87
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//88..8f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//90..97
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//98..9f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//a0..a7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//a8..af
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//b0..b7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//b8..bf
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//c0..c7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//c8..cf
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//d0..d7
	{ET_INV},{ET_INV},{ET_INV},												//d8..8a
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//db
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//dc
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//dd
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//de
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0x01},				//df
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//e0..e7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//e8..ef
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0xf0},				//f0
	{ET_JMPPFX, s_OpcodeMapPfx_0x38_0xf1},				//f1
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},					//f2..f7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV} //f8..ff
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x08[] = 
{
	{ET_INV},
	{ET_TERM, NULL,	"roundxx", 3, Vdq, Wdq, Ib},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x0a[] = 
{
	{ET_INV},
	{ET_TERM, NULL,	"roundxx", 3, Vss, Wss, Ib},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x0f[] = 
{
	{ET_TERM, NULL,	"palignr", 3, Pq, Qq, Ib},//pfx=00
	{ET_TERM, NULL,	"palignr", 3, Vdq, Wdq, Ib},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x14_Mod[4] =
{
	{ET_TERM, NULL, "pextrb", 3, Mb, Vdq, Ib}, //mod=00 TODO: PEXTRB_Exec
	{ET_TERM, NULL, "pextrb", 3, Mb, Vdq, Ib}, //mod=01 TODO: PEXTRB_Exec
	{ET_TERM, NULL, "pextrb", 3, Mb, Vdq, Ib}, //mod=10 TODO: PEXTRB_Exec
	{ET_TERM, NULL, "pextrb", 3, Rd, Vdq, Ib}, //mod=11
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x14[] = 
{
	{ET_INV},													//pfx=00
	{ET_JMPMOD, &s_OpcodeMapPfx_0x3a_0x14_Mod[0],	"", 0},		//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x15_Mod[4] =
{
	{ET_TERM, NULL,			"pextrw", 3, Mw, Vdq, Ib}, //mod=00 TODO: PEXTRW_Exec
	{ET_TERM, NULL,			"pextrw", 3, Mw, Vdq, Ib}, //mod=01 TODO: PEXTRW_Exec
	{ET_TERM, NULL,			"pextrw", 3, Mw, Vdq, Ib}, //mod=10 TODO: PEXTRW_Exec
	{ET_TERM, NULL, 	   "pextrw", 3, Rd, Vdq, Ib}, //mod=11
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x15[] = 
{
	{ET_INV},													//pfx=00
	{ET_JMPMOD, &s_OpcodeMapPfx_0x3a_0x15_Mod[0],"", 0},		//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x16[] = 
{
	{ET_INV},												//pfx=00
	{ET_TERM, NULL,			"pextrdq", 	3, Ey, Vdq, Ib},	//pfx=66 TODO: PEXTRDQ_Exec
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x17[] = 
{
	{ET_INV},												//pfx=00
	{ET_TERM, NULL,			"extractps",3, Ed, Vdq, Ib},	//pfx=66 TODO: EXTRACTPS_Exec
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x20[] = 
{
	{ET_INV},									//pfx=00
	{ET_TERM, NULL, "pinsrb",3, Vdq, Mb, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x21[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "insertps", 3, Vdq, Md, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x22[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "pinsrtdq", 3, Vdq, Ey, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x40[] = 
{
	{ET_INV},									//pfx=00
	{ET_TERM, NULL, "dpps", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x41[] = 
{
	{ET_INV},									//pfx=00
	{ET_TERM, NULL, "dppd", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x42[] = 
{
	{ET_INV},									//pfx=00
	{ET_TERM, NULL, "mpsadbw", 3, Vdq, Wdq, Ib},//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x44[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "pclmulqdq", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x60[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "pcmpestrm", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x61[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "pcmpestri", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x62[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "pcmpistrm", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0x63[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "pcmpistri", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMapPfx_0x3a_0xdf[] = 
{
	{ET_INV},										//pfx=00
	{ET_TERM, NULL, "aeskeygen", 3, Vdq, Wdq, Ib},	//pfx=66
	{ET_INV},{ET_INV}
};

const OPCODE_ENTRY s_OpcodeMap_3_0x3A[256] = 
{
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//00..07
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x08},								    //08
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x08},								    //09
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x0a},								    //0a
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x0a },								    //0b
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x08},								    //0c
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x08},								    //0d
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x08},								    //0e
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x0f},								    //0f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},									//10..13
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x14, "", 0},							//14
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x15, "", 0},							//15
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x16, "", 0},							//16
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x17, "", 0},							//17
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//18..1f
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x20, "", 0},							//20
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x21, "", 0},							//21
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x22, "", 0},							//22
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},							//23..27
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//28..2f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//30..37
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//38..3f
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x40, "", 0},							//40
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x41, "", 0},							//41
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x42, "", 0},							//42
	{ET_INV},
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x44, "", 0},							//44
	{ET_INV},{ET_INV},{ET_INV},												//45..47
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//48..4f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//50..57
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//58..5f
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x60, "", 0},							//60
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x61, "", 0},							//61
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x62, "", 0},							//62
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0x62, "", 0},							//63
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},									//64..67
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//68..6f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//70..77
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//78..7f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//80..87
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//88..8f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//90..97
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//98..9f
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//a0..a7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//a8..af
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//b0..b7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//b8..bf
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//c0..c7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//c8..cf
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//d0..d7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},			//d8..de
	{ET_JMPPFX, s_OpcodeMapPfx_0x3a_0xdf, "", 0},							//df
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//e0..e7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//e8..ef
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//f0..f7
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},//f8..ff
};

const OPCODE_ENTRY s_OpcodeMap_2[256] = // first byte is 0f
{
////////////////////////////////////////////////////////////////////
//	 Type     Handler		Mnemon. Cnt Op1 	Op2 	Op3	  OpCode
////////////////////////////////////////////////////////////////////
	{ET_JMPGR, GRP_6, 		"", 	 0}, 					//00
	{ET_JMPGR, GRP_7, 		"", 	 0}, 					//01
	{ET_TERM, NULL,			"lar",   2, Gv,     Ew},		//02
	{ET_TERM, NULL,			"lsl",   2, Gv,     Ew},		//03
	{ET_INV},												//04
	{ET_TERM, NULL,			"syscall",0},					//05
	{ET_TERM, NULL,			"clts",  0},					//06
	{ET_TERM, NULL,			"sysret",0},					//07
	{ET_TERM, NULL,			"invd",  0},					//08
	{ET_TERM, NULL,			"wbinvd",0},					//09
	{ET_INV},												//0a
	{ET_TERM, NULL, 		"ud2"},							//0b
	{ET_INV},												//0c
	{ET_TERM, NULL,			"nop", 	 1, Ev},				//0d
	{ET_INV}, {ET_INV},										//0e..0f
	{ET_JMPPFX, s_OpcodeMapPfx_0x10 },						//10
	{ET_JMPPFX, s_OpcodeMapPfx_0x11 },						//11
	{ET_JMPPFX, s_OpcodeMapPfx_0x12 },						//12
	{ET_JMPPFX, s_OpcodeMapPfx_0x13 },						//13
	{ET_JMPPFX, s_OpcodeMapPfx_0x14 },						//14
	{ET_JMPPFX, s_OpcodeMapPfx_0x15 },						//15
	{ET_JMPPFX, s_OpcodeMapPfx_0x16 },						//16
	{ET_JMPPFX, s_OpcodeMapPfx_0x17 },						//17
	{ET_JMPGR, GRP_16, 		"", 	 0}, 					//18
	{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},{ET_INV},	//19..1e
	{ET_TERM, NULL,			"nop", 	1, Ev},					//1f
	{ET_TERM, NULL,			"mov",  2, Rd,			Cd},	//20 r32/64 <-- cr0/7
	{ET_TERM, NULL,			"mov",  2, Rd,			Dd},	//21 r32/64 <-- dr0/7
	{ET_TERM, NULL,			"mov",  2, Cd,			Rd},	//22 cr0/7 <-- r32/64
	{ET_TERM, NULL,			"mov",  2, Dd,			Rd},	//23 dr0/7 <-- r32/64
	{ET_INV}, {ET_INV}, {ET_INV}, {ET_INV},					//24..27
	{ET_JMPPFX, s_OpcodeMapPfx_0x28 },						//28
	{ET_JMPPFX, s_OpcodeMapPfx_0x29 },						//29
	{ET_JMPPFX, s_OpcodeMapPfx_0x2a },						//2a
	{ET_JMPPFX, s_OpcodeMapPfx_0x2b },						//2b
	{ET_JMPPFX, s_OpcodeMapPfx_0x2c },						//2c
	{ET_JMPPFX, s_OpcodeMapPfx_0x2d },						//2d
	{ET_JMPPFX, s_OpcodeMapPfx_0x2e },						//2e
	{ET_JMPPFX, s_OpcodeMapPfx_0x2f },						//2f
	{ET_TERM,   NULL, 		"wrmsr", 0},					//30
	{ET_TERM,   NULL, 		"rdtsc", 0},					//31
	{ET_TERM,   NULL, 		"rdmsr", 0},					//32
	{ET_TERM,   NULL, 		"rdpmc", 0},					//33
	{ET_TERM,   NULL, 		"sysenter", 0},					//34
	{ET_TERM,   NULL, 		"sysexit", 0},					//35
	{ET_INV},												//36
	{ET_TERM,   NULL, 		"getsec", 0},					//37
	{ET_JMP3B,  s_OpcodeMap_3_0x38},						//38
	{ET_INV},												//39
	{ET_JMP3B,  s_OpcodeMap_3_0x3A},						//3a
	{ET_INV}, {ET_INV}, {ET_INV}, {ET_INV}, {ET_INV},       //3b..3f
	{ET_TERM,   NULL,		"cmovo", 2, Gv, 	Ev},		//40
	{ET_TERM,   NULL,		"cmovno",2, Gv, 	Ev},		//41
	{ET_TERM,   NULL,		"cmovb", 2, Gv, 	Ev},		//42
	{ET_TERM,   NULL,		"cmovae",2, Gv, 	Ev},		//43
	{ET_TERM,   NULL,		"cmove", 2, Gv, 	Ev},		//44
	{ET_TERM,   NULL,		"cmovne",2, Gv, 	Ev},		//45
	{ET_TERM,   NULL,		"cmovbe",2, Gv, 	Ev},		//46
	{ET_TERM,   NULL,		"cmova", 2, Gv, 	Ev},		//47
	{ET_TERM,   NULL,		"cmovs", 2, Gv, 	Ev},		//48
	{ET_TERM,   NULL,		"cmovns",2, Gv, 	Ev},		//49
	{ET_TERM,   NULL,		"cmovp", 2, Gv, 	Ev},		//4a
	{ET_TERM,   NULL,		"cmovnp",2, Gv, 	Ev},		//4b
	{ET_TERM,   NULL,		"cmovl", 2, Gv, 	Ev},		//4c
	{ET_TERM,   NULL,		"cmovnl",2, Gv, 	Ev},		//4d
	{ET_TERM,   NULL,		"cmovle",2, Gv, 	Ev},		//4e
	{ET_TERM,   NULL,		"cmovg", 2, Gv, 	Ev},		//4f
	{ET_JMPPFX, s_OpcodeMapPfx_0x50},						//50
	{ET_JMPPFX, s_OpcodeMapPfx_0x51},						//51
	{ET_JMPPFX, s_OpcodeMapPfx_0x52},						//52
	{ET_JMPPFX, s_OpcodeMapPfx_0x53},						//53
	{ET_JMPPFX, s_OpcodeMapPfx_0x54},						//54
	{ET_JMPPFX, s_OpcodeMapPfx_0x55},						//55
	{ET_JMPPFX, s_OpcodeMapPfx_0x56},						//56
	{ET_JMPPFX, s_OpcodeMapPfx_0x57},						//57
	{ET_JMPPFX, s_OpcodeMapPfx_0x58},						//58
	{ET_JMPPFX, s_OpcodeMapPfx_0x59},						//59
	{ET_JMPPFX, s_OpcodeMapPfx_0x5a},						//5a
	{ET_JMPPFX, s_OpcodeMapPfx_0x5b},						//5b
	{ET_JMPPFX, s_OpcodeMapPfx_0x5c},						//5c
	{ET_JMPPFX, s_OpcodeMapPfx_0x5d},						//5d
	{ET_JMPPFX, s_OpcodeMapPfx_0x5e},						//5e
	{ET_JMPPFX, s_OpcodeMapPfx_0x5f},						//5f
	{ET_JMPPFX, s_OpcodeMapPfx_0x60},						//60
	{ET_JMPPFX, s_OpcodeMapPfx_0x61},						//61
	{ET_JMPPFX, s_OpcodeMapPfx_0x62},						//62
	{ET_JMPPFX, s_OpcodeMapPfx_0x63},						//63
	{ET_JMPPFX, s_OpcodeMapPfx_0x64},						//64
	{ET_JMPPFX, s_OpcodeMapPfx_0x65},						//65
	{ET_JMPPFX, s_OpcodeMapPfx_0x66},						//66
	{ET_JMPPFX, s_OpcodeMapPfx_0x67},						//67
	{ET_JMPPFX, s_OpcodeMapPfx_0x68},						//68
	{ET_JMPPFX, s_OpcodeMapPfx_0x69},						//69
	{ET_JMPPFX, s_OpcodeMapPfx_0x6a},						//6a
	{ET_JMPPFX, s_OpcodeMapPfx_0x6b},						//6b
	{ET_JMPPFX, s_OpcodeMapPfx_0x6c},						//6c
	{ET_JMPPFX, s_OpcodeMapPfx_0x6d},						//6d
	{ET_JMPPFX, s_OpcodeMapPfx_0x6e},						//6e
	{ET_JMPPFX, s_OpcodeMapPfx_0x6f},						//6f
	{ET_JMPPFX, s_OpcodeMapPfx_0x70},						//70
	{ET_JMPGR,  GRP_12, 	"",		0},						//71
	{ET_JMPGR,  GRP_13, 	"",		0},						//72
	{ET_JMPGR,  GRP_14, 	"",		0},						//73
	{ET_JMPPFX, s_OpcodeMapPfx_0x74},						//74
	{ET_JMPPFX, s_OpcodeMapPfx_0x75},						//75
	{ET_JMPPFX, s_OpcodeMapPfx_0x76},						//76
	{ET_TERM, 	NULL, 		"emms", 0},						//77
	{ET_TERM,   NULL,		"vmread",  2, Ey,	Gy},		//78 VMREAD_Exec
	{ET_TERM,   NULL,		"vmwrite", 2, Gy,	Ey},		//79
	{ET_INV},{ET_INV},										//7a..7b
	{ET_JMPPFX, s_OpcodeMapPfx_0x7c},						//7c
	{ET_JMPPFX, s_OpcodeMapPfx_0x7d},						//7d
	{ET_JMPPFX, s_OpcodeMapPfx_0x7e},						//7e
	{ET_JMPPFX, s_OpcodeMapPfx_0x7f},						//7f
	{ET_TERMFOP64, NULL,	"jo",  1, Jz},					//80
	{ET_TERMFOP64,   NULL,	"jno", 1, Jz},					//81
	{ET_TERMFOP64,   NULL,	"jb",  1, Jz},					//82
	{ET_TERMFOP64,   NULL,	"jae", 1, Jz},					//83
	{ET_TERMFOP64,   NULL,	"je",  1, Jz},					//84
	{ET_TERMFOP64,   NULL,	"jne", 1, Jz},					//85
	{ET_TERMFOP64,   NULL,	"jbe", 1, Jz},					//86
	{ET_TERMFOP64,   NULL,	"ja",  1, Jz},					//87
	{ET_TERMFOP64,   NULL,	"js",  1, Jz},					//88
	{ET_TERMFOP64,   NULL,	"jns", 1, Jz},					//89
	{ET_TERMFOP64,   NULL,	"jp",  1, Jz},					//8a
	{ET_TERMFOP64,   NULL,	"jnp", 1, Jz},					//8b
	{ET_TERMFOP64,   NULL,	"jl",  1, Jz},					//8c
	{ET_TERMFOP64,   NULL,	"jge", 1, Jz},					//8d
	{ET_TERMFOP64,   NULL,	"jle", 1, Jz},					//8e
	{ET_TERMFOP64,   NULL,	"jg",  1, Jz},					//8f
	{ET_TERM,   SETO_Exec,  "seto",1, Eb},					//90
	{ET_TERM,   SETNO_Exec, "setno",	1, Eb},				//91
	{ET_TERM,   SETB_Exec,  "setb",		1, Eb},				//92
	{ET_TERM,   SETAE_Exec, "setae",	1, Eb},				//93
	{ET_TERM,   SETE_Exec,  "sete",		1, Eb},				//94
	{ET_TERM,   SETNE_Exec, "setne",	1, Eb},				//95
	{ET_TERM,   SETBE_Exec, "setbe",	1, Eb},				//96
	{ET_TERM,   SETA_Exec,  "seta",	    1, Eb},				//97
	{ET_TERM,   SETS_Exec,  "sets",		1, Eb},				//98
	{ET_TERM,   SETNS_Exec, "setns",	1, Eb},				//99
	{ET_TERM,   SETP_Exec,  "setp",		1, Eb},				//9a
	{ET_TERM,   SETNP_Exec, "setnp",	1, Eb},				//9b
	{ET_TERM,   SETL_Exec,  "setl",		1, Eb},				//9c
	{ET_TERM,   SETNL_Exec, "setge",	1, Eb},				//9d
	{ET_TERM,   SETLE_Exec, "setle",	1, Eb},				//9e
	{ET_TERM,   SETG_Exec,  "setg",		1, Eb},				//9f
	{ET_TERMDOP64,	NULL,	"push", 	1, OP_FS},			//a0 PUSH_Exec
	{ET_TERMDOP64,	NULL,  	"pop", 		1, OP_FS},			//a1
	{ET_TERM,	NULL,		"cpuid",    0},					//a2
	{ET_TERM,	BT_Exec,	"bt",		2, Ev, Gv},			//a3
	{ET_TERM,   SHLD_Exec,	"shld",		3, Ev, Gv, Ib},		//a4
	{ET_TERM,   SHLD_CL_Exec,"shld",	3, Ev, Gv, OP_CL},  //a5
	{ET_INV}, {ET_INV}, 									//a6..a7
	{ET_TERMDOP64, 	NULL,	"push",     1, OP_GS},			//a8 PUSH_Exec
	{ET_TERMDOP64,	NULL,  	"pop", 		1, OP_GS},			//a9
	{ET_TERM,   NULL,		"rsm",		0},					//aa
	{ET_TERMATOM,BTS_Exec,	"bts",		2, Ev, Gv},			//ab
	{ET_TERM,   SHRD_Exec,	"shrd",		3, Ev, Gv, Ib},		//ac
	{ET_TERM,   SHRD_CL_Exec,"shrd",	3, Ev, Gv, OP_CL},  //ad
	{ET_JMPGR,  GRP_15, 	"", 		0},					//ae
	{ET_TERM, 	NULL,		"imul",		2, Gv, Ev},			//af
	{ET_TERMATOM,CMPXCHG_Exec,"cmpxchg",2, Eb, Gb},			//b0 
	{ET_TERMATOM,CMPXCHG_Exec,"cmpxchg",2, Ev, Gv},			//b1
	{ET_TERM, 	NULL,		"lss",		2, Gv, Mp},			//b2
	{ET_TERMATOM,BTR_Exec,	"btr",		2, Ev, Gv},			//b3
	{ET_TERM, 	NULL,		"lfs",		2, Gv, Mp},			//b4
	{ET_TERM, 	NULL,		"lgs",		2, Gv, Mp},			//b5
	{ET_TERM,   NULL,		"movzx",	2, Gv, Eb},			//b6
	{ET_TERM,   NULL,		"movzx",	2, Gv, Ew},			//b7
	{ET_JMPPFX, s_OpcodeMapPfx_0xb8},						//b8
	{ET_INV},												//b9
	{ET_JMPGR, 	GRP_8,		"",			2, Ev, Ib},			//ba
	{ET_TERMATOM, BTC_Exec,	"btc",		2, Ev, Gv},			//bb
	{ET_TERM, 	NULL,		"bsf",		2, Gv, Ev},			//bc
	{ET_TERM, 	NULL,		"bsr",		2, Gv, Ev},			//bd
	{ET_TERM, 	NULL,		"movsx",	2, Gv, Eb},			//be
	{ET_TERM, 	NULL,		"movsx",	2, Gv, Ew},			//bf
	{ET_TERMATOM,XADD_Exec,	"xadd",		2, Eb, Gb},			//c0
	{ET_TERMATOM,XADD_Exec,	"xadd",		2, Ev, Gv},			//c1
	{ET_JMPPFX, s_OpcodeMapPfx_0xc2},						//c2
	{ET_TERM, 	NULL,		"movnti",	2, My, Gy},			//c3 TODO: MOVNTI_Exec
	{ET_JMPPFX, s_OpcodeMapPfx_0xc4},						//c4
	{ET_JMPPFX, s_OpcodeMapPfx_0xc5},						//c5
	{ET_JMPPFX, s_OpcodeMapPfx_0xc6},						//c6
	{ET_JMPGR, 	GRP_9,		"",			0},					//c7
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrAX},		//c8
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrCX},		//c9
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrDX},		//ca
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrBX},		//cb
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrSP},		//cc
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrBP},		//cd
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrSI},		//ce
	{ET_TERM,  	NULL, 		"bswap",	1, OP_xrDI},		//cf
	{ET_JMPPFX, s_OpcodeMapPfx_0xd0},						//d0
	{ET_JMPPFX, s_OpcodeMapPfx_0xd1},						//d1
	{ET_JMPPFX, s_OpcodeMapPfx_0xd2},						//d2
	{ET_JMPPFX, s_OpcodeMapPfx_0xd3},						//d3
	{ET_JMPPFX, s_OpcodeMapPfx_0xd4},						//d4
	{ET_JMPPFX, s_OpcodeMapPfx_0xd5},						//d5
	{ET_JMPPFX, s_OpcodeMapPfx_0xd6},						//d6
	{ET_JMPPFX, s_OpcodeMapPfx_0xd7},						//d7
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//d8
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//d9
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//da
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//db
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//dc
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//dd
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//de
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//df
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e0
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e1
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e2
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e3
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e4
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e5
	{ET_JMPPFX, s_OpcodeMapPfx_0xe6},						//e6
	{ET_JMPPFX, s_OpcodeMapPfx_0xe7},						//e7
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e8
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//e9
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//ea
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//eb
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//ec
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//ed
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//ee
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//ef
	{ET_JMPPFX, s_OpcodeMapPfx_0xf0},						//f0
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f1
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f2
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f3
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f4
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f5
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f6
	{ET_JMPPFX, s_OpcodeMapPfx_0xf7},						//f7
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f8
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//f9
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//fa
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//fb
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//fc
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//fd
	{ET_JMPPFX, s_OpcodeMapPfx_pxxxx_Pq_Qq},				//fe
	{ET_INV}												//ff
};

const OPCODE_ENTRY s_OpcodeMap_1[256] = 
{
////////////////////////////////////////////////////////////////////
//	 Type     Handler		Mnemon. Cnt Op1 	Op2 	Op3	  OpCode
////////////////////////////////////////////////////////////////////
	{ET_TERMATOM, ADD_Exec, "add", 2, Eb,      Gb}, 		//00
	{ET_TERMATOM, ADD_Exec, "add",  2, Ev,     Gv}, 		//01
	{ET_TERM, NULL,			"add",  2, Gb,     Eb}, 		//02
	{ET_TERM, NULL,			"add",  2, Gv,     Ev}, 		//03
	{ET_TERM, NULL, 		"add",  2, OP_AL,  Ib}, 		//04
	{ET_TERM, NULL, 		"add",  2, OP_rAX, Iz}, 		//05
	{ET_TX32, NULL,			"push", 1, OP_ES,  0}, 			//06 PUSH_Exec
	{ET_TX32, NULL, 		"pop",  1, OP_ES,  0}, 			//07
	{ET_TERMATOM,OR_Exec, 	"or",   2, Eb,     Gb}, 		//08
	{ET_TERMATOM,OR_Exec, 	"or",   2, Ev,     Gv}, 		//09
	{ET_TERM, NULL, 		"or",   2, Gb,     Eb}, 		//0a
	{ET_TERM, NULL, 		"or",   2, Gv,     Ev}, 		//0b
	{ET_TERM, NULL, 		"or",   2, OP_AL,  Ib}, 		//0c
	{ET_TERM, NULL, 		"or",   2, OP_rAX, Iz}, 		//0d
	{ET_TX32, NULL, 		"push", 1, OP_CS,  0}, 			//0e PUSH_Exec
	{ET_JMP2B, s_OpcodeMap_2},								//0f 2 byte escape code
	{ET_TERMATOM,ADDC_Exec, "adc", 2, Eb,     Gb}, 			//10
	{ET_TERMATOM,ADDC_Exec, "adc", 2, Ev,     Gv}, 			//11
	{ET_TERM, NULL, 		"adc", 2, Gb,     Eb}, 			//12
	{ET_TERM, NULL, 		"adc", 2, Gv,     Ev}, 			//13
	{ET_TERM, NULL, 		"adc", 2, OP_AL,  Ib}, 			//14
	{ET_TERM, NULL, 		"adc", 2, OP_rAX, Iz}, 			//15
	{ET_TX32, NULL, 		"push", 1, OP_SS,  0}, 		    //16 PUSH_Exec
	{ET_TX32, NULL, 		"pop",  1, OP_SS,  0}, 			//17
	{ET_TERMATOM,SBB_Exec, 	"sbb",  2, Eb,     Gb}, 		//18
	{ET_TERMATOM,SBB_Exec, 	"sbb",  2, Ev,     Gv}, 		//19
	{ET_TERM, NULL, 		"sbb",  2, Gb,     Eb}, 		//1a
	{ET_TERM, NULL, 		"sbb",  2, Gv,     Ev}, 		//1b
	{ET_TERM, NULL, 		"sbb",  2, OP_AL,  Ib}, 		//1c
	{ET_TERM, NULL, 		"sbb",  2, OP_rAX, Iz}, 		//1d
	{ET_TX32, NULL, 		"push", 1, OP_DS,  0}, 		    //1e PUSH_Exec
	{ET_TX32, NULL, 		"pop",  1, OP_DS,  0}, 			//1f
	{ET_TERMATOM,AND_Exec, 	"and",  2, Eb,     Gb}, 		//20
	{ET_TERMATOM,AND_Exec, 	"and",  2, Ev,     Gv}, 		//21
	{ET_TERM, NULL,     	"and",  2, Gb,     Eb}, 		//22
	{ET_TERM, NULL,     	"and",  2, Gv,     Ev}, 		//23
	{ET_TERM, NULL, 	 	"and",  2, OP_AL,  Ib}, 		//24
	{ET_TERM, NULL, 	 	"and",  2, OP_rAX, Iz}, 		//25
	{ET_INV}, 												//26 SEG=ES prefix override
	{ET_TX32, NULL, 		"daa",  0, 0,      0}, 			//27
	{ET_TERMATOM,SUB_Exec, 	"sub",  2, Eb,     Gb}, 		//28
	{ET_TERMATOM,SUB_Exec, 	"sub",  2, Ev,     Gv}, 		//29
	{ET_TERM, NULL, 		"sub",  2, Gb,     Eb}, 		//2a
	{ET_TERM, NULL, 		"sub",  2, Gv,     Ev}, 		//2b
	{ET_TERM, NULL, 		"sub",  2, OP_AL,  Ib}, 		//2c
	{ET_TERM, NULL, 		"sub",  2, OP_rAX, Iz}, 		//2d
	{ET_INV}, 												//2e SEG=CS prefix override
	{ET_TX32, NULL, 		"das",  0, 0,      0}, 			//2f
	{ET_TERMATOM, XOR_Exec, "xor",  2, Eb,     Gb}, 		//30
	{ET_TERMATOM, XOR_Exec, "xor",  2, Ev,     Gv}, 		//31
	{ET_TERM, NULL, 		"xor", 	2, Gb,     Eb}, 		//32
	{ET_TERM, NULL, 		"xor",  2, Gv,     Ev}, 		//33
	{ET_TERM, NULL, 		"xor",  2, OP_AL,  Ib}, 		//34
	{ET_TERM, NULL, 		"xor",  2, OP_rAX, Iz}, 		//35
	{ET_INV}, 												//36 SEG=SS prefix override
	{ET_TX32, NULL, 		"aaa",  0, 0,      0}, 			//37
	{ET_TERM, NULL, 		"cmp",  2, Eb,     Gb}, 		//38
	{ET_TERM, NULL, 		"cmp",  2, Ev,     Gv}, 		//39
	{ET_TERM, NULL, 		"cmp",  2, Gb,     Eb}, 		//3a
	{ET_TERM, NULL, 		"cmp",  2, Gv,     Ev}, 		//3b
	{ET_TERM, NULL, 		"cmp",  2, OP_AL,  Ib}, 		//3c
	{ET_TERM, NULL, 		"cmp",  2, OP_rAX, Iz}, 		//3d
	{ET_INV}, 												//3e SEG=DS prefix override
	{ET_TX32, NULL, 		"aas",  0, 0,      0}, 			//3f
	{ET_TX32, NULL, 		"inc",  1, OP_eAX, 0}, 			//40 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eCX, 0}, 			//41 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eDX, 0}, 			//42 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eBX, 0}, 			//43 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eSP, 0}, 			//44 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eBP, 0}, 			//45 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eSI, 0}, 			//46 i64
	{ET_TX32, NULL, 		"inc",  1, OP_eDI, 0}, 			//47 i64
	{ET_TX32, NULL, 		"dec",  1, OP_eAX, 0}, 			//48 i64
	{ET_TX32, NULL, 		"dec",  1, OP_eCX, 0}, 			//49 i64
	{ET_TX32, NULL, 		"dec",  1, OP_eDX, 0}, 			//4a i64
	{ET_TX32, NULL, 		"dec",  1, OP_eBX, 0}, 			//4b i64
	{ET_TX32, NULL, 		"dec",  1, OP_eSP, 0}, 			//4c i64
	{ET_TX32, NULL, 		"dec",  1, OP_eBP, 0}, 			//4d i64
	{ET_TX32, NULL, 		"dec",  1, OP_eSI, 0}, 			//4e i64
	{ET_TX32, NULL, 		"dec",  1, OP_eDI, 0}, 			//4f i64
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrAX,0}, 		    //50 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrCX,0}, 		    //51 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrDX,0}, 		    //52 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrBX,0}, 		    //53 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrSP,0}, 		    //54 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrBP,0}, 		    //55 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrSI,0}, 		    //56 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"push", 1, OP_xrDI,0}, 		    //57 PUSH_Exec
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrAX,0}, 		    //58
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrCX,0}, 		    //59
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrDX,0}, 		    //5a
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrBX,0}, 		    //5b
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrSP,0}, 		    //5c
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrBP,0}, 		    //5d
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrSI,0}, 		    //5e
	{ET_TERMDOP64, NULL, 	"pop", 1,  OP_xrDI,0}, 		    //5f
	{ET_TX32, NULL,			"pusha",0, 0,      0},			//60 PUSHA_Exec
	{ET_TX32, NULL,			"popa", 0, 0,      0},			//61 POPA_Exec
	{ET_TX32, NULL,			"bound", 2, Gv,    Ma},			//62
	{ET_JMPX86_X64, s_OpcodeMap_0x63, "", 0, 0, 0},		    //63
	{ET_INV},												//64 SEG=FS
	{ET_INV},												//65 SEG=GS
	{ET_INV},												//66 Operand size override
	{ET_INV},												//67 Address size override
	{ET_TERMDOP64, NULL,    "push", 1, Iz,     0}, 		    //68 PUSH_Exec
	{ET_TERM, NULL, 		"imul", 3, Gv, Ev, Iz},			//69
	{ET_TERMDOP64, NULL, 	"push", 1, Ibx,    0}, 		    //6a PUSH_Exec
	{ET_TERM, NULL, 		"imul", 3, Gv, Ev, Ibx},		//6b
	{ET_TERM, NULL,			"ins",  2, Yb,     OP_DX},		//6c INS_Exec
	{ET_TERM, NULL,			"ins",  2, Yz,     OP_DX},		//6d INS_Exec
	{ET_TERM, NULL,			"outs", 2, OP_DX,  Xb},			//6e
	{ET_TERM, NULL,			"outs", 2, OP_DX,  Xz},			//6f
	{ET_TERMFOP64, NULL,    "jo",   1, Jb,     0},			//70
	{ET_TERMFOP64, NULL,    "jno",  1, Jb,     0},			//71
	{ET_TERMFOP64, NULL,    "jb",   1, Jb,     0},			//72
	{ET_TERMFOP64, NULL,    "jae",  1, Jb,     0},			//73
	{ET_TERMFOP64, NULL,    "je",   1, Jb,     0},			//74
	{ET_TERMFOP64, NULL,    "jne",  1, Jb,     0},			//75
	{ET_TERMFOP64, NULL,    "jbe",  1, Jb,     0},			//76
	{ET_TERMFOP64, NULL,    "ja",   1, Jb,     0},			//77
	{ET_TERMFOP64, NULL,    "js",   1, Jb,     0},			//78
	{ET_TERMFOP64, NULL,    "jns",  1, Jb,     0},			//79
	{ET_TERMFOP64, NULL,    "jp",   1, Jb,     0},			//7a
	{ET_TERMFOP64, NULL,    "jnp",  1, Jb,     0},			//7b
	{ET_TERMFOP64, NULL,    "jl",   1, Jb,     0},			//7c
	{ET_TERMFOP64, NULL,    "jge",  1, Jb,     0},			//7d
	{ET_TERMFOP64, NULL,    "jle",  1, Jb,     0},			//7e
	{ET_TERMFOP64, NULL,    "jg",   1, Jb,     0},			//7f
	{ET_JMPGR, GRP_1, 		"", 	2, Eb, 	   Ib},			//80
	{ET_JMPGR, GRP_1, 		"", 	2, Ev, 	   Iz},			//81
	{ET_JMPGR, GRP_1, 		"", 	2, Eb, 	   Ib},			//82 i64
	{ET_JMPGR, GRP_1, 		"", 	2, Ev, 	   Ibx},		//83
	{ET_TERM, NULL, 		"test", 2, Eb, 	   Gb},			//84
	{ET_TERM, NULL, 		"test", 2, Ev, 	   Gv},			//85
	{ET_TERMATOM,XCHG_Exec, "xchg", 2, Eb, 	   Gb},			//86
	{ET_TERMATOM,XCHG_Exec, "xchg", 2, Ev, 	   Gv},			//87
	{ET_TERM, MOV_Exec,     "mov",  2, Eb,     Gb}, 		//88
	{ET_TERM, MOV_Exec,     "mov",  2, Ev,     Gv}, 		//89
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, Gb,     Eb}, 		//8a
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, Gv,     Ev}, 		//8b
	{ET_TERM, MOV_Exec,     "mov",  2, Ev,     Sw}, 		//8c MOV r/m16/m64,Sreg
	{ET_TERM, NULL, 		"lea",  2, Gv,     Mv}, 		//8d
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, Sw,     Ev}, 		//8e MOV Sreg,r/m16/m64
	{ET_JMPGR, GRP_1A, 		"",     0, 0,      0},			//8f
	{ET_TERM, NULL,			"nop",  0, 0,      0},			//90
	{ET_TERM, NULL,			"xchg", 2, OP_xrCX, OP_rAX},	//91
	{ET_TERM, NULL,			"xchg", 2, OP_xrDX, OP_rAX},	//92
	{ET_TERM, NULL,			"xchg", 2, OP_xrBX, OP_rAX},	//93
	{ET_TERM, NULL,			"xchg", 2, OP_xrSP, OP_rAX},	//94
	{ET_TERM, NULL,			"xchg", 2, OP_xrBP, OP_rAX},	//95
	{ET_TERM, NULL,			"xchg", 2, OP_xrSI, OP_rAX},	//96
	{ET_TERM, NULL,			"xchg", 2, OP_xrDI, OP_rAX},	//97
	{ET_TERM, NULL, 		"cwde", 0, 0,      0},			//98
	{ET_TERM, NULL, 		"cdq",  0, 0,      0},			//99
	{ET_TX32, NULL,			"callf", 1, Ap,    0},			//9a CALLF_Exec
	{ET_TERM, NULL,			"wait", 0},						//9b
	{ET_TERMDOP64, NULL,    "pushfq", 1, Fv,    0},			//9c PUSHF_Exec
	{ET_TERMDOP64, NULL,    "popfq", 1,  Fv,    0},			//9d
	{ET_TERM, NULL,         "sahf", 0,  0,     0},			//9e
	{ET_TERM, NULL,         "lahf", 0,  0,     0},			//9f
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_AL,  Ob},			//a0
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_rAX, Ov},			//a1
	{ET_TERM, MOV_Exec, 	"mov",  2, Ob,     OP_AL},		//a2
	{ET_TERM, MOV_Exec, 	"mov",  2, Ov,     OP_rAX},		//a3
	{ET_TERM, MOVS_Exec,    "movs", 2, Yb,     Xb},			//a4
	{ET_TERM, MOVS_Exec,    "movs", 2, Yv,     Xv},			//a5
	{ET_TERM, NULL,         "cmps", 2, Xb,     Yb},			//a6
	{ET_TERM, NULL,         "cmps", 2, Xv,     Yv},			//a7
	{ET_TERM, NULL, 		"test", 2, OP_AL,  Ib},			//a8
	{ET_TERM, NULL, 		"test", 2, OP_rAX, Iz},			//a9
	{ET_TERM, STOS_Exec,    "stos", 1, Yb,     0},			//aa
	{ET_TERM, STOS_Exec,    "stos", 1, Yv,     0},			//ab
	{ET_TERM, NULL, 		"lods", 1, Xb,     0},			//ac
	{ET_TERM, NULL, 		"lods", 1, Xv,     0},			//ad
	{ET_TERM, NULL, 		"scas", 1, Yb,     0},			//ae
	{ET_TERM, NULL, 		"scas", 1, Yv,     0},			//af
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xAL, Ib},			//b0
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xCL, Ib},			//b1
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xDL, Ib},			//b2
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xBL, Ib},			//b3
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xAH, Ib},			//b4
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xCH, Ib},			//b5
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xDH, Ib},			//b6
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xBH, Ib},			//b7
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrAX, Iv},		//b8
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrCX, Iv},		//b9
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrDX, Iv},		//ba
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrBX, Iv},		//bb
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrSP, Iv},		//bc
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrBP, Iv},		//bd
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrSI, Iv},		//be
	{ET_TERM, MOV_2Reg_Exec,"mov",  2, OP_xrDI, Iv},		//bf
	{ET_JMPGR, GRP_2,       "",     2, Eb,      Ib},		//c0
	{ET_JMPGR, GRP_2,       "",     2, Ev,      Ib},		//c1
	{ET_TERMFOP64, NULL,    "ret",  1, Iw,      0},			//c2
	{ET_TERMFOP64, NULL,    "ret",  0, 0,       0},			//c3
	{ET_TERM, NULL,         "les",  2, Gz,      Mp},		//c4
	{ET_TERM, NULL,         "lds",  2, Gz,      Mp},		//c5
	{ET_TERM, MOV_Exec,     "mov",  2, Eb,      Ib},		//c6 - group 11
	{ET_TERM, MOV_Exec,     "mov",  2, Ev,      Iz},		//c7 - group 11
	{ET_TERM, NULL,			"enter",2, Iw,      Ib},		//c8 ENTER_Exec
	{ET_TERMDOP64, NULL,	"leave",0, 0,       0},			//c9
	{ET_TERM, NULL,			"retf", 1, Iw,      0},			//ca
	{ET_TERM, NULL,			"retf", 0, 0,       0},			//cb
	{ET_TERM, NULL, 		"int 3",0, 0,       0}, 		//cc INTR3_Exec
	{ET_TERM, NULL,			"int",  1, Ib,      0},			//cd INTR_Exec
	{ET_TERM, NULL,			"into", 0, 0,       0},			//ce INTRO_Exec
	{ET_TERM, NULL,   		"iretd",0, 0,       0},			//cf
	{ET_JMPGR, GRP_2,       "",     2, Eb,      OP_NUM1},	//d0
	{ET_JMPGR, GRP_2,       "",     2, Ev,      OP_NUM1},	//d1
	{ET_JMPGR, GRP_2,       "",     2, Eb,      OP_CL},		//d2
	{ET_JMPGR, GRP_2,       "",     2, Ev,      OP_CL},		//d3
	{ET_TERM, NULL,         "aam",  1, Ib,      0},			//d4
	{ET_TERM, NULL,         "aad",  1, Ib,      0},			//d5
	{ET_INV},												//d6   //TODO: setalc
	{ET_TERM, NULL,         "xlat", 0, 0,       0},			//d7
	{ET_JMPFPU}, {ET_JMPFPU}, {ET_JMPFPU}, {ET_JMPFPU},		//d8..db
	{ET_JMPFPU}, {ET_JMPFPU}, {ET_JMPFPU}, {ET_JMPFPU},		//dc..df
	{ET_TERMFOP64, NULL,    "loopne", 1, Jb},               //e0
	{ET_TERMFOP64, NULL,    "loope",  1, Jb},				//e1
	{ET_TERMFOP64, NULL,    "loop",   1, Jb},				//e2
	{ET_TERMFOP64, NULL,    "jrcxz", 1,  Jb},				//e3
	{ET_TERM, NULL,			"in",    2, OP_AL,  Ib},		//e4
	{ET_TERM, NULL,			"in",    2, OP_eAX, Ib},		//e5
	{ET_TERM, NULL,			"out",   2, Ib,     OP_AL},		//e6 OUT_Exec
	{ET_TERM, NULL,			"out",   2, Ib,     OP_eAX},	//e7 OUT_Exec
	{ET_TERMFOP64, NULL,	"call",  1, Jz},				//e8 CALL_Exec
	{ET_TERMFOP64, NULL,    "jmp",   1, Jz},				//e9
	{ET_TERM, NULL,         "jmp",   1, Ap},				//ea
	{ET_TERMFOP64, NULL,    "jmp",   1, Jb},				//eb
	{ET_TERM, NULL,			"in",    2, OP_AL,  OP_DX},		//ec
	{ET_TERM, NULL,			"in",    2, OP_eAX, OP_DX},		//ed
	{ET_TERM, OUT_Exec,     "out",   2, OP_DX,  OP_AL},		//ee
	{ET_TERM, OUT_Exec,     "out",   2, OP_DX,  OP_eAX},	//ef
	{ET_INV},												//f0 LOCK prefix
	{ET_INV},												//f1
	{ET_INV},												//f2 REPNE prefix
	{ET_INV},												//f3 REPE prefix
	{ET_TERM, NULL,         "hlt",   0},					//f4
	{ET_TERM, NULL,         "cmc",   0},					//f4
	{ET_JMPGR, GRP_3_1,		"",      0},					//f6
	{ET_JMPGR, GRP_3_2,		"",      0},					//f7
	{ET_TERM, NULL,         "clc",   0},					//f8
	{ET_TERM, NULL,         "stc",   0},					//f9
	{ET_TERM, NULL,         "cli",   0},					//fa
	{ET_TERM, NULL,         "sti",   0},					//fb
	{ET_TERM, NULL,         "cld",   0},					//fc
	{ET_TERM, NULL,         "std",   0},					//fd
	{ET_JMPGR, GRP_4,		"",      0},					//fe
	{ET_JMPGR, GRP_5,		"",      0},					//ff
};

#endif //#ifndef OPCODEMAP_H
