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
#include <dbgeng.h>
#include <crtdbg.h>

#ifndef ASSERT
#define ASSERT _ASSERT
#endif

#include "x64emu.h" 

IDebugClient*		g_Client = NULL;
IDebugControl4*		g_Control = NULL;

bool g_is64bit = true;

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

bool AttachDbg()
{
	HRESULT status;

	if ((status = DebugCreate(__uuidof(IDebugClient),
		(void**)&g_Client)) != S_OK)
	{
		return false;
	}

	if ((status = g_Client->QueryInterface( __uuidof(IDebugControl4),
		(void**)&g_Control)) != S_OK)
	{
		return false;
	}

	if ((status = g_Client->AttachProcess( 0, GetCurrentProcessId(),
		DEBUG_ATTACH_NONINVASIVE | DEBUG_ATTACH_NONINVASIVE_NO_SUSPEND)) != S_OK)
	{
		return false;
	}

	if ((status = g_Control->WaitForEvent(DEBUG_WAIT_DEFAULT,
		INFINITE)) != S_OK)
	{
		return false;
	}

	return true;
}

void DetachDbg()
{
	if( g_Control != NULL )
	{
		g_Control->Release();
		g_Control = NULL;
	}

	if( g_Client != NULL )
	{
		g_Client->EndSession(DEBUG_END_ACTIVE_DETACH);
		g_Client->Release();
		g_Client = NULL;
	}

}

__inline UINT32 __cdecl Ntohl(UINT32 x)
{
	return (x >> 24) | (x << 24) | ((x << 8) & 0x00ff0000) | ((x >> 8) & 0x0000ff00);
}

UINT64 g_Rip = 0;

extern UINT_PTR
GetGuestContextRegisterValue(
	void*			ctx,
	int				registerId);

#define SKIP_3B_OPCODE(b1, b2, b3, dw) \
	{\
		if (((UINT32)(b1) | ((UINT32)(b2) << 8) | ((UINT32)(b3) << 16)) == ((dw)&0xffffff))\
			continue;\
	}

#define SKIP_2B_OPCODE(b1, b2, dw) \
	{\
		if (((UINT32)(b1) | ((UINT32)(b2) << 8)) == ((dw)&0xffff))\
			continue;\
	}

#define SKIP_1B_OPCODE(b1, dw) \
	{\
		if ((UINT32)(b1) == ((dw)&0xff))\
			continue;\
	}

void StrStrip(char* str, size_t len, char ch)
{
	if (0 == len) {
		len = strlen(str);
	}
	size_t slow = 0;
	for (size_t fast = 0; fast < len; fast++)
	{
		if (str[fast] != ch)
		{
			str[slow++] = str[fast];
		}
	}
	str[slow] = 0;
}

void StrStripConsec(char* str, size_t len, char ch)
{
	if (0 == len) {
		len = strlen(str);
	}
	size_t slow = 0;
	bool skip = !!(str[0] == ch);
	for (size_t fast = 0; fast < len; fast++)
	{
		if (str[fast] != ch || !skip)  
		{
			str[slow++] = str[fast];
		} 
		skip = !!(str[fast] == ch);
	}
	str[slow] = 0;
}

void NormalizeDbgMnemonic(char* str)
{
	StrStrip(str,0,'`');
	StrStripConsec(str,0,' ');
	size_t len = strlen(str);
	while (len && (
		str[len-1] == 0xa ||
		str[len-1] == 0xd ||
		str[len-1] == '.' ||
		str[len-1] == ' ' ||
		str[len-1] == ',' ||
		str[len-1] == '!' ||
		str[len-1] == '?'))
	{
		str[--len] = 0;
	}

	char* repe;
	if (0 != (repe = strstr(str,"repe")))
	{
		repe += 3;
		memmove(repe,repe+1,(len-(repe-str))*sizeof(char));
		--len;
	}

	if (strstr(str,"div") || 
		strstr(str,"div") ||
		strstr(str,"mul") ||
		strstr(str,"imul"))
	{
		// strip the first operand as it is implied to be eax and debugger
		// engine uses somewhat random logic to decide whether to display it
		// or not. I've seen "idiv bh", as well as "idiv eax,ebx"
		char* opEnd = strchr(str,',');
		char* opBegin = 0;
		ASSERT(len < opEnd);
		if (opEnd) 
		{
			opBegin = opEnd-1;
			while (opBegin >= str && *opBegin != ' ')
			{
				opBegin--;
			}
			if (opBegin >= str)
			{
				memmove(opBegin+1,opEnd+1,len - (opEnd - str) - 1);
				str[len - (opEnd-opBegin)] = 0;
			}
		}
	}
}

bool StrStripSubStr(
	char* str,
	size_t strLen,
	const char* _subStr)
{
	bool ret = false;
	char* subStr = strstr(str,_subStr);
	if (subStr)
	{
		size_t subStrLen = strlen(_subStr);
		strLen = (0 != strLen) ? strLen : strlen(str);
		memmove(subStr,subStr+subStrLen,strLen-(subStr-str)-subStrLen);
		str[strLen-subStrLen] = 0;
		ret = true;
	}
	return ret;
}

bool SkipOrFixupMnemonic(
	char* dbgStr,
	const char* emuStr)
{
	if (strstr(dbgStr, "fword ptr") ||
		strstr(dbgStr, "xlat") ||
		strstr(dbgStr, "xmm") ||
		strstr(dbgStr, "st("))
	{
		return true;
	}
	char* subStr;
	if (0 != (subStr = strstr(dbgStr,"xchg")))
	{
		char* opBeg = subStr+5;
		_strrev(opBeg);
		char* opEnd = strchr(dbgStr,',');
		if (0 == opEnd) {
			return false;
		}
		*opEnd = 0;
		_strrev(opBeg);
		*opEnd = ',';
		_strrev(opEnd + 1);
		if (!_stricmp(dbgStr,emuStr)) {
			return true;
		}
	}
	size_t len = strlen(dbgStr);
	if (StrStripSubStr(dbgStr,len,"es:") ||
		StrStripSubStr(dbgStr,len,"cs:") ||
		StrStripSubStr(dbgStr,len,"ss:") ||
		StrStripSubStr(dbgStr,len,"ds:") ||
		StrStripSubStr(dbgStr,len,"fs:") ||
		StrStripSubStr(dbgStr,len,"gs:"))
	{
		if (!_stricmp(dbgStr,emuStr)) {
			return true;
		}
	}

	if (StrStripSubStr(dbgStr,len,"hnt ")||
		StrStripSubStr(dbgStr,len,"ht "))
	{
		if (!_stricmp(dbgStr,emuStr)) {
			return true;
		}
	}
	
	char* sub = strchr(dbgStr, ' ');
	if (sub && StrStripSubStr(sub,len-(sub-dbgStr),"00000000"))
	{
		if (!_stricmp(dbgStr,emuStr)) {
			return true;
		}
	}
	
	return false;
}

bool DecodeInstrAndCompare(
	UINT32* opCode,
	char* _prevAsmBuffer = 0,
	bool* opcodeLenError = 0,
	bool* mnemonicError = 0)
{
	HRESULT hr = S_OK;
	char	asmBuffer[1024] = {0};
	ULONG	asmSize = 0;
	ULONG64 endAddr = 0;
	X64_EMULATOR_RUNTIME emuRte;
	char prevAsmBufferSub[1024] = {0};
	char* prevAsmBuffer = _prevAsmBuffer;
	bool ret = true;

	if (!prevAsmBuffer) {
		prevAsmBuffer = prevAsmBufferSub;
	}
	if (opcodeLenError) {
		*opcodeLenError = false;
	}
	if (mnemonicError) {
		*mnemonicError = false;
	}
	

	EmuInitRuntimeStruct(&emuRte,0,GetGuestContextRegisterValue);

	g_Rip = (ULONG64)opCode;

	g_Control->SetEffectiveProcessorType(g_is64bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386);

	hr = g_Control->GetNearInstruction( g_Rip, 1, &endAddr);

	if (S_OK == hr)
	{
		ULONG64 dbgInstrLen = endAddr - g_Rip;
		hr = g_Control->Disassemble( g_Rip, 0,
			asmBuffer, ARRAYSIZE(asmBuffer)-1,
			&asmSize, &endAddr);

		if (S_OK == hr && 
			0 == strchr(asmBuffer, '?'))
		{

			X64_EMULATOR_CTX emu;

			NormalizeDbgMnemonic(asmBuffer);

			EmuInitEmulatorCtxForDecode(&emu,g_Rip,8);
			emu.CpuState.IA32eX64 = g_is64bit;
			EmuDecodeInstruction(&emu);
			if (emu.Instruction.InstructionLen != dbgInstrLen)
			{
				if (!emu.Instruction.Flags.FpuInstruction) // TODO:
				{
					printf("INSTR LEN MISMATCH:  x64Emu %d, dbgeng %d\n\t%s\n",
						emu.Instruction.InstructionLen, dbgInstrLen, asmBuffer);
					if (opcodeLenError) {
						*opcodeLenError = true;
					}
					ret = false;
				}
			}
			else
			{
				const char* mnemonic = EmuGetDecodedMnemonic(&emu);
				NormalizeDbgMnemonic(const_cast<char*>(mnemonic));
				if (_stricmp(asmBuffer,prevAsmBuffer) &&
					_stricmp(asmBuffer,mnemonic))
				{
					strncpy(prevAsmBuffer,asmBuffer,ARRAYSIZE(asmBuffer)-1);
					if (!SkipOrFixupMnemonic(asmBuffer,mnemonic))
					{
						printf("DISASM MISMATCH:\n");
						printf("\tx64 emu: %s\n",mnemonic);
						printf("\tdbg eng: %s\n",prevAsmBuffer);
						if (mnemonicError) {
							*mnemonicError = true;;
						}
						ret = false;
					}
				}
				else
				{
					strncpy(prevAsmBuffer,asmBuffer,ARRAYSIZE(asmBuffer)-1);
				}
			}
		}
	}

	return ret;
}

int GenAndDecodeInstructions(UINT32 step)
{
	HRESULT hr = S_OK;
	int err = 0;
	int mnemonicErr = 0;
	UINT32 it = 0;
	char	prevAsmBuffer[1024] = {0};
	ULONG	asmSize = 0;
	ULONG64 endAddr = 0;
	UINT32	opCode[8] = {0,0,};

	g_Rip = (ULONG64)opCode;

	g_Control->SetEffectiveProcessorType(g_is64bit ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386);

	do
	{
		bool opcodeLenError = false;
		bool itMnemonicError = false;

		opCode[1] -= step;
		opCode[0] = Ntohl( opCode[1] );

		//
		// Skip opcodes for which I think there is a discrepancy between 
		// the debugger and intel's manual
		//
		SKIP_3B_OPCODE(0x0f,0xae,0x30, opCode[0]);
		SKIP_3B_OPCODE(0x0f,0xae,0x70, opCode[0]);
		SKIP_3B_OPCODE(0x0f,0xae,0xb0, opCode[0]);

		SKIP_2B_OPCODE(0x0f, 0x04, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x0a, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x0c, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x0e, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x0f, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x24, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x25, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x26, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x27, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x36, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x39, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x3b, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x3c, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x3d, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x3e, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x3f, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x7a, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0x7b, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0xb8, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0xa6, opCode[0]);
		SKIP_2B_OPCODE(0x0f, 0xa7, opCode[0]);

		if (g_is64bit)
		{
			SKIP_1B_OPCODE(0xc5,opCode[0]);
		}

		DecodeInstrAndCompare(opCode,prevAsmBuffer,&opcodeLenError,&itMnemonicError);
		if (opcodeLenError) {
			++err;
		}
		if (itMnemonicError) {
			++mnemonicErr;
		}
	
		++it;
	} 
	while (opCode[1] > (step - 1));

	printf("Instructions scanned: %d\n", it);
	printf("Opcode Len ERRORS:    %d\n", err);
	printf("Opcode Mnemon ERRORS: %d\n", mnemonicErr);

	return err;
}

void Usage()
{
	printf("Usage:\n");
	printf("\ttestemudecode64 [-d <hex opcode stream>] [-i386]\n\n");
	printf("where:\n");
	printf("\t-d When present the specified opcode stream will be decoded; if -d is\n"
		   "\t   not present, then the built-in sample of randomized instruction \n"
		   "\t   stream is tested.\n");
	printf("\t-i386 The instruction stream is treated as 32-bit opcode\n");
	printf("\nExamples: \n");
	printf("\ttestemudecode64 -d c70425b000feff00000000\n");
	printf("\ttestemudecode64 -d c70425b000feff00000000 -i386\n");
	printf("\ttestemudecode64\n");
	printf("\ttestemudecode64 -i386\n");

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
	printf("\tOperand count: %d\n", emu.Instruction.Flags.OperandCount);
	printf("\tDefault operand size: %d\n", emu.Instruction.OperandSize);
	for (UINT32 i = 0; i < emu.Instruction.Flags.OperandCount; i++)
	{
		PrintOperand(emu,i);
	}
}

bool DecodeInstructionStream(
	const UINT8* pInstr, 
	size_t streamLen,
	const wchar_t* _pCmpMnemonic = 0)
{
	X64_EMULATOR_CTX emu;
	X64_EMULATOR_RUNTIME emuRte;
	struct RUNTIME_CTX {
		size_t StreamLen;
		UINT64* RipPtr;
	};
	EmuInitRuntimeStruct(&emuRte,0,GetGuestContextRegisterValue);
	EmuInitEmulatorCtx(&emu, &emuRte, streamLen);
	g_Rip = (UINT64)pInstr;
	while (g_Rip < (UINT_PTR)pInstr + streamLen)
	{
		emu.CpuState.IA32eX64 = g_is64bit;
		if (!EmuDecodeInstruction(&emu))
		{
			ASSERT(false);
			printf("ERROR: failed to decode instruction at offset %d\n", streamLen);
			return false;
		}
		PrintDecodedInstruction(emu);
		if (_pCmpMnemonic)
		{
			size_t mnemonicLen = wcslen(_pCmpMnemonic);
			char* pCmpMnemonic = (char*)malloc(mnemonicLen+1);
			for (size_t i = 0; i < mnemonicLen; i++) {
				pCmpMnemonic[i] = (char)_pCmpMnemonic[i];
			}
			pCmpMnemonic[mnemonicLen]=0;
			NormalizeDbgMnemonic(pCmpMnemonic);
			if (0 != _stricmp(pCmpMnemonic,EmuGetDecodedMnemonic(&emu)))
			{
				printf("DISASM MISMATCH:\n");
				printf("\tx64 emu:  %s\n",EmuGetDecodedMnemonic(&emu));
				printf("\texpected: %s\n",pCmpMnemonic);
				free(pCmpMnemonic);
				return false;
			}
			free(pCmpMnemonic);
		}
		g_Rip += emu.Instruction.InstructionLen;
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

bool TestMove_8b04850000feff()
{
	UINT8 opCode[256] = {0x8b,0x04,0x85,0x00,0x00,0xfe,0xff,0,0};
	return DecodeInstrAndCompare((UINT32*)opCode);
}

int __cdecl
wmain(int argc, wchar_t* argv[])
{
	size_t err = 0;
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
		else
		{
			Usage();
			return -1;
		}
	}

	if (0 != pInstr) 
	{
		DecodeInstructionStream(pInstr, instrLen / 2);
		free(pInstr);
	}
	else if (AttachDbg())
	{
		TestMove_8b04850000feff();
		err += GenAndDecodeInstructions(0x1000);
		DetachDbg();
	}

	return err;
}
