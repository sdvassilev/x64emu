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

#ifndef _RAISE_PANIC_H
#define _RAISE_PANIC_H

#ifndef SUPERCELL
/*
* panic stop codes follow.
*/
#define PANIC_DEBUG_BREAK		0
#define PANIC_INVALID_PORT_EXIT		1
#define PANIC_VA_SPACE_EXHAUSTED	2
#define PANIC_EPT_CONFIGURATION		3
#define PANIC_DOMAIN0_INIT		4
#define PANIC_DOMAIN0_SIPI		5
#define PANIC_TEST_PANIC		6
#define PANIC_UNMAP_INVALID_VA		7
#define PANIC_UNEXPECTED_INTERRUPT	8
#define PANIC_INVALID_PAGE_STATE	9
#define PANIC_DSM_ERROR			10
#define PANIC_VMRESUME_FAIL		11
#define PANIC_PA_LOOKUP_FAIL		12
#define PANIC_PAGETABLE_CORRUPT		13
#define PANIC_VMXOFF_FAILED		14
#define PANIC_RINGBUFFER_CTX_MISMATCH	15
#define PANIC_STACKTHAW_FAILED		16
#define PANIC_RINGBUFFER_LOST		17
#define PANIC_DSM_FAILED_EPTVIOLATION	18
#define PANIC_NO_EVENTCALLBACKS		19
#define PANIC_VMCS_LOAD_FAILED		20
#define PANIC_VCPU_CONTEXT_LIST_CORRUPT	21
#define PANIC_NO_IO_READ_BUFFER		22
#define PANIC_SEND_PORT_IO_FAILED	23
#define PANIC_DOMAIN_NOT_FOUND		24
#define PANIC_IO_HANDLER_NOT_FOUND	25
#define PANIC_INTERRUPT_QUEUE_FAILED	26
#define PANIC_UNEXPECTED_DELIVERY_TYPE	27
#define PANIC_UNEXPECTED_APIC_ACCESS	29
#define PANIC_EXCEPTION_DELIVERY_FAILED	30
#define PANIC_NO_TRANSPORT		31
#define PANIC_UNKNOWN_ADDRESS_TYPE	32
#define PANIC_MMIOCONTEXT_MISMATCH	33
#define PANIC_IOCONTEXT_MISMATCH	34
#define PANIC_NO_SCI_VECTOR		35
#define PANIC_GUEST_INTERRUPTS_MASKED	36
#define PANIC_DOMAIN0_TRIPLEFAULT	37
#define PANIC_INVALID_VECTOR		38
#define PANIC_NO_PAT			39
#define PANIC_UNITY_EPT_VIOLATION	40
#define PANIC_X64EMU_ERROR		41	
#define PANIC_X64EMU_INVALID_CONTEXT	42	
#define PANIC_APIC_EOIQUEUE_ERROR	43
#define PANIC_FREEING_MAPPED_MDL	44
#define PANIC_BUILDING_MDL_FROM_GUEST	45
#define PANIC_UNMAPPING_VMXROOT_MDL	46
#define PANIC_UNMAPPED_MDL		47
#define PANIC_MAPPING_VMXROOT_MDL	48
#define PANIC_INVALID_LENGTH		49
#define PANIC_NULL_ADDRESS		50
#define PANIC_INVALID_PARAMETER		51
#define PANIC_INVALID_MTRR_INDEX	52
/* API called when not in vmxroot */
#define PANIC_INVALID_CALL_CONTEXT	53
/* unhandled GP fault (exception flags not clear on fault) */
#define PANIC_UNEXPECTED_GP_FAULT	54
/* error in faulting instruction decode in GP fault handler */
#define PANIC_DECODE_ERROR_IN_GP_FAULT	55
#define PANIC_PAGEPOOL_CORRUPT		56
#define PANIC_INTERRUPT_CONTEXT_CORRUPT	57
#define PANIC_EXCEPTION_ALREADY_PENDING 58
#define PANIC_UNEXPECTED_REGISTER_ID	59
#define PANIC_PAGEPOOL_ALLOC_FAILED	60
#endif

struct PANIC_PARAMS
{
	__inline PANIC_PARAMS(
		struct _CPU_CONTEXT* _pCPUContext,
		INT32 _panicCode,
		const char* _pMessage = "",
		INT64 p1 = 0, 
		INT64 p2 = 0,
		INT64 p3 = 0,
		INT64 p4 = 0)
	{
		this->pCPUContext = _pCPUContext;
		this->PanicCode = _panicCode;
		this->pMessage = _pMessage;
		this->P1 = p1;
		this->P2 = p2;
		this->P3 = p3;
		this->P4 = p4;
	}
	__inline PANIC_PARAMS(
		INT32 _panicCode,
		const char* _pMessage = "",
		INT64 p1 = 0, 
		INT64 p2 = 0,
		INT64 p3 = 0,
		INT64 p4 = 0)
	{
		this->pCPUContext = 0;
		this->PanicCode = _panicCode;
		this->pMessage = _pMessage;
		this->P1 = p1;
		this->P2 = p2;
		this->P3 = p3;
		this->P4 = p4;
	}
	struct _CPU_CONTEXT* pCPUContext;
	INT32 PanicCode;
	const char* pMessage;
	INT64 P1; 
	INT64 P2; 
	INT64 P3; 
	INT64 P4;
};

typedef void (*PanicHandlerT)(
	const char* pFile,
	UINT32 lineNo,
	const PANIC_PARAMS& params
	);

#define RAISE_PANIC(MyPanicHandler,_params_) \
	MyPanicHandler( \
	__FILE__, \
	__LINE__, \
	PANIC_PARAMS _params_)

#endif //#ifndef _RAISE_PANIC_H
