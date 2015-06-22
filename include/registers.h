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

#ifndef REGISTERS_H
#define REGISTERS_H

/*
 * Basically offsets from VMXRoot exit stack pointer.
 *
 * In ID order for exitQualification register IDs.
 */
#define RAX_GUEST_ID (0)
#define RCX_GUEST_ID (1)
#define RDX_GUEST_ID (2)
#define RBX_GUEST_ID (3)
// RSP - we leave a un-used register save on the stack for RSP
#define RSP_GUEST_ID (4)
#define RBP_GUEST_ID (5)
#define RSI_GUEST_ID (6)
#define RDI_GUEST_ID (7)
#define R8_GUEST_ID (8)
#define R9_GUEST_ID (9)
#define R10_GUEST_ID (10)
#define R11_GUEST_ID (11)
#define R12_GUEST_ID (12)
#define R13_GUEST_ID (13)
#define R14_GUEST_ID (14)
#define R15_GUEST_ID (15)
/*
 * These are actually saved in the VMCS (along with RSP above)
 */
#define RIP_GUEST_ID (16)
#define CR0_GUEST_ID (17)
#define CR3_GUEST_ID (18)
#define CR4_GUEST_ID (19)
// CR8 is not saved in the VMCS, use the TPR access page or the actual
// CR8 register to determine its value.
#define RFLAGS_GUEST_ID (20)

/*
 * These are also saved in the VMCS and return/set the segment base
 */
#define ES_GUEST_ID (21)
#define CS_GUEST_ID (22)
#define SS_GUEST_ID (23)
#define DS_GUEST_ID (24)
#define FS_GUEST_ID (25)
#define GS_GUEST_ID (26)

#define DR0_GUEST_ID (27)
#define DR1_GUEST_ID (28)
#define DR2_GUEST_ID (29)
#define DR3_GUEST_ID (30)
#define DR6_GUEST_ID (31)
#define DR7_GUEST_ID (32)

/*
 * Called in vmxroot context only.
 *
 * These routines operate on the current VCPU (vmcs) only
 */

UINT_PTR
GetGuestContextRegisterValue(
	int				registerId);

void
SetGuestContextRegisterValue(
	int				registerId,
	UINT_PTR			registerValue);

#define RFLAGS_DF_BIT			(1 << 10)
#define RFLAGS_IF_BIT			(1 << 9)
#define RFLAGS_IOPL_BITS		(0x3 << 12)
#define RFLAGS_TF_BIT			(1 << 8)
#define RFLAGS_RF_BIT			(1 << 16)
#define RFLAGS_VM_BIT			(1 << 17)
#define RFLAGS_IOPL_MASK		0x1800

#define CR0_PG_BIT			(1 << 31)

#endif
