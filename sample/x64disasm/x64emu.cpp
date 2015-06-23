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
#include "opcodemap.h"
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

extern UINT_PTR g_Rip;

UINT_PTR
GetGuestContextRegisterValue(
	void*			ctx,
	int				registerId)
{
	UNREFERENCED_PARAMETER(ctx);
	return (RIP_GUEST_ID == registerId) ? g_Rip : 0;
}
