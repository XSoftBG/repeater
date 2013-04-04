/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2010 Juan Pedro Gonzalez. All Rights Reserved.
//
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
/////////////////////////////////////////////////////////////////////////////

#ifndef _SLOTS_H
#define _SLOTS_H

#include <string>

typedef struct _repeaterslot
{
	SOCKET   server;
	SOCKET   viewer;
	uint32_t timestamp;
	uint32_t code;
	unsigned char challenge[CHALLENGESIZE];

	struct _repeaterslot * next;
	struct _repeaterslot * prev;
} repeaterslot;

extern unsigned char  challenge_key[CHALLENGESIZE];

void InitializeSlots(unsigned int max);
void FinalizeSlots();
repeaterslot * AddSlot(SOCKET server_socket, SOCKET viewer_socket, unsigned char *challenge, uint32_t code);
void FreeSlot(repeaterslot *slot);
void FreeSlots();
void CleanupSlots();
void ListSlots();
std::string DumpSlots();
repeaterslot * FindSlotByChallenge(unsigned char * challenge);

#endif
