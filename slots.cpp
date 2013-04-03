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

#include <stdlib.h>
#include <time.h>
#ifndef WIN32
#include <string.h>
#endif
#include "logger.h"
#include "sockets.h" /* SOCKET */
#include "vncauth.h" /* CHALLENGESIZE */
#include "repeater.h"
#include "slots.h"
#include <sstream>
#include <assert.h>

repeaterslot * Slots;
unsigned int slotCount;
unsigned int max_slots;

unsigned char challenge_key[CHALLENGESIZE];

mutex_t mutex_slots;

/*******************************************************************************
 *
 * Do NOT touch my slots without asking!
 *
 ******************************************************************************/
int LockSlots(const char * function_name)
{
	const int mutex_result = mutex_lock( &mutex_slots );
	if( mutex_result != 0 ) {
		logp(ERROR, "Failed to lock mutex in %s with error %d.", function_name, mutex_result);
		return -1;
	}
	return 0;
}

/*******************************************************************************
 *
 * Alright... You may touch my slots...
 *
 ******************************************************************************/
int UnlockSlots(const char * function_name)
{
	const int mutex_result = mutex_unlock( &mutex_slots );
	if (mutex_result != 0) {
		logp(ERROR, "Failed to unlock mutex in %s with error %d.", function_name, mutex_result);
		/* Damn! If we can not unlock he mutex we are in trouble! */
		notstopped = 0;
		return -1;
	}
	return 0;
}

repeaterslot * NewSlot( void )
{
	repeaterslot * new_slot = (repeaterslot *)malloc( sizeof(repeaterslot) );
	if (new_slot == NULL) log(ERROR, "Not enough memory to allocate a new slot.");
  memset(new_slot, 0, sizeof(repeaterslot));
	return new_slot;
}

void InitializeSlots( unsigned int max )
{
	Slots = NULL;
	slotCount = 0;
	max_slots = max;
	vncRandomBytes( challenge_key );
}

repeaterslot * DisposeSlot(repeaterslot *slot)
{
	if (slot->server != INVALID_SOCKET) {
		if (socket_close(slot->server) == -1) {
			logp(ERROR, "Server socket failed to close. Socket error = %d.", errno);
		}
		else {
			log(DEBUG, "Server socket has been closed.");
		}
	}

	if (slot->viewer != INVALID_SOCKET) {
		if (socket_close(slot->viewer) == -1) {
			logp(ERROR, "Viewer socket failed to close. Socket error = %d.", errno);
		}
		else {
			log(DEBUG, "Viewer socket has been closed.");
		}
	}
	repeaterslot *next = slot->next;
	if (slot->prev == NULL)
  {
		Slots = next;
    if(next) next->prev = NULL;
  }
	else
  {
		slot->prev->next = next;
    if(next) next->prev = slot->prev;
  }
  if (slot->server_init_msg) { free(slot->server_init_msg); slot->server_init_msg = NULL; }
	free(slot);
	slotCount--;
	logp(DEBUG, "Slot has been freed. Allocated repeater slots: %d.", slotCount);
  return next;
}

void FreeSlots( void )
{
	if( LockSlots("FreeSlots()") != 0 )
		return;

	for(repeaterslot *current = Slots; current != NULL;) {
    current = DisposeSlot(current);
	}
  assert(slotCount == 0);
	UnlockSlots("FreeSlots()");
}

repeaterslot * AddSlot(repeaterslot *slot)
{
	if (LockSlots("AddSlot()") != 0)
		return NULL;

	if (slot->server == INVALID_SOCKET && slot->viewer == INVALID_SOCKET) {
		log(ERROR, "Trying to allocate an empty slot.");
		UnlockSlots("AddSlot()");
		return NULL;
	} else if (slot->next != NULL) {
		log(ERROR, "Memory allocation problem detected while trying to add a slot.");
		UnlockSlots("AddSlot()");
		return NULL;
	} else if (max_slots > 0 && max_slots == slotCount) {
		log(ERROR, "All the slots are in use.");
		UnlockSlots("AddSlot()");
		return NULL;
	}

	repeaterslot *current;
	if (Slots == NULL) {
		/* There is no slot in use */
		Slots = NewSlot();
		if( Slots != NULL ) {
			memcpy(Slots, slot, sizeof(repeaterslot));
			Slots->prev = Slots->next = NULL;
			slotCount++;
		}
    current = Slots;
		log(DEBUG, "Create first new slot");
	} else {
		current = FindSlotByChallenge( slot->challenge );
		if (current == NULL) {
			/* This is a new slot, but slots already exist */
      Slots->prev = slot;
			slot->next = Slots;
			Slots = slot;
			slotCount++;
  		log(DEBUG, "Create new slot");
      current = Slots;
		} else if (current->server == INVALID_SOCKET && slot->server != INVALID_SOCKET) {
			current->server = slot->server;
			current->code = slot->code;
  		log(DEBUG, "update server_socket in the slot");
		} else if (current->viewer == INVALID_SOCKET && slot->viewer != INVALID_SOCKET) {
			current->viewer = slot->viewer;
  		log(DEBUG, "update viewer_socket in the slot");
		}
	}
	UnlockSlots("AddSlot()");
	logp(DEBUG, "Allocated repeater slots: %d.", slotCount);
	return current;
}

/* Free any slot if the connection has been reseted by peer */
void CleanupSlots( void )
{
	struct timeval tm;
	tm.tv_sec=0;
	tm.tv_usec=50;
	BYTE buf=0;

	if (LockSlots("CleanupSlots()") != 0)
		return;

	for(repeaterslot *current = Slots; current != NULL;) {
    if (current->viewer == INVALID_SOCKET) {
      if (socket_read_exact(current->server, (char *)&buf, 1, &tm, MSG_PEEK) == -1)
				logp(INFO, "Closing server (socket=%d) connection due to socket error number %d.", current->server, errno);
      else {
        current = current->next;
				continue;
      }
    } else if (current->server == INVALID_SOCKET) {
      if (socket_read_exact(current->viewer, (char *)&buf, 1, &tm, MSG_PEEK) == -1)
				logp(INFO, "Closing viewer (socket=%d) connection due to socket error number %d.", current->viewer, errno);
      else {
        current = current->next;
				continue;
      }
    }
    current = DisposeSlot(current);
		logp(DEBUG, "Slot has been freed. Allocated repeater slots: %d.", slotCount);
	}
	UnlockSlots("CleanupSlots()");
}

repeaterslot * FindSlotByChallenge(unsigned char * challenge)
{
	if( LockSlots("FindSlotByChallenge()") != 0 )
		return NULL;

	log(DEBUG, "Trying to find a slot for a challenge ID.");
	for(repeaterslot *current = Slots; current != NULL; current = current->next) {
		if( memcmp(challenge, current->challenge, CHALLENGESIZE) == 0 ) {
			log(DEBUG, "Found a slot assigned to the given challenge ID.");
			UnlockSlots("FindSlotByChallenge()");
			return current;
		}
	}
	log(DEBUG, "Failed to find an assigned slot for the given Challenge ID. Probably a new ID.");
	UnlockSlots("FindSlotByChallenge()");
	return NULL;
}

void FreeSlot(repeaterslot *slot)
{
	if( LockSlots("FreeSlot()") != 0 )
		return;

	logp(DEBUG, "Trying to free slot... (Allocated repeater slots: %d)", slotCount);
	for(repeaterslot *current = Slots; current != NULL; current = current->next) {
		if ( memcmp(current->challenge, slot->challenge, CHALLENGESIZE) == 0 ) {
      DisposeSlot(current);
			UnlockSlots("FreeSlot()");
			return;
		}
	}
	log(FATAL, "Called FreeSlot() but no slot was found.");
	UnlockSlots("FreeSlot()");
	logp(DEBUG, "Allocated repeater slots: %d.", slotCount);
}

void ListSlots( void )
{
  struct sockaddr_in  addr;
  socklen_t addrlen = sizeof(addr);
	if( LockSlots("ListSlots()") != 0 )
		return;

	log(DEBUG, "Listing current connections.");
	for(repeaterslot *current = Slots; current != NULL; current = current->next) {
	  if (current->server != INVALID_SOCKET) {
      if( getpeername( (int)current->server, (struct sockaddr *)&addr, &addrlen) == 0 )
        logp(DEBUG, "server connected with id=%d from %s", current->code, inet_ntoa(addr.sin_addr));
      else 
        logp(ERROR, "getpeername() failed: %d", errno);

      if (current->viewer != INVALID_SOCKET)
        if( getpeername( (int)current->viewer, (struct sockaddr *)&addr, &addrlen) == 0 )
          logp(DEBUG, "with viewer from %s", inet_ntoa(addr.sin_addr));
        else 
          logp(ERROR, "getpeername() failed: %d", errno);
      else 
        log(DEBUG, "without viewer");
    }
	}
	log(DEBUG, "End of Listing");
	UnlockSlots("ListSlots()");
}

std::string DumpSlots( void ) 
{
  std::ostringstream oss (std::ostringstream::out);
  struct sockaddr_in  addr;
  socklen_t addrlen = sizeof(addr);
	if( LockSlots("DumpSlots()") != 0 )
		return std::string();

  oss << "[\n";
	for(repeaterslot *current = Slots; current != NULL; current = current->next) {
    oss << "{";
    oss << "\"Id\": " << '"' << current->code << '"';
	  if( current->server != INVALID_SOCKET ) {
      if( getpeername( (int)current->server, (struct sockaddr *)&addr, &addrlen) == 0 ) {
        oss << ", \"addr\": " << '"' << inet_ntoa(addr.sin_addr) << '"';
      } else {
        log(ERROR,"getpeername() failed");
      }
      if ( current->viewer != INVALID_SOCKET ) {
        if( getpeername( (int)current->viewer, (struct sockaddr *)&addr, &addrlen) == 0 ) {
          oss << ", \"viewer_addr\": " << '"' << inet_ntoa(addr.sin_addr) << '"';
        } else {
          log(ERROR, "getpeername() failed");
        }
      }
    }
    oss << "}\n";
	}
	UnlockSlots("DumpSlots()");
  oss << "]\n";
	log(DEBUG, "Dump current connections.");
  return oss.str();
}

