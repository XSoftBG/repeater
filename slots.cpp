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
#include <ctype.h>
#ifndef WIN32
#include <string.h>
#endif
#include "logger.h"
#include "sockets.h" /* SOCKET */
#include "rfb.h"     /* CARD8 */
#include "vncauth.h" /* CHALLENGESIZE */
#include "repeater.h"
#include "slots.h"
#include <errno.h>
#include <stdio.h>
#include <iostream>
#include <sstream>



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
	if( mutex_result != 0 ) {
		logp(ERROR, "Failed to unlock mutex in %s with error %d.", function_name, mutex_result);
		/* Damn! If we can not unlock he mutex we are in trouble! */
		notstopped = 0;
		return -1;
	}
	return 0;
}


int ParseID(char * code)
{
	unsigned int i;
	int retVal;

	for( i=0; i<strlen( code ); i++ ) {
		if( !isdigit( code[i] ) ) {
			log(ERROR, "The repeater ID must be numeric.\n");
			return 0;
		}
	}

	retVal = strtol(code, NULL, 10);
	if( retVal <= 0 ) {
		log(ERROR, "The repeater ID should be a positive integer.\n");
		return 0;
	} else if( retVal > 99999999 ) {
		/* VNC password only allows for 8 characters, so 99999999 is the biggest number */
		log(ERROR, "The repeater ID is too big.\n");
		return 0;
	}

	return retVal;
}

repeaterslot * NewSlot( void )
{
	repeaterslot * new_slot = ((repeaterslot *)malloc( sizeof( repeaterslot ) ) );
	if( new_slot == NULL )
		log(ERROR, "Not enough memory to allocate a new slot.\n");
	return new_slot;
}


void InitializeSlots( unsigned int max )
{
	Slots = NULL;
	//nextSlot = NULL;
	slotCount = 0;
	max_slots = max;
	vncRandomBytes( challenge_key );
}


void FreeSlots( void )
{
	repeaterslot *current;

	if( LockSlots("FreeSlots()") != 0 )
		return;

	current = Slots;
	while( current != NULL )
	{
		/* Close server connection */
		if( current->server != INVALID_SOCKET ) {
			shutdown( current->server, 2);
			if( socket_close( current->server ) == -1 ) {
				logp(ERROR, "Server socket failed to close. Socket error = %d.\n", errno);
			}
			else {
				log(DEBUG, "Server socket has been closed.\n");
			}
		}

		/* Close viewer connection */
		if( current->viewer != INVALID_SOCKET ) {
			shutdown( current->viewer, 2);
			if( socket_close( current->viewer ) == -1 ) {
				logp(ERROR, "Viewer socket failed to close. Socket error = %d.\n", errno);
			}
			else {
				log(DEBUG, "Viewer socket has been closed.\n");
			}
		}

		Slots = current->next;
		free( current );
		slotCount--;

		current = Slots;
	}

	/* Check */
	if( slotCount != 0 ) {
		log(FATAL, "Failed to free repeater slots.\n");
		slotCount = 0;
	}

	UnlockSlots("FreeSlots()");
}


repeaterslot * AddSlot(repeaterslot *slot)
{
	repeaterslot *current;
	
	if( LockSlots("AddSlot()") != 0 )
		return NULL;

	if( ( slot->server == INVALID_SOCKET ) && ( slot->viewer == INVALID_SOCKET ) ) {
		log(ERROR, "Trying to allocate an empty slot.\n");
		UnlockSlots("AddSlot()");
		return NULL;
	} else if( slot->next != NULL ) {
		log(ERROR, "Memory allocation problem detected while trying to add a slot.\n");
		UnlockSlots("AddSlot()");
		return NULL;
	} else if( ( max_slots > 0 ) && (max_slots == slotCount) ) {
		log(ERROR, "All the slots are in use.\n");
		UnlockSlots("AddSlot()");
		return NULL;
	}

	if( Slots == NULL ) {
		/* There is no slot in use */
		Slots = NewSlot();
		if( Slots != NULL ) {
			memcpy(Slots, slot, sizeof(repeaterslot) );
			Slots->next = NULL;
			slotCount++;
		}
		UnlockSlots("AddSlot()");
		logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
		return Slots;
	} else {
		current = FindSlotByChallenge( slot->challenge );
		if( current == NULL ) {
			/* This is a new slot, but slots already exist */
			slot->next = Slots;
			Slots = slot;
			slotCount++;
			UnlockSlots("AddSlot()");
			logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
			return Slots;
		} else if( current->server == INVALID_SOCKET ) {
			current->server = slot->server;
			current->code = slot->code;
		} else if( current->viewer == INVALID_SOCKET ) {
			current->viewer = slot->viewer;
		} else {
			UnlockSlots("AddSlot()");
			logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
			return NULL;
		}

		UnlockSlots("AddSlot()");
		logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
		return current;
	}

	/* Unrecheable code, but just in case... */
	UnlockSlots("AddSlot()");
	logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
}

/* Free any slot if the connection has been reseted by peer */
void CleanupSlots( void )
{
	repeaterslot *current;
	repeaterslot * previous;
	repeaterslot *next;
	fd_set read_fds;
	struct timeval tm;
	BYTE buf;
	int num_bytes;

	if( LockSlots("CleanupSlots()") != 0 )
		return;

	current = Slots;
	previous = NULL;
	tm.tv_sec=0;
	tm.tv_usec=50;

	while( current != NULL )
	{
		if( ( current->viewer == INVALID_SOCKET ) || ( current->server == INVALID_SOCKET ) ) {
			FD_ZERO( &read_fds );
			
			if( current->viewer == INVALID_SOCKET ) {
				/* check the server connection */
				FD_SET( current->server , &read_fds );
				if( select( current->server + 1, &read_fds, NULL, NULL, &tm) == 0 ) {
					/* Timed out */
					previous = current;
					current = current->next;
					continue;
				}
	
				if( ( num_bytes = recv( current->server, (char *)&buf, 1, MSG_PEEK) ) < 0 ) {
#ifdef WIN32
					errno = WSAGetLastError();
#endif
					if( errno == ECONNRESET ) {
						logp(INFO, "Connection closed by server (socket=%d).\n", current->server );
					} else {
						logp(INFO, "Closing server (socket=%d) connection due to socket error number %d.\n", current->server, errno);
					}
				} else if( num_bytes == 0 ){
						logp(INFO, "Connection closed by server (socket=%d).\n", current->server );
				} else {
					/* Server is alive */
					previous = current;
					current = current->next;
					continue;
				}
			} else if( current->server == INVALID_SOCKET ) {
				/* Check the viewer connection */
				FD_SET( current->viewer , &read_fds );
				if( select( current->viewer + 1, &read_fds, NULL, NULL, &tm) == 0 ) {
					/* Timed out */
					previous = current;
					current = current->next;
					continue;
				}

				if( ( num_bytes = recv( current->viewer, (char *)&buf, 1, MSG_PEEK) ) < 0 ) {
#ifdef WIN32
					errno = WSAGetLastError();
#endif
					if( errno == ECONNRESET ) {
						logp(INFO, "Connection closed by viewer (socket=%d).\n", current->viewer );
					} else {
						logp(INFO, "Closing viewer (socket=%d) connection due to socket error number %d.\n", current->viewer, errno);
					}
				} else if( num_bytes == 0 ){
						logp(INFO, "Connection closed by viewer (socket=%d).\n", current->viewer );
				} else {
					/* Server is alive */
					previous = current;
					current = current->next;
					continue;
				}
			}

			// Free slot.
			next = current->next;
			if( previous == NULL )
				Slots = current->next;
			else
				previous->next = current->next;

			socket_close( current->viewer );
			free( current );
			current = next;
			slotCount--;
			logp(DEBUG, "Slot has been freed. Allocated repeater slots: %d.\n", slotCount);
		} else {
			previous = current;
			current = current->next;
			continue;
		}
	}

	UnlockSlots("CleanupSlots()");
}


repeaterslot * FindSlotByChallenge(unsigned char * challenge)
{
	repeaterslot *current;

	if( LockSlots("FindSlotByChallenge()") != 0 )
		return NULL;

	current = Slots;
	log(DEBUG, "Trying to find a slot for a challenge ID.\n");
	while( current != NULL)
	{
		// ERROR: Getting exception here!!!
		if( memcmp(challenge, current->challenge, CHALLENGESIZE) == 0 ) {
			log(DEBUG, "Found a slot assigned to the given challenge ID.\n");
			UnlockSlots("FindSlotByChallenge()");
			return current;
		}
		current = current->next;
	}

	log(DEBUG, "Failed to find an assigned slot for the given Challenge ID. Probably a new ID.\n");
	UnlockSlots("FindSlotByChallenge()");
	return NULL;
}


void FreeSlot(repeaterslot *slot)
{
	repeaterslot *current;
	repeaterslot *previous;

	if( LockSlots("FreeSlot()") != 0 )
		return;

	if( Slots == NULL ) {
		log(DEBUG, "There are no slots to be freed.\n");
		UnlockSlots("FreeSlot()");
		logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
		return;
	}

	current = Slots;
	previous = NULL;

	logp(DEBUG, "Trying to free slot... (Allocated repeater slots: %d)\n", slotCount);
	while( current != NULL )
	{
		if( memcmp(current->challenge, slot->challenge, CHALLENGESIZE) == 0 ) {
			/* The slot has been found */
			log(DEBUG, "Slots found. Trying to free resources.\n");
			/* Close server socket */
			if( slot->server != INVALID_SOCKET ) {
				shutdown( slot->server, 2 );
				if( socket_close( slot->server ) == -1 ) {
					logp(ERROR, "Server socket failed to close. Socket error = %d\n", errno);
				}
				else {
					log(DEBUG, "Server socket has been closed.\n");
				}
			}

			/* Close Viewer Socket */
			if( slot->viewer != INVALID_SOCKET ) {
				shutdown( slot->viewer, 2 );
				if( socket_close( slot->viewer ) == -1 ) {
					logp(ERROR, "Viewer socket failed to close. Socket error = %d\n", errno);
				}
				else {
					log(DEBUG, "Viewer socket has been closed.\n");
				}
			}

			if( previous != NULL )
				previous->next = current->next;
			else
				Slots = current->next;
			
			free( current );
			slotCount--;
			log(DEBUG, "Slot has been freed.\n");
			UnlockSlots("FreeSlot()");
			logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
			return;
		}

		previous = current;
		current = current->next;
	}

	log(FATAL, "Called FreeSlot() but no slot was found.\n");
	UnlockSlots("FreeSlot()");
	logp(DEBUG, "Allocated repeater slots: %d.\n", slotCount);
}

void ListSlots( void )
{
	repeaterslot *current;
  struct sockaddr_in  addr;
  socklen_t addrlen = sizeof(addr);
	if( LockSlots("ListSlots()") != 0 )
		return ;

	current = Slots;
	log(DEBUG, "Listing current connections.\n");
	while( current != NULL)
	{
	  if( current->server != INVALID_SOCKET ) {
      if( getpeername( (int)current->server, (struct sockaddr *)&addr, &addrlen) == 0 )
        logp(DEBUG, "server connected with id=%d from %s", current->code, inet_ntoa(addr.sin_addr));
      else 
        log(ERROR, "getpeername() failed");
      if ( current->viewer != INVALID_SOCKET )
        if( getpeername( (int)current->viewer, (struct sockaddr *)&addr, &addrlen) == 0 )
          logp(DEBUG, "with viewer from %s", inet_ntoa(addr.sin_addr));
        else 
          log(ERROR, "getpeername() failed");
      else 
        log(DEBUG, "without viewer \n");
    }
    current = current->next;
	}

	log(DEBUG, "End of Listing");
	UnlockSlots("ListSlots()");
}

std::string DumpSlots( void ) 
{
  std::ostringstream oss (std::ostringstream::out);
 	repeaterslot *current;
  struct sockaddr_in  addr;
  socklen_t addrlen = sizeof(addr);
	if( LockSlots("DumpSlots()") != 0 )
		return NULL;
  oss << "[\n";
	current = Slots;
	log(DEBUG, "Dumping current connections.\n");
  if (current != NULL )
	do 
	{
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
    current = current->next;
    oss << "}\n";
	} while ( current != NULL && oss << ", ");

	log(DEBUG, "End of Dumping.\n");
	UnlockSlots("DumpSlots()");
  oss << "]\n";
  return oss.str();
}

