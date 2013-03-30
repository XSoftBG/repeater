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

#include <string.h>
#ifndef WIN32
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include "logger.h"
#include "sockets.h"

#ifdef WIN32
int errno;
#endif

#ifdef WIN32

/*****************************************************************************
 *
 * Winsock specific functions
 *
 *****************************************************************************/
int WinsockInitialize( void )
{
	WORD	wVersionRequested;
	WSADATA	wsaData;

	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	wVersionRequested = MAKEWORD(2, 2);

	if( WSAStartup(wVersionRequested, &wsaData) != 0 ) {
		log(FATAL, "main(): WSAStartup failed.\n");
		return 0;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		log(FATAL, "main(): Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 0;
	}
	return 1;
}

void WinsockFinalize( void )
{
	WSACleanup();
}

#endif /* END WIN32 */




/*****************************************************************************
 *
 * Common functions
 *
 *****************************************************************************/

SOCKET CreateListenerSocket(u_short port)
{
	SOCKET              sock;
	struct sockaddr_in  addr;
	const int one = 1;

	/* zero the struct before filling the fields */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;					
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	/* Initialize the socket */
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		logp(ERROR, "Failed to create a listening socket for port %d.\n", port);
		return INVALID_SOCKET;
	}

	/* Set Socket options */
#ifdef WIN32
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof( one ));
	/* Disable Nagle Algorithm */
	setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof( one ));
#else
	setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, (void *)&one, sizeof( one ));
	/* Disable Nagle Algorithm */
	setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (void *)&one, sizeof( one ));
#endif

	/* Bind the socket to the port */
	if( bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0 ) {
		logp(ERROR, "Failed to bind socket on port %d.\n", port);
		socket_close(sock);
		return INVALID_SOCKET;
	}

	/* Start listening */
	if( listen(sock, 5) < 0 ) {
		logp(ERROR, "Failed to start listening on port %d.\n", port);
		socket_close(sock);
		return INVALID_SOCKET;
	}

	/* Return the SOCKET */
	return sock;
}

int  socket_read(SOCKET s, char * buff, socklen_t bufflen)
{
	int bytes = recv( s, buff, bufflen, 0);
	errno = 0;
	if(bytes < 0) {
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		return -1;
	} else if(bytes == 0) {
		errno = ENOTCONN;
	}
	return bytes;
}

int socket_read_exact(SOCKET s, char * buff, socklen_t bufflen)
{
	socklen_t currlen = bufflen;
	fd_set read_fds;
	int n;

	while (currlen > 0) {
		// Wait until some data can be read
		FD_ZERO( &read_fds );
		FD_SET( s, &read_fds );
			
		n = select(s + 1, &read_fds, NULL, NULL, NULL);
		if( n < 0 ) {
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			return -1;
		} else if( n > 2 ) {
			log(ERROR, "socket error in select()\n");
			return -1;
		}
		
		if( FD_ISSET( s, &read_fds ) ) {
			// Try to read some data in
			n = socket_read(s, buff, currlen);
			if (n > 0) {
				// Adjust the buffer position and size
				buff += n;
				currlen -= n;
			} else if ( n < 0 ) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if( errno != EWOULDBLOCK) {
					return -1;
				}
			} else if (n == 0) {
				errno = ENOTCONN;
				return -1;
			}
		}
   }

	return 0;
}

int socket_write_exact(SOCKET s, char * buff, socklen_t bufflen)
{
	socklen_t currlen = bufflen;
	fd_set write_fds;
	int n;

	while (currlen > 0) {
		// Wait until some data can be read
		FD_ZERO( &write_fds );
		FD_SET( s, &write_fds );
		
		n = select(s + 1, NULL, &write_fds, NULL, NULL);
		if( n < 0 ) {
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			return -1;
		} else if( n > 2 ) {
			log(ERROR, "socket error in select()\n");
			return -1;
		}

		n = send(s, buff, bufflen, 0);

		if (n > 0) {
			buff += n;
			currlen -= n;
		} else if (n == 0) {
			log(ERROR, "WriteExact: write returned 0?\n");
			return -1;
		} else {
			/* Negative value. This is an error! */
#ifdef WIN32
			errno = WSAGetLastError();
#endif
			return -1;
		}
	}

	return 1;
}

SOCKET  socket_accept(SOCKET s, struct sockaddr * addr, socklen_t * addrlen)
{
	SOCKET sock;
	const int one = 1;

	errno = 0;

#ifdef WIN32
	u_long ioctlsocket_arg = 1;
#endif

	sock = INVALID_SOCKET;

	if( ( sock = accept(s, addr, addrlen) ) == INVALID_SOCKET ) {
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		return INVALID_SOCKET;
	}

	// Attempt to set the new socket's options
	// Disable Nagle Algorithm
	if( setsockopt( sock, IPPROTO_TCP, TCP_NODELAY, (char *)&one, sizeof(one)) == -1 ) {
#ifdef WIN32
		errno = WSAGetLastError();
#endif
		if( errno == ENOTSOCK )
			return INVALID_SOCKET;
		log(INFO, "Failed to disable Nagle Algorithm.\n");
	} else {
		log(INFO, "Nagle Alorithm has been disabled.\n");
	}

	// Put the socket into non-blocking mode
#ifdef WIN32
	if (ioctlsocket( sock, FIONBIO, &ioctlsocket_arg) != 0) {
		log(ERROR, "Failed to set socket in non-blocking mode.\n");
		socket_close( sock );
		return INVALID_SOCKET;
	}
#else
	if (fcntl( sock, F_SETFL, O_NDELAY) != 0) {
		log(ERROR, "Failed to set socket in non-blocking mode.\n");
		socket_close( sock );
		return INVALID_SOCKET;
	}
#endif

	return sock;
}

int socket_close(SOCKET s)
{
	errno = 0;
	shutdown(s, 2);
#ifdef WIN32
	if( closesocket( s ) != 0 ) {
		errno = WSAGetLastError();
#else
	if( close( s ) != 0 ) {
#endif
		return -1;
	}
	return 0;
}

