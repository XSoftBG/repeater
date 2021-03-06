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
#include <unistd.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#endif

#include "logger.h"
#include "sockets.h"

#ifdef WIN32
/*****************************************************************************
 *
 * Winsock specific functions
 *
 *****************************************************************************/
int WinsockInitialize( void )
{
	WSADATA	wsaData;
	/* Use the MAKEWORD(lowbyte, highbyte) macro declared in Windef.h */
	WORD wVersionRequested = MAKEWORD(2, 2);

	if( WSAStartup(wVersionRequested, &wsaData) != 0 ) {
		log(FATAL, "main(): WSAStartup failed.");
		return 0;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		log(FATAL, "main(): Could not find a usable version of Winsock.dll");
		WSACleanup();
		return 0;
	}
	return 1;
}

void WinsockFinalize( void ) { WSACleanup(); }

#endif /* END WIN32 */


/*****************************************************************************
 *
 * Common functions
 *
 *****************************************************************************/
int getLastErrNo()
{
  if(errno)
    return errno;
#ifdef WIN32
  else
  if( ::GetLastError() > 0 )
    return ::GetLastError();
  else
  if( ::WSAGetLastError() > 0 )
    return ::WSAGetLastError();
#endif
  else
    return 0;
}


SOCKET create_listener_socket(u_short port)
{
	struct sockaddr_in  addr;
	const int one = 1;

	/* zero the struct before filling the fields */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;					
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	/* Initialize the socket */
	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		logp(ERROR, "Failed to create a listening socket for port %d, error: %d.", port, getLastErrNo());
		return INVALID_SOCKET;
	}

	/* Set Socket options */
	if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 )
		logp(ERROR, "Failed to set socket option SO_REUSEADDR on port %d, error: %d.", port, getLastErrNo());

	/* Disable Nagle Algorithm */
	if( setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0 )
		logp(ERROR, "Failed to set socket option TCP_NODELAY on port %d, error: %d.", port, getLastErrNo());

	/* Bind the socket to the port */
	if (bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)) < 0) {
		logp(ERROR, "Failed to bind socket on port %d, error: %d.", port, getLastErrNo());
		socket_close(sock);
		return INVALID_SOCKET;
	}

	/* Start listening */
	if (listen(sock, 5) < 0) {
		logp(ERROR, "Failed to start listening on port %d, error: %d.", port, getLastErrNo());
		socket_close(sock);
		return INVALID_SOCKET;
	}
	return sock;
}

int socket_read(SOCKET s, char * buff, socklen_t bufflen, int flags)
{
	const int bytes = recv(s, buff, bufflen, flags);
	if(bytes < 0) {
    int err = getLastErrNo();
    if (err == EWOULDBLOCK || err == EAGAIN) return 0;
    logp(ERROR, "socket_read: socket: %d error: %d.", s, err);
		return -1;
	} else if(bytes == 0) {
		errno = ENOTCONN;
    logp(DEBUG, "socket_read: connection closed (socket: %d).", s);
		return -1;
	}
	return bytes;
}

int socket_write(SOCKET s, char * buff, socklen_t bufflen, int flags)
{
  const int bytes = send(s, buff, bufflen, flags);
  if(bytes < 0) {
    int err = getLastErrNo();
    if (err == EWOULDBLOCK || err == EAGAIN) return 0;
    logp(ERROR, "socket_write: socket: %d error: %d.", s, err);
    return -1;
  } else if(bytes == 0) {
		errno = ENOTCONN;
    logp(DEBUG, "socket_write: connection closed (socket: %d).", s);
		return -1;
	}
  return bytes;
}

int socket_read_exact(SOCKET s, char * buff, socklen_t bufflen, struct timeval *tm, int flags)
{
	socklen_t currlen = bufflen;
	fd_set read_fds;
	int n;

	while (currlen > 0) {
		FD_ZERO(&read_fds);
		FD_SET(s, &read_fds);
		n = select(s + 1, &read_fds, NULL, NULL, tm); // Wait until some data can be read or select tiemouted
		if (n < 0) {
			logp(ERROR, "socket_read_exact: select() error: %d", getLastErrNo());
			return -1;
		} else if (n == 0)
      return -2;
	
		if( FD_ISSET(s, &read_fds) ) {
			n = socket_read(s, buff, currlen, flags);
			if (n > 0) {
				buff += n;
				currlen -= n;
			} else if (n < 0)
					return -1;
		}
  }
	return bufflen;
}

int socket_write_exact(SOCKET s, char * buff, socklen_t bufflen, struct timeval *tm, int flags)
{
	socklen_t currlen = bufflen;
	fd_set write_fds;
	int n;

	while (currlen > 0) {
		FD_ZERO(&write_fds);
		FD_SET(s, &write_fds);
		n = select(s + 1, NULL, &write_fds, NULL, tm); // Wait until some data can be read or select tiemouted
		if (n < 0) {
			logp(ERROR, "socket_write_exact: select() error: %d", getLastErrNo());
			return -1;
		} else if (n == 0)
      return -2;

		n = socket_write(s, buff, bufflen, flags);
		if (n > 0) {
			buff += n;
			currlen -= n;
		} else if (n < 0)
			return -1;
	}
	return bufflen;
}

SOCKET  socket_accept(SOCKET s, struct sockaddr * addr, socklen_t * addrlen)
{
	SOCKET sock;
	const int one = 1;

	if ( (sock = accept(s, addr, addrlen)) == INVALID_SOCKET ) return INVALID_SOCKET;

	// Attempt to set the new socket's options
	// Disable Nagle Algorithm
	if( setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) != 0) {
		if (getLastErrNo() == ENOTSOCK) return INVALID_SOCKET;
		log(INFO, "Failed to disable Nagle Algorithm.");
	} else
		log(INFO, "Nagle Alorithm has been disabled.");

	// Put the socket into non-blocking mode
#ifdef WIN32
	u_long ioctlsocket_arg = 1;

	if (ioctlsocket(sock, FIONBIO, &ioctlsocket_arg) != 0) {
		log(ERROR, "Failed to set socket in non-blocking mode.");
		socket_close( sock );
		return INVALID_SOCKET;
	}
#else
	if (fcntl(sock, F_SETFL, O_NDELAY) != 0) {
		log(ERROR, "Failed to set socket in non-blocking mode.");
		socket_close( sock );
		return INVALID_SOCKET;
	}
#endif
	return sock;
}

int socket_close(SOCKET s)
{
	shutdown(s, 2);
#ifdef WIN32
	return closesocket(s) != 0 ? -1 : 0;
#else
	return close(s) != 0 ? -1 : 0;
#endif
}

