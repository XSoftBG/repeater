/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2010 Juan Pedro Gonzalez. All Rights Reserved.
//  Copyright (C) 2005 Jari Korhonen, jarit1.korhonen@dnainternet.net
//  Copyright (C) 2002 Ultr@VNC Team Members. All Rights Reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <memory.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <stdarg.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h> 
#ifndef WIN32
#include <pthread.h>
#include <netinet/tcp.h>	/* u_short */
#include <unistd.h>
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <sys/timeb.h>
#include <string>

#include "thread.h"
#include "sockets.h"
#include "rfb.h"
#include "vncauth.h"
#include "repeater.h"
#include "slots.h"
#include "config.h"
#include "version.h"

// Defines
#ifndef WIN32
#define _stricmp strcasecmp
#endif

#define TRUE   1
#define FALSE  0 


#define MAX_HOST_NAME_LEN	250

// Structures

typedef struct _listener_thread_params {
	u_short	port;
	SOCKET	sock;
} listener_thread_params;

// Global variables
int notstopped;
int log_level = INFO;


// Prototypes
int ParseDisplay(char *display, char *phost, int hostlen, char *pport);
void ExitRepeater(int sig);
void usage(char * appname);
THREAD_CALL do_repeater(LPVOID lpParam);
THREAD_CALL server_listen(LPVOID lpParam);
THREAD_CALL viewer_listen(LPVOID lpParam);
#ifdef WIN32
void ThreadCleanup(HANDLE hThread, DWORD dwMilliseconds);
//DWORD WINAPI do_repeater(LPVOID lpParam);
#endif


/*****************************************************************************
 *
 * Output methods
 *
 *****************************************************************************/

int64_t millitime()
{
  struct timeb t;
  ::ftime( &t );
  return t.time * 1000LL + t.millitm;
}

int64_t microtime()
{
#ifdef WIN32
  return ::millitime() * 1000LL;
#else
  struct timeval tv;
  return ::gettimeofday( &tv, NULL ) ? 0LL : tv.tv_sec * 1000000LL + tv.tv_usec;
#endif
}

const char *microtime_str(int64_t t)
{
  static char buf[40];
  time_t time = int(t / 1000000LL);
  int64_t milltime = t % 1000000LL;

  size_t n = ::strftime( buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ::localtime( &time ) );
  sprintf( buf+n, ".%06d", (int)milltime );
  return buf;
}

const char * get_log_level_name(char level)
{
  switch(level)
  {
    case ERROR: return "ERROR";
    case FATAL: return "FATAL";
    case INFO:  return "INFO";
    case DEBUG: return "DEBUG";
    default:    return "???";
  }
}

char get_log_level(std::string level_name)
{
  if( level_name == "ERROR") return ERROR;
  else
  if( level_name == "FATAL") return FATAL;
  else
  if( level_name == "INFO")  return INFO;
  else
  if( level_name == "DEBUG") return DEBUG;
  else return -1;
}

int logger(char level, const char *fmt, ...)
{
  static char buffer[32*1024]; // max 8k message

  if( ::log_level >= level )
  { 
    va_list args;
    va_start(args, fmt);
    const char *ts = ::microtime_str( ::microtime() );
    const char * str_level = get_log_level_name(level);
    size_t sz = snprintf( buffer, sizeof(buffer)-40, "[%s][%s] ", ts, str_level);
    int n = vsnprintf( buffer+sz, sizeof(buffer)-40-sz, fmt, args);
    if( n > 0 )
      sz += n;
    if( n < 0 || sz >= sizeof(buffer)-40 )
    {
      sz = sizeof(buffer)-40;
      const char *msg = "... \n**** MESSAGE TRUNCATED ****\n";
      strcpy( buffer+sz, msg );
      sz += strlen(msg);
    }
    va_end(args);
    fprintf(stderr, "%s", buffer);
    return 1;
  }
  return 0;
}


/*****************************************************************************
 *
 * Helpers / Misc.
 *
 *****************************************************************************/

int ParseDisplay(char *display, char *phost, int hostlen, int *pport, unsigned char *challengedid) 
{
	unsigned char challenge[CHALLENGESIZE];
	char tmp_id[MAX_HOST_NAME_LEN + 1];
	char *colonpos = strchr(display, ':');
	int tmp_code;

	if( hostlen < (int)strlen(display) ) return FALSE;

	if( colonpos == NULL ) return FALSE;

	strncpy(phost, display, colonpos - display);
	phost[colonpos - display]  = '\0';

	memset(tmp_id, 0, sizeof(tmp_id));
	if( sscanf(colonpos + 1, "%d", &tmp_code) != 1 ) return FALSE;
	if( sscanf(colonpos + 1, "%s", tmp_id) != 1 ) return FALSE;

	// encrypt
	memcpy(challenge, challenge_key, CHALLENGESIZE);
	vncEncryptBytes(challenge, tmp_id);

	memcpy(challengedid, challenge, CHALLENGESIZE);
	*pport = tmp_code;
	return TRUE;
}


/*****************************************************************************
 *
 * Threads
 *
 *****************************************************************************/

THREAD_CALL do_repeater(LPVOID lpParam)
{
	/** vars for viewer input data **/
	char viewerbuf[4096];        /* viewer input buffer */
	unsigned int viewerbuf_len;  /* available data in viewerbuf */
	int f_viewer;                /* read viewer input more? */ 

	/** vars for server input data **/
	char serverbuf[4096];        /* server input buffer */
	unsigned int serverbuf_len;  /* available data in serverbuf */
	int f_server;                /* read server input more? */

	/** other variables **/
	int nfds, len;
	fd_set ifds;
	fd_set ofds; 
	CARD8 client_init;
	repeaterslot *slot;
	int selres;

	slot = (repeaterslot *)lpParam;
	
	viewerbuf_len = 0;
	serverbuf_len = 0;

	logp(DEBUG, "do_reapeater(): Starting repeater for ID %d.\n", slot->code);

	// Send ClientInit to the server to start repeating
	client_init = 1;
	if( socket_write_exact(slot->server, (char *)&client_init, 1) < 0 ) {
		log(ERROR, "do_repeater(): Writting ClientInit error.\n");
		f_viewer = 0;              /* no, don't read from viewer */
		f_server = 0;              /* no, don't read from server */
	} else {
		/* repeater between stdin/out and socket  */
		nfds = ((slot->viewer < slot->server) ? slot->server : slot->viewer) + 1;

		viewerbuf_len = 0;
		serverbuf_len = 0;

		f_viewer = 1;              /* yes, read from viewer */
		f_server = 1;              /* yes, read from server */
	}

  nfds = (slot->server > slot->viewer ? slot->server : slot->viewer)+1;

	// Start the repeater loop.
	while(f_viewer && f_server)
	{
		/* Bypass reading if there is still data to be sent in the buffers */
		if( serverbuf_len == 0 && viewerbuf_len == 0 ) {
			FD_ZERO( &ifds );
			FD_ZERO( &ofds ); 

			/** prepare for reading viewer input **/ 
			if (f_viewer && viewerbuf_len < sizeof(viewerbuf)) {
				FD_SET(slot->viewer, &ifds);
			} 

			/** prepare for reading server input **/
			if (f_server && serverbuf_len < sizeof(serverbuf)) {
				FD_SET(slot->server, &ifds);
			} 

			selres = select(nfds, &ifds, &ofds, NULL, NULL);
			if( selres == -1 ) {
				/* some error */
				logp(ERROR, "do_repeater(): select() failed, errno=%d\n", errno);
				f_viewer = 0;              /* no, don't read from viewer */
				f_server = 0;              /* no, don't read from server */
				continue;
			} 		

			/* server => viewer */ 
			if (FD_ISSET(slot->server, &ifds) && serverbuf_len < sizeof(serverbuf)) { 
				len = recv(slot->server, serverbuf + serverbuf_len, sizeof(serverbuf) - serverbuf_len, 0); 

				if (len == 0) { 
					log(DEBUG, "do_repeater(): connection closed by server.\n");
					f_server = 0;              /* no, don't read from server */
					continue;
				} else if ( len == -1 ) {
					/* error on reading from stdin */
#ifdef WIN32
					errno = WSAGetLastError();
#endif
					logp(ERROR, "Error reading from socket. Socket error = %d.\n", errno );
					f_server = 0;              /* no, don't read from server */
					continue;
				} else {
					/* repeat */
					serverbuf_len += len; 
				}
			}

			/* viewer => server */ 
			if( FD_ISSET(slot->viewer, &ifds)  && viewerbuf_len < sizeof(viewerbuf) ) {
				len = recv(slot->viewer, viewerbuf + viewerbuf_len, sizeof(viewerbuf) - viewerbuf_len, 0);

				if (len == 0) { 
					log(DEBUG, "do_repeater(): connection closed by viewer.\n");
					// ToDo: Leave ready, but don't remove it...
					f_viewer = 0;
					continue;
				} else if ( len == -1 ) {
					/* error on reading from stdin */
#ifdef WIN32
					errno = WSAGetLastError();
#endif
					logp(ERROR, "Error reading from socket. Socket error = %d.\n", errno );
					f_viewer = 0;
					continue;
				} else {
					/* repeat */
					viewerbuf_len += len; 
				}
			}
		}

		/* flush data in viewerbuffer to server */ 
		if( 0 < viewerbuf_len ) { 
			
			len = send(slot->server, viewerbuf, viewerbuf_len, 0); 
			if( len == -1 ) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if( errno != EWOULDBLOCK ) {
					logp(DEBUG, "do_repeater(): send() failed, viewer to server. Socket error = %d\n", errno);
					f_server = 0;
				}
				continue;
			} else if ( 0 < len ) {
				/* move data on to top of buffer */ 
				viewerbuf_len -= len;

				if( 0 < viewerbuf_len ) 
					memcpy(viewerbuf, viewerbuf + len, viewerbuf_len);

				assert(0 <= viewerbuf_len); 
			}
		}

		/* flush data in serverbuffer to viewer */
		if( 0 < serverbuf_len ) { 
			len = send(slot->viewer, serverbuf, serverbuf_len, 0);

			if( len == -1 ) {
#ifdef WIN32
				errno = WSAGetLastError();
#endif
				if( errno != EWOULDBLOCK ) {
					logp(DEBUG, "do_repeater(): send() failed, server to viewer. Socket error = %d\n", errno);
					f_viewer = 0;
				}
				continue;
			} else if ( 0 < len ) {
				/* move data on to top of buffer */ 
				serverbuf_len -= len;

				if( len < (int)serverbuf_len )
					memcpy(serverbuf, serverbuf + len, serverbuf_len);

				assert(0 <= serverbuf_len); 
			}
		}
	}

	/** When the thread exits **/
	FreeSlot( slot );
	log(INFO, "Repeater thread closed.\n");
	return 0;
}



THREAD_CALL server_listen(LPVOID lpParam)
{
	listener_thread_params *thread_params;
	SOCKET connection;
	struct sockaddr_in client;
	socklen_t socklen = sizeof(client);
	rfbProtocolVersionMsg protocol_version; 
	char host_id[MAX_HOST_NAME_LEN + 1];
	char phost[MAX_HOST_NAME_LEN + 1];
	CARD32 auth_type;
	unsigned char challenge[CHALLENGESIZE];
	unsigned long code;
	repeaterslot *slot;
	repeaterslot *current;
	char * ip_addr;
	thread_t repeater_thread; 

	thread_params = (listener_thread_params *)lpParam;
	thread_params->sock = CreateListenerSocket( thread_params->port );
	if ( thread_params->sock == INVALID_SOCKET ) {
		notstopped = FALSE;
	} else {
		logp(DEBUG, "Listening for incoming server connections on port %d.\n", thread_params->port);
	}

	while( notstopped )
	{
		connection = socket_accept(thread_params->sock, (struct sockaddr *)&client, &socklen);
		if( connection == INVALID_SOCKET ) {
			if( notstopped )
				logp(ERROR, "server_listen(): accept() failed, errno=%d\n", errno);
			else
				break;
		} else {
			/* IP Address for monitoring purposes */
			ip_addr = inet_ntoa(client.sin_addr);
			logp(INFO, "Server (socket=%d) connection accepted from %s.\n", connection, ip_addr);
			// First thing is first: Get the repeater ID...
			if( socket_read_exact(connection, host_id, MAX_HOST_NAME_LEN) < 0 ) {
				if( ( errno == ECONNRESET )  || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by server (socket=%d) while trying to read the host id.\n", connection);
				} else {
					logp(DEBUG, "Reading host id from server (socket=%d) return socket error %d.\n", connection, errno);
				}
				socket_close( connection ); 
				continue;
			}

			// Check and cypher the ID
			memset(challenge, 0, CHALLENGESIZE);
			if( ParseDisplay(host_id, phost, MAX_HOST_NAME_LEN, (int *)&code, (unsigned char *)&challenge) == FALSE ) {
				log(ERROR, "server_listen(): Reading Proxy settings error");
				socket_close( connection ); 
				continue;
			}
			else {
				logp(DEBUG, "Server (socket=%d) sent the host ID:%d.\n", connection, code );
			}

			// Continue with the handshake until ClientInit.
			// Read the Protocol Version
			if( socket_read_exact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				if( ( errno == ECONNRESET )  || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by server (socket=%d) while trying to read the protocol version.\n", connection);
				} else {
					logp(DEBUG, "Reading protocol version from server (socket=%d) return socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Server (socket=%d) sent protocol version.\n", connection);
			}
			// ToDo: Make sure the version is OK!

			// Tell the server we are using Protocol Version 3.3
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( socket_write_exact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				if( ( errno == ECONNRESET  ) || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by server (socket=%d) while trying to write protocol version.\n", connection);
				} else {
					logp(DEBUG, "Writting protocol version to server (socket=%d) returned socket error %d.\n", connection, errno);
				}
				socket_close(connection);
				continue;
			} 
			else {
				logp(DEBUG, "Protocol version sent to server (socket=%d).\n", connection);
			}

			// The server should send the authentication type it whises to use.
			// ToDo: We could add a password this would restrict other servers from
			//       connecting to our repeater, in the meanwhile, assume no auth
			//       is the only scheme allowed.
			if( socket_read_exact(connection, (char *)&auth_type, sizeof(auth_type)) < 0 ) {
				if( ( errno == ECONNRESET )  || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by server (socket=%d) while trying to read the authentication scheme.\n", connection);
				} else {
					logp(DEBUG, "Reading authentication scheme from server (socket=%d) return socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Server (socket=%d) sent authentication scheme.\n", connection);
			}

			auth_type = Swap32IfLE(auth_type);
			if( auth_type != rfbNoAuth ) {
				logp(ERROR, "Invalid authentication scheme sent by server (socket=%d).\n", connection);
				socket_close( connection );
				continue;
			}

			// Screws LINUX!
			// shutdown(thread_params->sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			/* Initialize the slot */
			slot = (repeaterslot *)malloc( sizeof(repeaterslot) );
			memset(slot, 0, sizeof(repeaterslot));

			slot->server = connection;
			slot->viewer = INVALID_SOCKET;
			slot->timestamp = (unsigned long)time(NULL);
			memcpy(slot->challenge, challenge, CHALLENGESIZE);
			slot->code = code;
			slot->next = NULL;
			
			current = AddSlot(slot);
			if( current == NULL ) {
				free( slot );
				socket_close( connection );
				continue;
			} else if( ( current->viewer != INVALID_SOCKET ) && ( current->server != INVALID_SOCKET ) ) {
				// Thread...
				// ToDo: repeater_thread should be stored inside the slot in order to access it
				if( notstopped ) {
					if( thread_create(&repeater_thread, NULL, do_repeater, (LPVOID)current) != 0 ) {
						log(FATAL, "Unable to create the repeater thread.\n");
						notstopped = 0;
					}
				}
			} else {
				logp(DEBUG, "Server (socket=%d) waiting for viewer to connect...\n", current->server);
			}
		}
	}

	notstopped = FALSE;
	shutdown( thread_params->sock, 2);
	socket_close(thread_params->sock);
	log(INFO, "Server listening thread has exited.\n");
	return 0;
}


THREAD_CALL viewer_listen(LPVOID lpParam)
{
	listener_thread_params *thread_params;
	SOCKET connection;
	struct sockaddr_in client;
  socklen_t socklen = sizeof(client);
	rfbProtocolVersionMsg protocol_version; 
	CARD32 auth_type;
	CARD32 auth_response;
	CARD8 client_init;
	unsigned char challenge[CHALLENGESIZE];
	repeaterslot *slot;
	repeaterslot *current;
	char * ip_addr;
	thread_t repeater_thread; 

	thread_params = (listener_thread_params *)lpParam;
	thread_params->sock = CreateListenerSocket( thread_params->port );
	if ( thread_params->sock == INVALID_SOCKET ) {
		notstopped = FALSE;
	} else {
		logp(DEBUG, "Listening for incoming viewer connections on port %d.\n", thread_params->port);
	}

	// Main loop
	while( notstopped )
	{
		connection = socket_accept(thread_params->sock, (struct sockaddr *)&client, &socklen);
		if( connection == INVALID_SOCKET ) {
			if( notstopped ) 
				logp(INFO, "viewer_listen(): accept() failed, errno=%d\n", errno);
			else 
				break;
		} else {
			/* IP Address for monitoring purposes */
			ip_addr = inet_ntoa(client.sin_addr);
			logp(INFO, "Viewer (socket=%d) connection accepted from %s.\n", connection, ip_addr);

			// Act like a server until the authentication phase is over.
			// Send the protocol version.
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( socket_write_exact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				if( ( errno == ECONNRESET  ) || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by viewer (socket=%d) while trying to write protocol version.\n", connection);
				} else {
					logp(DEBUG, "Writting protocol version to viewer (socket=%d) returned socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Protocol version sent to viewer (socket=%d).\n", connection);
			}

			// Read the protocol version the client suggests (Must be 3.3)
			if( socket_read_exact(connection, protocol_version, sz_rfbProtocolVersionMsg) < 0 ) {
				if( ( errno == ECONNRESET  ) || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by viewer (socket=%d) while trying to read protocol version.\n", connection);
				} else {
					logp(DEBUG, "Reading protocol version from viewer (socket=%d) returned socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Viewer (socket=%d) sent protocol version.\n", connection);
			}

			// Send Authentication Type (VNC Authentication to keep it standard)
			auth_type = Swap32IfLE(rfbVncAuth);
			if( socket_write_exact(connection, (char *)&auth_type, sizeof(auth_type)) < 0 ) {
				if( ( errno == ECONNRESET  ) || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by viewer (socket=%d) while trying to write authentication scheme.\n", connection);
				} else {
					logp(DEBUG, "Writting authentication scheme to viewer (socket=%d) returned socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Authentication scheme sent to viewer (socket=%d).\n", connection);
			}

			// We must send the 16 bytes challenge key.
			// In order for this to work the challenge must be always the same.
			if( socket_write_exact(connection, (char *)challenge_key, CHALLENGESIZE) < 0 ) {
				if( ( errno == ECONNRESET  ) || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by viewer (socket=%d) while trying to write challenge key.\n", connection);
				} else {
					logp(DEBUG, "Writting challenge key to viewer (socket=%d) returned socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Challenge sent to viewer (socket=%d).\n", connection );
			}

			// Read the password.
			// It will be treated as the repeater IDentifier.
			memset(challenge, 0, CHALLENGESIZE);
			if( socket_read_exact(connection, (char *)challenge, CHALLENGESIZE) < 0 ) {
				if( ( errno == ECONNRESET )  || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by viewer (socket=%d) while trying to read challenge response.\n", connection);
				} else {
					logp(DEBUG, "Reading challenge response from viewer (socket=%d) return socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Viewer (socket=%d) sent challenge response.\n", connection);
			}

			// Send Authentication response
			auth_response = Swap32IfLE(rfbVncAuthOK);
			if( socket_write_exact(connection, (char *)&auth_response, sizeof(auth_response)) < 0 ) {
				if( ( errno == ECONNRESET  ) || ( errno == ENOTCONN ) ) {
					logp(INFO, "Connection closed by viewer (socket=%d) while trying to write authentication response.\n", connection);
				} else {
					logp(DEBUG, "Writting authentication response to viewer (socket=%d) returned socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			}
			else {
				logp(DEBUG, "Authentication response sent to viewer (socket=%d).\n", connection);
			}

			// Retrieve ClientInit and save it inside the structure.
			if( socket_read_exact(connection, (char *)&client_init, sizeof(client_init)) < 0 ) {
				if( ( errno == ECONNRESET )  || ( errno == ENOTCONN ) ) {
					logp(DEBUG, "Connection closed by viewer (socket=%d) while trying to read ClientInit.\n", connection);
				} else {
					logp(DEBUG, "Reading ClientInit from viewer (socket=%d) return socket error %d.\n", connection, errno);
				}
				socket_close( connection );
				continue;
			} 
			else {
				logp(DEBUG, "Viewer (socket=%d) sent ClientInit message.\n", connection);
			}

			// Screws LINUX!
			//shutdown(thread_params->sock, 2);

			// Prepare the reapeaterinfo structure for the viewer
			slot = (repeaterslot *)malloc( sizeof(repeaterslot) );
			memset(slot, 0, sizeof(repeaterslot));

			slot->server = INVALID_SOCKET;
			slot->viewer = connection;
			slot->timestamp = (unsigned long)time(NULL);
			memcpy(slot->challenge, challenge, CHALLENGESIZE);
			slot->next = NULL;
			
			current = AddSlot( slot );
			if( current == NULL ) {
				free( slot );
				socket_close( connection );
				continue;
			} else if( ( current->server != INVALID_SOCKET ) && ( current->viewer != INVALID_SOCKET ) ) {
				// Thread...
				// ToDo: repeater_thread should be stored inside the slot in order to access it
				if( notstopped ) {
					if( thread_create(&repeater_thread, NULL, do_repeater, (LPVOID)current) != 0 ) {
						log(FATAL, "Unable to create the repeater thread.\n");
						notstopped = 0;
					}
				}
			} else {
				logp(DEBUG, "Viewer (socket=%d) waiting for server to connect...\n", current->viewer);
			}
		}
	}

	notstopped = FALSE;
	shutdown( thread_params->sock, 2);
	socket_close( thread_params->sock );
	log(INFO, "Viewer listening thread has exited.\n");
	return 0;
}


void ExitRepeater(int sig)
{
	log(DEBUG, "Exit signal trapped.\n");
	notstopped = FALSE;
}


void usage(char * appname)
{
	fprintf(stderr, "\nUsage: %s [-server port] [-viewer port]\n\n", appname);
	fprintf(stderr, "  -server port  Defines the listening port for incoming VNC Server connections.\n");
	fprintf(stderr, "  -viewer port  Defines the listening port for incoming VNC viewer connections.\n");
	fprintf(stderr, "  -dump file  Defines the file to dump the json representation of current connections.\n");
	fprintf(stderr, "  -loglevel level Defines the logger level - ERROR, FATAL, INFO, DEBUG.\n");
	fprintf(stderr, "\nFor more information please visit http://code.google.com/p/vncrepeater\n\n");
	exit(1);
}

/*****************************************************************************
 *
 * Main entry point
 *
 *****************************************************************************/

int main(int argc, char **argv)
{
	listener_thread_params *server_thread_params;
	listener_thread_params *viewer_thread_params;
	u_short server_port;
	u_short viewer_port;
	int t_result;
  char * dump_file = NULL;
	thread_t hServerThread;
	thread_t hViewerThread;

	/* Load configuration file */
	if( GetConfigurationPort("ServerPort", &server_port) == 0 )
		server_port = 5500;
	if( GetConfigurationPort("ViewerPort", &viewer_port) == 0 )
		viewer_port = 5900;

	/* Arguments */
	if( argc > 1 ) {
		for( int i=1;i<argc;i++ )
		{
			if( _stricmp( argv[i], "-server" ) == 0 ) {
				/* Requires argument */
				if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

				server_port = atoi( argv[(i+1)] );
				if( argv[(i+1)][0] == '-' ) {
					usage( argv[0] );
					return 1;
				} else if( server_port == 0 ) {
					usage( argv[0] );
					return 1;
				} else if( server_port > 65535 ) {
					usage( argv[0] );
					return 1;
				}
				i++;
			} else if( _stricmp( argv[i], "-viewer" ) == 0 ) {
				/* Requires argument */
				if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

				viewer_port = atoi( argv[(i+1)] );
				if( argv[(i+1)][0] == '-' ) {
					usage( argv[0] );
					return 1;
				} else if( viewer_port == 0 ) {
					usage( argv[0] );
					return 1;
				} else if( viewer_port > 65535 ) {
					usage( argv[0] );
					return 1;
				}

				i++;
			} else if ( _stricmp( argv[i], "-dump" ) == 0 ) {
        if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

				dump_file = argv[(i+1)];
        i++; 
			} else if ( _stricmp( argv[i], "-loglevel" ) == 0 ) {
        if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

				char level = ::get_log_level(argv[(i+1)]);
        if(level == -1) { usage( argv[0] ); return 1; }
        ::log_level = level;
        i++; 
      } 
      else {
				usage( argv[0] );
				return 1;
			}
		}
	}
	
#ifdef WIN32
	/* Winsock */
	if( WinsockInitialize() == 0 )
		return 1;
#endif

	/* Start */
	logp(ERROR, "VNC Repeater [Version %s]\n", VNCREPEATER_VERSION);
	log(INFO, "Copyright (C) 2010 Juan Pedro Gonzalez Gutierrez. Licensed under GPL v2.\n");
	log(INFO, "Get the latest version at http://code.google.com/p/vncrepeater/\n\n");

	/* Initialize some variables */
	notstopped = TRUE;
	InitializeSlots( 20 );

	/* Trap signal in order to exit cleanlly */
	signal(SIGINT, ExitRepeater);

	server_thread_params = (listener_thread_params *)malloc(sizeof(listener_thread_params));
	memset(server_thread_params, 0, sizeof(listener_thread_params));
	viewer_thread_params = (listener_thread_params *)malloc(sizeof(listener_thread_params));
	memset(viewer_thread_params, 0, sizeof(listener_thread_params));

	server_thread_params->port = server_port;
	viewer_thread_params->port = viewer_port;


	// Start multithreading...
	// Initialize MutEx
	t_result = mutex_init( &mutex_slots );
	if( t_result != 0 ) {
		logp(ERROR, "Failed to create mutex for repeater slots with error: %d\n", t_result );
		notstopped = 0;
	}

	// Tying new threads ;)
	if( notstopped ) {
		if( thread_create(&hServerThread, NULL, server_listen, (LPVOID)server_thread_params) != 0 ) {
			log(FATAL, "Unable to create the thread to listen for servers.\n");
			notstopped = 0;
		}
	}

	if( notstopped ) {
		if( thread_create(&hViewerThread, NULL, viewer_listen, (LPVOID)viewer_thread_params) != 0 ) {
			log(FATAL, "Unable to create the thread to listen for viewers.\n");
			notstopped = 0;
		}
	}
  if( notstopped )
  {
    FILE *f = fopen( "pid.repeater", "w" );
    if(!f) perror("pid.repeater"), exit(1);
    fprintf(f, "%d\n", (int)getpid());
    fclose(f);
  } 
	// Main loop
	while( notstopped ) 
	{ 
		/* Clean slots: Free slots where the endpoint has disconnected */
		CleanupSlots();
    if (dump_file != NULL) {
      int dump_fd = open (dump_file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
      std::string json = DumpSlots();
      if (!json.empty()) 
        write (dump_fd, json.c_str(), json.length() );	
      close (dump_fd);
    }

		/* Take a "nap" so CPU usage doesn't go up. */
#ifdef WIN32
		Sleep( 50000 );
#else
		usleep( 5000000 );
#endif
	}

  log(ERROR, "\nExiting VNC Repeater...\n");

	notstopped = FALSE;

	/* Free the repeater slots */
	FreeSlots();

	/* Close the sockets used for the listeners */
	socket_close( server_thread_params->sock );
	socket_close( viewer_thread_params->sock );
	
	/* Free allocated memory for the thread parameters */
	free( server_thread_params );
	free( viewer_thread_params );

	/* Make sure the threads have finalized */
	if( thread_cleanup( hServerThread, 30) != 0 ) {
		log(ERROR, "The server listener thread doesn't seem to exit cleanlly.\n");
	}
	if( thread_cleanup( hViewerThread, 30) != 0 ) {
		log(ERROR, "The viewer listener thread doesn't seem to exit cleanlly.\n");
	}

	// Destroy mutex
  t_result = mutex_destroy( &mutex_slots );
	if( t_result != 0 ) {
		 logp(ERROR, "Failed to destroy mutex for repeater slots with error: %d\n", t_result);
	 }

#ifdef WIN32
	 // Cleanup Winsock.
	 WinsockFinalize();
#endif

	 return 0;
}

