/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2013 XSoft Ltd. - www.xsoftbg.com (Andrey Andreev, andreev@xsoftbg.com). All Rights Reserved.
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
#include <fcntl.h>
#include <signal.h>

#include "logger.h"
#include "thread.h"
#include "sockets.h"
#include "rfb.h"
#include "vncauth.h"
#include "slots.h"
#include "version.h"

#ifndef WIN32
#define _stricmp strcasecmp
#endif

#define MAX_HOST_NAME_LEN	250
int IOBUFFER_SIZE=1024*16; // 16k

bool notstopped; // Global variable

typedef struct _listener_thread_params {
	u_short	port;
	SOCKET	sock;
} listener_thread_params;


bool ParseDisplay(char *display, char *phost, int hostlen, int *pport, unsigned char *challengedid) 
{
	unsigned char challenge[CHALLENGESIZE];
	char tmp_id[MAX_HOST_NAME_LEN + 1];
	char *colonpos = strchr(display, ':');
	int tmp_code;

	if( hostlen < (int)strlen(display) ) return false;

	if( colonpos == NULL ) return false;

	strncpy(phost, display, colonpos - display);
	phost[colonpos - display]  = '\0';

	memset(tmp_id, 0, sizeof(tmp_id));
	if( sscanf(colonpos + 1, "%d", &tmp_code) != 1 ) return false;
	if( sscanf(colonpos + 1, "%s", tmp_id) != 1 ) return false;

	// encrypt
	memcpy(challenge, challenge_key, CHALLENGESIZE);
	vncEncryptBytes(challenge, tmp_id);

	memcpy(challengedid, challenge, CHALLENGESIZE);
	*pport = tmp_code;
	return true;
}

THREAD_CALL do_repeater(LPVOID lpParam)
{
	char viewerbuf[IOBUFFER_SIZE];      /* viewer input buffer */
	unsigned int viewerbuf_len = 0;     /* available data in viewerbuf */
	unsigned int viewerbuf_off = 0;     /* offset in viewerbuf */
  bool         viewer_closed = false; /* viewer socket closed */
	char serverbuf[IOBUFFER_SIZE];      /* server input buffer */
	unsigned int serverbuf_len = 0;     /* available data in serverbuf */
	unsigned int serverbuf_off = 0;     /* offset data in serverbuf */
  bool         server_closed = false; /* server socket closed */
	repeaterslot *slot = (repeaterslot *)lpParam;
	int len = 0, nfds = (slot->server > slot->viewer ? slot->server : slot->viewer)+1;
	fd_set fds; 
	CARD8 client_init = 1;

	logp(DEBUG, "do_reapeater(): Starting repeater for ID %d, server_initialized=%d.", slot->code, slot->server_initialized);
  if (!slot->server_initialized)
    slot->server_initialized = socket_write_exact(slot->server, (char *)&client_init, sizeof(client_init)) > 0; // Send ClientInit to the server to start repeating

	if (slot->server_initialized) {
	  // Start the repeater loop (repeater between stdin/out and socket)
	  while(true)
	  {
		  /* Bypass reading if there is still data to be sent in the buffers */
		  if (serverbuf_len == 0 && viewerbuf_len == 0) {
  		  FD_ZERO( &fds );
			  FD_SET(slot->server, &fds); /** prepare for reading server input **/
			  FD_SET(slot->viewer, &fds); /** prepare for reading viewer input **/ 

			  if( select(nfds, &fds, NULL, NULL, NULL) < 0 ) {
				  logp(ERROR, "do_repeater(): input select() failed, errno=%d", errno);
          viewer_closed = server_closed = true;
          break;
			  } 		

			  /* server => viewer */ 
			  if (FD_ISSET(slot->server, &fds)) { 
				  len = ::socket_read(slot->server, serverbuf, sizeof(serverbuf)); 
				  if (len > 0) {
					  serverbuf_len += len; /* repeat */
            serverbuf_off  = 0;
				  } else if (len < 0) {
              server_closed = true;
  					  break;
          }
			  }

			  /* viewer => server */ 
			  if( FD_ISSET(slot->viewer, &fds) ) {
				  len = ::socket_read(slot->viewer, viewerbuf, sizeof(viewerbuf));
				  if (len > 0) {
					  viewerbuf_len += len;  /* repeat */
            viewerbuf_off  = 0;
				  } else if (len < 0) {
              viewer_closed = true;
					    break;
          }
			  }
		  }

      if (viewerbuf_len > 0 || serverbuf_len > 0) {
  		  FD_ZERO( &fds ); 
			  FD_SET(slot->server, &fds); /** prepare for reading server output **/
			  FD_SET(slot->viewer, &fds); /** prepare for reading viewer output **/ 

		    if( ::select(nfds, NULL, &fds, NULL, NULL) < 0 ) {
			    logp(ERROR, "do_repeater(): ouput select() failed, errno=%d", errno);
          viewer_closed = server_closed = true;
          break;
		    } 		

		    /* flush data in viewerbuffer to server */ 
		    if( FD_ISSET(slot->server, &fds) && viewerbuf_len > 0 ) { 
			    len = ::socket_write(slot->server, viewerbuf+viewerbuf_off, viewerbuf_len); 
			    if (len > 0) {
				    viewerbuf_len -= len;
            viewerbuf_off += len;
			    } else if (len < 0) {
              server_closed = true;
  					  break;
          }
		    }

		    /* flush data in serverbuffer to viewer */
		    if( FD_ISSET(slot->viewer, &fds) && serverbuf_len > 0 ) { 
			    len = ::socket_write(slot->viewer, serverbuf+serverbuf_off, serverbuf_len);
			    if (len > 0) {
				    serverbuf_len -= len;
				    serverbuf_off += len;
			    } else if (len < 0) {
              viewer_closed = true;
					    break;
          }
		    }
      }
	  }
  } else
  		logp(ERROR, "do_repeater(): Writting the ClientInit message to server (socket=%d) returned socket error %d.", slot->server, errno);

	/** When the thread exits **/
  if (server_closed && viewer_closed) FreeSlot(slot);
  else
  if (server_closed) { socket_close(slot->server); slot->server = INVALID_SOCKET; slot->server_initialized = false; } 
  else
  if (viewer_closed) { socket_close(slot->viewer); slot->viewer = INVALID_SOCKET; }
	logp(INFO, "Repeater thread closed (server_closed=%d, server_initialized=%d, viewer_closed=%d).", server_closed, slot->server_initialized, viewer_closed);
	return 0;
}

void add_new_slot(SOCKET server_socket, SOCKET viewer_socket, unsigned char *challenge, uint32_t code)
{
	thread_t repeater_thread = 0; 
  repeaterslot *slot = NewSlot();
  slot->server = server_socket;
  slot->viewer = viewer_socket;
  slot->timestamp = (unsigned long)::time(NULL);
  memcpy(slot->challenge, challenge, CHALLENGESIZE);
  slot->code = code;
  slot->next = NULL;

  repeaterslot *current = AddSlot(slot);
  if (current == NULL) {
    free(slot);
    socket_close(server_socket == INVALID_SOCKET ? current->viewer : current->server);
  } else if (current->server != INVALID_SOCKET && current->viewer != INVALID_SOCKET) {
    if (notstopped) {
      if (thread_create(&repeater_thread, NULL, do_repeater, (LPVOID)current) != 0) {
	      log(FATAL, "Unable to create the repeater thread.");
	      notstopped = false;
      }
    }
  } else {
      logp(DEBUG, "%s (socket=%d) waiting for %s to connect...", 
           server_socket == INVALID_SOCKET ? "Viewer" : "Server",
           server_socket == INVALID_SOCKET ? current->viewer : current->server, 
           server_socket == INVALID_SOCKET ? "server" : "viewer");
  }
}

bool socket_recv(SOCKET s, char * buff, socklen_t bufflen, const char *msg)
{
  if( socket_read_exact(s, buff, bufflen) < 0 ) {
	  if( errno == ECONNRESET || errno == ENOTCONN ) {
		  logp(INFO, "Connection closed (socket=%d) while trying to read the %s.", s, msg);
	  } else {
		  logp(ERROR, "Reading the %s (socket=%d) return socket error %d.", msg, s, errno);
	  }
	  socket_close(s); 
	  return false;
  }
  return true;
}

bool socket_send(SOCKET s, char * buff, socklen_t bufflen, const char *msg)
{
  if( socket_write_exact(s, buff, bufflen) < 0 ) {
	  if( errno == ECONNRESET || errno == ENOTCONN ) {
		  logp(INFO, "Connection closed (socket=%d) while trying to write the %s.", s, msg);
	  } else {
		  logp(ERROR, "Writting the %s (socket=%d) returned socket error %d.", msg, s, errno);
	  }
	  socket_close(s);
	  return false;
  }
  return true;
}

THREAD_CALL server_listen(LPVOID lpParam)
{
	listener_thread_params *thread_params = (listener_thread_params *)lpParam;
	SOCKET conn;
	struct sockaddr_in client;
	socklen_t socklen = sizeof(client);
	rfbProtocolVersionMsg protocol_version; 
	char host_id[MAX_HOST_NAME_LEN + 1];
	char phost[MAX_HOST_NAME_LEN + 1];
	CARD32 auth_type;
	unsigned char challenge[CHALLENGESIZE];
	uint32_t code;
	char *ip_addr;

	thread_params->sock = create_listener_socket( thread_params->port );
	if ( thread_params->sock == INVALID_SOCKET ) {
		notstopped = false;
	} else {
		logp(DEBUG, "Listening for incoming server connections on port %d.", thread_params->port);
	}

	while(notstopped)
	{
		conn = socket_accept(thread_params->sock, (struct sockaddr *)&client, &socklen);
		if( conn == INVALID_SOCKET ) {
			if( notstopped )
				logp(ERROR, "server_listen(): accept() failed, errno=%d", errno);
			else
				break;
		} else {
			ip_addr = inet_ntoa(client.sin_addr); /* IP Address for monitoring purposes */
			logp(INFO, "Server (socket=%d) connection accepted from %s.", conn, ip_addr);

			// First thing is first: Get the repeater ID...
			if( socket_recv(conn, host_id, MAX_HOST_NAME_LEN, "hostid from server") ) {
		    // Check and cypher the ID
		    memset(challenge, 0, CHALLENGESIZE);
		    if( ParseDisplay(host_id, phost, MAX_HOST_NAME_LEN, (int *)&code, challenge) ) {
  		    logp(DEBUG, "Server (socket=%d) sent the host ID:%d.", conn, code);

			    // Continue with the handshake until ClientInit. Read the Protocol Version.
			    if( socket_recv(conn, protocol_version, sz_rfbProtocolVersionMsg, "protocol version from server") ) {
      			// ToDo: Make sure the version is OK!
  			    logp(DEBUG, "Server (socket=%d) sent protocol version.", conn);

			      // Tell the server we are using Protocol Version 3.3
			      sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			      if( socket_send(conn, protocol_version, sz_rfbProtocolVersionMsg, "protocol version to server") ) {
  			      logp(DEBUG, "Protocol version sent to server (socket=%d).", conn);

			        // The server should send the authentication type it whises to use.
			        // ToDo: We could add a password this would restrict other servers from connecting to our repeater, 
              // in the meanwhile, assume no auth is the only scheme allowed.
			        if( socket_recv(conn, (char *)&auth_type, sizeof(auth_type), "auth type from server") ) {
  			        logp(DEBUG, "Server (socket=%d) sent authentication scheme.", conn);

			          if( Swap32IfLE(auth_type) != rfbNoAuth ) {
				          logp(ERROR, "Invalid authentication scheme sent by server (socket=%d).", conn);
				          socket_close(conn);
			          }
                else
                  add_new_slot(conn, INVALID_SOCKET, challenge, code);
			        }
			      } 
			    }
		    }
        else
			    log(ERROR, "server_listen(): Reading Proxy settings error");
			}
		}
	}

	notstopped = false;
	socket_close(thread_params->sock);
	log(INFO, "Server listening thread has exited.\n");
	return 0;
}

THREAD_CALL viewer_listen(LPVOID lpParam)
{
	listener_thread_params *thread_params = (listener_thread_params *)lpParam;
	SOCKET conn;
	struct sockaddr_in client;
  socklen_t socklen = sizeof(client);
	rfbProtocolVersionMsg protocol_version; 
	CARD32 auth_type;
	CARD32 auth_response;
	CARD8 client_init;
	unsigned char challenge[CHALLENGESIZE];
	char * ip_addr;

	thread_params->sock = create_listener_socket( thread_params->port );
	if ( thread_params->sock == INVALID_SOCKET ) {
		notstopped = false;
	} else {
		logp(DEBUG, "Listening for incoming viewer connections on port %d.", thread_params->port);
	}

	while(notstopped)
	{
		conn = socket_accept(thread_params->sock, (struct sockaddr *)&client, &socklen);
		if( conn == INVALID_SOCKET ) {
			if( notstopped ) 
				logp(ERROR, "viewer_listen(): accept() failed, errno=%d", errno);
			else 
				break;
		} else {
			ip_addr = inet_ntoa(client.sin_addr); /* IP Address for monitoring purposes */
			logp(INFO, "Viewer (socket=%d) connection accepted from %s.", conn, ip_addr);

			// Act like a server until the authentication phase is over. Send the protocol version.
			sprintf(protocol_version, rfbProtocolVersionFormat, rfbProtocolMajorVersion, rfbProtocolMinorVersion);
			if( socket_send(conn, protocol_version, sz_rfbProtocolVersionMsg, "protocol version to viewer") ) {
  			logp(DEBUG, "Protocol version sent to viewer (socket=%d).", conn);

			  // Read the protocol version the client suggests (Must be 3.3)
			  if( socket_recv(conn, protocol_version, sz_rfbProtocolVersionMsg, "protocol version from viewer") ) {
  			  logp(DEBUG, "Viewer (socket=%d) sent protocol version.", conn);

			    // Send Authentication Type (VNC Authentication to keep it standard)
			    auth_type = Swap32IfLE(rfbVncAuth);
			    if( socket_send(conn, (char *)&auth_type, sizeof(auth_type), "auth type to viewer") ) {
  			    logp(DEBUG, "Authentication scheme sent to viewer (socket=%d).", conn);

			      // We must send the 16 bytes challenge key.
			      // In order for this to work the challenge must be always the same.
			      if( socket_send(conn, (char *)challenge_key, CHALLENGESIZE, "challenge key to viewer") ) {
  			      logp(DEBUG, "Challenge sent to viewer (socket=%d).", conn);

			        // Read the password. It will be treated as the repeater IDentifier.
			        memset(challenge, 0, CHALLENGESIZE);
			        if( socket_recv(conn, (char *)challenge, CHALLENGESIZE, "challenge response from viewer") ) {
  			        logp(DEBUG, "Viewer (socket=%d) sent challenge response.", conn);

			          // Send Authentication response
			          auth_response = Swap32IfLE(rfbVncAuthOK);
			          if( socket_send(conn, (char *)&auth_response, sizeof(auth_response), "auth response to viewer") ) {
  			          logp(DEBUG, "Authentication response sent to viewer (socket=%d).", conn);

			            // Retrieve ClientInit and save it inside the structure.
			            if( socket_recv(conn, (char *)&client_init, sizeof(client_init), "ClientInit from viewer") ) {
			              logp(DEBUG, "Viewer (socket=%d) sent ClientInit message.", conn);
                    add_new_slot(INVALID_SOCKET, conn, challenge, -1);
			            } 
			          }
			        }
			      }
			    }
			  }
			}
		}
	}

	notstopped = false;
	socket_close(thread_params->sock);
	log(INFO, "Viewer listening thread has exited.");
	return 0;
}

void ExitRepeater(int sig)
{
	log(DEBUG, "Exit signal trapped.\n");
	notstopped = false;
}

void usage(char * appname)
{
	fprintf(stderr, "\nUsage: %s [-server port] [-viewer port]\n\n", appname);
	fprintf(stderr, "  -server port Defines the listening port for incoming VNC Server connections (default 5500).\n");
	fprintf(stderr, "  -viewer port Defines the listening port for incoming VNC viewer connections (default 5900).\n");
	fprintf(stderr, "  -dump file name Defines the file to dump the json representation of current connections.\n");
	fprintf(stderr, "  -loglevel level Defines the logger level - ERROR, FATAL, INFO, DEBUG (default INFO).\n");
	fprintf(stderr, "  -iobuffer_size size Defines the input/output buffer size (default 16kb).\n");
	fprintf(stderr, "\nFor more information please visit http://code.google.com/p/vncrepeater or https://github.com/XSoftBG/repeater\n\n");
	exit(1);
}

int main(int argc, char **argv)
{
	listener_thread_params *server_thread_params;
	listener_thread_params *viewer_thread_params;
	u_short server_port = 5500;
	u_short viewer_port = 5900;
	int t_result;
  char * dump_file = NULL;
	thread_t hServerThread;
	thread_t hViewerThread;

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
        ::logger_level = level;
        i++; 
			} else if ( _stricmp( argv[i], "-iobuffer_size" ) == 0 ) {
        if( (i+i) == argc ) {
					usage( argv[0] );
					return 1;
				}

        int buffer_sz = atoi(argv[(i+1)]);
        if(buffer_sz <= 0) { usage( argv[0] ); return 1; }
        IOBUFFER_SIZE = buffer_sz;
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
	logp(ERROR, "VNC Repeater [Version %s]", VNCREPEATER_VERSION);
	log(INFO, "Copyright (C) 2010 Juan Pedro Gonzalez Gutierrez. Licensed under GPL v2.");
	log(INFO, "Copyright (C) 2013 XSoft Ltd. - www.xsoftbg.com. Licensed under GPL v2.");
	log(INFO, "Get the latest version at http://code.google.com/p/vncrepeater/ or https://github.com/XSoftBG/repeater\n");

	/* Initialize some variables */
	notstopped = true;
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
		logp(ERROR, "Failed to create mutex for repeater slots with error: %d", t_result );
		notstopped = false;
	}

	// Tying new threads ;)
	if( notstopped ) {
		if( thread_create(&hServerThread, NULL, server_listen, (LPVOID)server_thread_params) != 0 ) {
			log(FATAL, "Unable to create the thread to listen for servers.");
			notstopped = false;
		}
	}

	if( notstopped ) {
		if( thread_create(&hViewerThread, NULL, viewer_listen, (LPVOID)viewer_thread_params) != 0 ) {
			log(FATAL, "Unable to create the thread to listen for viewers.");
			notstopped = false;
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
      int dump_fd = ::open(dump_file, O_CREAT | O_TRUNC | O_WRONLY, 0644);
      std::string json = DumpSlots();
      if (!json.empty()) 
        write (dump_fd, json.c_str(), json.length() );	
      close (dump_fd);
    }

		/* Take a "nap" so CPU usage doesn't go up. */
#ifdef WIN32
		Sleep(5000000);
#else
		usleep(5000000);
#endif
	}

  log(ERROR, "\nExiting VNC Repeater...\n");
	notstopped = false;

	/* Free the repeater slots */
	FreeSlots();

	/* Close the sockets used for the listeners */
	socket_close( server_thread_params->sock );
	socket_close( viewer_thread_params->sock );
	
	/* Free allocated memory for the thread parameters */
	free( server_thread_params );
	free( viewer_thread_params );

	/* Make sure the threads have finalized */
	if( thread_cleanup(hServerThread, 30) != 0 ) {
		log(ERROR, "The server listener thread doesn't seem to exit cleanlly.");
	}
	if( thread_cleanup(hViewerThread, 30) != 0 ) {
		log(ERROR, "The viewer listener thread doesn't seem to exit cleanlly.");
	}

	// Destroy mutex
  t_result = mutex_destroy( &mutex_slots );
	if( t_result != 0 ) {
		 logp(ERROR, "Failed to destroy mutex for repeater slots with error: %d", t_result);
	 }

#ifdef WIN32
	 // Cleanup Winsock.
	 WinsockFinalize();
#endif
	 return 0;
}

