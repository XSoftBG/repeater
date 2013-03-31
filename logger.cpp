/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2013 XSoft Ltd. - Bulgaria. All Rights Reserved.
//  Author: Andrey Maximov Andreev 
//  andreev@xsoftbg.com
//  www.xsoftbg.com
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

#ifndef WIN32
#include <sys/time.h>
#else
#include <time.h>
#endif
#include <sys/timeb.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "logger.h"

char logger_level = INFO;

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
  size_t n = ::strftime( buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ::localtime( &time ) );
  sprintf( buf+n, ".%06d", int(t % 1000000LL) );
  return buf;
}

const char *millitime_str(int64_t t)
{
  static char buf[40];
  time_t time = int(t / 1000LL);
  size_t n = ::strftime( buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", ::localtime( &time ) );
  ::sprintf( buf+n, ".%03d", int(t % 1000LL) );
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
  const size_t buffer_sz = sizeof(buffer)-50;
  if( ::logger_level >= level )
  { 
    va_list args;
    va_start(args, fmt);
    const char *ts = ::millitime_str( ::millitime() );
    const char * str_level = get_log_level_name(level);
    size_t sz = snprintf( buffer, buffer_sz, "[%s][%s] ", ts, str_level);
    int n = vsnprintf( buffer+sz, buffer_sz-sz, fmt, args);
    if( n > 0 ) sz += n;
    if( n < 0 || sz >= buffer_sz )
    {
      sz = buffer_sz;
      const char *msg = "... \n**** MESSAGE TRUNCATED ****\n";
      strcpy( buffer+sz, msg );
      sz += strlen(msg);
    }
    va_end(args);
    fprintf(stderr, "%s\n", buffer);
    return 1;
  }
  return 0;
}

