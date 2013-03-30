/////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2013 XSoft Ltd Bulgaria. All Rights Reserved.
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

#define ERROR '\0'
#define FATAL '\1'
#define INFO  '\2'
#define DEBUG '\3'

#include <string>
#include <stdint.h>


int64_t millitime();
int64_t microtime();
const char *microtime_str(int64_t t);
const char *millitime_str(int64_t t);

extern char logger_level;

int logger(char level, const char *fmt, ...);
char get_log_level(std::string level_name);

#define logp(l,fmt,...) ( (::logger_level>=l) ? logger(l, fmt, __VA_ARGS__) : 0 )
#define log(l,s) ( (::logger_level>=l) ? logger(l, "%s", s) : 0 )

