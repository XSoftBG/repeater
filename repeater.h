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

#define ERROR '\0'
#define FATAL '\1'
#define INFO  '\2'
#define DEBUG '\3'

int logger(char level, const char *fmt, ...);

extern int notstopped;
extern int log_level;

#define logp(l,fmt,...) ( (::log_level>=(l)) ? logger(l, fmt, __VA_ARGS__) : 0 )
#define log(l,s) ( (::log_level>=(l)) ? logger(l, "%s", s) : 0 )

