# Makefile for x86 Length Disassembler.
# Copyright (C) 2016 Alessandro Pellegrini
# Copyright (C) 2013 Byron Platt
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

CFLAGS=-Wall -ansi -Os -g
CC=gcc
LIB_OBJ=ld.o
TEST_OBJ=ldtest.o

all: library test

library: $(LIB_OBJ)
	ar -cvq liblend.a $(LIB_OBJ)

test: $(TEST_OBJ)
	$(CC) $(TEST_OBJ) -L . -llend -lbfd -lopcodes -liberty -lz -ldl -o ldtest

clean:
	rm -f $(TEST_OBJ) $(LIB_OBJ) liblend.a
