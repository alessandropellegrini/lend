/*
x86 Length Disassembler test.
Copyright (C) 2016 Alessandro Pellegrini

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#define PACKAGE "BFD" /* This fools bfd.h into thinking that we're using autoconf */
#include <bfd.h>
#include <dis-asm.h>

#include "lend.h"

/* This variable can be used as a watchpoint to walk through the disassembly
 * of a certain instruction */
static int count = 0;

static int errors = 0;

static int binning[15] = {0};

/* Buffer to keep track of a disassembled instruction mnemonic, used to
 * display instructions that are handled incorrectly by liblend */
struct asm_insn {
	char mnemonic[16];
	char src[32];
	char dest[32];
	char arg[32];
} curr_insn;

/* Called by libopcodes to generate textual representation of a portion
 * of a disassembled instruction */
int disprintf(void *stream, const char *format, ...) {
	va_list args;
	char *str;

	va_start(args, format);
	str = va_arg(args, char *);

	/* libopcodes passes one mnem/operand per call, and src twice!
	 * Sometimes it passess a null string (sic!) */
	if(str != NULL) {
		if(!curr_insn.mnemonic[0]) {
			strncpy(curr_insn.mnemonic, str, 15);
		} else if(!curr_insn.src[0]) {
			strncpy(curr_insn.src, str, 31);
		} else if(!curr_insn.dest[0]) {
			strncpy(curr_insn.dest, str, 31);
			if(strncmp(curr_insn.dest, "DN", 2) == 0)
				curr_insn.dest[0] = '\0';
		} else {
			if(!strcmp(curr_insn.src, curr_insn.dest)) {
				/* src was passed twice */
				strncpy(curr_insn.dest, str, 31);
			} else {
				strncpy(curr_insn.arg, str, 31);
			}
		}
	}
	va_end(args);

	return 0;
}

/* Print the last disassembled instruction mnemonic */
void print_insn(void) {
	printf("\t%s", curr_insn.mnemonic);
	if(curr_insn.src[0]) {
		printf("\t%s", curr_insn.src);
		if(curr_insn.dest[0]) {
			printf(", %s", curr_insn.dest);
			if(curr_insn.arg[0]) {
				printf(", %s", curr_insn.arg);
			}
		}
	}
}

/* Disassemble a code section in the given executable */
static void disasm_section(bfd *b, asection *section, PTR data) {
	int size;
	char mode;
	unsigned char *buf;
	disassembler_ftype disassemble_fn;
	static disassemble_info info = {0};
	int libopcodes_length, liblend_length;
	int i, bytes = 0;
	count = 0;

	/* Handle only code sections, avoid .plt and .got */
	if(!(section->flags & SEC_CODE))
		return;
	if(!strncmp(".plt", section->name, 4) || !strncmp(".got", section->name, 4))
		return;

	/* Get the bytecode buffer */
	size = bfd_section_size(b, section);
	buf = calloc(size, 1);
	if(!buf || !bfd_get_section_contents(b, section, buf, 0, size))
		return;

	printf("\n***Disassemblying section %s***\n\n", section->name);

	/* Initialize bfd disassembler */
	init_disassemble_info(&info, NULL, disprintf);
	info.arch = bfd_get_arch(b);
	info.mach = bfd_get_mach(b);
	info.flavour = bfd_get_flavour(b);
	info.endian = b->xvec->byteorder;
	disassemble_init_for_target(&info);

	/* Setup disassemble function */
	if(info.mach == bfd_mach_x86_64) {
		mode = MODE_X64;
	} else if(info.mach == bfd_mach_i386_i386) {
		mode = MODE_X32;
	} else {
		return;
	}
	disassemble_fn = disassembler(b);
	info.section = section;
	info.buffer = buf;
	info.buffer_length = size;
	info.buffer_vma = section->vma;

	/* disassemble the current section */
	while(bytes < info.buffer_length) {
		printf("%03d) ", count);

		/* call libopcodes disassembler */
		memset(&curr_insn, 0, sizeof(curr_insn));
		libopcodes_length = (*disassemble_fn)(info.buffer_vma + bytes, &info);
		/* call liblend disassembler */
		liblend_length = length_disasm(&info.buffer[bytes], mode);

		/* if the length is different, highlight the text and print
		 * the found and expected length. Continue using the length
		 * taken from libopcodes, to be resilient to liblend errors */
		if(libopcodes_length != liblend_length) {
			printf("\e[31m");
			errors++;
		}
		for(i = 0; i < libopcodes_length; i++) {
			printf("%02x ", info.buffer[bytes + i]);
		}
		if(libopcodes_length != liblend_length) {
			printf("\e[0m ");
			printf("[expected: %d - found: %d] - ", libopcodes_length, liblend_length);
			print_insn();
		}
		printf("\n");

		bytes += libopcodes_length;
		count++;
		binning[libopcodes_length-1]++;
	}

	free(buf);
}


/* Opens an executable file with libbfd to disassemble it using both
 * libopcodes and liblend, to compare the lengths of the instructions */
int main(int argc, char **argv) {
	struct stat s;
	bfd *infile;
	int i;

	if(argc < 2) {
		fprintf(stderr, "USage: %s target\n\ntarget is an x86 executable", argv[0]);
		exit(EXIT_FAILURE);
	}
	if(stat(argv[1], &s)) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	bfd_init();

	infile = bfd_openr(argv[1], NULL);
	if(!infile) {
		bfd_perror("Error on infile");
		exit(EXIT_FAILURE);
	}

	if(bfd_check_format(infile, bfd_object)) {
		bfd_map_over_sections(infile, disasm_section, NULL);
	} else {
		fprintf(stderr, "Error: file format not supported\n");
		exit(EXIT_FAILURE);
	}

	printf("\n*** Total disassembly errors: %d\n", errors);

	printf("\nInstruction length count:\n");
	for(i = 0; i < 15; i++) {
		printf("%02d: %d\n", i+1, binning[i]);
	}

	bfd_close(infile);
	return 0;
}
