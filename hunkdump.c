#include <stdio.h>
#include <stdlib.h>

unsigned read4(FILE * f) {
	static unsigned char b[4];
	if (fread(b, 4, 1, f) != 1)
		return 0xffffffff;
	return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

unsigned nameLen; // size of current name
char * name;    // some name

void readName(unsigned l, FILE * f) {
	if (nameLen < l) {
		free(name);
		name = malloc(l * 4 + 1);
		nameLen = l;
	}
	name[l * 4] = 0;
	if (l)
		fread(name, 4, l, f);
}

char const *
nameOf(unsigned hid) {
	switch (hid & 0x3fffffff) {
	case 999: // 0X3E7
		return "HUNK_UNIT";
	case 1000: // 0X3E8
		return "HUNK_NAME";
	case 1001: // 0X3E9
		return "HUNK_CODE";
	case 1002: // 0X3EA
		return "HUNK_DATA";
	case 1003: // 0X3EB
		return "HUNK_BSS";
	case 1004: // 0X3EC
		return "HUNK_RELOC32";
	case 1005: // 0X3ED
		return "HUNK_RELOC16";
	case 1006: // 0X3EE
		return "HUNK_RELOC8";
	case 1007: // 0X3EF
		return "HUNK_EXT";
	case 1008: // 0x3F0
		return "HUNK_SYMBOL";
	case 1009: // 0x3F1
		return "HUNK_DEBUG";
	case 1010: // 0x3F2
		return "HUNK_END";
	case 1011: // 0x3F3
		return "HUNK_HEADER";
	case 1013: // 0x3F5
		return "HUNK_OVERLAY";
	case 1014: // 0x3F6
		return "HUNK_BREAK";
	case 1015: // 0x3F7
		return "HUNK_DREL32";
	case 1016: // 0x3F8
		return "HUNK_DREL16";
	case 1017: // 0x3F9
		return "HUNK_DREL8";
	case 1018: // 0x3FA
		return "HUNK_LIB";
	case 1019: // 0x3FB
		return "HUNK_INDEX";
	case 1020: // 0x3FC
		return "HUNK_RELOC32SHORT";
	case 1021: // 0x3FD
		return "HUNK_RELRELOC32";
	case 1022: // 0x3FE
		return "HUNK_ABSRELOC16";
	}
	return "?";
}

int main(int argc, char ** argv) {
	if (argc != 2)
		return 1;

	FILE * f = fopen(argv[1], "rb+");
	do {
		if (!f) {
			printf("file not found %s\n", argv[1]);
			break;
		}

		printf("reading %s\n", argv[1]);

		while (!feof(f)) {
			unsigned hid = read4(f);
			if (hid == 0xffffffff)
				break;
			if (hid == 0x3f2) {
				printf("HUNK_END\n");
				continue;
			}

			unsigned sz = read4(f);
			printf("hunk %08x, %16s, %10d\n", hid, nameOf(hid), sz << 2);

			switch (hid & 0x3fffffff) {
			case 0x3f3: // HEADER
				if (sz) {
					readName(sz, f);
					printf("exe file %s\n", name);
				}
				// first last + sizes
				unsigned nsecs = read4(f);
				unsigned first = read4(f);
				unsigned last = read4(f);
				printf("%d sections, %d - %d \nsizes: ", nsecs, first, last);
				for (int i = 0; i < nsecs; ++i) {
					sz = read4(f);
					printf("%d", sz << 2);
					if (sz & 0x80000000)
						printf("(f)");
					if (sz & 0x40000000)
						printf("(c)");
					if (i + 1 < nsecs)
						printf(", ");
				}
				printf("\n");
				break;

			case 0x3e8: // NAME
				readName(sz, f);
				puts(name);
				break;
			case 0x3e7: // UNIT
			case 0x3e9: // CODE
			case 0x3ea: // DATA
			case 0x3f1: // DEBUG
				// skip sz long words.
				fseek(f, sz * 4, SEEK_CUR);
				break;

			case 0x3eb: // BSS
				// no more data
				break;

			case 0x3ec: // RELOC32
			case 0x3ed: // RELOC16
			case 0x3ee: // RELOC8
			case 0x3f7: // DRELOC32
			case 0x3f8: // DRELOC16
			case 0x3f9: // DRELOC8
			case 0x3f0: // SYMBOL
			case 0x3fe: // ABSRELOC16
				while (sz) {
					unsigned hn = read4(f);
					fseek(f, sz * 4, SEEK_CUR);
					sz = read4(f);
				}
				break;

			case 0x3fc: // RELOC32SHORT
				while (sz) {
					unsigned hn = read4(f);
					fseek(f, sz * 2, SEEK_CUR);
					sz = read4(f);
				}
				break;

			case 0x3ef: // EXT
				while (sz & 0xff000000) {
					printf("%08x ", sz);
					unsigned l = sz & 0xffffff;
					unsigned b = sz >> 24;
					readName(l, f);
					printf("ext %d %s\n", b, name);
					switch (b) {
					case 0: // ext_symb
					case 1: // ext_def
					case 2: // ext_abs
					case 3: // ext_res
					{
						unsigned v = read4(f);
					}
						break;
					case 130: // ext_common EXT_ABSCOMMON
					case 137: // EXT_RELCOMMON
					case 208: // EXT_DEXT32COMMON
					case 209: // EXT_DEXT16COMMON
					case 210: // EXT_DEXT8COMMON
					{
						unsigned value = read4(f);
						unsigned blocksize = read4(f);
						fseek(f, blocksize * 4, SEEK_CUR);
					}
						break;
					case 129: // ext_ref32
					case 131: // ext_ref16
					case 132: // ext_ref8
					case 133: // ext_dref32
					case 134: // ext_dref16
					case 135: // ext_dref8
					case 136: // EXT_RELREF32
					case 138: // EXT_ABSREF16
					case 139: // EXT_ABSREF8
					{
						unsigned n = read4(f);
						printf("ext ref %d\n", n);
						fseek(f, n * 4, SEEK_CUR);
					}
						break;
					default:
						printf("invalid %x\n", b);
						break;
					}

					sz = read4(f);
				}
				break;
			}
		}

	} while (0);
	if (f)
		fclose(f);
	if (name)
		free(name);
}
