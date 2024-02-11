// Copyright (c) 2012- PPSSPP Project.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 2.0.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License 2.0 for more details.

// A copy of the GPL 2.0 should have been included with the program.
// If not, see http://www.gnu.org/licenses/

// Official git repository and contact information can be found at
// https://github.com/hrydgard/ppsspp and http://www.ppsspp.org/.

#pragma once

//#include "Common.h"
#include "CommonTypes.h"
#include "Swap.h"

#define PSP_HEADER_SIZE (0x150)

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif

typedef struct
{
	u32_le      signature;       // 0
	u16_le      attribute;       // 4  modinfo
	u16_le      comp_attribute;  // 6
	u8          module_ver_lo;   // 8
	u8          module_ver_hi;   // 9
	char        modname[28];     // 0A
	u8          version;         // 26
	u8          nsegments;       // 27
	u32_le      elf_size;        // 28
	u32_le      psp_size;        // 2C
	u32_le      entry;           // 30
	u32_le      modinfo_offset;  // 34
	s32_le      bss_size;        // 38
	u16_le      seg_align[4];    // 3C
	u32_le      seg_address[4];  // 44
	s32_le      seg_size[4];     // 54
	u32_le      reserved[5];     // 64
	u32_le      devkitversion;   // 78
	u32_le      decrypt_mode;    // 7C 
	u8          key_data0[0x30]; // 80
	s32_le      comp_size;       // B0
	s32_le      _80;             // B4
	s32_le      reserved2[2];    // B8
	u8          key_data1[0x10]; // C0
	u32_le      tag;             // D0
	u8          scheck[0x58];    // D4
	u32_le      key_data2;       // 12C
	u32_le      oe_tag;          // 130
	u8          key_data3[0x1C]; // 134
#ifdef _MSC_VER
} PSP_Header;
#else
} __attribute__((packed)) PSP_Header;
#endif

typedef struct
{
    /** Magic "~SCE" */
    u32_be magic;
    /** Size of this header + additional data (if any). Typically 0x40 */
    u32_le size;
    /** SCE header verison number. */
    u32_le version;
    u32 unk[13];
} SceHeader; // size: 0x40

/**
 * PBP file data header.
 * A PBP file is a simple concatenation of pre-determined files.
 * All the structure members are Little-Endian.
 * The size of an embedded file data is determined as follows:
 *  size = file_offset[index + 1] - file_offset[index]
 * Where index is the file index whose size you want.
 * When the file index is 7:
 *  size = pbp_file_size - file_offset[7]
 * A size of zero means there is no file data.
 */
typedef struct
{
    /** PBP file header magic "\0PBP". */
    u32_be magic; // 0x00
    /** File header version. Always 0x00010000 (1.0) or 0x00010001 (1.1). */
    u32_le version; // 0x04
    union {
        /* Data offset by file name. */
        struct {
            /** PARAM.SFO file data offset. */
            u32_le off_param;      // 0x08
            /** ICON0.PNG file data offset. */
            u32_le off_icon0;      // 0x0c
            /** ICON1.PNG / ICON1.PMF file data offset. */
            u32_le off_icon1;      // 0x10
            /** PIC0.PNG file data offset. */
            u32_le off_pic0;       // 0x14
            /** PIC1.PNG / PICT1.PNG file data offset. */
            u32_le off_pic1;       // 0x18
            /** SND0.AT3 file data offset. */
            u32_le off_snd0;       // 0x1c
            /** DATA.PSP file data offset. */
            u32_le off_data_psp;   // 0x20
            /** DATA.PSAR file data offset. */
            u32_le off_data_psar;  // 0x24
        };
        /** File data offset by index. */
        u32_le file_offset[8];
    };
    /* The embedded files data follows this structure. */
} ScePBPHeader; // size: 0x28

#ifdef _MSC_VER
#pragma pack(pop)
#endif

int pspDecryptPRX(const u8 *inbuf, u8 *outbuf, u32 size, const u8 *secureId = nullptr, bool verbose = false);
