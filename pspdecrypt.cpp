#include <libgen.h>
#include <algorithm>
#include <cstdio>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string>
#include <string.h>
#include <getopt.h>
#include "PsarDecrypter.h"
#include "PrxDecrypter.h"
#include "pspdecrypt_lib.h"
#include "common.h"
#include "Swap.h"

using namespace std;

/* Magic numbers in Big-Endian. */
static const u32 ELF_MAGIC  = 0x7F454C46; /* \x7fELF */
static const u32 SCE_MAGIC  = 0x7E534345; /* ~SCE */
static const u32 PSP_MAGIC  = 0x7E505350; /* ~PSP */
static const u32 PSAR_MAGIC = 0x50534152; /* PSAR */
static const u32 PBP_MAGIC  = 0x00504250; /* \0PBP */

static const u32 MAX_PREIPL_SIZE = 0x1000;

static int decryptAndDecompressPrx(u8 *out, const u8 *in, u32 inSize, const u8 *secureId, bool verbose, bool decompPsp = true);

static inline u32 readMagic(const void *buf)
{
    return (u32)(*(u32_be *)buf);
}

/* Get the appropriate output buffer size for a decrypted & decompressed ~PSP file. */
static size_t getPspOutputBufferCapacity(const u8 *psp)
{
    /* The output buffer capacity must be at least the size of the input data
       because the input data will be copied to the output buffer first,
       then it will be decrypted. */
    u32 size = max(pspGetElfSize(psp), pspGetPspSize(psp));
    /* Align it to the AES block size ie. 16 bytes. */
    return ALIGN(size, 16);
}

void help(const char* exeName) {
    cout << "Usage: " << exeName << " [OPTION]... [FILE]" << endl;
    cout << endl;
    cout << "Decrypts encrypted PSP binaries (.PSP) or updaters (.PSAR)." << endl;
    cout << "Can also take PBP files as an input, or IPL binaries if the option is given." << endl;
    cout << endl;
    cout << "General options:" << endl;
    cout << "  -h, --help          display this help and exit" << endl;
    cout << "  -v, --verbose       enable verbose mode (mostly for debugging)" << endl;
    cout << "  -i, --info          display information about the input file and exit" << endl;
    cout << "  -c, --no-decomp     do not decompress GZIP/KL4E/KL3E/2RLZ decrypted data" << endl;
    cout << "PSP(/PBP)-only options:" << endl;
    cout << "  -o, --outfile=FILE  output file for the decrypted binary (default: [FILE.PSP].dec)" << endl;
    cout << "  -s, --secureid=XSTR 16-bytes secure ID hex string (default: none)" << endl;
    cout << "                      secure ID may only be used by PRX type 3/5/7/10" << endl;
    cout << "PSAR(/PBP)-only options:" << endl;
    cout << "  -e, --extract-only  do not decrypt files contained in the PSAR" << endl;
    cout << "PBP-only options:" << endl;
    cout << "  -P, --psp-only      only extract/decrypt the .PSP executable file of the PBP" << endl;
    cout << "  -A, --psar-only     only extract/decrypt the .PSAR updater file of the PBP" << endl;
    cout << "IPL decryption & PSAR(/PBP) options:" << endl;
    cout << "  -O, --outdir=DIR    output path for the PSAR's or IPL's contents (default: [VER] if given [VER].PBP/PSAR)" << endl;
    cout << "  -i, --ipl-decrypt   decrypt the IPL given as an argument" << endl;
    cout << "  -V, --version=VER   the firmware version (eg 660) used for extracting the IPL stages" << endl;
    cout << "  -p, --preipl        preipl image used for decrypting the later IPL stages" << endl;
    cout << "  -k, --keep-all      also keep the intermediate .gz files of later stages" << endl;
}

int main(int argc, char *argv[]) {

    static struct option long_options[] = {
        {"help",         no_argument,       0, 'h'},
        {"verbose",      no_argument,       0, 'v'},
        {"outfile",      required_argument, 0, 'o'},
        {"secureid",     required_argument, 0, 's'},
        {"no-decomp",    no_argument,       0, 'c'},
        {"extract-only", no_argument,       0, 'e'},
        {"outdir",       required_argument, 0, 'O'},
        {"ipl-decrypt",  no_argument,       0, 'i'},
        {"preipl",       required_argument, 0, 'p'},
        {"version",      required_argument, 0, 'V'},
        {"info",         no_argument,       0, 'I'},
        {"psar-only",    no_argument,       0, 'A'},
        {"psp-only",     no_argument,       0, 'P'},
        {"keep-all",     no_argument,       0, 'k'},
        {0,              0,                 0,  0 }
    };
    int long_index;

    string inFilename = "";
    string outDir = "";
    string outFile = "";
    string preipl = "";
    string xstr = "";
    u8 secureId[16] = {0};  // optional for PRX type 3/5/7/10
    bool preiplSet = false;
    u8 preiplBuf[MAX_PREIPL_SIZE];
    u32 preiplSize = 0;
    bool verbose = false;
    bool extractOnly = false;
    bool decompPsp = true;
    bool iplDecrypt = false;
    bool infoOnly = false;
    bool pspOnly = false;
    bool psarOnly = false;
    bool keepAll = false;
    int version = -1;
    int c = 0;
    cout << showbase << internal << setfill('0');
    while ((c = getopt_long(argc, argv, "hvco:s:eO:ip:V:IAP", long_options, &long_index)) != -1) {
        switch (c) {
            case 'h':
                help(argv[0]);
                return 0;
            case 'v':
                verbose = true;
                break;
            case 'c':
                decompPsp = false;
                break;
            case 'o':
                outFile = string(optarg);
                break;
            case 's':
                xstr = string(optarg);
                for (u32 i = 0, j = 0; i < xstr.length(); i += 2, j++) {
                    string byteStr = xstr.substr(i, 2);
                    secureId[j] = (u8)strtoul(byteStr.c_str(), NULL, 16);
                }
                break;
            case 'e':
                extractOnly = true;
                break;
            case 'O':
                outDir = string(optarg);
                break;
            case 'i':
                iplDecrypt = true;
                break;
            case 'p':
                preipl = string(optarg);
                preiplSet = true;
                break;
            case 'V':
                version = atoi(optarg);
                break;
            case 'I':
                infoOnly = true;
                break;
            case 'A':
                psarOnly = true;
                break;
            case 'P':
                pspOnly = true;
                break;
            case 'k':
                keepAll = true;
                break;
            default:
                help(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        cerr << "No file specified!" << endl;
        return 1;
    }

    if (optind + 1 < argc) {
        cerr << "More than two input files specified!" << endl;
        return 1;
    }

    inFilename = string(argv[optind]);

    if (outFile == "") {
        outFile = inFilename + ".dec";
    }

    if (outDir == "") {
        size_t dotOff = inFilename.find_last_of('.');
        if (dotOff == string::npos) {
            outDir = inFilename + ".extr";
        } else {
            outDir = inFilename.substr(0, dotOff);
        }
    }

    ifstream inFile (inFilename, ios::in|ios::binary|ios::ate);
    if (!inFile.is_open()) {
        cerr << "Could not open " << inFilename << "!" << endl;
        return 1;
    }

    streampos size = inFile.tellg();
    u8 *inData = new u8[size];
    inFile.seekg(0, ios::beg);
    inFile.read((char *)inData, size);
    inFile.close();
    if (size < 0x30) {
        cerr << "Input file is too small!" << endl;
        return 1;
    }

    if (preiplSet) {
        ifstream preiplFile (preipl, ios::in|ios::binary|ios::ate);
        if (!preiplFile.is_open()) {
            cerr << "Could not open " << preipl << "!" << endl;
            return 1;
        }

        preiplSize = preiplFile.tellg();
        if (preiplSize > MAX_PREIPL_SIZE) {
            cerr << "Preipl file too big!" << endl;
            return 1;
        }
        preiplFile.seekg(0, ios::beg);
        preiplFile.read((char*)preiplBuf, preiplSize);
        preiplFile.close();
    }

    if (iplDecrypt) {
        if (infoOnly) {
            cerr << "No info to display for IPL..." << endl;
            return 1;
        }
        if (version < 0) {
            cerr << "You need to set --version to extract later stages of a standalone IPL." << endl;
            return 1;
        }
        string logStr;
        if (decryptIPL(inData, size, version, "ipl", outDir, preiplSet ? preiplBuf : nullptr, preiplSize, verbose, keepAll, logStr) < 0) {
            cerr << "Decrypting standalone IPL" << logStr << endl;
            return 1;
        }
        cout << "Decrypting standalone IPL" << logStr << endl;
    }
    else {
        switch (readMagic(inData)) {
        case PSP_MAGIC:
            if (infoOnly) {
                cout << "Input is an encrypted PSP executable encrypted with tag " << hex << setw(8) << pspGetTagVal(inData) << endl;
            }
            else if (size < PSP_HEADER_SIZE) {
                cerr << "Input file is too small!" << endl;
                return 1;
            }
            else {
                u8 *outData = new u8[getPspOutputBufferCapacity(inData)];
                int outSize = decryptAndDecompressPrx(outData, inData, pspGetPspSize(inData), secureId, true, decompPsp);
                WriteFile(outFile.c_str(), outData, outSize);
                delete[] outData;
            }
            break;
        case PBP_MAGIC:
            {
                u32 pspOff = (u32)*(u32_le*)&inData[0x20];
                u32 psarOff = (u32)*(u32_le*)&inData[0x24];
                if (infoOnly) {
                    cout << "Input is a PBP with:" << endl;
                }
                if (pspOff < size && !psarOnly) {
                    if (readMagic(&inData[pspOff]) == ELF_MAGIC) {
                        if (infoOnly) {
                            cout << "- an unencrypted PSP (ELF) file" << endl;
                        } else {
                            cout << "Non-encrypted PSP file, writing to " << outFile << endl;
                            WriteFile(outFile.c_str(), &inData[pspOff], psarOff - pspOff);
                        }
                    }
                    else if (readMagic(&inData[pspOff]) == PSP_MAGIC) {
                        if (infoOnly) {
                            cout << "- an encrypted PSP executable encrypted with tag " << hex << setw(8) << pspGetTagVal(&inData[pspOff]) << endl;
                        }
                        else if (psarOff - pspOff < PSP_HEADER_SIZE) {
                            cerr << "DATA.PSP file within the input PBP is too small!" << endl;
                            return 1;
                        }
                        else {
                            cout << "Decrypting PSP file to " << outFile << endl;
                            u8 *outData = new u8[getPspOutputBufferCapacity(inData)];
                            int outSize = decryptAndDecompressPrx(outData, &inData[pspOff], pspGetPspSize(&inData[pspOff]), secureId, true, decompPsp);
                            WriteFile(outFile.c_str(), outData, outSize);
                            delete[] outData;
                        }
                    }
                    else if (infoOnly) {
                        cout << "- unknown DATA.PSP file data" << endl;
                    }
                }
                if (psarOff < size && !pspOnly) {
                    if (infoOnly) {
                        cout << "- a PSAR with the following characteristics:" << endl;
                    } else {
                        cout << "Extracting PSAR to " << outDir << endl;
                    }
                    pspDecryptPSAR(&inData[psarOff], (u32)size - psarOff, outDir, extractOnly, preiplSet ? preiplBuf : nullptr, preiplSize, verbose, infoOnly, keepAll, decompPsp);
                }
            }
            break;
        case PSAR_MAGIC:
            if (infoOnly) {
                cout << "Input is a PSAR with the following characteristics:" << endl;
            }
            pspDecryptPSAR(inData, size, outDir, extractOnly, preiplSet ? preiplBuf : nullptr, preiplSize, verbose, infoOnly, keepAll, decompPsp);
            break;
        case ELF_MAGIC:
            if (infoOnly) {
                cout << "Input is a non-encrypted PSP binary (ELF) file" << endl;
            } else {
                cout << "Non-encrypted file, copying to " << outFile << endl;
                WriteFile(outFile.c_str(), inData, size);
            }
            break;
        default:
            cout << "Unknown input file format!" << endl;
            return 1;
        }
    }

    delete[] inData;

    return 0;
}

static int decryptAndDecompressPrx(u8 *out, const u8 *in, u32 inSize, const u8 *secureId, bool verbose, bool decompPsp)
{
    int elfSize, outSize;

    elfSize = pspGetElfSize(in);
    outSize = pspDecryptPRX(in, out, inSize, secureId, verbose);
    if (outSize < 0) {
        return outSize;
    }

    if (outSize >= 4 && pspIsCompressed(out)) {
        if (decompPsp) {
            std::string logStr;
            u8 *temp = new u8[elfSize];
            outSize = pspDecompress(out, outSize, temp, elfSize, logStr);
            if (outSize == elfSize) {
                memcpy(out, temp, elfSize);
                if (verbose) {
                    printf("Decompression successful (%s)\n", logStr.substr(1).c_str());
                }
            }
            else if (verbose) {
                printf("Decompression failed (%s)\n", logStr.substr(1).c_str());
            }
            delete[] temp;
        }
        else if (verbose) {
            printf("Skipped data decompression\n");
        }
    }
    return outSize;
}