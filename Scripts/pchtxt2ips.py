import os
import struct
import sys

IPS32_HEAD_MAGIC = b"IPS32"
IPS32_FOOT_MAGIC = b"EEOF"
IPS_PATCH_LEN_STRUCT = struct.Struct('>H')
PATCH_TEXT_ADDRESS_STRUCT = struct.Struct('>I')

NSO_HEADER_LEN = 0x100
NSOBID_MAGIC_LOWER = b"@nsobid-"
NSOBID_MAGIC_UPPER = b"@NSOBID-"
LINE_IGNORE_CHARS = " \n\r\t"
PATCH_LINE_MIN_SIZE = 9

class Patch:
    def __init__(self):
        self.offset = 0
        self.value = b""
        self.len = 0
        self.type = 0

def get_patch_from_line(line):
    patch = Patch()
    offset_str = line[:8]
    if not all(c in '0123456789ABCDEFabcdef' for c in offset_str):
        return None
    patch.offset = int(offset_str, 16)

    value_str = line[9:].strip()
    if value_str.startswith('"') and value_str.endswith('"'):
        patch.value = value_str[1:-1].encode('utf-8')
        patch.len = len(patch.value)
        patch.type = 1  # PATCH_TYPE_STRING
    else:
        if len(value_str) % 2 != 0:
            return None
        try:
            patch.value = bytes.fromhex(value_str)
            patch.len = len(patch.value)
            patch.type = 0  # PATCH_TYPE_BYTE
        except ValueError:
            return None

    return patch

def pchtxt2ips(pchtxt_path, out_ips_path=None, is_all_run=False):
    print("\nReading patch text file:")

    with open(pchtxt_path, 'r') as pchtxt_file:
        lines = pchtxt_file.readlines()

    nsobid = ""
    patches = []
    offset_shift = 0
    enabled = False
    last_comment = "No comment"
    for line in lines:
        line = line.strip()
        if line.startswith(('@nsobid-', '@NSOBID-')) and len(line) > 8:
            nsobid = line[8:72]
        elif line.startswith('#'):
            print(f"\033[33;1m\n{line}\033[0m")
        elif line.startswith('//'):
            last_comment = line
        elif line.startswith('@'):
            if line.lower().startswith('@enabled'):
                enabled = True
                print(f"\033[36mPatch read: {last_comment}\033[0m")
            elif line.lower().startswith('@flag'):
                flag_parts = line[6:].split(None, 1)
                if len(flag_parts) == 2:
                    flag_name, flag_value = flag_parts
                    if flag_name.lower() == 'offset_shift':
                        offset_shift = int(flag_value, 0)
                        print(f"\033[34;1mFlag: offset_shift 0x{offset_shift:X}\033[0m")
        elif enabled and len(line) >= PATCH_LINE_MIN_SIZE:
            patch = get_patch_from_line(line)
            if patch:
                patch.offset += offset_shift
                patches.append(patch)

    if not nsobid:
        print("\033[31mFailed to find output target.\033[0m")
        return -2

    ips_data = bytearray(IPS32_HEAD_MAGIC)
    for patch in patches:
        ips_data.extend(struct.pack('>I', patch.offset))
        ips_data.extend(IPS_PATCH_LEN_STRUCT.pack(patch.len))
        ips_data.extend(patch.value)
    ips_data.extend(IPS32_FOOT_MAGIC)

    if out_ips_path is None:
        out_ips_path = nsobid + '.ips'
    
    if is_all_run is True:
        out_ips_path = os.path.join(out_ips_path, nsobid + '.ips')

    with open(out_ips_path, 'wb') as out_file:
        out_file.write(ips_data)

    print(f"\nIPS output to\n{out_ips_path}")
    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pchtxt2ips.py <input_pchtxt_file> [output_ips_file]")
        sys.exit(1)

    pchtxt_path = sys.argv[1]
    if (pchtxt_path == "batch"):
        pchtxt_dir = sys.argv[2]
        ips_out = sys.argv[3]
        if (os.path.isdir(ips_out) is False):
            os.mkdir(ips_out)
        for file in os.listdir(pchtxt_dir):
            print(file)
            filepath = os.path.join(pchtxt_dir, file)
            pchtxt2ips(filepath, ips_out, True)
        print("Created IPS for every pchtxt!")
        sys.exit(1)
    out_ips_path = sys.argv[2] if len(sys.argv) > 2 else None
    result = pchtxt2ips(pchtxt_path, out_ips_path)
    sys.exit(result)
