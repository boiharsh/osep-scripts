import argparse
import re
import sys

# --- csharp Processor ---
def process_cs(content, xor_key, raw=False):
    """XORs a C#-style byte array: {0xaa, 0xbb, ...}."""
    pattern = r"(.*\{)(.*)(\}.*)"
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        raise ValueError("Could not find a valid C# array syntax, e.g., 'byte[] name = { ... }'.")

    prefix = match.group(1)
    raw_data = match.group(2)

    try:
        original_bytes = [int(b.strip(), 16) for b in raw_data.split(',') if b.strip()]
    except ValueError as e:
        raise ValueError(f"Error parsing C# byte data: {e}")

    xored_bytes = [b ^ xor_key for b in original_bytes]

    formatted_lines = []
    if xored_bytes:
        first_chunk = xored_bytes[:9]
        formatted_lines.append(",".join([f"0x{b:02x}" for b in first_chunk]))
        
        remaining_bytes = xored_bytes[9:]
        for i in range(0, len(remaining_bytes), 15):
            chunk = remaining_bytes[i:i + 15]
            formatted_lines.append(",".join([f"0x{b:02x}" for b in chunk]))

    new_payload = ",\n".join(formatted_lines)
    
    full_block = f"{prefix}{new_payload}}};\n"

    if raw:
        return full_block
    else:
        # Non-raw output includes informational header
        header = f"// XORed with key '{(chr(xor_key))}' (0x{xor_key:02x})\n// Original size: {len(original_bytes)} bytes\n"
        return f"{header}{full_block}"

# --- PowerShell Processor ---
def process_ps(content, xor_key, single_line=False, raw=False):
    """XORs a PowerShell-style byte array: [Byte[]] $Var = 0xaa,0xbb,..."""
    pattern = r"(\[Byte\[\]\]\s*\$[a-zA-Z0-9]+\s*=\s*)(.*)"
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        raise ValueError("Could not find a valid PowerShell array syntax '[Byte[]] $var = ...'.")

    prefix = match.group(1)
    raw_data = match.group(2).strip()
    
    try:
        original_bytes = [int(b.strip(), 16) for b in raw_data.split(',') if b.strip()]
    except ValueError as e:
        raise ValueError(f"Error parsing PowerShell byte data: {e}")

    xored_bytes = [b ^ xor_key for b in original_bytes]
    
    if single_line:
        new_payload = ",".join([f"0x{b:02x}" for b in xored_bytes])
    else:
        formatted_lines = []
        for i in range(0, len(xored_bytes), 15):
            chunk = xored_bytes[i:i + 15]
            formatted_lines.append(",".join([f"0x{b:02x}" for b in chunk]))
        new_payload = ",\n".join(formatted_lines)
    
    full_block = f"{prefix}{new_payload}"

    if raw:
        return full_block
    else:
        header = f"# XORed with key '{(chr(xor_key))}' (0x{xor_key:02x})\n# Original size: {len(original_bytes)} bytes\n"
        return f"{header}{full_block}"

# --- C Processor ---
def process_c(content, xor_key, raw=False):
    """XORs a C-style byte array: unsigned char buf[] = "\\xaa\\xbb...";"""
    prefix_match = re.search(r"(unsigned\s+char\s+\w+\s*\[\s*\]\s*=\s*)", content)
    if not prefix_match:
        raise ValueError("Could not find C array declaration, e.g., 'unsigned char var[] = ...'.")
    prefix = prefix_match.group(1)

    byte_content = content.encode('utf-8')
    hex_strings = re.findall(b'"([^"]*)"', byte_content)

    if not hex_strings:
        raise ValueError("Could not find any byte strings in the format '\\x...' in the file.")

    full_hex_string = b''.join(hex_strings).replace(b'\\x', b'')
    
    try:
        shellcode = bytes.fromhex(full_hex_string.decode('ascii'))
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"Failed to decode hex string. Ensure it's valid hex. Details: {e}")

    xored_shellcode = bytes([b ^ xor_key for b in shellcode])

    c_array_parts = []
    for i in range(0, len(xored_shellcode), 16):
        chunk = xored_shellcode[i:i+16]
        c_array_parts.append('"' + ''.join([f'\\x{b:02x}' for b in chunk]) + '"')
    
    c_array_string = '\n'.join(c_array_parts)
    
    full_block = f"{prefix}{c_array_string};"
    
    if raw:
        return full_block
    else:
        header = f"// XORed with key '{(chr(xor_key))}' (0x{xor_key:02x})\n// Original size: {len(shellcode)} bytes\n"
        return f"{header}{full_block}"

# --- VBA Processor ---
def process_vba(content, xor_key, raw=False):
    """XORs a VBA-style byte array: Array(1, 2, ...)"""
    pattern = r"(.*Array\()([^)]+)(\).*)"
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        raise ValueError("Could not find a valid VBA array syntax 'Array(...)'")

    prefix = match.group(1)
    raw_data = match.group(2)
    suffix = match.group(3)

    try:
        # VBA arrays in this context usually use decimal integers
        original_bytes = [int(b.replace('_', '').strip()) for b in raw_data.split(',') if b.strip() and not b.strip().isspace()]
    except ValueError as e:
        raise ValueError(f"Error parsing VBA byte data: {e}")

    xored_bytes = [b ^ xor_key for b in original_bytes]

    formatted_lines = []
    # VBA formatting: chunks of 75 for readability
    chunkSize = 75
    for i in range(0, len(xored_bytes), chunkSize):
        chunk = xored_bytes[i:i + chunkSize]
        line_str = " _\n" + ",".join([str(b) for b in chunk])
        formatted_lines.append(line_str)

    new_payload = ",".join(formatted_lines).replace(" _\n", "", 1)
    
    full_block = f"{prefix}{new_payload}{suffix}"

    if raw:
        return full_block
    else:
        header = f"' XORed with key '{(chr(xor_key))}' (0x{xor_key:02x})\n' Original size: {len(original_bytes)} bytes\n"
        return f"{header}{full_block}"

def process_bin(input_path, output_path, xor_key):
    """XORs a raw binary file and saves it to the output path."""
    with open(input_path, 'rb') as f:
        data = f.read()
    xored_data = bytes([b ^ xor_key for b in data])
    with open(output_path, 'wb') as f:
        f.write(xored_data)

def main():
    parser = argparse.ArgumentParser(
        description="A unified script to XOR byte arrays in C, C#, or PowerShell files.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument("-i", "--input", required=True, help="Path to the input source file.")
    parser.add_argument("-k", "--key", required=True, help="Single character key for XORing.")
    parser.add_argument(
        "-t", "--type", required=True, choices=['c', 'cs', 'ps', 'vba', 'bin'],
        help="Type of the source file:\n"
             "  c   - C-style string (e.g., unsigned char buf[] = \"\\xde\\xad...\")\n"
             "  cs  - C#-style array (e.g., byte[] buf = {0xde, 0xad, ...})\n"
             "  ps - PowerShell-style array (e.g., [Byte[]] $buf = 0xde,0xad,...)\n"
             "  vba - VBA-style array (e.g., Array(1, 2, ...))\n"
             "  bin - Raw binary file (requires -o/--output)"
    )
    parser.add_argument("-o", "--output", help="Path to save the output code block (headers/comments are omitted).")
    parser.add_argument("-s", "--single-line", action="store_true", help="[For PS only] Output the PowerShell array on a single line.")
    parser.add_argument("--raw", action="store_true", help="Print only the formatted code block to the console, omitting headers and comments.")

    args = parser.parse_args()

    if len(args.key) != 1:
        print("Error: Key must be a single character.", file=sys.stderr)
        sys.exit(1)
        
    xor_key = ord(args.key)

    if args.type == 'bin':
        output_path = args.output
        if not output_path:
            output_path = f"{args.input}_{args.key}"
        process_bin(args.input, output_path, xor_key)
        print(f"[+] Binary file XORed and saved to: {output_path}")
        return

    try:
        with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{args.input}' not found.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        # --- Determine processor and arguments ---
        processor = None
        proc_args = {}
        if args.type == 'c':
            processor = process_c
            proc_args = {'raw': args.raw}
        elif args.type == 'cs':
            processor = process_cs
            proc_args = {'raw': args.raw}
        elif args.type == 'ps':
            processor = process_ps
            proc_args = {'single_line': args.single_line, 'raw': args.raw}
        elif args.type == 'vba':
            processor = process_vba
            proc_args = {'raw': args.raw}
        
        if not processor:
            print(f"Error: Unknown type '{args.type}'.", file=sys.stderr)
            sys.exit(1)

        # --- Handle File Output ---
        if args.output:
            # Always write the clean "raw" block to a file
            file_output_args = proc_args.copy()
            file_output_args['raw'] = True
            file_output = processor(content, xor_key, **file_output_args)
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(file_output)
            print(f"[+] Code block saved to: {args.output}")

        # --- Handle Console Output ---
        if not args.output:
            if not args.raw:
                print(f"[*] Processing file '{args.input}' as type '{args.type}' with key '{args.key}'.")
            
            console_output = processor(content, xor_key, **proc_args)

            if not args.raw:
                print("\n--- Formatted Output ---")
                print(console_output)
                print("------------------------\n")
            else:
                # For raw output, print exactly what the processor returns, with no extra newline
                print(console_output, end='')

    except ValueError as e:
        print(f"\nProcessing Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
