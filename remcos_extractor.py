import sys
import os
import pefile
from Crypto.Cipher import ARC4

# Dictionary mapping index to field name and description
field_mapping = {
    0x0: ("c2_list", "String containing 'domain:port:enable_tls'"),
    0x1: ("botnet", "Name of the botnet"),
    0x2: ("connect_interval", "Interval in second between connection attempt to C2"),
    0x3: ("enable_install_flag", "Install REMCOS on the machine host"),
    0x4: ("enable_hkcu_run_persistence_flag", "Enable setup of the persistence in the registry"),
    0x5: ("enable_hklm_run_persistence_flag", "Enable setup of the persistence in the registry"),
    0x7: ("keylogger_maximum_file_size", "Maximum size of the keylogging data before rotation"),
    0x8: ("enable_hklm_policies_explorer_run_flag", "Enable setup of the persistence in the registry"),
    0x9: ("install_parent_directory", "Parent directory of the install folder. Integer mapped to an hardcoded path"),
    0xA: ("install_filename", "Name of the REMCOS binary once installed"),
    0xC: ("enable_persistence_directory_and_binary_hidding_flag", "Enable super hiding the install directory and binary as well as setting them to read only"),
    0xD: ("enable_process_injection_flag", "Enable running the malware injected in another process"),
    0xE: ("mutex", "String used as the malware mutex and registry key"),
    0xF: ("keylogger_mode", "Set keylogging capability. Keylogging mode, 0 = disabled, 1 = keylogging everything, 2 = keylogging specific window(s)"),
    0x10: ("keylogger_parent_directory", "Parent directory of the keylogging folder. Integer mapped to an hardcoded path"),
    0x11: ("keylogger_filename", "Filename of the keylogged data"),
    0x12: ("enable_keylogger_file_encryption_flag", "Enable encryption RC4 of the keylogger data file"),
    0x13: ("enable_keylogger_file_hidding_flag", "Enable super hiding of the keylogger data file"),
    0x14: ("enable_screenshot_flag", "Enable screen recording capability"),
    0x15: ("screenshot_interval_in_minutes", "The time interval in minute for capturing each screenshot"),
    0x16: ("enable_screenshot_specific_window_names_flag", "Enable screen recording for specific window names"),
    0x17: ("screenshot_specific_window_names", "String containing window names separated by the ';' character"),
    0x18: ("screenshot_specific_window_names_interval_in_seconds", "The time interval in second for capturing each screenshot when a specific window name is found in the current foreground window title"),
    0x19: ("screenshot_parent_directory", "Parent directory of the screenshot folder. Integer mapped to an hardcoded path"),
    0x1A: ("screenshot_folder", "Name of the screenshot folder"),
    0x1B: ("enable_screenshot_encryption_flag", "Enable encryption of screenshots"),
    0x23: ("enable_audio_recording_flag", "Enable audio recording capability"),
    0x24: ("audio_recording_duration_in_minutes", "Duration in second of each audio recording"),
    0x25: ("audio_record_parent_directory", "Parent directory of the audio recording folder. Integer mapped to an hardcoded path"),
    0x26: ("audio_record_folder", "Name of the audio recording folder"),
    0x27: ("disable_uac_flag", "Disable UAC in the registry"),
    0x28: ("logging_mode", "Set logging mode: 0 = disabled, 1 = minimized in tray, 2 = console logging"),
    0x29: ("connect_delay_in_second", "Delay in second before the first connection attempt to the C2"),
    0x2A: ("keylogger_specific_window_names", "String containing window names separated by the ';' character"),
    0x2B: ("enable_browser_cleaning_on_startup_flag", "Enable cleaning web browsers' cookies and logins on REMCOS startup"),
    0x2C: ("enable_browser_cleaning_only_for_the_first_run_flag", "Enable web browsers cleaning only on the first run of Remcos"),
    0x2D: ("browser_cleaning_sleep_time_in_minutes", "Sleep time in minute before cleaning the web browsers"),
    0x2E: ("enable_uac_bypass_flag", "Enable UAC bypass capability"),
    0x30: ("install_directory", "Name of the install directory"),
    0x31: ("keylogger_root_directory", "Name of the keylogger directory"),
    0x32: ("enable_watchdog_flag", "Enable watchdog capability"),
    0x34: ("license", "License serial"),
    0x35: ("enable_screenshot_mouse_drawing_flag", "Enable drawing the mouse on each screenshot"),
    0x36: ("tls_raw_certificate", "Certificate in raw format used with tls enabled C2 communication"),
    0x37: ("tls_key", "Key of the certificate"),
    0x38: ("tls_raw_peer_certificate", "C2 public certificate in raw format")
}

def parse_data(data):
    """Parse and decode data fields."""
    fields = data.split('||')
    
    for i, raw_field in enumerate(fields):
        field = raw_field.strip().strip("\x00")
        
        if not field:
            continue  

        index = i
        if index in field_mapping:
            field_name, description = field_mapping[index]
            print(f"\nName: {field_name}\n")
            print(f"Description: {description}\n")
            print(f"Value: {field}\n")
            print("-" * 80)

def extract_remcos_config(pe_file_path, output_file_path):
    """Extract and decrypt the REMCOS configuration from the PE file."""
    pe = pefile.PE(pe_file_path)

    settings_section = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name is None and entry.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
            for sub_entry in entry.directory.entries:
                if sub_entry.name and sub_entry.name.decode() == 'SETTINGS':
                    settings_section = sub_entry
                    break

    if not settings_section:
        print("SETTINGS section not found in the PE file.")
        return

    data_rva = settings_section.directory.entries[0].data.struct.OffsetToData
    size = settings_section.directory.entries[0].data.struct.Size
    data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

    key_size = data[0]
    rc4_key = data[1:1 + key_size]
    encrypted_config = data[1 + key_size:]

    cipher = ARC4.new(rc4_key)
    decrypted_config = cipher.decrypt(encrypted_config)

    with open(output_file_path, 'wb') as f:
        f.write(decrypted_config)

    print(f"Decrypted configuration written to {output_file_path}")

def reencrypt_remcos_config(pe_file_path, output_decrypted_config_path, output_file_path):
    """Re-encrypt the REMCOS configuration and update the PE file."""
    pe = pefile.PE(pe_file_path)

    settings_section = None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.name is None and entry.id == pefile.RESOURCE_TYPE['RT_RCDATA']:
            for sub_entry in entry.directory.entries:
                if sub_entry.name and sub_entry.name.decode() == 'SETTINGS':
                    settings_section = sub_entry
                    break

    if not settings_section:
        print("SETTINGS section not found in the PE file.")
        return

    data_rva = settings_section.directory.entries[0].data.struct.OffsetToData
    size = settings_section.directory.entries[0].data.struct.Size
    data = pe.get_memory_mapped_image()[data_rva:data_rva + size]

    key_size = data[0]
    rc4_key = data[1:1 + key_size]

    with open(output_decrypted_config_path, 'rb') as f:
        decrypted_config = f.read()

    cipher = ARC4.new(rc4_key)
    encrypted_config = cipher.encrypt(decrypted_config)

    new_data = bytes([key_size]) + rc4_key + encrypted_config

    # Replace the old "SETTINGS" data with the new data in the PE file
    pe.set_bytes_at_rva(data_rva, new_data)

    # Save the modified PE file
    pe.write(output_file_path)

    print(f"Modified PE file written to {output_file_path}")

def main():
    script_name = os.path.basename(__file__)    
    if len(sys.argv) < 2 or any(arg in sys.argv for arg in ('-h', '-help', '--h', '--help', '/h', '/help', 'help', 'h', '-?', '?', '/?')):
        print("Usage:")
        print(f"  To decrypt: python {script_name} -d <remcos_binary> <output_decrypted_config>")
        print(f"  To re-encrypt: python {script_name} -e <remcos_binary> <decrypted_config> <output_remcos_binary>")
        print(f"  To parse: python {script_name} -p <decrypted_config>")
        sys.exit(1)

    mode = sys.argv[1]
    
    if mode == "-d":
        if len(sys.argv) != 4:
            print(f"Usage: python {script_name} -d <remcos_binary> <output_decrypted_config>")
            sys.exit(1)

        pe_file_path = sys.argv[2]
        output_file_path = sys.argv[3]

        if not os.path.isfile(pe_file_path):
            print(f"Error: The file '{pe_file_path}' does not exist.")
            sys.exit(1)

        extract_remcos_config(pe_file_path, output_file_path)

    elif mode == "-e":
        if len(sys.argv) != 5:
            print(f"Usage: python {script_name} -e <remcos_binary> <decrypted_config> <output_remcos_binary>")
            sys.exit(1)

        pe_file_path = sys.argv[2]
        output_decrypted_config_path = sys.argv[3]
        output_file_path = sys.argv[4]

        if not os.path.isfile(pe_file_path):
            print(f"Error: The file '{pe_file_path}' does not exist.")
            sys.exit(1)
        if not os.path.isfile(output_decrypted_config_path):
            print(f"Error: The file '{output_decrypted_config_path}' does not exist.")
            sys.exit(1)

        reencrypt_remcos_config(pe_file_path, output_decrypted_config_path, output_file_path)

    elif mode == "-p":
        if len(sys.argv) != 3:
            print(f"Usage: python {script_name} -p <decrypted_config>")
            sys.exit(1)

        file_path = sys.argv[2]

        if not os.path.isfile(file_path):
            print(f"Error: File '{file_path}' does not exist.")
            sys.exit(1)

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = file.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin1') as file:
                data = file.read()

        parse_data(data)

    else:
        print("Error: Invalid mode. Use '-d' for decryption, '-e' for re-encryption, or '-p' for parsing.")
        sys.exit(1)

if __name__ == "__main__":
    main()
