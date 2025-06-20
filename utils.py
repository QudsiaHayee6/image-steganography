def message_to_binary(message):
    """Convert message (bytes) to binary string"""
    return ''.join(format(byte, '08b') for byte in message)

def binary_to_message(binary_str):
    """Convert binary string to bytes"""
    if len(binary_str) % 8 != 0:
        binary_str = binary_str[:-(len(binary_str) % 8)]
    return bytes(int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8))