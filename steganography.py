import cv2
import numpy as np
class SteganographyProcessor:
    @staticmethod
    def embed_message(image_path, binary_message):
        """Embed binary message into image using LSB steganography"""
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Could not read image file")

        if len(binary_message) > img.size * 3:
            raise ValueError(
                f"Message too large. Needs {len(binary_message)} bits "
                f"but image has only {img.size * 3} bits capacity"
            )

        data_index = 0
        for row in img:
            for pixel in row:
                for color in range(3):  # R, G, B channels
                    if data_index < len(binary_message):
                        pixel[color] = (pixel[color] & 0xFE) | int(binary_message[data_index])
                        data_index += 1
                    else:
                        return img
        return img

    @staticmethod
    def extract_message(image_path, termination_seq):
        """Extract binary message from image using LSB steganography"""
        img = cv2.imread(image_path)
        if img is None:
            raise ValueError("Could not read image file")

        binary_msg = ''
        for row in img:
            for pixel in row:
                for color in range(3):
                    binary_msg += str(pixel[color] & 1)

        end_index = binary_msg.find(termination_seq)
        if end_index == -1:
            raise ValueError("No termination sequence found - may not contain a message")

        return binary_msg[:end_index]

    @staticmethod
    def save_image(img, path):
        """Save image to file"""
        if not cv2.imwrite(path, img):
            raise Exception("Failed to save image")