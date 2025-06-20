import tkinter as tk
from tkinter import filedialog, messagebox, font
import os
from steganography import SteganographyProcessor
from encryption import AESEncryptor
from blockchain import Blockchain


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Image Steganography with AES & Blockchain")

        # Initialize components
        self.blockchain = Blockchain()
        self.encryptor = AESEncryptor("secure_steganography_key")
        self.steganography = SteganographyProcessor()

        # UI Configuration
        self.UISetup()

    def UISetup(self):
        """Configure the user interface"""
        self.ColorsAndFonts()
        self.MainFrame()
        self.Title()
        self.MessageBlock()
        self.Buttons()
        self.BlockchainLog()

    def ColorsAndFonts(self):
        """Define UI colors and fonts"""
        self.bg_color = "#f0f8ff"
        self.button_color = "#4682b4"
        self.entry_color = "#ffffff"
        self.text_color = "#2f4f4f"
        self.highlight_color = "#e6e6fa"

    def MainFrame(self):
        """Create the main container frame"""
        self.main_frame = tk.Frame(self.root, bg=self.bg_color, padx=25, pady=25)
        self.main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    def Title(self):
        """Create the title label"""
        title_font = font.Font(family="Helvetica", size=16, weight="bold")
        self.title_label = tk.Label(
            self.main_frame,
            text="Secure Image Steganography",
            font=title_font,
            bg=self.bg_color,
            fg=self.text_color
        )
        self.title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

    def MessageBlock(self):
        """Create message entry widgets"""
        msg_font = font.Font(family="Helvetica", size=10)

        self.message_label = tk.Label(
            self.main_frame,
            text="Secret Message:",
            font=msg_font,
            bg=self.bg_color,
            fg=self.text_color
        )
        self.message_label.grid(row=1, column=0, pady=5, sticky="w")

        self.message_entry = tk.Text(
            self.main_frame,
            width=40,
            height=5,
            font=msg_font,
            bg=self.entry_color,
            fg=self.text_color,
            wrap=tk.WORD
        )
        self.message_entry.grid(row=1, column=1, pady=5, padx=10)

    def Buttons(self):
        """Create encryption/decryption buttons"""
        button_font = font.Font(family="Helvetica", size=10, weight="bold")

        # Encrypt Button
        self.encrypt_button = tk.Button(
            self.main_frame,
            text="ENCRYPT MESSAGE IN IMAGE",
            font=button_font,
            bg=self.button_color,
            fg="white",
            command=self.encrypt_image,
            padx=15,
            pady=8,
            relief="groove",
            bd=2,
            activebackground="#5f9ea0"
        )
        self.encrypt_button.grid(row=2, column=0, pady=20, sticky="ew")

        # Decrypt Button
        self.decrypt_button = tk.Button(
            self.main_frame,
            text="DECRYPT MESSAGE FROM IMAGE",
            font=button_font,
            bg=self.button_color,
            fg="white",
            command=self.decrypt_image,
            padx=15,
            pady=8,
            relief="groove",
            bd=2,
            activebackground="#5f9ea0"
        )
        self.decrypt_button.grid(row=2, column=1, pady=20, sticky="ew")

    def BlockchainLog(self):
        """Create blockchain transaction log display"""
        log_font = font.Font(family="Courier New", size=9)

        self.blockchain_log = tk.Label(
            self.main_frame,
            text="Blockchain Transaction Log:",
            font=log_font,
            bg=self.bg_color,
            fg=self.text_color
        )
        self.blockchain_log.grid(row=3, column=0, columnspan=2, pady=(20, 5), sticky="w")

        self.blockchain_log_text = tk.Text(
            self.main_frame,
            height=10,
            width=70,
            font=log_font,
            bg=self.highlight_color,
            fg="#000080",
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.blockchain_log_text.grid(row=4, column=0, columnspan=2, pady=(0, 10))

        # Add scrollbar
        scrollbar = tk.Scrollbar(self.main_frame, command=self.blockchain_log_text.yview)
        scrollbar.grid(row=4, column=2, sticky="ns")
        self.blockchain_log_text.config(yscrollcommand=scrollbar.set)

    def encrypt_image(self):
        """Handle image encryption process"""
        message = self.message_entry.get("1.0", tk.END).strip()
        if not message:
            messagebox.showwarning("Input Error", "Please enter a message to encrypt.")
            return

        image_path = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("PNG Images", "*.png")]
        )
        if not image_path:
            return

        try:
            # Encrypt message
            encrypted_msg = self.encryptor.encrypt(message)
            binary_msg = self.BinaryMessage(encrypted_msg + b'ENDOFMSG')

            # Embed in image
            encrypted_image = self.steganography.embed_message(image_path, binary_msg)

            # Save result
            save_path = filedialog.asksaveasfilename(
                title="Save Encrypted Image",
                defaultextension=".png",
                filetypes=[("PNG Image", "*.png")]
            )
            if save_path:
                self.steganography.save_image(encrypted_image, save_path)
                self.blockchain.add_transaction(
                    f"Encrypted message into {os.path.basename(save_path)}"
                )
                self._update_blockchain_log()
                messagebox.showinfo(
                    "Success",
                    f"Message successfully encrypted and saved to:\n{save_path}"
                )
        except Exception as e:
            messagebox.showerror("Encryption Error", f"Error during encryption: {str(e)}")

    def BinaryMessage(self, message):
        """Convert message (bytes) to binary string"""
        return ''.join(format(byte, '08b') for byte in message)

    def _update_blockchain_log(self):
        """Update the blockchain transaction log display"""
        log_text = "Blockchain Transactions:\n\n"
        for block in self.blockchain.chain:
            log_text += (
                f"Block {block['index']} ({block['timestamp']}):\n"
                f"• Data: {block['transaction_data']}\n"
                f"• Hash: {block['hash']}\n"
                f"• Prev: {block['previous_hash']}\n\n"
            )

        self.blockchain_log_text.config(state=tk.NORMAL)
        self.blockchain_log_text.delete(1.0, tk.END)
        self.blockchain_log_text.insert(tk.END, log_text)
        self.blockchain_log_text.config(state=tk.DISABLED)
        self.blockchain_log_text.see(tk.END)

    def decrypt_image(self):
        """Handle image decryption process"""
        image_path = filedialog.askopenfilename(
            title="Select Image with Hidden Message",
            filetypes=[("PNG Images", "*.png")]
        )
        if not image_path:
            return

        try:
            extracted_message = self._extract_message_from_image(image_path)
            if extracted_message:
                self.blockchain.add_transaction(
                    f"Decrypted message from {os.path.basename(image_path)}"
                )
                self._update_blockchain_log()
                self.DecryptedMessage(extracted_message)
        except Exception as e:
            messagebox.showerror("Decryption Error", f"Error decrypting image: {str(e)}")

    def _extract_message_from_image(self, image_path):
        """Extract and decrypt message from image"""
        termination_seq = self.BinaryMessage(b'ENDOFMSG')
        binary_msg = self.steganography.extract_message(image_path, termination_seq)
        encrypted_msg = self.OriginalMessage(binary_msg)
        return self.encryptor.decrypt(encrypted_msg)

    def OriginalMessage(self, binary_str):
        """Convert binary string to bytes"""
        if len(binary_str) % 8 != 0:
            binary_str = binary_str[:-(len(binary_str) % 8)]
        return bytes(int(binary_str[i:i + 8], 2) for i in range(0, len(binary_str), 8))

    def DecryptedMessage(self, message):
        """Display decrypted message in a new window"""
        result_window = tk.Toplevel(self.root)
        result_window.title("Decrypted Message")
        result_window.geometry("500x300")
        result_window.configure(bg=self.bg_color)

        # Title
        title_label = tk.Label(
            result_window,
            text="SECRET MESSAGE FOUND",
            font=("Helvetica", 14, "bold"),
            bg=self.bg_color,
            fg="#8b0000"
        )
        title_label.pack(pady=10)

        # Message display
        msg_frame = tk.Frame(result_window, bg=self.entry_color, padx=10, pady=10)
        msg_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)

        text_widget = tk.Text(
            msg_frame,
            wrap=tk.WORD,
            font=("Courier New", 12),
            bg=self.entry_color,
            fg=self.text_color,
            padx=10,
            pady=10
        )
        text_widget.insert(tk.END, message)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True)

        # Scrollbar
        scrollbar = tk.Scrollbar(msg_frame, command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.config(yscrollcommand=scrollbar.set)

        # Close button
        close_button = tk.Button(
            result_window,
            text="CLOSE",
            command=result_window.destroy,
            bg=self.button_color,
            fg="white",
            padx=20,
            pady=5
        )
        close_button.pack(pady=10)