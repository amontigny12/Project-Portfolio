import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog


def caesar_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('A') if char.isupper() else ord('a')
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text


def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)


def encrypt_file():
    filepath = filedialog.askopenfilename(title="Select File to Encrypt")
    if not filepath:
        return

    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
    except Exception as e:
        messagebox.showerror("Error", f"Unable to read the file: {e}")
        return

    shift = shift_key_prompt("encrypt")
    if shift is None:
        return

    encrypted_content = caesar_encrypt(content, shift)

    output_filepath = filedialog.asksaveasfilename(
        title="Save Encrypted File As",
        defaultextension=".enc",
        filetypes=[("Encrypted Files", "*.enc"), ("All Files", "*.*")]
    )
    if not output_filepath:
        return

    try:
        with open(output_filepath, 'w', encoding='utf-8') as file:
            file.write(encrypted_content)
        messagebox.showinfo("Success", f"File encrypted and saved as {output_filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Unable to save the file: {e}")


def decrypt_file():
    filepath = filedialog.askopenfilename(title="Select File to Decrypt")
    if not filepath:
        return

    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
    except Exception as e:
        messagebox.showerror("Error", f"Unable to read the file: {e}")
        return

    shift = shift_key_prompt("decrypt")
    if shift is None:
        return

    decrypted_content = caesar_decrypt(content, shift)

    output_filepath = filedialog.asksaveasfilename(
        title="Save Decrypted File As",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if not output_filepath:
        return

    try:
        with open(output_filepath, 'w', encoding='utf-8') as file:
            file.write(decrypted_content)
        messagebox.showinfo("Success", f"File decrypted and saved as {output_filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Unable to save the file: {e}")


def shift_key_prompt(action):
    shift = simpledialog.askinteger(
        "Shift Key", f"Enter the shift key to {action} the file (1-25):", minvalue=1, maxvalue=25
    )
    if shift is None:
        messagebox.showinfo("Cancelled", "Operation cancelled.")
    return shift


def show_caesar_info():
    messagebox.showinfo(
        "What is a Caesar Cipher?",
        "A Caesar cipher is a substitution cipher that shifts each letter in the plaintext "
        "by a fixed number of positions in the alphabet. For example, with a shift of 3, "
        "A becomes D, B becomes E, and so on. This technique was named after Julius Caesar, "
        "who used it to encode military messages."
    )


def main():
    root = tk.Tk()
    root.title("Caesar Cipher File Encryption")
    root.geometry("600x300")  

    encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_file, width=25, height=2)
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file, width=25, height=2)
    decrypt_button.pack(pady=10)

    info_button = tk.Button(root, text="What is a Caesar Cipher?", command=show_caesar_info, width=25, height=2)
    info_button.pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
