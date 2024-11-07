import tkinter as tk
from tkinter import messagebox
import forward as fw
import inverse as iv
def s_aes_encrypt(plaintext, key):
    # 生成子密钥
    # 初始轮密钥加
    print("加密")
    print("初始",plaintext)
    state = fw.add_round_key(plaintext, key)
    print("第一轮密钥加",state)
    K1,K2=fw.KEY3(key)

    # 第一轮
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]
    print("半字节处理前",state)
    state = fw.byte_substitution(state)#半字节代替，需要用16进制数
    print("半字节处理1",state)

    state = fw.shift_rows(state) #行移位，4个16位
    print("行1",state)

    state = fw.mix_columns(state) #列混淆
    print("列1",state)

    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    print("第2轮密相加前",state)
    state = fw.add_round_key(state, K1) #轮密相加
    print("轮密相加2",state)
    
    # 第二轮
    print("半字节处理前",state)
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]
    state = fw.byte_substitution(state) #半字节代替
    print("半字节2",state)

    state = fw.shift_rows(state) #行位移
    print("行2",state)

    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    print("第三轮密钥加前",state)
    state = fw.add_round_key(state, K2) #密钥加
    print("输出",state)
    print("三轮密")

    return state

def s_aes_decrypt(ciphertext, key):
    # 生成子密钥
    K1, K2 = fw.KEY3(key)

    # 初始轮密钥加
    print("初始",ciphertext)
    state = iv.add_round_key(ciphertext, K2)
    print("第三轮密钥加上",state)
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]

    # 第二轮
    state = iv.shift_rows(state)
    print("移位",state)
    
    state = iv.byte_substitution(state)
    print("半字节",state)
    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    print("二轮密钥加下",state)
    state = iv.add_round_key(state, K1)
    print("二密钥加上",state)
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]
    # 第一轮
    print("混淆下",state)
    state = iv.mix_columns(state)
    print("混淆上",state)
    state = iv.shift_rows(state)
    print("行移位上",state)
    state = iv.byte_substitution(state)
    print("半字节上",state)
    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    print("一轮前",state)
    state = iv.add_round_key(state, key)
    print(state)

    return state

def open_double_encryption_window():
    double_root=tk.Tk()
    #double_window = tk.Toplevel(double_root)
    double_root.title("双重加密")
    
    tk.Label(double_root, text="输入 (16位二进制):").grid(row=0, column=0)
    input_entry_double = tk.Entry(double_root,width=40)
    input_entry_double.grid(row=0, column=1)

    tk.Label(double_root, text="密钥 (32位二进制):").grid(row=1, column=0)
    key_entry_double = tk.Entry(double_root, width=40)
    key_entry_double.grid(row=1, column=1)

    result_entry_double = tk.Entry(double_root)
    result_entry_double.grid(row=4, column=1)

    def encrypt_callback_double():
        plaintext = input_entry_double.get()
        key = key_entry_double.get()
        if len(key) != 32:
            messagebox.showerror("Error", "密钥必须是32位")
            return
        if len(plaintext) == 16 and all(bit in '01' for bit in plaintext):
            plaintext_bits = [int(x) for x in plaintext]
            key_bits = [int(x) for x in key]
            key1=key_bits[:16]
            key2=key_bits[16:]
            encrypted_bits = s_aes_encrypt(plaintext_bits, key1)
            encrypted_bits = s_aes_encrypt(encrypted_bits,key2)
            result_entry_double.delete(0, tk.END)
            result_entry_double.insert(0, ''.join(map(str, encrypted_bits)))
        else:
            messagebox.showerror("Error", "明文必须是16位二进制")

    def decrypt_callback_double():
        ciphertext = input_entry_double.get()
        key = key_entry_double.get()
        if len(key) != 32:
            messagebox.showerror("Error", "密钥必须是32位")
            return
        if len(ciphertext) == 16 and all(bit in '01' for bit in ciphertext):
            ciphertext_bits = [int(x) for x in ciphertext]
            key_bits = [int(x) for x in key]
            key1=key_bits[:16]
            key2=key_bits[16:]
            decrypted_bits = s_aes_decrypt(ciphertext_bits, key2)
            decrypted_bits = s_aes_decrypt(decrypted_bits,key1)
            result_entry_double.delete(0, tk.END)
            result_entry_double.insert(0, ''.join(map(str, decrypted_bits)))
        else:
            messagebox.showerror("Error", "密文必须是16位二进制")

    def encrypt_callback_three():
        plaintext = input_entry_double.get()
        key = key_entry_double.get()
        if len(key) != 48:
            messagebox.showerror("Error", "密钥必须是48位")
            return
        if len(plaintext) == 16 and all(bit in '01' for bit in plaintext):
            plaintext_bits = [int(x) for x in plaintext]
            key_bits = [int(x) for x in key]
            key1=key_bits[:16]
            key2=key_bits[16:32]
            key3=key_bits[32:]
            encrypted_bits = s_aes_encrypt(plaintext_bits, key1)
            encrypted_bits = s_aes_encrypt(encrypted_bits,key2)
            encrypted_bits = s_aes_encrypt(encrypted_bits,key3)
            result_entry_double.delete(0, tk.END)
            result_entry_double.insert(0, ''.join(map(str, encrypted_bits)))
        else:
            messagebox.showerror("Error", "明文必须是16位二进制")

    def decrypt_callback_three():
        ciphertext = input_entry_double.get()
        key = key_entry_double.get()
        if len(key) != 48:
            messagebox.showerror("Error", "密钥必须是48位")
            return
        if len(ciphertext) == 16 and all(bit in '01' for bit in ciphertext):
            ciphertext_bits = [int(x) for x in ciphertext]
            key_bits = [int(x) for x in key]
            key1=key_bits[:16]
            key2=key_bits[16:32]
            key3=key_bits[32:]
            decrypted_bits = s_aes_decrypt(ciphertext_bits, key3)
            decrypted_bits = s_aes_decrypt(decrypted_bits,key2)
            decrypted_bits = s_aes_decrypt(decrypted_bits,key1)
            result_entry_double.delete(0, tk.END)
            result_entry_double.insert(0, ''.join(map(str, decrypted_bits)))
        else:
            messagebox.showerror("Error", "密文必须是16位二进制")

    encrypt_button_double = tk.Button(double_root, text="二重加密", command=encrypt_callback_double)
    encrypt_button_double.grid(row=2, column=0)

    decrypt_button_double = tk.Button(double_root, text="二重解密", command=decrypt_callback_double)
    decrypt_button_double.grid(row=2, column=1)

    encrypt_button_three = tk.Button(double_root, text="三重加密", command=encrypt_callback_three)
    encrypt_button_three.grid(row=3, column=0)

    decrypt_button_three = tk.Button(double_root, text="三重解密", command=decrypt_callback_three)
    decrypt_button_three.grid(row=3, column=1)
    tk.Label(double_root, text="结果:",width=40).grid(row=4, column=0)
