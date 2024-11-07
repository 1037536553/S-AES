import tkinter as tk
from tkinter import messagebox
import forward as fw
import inverse as iv
import 多重 as db
# S-AES S盒和逆S盒
SBOX = [
    [9, 4, 10, 11],
    [13, 1, 8, 5],
    [6, 2, 0, 3],
    [12, 14, 15, 7]
]

INVERSE_SBOX = [
    [10, 5, 9, 11],
    [1, 7, 8, 15],
    [6, 0, 2, 3],
    [12, 4, 13, 14]
]
rcon=[[1,0,0,0,0,0,0,0],[0,0,1,1,0,0,0,0]]
rcon1=[0,0,1,1,0,0,0,0]


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

def ascii_to_binary(s):
    return [int(bit) for char in s for bit in format(ord(char), '08b')]

def binary_to_ascii(bits):
    chars = [chr(int(''.join(map(str, bits[i:i+8])), 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

def encrypt_pair(pair, key):
    plaintext_bits = ascii_to_binary(pair)
    key_bits = [int(x) for x in key]
    encrypted_bits = s_aes_encrypt(plaintext_bits, key_bits)
    return binary_to_ascii(encrypted_bits)

def decrypt_pair(pair, key):
    ciphertext_bits = ascii_to_binary(pair)
    key_bits = [int(x) for x in key]
    decrypted_bits = s_aes_decrypt(ciphertext_bits, key_bits)
    return binary_to_ascii(decrypted_bits)

def encrypt_callback():
    # 获取用户输入的明文和密钥
    plaintext = input_entry.get()
    key = key_entry.get()
    # 检查输入长度是否正确
    if len(key) != 16:
        messagebox.showerror("Error", "密钥必须是16位")
        return
    if len(plaintext) == 16 and all(bit in '01' for bit in plaintext):
        try:#16位二进制
            # 将输入转换为二进制格式并进行加密
            plaintext_bits = [int(x) for x in plaintext]
            key_bits = [int(x) for x in key]
            encrypted_bits = s_aes_encrypt(plaintext_bits, key_bits)
            # 将加密结果显示在结果框中
            result_entry.delete(0, tk.END)
            result_entry.insert(0, ''.join(map(str, encrypted_bits)))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    elif len(plaintext) >= 2:
        # 输入为ASCII，进行处理
        try:
            encrypted_result = ""
            for i in range(0, len(plaintext), 2):
                pair = plaintext[i:i + 2]  # 每两位字符一组
                if len(pair) < 2:
                    continue  # 如果最后剩下一个字符，跳过
                encrypted_result += encrypt_pair(pair, key)

            result_entry.delete(0, tk.END)
            result_entry.insert(0, encrypted_result)
        except Exception as e:
            messagebox.showerror("Error", str(e))


def decrypt_callback():
    # 获取用户输入的密文和密钥
    ciphertext = input_entry.get()
    key = key_entry.get()

# 检查密钥长度
    if len(key) != 16:
        messagebox.showerror("Error", "密钥必须是16位")
        return

    # 检查输入长度和内容
    if len(ciphertext) == 16 and all(bit in '01' for bit in ciphertext):
        # 输入为16位二进制
        try:
            ciphertext_bits = [int(x) for x in ciphertext]
            key_bits = [int(x) for x in key]
            decrypted_bits = s_aes_decrypt(ciphertext_bits, key_bits)
            result_entry.delete(0, tk.END)
            result_entry.insert(0, ''.join(map(str, decrypted_bits)))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    elif len(ciphertext) >= 2:
        # 输入为ASCII，进行处理
        try:
            decrypted_result = ""
            for i in range(0, len(ciphertext), 2):
                pair = ciphertext[i:i + 2]  # 每两位字符一组
                if len(pair) < 2:
                    continue  # 如果最后剩下一个字符，跳过
                decrypted_result += decrypt_pair(pair, key)

            result_entry.delete(0, tk.END)
            result_entry.insert(0, decrypted_result)
        except Exception as e:
            messagebox.showerror("Error", str(e))


# GUI界面设置
root = tk.Tk()
root.title("S-AES 加密/解密")

# 输入字段
tk.Label(root, text="输入 (16位二进制):").grid(row=0, column=0)
input_entry = tk.Entry(root,width=40)
input_entry.grid(row=0, column=1)

tk.Label(root, text="密钥 (16位二进制):").grid(row=1, column=0)
key_entry = tk.Entry(root,width=40)
key_entry.grid(row=1, column=1)

# 加密按钮
encrypt_button = tk.Button(root, text="加密", command=encrypt_callback)
encrypt_button.grid(row=2, column=0)

# 解密按钮
decrypt_button = tk.Button(root, text="解密", command=decrypt_callback)
decrypt_button.grid(row=2, column=1)

# 结果字段
tk.Label(root, text="结果:").grid(row=3, column=0)
result_entry = tk.Entry(root,width=40)
result_entry.grid(row=3, column=1)
# 多重加密按钮
double_encrypt_button = tk.Button(root, text="多重加密", command=db.open_double_encryption_window)
double_encrypt_button.grid(row=4, column=1)
# 打开GUI
root.mainloop()
