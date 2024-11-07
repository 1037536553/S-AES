import forward as fw
import inverse as iv
import tkinter as tk
from tkinter import messagebox

def s_aes_encrypt(plaintext, key):
    # 生成子密钥
    # 初始轮密钥加
    #print("加密")
    #print("初始",plaintext)
    state = fw.add_round_key(plaintext, key)
    #print("第一轮密钥加",state)
    K1,K2=fw.KEY3(key)

    # 第一轮
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]
    #print("半字节处理前",state)
    state = fw.byte_substitution(state)#半字节代替，需要用16进制数
    #print("半字节处理1",state)

    state = fw.shift_rows(state) #行移位，4个16位
    #print("行1",state)

    state = fw.mix_columns(state) #列混淆
    #print("列1",state)

    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    #print("第2轮密相加前",state)
    state = fw.add_round_key(state, K1) #轮密相加
    #print("轮密相加2",state)
    
    # 第二轮
    #print("半字节处理前",state)
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]
    state = fw.byte_substitution(state) #半字节代替
    #print("半字节2",state)

    state = fw.shift_rows(state) #行位移
    #print("行2",state)

    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    #print("第三轮密钥加前",state)
    state = fw.add_round_key(state, K2) #密钥加
    #print("输出",state)
    #print("三轮密")

    return state

def s_aes_decrypt(ciphertext, key):
    # 生成子密钥
    K1, K2 = fw.KEY3(key)

    # 初始轮密钥加
    #print("初始",ciphertext)
    state = iv.add_round_key(ciphertext, K2)
    #print("第三轮密钥加上",state)
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]

    # 第二轮
    state = iv.shift_rows(state)
    #print("移位",state)
    
    state = iv.byte_substitution(state)
    #print("半字节",state)
    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    #print("二轮密钥加下",state)
    state = iv.add_round_key(state, K1)
    #print("二密钥加上",state)
    state = [int(''.join(map(str, state[i:i+4])), 2) for i in range(0, len(state), 4)]
    # 第一轮
    #print("混淆下",state)
    state = iv.mix_columns(state)
    #print("混淆上",state)
    state = iv.shift_rows(state)
    #print("行移位上",state)
    state = iv.byte_substitution(state)
    #print("半字节上",state)
    state = [int(bit) for num in state for bit in format(num, '04b')]#16to2
    #print("一轮前",state)
    state = iv.add_round_key(state, key)
    #print(state)

    return state


def meet_in_the_middle_attack(plaintext, ciphertext):
    # 查找可能得中间值及其密钥
    intermediate_dict = {}
    
    # 生成所有可能的K1和K2
    for k1 in range(0, 65536):  # K1从0到15
        key = [int(bit) for bit in format(k1, '016b')]
            
        # 加密明文得到中间值
        intermediate_value = s_aes_encrypt(plaintext, key)
        # 存储中间值和对应的密钥
        if tuple(intermediate_value) not in intermediate_dict:
            intermediate_dict[tuple(intermediate_value)] = []
        intermediate_dict[tuple(intermediate_value)].append(key)

    # 存储所有中间值的字典
    found_keys = []#存储找到的密钥组合
    # 遍历所有可能的K1和K2
    for k1 in range(0, 65536):

        key = [int(bit) for bit in format(k1, '016b')]

        # 反向解密密文得到中间值
        intermediate_value = s_aes_decrypt(ciphertext, key)
            
        # 检查是否存在相同的中间值
        if tuple(intermediate_value) in intermediate_dict:
            for left_key in intermediate_dict[tuple(intermediate_value)]:
                found_keys.append((left_key, key))
    if found_keys:
        for left,right  in found_keys:
            print(f"找到匹配的密钥: KL={left}, KR={right} (对应中间值: {intermediate_value})")
            print(f"原密钥组合: {left+right}")
    else:
        print("未找到匹配的密钥")
    return None

def miss_attack():
    # 获取用户输入的密文和密钥
    ciphertext = input_entry.get()
    key = key_entry.get()

# 检查密钥长度
    if len(key) != 16 or len(ciphertext) != 16:
        messagebox.showerror("Error", "明密文必须是16位")
        return


        # 输入为16位二进制
    try:
        ciphertext_bits = [int(x) for x in ciphertext]
        key_bits = [int(x) for x in key]
        meet_in_the_middle_attack(ciphertext_bits,key_bits)
    except Exception as e:
        messagebox.showerror("Error", str(e))



# GUI界面设置
root = tk.Tk()
root.title("S-AES 加密/解密")

# 输入字段
tk.Label(root, text="明文 (16位二进制):").grid(row=0, column=0)
input_entry = tk.Entry(root,width=40)
input_entry.grid(row=0, column=1)

tk.Label(root, text="密文 (16位二进制):").grid(row=1, column=0)
key_entry = tk.Entry(root,width=40)
key_entry.grid(row=1, column=1)

# 攻击按钮
encrypt_button = tk.Button(root, text="攻击", command=miss_attack)
encrypt_button.grid(row=2, column=0)

# 打开GUI
root.mainloop()
