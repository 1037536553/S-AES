#加密算法
#GF2^4
GFa=[[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
[1,0,3,2,5,4,7,6,9,8,11,10,13,12,15,14],
[2,3,0,1,6,7,4,5,10,11,8,9,14,15,12,13],
[3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12],
[4,5,6,7,0,1,2,3,12,13,14,15,8,9,10,11],
[5,4,7,6,1,0,3,2,13,12,15,14,9,8,11,10],
[6,7,4,5,2,3,0,1,14,15,12,13,10,11,8,9],
[7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8],
[8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7],
[9,8,11,10,13,12,15,14,1,0,3,2,5,4,7,6],
[10,11,8,9,14,15,12,13,2,3,0,1,6,7,4,5],
[11,10,9,8,15,14,13,12,3,2,1,0,7,6,5,4],
[12,13,14,15,8,9,10,11,4,5,6,7,0,1,2,3],
[13,12,15,14,9,8,11,10,5,4,7,6,1,0,3,2],
[14,15,12,13,10,11,8,9,6,7,4,5,2,3,0,1],
[15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0]]
GFm=[
[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
[0,2,4,6,8,10,12,14,3,1,7,5,11,9,15,13],
[0,3,6,5,12,15,10,9,11,8,13,14,7,4,1,2],
[0,4,8,12,3,7,11,15,6,2,14,10,5,1,13,9],
[0,5,10,15,7,2,13,8,14,11,4,1,9,12,3,6],
[0,6,12,10,11,13,7,1,5,3,9,15,14,8,2,4],
[0,7,14,9,15,8,1,6,13,10,3,4,2,5,12,11],
[0,8,3,11,6,14,5,13,12,4,15,7,10,2,9,1],
[0,9,1,8,2,11,3,10,4,13,5,12,6,15,7,14],
[0,10,7,13,14,4,9,3,15,5,8,2,1,11,6,12],
[0,11,5,14,10,1,15,4,7,12,2,9,13,6,8,3],
[0,12,11,7,5,9,14,2,10,6,1,13,15,3,4,8],
[0,13,9,4,1,12,8,5,2,15,11,6,3,14,10,7],
[0,14,15,1,13,3,2,12,9,7,6,8,4,10,11,5],
[0,15,13,2,9,6,4,11,1,14,12,3,8,7,5,10]
 ]
#S盒
SBOX = [
    [9, 4, 10, 11],
    [13, 1, 8, 5],
    [6, 2, 0, 3],
    [12, 14, 15, 7]
]
rcon=[[1,0,0,0,0,0,0,0],[0,0,1,1,0,0,0,0]]
# 密钥扩展
def key_expansion(key,n):
    #print("KEY扩展开始")
    # 密钥分半
    key_left = key[:8]#左半密钥
    key_right = key[8:]#右半密钥
    key_new_left=left_shift(key_right,4) # 第i-1个密钥右半部分左循环移位
    key_new_left_0=key_new_left[:4]
    key_new_left_1=key_new_left[4:]
    key_new_left_0=s_box(key_new_left_0,SBOX) # 字节替换
    key_new_left_1=s_box(key_new_left_1,SBOX)
    key_new_left=key_new_left_0+key_new_left_1

    key_new_left = [key_new_left[i] ^ rcon[n][i] for i in range(8)]  # 与轮常数异或
    key_new_left = [key_new_left[i] ^ key_left[i] for i in range(8)] # 与w_0异或

    #右半部分
    key_new_right=[key_new_left[i] ^ key_right[i]for i in range(8)] #新key左半与旧key右半异或

    new_key=key_new_left+key_new_right
    #print("KEY扩展结束")
    return new_key
def KEY3(key):
    K1=key_expansion(key=key,n=0)
    K2=key_expansion(key=K1,n=1)
    return K1,K2
def left_shift(bits, shifts):
    # 对输入的比特串进行左移操作
    return bits[shifts:] + bits[:shifts]

def s_box(bits, sbox):
    # 根据行（首尾两位）和列（中间两位）选择S盒的值
    row = (bits[0] << 1) + bits[1]  # 前两位组成行
    col = (bits[2] << 1) + bits[3]  # 后两位组成列
    return [int(x) for x in format(sbox[row][col], "04b")]

def add_round_key(state, key):
    #print(state,key)
    return [state[i] ^ key[i] for i in range(16)]

def byte_substitution(state):
    return [SBOX[state[i] // 4][state[i] % 4] for i in range(len(state))]

def shift_rows(state):
    return [
        state[0],state[1],
        state[3],state[2]
    ]

def mix_columns(state):
    #state[0],state[1]
    #state[2],state[3]
    new_state = [0] * 4
    #newstate[0]=s[0]+4*s[2]
    new_state[0]=GFm[4][state[2]]
    new_state[0]=GFa[new_state[0]][state[0]]

    #newstate[1]=s[1]+4*s[3]
    new_state[1]=GFm[4][state[3]]
    new_state[1]=GFa[new_state[1]][state[1]]

    #newstate[2]=s[2]+4*s[0]
    new_state[2]=GFm[4][state[0]]
    new_state[2]=GFa[new_state[2]][state[2]]

    #newstate[3]=s[3]+4*s[1]
    new_state[3]=GFm[4][state[1]]
    new_state[3]=GFa[new_state[3]][state[3]]

    return new_state