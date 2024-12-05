# 查詢 mnemonic 對應的 opcode , 無則返回 invalid
def lookup_opcode(mnemonic, opcode_table):
    return opcode_table.get(mnemonic, "invalid")

def main():
    # 讀取 opcode_table 檔案
    file_path = r"opCode.txt"
    # 初始化 opcode_table
    opcode_table = {}
    try:
        # 打開檔案並讀取內容
        with open(file_path, 'r') as file:
            # 解析檔案內容，對應 mnemonic 和 opcode
            for line in file:
                mnemonic, opcode = line.strip().split()
                opcode_table[mnemonic] = opcode
    except FileNotFoundError:
        print("File Not Found")
        return

    # 輸入 mnemonic
    mnemonic = input("search ( Input a mnemonic) : ").strip().upper()

    # 查詢並輸出對應的 opcode
    opcode = lookup_opcode(mnemonic, opcode_table)
    print(f"opCode : {opcode}")

# 當程式直接執行時（不是被引入其他程式中），執行 main()
if __name__ == "__main__":
    main()