import sys

def passTwo( symbol_table, middleFile, errorStatus):

    ObjectCode=[]               # 放各個指令的 objectcode
    for line in middleFile:     # 開始跑每一行指令
        #前面有錯誤訊息
        if errorStatus != [] and len(line)<3 and line[1] not in symbol_table:
            if not line[1].isdigit():
                errorStatus.append(f"找不到 symbol ({line[1]}) in line : {line[0]}")
            continue

        elif errorStatus != [] and line[1] in symbol_table:
            continue

        #前面無錯誤訊息
        # 38 204e *** STCH BUFFER,X 54 indexed
        elif line[4] not in symbol_table and line[4].split(",")[0] not in symbol_table and "'" not in line[4] and line[4]!="***" and not line[4].isdigit():
            errorStatus.append(f"找不到 symbol ({line[4]}) in line : {line[0]}")
            continue

        if errorStatus == []:
            # START END RESW RESB 的 objectcode 為空
            if line[3] == "START" or line[3] == "END" or line[3] == "RESW" or line[3] == "RESB":
                ObjectCode.append("")
                continue

            # 如果是索引定址，objectcode 為 opcode + operand(label loc + x register)
            # ex: *** STCH BUFFER,X 54 indexed
            elif line[6] == "indexed":
                opCode = line[5]                                      # 54
                operand=hex(int(symbol_table[line[4].split(",")[0]],16)+int("8000",16))[2:].upper()  # 1039+ 8000 (xbpe=(1000)10=(8)16)
                objectCode = opCode+operand
                ObjectCode.append(objectCode)

            # 如果 mnemonic 為 RSUB，objectcode 為 RSUB opcode + 0000
            elif line[3] == "RSUB":
                opCode = line[5]
                objectCode = opCode+"0000"
                ObjectCode.append(objectCode)

            # 如果 mnemonic 為 WORD，objectcode 為 00 + operand(十進位轉十六進位)
            elif line[3] == "WORD":
                opCode = "00"
                operand = str(format(int(line[4]), '04X'))  # ex: (1000)10 -> (3EB)16
                objectCode = opCode+operand
                ObjectCode.append(objectCode)
            
            # 如果 BYTE X'(十六進位)'，objectcode 為 (十六進位)
            # 如果 BYTE C'(string)'，objectcode 為 (string 的 ASCII 碼)
            elif line[3] == "BYTE":
                # print(Operand[num])
                parts = line[4].strip().split("'")
                # print(parts)
                if parts[0] == "X":
                    objectCode = parts[1]
                    ObjectCode.append(str(objectCode))
                elif parts[0] == "C":
                    objectCode = ''.join([format(ord(char), '02X') for char in parts[1]]) # 轉換為對應的ASCII碼
                    ObjectCode.append(objectCode)
            
            # 剩下的 objectcode 都是 opcode + operand(loc)
            else:
                opCode = line[5]
                operand=symbol_table[line[4]]
                objectCode = opCode + operand
                ObjectCode.append(objectCode)
    # print(ObjectCode)

    # 錯誤訊息陣列中有錯誤訊息的話，輸出錯誤訊息並結束程式
    if errorStatus!=[]:
        for i in errorStatus:
            print(i)
        sys.exit()
    # 把 Objectcode 按 object program 格式一列列放入 result[]
    current = []
    result = []
    length = 0
    for i in ObjectCode:
        if i:  # 不為空
            if length + len(i) / 2 > 30:  # 加上 i 之後會超過30，就改放在下一行
                result.append(current)
                current = []
                length = 0
            current.append(i)
            length += len(i) / 2
        else:
            result.append(current)
            current = []
            length = 0
    # print(result)
    print("symbol table :")
    print(symbol_table)
    print("----")
    print("pass two :")
    # 輸出 object program
    output_lines = []
    # Header record
    header = f"H {middleFile[0][2].ljust(6)} {hex(int(middleFile[0][1],16))[2:].zfill(6)} {hex(int(middleFile[-1][1],16)-int(middleFile[0][1],16))[2:].zfill(6)}"
    print(header)
    output_lines.append(header)

    size = 0
    for sublist in result:
        if sublist == []:
            size = 0
            continue
        for i in sublist:
            size += int(len(i)/2)
        pos = ObjectCode.index(sublist[0])
        text_record = f"T {hex(int(middleFile[pos][1],16))[2:].zfill(6)} {hex(size)[2:].zfill(2)} {' '.join(sublist).upper()}"
        print(text_record)
        output_lines.append(text_record)
        size = 0

    # End label，可以改
    endLabel = symbol_table[middleFile[-1][4]]
    end_record = f"E {hex(int(endLabel,16))[2:].zfill(6)}"
    print(end_record)
    output_lines.append(end_record)

    # Write to file
    with open("110213018陳宣閔_passTwo_output.txt", "w") as file:
        for line in output_lines:
            file.write(line + "\n")

def passOne(file_path, opcode_table):
    with open(file_path, 'r') as file, open('110213018陳宣閔_passOne_output.txt','w') as PassOne_output_file:
        num = 0                                              # 程式碼行數(包括註解及空白行)
        errorStatus = []                                     # 錯誤訊息
        operandConfirm=[]                                    # 放 operand (當影錯誤訊息時，看這個判斷有無 symbol)
        firstIn = False                                      # 紀錄是不是第一次進入正式的指令
        firstCommand = True                                  # 如果第一次進入正式的指令(firstIn = True)，就會變成 False用來做跟第一行指令 (start) 有關的判斷
        loc = [None] * 2                                     # 這行指令的 loc , 下一行的 loc
        mnemonic = ""                                        # 這一行指令的 mnemonic
        opcode = ""                                          # 這一行指令的 opcode
        current=[]                                           # 放這一行指令的 num loc label mnemonic operand opcode addressing
        result=[]                                            # 放 current
        special={"START","END","WORD","BYTE","RESW","RESB"}  # 不在 optable 的 mnenomic
        endCorrect = False                                   # 做跟 最後一行指令的相關的判斷
        symbol_table={}

        for line in file:
            byteParts = [None] *2  # 用來處理 BYTE 的 operand
            num += 1               # 程式碼第幾行 (註解空白也算)
            addressing ="direct"   # 一開始都先預設是 direct ，遇到索引定址下面會再改成 indexed
            byteError = False      # 處理 BYTE 格式錯誤

            # 第一次進入指令 (全註解或空白的行數不算)，firstCommand = False
            if firstIn == True:    
                firstCommand = False # 不是第一行指令

            # 忽略空白行、註解行
            if line.strip() == "" or line.strip().startswith('.'):
                continue

            # 用空白分割程式碼 (去除頭尾的換行符號)
            parts = line.strip().split()
            # 把指令後面的註解用掉
            for i in range(len(parts)):
                if parts[i].startswith('.'):
                    parts = parts[:i]
                    break

            # 標記第一次進入指令跟還沒到 END
            firstIn = True
            endCorrect = False


            if "***" in parts:
                errorStatus.append(f"程式碼格式錯誤 in line : {num}")
                continue
            # 根據分割後的數量分別處理，並分類好 num loc label mnemonic operand opcode addressing
            #如果是第一行指令為錯誤的，顯示各種錯誤。標註第一行指令結束，並處理下一個指令。如果都正確，下面會處理後面16進位
            elif firstCommand and (len(parts)!=3 or (len(parts)==3 and parts[1]!="START")):
                if len(parts) == 3 and parts[1] != "START": # EX: HI HELLO WORLD
                    label = parts[0]
                    errorStatus.append(f"要從 start 開始 in line : {num}")
                    errorStatus.append(f"Opcode({parts[1]}) 錯誤 in line : {num}")
                else :
                    if "START" not in parts:
                        errorStatus.append(f"要從 start 開始 in line : {num}")
                    errorStatus.append(f"程式碼 START 格式錯誤 in line : {num}")
                continue

            # 分割後只有一個，且為 mnemonic ; 反之，Opcode 錯誤，執行下一行指令
            elif (len(parts) == 1):
                if parts[0] == "RSUB":
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label="***"
                    mnemonic=parts[0]
                    operand="***"
                    opcode=opcode_table[parts[0]]
                else:
                    errorStatus.append(f"Opcode({parts[0]}) 錯誤 in line : {num}")
                    continue

            # 分割後有兩個，mnemonic operand / label "RSUB" / HI HAPPY (XF)
            elif len(parts) == 2:
                # mnemonic operand (mnemonic 在 opcode_table或special ，且不是 BYTE ，且不為索引定址，且不為"START")
                if (parts[0] in opcode_table or parts[0] in special )and parts[0] != "BYTE" and ',' not in parts[1] and parts[0] != "START":
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label="***"
                    mnemonic=parts[0]
                    operand=parts[1]
                    operandTmp=[num,parts[1]]
                    operandConfirm.append(operandTmp)
                    if parts[1] in opcode_table:
                        errorStatus.append(f"operand ({parts[1]}) 不能是指令 in line : {num}")
                        continue
                    if parts[0] !="END" and parts[0] not in special:
                        opcode = opcode_table[parts[0]]
                    else:
                        opcode = "***"
                        if parts[0] =="END":
                            endCorrect = True # 標記到 END 了
                elif parts[1] == "RSUB":
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label=parts[0]
                    # operandTmp=[num,parts[1]]
                    # operandConfirm.append(operandTmp)
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic=parts[1]
                    operand="***"
                    opcode = opcode_table[parts[1]]
                # mnemonic operand (mnemonic 是 BYTE) -> BYTE ?'?' (型態內容之間無空白)
                elif parts[0] == "BYTE":
                    label="***"
                    mnemonic=parts[0]
                    operand=parts[1]
                    opcode="***"
                    byteParts = parts[1].split("'")
                    # X'(十六進位)' / C'(string)'
                    if len(byteParts)!=1:
                        if byteParts[0] == 'X':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ int(len(byteParts[1])/2)
                        elif byteParts[0] == 'C':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ len(byteParts[1])
                # mnemonic operand (為索引定址) -> mnemonic address,x (逗號前後無空白)
                elif ','in parts[1]:
                    label="***"
                    mnemonic=parts[0]
                    operand=parts[1]
                    operandTmp=[num,parts[1]]
                    operandConfirm.append(operandTmp)
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    if parts[0] in opcode_table:
                        opcode = opcode_table[parts[0]]
                    elif parts[0] not in opcode_table:
                        errorStatus.append(f"Opcode({parts[0]}) 錯誤 in line : {num}")
                        # continue
                    addressing ="indexed"
                elif (parts[0] not in opcode_table and parts[0] not in special) and (parts[1] not in opcode_table and parts[1] not in special): # happy happy
                    errorStatus.append(f"Opcode({parts[0]}) 錯誤 in line : {num}")
                    operandTmp=[num,parts[1]]
                    operandConfirm.append(operandTmp)
                    operand=parts[1]
                    continue
                else: # label mnemonic (x)
                    errorStatus.append(f"程式碼格式錯誤 in line : {num}")
                    continue

            # label mnemonic operand / 索引定址 (mnemonic address, x / mnemonic address ,x)
            elif len(parts) == 3:
                # label mnemonic operand (mnemonic 不是 BYTE 且 不為索引定址)
                if firstCommand or (parts[1] in opcode_table or parts[1] in special and parts[1] != "BYTE" and ','not in parts[1] and ','not in parts[2]): # label mnemonic operand 
                    label=parts[0]
                    mnemonic=parts[1]
                    operand=parts[2]
                    operandTmp=[num,parts[2]]
                    operandConfirm.append(operandTmp)
                    if parts[2] in opcode_table:
                        errorStatus.append(f"operand ({parts[2]}) 不能是指令 in line : {num}")
                        continue
                    opcode = opcode_table[parts[1]] if parts[1] in opcode_table else "***"
                    # 判斷第一行指令 start 後面是不是接十六進位
                    if parts[1] == "START" and firstCommand:
                        try:
                            int(parts[2], 16)
                        except ValueError:
                            errorStatus.append(f"start 只能接16進位 in line : {num}")
                            operand=parts[2]
                            # continue
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[0] = int(parts[2], 16)
                            loc[1] = loc[0]
                    elif parts[1] == "RESW":
                        if parts[2].isdigit()== False:
                            errorStatus.append(f"RESW 只能接10進位數字 in line :{num}")
                            # continue
                        else:
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ int(parts[2])*3  # 一個 word，3 個 byte
                    # label "RESB"
                    elif parts[1] == "RESB":
                        if parts[2].isdigit()== False:
                            errorStatus.append(f"RESB 只能接10進位數字 in line :{num}")
                            # continue
                        else:
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ int(parts[2])
                    else:
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[1] = loc[0]+3
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                # label mnemonic operand ( BYTE ? '?' / label BYTE ?'?')
                elif parts[0] == "BYTE" or parts[1] == "BYTE" :
                    opcode="***"
                    if parts[0] == "BYTE": # BYTE X '' / BYTE X' EOF' /BYTE X 'ee'
                        if "'" in parts[1] and "C" not in parts[1]:
                            byteError=True
                        label="***"
                        mnemonic=parts[0]
                        if "C" not in parts[1]:
                            operand=parts[1]+parts[2]
                            byteParts[0] = parts[1].split("'")[0]
                            byteParts[1] = parts[2].split("'")[1]
                        else: # BYTE C' EOF' / BYTE C 'EOF'
                            if "'" in parts[1]:
                                operand=line[line.index('C'):].strip()
                            else:
                                operand=parts[1]+parts[2]
                            # print(operand)
                            byteParts[0] = parts[1].split("'")[0]
                            byteParts[1] = line[line.index("'"):].split("'")[1] # ['C',' EOF']
                        # print(byteParts)
                    elif parts[1] == "BYTE": # label BYTE X'?'
                        opcode="***"
                        markNum=0
                        for i in parts[2]:
                            if i == "'":
                                markNum+=1
                        if markNum != 2:
                            byteError=True
                        label=parts[0]
                        mnemonic=parts[1]
                        operand=parts[2]
                        byteParts[0] = parts[2].split("'")[0]
                        if "'" in parts[2]:
                            byteParts[1] = parts[2].split("'")[1]
                    if label != "***":
                        if label in symbol_table:
                            errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                        else:
                            symbol_table[label] = hex(loc[0])[2:]
                    # X'(十六進位)' / C'(string)'
                    if "'" in parts[2]:
                        if byteParts[0] == 'X':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ int(len(byteParts[1])/2)
                        elif byteParts[0] == 'C':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ len(byteParts[1])
                    
                # 索引定址 (mnemonic address, x / mnemonic address ,x)
                elif ','in parts[1] or ','in parts[2]:
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label="***"
                    mnemonic=parts[0]
                    operand=parts[1]+parts[2]
                    operandTmp=[num,parts[1].split(",")[0]]
                    operandConfirm.append(operandTmp)
                    if parts[0] in opcode_table:
                        opcode = opcode_table[parts[0]]
                    elif parts[0] not in opcode_table:
                        errorStatus.append(f"Opcode({parts[0]}) 錯誤 in line : {num}")
                        operandTmp=[num,parts[1].split(",")[0]]
                        operandConfirm.append(operandTmp)
                        # continue
                    addressing ="indexed"
                # label mnemonic(?) operand
                elif parts[1] not in opcode_table and parts[1] not in special:
                    errorStatus.append(f"Opcode({parts[1]}) 錯誤 in line : {num}")
                    operandTmp=[num,parts[2]]
                    operandConfirm.append(operandTmp)
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic = parts[1]
                    operand=parts[2]
                    # continue
                else :
                    errorStatus.append(f"程式碼格式錯誤 in line : {num}")
                    continue

            # 索引定址 (mnemonic address , x / label mnemonic address ,x / label mnemonic address, x / label "BYTE" "型態"  "'內容'")
            elif len(parts) == 4:
                # mnemonic address , x 
                if parts[2] == ',':
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label="***"
                    mnemonic=parts[0]
                    if parts[1] in opcode_table:
                        errorStatus.append(f"operand ({parts[2]}) 不能是指令 in line : {num}")
                        continue
                    operand=parts[1]+parts[2]+parts[3]
                    operandTmp=[num,parts[1]]
                    operandConfirm.append(operandTmp)
                    if parts[0] in opcode_table:
                        opcode = opcode_table[parts[0]]
                    elif parts[0] not in opcode_table:
                        errorStatus.append(f"Opcode({parts[0]}) 錯誤 in line : {num}")
                        # continue
                    addressing ="indexed"
                # label mnemonic address, x / label mnemonic address ,x
                elif ',' in parts[2] or ',' in parts[3] :
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic=parts[1]
                    if parts[2].split(",")[0] in opcode_table:
                        errorStatus.append(f"指令格式錯誤 in line : {num}")
                        continue
                    operand=parts[2]+parts[3]
                    operandTmp=[num,parts[2]]
                    operandConfirm.append(operandTmp)
                    if parts[1] in opcode_table:
                        opcode = opcode_table[parts[1]]
                    elif parts[1] not in opcode_table:
                        errorStatus.append(f"Opcode({parts[1]}) 錯誤 in line : {num}")
                    addressing ="indexed"
                # BYTE 型態與內容之間可以空白 EX: EOF BYTE C  'EOF' / EOF BYTE C' EOF' / EOF BYTE C ''
                elif parts[1] == "BYTE":
                    opcode="***"
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic=parts[1]
                    if "C" not in parts[2]:
                        if "'" in parts[2]:
                            byteError = True
                            operand=parts[2]+parts[3]
                        else:
                            operand=parts[2]+parts[3]
                        byteParts[0] = parts[2].split("'")[0]
                        byteParts[1] = parts[3].split("'")[1]
                    else: # E BYTE C' EOF' / O BYTE C 'EOF'
                        if parts[2] == "C'":
                            operand=line[line.index('C'):].strip()
                        else:
                            operand=line[line.index('C'):].strip().replace(" ","")
                        byteParts[0] = parts[2].split("'")[0]
                        byteParts[1] = line[line.index("'"):].split("'")[1]
                    # X'(十六進位)' / C'(string)'
                    if byteParts[0] == 'X':
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[1] = loc[0]+ int(len(byteParts[1])/2)
                    elif byteParts[0] == 'C':
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[1] = loc[0]+ len(byteParts[1])
                elif parts[0]=="BYTE": # BYTE X ' ee'/...
                    opcode="***"
                    label="***"
                    mnemonic = parts[0]
                    if "C" not in parts[1]:
                        byteError = True
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[1] = loc[0]+3
                        operand=parts[1]+parts[2]+parts[3]
                    else: #BYTE C' EO F' / BYTE C ' EOF'
                        if parts[1] == "C'":
                            operand=line[line.index('C'):].strip()
                        else: 
                            operand=line[line.index('C'):line.index("'")].strip()+line[line.index("'"):].strip()
                        byteParts[0] = parts[1].split("'")[0]
                        byteParts[1] = line[line.index("'"):].split("'")[1]
                        # C'(string)'
                        if byteParts[0] == 'C':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ len(byteParts[1])
                else: # ex:  EOF BYT C 'EOF' / STCH BUFFE , X
                    errorStatus.append(f"程式碼格式錯誤 in line : {num}")
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    if "," in parts:
                        operand = parts[1]+parts[2]+parts[3]
                    else:
                        operand=parts[2]+parts[3]
                    #continue
            # 索引定址 (label mnemonic address , x )
            elif len(parts) == 5:
                if parts[3] == ",":
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = loc[0]+3
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic=parts[1]
                    operand=parts[2]+parts[3]+parts[4]
                    if parts[1] in opcode_table:
                        opcode = opcode_table[parts[1]]
                    elif parts[1] not in opcode_table :
                        errorStatus.append(f"Opcode({parts[1]}) 錯誤 in line : {num}")
                    operandTmp=[num,parts[2]]
                    operandConfirm.append(operandTmp)
                        
                        # continue
                    addressing ="indexed"
                else:
                    if parts[0]=="BYTE" and "C" in parts[1]: #BYTE C' E O F' / BYTE C 'E O F'
                        opcode="***"
                        label="***"
                        mnemonic=parts[0]
                        if parts[1] == "C'": # BYTE C' E O F'
                            operand=line[line.index('C'):].strip()
                        else:
                            operand=line[line.index('C'):line.index("'")].strip()+line[line.index("'"):].strip()
                        byteParts[0] = parts[1].split("'")[0]
                        byteParts[1] = line[line.index("'"):].split("'")[1]
                        if byteParts[0] == 'C':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ len(byteParts[1])
                    elif parts[1]=="BYTE" and "C" in parts[2]: # E BYTE C' EO F'/ O BYTE C 'E OF'
                        opcode="***"
                        label=parts[0]
                        if label in symbol_table:
                            errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                        else:
                            symbol_table[label] = hex(loc[0])[2:]
                        mnemonic=parts[1]
                        if parts[2] == "C'": # E BYTE C' EO F'
                            operand=line[line.index('C'):].strip()
                        else: # O BYTE C 'E OF'
                            operand=line[line.index('C'):line.index("'")].strip()+line[line.index("'"):].strip()
                        byteParts[0] = parts[2].split("'")[0]
                        byteParts[1] = line[line.index("'"):].split("'")[1]
                        if byteParts[0] == 'C':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ len(byteParts[1])
                    else:
                        # X'(十六進位)' / C'(string)'
                        if byteParts[0] == 'X':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ int(len(byteParts[1])/2)
                        elif byteParts[0] == 'C':
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = loc[0]+ len(byteParts[1])
                        if parts[1]!="BYTE" and parts[0]!="BYTE": #BYTE X ' ee '(x)
                            errorStatus.append(f"程式碼格式錯誤 in line : {num}")
                        elif parts[1]=="BYTE" or parts[0]=="BYTE": # EOF BYTE C ' EOF'
                            opcode="***"
                            byteError = True
                        if parts[0] == "BYTE":
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = 0
                            label="***"
                            mnemonic=parts[0]
                            operand=parts[1]+parts[2]+parts[3]+parts[4]
                        else:
                            if not errorStatus:  # 沒有錯誤再執行
                                loc[1] = 0
                            label=parts[0]
                            if label in symbol_table:
                                errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                            else:
                                symbol_table[label] = hex(loc[0])[2:]
                            mnemonic=parts[1]
                            operand=parts[2]+parts[3]+parts[4]
            else:
                if parts[0]=="BYTE" and "C" in parts[1]: #BYTE C' E O F' / BYTE C 'E O F'
                    opcode="***"
                    label="***"
                    mnemonic=parts[0]
                    if parts[1] == "C'": # BYTE C' E O F'
                        operand=line[line.index('C'):].strip()
                    else:
                        operand=line[line.index('C'):line.index("'")].strip()+line[line.index("'"):].strip()
                    byteParts[0] = parts[1].split("'")[0]
                    byteParts[1] = line[line.index("'"):].split("'")[1]
                    if byteParts[0] == 'C':
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[1] = loc[0]+ len(byteParts[1])
                elif parts[1]=="BYTE" and "C" in parts[2]: # E BYTE C' EO F'/ O BYTE C 'E OF'
                    opcode="***"
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic=parts[1]
                    if parts[2] == "C'": # E BYTE C' EO F'
                        operand=line[line.index('C'):].strip()
                    else: # O BYTE C 'E OF'
                        operand=line[line.index('C'):line.index("'")].strip()+line[line.index("'"):].strip()
                    byteParts[0] = parts[2].split("'")[0]
                    byteParts[1] = line[line.index("'"):].split("'")[1]
                    if byteParts[0] == 'C':
                        if not errorStatus:  # 沒有錯誤再執行
                            loc[1] = loc[0]+ len(byteParts[1])
                else:
                    if not errorStatus:  # 沒有錯誤再執行
                        loc[1] = 0
                    if "BYTE" not in parts:
                        errorStatus.append(f"程式碼格式錯誤 in line : {num}")
                        continue
                    # 下面是 byte
                    opcode="***"
                    byteError = True
                    label=parts[0]
                    if label in symbol_table:
                        errorStatus.append(f"重複的symbol({label}) in line : {num}")  
                    else:
                        symbol_table[label] = hex(loc[0])[2:]
                    mnemonic="BYTE"
                    operand=""

            # 索引定址格式錯誤
            tmp=[None]*2
            if "," in operand:
                addressing ="indexed"
                tmp = operand.split(",")
                if tmp[1] != "X":
                    errorStatus.append(f"索引定址格式錯誤 in line : {num}")
                    continue

            # BYTE 格式錯誤
            tmp = [None] *2
            if mnemonic == "BYTE" and operand != "***":
                tmp1 = operand.replace(" ", "")
                tmp = tmp1.split("'")
                if (tmp[0]!= 'X' and tmp[0] != 'C') or len(tmp)<=2 or byteError: #df
                    errorStatus.append(f"BYTE 格式錯誤 in line : {num}")
                    continue
                elif tmp[1]=='': # X''
                    errorStatus.append(f"BYTE 型態裡面不可沒內容 in line : {num}")
                    continue
                elif tmp[0]== 'X':
                    if len(tmp[1])%2 != 0:
                        errorStatus.append(f"BYTE 的 X 型態內容要為偶數長度({tmp[1]}) in line : {num}")
                    try:
                        int(tmp[1], 16)
                    except ValueError:
                        errorStatus.append(f"BYTE 的 X 型態裡只能為16進位數字 in line : {num}")

            # WORD 錯誤
            if mnemonic == "WORD": # 一個 word，3 個 byte
                if operand.isdigit()== False:
                    errorStatus.append(f"WORD 只能接10進位數字 in line :{num}")
                    continue

            # RSUB 格式錯誤
            if mnemonic == "RSUB":
                if operand!="***":
                    errorStatus.append(f"RSUB 不能擺 Operand in line :{num}")
                    continue

            # label 不能和 Mnemonic 撞名
            if label == mnemonic:
                errorStatus.append(f"symbol({label}) 不能和 Mnemonic 撞名 in line :{num}")
                continue

            # label 不能和 Operand 撞名
            if label == operand and label != "***" :
                errorStatus.append(f"symbol({label}) 不能和 Operand 撞名 in line :{num}")
                continue

            # 將分類好 num loc label mnemonic operand opcode addressing 塞入對應的陣列
            current.append(num)
            lastNum = num+1 # 紀錄最後一行指令行數
            if not errorStatus:  # 沒有錯誤再執行
                current.append(hex(loc[0])[2:])
            else:
                current.append("")
            current.append(label)
            current.append(mnemonic)
            current.append(operand)
            current.append(opcode)
            current.append(addressing)
            result.append(current)
            current=[]

            if not errorStatus:  # 沒有錯誤再執行
                loc[0]=loc[1]
                loc[1]=[None]
        # 最後一行
        if endCorrect != True:
            current.append(lastNum)
            if not errorStatus:  # 沒有錯誤再執行
                current.append(hex(loc[0])[2:])
            else:
                current.append("")
            current.append(label)
            current.append(mnemonic)
            current.append(operand)
            current.append(opcode)
            current.append(addressing)
            result.append(current)
            current=[]

        # 要從 end 結束
        # print(result[-1])
        if result[-1][3] != "END":
            # pointNumCheck.append(result[-1][0])
            errorStatus.append(f"要從 end 結束 in line : {result[-1][0]}")

        if len(errorStatus)!=0:
            # for i in errorStatus:
            #     print(i)
            print(operandConfirm)
            return symbol_table, operandConfirm, errorStatus
        else:
            # print("symbol_table :")
            # print(symbol_table)
            # print("-----")

            # 輸出並產生中間檔
            # print("pass one :")
            for i in result:
                # print(' '.join(map(str, i))) #將每個子列表的元素轉換為字串並連接起來，使用空格分隔
                PassOne_output_file.write(f"{' '.join(map(str, i))}\n")
            return symbol_table, result, []

if __name__ == "__main__":
    file_path = "SIC_test.txt"
    opcodeTable = r"opCode.txt"
    opcode_table = {}
    try:
        with open(opcodeTable, 'r') as file:
            for line in file:
                mnemonic, opcode = line.strip().split()
                opcode_table[mnemonic] = opcode
    except FileNotFoundError:
        print("opcode_table Not Found")
    symbol_table, result, errorStatus=passOne(file_path, opcode_table)

    passOne_table_path = r"110213018陳宣閔_passOne_output.txt"
    passTwo( symbol_table, result, errorStatus)