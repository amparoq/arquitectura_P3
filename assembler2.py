import re

inst_e = ["MOV","ADD","SUB","AND","OR","NOT","XOR","RST","SHL","SHR","INC","CMP","JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL","RET","POP","PUSH","RST"]
instMOV = ["A,B","B,A","A,(B)","B,(B)","(B),A"] #instrucciones que se pueden, las otras hay que ver casos especiales
instADDANDSUBORXOR = ["A,B","B,A","A,(B)"]
instNOTSHLSHR = ["A,A","A,B","B,A","B,B"]
jumps = ["JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL"]

literal = re.compile('[0-9]+$')

codigo = open("p3_1-correccion1.ass",'r')
traduccion = open("traduccion.out",'w')

p = codigo.read()
lineas = p.split("\n")

literal_c = False

instrucciones = []
datos = []
etiquetas = []
for linea in lineas:
    l = 0
    uvpl = 0
    l = linea.strip()
    lin = l.split(",")
    prim_seg = lin[0].split(" ")
    if len(lin) != 0:
        if len(lin) == 1:
            if len(prim_seg) == 2:
                instrucciones.append(prim_seg[0])
                datos.append(prim_seg[1])
            else:
                if lin[0] != "CODE:":
                    etiquetas.append(linea)
                    instrucciones.append(0)
                    datos.append(0)
        else:
            instrucciones.append(prim_seg[0])
            dat = prim_seg[1]+","+lin[1].replace(" ","")
            datos.append(dat)
ndl = 0
error = 0

for e in etiquetas:
    if e != "":
        if e[-1] != ":":
            print(f'Error: La etiqueta {e} no contiene ":"\n')
            error = 1

for inst in instrucciones:
    if inst != 0:
        if inst not in inst_e:
            print(f'La instrucción {inst} de la linea {ndl+1} no existe\n')
            error = 1
        if inst == "MOV":
            if datos[ndl] not in instMOV:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if literal.search(valores[0]) != None:
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) != 2:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
        if inst == "AND" or inst == "ADD" or inst == "SUB" or inst == "OR" or inst == "XOR":
            if datos[ndl] not in instADDANDSUBORXOR:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if literal.search(valores[0]) != None:
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) == 1:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A" or valores[0][1] == "B":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                if len(valores) != 1 and len(valores) != 2:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst == "NOT" or inst == "SHL" or inst == "SHR":
            if datos[ndl] not in instNOTSHLSHR:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A" or valores[0][1] == "B":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A" or valores[1][1] == "B":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if literal.search(valores[0]) != None:
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) == 1:
                    if valores[0] != "(B)":
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) != 1 and len(valores) != 2:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst == "INC":
            valores = datos[ndl].split(",")
            if valores[0][0] == "(":
                if valores[0][1] == "A":
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
                if literal.search(valores[0][1]) != None:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
            if len(valores) != 1:
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
            if literal.search(valores[0]) != None:
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "RST":
            valores = datos[ndl].split(",")
            if len(valores) == 1:
                if valores[0][0] == "(":
                    if valores[0][1] == "A":
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                else:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
                if literal.search(valores[0]) != None:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
            if len(valores) != 1:
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "CMP":
            if datos[ndl] != "A,B" and datos[ndl] != "A,(B)":
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A" or valores[0][1] == "B":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A" or valores[1][1] == "B":
                            print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if literal.search(valores[0]) != None:
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                else:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst in jumps:
            encontrada = 0
            for i in etiquetas:
                if i[0:-1] == datos[ndl]:
                    encontrada = 1
            if encontrada == 0:
                if datos[ndl][0] != "#" and literal.search(datos[ndl]) == None:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe. La etiqueta {datos[ndl]} no existe o está mal declarada\n')
                    error = 1
        
        if inst == "RET":
            if datos[ndl] != "" or datos[ndl] != " ":
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "POP" or inst == "PUSH":
            if datos[ndl] != "A" and datos[ndl] != "B":
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
    if inst == 0:
        pass
    ndl+=1

ndl = 0
if error != 1:
    opcode=""
    lit= ""
    for inst in instrucciones:
        if inst == "MOV":
            if datos[ndl] in instMOV:
                if datos[ndl] == instMOV[0]:
                    opcode = "0000000"
                if datos[ndl] == instMOV[1]:
                    opcode = "0000001"
                if datos[ndl] == instMOV[2]:
                    opcode = "0101001"
                if datos[ndl] == instMOV[3]:
                    opcode = "0101010"
                if datos[ndl] == instMOV[4]:
                    opcode = "0101011"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if literal.search(valores[1]) != None:
                    if valores[0] == "A":
                        opcode = "0000010"
                    if valores[0] == "B":
                        opcode = "0000011"
                    if valores[1][0] == "#":
                        lit_num = int(valores[1][1:len(valores[1])],base=16)
                        lit_b = str(bin(lit_num))
                        lit = lit_b[2:len(lit_b)].zfill(8)
                        literal_c = True
                    else:
                        if len(valores[1])==1:
                            lit_num = int(valores[1])
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                            literal_c = True
                        else:
                            if valores[1][1] == "b":
                                lit = valores[1][2:len(valores[1])]
                                literal_c = True
                            else:
                                lit_num = int(valores[1])
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                                literal_c = True
                if literal_c == False:
                    if valores[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "0100111"
                        if valores[1] == "B":
                            opcode = "0101000"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
                    if valores[1][0]=="(":
                        if valores[0] == "A":
                            opcode = "0100101"
                        if valores[0] == "B":
                            opcode = "0100110"
                        num_1 = valores[1].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
        if inst == "ADD":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0000100"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0000101"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0101110"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if literal.search(valores[1]) != None:
                        if valores[0] == "A":
                            opcode = "0000110"
                        if valores[0] == "B":
                            opcode = "0000111"
                        if valores[1][0] == "#":
                            lit_num = int(valores[1][1:len(valores[1])],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                            literal_c = True
                        else:
                            if len(valores[1])==1:
                                lit_num = int(valores[1])
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                                literal_c = True
                            else:
                                if valores[1][1] == "b":
                                    lit = valores[1][2:len(valores[1])]
                                    literal_c = True
                                else:
                                    lit_num = int(valores[1])
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                    literal_c = True
                    if literal_c == False:
                        if valores[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0101100"
                            if valores[0] == "B":
                                opcode = "0101101"
                            num_1 = valores[1].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]
                        else:
                            opcode = "0101111"
                            num_1 = valores[0].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]
        if inst == "SUB":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0001000"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0001001"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0110010"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if literal.search(valores[1]) != None:
                        if valores[0] == "A":
                            opcode = "0001010"
                        if valores[0] == "B":
                            opcode = "0001011"
                        if valores[1][0] == "#":
                            lit_num = int(valores[1][1:len(valores[1])],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                            literal_c = True
                        else:
                            if len(valores[1])==1:
                                lit_num = int(valores[1])
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                                literal_c = True
                            else:
                                if valores[1][1] == "b":
                                    lit = valores[1][2:len(valores[1])]
                                    literal_c = True
                                else:
                                    lit_num = int(valores[1])
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                    literal_c = True
                    if literal_c == False:
                        if valores[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0110000"
                            if valores[0] == "B":
                                opcode = "0110001"
                            num_1 = valores[1].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]
                        else:
                            opcode = "0110011"
                            num_1 = valores[0].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]     
        if inst == "AND":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0001100"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0001101"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0110110"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if literal.search(valores[1]) != None:
                        if valores[0] == "A":
                            opcode = "0001110"
                        if valores[0] == "B":
                            opcode = "0001111"
                        if valores[1][0] == "#":
                            lit_num = int(valores[1][1:len(valores[1])],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                            literal_c = True
                        else:
                            if len(valores[1])==1:
                                lit_num = int(valores[1])
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                                literal_c = True
                            else:
                                if valores[1][1] == "b":
                                    lit = valores[1][2:len(valores[1])]
                                    literal_c = True
                                else:
                                    lit_num = int(valores[1])
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                    literal_c = True
                    if literal_c == False:
                        if valores[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0110100"
                            if valores[0] == "B":
                                opcode = "0110101"
                            num_1 = valores[1].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]
                        else:
                            opcode = "0110111"
                            num_1 = valores[0].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]  
        if inst == "OR":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0010000"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0010001"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0111010"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if literal.search(valores[1]) != None:
                        if valores[0] == "A":
                            opcode = "0010010"
                        if valores[0] == "B":
                            opcode = "0010011"
                        if valores[1][0] == "#":
                            lit_num = int(valores[1][1:len(valores[1])],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                            literal_c = True
                        else:
                            if len(valores[1])==1:
                                lit_num = int(valores[1])
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                                literal_c = True
                            else:
                                if valores[1][1] == "b":
                                    lit = valores[1][2:len(valores[1])]
                                    literal_c = True
                                else:
                                    lit_num = int(valores[1])
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                    literal_c = True
                    if literal_c == False:
                        if valores[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0111000"
                            if valores[0] == "B":
                                opcode = "0111001"
                            num_1 = valores[1].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]
                        else:
                            opcode = "0111011"
                            num_1 = valores[0].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]  
        if inst == "XOR":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0011000"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0011001"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "1000001"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if literal.search(valores[1]) != None:
                        if valores[0] == "A":
                            opcode = "0011010"
                        if valores[0] == "B":
                            opcode = "0011011"
                        if valores[1][0] == "#":
                            lit_num = int(valores[1][1:len(valores[1])],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                            literal_c = True
                        else:
                            if len(valores[1])==1:
                                lit_num = int(valores[1])
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                                literal_c = True
                            else:
                                if valores[1][1] == "b":
                                    lit = valores[1][2:len(valores[1])]
                                    literal_c = True
                                else:
                                    lit_num = int(valores[1])
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                    literal_c = True
                    if literal_c == False:
                        if valores[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0111111"
                            if valores[0] == "B":
                                opcode = "1000000"
                            num_1 = valores[1].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)]
                        else:
                            opcode = "1000010"
                            num_1 = valores[0].replace("(","")
                            num = num_1.replace(")","")
                            if num[0] == "#":
                                lit_num = int(num[1:len(num)],base=16)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if literal.search(num) != None:
                                    lit_num = int(num)
                                    lit_b = str(bin(lit_num))
                                    lit = lit_b[2:len(lit_b)].zfill(8)
                                else:
                                    if num[1] == "b":
                                        lit = num[2:len(num)] 
        if inst == "NOT":
            if datos[ndl] in instNOTSHLSHR:
                # instNOTSHLSHR = ["A,B","A,A","B,A","B,B"]
                if datos[ndl] == instNOTSHLSHR[0]:
                    opcode = "0010100"
                if datos[ndl] == instNOTSHLSHR[1]:
                    opcode = "0010101"
                if datos[ndl] == instNOTSHLSHR[2]:
                    opcode = "0010110"
                if datos[ndl] == instNOTSHLSHR[3]:
                    opcode = "0010111"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "0111100"
                        if valores[1] == "B":
                            opcode = "0111101"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
                    else:
                        opcode = "0111110"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
        if inst == "SHL":
            if datos[ndl] in instNOTSHLSHR:
                # instNOTSHLSHR = ["A,B","A,A","B,A","B,B"]
                if datos[ndl] == instNOTSHLSHR[0]:
                    opcode = "0011100"
                if datos[ndl] == instNOTSHLSHR[1]:
                    opcode = "0011101"
                if datos[ndl] == instNOTSHLSHR[2]:
                    opcode = "0011110"
                if datos[ndl] == instNOTSHLSHR[3]:
                    opcode = "0011111"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "1000011"
                        if valores[1] == "B":
                            opcode = "1000100"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
                    else:
                        opcode = "1000101"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
        if inst == "SHR":
            if datos[ndl] in instNOTSHLSHR:
                if datos[ndl] == instNOTSHLSHR[0]:
                    opcode = "0100000"
                if datos[ndl] == instNOTSHLSHR[1]:
                    opcode = "0100001"
                if datos[ndl] == instNOTSHLSHR[2]:
                    opcode = "0100010"
                if datos[ndl] == instNOTSHLSHR[3]:
                    opcode = "0100011"
                lit = "00000000"
            else:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "1000110"
                        if valores[1] == "B":
                            opcode = "1000111"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]
                    else:
                        opcode = "1000101"
                        num_1 = valores[0].replace("(","")
                        num = num_1.replace(")","")
                        if num[0] == "#":
                            lit_num = int(num[1:len(num)],base=16)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if literal.search(num) != None:
                                lit_num = int(num)
                                lit_b = str(bin(lit_num))
                                lit = lit_b[2:len(lit_b)].zfill(8)
                            else:
                                if num[1] == "b":
                                    lit = num[2:len(num)]            
        if inst == "INC":
            if datos[ndl]=="B":
                opcode = "0100100"
                lit = "00000000"
            if datos[ndl][0]=="(":
                if datos[ndl][1]=="B":
                    opcode = "1001010"
                    lit = "00000000"
                else:
                    opcode = "1001001"
                    num_1 = datos[ndl].replace("(","")
                    num = num_1.replace(")","")
                    if num[0] == "#":
                        lit_num = int(num[1:len(num)],base=16)
                        lit_b = str(bin(lit_num))
                        lit = lit_b[2:len(lit_b)].zfill(8)
                    else:
                        if literal.search(num) != None:
                            lit_num = int(num)
                            lit_b = str(bin(lit_num))
                            lit = lit_b[2:len(lit_b)].zfill(8)
                        else:
                            if num[1] == "b":
                                lit = num[2:len(num)]
        if inst == "RST":
            if datos[ndl] == "(B)":
                opcode = "1001100"
                lit = "00000000"
            else:
                opcode = "1001011"
                num_1 = datos[ndl].replace("(","")
                num = num_1.replace(")","")
                if num[0] == "#":
                    lit_num = int(num[1:len(num)],base=16)
                    lit_b = str(bin(lit_num))
                    lit = lit_b[2:len(lit_b)].zfill(8)
                else:
                    if literal.search(num) != None:
                        lit_num = int(num)
                        lit_b = str(bin(lit_num))
                        lit = lit_b[2:len(lit_b)].zfill(8)
                    else:
                        if num[1] == "b":
                            lit = num[2:len(num)]
        #Las de salto
        if inst == 0:
            pass
        traduccion.write(f'{opcode}{lit}\n')
        literal_c = False                  
        ndl+=1




if error == 0:
    print("Todas las instrucciones existen")
else:
    print("El código finalizó con errores")

