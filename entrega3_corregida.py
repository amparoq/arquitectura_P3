import re

inst_e = ["MOV","ADD","SUB","AND","OR","NOT","XOR","RST","SHL","SHR","INC","CMP","JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL","RET","POP","PUSH","RST"]
instMOV = ["A,B","B,A","A,(B)","B,(B)","(B),A"] #instrucciones que se pueden, las otras hay que ver casos especiales
instADDANDSUBORXOR = ["A,B","B,A","A,(B)"]
instNOTSHLSHR = ["A,A","A,B","B,A","B,B"]
jumps = ["JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL"]
jumps_opcode=[]
opcode_n = 83
i = 0

instGEN = ["A,B","B,A","A,(B)","B,(B)","(B),A","A,A","B,B","(B)"]

while i<(len(jumps)-1):
    opc_str = str(bin(opcode_n))
    jumps_opcode.append(opc_str[2:len(opc_str)])
    opcode_n+=1
    i+=1

jumps_opcode.append("1011100")

literal = re.compile('[0-9a-fA-F]+$')
literal_dec = re.compile('^[0-9]+$')

e_lit = False
data_on = False
registros = {} #para guardar la dirección de lo que está en data
registros_valores = [] #para guardar mem

codigo = open("p3F_1.ass",'r')

p = codigo.read()
lineas = p.split("\n")
if lineas[0] == "DATA:":
    data_on = True

instrucciones = []
datos = []
etiquetas = {}
endata = False
encode = False
reg_posi = []
ndl = 0
ndl_codigo = 0
contador_var = 0
for linea in lineas:
    l = 0
    uvpl = 0
    l = linea.strip()
    lin = l.split(",")
    prim_seg = lin[0].split(" ")
    if len(lin) != 0:
        if len(lin) == 1:
            if data_on == True:
                if prim_seg[0] == "CODE:":
                    encode = True
                    endata = False
                if prim_seg[0] == "DATA:":
                    encode = False
                    endata = True
            else:
                encode = True
            if len(prim_seg) == 2:
                if encode == True:
                    instrucciones.append(prim_seg[0])
                    datos.append(prim_seg[1])
                if endata == True:
                    if prim_seg[0] != "DATA:":
                        if literal.search(prim_seg[1]) == None:
                            print(f'El registro {prim_seg[0]} tiene asignado un valor erróneo\n')
                        if literal.search(prim_seg[1]) != None:
                            num_encontrado = False
                            if prim_seg[1][0] == "#":
                                try:
                                    num_bi = bin(int(prim_seg[1][1:],base = 16))[2:]
                                    num_encontrado = True
                                except:
                                    print(f'El registro {prim_seg[0]} tiene asignado un valor erróneo\n')
                            else:
                                if prim_seg[1][0] == "b":
                                    if literal_dec.search(prim_seg[1][1:]) != None:
                                        num_bi = prim_seg[1:]
                                        num_encontrado = True
                                    else:
                                        print(f'El registro {prim_seg[0]} tiene asignado un valor erróneo\n')
                                else:
                                    if prim_seg[1][0] == "-":
                                        int_sin = prim_seg[1].replace("-","")
                                        if literal_dec.search(int_sin) == None:
                                            print(f'El registro {prim_seg[0]} tiene asignado un valor erróneo\n')
                                            error = 1
                                        else:
                                            bin_sin = bin(int(int_sin))[2:]
                                            if len(bin_sin)>8:
                                                print(f'El registro {prim_seg[0]} tiene asignado un valor mayor a 8 bits\n')
                                                error = 1
                                            else:
                                                num_bi = bin(int(prim_seg[1]) & 0b11111111)[2:]
                                                num_encontrado = True
                                    else:
                                        try:
                                            num_bi= bin(int(prim_seg[1]))[2:]
                                            num_encontrado = True
                                        except:
                                            print(f'El registro {prim_seg[0]} tiene asignado un valor erróneo\n')
                            if num_encontrado == True:
                                if len(num_bi)>8:
                                    print(f'El registro {prim_seg[0]} está asignado a un valor mayor a 8 bits\n') #ver si esto se puede
                                else:
                                    registros_valores.append(num_bi.zfill(8))
                        num_bi = bin(contador_var)[2:].zfill(8)
                        if contador_var == 0:
                            num_bi = "00000000"
                        registros[prim_seg[0]] = num_bi
                        contador_var+=1
            else:
                if encode == True:
                    if lin[0] != "CODE:":
                        if lin[0].strip() == "RET":
                            instrucciones.append(lin[0].strip())
                            datos.append("")
                        else:
                            etiquetas[linea.strip()] = bin(ndl_codigo)[2:].zfill(8) 
                            instrucciones.append(0)
                            datos.append(0)
                if endata == True:
                    if lin[0] != "DATA:":
                        print(f'El registro {prim_seg[0]} no está siendo asignado ningún valor\n')

        else:
            if encode == True:
                instrucciones.append(prim_seg[0])
                dat = prim_seg[1]+","+lin[1].replace(" ","")
                datos.append(dat)
        if encode == True and lin[0] != "CODE:" and len(prim_seg)==2:
            ndl_codigo+=1
ndl = 0
error = 0

for e in etiquetas:
    if e != "":
        if e[-1] != ":":
            print(f'Error: La etiqueta {e} no contiene ":"\n')
            error = 1

literales = []

#correccion de errores
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
                    if valores[0]!= "A" and valores[0]!= "B":
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
                    if valores[0]!= "A" and valores[0]!= "B":
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
                    if valores[0]!= "A" and valores[0]!= "B":
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
                if valores[0][1]!= "B":
                    c = valores[0].replace("(","")
                    cc = c.replace(")","")
                    if literal.search(valores[0]) != None:
                        print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
            if len(valores) != 1:
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
            if valores[0]!= "(B)" and valores[0]!= "B":
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
                if valores[0]!= "A" and valores[0]!= "B":
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
                    if valores[0]!= "A" and valores[0]!= "B":
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
                    lit_p = etiquetas[i]
                    literales.append(lit_p)
            if encontrada == 0:
                if literal.search(datos[ndl]) == None:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe. La etiqueta {datos[ndl]} no existe o está mal declarada\n')
                    error = 1
        
        if inst == "RET":
            if datos[ndl] != "" and datos[ndl] != " ":
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "POP" or inst == "PUSH":
            if datos[ndl] != "A" and datos[ndl] != "B":
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        #handling de los numeros
            
        if datos[ndl] != 0 and datos[ndl] not in instGEN and datos[ndl] != "":
            v = datos[ndl].split(",")
            drr = v[0].replace("(","")
            dr1 = drr.replace(")","")
            if len(v)>1:
                drr = v[1].replace("(","")
                dr2 = drr.replace(")","")
                if dr2[0] != "#" and dr2[0] != "b" and dr2[0] != "-" and literal_dec.search(dr2[0]) == None and (dr2 != "A" and dr2 != "B") and dr2 not in registros:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} está usando una variable no declarada en bloque DATA\n')
                    error = 1
                else:
                    e_lit = True
                    if dr2 in registros:
                        lit_p = "00000000"
                    else:
                        if dr2[0] == "#":
                            try:
                                lit_num = int(dr2[1:],base=16)
                                lit_b = str(bin(lit_num))
                                lit_p = lit_b[2:len(lit_b)]
                            except:
                                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                error = 1
                                e_lit = False
                        if dr2[0] == "b":
                            if literal_dec.search(dr2[0][1:])!=None:
                                lit_p = dr2[1:]
                            else:
                                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                error = 1
                                e_lit = False
                        if dr2[0] == "-":
                            int_sin = dr2.replace("-","")
                            if literal_dec.search(int_sin) == None:
                                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                error = 1
                            else:
                                bin_sin = bin(int(int_sin))[2:]
                                if len(bin_sin)>8:
                                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} está usando un literal mayor a 8 bits\n')
                                    error = 1
                                else:
                                    lit_p = bin(int(dr2) & 0b11111111)[2:]
                        if literal_dec.search(dr2) != None:
                            lit_p = bin(int(dr2))[2:]
            if dr1[0] != "#" and dr1[0] != "b" and dr1[0] != "-" and literal_dec.search(dr1[0]) == None and dr1 != "A" and dr1 != "B" and e_lit == True and dr1 not in registros:
                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} está usando una variable no declarada en bloque DATA\n')
                error = 1
            else:
                if dr1 == "B":
                    if inst in instNOTSHLSHR or inst == "INC" or inst == "RST":
                        e_lit = False
                else:
                    e_lit = True
                    if dr1 in registros:
                        lit_p = "00000000"
                    else:
                        if dr1[0] == "#":
                            try:
                                lit_num = int(dr1[1:],base=16)
                                lit_b = str(bin(lit_num))
                                lit_p = lit_b[2:len(lit_b)]
                            except:
                                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                error = 1
                                e_lit = False
                        if dr1[0] == "b":
                            if literal_dec.search(dr1[1:])!=None:
                                lit_p = dr1[1:]
                            else:
                                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                error = 1
                                e_lit = False
                        if dr1[0] == "-":
                            int_sin = dr1.replace("-","")
                            if literal_dec.search(int_sin) == None:
                                print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                error = 1
                            else:
                                bin_sin = bin(int(int_sin))[2:]
                                if len(bin_sin)>8:
                                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                                    error = 1
                                else:
                                    lit_p = bin(int(dr1) & 0b11111111)[2:]
                        if literal_dec.search(dr1) != None:
                            lit_p = bin(int(dr1))[2:]
            if e_lit == True:
                if len(lit_p)>8:
                    print(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} está usando un literal mayor a 8 bits\n')
                    error = 1
            if e_lit == False:
                lit_p = "00000000"
            else:
                valores = datos[ndl].split(",")
                reg1 = valores[0].replace("(","").replace(")","")
                if len(valores) > 1:
                    reg2 = valores[1].replace("(","").replace(")","")
                    if reg2 in registros:
                        lit_p = registros[reg2]
                if reg1 in registros:
                    lit_p = registros[reg1]
        else:
            lit_p = "00000000"
    else:
        literales.append(0)
    e_lit = False
    if inst != 0:
        if len(literales) != ndl+1:
            literales.append(lit_p.zfill(8))
    ndl+=1

ndl = 0
#traducción
if error != 1:
    traduccion = open("traduccion.out",'w')
    memoria = open("memoria.mem",'w')
    opcode = ""
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
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                    #hacer esto de or en los otros
                    if valores[0] == "A":
                        opcode = "0000010"
                    if valores[0] == "B":
                        opcode = "0000011"
                    if valore[1][0]=="(":
                        if valores[0] == "A":
                            opcode = "0100101"
                        if valores[0] == "B":
                            opcode = "0100110"
                if (literal.search(valores[0]) != None or valores[0] in registros) and valores[0]!= "A" and valores[0]!= "B":
                    if valore[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "0100111"
                        if valores[1] == "B":
                            opcode = "0101000"
        if inst == "ADD":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0000100"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0000101"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0101110"
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                        if valores[0] == "A":
                            opcode = "0000110"
                        if valores[0] == "B":
                            opcode = "0000111"
                        if valore[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0101100"
                            if valores[0] == "B":
                                opcode = "0101101"
                else:
                    opcode = "0101111"
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
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                        if valores[0] == "A":
                            opcode = "0001010"
                        if valores[0] == "B":
                            opcode = "0001011"
                        if valore[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0110000"
                            if valores[0] == "B":
                                opcode = "0110001"
                else:
                    opcode = "0110011"   
        if inst == "AND":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0001100"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0001101"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0110110"
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                        if valores[0] == "A":
                            opcode = "0001110"
                        if valores[0] == "B":
                            opcode = "0001111"
                        if valore[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0110100"
                            if valores[0] == "B":
                                opcode = "0110101"
                else:
                    opcode = "0110111"
        if inst == "OR":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0010000"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0010001"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "0111010"
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                        if valores[0] == "A":
                            opcode = "0010010"
                        if valores[0] == "B":
                            opcode = "0010011"
                        if valore[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0111000"
                            if valores[0] == "B":
                                opcode = "0111001"
                else:
                    opcode = "0111011"
        if inst == "XOR":
            if datos[ndl] in instADDANDSUBORXOR:
                if datos[ndl] == instADDANDSUBORXOR[0]:
                    opcode = "0011000"
                if datos[ndl] == instADDANDSUBORXOR[1]:
                    opcode = "0011001"
                if datos[ndl] == instADDANDSUBORXOR[2]:
                    opcode = "1000001"
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                        if valores[0] == "A":
                            opcode = "0011010"
                        if valores[0] == "B":
                            opcode = "0011011"
                        if valore[1][0]=="(":
                            if valores[0] == "A":
                                opcode = "0111111"
                            if valores[0] == "B":
                                opcode = "1000000"
                else:
                    opcode = "1000010"
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
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if valore[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "0111100"
                        if valores[1] == "B":
                            opcode = "0111101"
                else:
                    opcode = "0111110"
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
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if valore[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "1000011"
                        if valores[1] == "B":
                            opcode = "1000100"
                else:
                    opcode = "1000101"
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
            else:
                valores = datos[ndl].replace("(","").replace(")","").split(",")
                valore = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0]=="(":
                        if valores[1] == "A":
                            opcode = "1000110"
                        if valores[1] == "B":
                            opcode = "1000111"
                    else:
                        opcode = "1000101"        
        if inst == "INC":
            if datos[ndl]=="B":
                opcode = "0100100"
            if datos[ndl][0]=="(":
                if datos[ndl][1]=="B":
                    opcode = "1001010"
                else:
                    opcode = "1001001"
        if inst == "RST":
            if datos[ndl] == "(B)":
                opcode = "1001100"
            else:
                opcode = "1001011"
        if inst == "CMP":
            if datos[ndl] == "A,B":
                opcode = "1001101"
            if datos[ndl] == "A,(B)":
                opcode = "1010010"
            valores = datos[ndl].replace("(","").replace(")","").split(",")
            valore = datos[ndl].split(",")
            if (literal.search(valores[1]) != None or valores[1] in registros) and valores[1]!= "A" and valores[1]!= "B":
                if valores[0] == "A":
                    opcode = "1001110"
                if valores[0] == "B":
                    opcode = "1001111"
                if valore[1][0]=="(":
                    if valores[0] == "A":
                        opcode = "1010000"
                    if valores[0] == "B":
                        opcode = "1010001"
        if inst in jumps:
            ind = jumps.index(inst)
            opcode = jumps_opcode[ind]    
        if inst == "RET":
            opcode = "1011101"
        if inst == "PUSH":
            if datos[ndl] == "A":
                opcode = "1011110"
            if datos[ndl] == "B":
                opcode = "1011111"
        if inst == "POP":
            if datos[ndl] == "A":
                opcode = "1100000"
            if datos[ndl] == "B":
                opcode = "1100001"
        if inst != 0 and inst != "":
            traduccion.write(f'{opcode}{literales[ndl]}\n')                
        ndl+=1
    for vr in registros_valores:
        memoria.write(f'{vr}\n')
if error == 0:
    print("Todas las instrucciones existen")
else:
    print("El código finalizó con errores")

#dudas:
#CALL solo pueden ser etiquetas? o numeros tmb?