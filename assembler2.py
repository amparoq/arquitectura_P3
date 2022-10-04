import re

inst_e = ["MOV","ADD","SUB","AND","OR","NOT","XOR","SHL","SHR","INC","CMP","JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL","RET","POP","PUSH"]
instMOV = ["A,B","B,A","A,(B)","B,(B)","(B),A"] #instrucciones que se pueden, las otras hay que ver casos especiales
instADDANDSUBORXOR = ["A,B","B,A","A,(B)","(B),A"]
instNOTSHLSHR = ["A,B","A,A","B,A","B,B"]
jumps = ["JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV"]

literal = re.compile('[0-9]+')

codigo = open("prueba.ass",'r')
respuesta = open("respuesta.out",'w')

p = codigo.read()
lineas = p.split("\n")

instrucciones = []
datos = []
etiquetas = []
for linea in lineas:
    l = 0
    uvpl = 0
    linea_b = linea.replace(" ","")
    if linea != "":
        if linea_b[0:3].islower():
            etiquetas.append(linea)
            instrucciones.append(0)
            datos.append(0)
        else:
            if linea_b != "CODE:":
                if linea_b[0:2] == "OR":
                    instruccion = linea_b[0:2]
                    dato = linea_b[2:largo]
                if linea_b[0:4] == "PUSH" or linea_b[0:4] == "CALL":
                    instruccion = linea_b[0:4]
                    dato = linea_b[4:largo]
                if linea_b[0:2] != "OR" and linea_b[0:4] != "PUSH" and linea_b[0:4] != "CALL":
                    instruccion = linea_b[0:3]
                    largo = len(linea_b)
                    dato = linea_b[3:largo]
                instrucciones.append(instruccion)
                datos.append(dato)

ndl = 0
error = 0

for e in etiquetas:
    if e[-1] != ":":
        respuesta.write(f'Error: La etiqueta {e} no contiene ":"\n')
        error = 1

for inst in instrucciones:
    if inst != 0:
        if inst not in inst_e:
            respuesta.write(f'La instrucción {inst} de la linea {ndl+1} no existe\n')
            error = 1
        if inst == "MOV":
            if datos[ndl] not in instMOV:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if literal.search(valores[0]) != None:
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) != 2:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst == "AND" or inst == "ADD" or inst == "SUB" or inst == "OR" or inst == "XOR":
            if datos[ndl] not in instADDANDSUBORXOR:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if literal.search(valores[0]) != None:
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) == 1:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A" or valores[0][1] == "B":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                if len(valores) != 1 and len(valores) != 2:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst == "NOT" or inst == "SHL" or inst == "SHR":
            if datos[ndl] not in instNOTSHLSHR:
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A" or valores[0][1] == "B":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A" or valores[1][1] == "B":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if literal.search(valores[0]) != None:
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) == 1:
                    if valores[0] != "(B)":
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                if len(valores) != 1 and len(valores) != 2:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst == "INC":
            valores = datos[ndl].split(",")
            if valores[0][0] == "(":
                if valores[0][1] == "A":
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
                if literal.search(valores[0][1]) != None:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
            if len(valores) != 1:
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
            if literal.search(valores[0]) != None:
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "RST":
            valores = datos[ndl].split(",")
            if len(valores) == 1:
                if valores[0][0] == "(":
                    if valores[0][1] == "A":
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                else:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
                if literal.search(valores[0]) != None:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1
            if len(valores) != 1:
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "CMP":
            if datos[ndl] != "A,B" and datos[ndl] != "A,(B)":
                valores = datos[ndl].split(",")
                if len(valores) == 2:
                    if valores[0][0] == "(":
                        if valores[0][1] == "A" or valores[0][1] == "B":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[1][0] == "(":
                        if valores[1][1] == "A" or valores[1][1] == "B":
                            respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                            error = 1
                    if valores[0][0] == "(" and valores[1][0] == "(":
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                    if literal.search(valores[0]) != None:
                        respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                        error = 1
                else:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                    error = 1

        if inst in jumps:
            encontrada = 0
            for i in etiquetas:
                if i[0:-1] == datos[ndl]:
                    encontrada = 1
            if encontrada == 0:
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe. La etiqueta {datos[ndl]} no existe o está mal declarada\n')
                error = 1
        
        if inst == "RET":
            if datos[ndl] != "" or datos[ndl] != " ":
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "POP" or inst == "PUSH":
            if datos[ndl] != "A" or datos[ndl] != "B":
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "CALL":
            pass
    if inst == 0:
        pass
    ndl+=1




if error == 0:
    respuesta.write("Todas las instrucciones existen\n")
else:
    respuesta.write("El código finalizó con errores\n")

