import re

inst_e = ["MOV","ADD","SUB","AND","OR","NOT","XOR","RST","SHL","SHR","INC","CMP","JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL","RET","POP","PUSH","RST"]
instMOV = ["A,B","B,A","A,(B)","B,(B)","(B),A"] #instrucciones que se pueden, las otras hay que ver casos especiales
instADDANDSUBORXOR = ["A,B","B,A","A,(B)","(B),A"]
instNOTSHLSHR = ["A,B","A,A","B,A","B,B"]
jumps = ["JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL"]

literal = re.compile('[0-9]+$')

codigo = open("p3_1-correccion1.ass",'r')
respuesta = open("respuesta.out",'w')

p = codigo.read()
lineas = p.split("\n")

instrucciones = []
datos = []
etiquetas = []
for linea in lineas:
    l = 0
    uvpl = 0
    lin = linea.split(" ")
    if len(lin) != 0:
        if len(lin) == 1:
            if lin[0] != "CODE:":
                etiquetas.append(linea)
                instrucciones.append(0)
                datos.append(0)
        else:
            instrucciones.append(lin[len(lin)-2])
            datos.append(lin[len(lin)-1])
ndl = 0
error = 0

for e in etiquetas:
    if e != "":
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
                if datos[ndl][0] != "#" and literal.search(datos[ndl]) == None:
                    respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe. La etiqueta {datos[ndl]} no existe o está mal declarada\n')
                    error = 1
        
        if inst == "RET":
            if datos[ndl] != "" or datos[ndl] != " ":
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
        
        if inst == "POP" or inst == "PUSH":
            if datos[ndl] != "A" and datos[ndl] != "B":
                respuesta.write(f'La instrucción {inst} {datos[ndl]} de la linea {ndl+1} no existe\n')
                error = 1
    if inst == 0:
        pass
    ndl+=1




if error == 0:
    respuesta.write("Todas las instrucciones existen\n")
else:
    respuesta.write("El código finalizó con errores\n")

