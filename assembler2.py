inst_e = ["MOV","ADD","SUB","AND","OR","NOT","XOR","SHL","SHR","INC","CMP","JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV","CALL","RET","POP","PUSH"]
instMOV = ["A,B","B,A","A,(B)","B,(B)","(B),A"] #instrucciones que se pueden, las otras hay que ver casos especiales

codigo = open("prueba.ass",'r')
respuesta = open("respuesta.txt",'w')

p = codigo.read()
lineas = p.split("\n")

instrucciones = []
datos = []
etiquetas = []
for linea in lineas:
    l = 0
    uvpl = 0
    linea_b = linea.replace(" ","")
    print(linea_b)
    if linea != "":
        if linea_b[0:3].islower():
            etiquetas.append(linea)
        else:
            instruccion = linea_b[0:3]
            largo = len(linea_b)
            dato = linea_b[3:largo]
            instrucciones.append(instruccion)
            datos.append(dato)

ndl = 0
error = 0
for inst in instrucciones:
    if inst not in inst_e:
        respuesta.write(f'La instrucción {inst} de la linea {ndl+1} no existe\n')
        error = 1
    if inst == "MOV":
        valores = datos[ndl].split(",")
        
            

    ndl+=1




if error == 0:
    respuesta.write("Todas las instrucciones existen\n")
else:
    respuesta.write("El código finalizó con errores\n")

