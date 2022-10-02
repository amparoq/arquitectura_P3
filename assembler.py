
inst_e = ["MOV","ADD","SUB","AND","OR","NOT","XOR","SHL","SHR","INC","CMP","JMP","JEQ","JNE","JGT","JLT","JGE","JLE","JCR","JOV"]

codigo = open("prueba.txt",'r')
respuesta = open("respuesta.txt",'w')

p = codigo.read()
lineas = p.split("\n")

instrucciones = []
for linea in lineas:
    l = 0
    uvpl = 0
    for letra in linea:
        if letra == " " and uvpl == 0:
            instruccion = linea[0:l]
            instrucciones.append(instruccion)
            uvpl = 1
        else:
            l+=1

ndl = 0
error = 0
for inst in instrucciones:
    if inst not in inst_e:
        respuesta.write(f'La instrucción {inst} de la linea {ndl+1} no existe\n')
        error = 1
    ndl+=1

if error == 0:
    respuesta.write("Todas las instrucciones existen\n")
else:
    respuesta.write("El código finalizó con errores\n")



