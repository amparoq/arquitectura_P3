Para utilizar el assembler se debe poner el nombre del código a leer en
la linea 7, donde originalmente dice "prueba.ass"
Se debe especificar la extensión, es decir, si se quiere poner un archivo txt llamado
codigo1 se coloca "codigo1.txt"

El archivo de prueba debe tener el siguiente formato:

inicio:
    MOV A,B
    ADD A,B
    INC B
    JMP final
final:
    MOV A,B
    AND A,1

Es decir, las etiquetas van separadas del código


