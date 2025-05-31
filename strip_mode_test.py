import time
mode = 1
ser_num = 1 
i = 0
print ("mode: ", mode)
print ("ser_num: ", ser_num, "\n")
while True:
    i+=1
    time.sleep(1)
    if mode == 0:
        print ("ch#1: ",i)
        print ("ch#2: ", i, "\n")
    elif mode == 1:
        if ser_num == 1:
            print ("ch#1: ",i, "\n")
            ser_num = 2
        elif ser_num == 2:
            print ("ch#2: ", i, "\n")
            ser_num = 1