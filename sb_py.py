import time

list1 = [1, 2, 3]
list2 = ['a', 'b', 'c']

for a, b in zip(list1, list2):
    print(a, b)
    
time_stamp_1= time.time()
print(time_stamp_1)
time.sleep(5/1000)
time_stamp_2 = time.time()
print(time_stamp_2)
time_dl = time_stamp_2-time_stamp_1
print(time_dl)
i_time_dl = int(time_dl*1000)
print(i_time_dl)
time_dl_list  = []
for i in range(10):
    time_stamp_1= time.time()
    time.sleep(1600/1000000)
    time_stamp_2 = time.time()
    time_dl = ((time_stamp_2-time_stamp_1)*1000)
    time_dl_list.append(time_dl)
    
print(time_dl_list)