import multiprocessing
import time

def tx(shared_list):
    idx = 0
    while True:
        shared_list.append(f'tx: {idx}')
        idx += 1
        print(f"tx: {list(shared_list)}")
        time.sleep(2)

def rx(shared_list):
    idx = 0
    while True:
        shared_list.append(f'rx: {idx}')
        idx += 1
        print(f"rx: {list(shared_list)}")
        time.sleep(2)

def main():
    manager = multiprocessing.Manager()
    shared_list = manager.list()  # Создаем общий список
    print('start')
    
    # Создаем процессы
    tx_process = multiprocessing.Process(target=tx, args=(shared_list,))
    rx_process = multiprocessing.Process(target=rx, args=(shared_list,))

    # Запускаем процессы
    tx_process.start()
    rx_process.start()

    # Ожидаем завершения процессов
    tx_process.join()
    rx_process.join()
    
if __name__ == "__main__":
    main()