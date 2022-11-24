from subprocess import Popen, CREATE_NEW_CONSOLE

PROCESS = []

while True:
    ANSWER = input('Выберите действие: q - выход, '
                   's - запустить сервер и клиенты, x - закрыть все окна: ')

    if ANSWER == 'q':
        break
    elif ANSWER == 's':
        PROCESS.append(Popen('python server/run_server.py"',
                             creationflags=CREATE_NEW_CONSOLE))

        for i in range(2): 
            PROCESS.append(Popen('python client/run_client.py',
                                 creationflags=CREATE_NEW_CONSOLE))

    elif ANSWER == 'x':
        while PROCESS:
            VICTIM = PROCESS.pop()
            VICTIM.kill()
