from asyncio import Protocol, CancelledError
from hashlib import pbkdf2_hmac
from binascii import hexlify
from sys import stdout


from utils.mixins import ConvertMixin, DbInterfaceMixin
from utils.client_messages import JimClientMessage



class ChatClientProtocol(Protocol, ConvertMixin, DbInterfaceMixin):
    def __init__(self, db_path, loop, tasks=None, username=None, password=None, gui_instance=None, **kwargs):
        super().__init__(db_path)
        self.user = username
        self.password = password
        self.jim = JimClientMessage()
        self.gui_instance = gui_instance
        self.tasks = tasks

        self.conn_is_open = False
        self.loop = loop
        self.sockname = None
        self.transport = None
        self.output = None


    def connection_made(self, transport):
        """ Called when connection is initiated """
        self.sockname = transport.get_extra_info("sockname")
        self.transport = transport
        self.send_auth(self.user, self.password)
        self.conn_is_open = True

    def connection_lost(self, exc):

        try:
            self.conn_is_open = False
            for task in self.tasks:
                task.cancel()

        except:
            pass

        finally:
            self.loop.stop()
            self.loop.close()

    def send_auth(self, user, password):
        """send authenticate message to the server"""
        if user and password:
            self.transport.write(
                self._dict_to_bytes(self.jim.auth(user, password)))

    def data_received(self, data):
        """
        Receive data from server and send output message to console/gui
        :param data: json-like dict in bytes
        :return:
        """
        msg = self._bytes_to_dict(data)
        if msg:
            try:

                if msg['action'] == 'probe':

                    self.transport.write(self._dict_to_bytes(
                        self.jim.presence(self.user,status="Connected from {0}:{1}".format(*self.sockname))))

                elif msg['action'] == 'response':
                    if msg['code'] == 200:
                        pass

                    elif msg['code'] == 402:
                        self.connection_lost(CancelledError)
                    else:
                        self.output(msg)

                elif msg['action'] == 'msg':
                    self.output(msg)
            except Exception as e:
                print(e)

    async def get_from_console(self):

        while not self.conn_is_open:
            pass

        self.output = self.output_to_console
        self.output(
            "{2} connected to {0}:{1}\n".format(*self.sockname, self.user))

        while True:
            content = await self.loop.run_in_executor(None,input)

    def output_to_console(self, data):

        _data = data

        stdout.write(_data)

    def send(self, request):

        if request:
            msg = self._dict_to_bytes(request)
            self.transport.write(msg)

    def send_msg(self, to_user, content):

        if to_user and content:
            request = self.jim.message(self.user, to_user, content)
            self.transport.write(self._dict_to_bytes(request))

    def get_from_gui(self):
        self.output = self.output_to_gui

    def output_to_gui(self, msg, response=False):
        try:
            if self.gui_instance:
                if response:
                    self.gui_instance.is_auth = True

                if self.user == msg['to']:
                    self.gui_instance.chat_ins()

        except Exception as e:
            print(e)


class ClientAuth(ConvertMixin, DbInterfaceMixin):

    def __init__(self, db_path, username=None, password=None):
        super().__init__(db_path)
        self.username = username
        self.password = password
        
    def authenticate(self):
        """authentication method, which verify user in DB"""

        # check user in DB
        if self.username and self.password:
            usr = self.get_client_by_username(self.username)
            dk = pbkdf2_hmac('sha256', self.password.encode('utf-8'),
                            'salt'.encode('utf-8'), 100000)
            hashed_password = hexlify(dk)

            if usr: 
                # existing user
                if hashed_password == usr.password:
                    # add client's history row
                    self.add_client_history(self.username)
                    return True
                else:
                    return False
            else: 
                # new user
                print('new user')
                self.add_client(self.username, hashed_password)
                # add client's history row
                self.add_client_history(self.username)
                return True
        else:
            return False
