import os
home = os.path.dirname(os.path.abspath(__file__))

# constants
PORT = 14908
ENCODING = 'utf-8'

# Database
DB_PROTOCOL = 'sqlite:///'
DB_NAME = '/client_con.db'
DB_PATH = DB_PROTOCOL + home + DB_NAME
