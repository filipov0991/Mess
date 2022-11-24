from datetime import datetime as dt
from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy import Column, Integer, String, DateTime, LargeBinary , Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, backref
from sqlalchemy import Unicode


CBase = declarative_base()

class Client(CBase):
    """Таблица с клиентами"""
    __tablename__ = 'client'

    id = Column(Integer(), primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password = Column(LargeBinary(), nullable=False)
    info = Column(String(255), default='')
    online_status = Column(Boolean(), default=False)


class History(CBase):
    """Таблица с историей входов клиентов"""
    __tablename__ = 'history'

    id = Column(Integer(), primary_key=True)
    time = Column(DateTime(), default=dt.now(), nullable=False)
    ip_addr = Column(String(255))
    client_id = Column(Integer(), ForeignKey('client.id'))
    client = relationship('Client',
                          backref=backref('history', order_by=client_id))


class Contacts(CBase):
    """Таблица с контактами(друзьями) клиента"""
    __tablename__ = 'contacts'
    __table_args__ = (
        UniqueConstraint('client_id', 'contact_id', 
						name='unique_contact'),)

    id = Column(Integer(), primary_key=True)
    client_id = Column(Integer(), ForeignKey('client.id'))
    contact_id = Column(Integer(), ForeignKey('client.id'))
    client = relationship("Client", foreign_keys=[client_id])
    contact = relationship("Client", foreign_keys=[contact_id])


class Messages(CBase):
    """История сообщений клиента"""
    __tablename__ = 'messages'

    id = Column(Integer(), primary_key=True)
    client_id = Column(Integer(), ForeignKey('client.id'))
    contact_id = Column(Integer(), ForeignKey('client.id'))
    time = Column(DateTime(), default=dt.now(), nullable=False)
    client = relationship("Client", foreign_keys=[client_id])
    contact = relationship("Client", foreign_keys=[contact_id])
    message = Column(Unicode())
