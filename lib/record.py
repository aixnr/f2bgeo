from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base


# Initial configuration
Base = declarative_base()
Session = sessionmaker()
session = Session()


def bind_engine(engine):
    """Main program creates engine object, this script 'uses' it.
    Using session so that we could utilize ORM instead of raw SQL commands.
    """
    Base.metadata.bind = engine
    Session.configure(bind=engine)
    Base.metadata.create_all(engine)


class Record(Base):
    """ORM class for handling banned IP addresses
    """
    __tablename__ = "banned"

    id = Column(Integer, primary_key=True)
    date = Column(String)
    time = Column(String)
    ip = Column(String)
    city = Column(String)
    division = Column(String)
    country = Column(String)
    latitude = Column(String)
    longitude = Column(String)

    def __repr__(self):
        return f"Banned {self.ip}"


def record_banned(cap_info):
    """Commits info on banned IP addresses after being read by geoip2.database.Reader()
    """
    ip_banned = Record(
        date = cap_info["date"],
        time = cap_info["time"],
        ip = cap_info["ip"],
        country = cap_info["Country"],
        division = cap_info["Division"],
        city = cap_info["City"],
        latitude = cap_info["Latitude"],
        longitude = cap_info["Longitude"]
    )

    session.add(ip_banned)
    session.commit()
