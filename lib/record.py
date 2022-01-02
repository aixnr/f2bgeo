from sqlalchemy import Column, Integer, String, Float
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime


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
    datetimestr = Column(String)
    unixepoch = Column(Float)
    ip = Column(String)
    city = Column(String)
    division = Column(String)
    country = Column(String)
    latitude = Column(String)
    longitude = Column(String)
    network = Column(String)
    asn = Column(String)
    org = Column(String)

    def __repr__(self):
        return f"Banned {self.ip}"


def record_banned(cap_info):
    """Commits info on banned IP addresses after being read by geoip2.database.Reader()
    """
    # Convert datetimestr to unixepoch
    _unixepoch = datetime.strptime(cap_info["datetimestr"], "%Y-%m-%d %H:%M:%S").timestamp()

    # Start adding to the database
    ip_banned = Record(
        datetimestr = cap_info["datetimestr"],
        unixepoch = _unixepoch,
        ip = cap_info["ip"],
        country = cap_info["Country"],
        division = cap_info["Division"],
        city = cap_info["City"],
        latitude = cap_info["Latitude"],
        longitude = cap_info["Longitude"],
        network = cap_info["Network"],
        asn = cap_info["ASN"],
        org = cap_info["Org"]
    )

    # Commit to the database
    session.add(ip_banned)
    session.commit()
