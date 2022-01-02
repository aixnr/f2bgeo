from os import path
import sys
import subprocess
import select
import re
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Float
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from geoip2.database import Reader
import argparse


# SQL Alchemy Main Config
# ------------------------------------------------------------------------------ 
# Define engine and location
engine = create_engine("sqlite:///sqlite.db")

# Set up the database: return base class
Base = declarative_base()

class Record(Base):
    """ORM class for handling denied user
    """
    __tablename__ = "ssh_denied"

    id = Column(Integer, primary_key=True)
    datetimestr = Column(String)
    unixepoch = Column(Float)
    userid = Column(String)
    ip = Column(String)
    city = Column(String)
    division = Column(String)
    country = Column(String)
    latitude = Column(String)
    longitude = Column(String)

    def __repr__(self):
        return f"Denied {self.userid} from {self.ip} at {self.datetimestr}"

# Issue create table command
Base.metadata.bind = engine
Base.metadata.create_all(engine)

# Creates new session
Session = sessionmaker()
session = Session()
Session.configure(bind=engine)


def regex_matcher(line, match_to):
    """
    Parameter
    ---------
    line: str
    match_to: str

    Return
    ------
    _caught: dict
    """
    # Matches:
    _datetimestr = "(?P<datetimestr>\w+ [\d]{2} [\d]{2}:[\d]{2}:[\d]{2})"
    _ip = "(?P<ip>[\d]*.[\d]*.[\d]*.[\d]*)"

    # Matches to: "Dec 26 00:32:17 athena sshd[1036130]: Invalid user support from 92.255.85.37 port 32036"
    # Named groups: datetimestr, user, ip
    _invalid_user = rf"{_datetimestr}(.+?user )(?P<userid>\w*)( from ){_ip}(.*)"

    # Matches to: "Jan 02 02:26:35 athena sshd[1156190]: User root from 98.13.35.92 not allowed because not listed in AllowUsers"
    # Named groups:
    _root_user = rf"{_datetimestr}(.* User root from ){_ip}(.*)"

    _caught = {}
    
    if match_to == "invalid":
        _compiled = re.compile(_invalid_user)
        _caught = _compiled.search(line).groupdict()
    elif match_to == "root":
        _compiled = re.compile(_root_user)
        _caught = _compiled.search(line).groupdict()
        _caught["userid"] = "root"

    return _caught


def record(caught_dict, mmdb):
    """
    Parameter
    ---------
    caught_dict: str
      Output from regex_matcher()

    Return
    ------
    None, committing to database
    """
    _userid = caught_dict["userid"]
    _ip = caught_dict["ip"]

    # Because journalctl logs time in "Dec 26 00:32:17" format
    _datetime_object = datetime.strptime(f"{datetime.now().year} {caught_dict['datetimestr']}",
                                        "%Y %b %d %H:%M:%S")

    # Making it human readable
    _date = datetime.strftime(_datetime_object, "%Y-%b-%d %H:%M:%S")

    # Unixepoch value (for timeseries), float
    _unixepoch = _datetime_object.timestamp()

    # Read where they are coming from
    with Reader(mmdb) as reader:
        x = reader.city(_ip)
        _country = x.country.name
        _division = x.subdivisions.most_specific.name
        _city = x.city.name
        _lat = x.location.latitude
        _lon = x.location.longitude

    print(f"Caught {_userid} from {_ip} at {_date}")

    denied_record = Record(
        datetimestr = _date,
        unixepoch = _unixepoch,
        userid = _userid,
        ip = _ip,
        country = _country,
        division = _division,
        city = _city,
        latitude = _lat,
        longitude = _lon
    )

    session.add(denied_record)
    session.commit()


def journal_tail():
    """Reading journalctl using subprocess.Popen()

    Steps
    -----
      1) Create the command 'f'
      2) Initiate polling for 'f.stdout'
      3) Poll for every 100 ms
      4) Yield result for main() to consume

    Return
    ------
      line: Iterator[str]
    """
    args = ["journalctl", "--follow", "-u", "sshd", "--lines", "0"]
    f = subprocess.Popen(args, stdout=subprocess.PIPE)

    p = select.poll()
    p.register(f.stdout)
    
    while True:
        # Polling for every 100 ms
        if p.poll(100):
            line = f.stdout.readline().decode()
            yield line


def main(path_mmdb):
    journal = journal_tail()
    for line in journal:
        if line.find("Invalid") != -1:
            caught = regex_matcher(line, match_to="invalid")
            record(caught, mmdb=path_mmdb)
        elif line.find("User root") != -1:
            caught = regex_matcher(line, match_to="root")
            record(caught, mmdb=path_mmdb)
        

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mmdb", type=str, required=False, default="GeoLite2-City.mmdb")
    args = parser.parse_args()

    main(path_mmdb=args.mmdb)


if __name__ == "__main__":
    try:
        cli()
    except KeyboardInterrupt:
        sys.exit()
