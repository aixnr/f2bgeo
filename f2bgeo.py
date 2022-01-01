# Import modules
import sys
import time
import os
import re
import geoip2.database
from pathlib import Path
import tarfile
import shutil
from sqlalchemy import create_engine
import subprocess
import argparse


# SQL Alchemy Main Config
# ------------------------------------------------------------------------------
engine = create_engine("sqlite:///sqlite.db")
from lib.record import bind_engine, record_banned
bind_engine(engine)


# Code blocks for main program of f2b_geo.py
# ------------------------------------------------------------------------------ 
def mmdb_download(action="download", license_key="LICENSE_KEY_HERE"):
    """Download GeoLite2 City .mmdb database file

    Parameter
    --------
    action: str
      If 'download', downloads the gzipped database. If 'clean', delete downloaded stuff
    """
    # Preparing to download
    download_url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
    local_file = "GeoLite2-City.tar.gz"
    local_db = "GeoLite2-City.mmdb"

    # If 'download' is passed, download, extract, and move GeoLite2-City.mmdb to root cwd
    if action == "download":
        if license_key == "LICENSE_KEY_HERE":
            raise Exception("License key not present, please pass license_key parameter")
        if not Path(local_file).is_file():
            # Using system's wget to download the database
            subprocess.check_output(["wget", "-O", local_file, download_url])

        file_archive = tarfile.open(local_file)
        file_archive.extractall("GeoLite2")
        file_archive.close()

        if not Path(local_db).is_file():
            for _f in Path("GeoLite2").rglob("*.mmdb"):
                Path(local_db).write_bytes(_f.read_bytes())

        # Delete GeoLite2 directory and GeoLite2-City.tar.gz after extraction
        shutil.rmtree("GeoLite2", ignore_errors=True)
        os.remove(local_file)
    
    # If 'clean' is passed at the cli (argparse), delete the .mmdb database
    if action == "clean":
        os.remove(local_db)


def regex_match_string():
    """Specifically to match the following string:
    2021-12-31 07:47:02,358 fail2ban.actions        [24605]: NOTICE  [sshd] Ban 74.87.110.94

    By using named matched groups:
      _date   : group "date", formatted as "2021-01-01"
      _time   : group "time", formatted as "00:00"
      _status : group "status", formatted as "Ban"
      _ip     : group "ip", formatted as "127.0.0.1"

    Note
    ----
    _junk: str
      Stuff not needed between _time and _status group
    _crap: str (excluded by default)
      Usable when capturing non-Banned line to exclude anything after IP address

    Return
    ------
    compiled: retype
    """
    _date = "(?P<date>[\d]{4}-[\d]{2}-[\d]{2})"
    _time = "(?P<time>[\d]{2}:[\d]{2}:[\d]{2})"
    _junk = "(.+?sshd\] )"
    _status = "(?P<status>\w*)"
    _ip = "(?P<ip>[\d]*.[\d]*.[\d]*.[\d].*)"
    _crap = "\ - (.*)"

    _combined_string = _date + " " + _time + _junk + _status + " " + _ip
    compiled = re.compile(rf"{_combined_string}")

    return compiled


def follow(logfile):
    """Generator for returning last-read line of the logfile
    Similar in functionality using tail -f

    Return
    ------
    line: Iterator[str]
    """
    logfile.seek(0, os.SEEK_END)
    while True:
        line = logfile.readline()

        if not line:
            time.sleep(0.1)
            continue

        yield line


def geoip_reader(cap, mmdb="GeoLite2-City.mmdb"):
    """Return information after reading .mmdb database using geoip2.database.Reader()
    
    Return
    ------
    cap_info: dict[str]
      Information of the offending IP
    """
    cap_info = {}
    with geoip2.database.Reader(mmdb) as reader:
        x = reader.city(cap["ip"])
        cap_info = {"ip": cap["ip"],
                    "time": cap["time"],
                    "date": cap["date"],
                    "Country": x.country.name,
                    "Division": x.subdivisions.most_specific.name,
                    "City": x.city.name,
                    "Latitude": x.location.latitude,
                    "Longitude": x.location.longitude}
        
        return cap_info


def main(path_log="/var/log/fail2ban.log", path_mmdb="GeoLite2-City.mmdb"):
    """Start logging offending IPs that were successfully banned after 3 failed attempts

    Parameters
    ----------
    path_log: str
      Defaults to location of fail2ban.log file
    path_mmdb: str
      Location of GeoLite2-City.mmdb MaxMind binary DB file, defaults to current directory
    """
    # Check for filepaths
    for file_path in [path_log, path_mmdb]:
        _path = Path(file_path)
        if _path.is_file():
            continue
        else:
            raise Exception(f"{file_path} not found")

    logfile = open(path_log, "r")
    loglines = follow(logfile)

    logfile = open("/var/log/fail2ban.log", "r")
    loglines = follow(logfile)

    cap_info = {}
    compiled = regex_match_string()
    for line in loglines:
        if line.find("NOTICE") != -1:
            cap = compiled.search(line).groupdict()
            if cap["status"] == "Ban":
                cap_info = geoip_reader(cap, mmdb=path_mmdb)
                
                # Commit to sqlite database
                record_banned(cap_info)
                
                # Print to stdout
                cap_statement = f"Banned {cap_info['ip']} from {cap_info['Division']}, {cap_info['Country']} at {cap_info['time']}"
                print(cap_statement)


def cli():
    """
    Parser subcommands
    ------------------
    download : For download .mmdb database file from MaxMind server
    start    : Start tailing and recording
    clean    : Clean all the downloaded files
    """
    # Initialize ArgumentParser()
    parser = argparse.ArgumentParser()
    subparser = parser.add_subparsers(dest="command")
    download = subparser.add_parser("download")
    start = subparser.add_parser("start")
    clean_download = subparser.add_parser("clean")

    # Sub-command for downloading .mmdb binary database from MaxMind server
    download.add_argument("--license", type=str, required=True, default=None,
                          help="Register an account with MaxMind to get a license key to download the .mmdb file")

    # Sub-command for the actual monitoring
    start.add_argument("--logfile", type=str, required=False,
                           default="/var/log/fail2ban.log", help="Location of Fail2Ban logfile")
    start.add_argument("--mmdb", type=str, required=False,
                           default="GeoLite2-City.mmdb", help="Location of the .mmdb binary DB file")

    
    # Complete the activation of ArgumentParser()
    args = parser.parse_args()
    
    # Conditional switching
    if args.command == "download":
        mmdb_download(action="download", license_key=args.license)
    elif args.command == "start":
        main(path_log=args.logfile, path_mmdb=args.mmdb)
    elif args.command == "clean":
        mmdb_download(action="clean")
    else:
        # If no subcommand supplied
        parser.print_help()
    

if __name__ == "__main__":
    try:
        # Run cli() function, which first hits ArgumentParser()
        cli()
    
    except KeyboardInterrupt:
        # Gracefully exit without traceback upon Ctrl-c
        sys.exit()