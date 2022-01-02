# Import modules
import sys
import time
import os
import re
from geoip2.database import Reader
from pathlib import Path
import tarfile
import shutil
from sqlalchemy import create_engine
import subprocess
import argparse

# Import custom modules
from lib.show import show_table
from lib.record import bind_engine, record_banned


# SQL Alchemy Main Config
# ------------------------------------------------------------------------------
engine = create_engine("sqlite:///sqlite.db")
bind_engine(engine)


# Code blocks for main program of f2b_geo.py
# ------------------------------------------------------------------------------ 
def mmdb_download(action="download", license_key="LICENSE_KEY_HERE"):
    """Download City and ASN binary (.mmdb) database files.

    Parameter
    --------
    action: str
      If 'download', downloads the gzipped database. If 'clean', delete downloaded stuff
    license_key: str
      License key (registration required), passed by --license parameter at the CLI
    """
    # Preparing to download City database
    url_city = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
    db_city = "GeoLite2-City"

    # Preparing to download ASN database
    url_asn = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key={license_key}&suffix=tar.gz"
    db_asn = "GeoLite2-ASN"

    # If 'download' is passed, download, extract, and move GeoLite2-City.mmdb to root cwd
    if action == "download":
        if license_key == "LICENSE_KEY_HERE":
            raise Exception("License key not present, please pass the --license parameter")
        
        for _db, _url in zip([db_city, db_asn], [url_city, url_asn]):
            if not Path(f"{_db}.mmdb").is_file():
            # Using system's wget to download the database
                _args = ["wget", "-O", f"{_db}.tar.gz", _url]
                subprocess.check_output(_args)
            
            if not Path(f"{_db}.tar.gz").is_file():
                raise Exception("Fatal error, download failed")
            
            else:
                file_archive = tarfile.open(f"{_db}.tar.gz")
                file_archive.extractall(_db)
                file_archive.close()

            for _f in Path(_db).rglob("*.mmdb"):
                Path(f"{_db}.mmdb").write_bytes(_f.read_bytes())

            shutil.rmtree(_db, ignore_errors=True)
            os.remove(f"{_db}.tar.gz")

     # If 'clean' is passed at the cli (argparse), delete the .mmdb database
    elif action == "clean":
        for _db in [db_city, db_asn]:
            os.remove(f"{_db}.mmdb")

    else:
        raise Exception("Invalid option, use either 'download' or 'clean'")


def regex_match_string():
    """Specifically to match the following string:
    2021-12-31 07:47:02,358 fail2ban.actions        [24605]: NOTICE  [sshd] Ban 74.87.110.94

    By using named matched groups:
      _datetimestr : group "datetime", formatted as 2021-12-31 00:00:00
      _status      : group "status", formatted as "Ban"
      _ip          : group "ip", formatted as "127.0.0.1"

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
    _datetimestr ="(?P<datetimestr>[\d]{4}-[\d]{2}-[\d]{2} [\d]{2}:[\d]{2}:[\d]{2})"
    _junk = "(.+?sshd\] )"
    _status = "(?P<status>\w*)"
    _ip = "(?P<ip>[\d]*.[\d]*.[\d]*.[\d].*)"
    _crap = "\ - (.*)"

    _combined_string = _datetimestr + _junk + _status + " " + _ip
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


def geoip_reader(cap):
    """Return information after reading .mmdb database using geoip2.database.Reader()
    
    Return
    ------
    cap_info: dict[str]
      Information of the offending IP
    """
    cap_info = {}
    
    # Obtain information from GeoLite2-City.mmdb
    with Reader("GeoLite2-City.mmdb") as reader:
        x = reader.city(cap["ip"])
        cap_info = {"ip": cap["ip"],
                    "datetimestr": cap["datetimestr"],
                    "Country": x.country.name,
                    "Division": x.subdivisions.most_specific.name,
                    "City": x.city.name,
                    "Latitude": x.location.latitude,
                    "Longitude": x.location.longitude}

    # Obtain information from GeoLite2-ASN.mmdb
    with Reader("GeoLite2-ASN.mmdb") as reader:
        x = reader.asn(cap["ip"]) 
        cap_info["Network"] = x.network.with_prefixlen
        cap_info["ASN"] = x.autonomous_system_number
        cap_info["Org"] = x.autonomous_system_organization

    return cap_info


def main(path_log="/var/log/fail2ban.log"):
    """Start logging offending IPs that were successfully banned after 3 failed attempts

    Parameters
    ----------
    path_log: str
      Defaults to location of fail2ban.log file
    """
    # Check location for /var/log/fail2ban.log
    if not Path(path_log).is_file():
        raise FileNotFoundError

    # Follow the log file
    logfile = open(path_log, "r")
    loglines = follow(logfile)

    # Generate regex matching object
    compiled = regex_match_string()

    for line in loglines:
        if line.find("NOTICE") != -1:
            cap = compiled.search(line).groupdict()
            if cap["status"] == "Ban":
                cap_info = geoip_reader(cap)
                
                # Commit to sqlite database and print to stdout
                record_banned(cap_info)
                cap_statement = f"Banned {cap_info['ip']} from {cap_info['Division']}, {cap_info['Country']} at {cap_info['datetimestr']}"
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
    show = subparser.add_parser("show")

    # Sub-command for downloading .mmdb binary database from MaxMind server
    download.add_argument("--license", type=str, required=True, default=None,
                          help="Register an account with MaxMind to get a license key to download the .mmdb file")

    # Sub-command for the actual monitoring
    start.add_argument("--logfile", type=str, required=False,
                       default="/var/log/fail2ban.log", help="Location of Fail2Ban logfile")
    
    # Sub-command to show table
    show.add_argument("--table", type=str, required=False,
                      default="banned", help="Table to print to stdout")
    show.add_argument("--db", type=str, required=False,
                      default="sqlite.db", help="Location of the sqlite db file")

    # Complete the activation of ArgumentParser()
    args = parser.parse_args()
    
    # Conditional switching
    if args.command == "download":
        mmdb_download(action="download", license_key=args.license)
    elif args.command == "start":
        main(path_log=args.logfile)
    elif args.command == "clean":
        mmdb_download(action="clean")
    elif args.command == "show":
        show_table(table=args.table, db=args.db)
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
