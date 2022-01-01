# `f2bgeo` Fail2Ban GeoLocation Script 

I wanted to know which regions, roughly, were the offending IPs that tried to get into my SSH coming from.
MaxMind provides the *lite* version of their GeoIP2 offering called [GeoLite2](https://dev.maxmind.com/geoip?lang=en), albeit at a lower accuracy, for free.
But that is fine for my purpose, which is just to assign *identifier* to the IP addresses that my Fail2Ban configuration blocked after 3 failed attempts.

User of this script needs to [register an account with MaxMind to access GeoLite2](https://www.maxmind.com/en/geolite2/signup).
MaxMind imposes a limitation of 1,000 IP lookups per day if users are performing API query.
However, I decided to do it slightly differently by downloading their database file.
All users are imposed with [2,000 total direct downloads limit in a 24 hour period](https://support.maxmind.com/hc/en-us/articles/4408216129947).

**Table of Contents**

- [Dependencies](#dependencies)
- [Fail2Ban SSHD Jail](#fail2ban-sshd-jail)
- [Downloading MaxMind GeoLite2 Database](#downloading-maxmind-geolite2-database)
- [Running](#running)
- [How Does It Work](#how-does-it-work)
- [License](#license)

## Dependencies

Create a virtual environment for python (tested with `conda env` and `python -m venv`) and download the following modules.

```bash
# Required by f2bgeo.py
pip install geoip2 maxminddb sqlalchemy

# For generating standalone linux executable
pip install pyinstaller
```

To compile `f2bgeo.py` script into a standalone linux executable with `pyinstaller`:

```bash
pyinstaller --onefile f2bgeo.py
```

Locate the compiled binary at `./dist/f2bgeo`.
To run it, `f2bgeo` depends on system's `wget` to download the database archive from MaxMind website.

The rationale for compiling into a binary file because I was developing the script locally with the aforementioned dependencies.
For deploying on a remote server, I prefer not to set up the environments again and would rather run it as a binary.
Another reason is that `f2bgeo` needs to access `/var/local/fail2ban.log` which is restricted to root.
Running the script with `sudo python f2geo.py start` leads to an interesting complication.

## Fail2Ban SSHD Jail

My `/etc/fail2ban/jail.local` contains the following block for `sshd`:

```bash
[sshd]
enabled = true
port = 22
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
```

As I recently discovered on Fedora, `fail2ban` uses `firewalld` for updating `iptables` instead of using `iptables` itself.
Since I am using `ufw` as my firewall frontend (and having `firewalld` disabled through `systemctl`), `fail2ban` would still report offending IP but cannot block.

To fix this, simply rename `/etc/fail2ban/jail.d/00-firewalld.conf` to `/etc/fail2ban/jail.d/00-firewalld.conf.disabled`.
This basically prevents `fail2ban` from using `firewalld` and defaulting it back to `iptables`.
Verify this by restarting `fail2ban` and tail `/var/log/fail2ban.log`.

```bash
# Before renaming
>> ERROR   Failed to execute ban jail 'sshd' action 'firewallcmd-rich-rules'
```

I did this because `firewalld` kicked me out of my SSH session soon after activation.
Since I was not in the mood to learn yet another firewall tool, I decided to just stick with `iptables` and `ufw`.

## Downloading MaxMind GeoLite2 Database

There are [three different databases](https://dev.maxmind.com/static/pdf/GeoLite2-IP-MetaData-Databases-Comparison-Chart.pdf): GeoLite2 *ASN*, GeoLite2 *City*, and GeoLite2 *Country*.
The *City* version contains everything that is in the *Country* but offers more information pertaining to an IP.
The *ASN* version provides two additional information: ASN info and name of the organization (ISP) managing that ASN.
`f2bgeo.py` is designed for the `City` version. 

To download the database (the scripts handles extraction):

```bash
./f2bgeo download --license "LICENSE_KEY"
```

It downloads the database archive `GeoLite2-City.tar.gz`, extracts it, and place `GeoLite2-City.mmdb` in current directory.

According to MaxMind, they update the databases weekly on Tuesday. For users that would like to automate the download (`cron` or `systemd` timer), `f2bgeo` provides `clean` subcommand to remove the `GeoLite2-City.mmdb` file for convenience.

```bash
./f2bgeo clean
```

## Running

Run as root since it needs to read `/var/log/fail2ban.log`:

```bash
sudo ./f2bgeo start
```

It runs at the foreground and spitting information on banned IPs.
At the same time, it also writes to a local `sqlite.db` database file.

```bash
Banned 2.56.57.216 from Virginia, United States at 11:00
Banned 180.73.43.14 from Selangor, Malaysia at 14:07
Banned 116.105.222.202 from Da Nang, Vietnam at 15:32
Banned 116.98.60.14 from Ho Chi Minh, Vietnam at 15:33
Banned 84.58.27.240 from North Rhine-Westphalia, Germany at 16:22
```

Users can write a `systemd` unit file to automate this process.
Otherwise, running through a `tmux` session is fine too.

I included data persistence with SQLite because I wanted to visualize the dataset later.
Although visualization on Grafana can be done using Promtail and Loki, I decided to use SQLite so I did not spend extra time debugging Grafana/Loki/Promtail if it did not work.

## How Does It Work?

Fail2Ban logs data to `/var/log/fail2ban.log` file (check your distro).
`f2bgeo` reads it and identifies *ban* event based on a set of `regex` rules (see `regex_match_string()`), and then returned `re.groupdict()` (a dictionary of strings) of regex named capture as `cap_info`.

The `main()` function passes `cap_info` to `geoip_reader()` which uses `geoip2.database.Reader()` to return GeoIP information associated with `cap_info["ip"]`.
It then prints to `stdout` and logs to the `sqlite.db` through `record_banned()` function.

The following information are stored in `sqlite.db`: date, time, ip, city, division, country, latitude, longitude.
For time-series visualization, users need to convert date and time to linux epoch (not implemented in the script).
In SQLite, this can be done with the following sql query:

```sql
SELECT
  strftime("%s", date || " " || time) as epochtime
FROM
  banned
```

## License

The MIT License

Copyright 2022, Aizan Fahri @aixnr

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
