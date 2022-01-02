# Unit Files For `systemd`

Run the following commands from the directory where `f2bgeo` and `failedsshd` binaries are located, because it uses shell `pwd` command to get the binaries' absolute path.
The following commands install `f2bgeo.service` and `failedsshd.service` unit files to `/lib/systemd/system/` directory.

For `f2bgeo`.

```bash
cat << EOF | sudo tee /lib/systemd/system/f2bgeo.service > /dev/null 2>&1
[Unit]
Description=f2bgeo fail2ban.log monitoring service
After=fail2ban.service
Wants=fail2ban.service
StartLimitInterval=500
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/f2bgeo start
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
```

For `failedsshd`.

```bash
cat << EOF | sudo tee /lib/systemd/system/failedsshd.service > /dev/null 2>&1
[Unit]
Description=failedsshd monitoring service
StartLimitInterval=500
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/failedsshd
User=$USER
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
```

Enable at boot and run both services:

```bash
sudo systemctl enable --now f2bgeo.service
sudo systemctl enable --now failedsshd.service
```
