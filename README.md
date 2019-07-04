# RPi Picture


## Setup Raspberry Pi
### Install Raspbian
I've only tested with RASPBIAN STRETCH WITH DESKTOP November 2017 version

### Enable auto login (Optional)
```
sudo raspi-config
```
Select “Boot Options” then “Desktop/CLI” then “Console Autologin”

### Compile & Install
#### Compile Video Shuffler for Raspberry Pi
```
GOARM=6 GOARCH=arm GOOS=linux go build -o rpi_pic
```

#### Install
To Install:
1. copy compiled binary to ```/home/pi/rpi_pic```
2. copy config.yaml to ```/home/pi/config.yaml```
3. copy video files to match BasePath in config.yaml

### Startup with SYSTEMD
The best method (that I've found) to running a go program on a Raspberry Pi at startup is to use the **systemd** files. **systemd** provides a standard process for controlling what programs run when a Linux system boots up. 
Note that **systemd** is available only from the Jessie versions of Raspbian OS.

#### 1. Create A Unit File
Create a service file at the following location:
```
sudo touch /lib/systemd/system/rpi_pic.service
```

Edit the file to look like this:
```
[Unit]
 Description=Video Shuffler
 After=multi-user.target

 [Service]
 Type=idle
 ExecStart=/home/pi/rpi_pic

 [Install]
 WantedBy=multi-user.target
```

This defines a new service called “Video Shuffler” and we are requesting that it is launched once the multi-user environment is available. The “ExecStart” parameter is used to specify the command we want to run. The “Type” is set to “idle” to ensure that the ExecStart command is run only when everything else has loaded. Note that the paths are absolute.

The permission on the unit file needs to be set to 644 :
```
sudo chmod 644 /lib/systemd/system/rpi_pic.service
```

#### **2. Configure systemd**
Now the unit file has been defined we can tell systemd to start it during the boot sequence :
```
sudo systemctl daemon-reload
sudo systemctl enable rpi_pic.service
```

Reboot the Pi and your custom service should run:
```
sudo reboot
```

### update app if neded
```
sudo systemctl stop rpi_pic.service
 ```
recompile and copy file
```
sudo reboot
```

## Config
Config options can be change by editing 

### Shuffle 
```Shuffle: true```
Randomize video playback. Videos are randomized on every reboot. 

### Autostart
```Autostart: false```
Start plaing a video once OS has loaded. Otherwise press button to start.

### BasePath
```BasePath: /home/pi/Videos/Simpsons*```
Golang filepath.Glob pattern (https://golang.org/pkg/path/filepath/#Glob). 
For pattern info see: https://golang.org/pkg/path/filepath/#Match 