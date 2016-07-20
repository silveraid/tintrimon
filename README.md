# tintrimon

A Nagios monitoring plugin written in Python focusing on generic errors and available free space.


### Requirements

* Python 2.7 (hopefully works with Python 3.x as well)


### Usage
```
usage: tintrimon.py [-h] -s HOST -u USER -p PASSWORD -w WARNING -e ERROR [-v]

optional arguments:
  -h, --help            show this help message and exit
  -s HOST, --host HOST  The IP address or the hostname of the datastore
  -u USER, --user USER  Username with read-only access
  -p PASSWORD, --password PASSWORD
                        Password belongs to the user
  -w WARNING, --warning WARNING
                        Nagios warning threshold in GB (free raw space)
  -e ERROR, --error ERROR
                        Nagios error threshold in GB (free raw space)
  -v, --verbose
```