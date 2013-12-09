# Disass

Disass is a binary analysis framework written in Python to ease the automation of static malware reverse engineering. The purpose of Disass is to automatically retrieve relevant information in a malware such as the C&C, the user agent, cipher keys, etc.

## Install
Checkout the source: `hg clone http://bitbucket.cassidiancybersecurity.com/disass` and there are a few different ways to use disass. 

* Install disass : 
```shell
pip install -r requirements.txt
python setup.py install
```

* Just use it without any installation

   
## Getting Started

## Examples

Search Mutex name in malware:

```python
import sys
import argparse
from disass.Disass32 import Disass32

disass = Disass32(path='malware.exe', verbose=True)

if disass.go_to_next_call('CreateMutex'):
    address_mutex = disass.get_arguments(3)
    print "  Mutex\t:", disass.get_string(address_mutex)

```


It's possible to navigate easily with X references
```python
import sys
from disass.Disass32 import Disass32

disass = Disass32(path='malware.exe', verbose=True)


disass.make_xref()

for address in disass.xref['InternetOpenA']:
    disass.set_position(address)

    # Do some code
```




## Author

Disass is written by Ivan Fontarensky (ivan.fontarensky_at_cassidian.com)
who is currently working at Cassidian CyberSecurity.


## Licence

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation version 3 of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
