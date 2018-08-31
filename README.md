Ansible modules using the legacy HPE RESTful APIs to configure different iLO settings and BIOS.

Note: Only tested with HPE BL460c Gen8 and DL380 Gen9 servers.

Note: Doesn't work with Python 2.7.5 available on CentOS. It works with Python3.6 or (compiled) Python 2.7.15.

# Setup

1. Create a library directory in your repository and add the repository as a submodule

~~~~
mkdir ./library
git submodule add https://github.com/ckotte/ansible-hpilorest.git library/ansible-hpilorest
~~~~

2. Create a module_utils directory in your repository and link the module utils

~~~~
mkdir -p ./module_utils/ansible-hpilorest
cd ./module_utils/ansible-hpilorest
ln -sf ../../library/ansible-hpilorest/hpilorest.py hpilorest.py
~~~~

3. Add library and module_utils to ansible.cfg

~~~~
library = ./library
module_utils = ./module_utils/ansible-hpilorest
~~~~
