# P4_ml_project
## Getting Started
### Install Docker
https://www.docker.com/get-started/

### P4 Compiler
https://github.com/p4lang/p4c

### P4 Mininet Docker
https://github.com/opennetworkinglab/p4mn-docker

### P4Runtime Shell
https://github.com/p4lang/p4runtime-shell

## Usage

Create mininet
``` bash
p4mn
```
Set up Controller
``` bash
python3 runtime_digest_predict.py
```

Get into host shell

Example:
```bash
(sudo) nsenter -a -t `pgrep -f mininet:h1`
```
