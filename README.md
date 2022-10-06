# Paper-LADEMU

LADEMU (Labelled Apt Datasets from EMUlations) is a proof-of-concept implementation of a dataset labeler which is integrated with the Mitre CALDERA emulation platform and uses the GHOSTS framework for benign behaviour. 

The host log Labeller is located in the HostLabeller folder, and the network log labeller is located in the NetworkLabeller folder.

## Installation and usage
The host labeller is written in C# and the network labeller is written in python and bash.

### Network labeller
Requirements:
- Wireshark
- Pyshark
- Pytz

After installing dependencies, the program can be run with 'python main.py'. See 'python main.py --help' for command line options.


## Dataset files
The datasets files are located in the Datasets folder and separated into HostData and NetworkData.

## License
This repository is available under the MIT License. See the license file for details.