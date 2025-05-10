# wlcg-voms
Extracted version of all WLCG VOMS packages from <https://linuxsoft.cern.ch/wlcg/>.

## Updating the repository

The script used to extract the latest package versions and download them is
[`get_repo_packages.txt`].

### Requirements

```shell
python -m pip install packages
# If on macOS:
brew install rpm2cpio
```

### Execution

```shell
python get_repo_packages.py --filter wlcg-voms --extract-dir ./
python get_repo_packages.py --filter wlcg-iam --extract-dir ./
```
