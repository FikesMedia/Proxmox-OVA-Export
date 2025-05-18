# Proxmox VE to OVA Export Script (`ovaexport.sh`)

This Bash script facilitates the export of a Proxmox VE Virtual Machine (VM) to a single OVA (Open Virtual Appliance) file. The OVA file will contain an OVF (Open Virtualization Format) descriptor and VMDK (Virtual Machine Disk Format) versions of the VM's disks, suitable for import into other hypervisors like VMware vSphere, Workstation/Fusion, VirtualBox, etc.

**This script is designed to be run directly on a Proxmox VE host with root privileges.**

## Features

* Exports a specified Proxmox VE QEMU/KVM VM.
* Retrieves VM configuration directly from the Proxmox VE environment.
* Supports various Proxmox storage types for disk images (Directory, LVM, LVM-thin, ZFS, NFS, CIFS, RBD).
* Converts VM disks to `streamOptimized` VMDK format.
* Generates an OVF 1.0 descriptor file with VM hardware specifications.
* Packages the OVF descriptor and VMDK disk(s) into a single `.ova` archive.
* Attempts to map Proxmox OS types and hardware to common OVF/VMware equivalents.

## Requirements

1.  **Proxmox VE Host:** The script must be run on the Proxmox VE host where the target VM resides.
2.  **Root Access:** Root privileges are required to access VM configurations, disk paths, and execute necessary commands.
3.  **Required Packages:** Ensure the following command-line utilities are installed on your Proxmox VE host:
    * `qm`: Proxmox VE VM management tool (standard).
    * `pvesh`: Proxmox VE shell/API tool (standard).
    * `jq`: Command-line JSON processor.
        * Install if missing: `apt update && apt install jq`
    * `qemu-img`: QEMU disk image utility (usually standard with `qemu-utils`).
        * Install if missing: `apt update && apt install qemu-utils`
    * `tar`: The GNU tar archiving utility (standard).
    * `sha256sum`: For generating checksums (standard, part of `coreutils`).
    * `uuidgen`: For generating unique IDs (standard, part of `util-linux`).
    * `bc`: Basic command-line calculator (standard).
    * `stat`: Display file or file system status (standard, part of `coreutils`).
4.  **Sufficient Disk Space:**
    * **Temporary Space:** The script creates a temporary working directory (usually in `/tmp`) to store converted VMDK files before packaging. This will require space roughly equivalent to the *virtual size* of all VM disks.
    * **Output Space:** The location for the final `.ova` file must have enough space to hold the packaged appliance.

## Script Download and Preparation

1.  Download the `ovaexport.sh` script to your Proxmox VE host.
2.  Make it executable:
    ```bash
    chmod +x ovaexport.sh
    ```

## How to Run the Script

Execute the script as the `root` user or using `sudo`:

```bash
sudo ./ovaexport.sh <VMID> <output_ova_filepath>