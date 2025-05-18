#!/bin/bash
# Provided by FikesMedia

# ovaexport - Proxmox VE VM to OVA Exporter
# Script to be run directly on a Proxmox VE host as root.


# --- Configuration & Globals ---
DEFAULT_OVF_OS_MAP=(
    ["l24"]="other24xLinux64Guest" # Linux 2.4x Kernel (64-bit)
    ["l26"]="otherLinux64Guest"    # Linux 2.6x/3.x/4.x/5.x Kernel (64-bit) (generic)
    ["wxp"]="winXPPro64Guest"
    ["w2k3"]="winNetEnterprise64Guest" # Windows Server 2003 (64-bit)
    ["w2k8"]="winLonghorn64Guest"      # Windows Server 2008 (64-bit)
    ["wvista"]="winVista64Guest"
    ["win7"]="windows7_64Guest"
    ["win8"]="windows8_64Guest"
    ["win10"]="windows9_64Guest"       # VMware uses 'windows9' for Windows 10
    ["win11"]="windows11_64Guest"
    ["w2k12"]="windows8Server64Guest"  # Windows Server 2012 / R2
    ["w2k16"]="windows9Server64Guest"  # Windows Server 2016
    ["w2k19"]="windows2019srv_64Guest" # Windows Server 2019
    ["w2k22"]="windows2022srvNext_64Guest" # Windows Server 2022 (using a common VMware ID)
    ["solaris"]="solaris11_64Guest"    # Solaris 11 (64-bit)
    ["other"]="otherGuest64"
)
DEFAULT_VMX_VERSION="vmx-19" # Default VMware Hardware Version for the OVF

# --- Helper Functions ---
display_usage() {
    echo "Usage: $0 <VMID> <output_ova_filepath>" >&2
    echo "  VMID: The numeric ID of the Proxmox VM to export." >&2
    echo "  output_ova_filepath: The full path where the .ova file will be saved." >&2
    echo "" >&2
    echo "Example: $0 108 /mnt/export/vm108.ova" >&2
    echo "" >&2
    echo "This script must be run as root on the Proxmox VE host." >&2
}

log_info() {
    echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S'): $1" >&2
}

log_error() {
    echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S'): $1" >&2
}

check_prerequisites() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root."
        exit 1
    fi

    for cmd in qm pvesh jq qemu-img tar sha256sum uuidgen bc stat; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found. Please install it."
            if [[ "$cmd" == "jq" ]]; then
                log_error "Try: apt update && apt install jq"
            fi
            exit 1
        fi
    done
}

convert_proxmox_size_to_bytes() {
    local size_spec="$1"
    local num_part=$(echo "$size_spec" | grep -oP '^\d+(\.\d+)?')
    local unit_part=$(echo "$size_spec" | grep -oP '[GMK]$' | tr '[:lower:]' '[:upper:]')
    local bytes

    if [[ -z "$num_part" ]]; then echo "0"; return; fi

    case "$unit_part" in
        G) bytes=$(echo "$num_part * 1024 * 1024 * 1024" | bc -l | awk '{printf "%.0f", $1}') ;;
        M) bytes=$(echo "$num_part * 1024 * 1024" | bc -l | awk '{printf "%.0f", $1}') ;;
        K) bytes=$(echo "$num_part * 1024" | bc -l | awk '{printf "%.0f", $1}') ;;
        *)
           if [[ "$size_spec" =~ ^[0-9]+$ ]]; then
             bytes=$(echo "$num_part * 1024" | bc -l | awk '{printf "%.0f", $1}')
           else
             log_error "Could not parse size '$size_spec' accurately. Assuming 0."
             echo "0"
             return
           fi
           ;;
    esac
    echo "$bytes"
}

resolve_disk_path_and_format() {
    local disk_string="$1"
    local vm_id="$2"
    local storage_configs_json="$3"

    local storage_id=$(echo "$disk_string" | cut -d':' -f1)
    local volume_part=$(echo "$disk_string" | cut -d':' -f2-)
    local volume_name=$(echo "$volume_part" | cut -d',' -f1)

    local disk_format_in_config=$(echo "$volume_part" | grep -oP 'format=\K[^,]+')
    local source_disk_format=${disk_format_in_config:-raw}

    local storage_info=$(echo "$storage_configs_json" | jq -r --arg sid "$storage_id" '.[] | select(.storage == $sid)')
    if [[ -z "$storage_info" ]]; then
        log_error "Storage ID '$storage_id' not found in Proxmox configuration."
        return 1
    fi

    local storage_type=$(echo "$storage_info" | jq -r '.type')
    local storage_path=$(echo "$storage_info" | jq -r '.path // ""')
    local vgname=$(echo "$storage_info" | jq -r '.vgname // ""')
    local pool=$(echo "$storage_info" | jq -r '.pool // ""')

    local actual_path=""

    case "$storage_type" in
        dir)
            if [[ "$volume_name" == "cloudinit" ]]; then
                 actual_path="${storage_path}/template/iso/${vm_id}-cloudinit.iso"
                 source_disk_format="iso"
            elif [[ "$volume_name" == *":"* ]]; then
                 actual_path="${storage_path}/${volume_name#*:}"
            elif [[ "$volume_name" == *"/"* ]]; then
                 actual_path="${storage_path}/${volume_name}"
            else
                 actual_path="${storage_path}/images/${vm_id}/${volume_name}"
            fi
            ;;
        lvm|lvmthin)
            actual_path="/dev/${vgname}/${volume_name}"
            ;;
        zfspool)
            local full_zfs_name="${pool}/${volume_name}"
            local zvol_path="/dev/zvol/${full_zfs_name}"

            if [[ -b "$zvol_path" ]]; then
                actual_path="$zvol_path"
                log_info "Using ZFS zvol block device path: $actual_path for ${full_zfs_name}"
            else
                actual_path="$full_zfs_name"
                log_info "Using direct ZFS name: $actual_path. /dev/zvol path $zvol_path not found or not a block device."
            fi
            ;;
        nfs|cifs|iscsi|cephfs)
            if [[ "$volume_name" == *"/"* ]]; then
                 actual_path="${storage_path}/${volume_name}"
            else
                 actual_path="${storage_path}/images/${vm_id}/${volume_name}"
            fi
            ;;
        rbd)
            actual_path="rbd:${volume_name}"
            source_disk_format="rbd"
            ;;
        *)
            log_error "Unsupported storage type '$storage_type' for disk '$disk_string'."
            return 1
            ;;
    esac

    if [[ "$storage_type" != "rbd" ]]; then
        if [[ "$storage_type" == "zfspool" && "$actual_path" != /dev/zvol* ]]; then
             log_info "Pre-flight check for ZFS name '$actual_path' with qemu-img info..."
             if ! qemu-img info "$actual_path" &>/dev/null; then
                 log_error "qemu-img info failed for ZFS name '$actual_path'. Disk may not be accessible."
                 return 1
             fi
        elif [[ ! -e "$actual_path" && ! -b "$actual_path" ]]; then
            log_error "Resolved disk path '$actual_path' does not exist or is not accessible for disk string '$disk_string' (type: $storage_type)."
            return 1
        fi
    fi
    echo "$actual_path;$source_disk_format"
}

# --- Main Script ---
if [[ "$#" -ne 2 ]]; then
    display_usage
    exit 1
fi

VMID="$1"
OUTPUT_OVA_PATH="$2"

if ! [[ "$VMID" =~ ^[0-9]+$ ]]; then
    log_error "VMID '$VMID' is not a valid number."
    display_usage
    exit 1
fi

if [[ -d "$OUTPUT_OVA_PATH" ]]; then
    log_error "Output OVA path '$OUTPUT_OVA_PATH' is a directory. Please provide a full filename (e.g., /path/to/vm.ova)."
    exit 1
fi

OUTPUT_DIR=$(dirname "$OUTPUT_OVA_PATH")
if [ ! -d "$OUTPUT_DIR" ]; then
    if ! mkdir -p "$OUTPUT_DIR"; then
        log_error "Failed to create output directory: $OUTPUT_DIR"
        exit 1
    fi
fi

check_prerequisites

log_info "Starting OVA export for VMID $VMID to $OUTPUT_OVA_PATH"

WORKDIR=$(mktemp -d -p "${TMPDIR:-/tmp}" "ovaexport.${VMID}.XXXXXX")
log_info "Using temporary directory: $WORKDIR"
trap 'log_info "Cleaning up temporary directory: $WORKDIR"; rm -rf "$WORKDIR"' EXIT HUP INT QUIT TERM

log_info "Fetching configuration for VM $VMID..."
VM_NODE=$(hostname -s)
VM_CONFIG_JSON=$(pvesh get "/nodes/${VM_NODE}/qemu/${VMID}/config" --output-format json 2>/dev/null)

if [[ -z "$VM_CONFIG_JSON" || $(echo "$VM_CONFIG_JSON" | jq 'has("errors") or (. | length == 0 and . != [])') == "true" ]]; then
    log_error "Failed to retrieve configuration for VM $VMID or VM does not exist."
    if [[ -n "$VM_CONFIG_JSON" ]]; then echo "$VM_CONFIG_JSON" | jq . >&2; fi
    exit 1
fi

VM_NAME=$(echo "$VM_CONFIG_JSON" | jq -r '.name // "vm-'${VMID}'"')
CPU_CORES=$(echo "$VM_CONFIG_JSON" | jq -r '.cores // "1"')
CPU_SOCKETS=$(echo "$VM_CONFIG_JSON" | jq -r '.sockets // "1"')
TOTAL_VCPUS=$(( CPU_CORES * CPU_SOCKETS ))
MEMORY_MB=$(echo "$VM_CONFIG_JSON" | jq -r '.memory // "1024"')
MACHINE_TYPE=$(echo "$VM_CONFIG_JSON" | jq -r '.machine // "i440fx"')
VMX_TYPE=${DEFAULT_VMX_VERSION}

PROXMOX_OS_TYPE=$(echo "$VM_CONFIG_JSON" | jq -r '.ostype // "other"')
GUEST_OS_ID="${DEFAULT_OVF_OS_MAP[$PROXMOX_OS_TYPE]:-${DEFAULT_OVF_OS_MAP["other"]}}"

log_info "VM Name: $VM_NAME"
log_info "vCPUs: $TOTAL_VCPUS ($CPU_SOCKETS sockets, $CPU_CORES cores/socket)"
log_info "Memory: $MEMORY_MB MB"
log_info "Proxmox OS Type: $PROXMOX_OS_TYPE -> Mapped OVF GuestOSID: $GUEST_OS_ID"
log_info "Proxmox Machine Type: $MACHINE_TYPE -> OVF VMX Type: $VMX_TYPE"

log_info "Fetching storage configuration..."
STORAGE_CONFIGS_JSON=$(pvesh get /storage --output-format json 2>/dev/null)
if [[ -z "$STORAGE_CONFIGS_JSON" ]]; then
    log_error "Failed to retrieve Proxmox storage configurations."
    exit 1
fi

declare -a VMDK_FILES_INFO
VMDK_INDEX=0
OVF_ITEM_INSTANCE_ID_COUNTER=10 # Start instance IDs for hardware items after System(0), CPU(1), Mem(2)

log_info "Processing virtual disks..."
for disk_key_type in ide sata scsi virtio; do
    while IFS= read -r DISK_ENTRY_JSON; do
        if [[ -z "$DISK_ENTRY_JSON" ]]; then continue; fi # Skip empty lines if jq output is weird

        PROXMOX_DISK_KEY=$(echo "$DISK_ENTRY_JSON" | jq -r '.key')
        DISK_STRING_FULL=$(echo "$DISK_ENTRY_JSON" | jq -r '.value')

        log_info "Found Proxmox disk: $PROXMOX_DISK_KEY -> $DISK_STRING_FULL"

        if echo "$DISK_STRING_FULL" | grep -qP ',media=cdrom'; then
            log_info "Skipping CD-ROM entry: $PROXMOX_DISK_KEY"
            continue
        fi
        if [[ "$DISK_STRING_FULL" == "none" ]]; then
             log_info "Skipping 'none' disk entry: $PROXMOX_DISK_KEY"
             continue
        fi

        RESOLVED_PATH_FORMAT_OUTPUT=$(resolve_disk_path_and_format "$DISK_STRING_FULL" "$VMID" "$STORAGE_CONFIGS_JSON")
        if [[ $? -ne 0 ]]; then
            log_error "Failed to resolve path for disk $PROXMOX_DISK_KEY based on string '$DISK_STRING_FULL'."
            touch "$WORKDIR/disk_resolve_error"
            continue
        fi
        SOURCE_DISK_PATH=$(echo "$RESOLVED_PATH_FORMAT_OUTPUT" | cut -d';' -f1)
        SOURCE_DISK_FORMAT=$(echo "$RESOLVED_PATH_FORMAT_OUTPUT" | cut -d';' -f2)

        DISK_SIZE_SPEC=$(echo "$DISK_STRING_FULL" | grep -oP 'size=\K[^,]+' || echo "0")
        DISK_CAPACITY_BYTES=$(convert_proxmox_size_to_bytes "$DISK_SIZE_SPEC")
        if [[ "$DISK_CAPACITY_BYTES" == "0" ]]; then
            log_info "Disk $PROXMOX_DISK_KEY has size 0 or could not parse size from config string. Attempting to get from qemu-img."
            DISK_CAPACITY_BYTES_QEMU=$(qemu-img info --output=json "$SOURCE_DISK_PATH" 2>/dev/null | jq -r '."virtual-size"' 2>/dev/null || echo "0")
            DISK_CAPACITY_BYTES="$DISK_CAPACITY_BYTES_QEMU"
            if [[ "$DISK_CAPACITY_BYTES" == "0" || "$DISK_CAPACITY_BYTES" == "null" ]]; then
                 log_error "Cannot determine capacity for $PROXMOX_DISK_KEY ($SOURCE_DISK_PATH). Skipping."
                 continue
            fi
            log_info "Using qemu-img detected capacity: $DISK_CAPACITY_BYTES bytes for $PROXMOX_DISK_KEY"
        fi

        VMDK_BASENAME="disk-${VMDK_INDEX}.vmdk"
        VMDK_FILEPATH="$WORKDIR/$VMDK_BASENAME"
        OVF_FILE_ID="file${VMDK_INDEX}"
        OVF_DISK_ID="vmdisk${VMDK_INDEX}"

        log_info "Converting disk $PROXMOX_DISK_KEY ($SOURCE_DISK_PATH, format: $SOURCE_DISK_FORMAT) to $VMDK_FILEPATH (streamOptimized VMDK)..."
        if ! qemu-img convert -p -f "$SOURCE_DISK_FORMAT" -O vmdk -o subformat=streamOptimized "$SOURCE_DISK_PATH" "$VMDK_FILEPATH"; then
            log_error "Failed to convert $SOURCE_DISK_PATH to VMDK. Check disk path and format."
            if [[ "$SOURCE_DISK_FORMAT" != "rbd" ]]; then # Only retry if not RBD, as RBD format is specific
                log_info "Retrying conversion with source format auto-detection for $SOURCE_DISK_PATH..."
                if ! qemu-img convert -p -O vmdk -o subformat=streamOptimized "$SOURCE_DISK_PATH" "$VMDK_FILEPATH"; then # Let qemu-img auto-detect source format
                    log_error "Retry also failed for $SOURCE_DISK_PATH."
                    touch "$WORKDIR/disk_convert_error"
                    continue
                fi
            else
                touch "$WORKDIR/disk_convert_error"
                continue
            fi
        fi
        log_info "Disk conversion successful for $VMDK_BASENAME."

        POPULATED_VMDK_SIZE_BYTES=$(stat -c%s "$VMDK_FILEPATH")

        VMDK_FILES_INFO+=("$VMDK_BASENAME $OVF_FILE_ID $OVF_DISK_ID $DISK_CAPACITY_BYTES $POPULATED_VMDK_SIZE_BYTES $PROXMOX_DISK_KEY $VMDK_FILEPATH")
        VMDK_INDEX=$((VMDK_INDEX + 1))
    done < <(echo "$VM_CONFIG_JSON" | jq -c ". | to_entries[] | select(.key | test(\"^${disk_key_type}[0-9]+\$\"))")
done

if [[ -f "$WORKDIR/disk_resolve_error" || -f "$WORKDIR/disk_convert_error" ]]; then
    log_error "One or more disk processing errors occurred during the disk loop. Aborting."
    exit 1
fi

if [[ ${#VMDK_FILES_INFO[@]} -eq 0 ]]; then
    log_error "No disks were successfully processed for VM $VMID. Cannot create OVA."
    exit 1
fi


# --- Generate OVF File ---
OVF_FILENAME="${VM_NAME}.ovf"
OVF_FILEPATH="$WORKDIR/$OVF_FILENAME"
SYSTEM_ID=$(uuidgen)

log_info "Generating OVF file: $OVF_FILEPATH"

cat <<EOF > "$OVF_FILEPATH"
<?xml version="1.0"?>
<Envelope ovf:version="1.0" xml:lang="en-US" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vrd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References>
EOF

for info_str in "${VMDK_FILES_INFO[@]}"; do
    read -r vmdk_basename ovf_fid _ _ _ _ actual_vmdk_filepath <<< "$info_str"
    vmdk_actual_filesize=$(stat -c%s "$actual_vmdk_filepath")
    cat <<EOF >> "$OVF_FILEPATH"
    <File ovf:href="${vmdk_basename}" ovf:id="${ovf_fid}" ovf:size="${vmdk_actual_filesize}" />
EOF
done

cat <<EOF >> "$OVF_FILEPATH"
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
EOF

for info_str in "${VMDK_FILES_INFO[@]}"; do
    read -r _ ovf_fid ovf_did capacity_b populated_vmdk_size_b _ _ <<< "$info_str"
    cat <<EOF >> "$OVF_FILEPATH"
    <Disk ovf:capacity="${capacity_b}" ovf:capacityAllocationUnits="byte" ovf:diskId="${ovf_did}" ovf:fileRef="${ovf_fid}" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized" ovf:populatedSize="${populated_vmdk_size_b}" />
EOF
done

cat <<EOF >> "$OVF_FILEPATH"
  </DiskSection>
  <NetworkSection>
    <Info>List of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The default VM Network. This may need to be reconfigured on import.</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="${SYSTEM_ID}">
    <Info>A virtual machine exported from Proxmox VE</Info>
    <Name>${VM_NAME}</Name>
    <OperatingSystemSection ovf:id="100" vmw:osType="${GUEST_OS_ID}">
      <Info>Guest Operating System</Info>
      <Description>${GUEST_OS_ID}</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual Hardware Requirements</Info>
      <System>
        <vrd:ElementName>Virtual Hardware Family</vrd:ElementName>
        <vrd:InstanceID>0</vrd:InstanceID>
        <vrd:VirtualSystemIdentifier>${SYSTEM_ID}</vrd:VirtualSystemIdentifier>
        <vrd:VirtualSystemType>${VMX_TYPE}</vrd:VirtualSystemType>
      </System>
      <Item>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>${TOTAL_VCPUS} virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID> <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>${TOTAL_VCPUS}</rasd:VirtualQuantity>
        <vmw:CoresPerSocket ovf:required="false">${CPU_CORES}</vmw:CoresPerSocket>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>${MEMORY_MB} MB RAM</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID> <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>${MEMORY_MB}</rasd:VirtualQuantity>
      </Item>
EOF

NEEDS_IDE_CONTROLLER=false
NEEDS_SCSI_CONTROLLER=false
PROXMOX_SCSIHW=$(echo "$VM_CONFIG_JSON" | jq -r '.scsihw // "lsi"')

for info_str in "${VMDK_FILES_INFO[@]}"; do
    read -r _ _ _ _ _ proxmox_dkey _ <<< "$info_str"
    if [[ "$proxmox_dkey" == ide* ]]; then NEEDS_IDE_CONTROLLER=true; fi
    if [[ "$proxmox_dkey" == scsi* || "$proxmox_dkey" == virtio* ]]; then
      NEEDS_SCSI_CONTROLLER=true
    fi
done

IDE_CONTROLLER_INSTANCE_ID=""
if $NEEDS_IDE_CONTROLLER; then
    IDE_CONTROLLER_INSTANCE_ID=$((OVF_ITEM_INSTANCE_ID_COUNTER++)) # Start from 10
    cat <<EOF >> "$OVF_FILEPATH"
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>IDE Controller</rasd:Description>
        <rasd:ElementName>IDE Controller 0</rasd:ElementName>
        <rasd:InstanceID>${IDE_CONTROLLER_INSTANCE_ID}</rasd:InstanceID>
        <rasd:ResourceSubType>PIIX4</rasd:ResourceSubType>
        <rasd:ResourceType>5</rasd:ResourceType>
      </Item>
EOF
fi

SCSI_CONTROLLER_INSTANCE_ID=""
SCSI_CONTROLLER_OVF_TYPE="6" # Default OVF SCSI ResourceType
SCSI_CONTROLLER_SUBTYPE="lsilogicsas" # Default OVF SCSI SubType

if $NEEDS_SCSI_CONTROLLER; then
    SCSI_CONTROLLER_INSTANCE_ID=$((OVF_ITEM_INSTANCE_ID_COUNTER++)) # Increment from 10 or 11
    case "$PROXMOX_SCSIHW" in
        "lsi"|"lsi53c810"|"lsi53c895a")
            SCSI_CONTROLLER_SUBTYPE="lsilogic" ;;
        "megasas")
            SCSI_CONTROLLER_SUBTYPE="sas1068" ;; # VMware uses this for MegaRAID SAS
        "virtio-scsi-pci"|"virtio-scsi-single")
            SCSI_CONTROLLER_SUBTYPE="pvscsi" ;; # VMware Paravirtual SCSI
         "virtio") # This is virtio-blk, often mapped to LSI Logic SAS for broader compatibility
            SCSI_CONTROLLER_SUBTYPE="lsilogicsas" ;;
        *) SCSI_CONTROLLER_SUBTYPE="lsilogicsas" ;; # Default
    esac

    cat <<EOF >> "$OVF_FILEPATH"
      <Item>
        <rasd:Address>0</rasd:Address> <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0 (${SCSI_CONTROLLER_SUBTYPE})</rasd:ElementName>
        <rasd:InstanceID>${SCSI_CONTROLLER_INSTANCE_ID}</rasd:InstanceID>
        <rasd:ResourceSubType>${SCSI_CONTROLLER_SUBTYPE}</rasd:ResourceSubType>
        <rasd:ResourceType>${SCSI_CONTROLLER_OVF_TYPE}</rasd:ResourceType> </Item>
EOF
fi

for info_str in "${VMDK_FILES_INFO[@]}"; do
    read -r _ _ ovf_did _ _ proxmox_dkey _ <<< "$info_str"
    DISK_ITEM_INSTANCE_ID=$((OVF_ITEM_INSTANCE_ID_COUNTER++)) # Increment for each disk
    PARENT_INSTANCE_ID=""
    DISK_ADDRESS_ON_PARENT=""
    DISK_CONTROLLER_TYPE_FOR_DISK=""

    if [[ "$proxmox_dkey" == ide* ]]; then
        PARENT_INSTANCE_ID=$IDE_CONTROLLER_INSTANCE_ID
        case "$proxmox_dkey" in
            ide0) DISK_ADDRESS_ON_PARENT=0 ;; ide1) DISK_ADDRESS_ON_PARENT=1 ;;
            # ide2/3 mapping would require a second IDE controller item, or map to SCSI
            ide2) log_warning "Proxmox ide2 disk ($proxmox_dkey) - OVF mapping as primary IDE master, potential conflict if ide0 exists."; DISK_ADDRESS_ON_PARENT=0 ;;
            ide3) log_warning "Proxmox ide3 disk ($proxmox_dkey) - OVF mapping as primary IDE slave, potential conflict if ide1 exists."; DISK_ADDRESS_ON_PARENT=1 ;;
            *) log_warning "Unknown IDE disk index: $proxmox_dkey. Skipping attachment."; continue ;;
        esac
        DISK_CONTROLLER_TYPE_FOR_DISK="IDE"
    elif [[ "$proxmox_dkey" == scsi* || "$proxmox_dkey" == virtio* ]]; then
        PARENT_INSTANCE_ID=$SCSI_CONTROLLER_INSTANCE_ID
        DISK_ADDRESS_ON_PARENT=$(echo "$proxmox_dkey" | grep -oP '[0-9]+$') # Unit on SCSI bus
        DISK_CONTROLLER_TYPE_FOR_DISK="SCSI"
    else
        log_warning "Unknown controller type for disk key $proxmox_dkey. Skipping attachment."
        continue
    fi

    if [[ -z "$PARENT_INSTANCE_ID" ]]; then
        log_warning "Parent controller for disk $proxmox_dkey (type ${DISK_CONTROLLER_TYPE_FOR_DISK}) not defined in OVF. Skipping disk attachment."
        continue
    fi

    cat <<EOF >> "$OVF_FILEPATH"
      <Item>
        <rasd:AddressOnParent>${DISK_ADDRESS_ON_PARENT}</rasd:AddressOnParent>
        <rasd:ElementName>Hard disk ${DISK_ADDRESS_ON_PARENT} on ${DISK_CONTROLLER_TYPE_FOR_DISK} Controller</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/${ovf_did}</rasd:HostResource>
        <rasd:InstanceID>${DISK_ITEM_INSTANCE_ID}</rasd:InstanceID>
        <rasd:Parent>${PARENT_INSTANCE_ID}</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
        <vmw:Config ovf:required="false" vmw:key="backing.writeThrough" vmw:value="false"/>
      </Item>
EOF
done

NET_IDX=0
NET_KEYS_AND_VALUES=$(echo "$VM_CONFIG_JSON" | jq -r 'to_entries[] | select(.key | test("^net[0-9]+")).key + "|" + .value')
if [[ -n "$NET_KEYS_AND_VALUES" ]]; then
    echo "$NET_KEYS_AND_VALUES" | while IFS="|" read -r NET_KEY NET_VALUE_FULL; do
        if [[ -z "$NET_KEY" ]]; then continue; fi

        MAC_ADDRESS=$(echo "$NET_VALUE_FULL" | grep -oP '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | tr '[:lower:]' '[:upper:]')
        PROXMOX_NIC_MODEL=$(echo "$NET_VALUE_FULL" | cut -d'=' -f1 | cut -d',' -f1)

        OVF_NIC_SUBTYPE="Vmxnet3"
        case "$PROXMOX_NIC_MODEL" in
            e1000) OVF_NIC_SUBTYPE="E1000" ;;
            e1000e) OVF_NIC_SUBTYPE="E1000E" ;;
            rtl8139) OVF_NIC_SUBTYPE="PCNet32" ;;
            vmxnet3) OVF_NIC_SUBTYPE="Vmxnet3" ;;
            virtio) OVF_NIC_SUBTYPE="Vmxnet3" ;;
        esac
        NET_ITEM_INSTANCE_ID=$((OVF_ITEM_INSTANCE_ID_COUNTER++)) # Increment from previous counter

        cat <<EOF >> "$OVF_FILEPATH"
      <Item>
        <rasd:AddressOnParent>${NET_IDX}</rasd:AddressOnParent> <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>Network adapter ${NET_IDX}</rasd:Description>
        <rasd:ElementName>Ethernet adapter ${NET_IDX} (${OVF_NIC_SUBTYPE})</rasd:ElementName>
        <rasd:InstanceID>${NET_ITEM_INSTANCE_ID}</rasd:InstanceID>
        <rasd:ResourceSubType>${OVF_NIC_SUBTYPE}</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
        $( [[ -n "$MAC_ADDRESS" ]] && echo "        <rasd:Address>${MAC_ADDRESS}</rasd:Address>" )
      </Item>
EOF
        NET_IDX=$((NET_IDX + 1))
    done
fi


PROXMOX_VERSION_SHORT=$(pveversion -v | awk '$1 ~ /^pve-manager\// {print $2; exit}')
PROXMOX_VERSION_FULL=$(pveversion --verbose)

cat <<EOF >> "$OVF_FILEPATH"
    </VirtualHardwareSection>
    <ProductSection ovf:class="com.proxmox.exported.vm" ovf:instance="${VMID}" ovf:required="false">
      <Info>Information about the exported Proxmox VE virtual machine</Info>
      <Product>${VM_NAME}</Product>
      <Vendor>Proxmox VE OVA Export Script</Vendor>
      <Version>${PROXMOX_VERSION_SHORT}</Version>
      <FullVersion>${PROXMOX_VERSION_FULL}</FullVersion>
      <VendorUrl>https://www.proxmox.com</VendorUrl>
    </ProductSection>
  </VirtualSystem>
</Envelope>
EOF

log_info "OVF file generated: $OVF_FILEPATH"

MF_FILENAME="${VM_NAME}.mf"
MF_FILEPATH="$WORKDIR/$MF_FILENAME"
log_info "Generating manifest file: $MF_FILEPATH"

{
    echo "SHA256(${OVF_FILENAME}) = $(sha256sum "$OVF_FILEPATH" | awk '{print $1}')"
    for info_str in "${VMDK_FILES_INFO[@]}"; do
        read -r vmdk_basename _ _ _ _ _ actual_vmdk_filepath <<< "$info_str"
        echo "SHA256(${vmdk_basename}) = $(sha256sum "$actual_vmdk_filepath" | awk '{print $1}')"
    done
} > "$MF_FILEPATH"

log_info "Manifest file generated: $MF_FILEPATH"

log_info "Creating OVA package: $OUTPUT_OVA_PATH"
TAR_FILES_BASENAMES=("$OVF_FILENAME" "$MF_FILENAME")
for info_str in "${VMDK_FILES_INFO[@]}"; do
    read -r vmdk_basename _ _ _ _ _ _ <<< "$info_str"
    TAR_FILES_BASENAMES+=("$vmdk_basename")
done

printf "%s\n" "${TAR_FILES_BASENAMES[@]}" | tar -cf "$OUTPUT_OVA_PATH" -C "$WORKDIR" --files-from -
if [[ $? -eq 0 ]]; then
    log_info "OVA package created successfully: $OUTPUT_OVA_PATH"
else
    log_error "Failed to create OVA package. Tar exit code: $?"
    exit 1
fi

log_info "Export complete for VM $VMID."
exit 0