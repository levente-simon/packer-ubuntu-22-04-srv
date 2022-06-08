source "proxmox" "ubuntu-22_04" {
  proxmox_url              = "${var.proxmox_hostname}/api2/json"
  username                 = var.proxmox_username
  password                 = var.proxmox_password
  node                     = var.proxmox_node

  # iso_url                  = var.iso_url
  iso_file                 = var.iso_file
  insecure_skip_tls_verify = true
  vm_name                   = "Ubuntu-22-04"
  memory                    = "6144"
  cores                     = "2"
  sockets                   = "2"
  cpu_type                 = "host"
  os                       = "l26"
  onboot                   = true
  template_name            = "ubuntu-22.04-srv-tmpl"
  template_description     = "Template for Ubuntu 22.04 LTS"
  unmount_iso              = true

  ssh_username              = "iac"
  ssh_password              = "ubuntu"
  ssh_timeout              = "40m"

  http_directory           = "./http"

  scsi_controller          = "virtio-scsi-single"
  boot_wait                = "10s"
  cloud_init               = true
  cloud_init_storage_pool  = var.proxmox_storage_pool
  
  network_adapters {
    bridge = "vmbr0"
    model  = "virtio"
  }
  disks {
    type               = "scsi"
    disk_size          = "32G"
    storage_pool       = var.proxmox_storage_pool
    storage_pool_type  = var.proxmox_storage_pool_type
    format             = "raw"
  }
  
  boot_command = [
    " <wait>", " <wait>", " <wait>", " <wait>", " <wait>",
    "c", "<wait>",
    "set gfxpayload=keep", "<enter><wait>",
    "linux /casper/vmlinuz<wait>", " autoinstall<wait>", " 'ds=nocloud-net<wait>", ";s=http://<wait>", "{{.HTTPIP}}<wait>", ":{{.HTTPPort}}/'<wait>", " ---",
    "<enter><wait>",
    "initrd<wait>", " /casper/<wait>", "initrd<enter><wait>",
    "boot<enter><wait>"
  ]
}

build {
  sources = [
    "proxmox.ubuntu-22_04"
  ]
  
  provisioner "shell" {
    pause_before = "20s"
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script = "ubuntu-22.04-setup.sh"
  }
}
