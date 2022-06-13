source "proxmox" "ubuntu-22_04" {
  proxmox_url              = "${var.proxmox_hostname}/api2/json"
  username                 = var.proxmox_username
  password                 = var.proxmox_password

  # iso_url                  = var.iso_url
  iso_file                 = var.iso_file
  insecure_skip_tls_verify = true
  memory                    = "6144"
  cores                     = "2"
  sockets                   = "2"
  cpu_type                 = "host"
  os                       = "l26"
  onboot                   = true
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
  source "proxmox.ubuntu-22_04" {
    node                 = var.proxmox_node
    vm_name              = "Ubuntu-22-04"
    template_name        = "ubuntu-22.04-srv-tmpl"
    template_description = "Template for Ubuntu 22.04 LTS"
  }
  
  provisioner "shell" {
    pause_before    = "20s"
    inline          = [ "while [ ! -f /var/lib/cloud/instance/boot-finished ]; do echo 'Waiting for boot-finished...'; sleep 5; done" ]
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-cis.sh"
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-cloud-init.sh"
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-cleanup.sh"
  }
}

build {
  source "proxmox.ubuntu-22_04" {
    node                 = var.proxmox_node
    vm_name              = "Ubuntu-22-04-docker"
    template_name        = "ubuntu-22.04-docker-tmpl"
    template_description = "Template for Ubuntu 22.04 LTS with docker"
  }
  
  provisioner "shell" {
    pause_before    = "20s"
    inline          = [ "while [ ! -f /var/lib/cloud/instance/boot-finished ]; do echo 'Waiting for boot-finished...'; sleep 5; done" ]
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-cis.sh"
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-cloud-init.sh"
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-docker.sh"
  }
  provisioner "shell" {
    execute_command = "chmod +x {{ .Path }}; echo 'ubuntu' | sudo -S bash -x -c '{{ .Vars }} {{ .Path }}'"
    script          = "ubuntu-22.04-cleanup.sh"
  }
}
