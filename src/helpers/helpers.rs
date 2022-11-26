use std::env;
use std::str;
use human_bytes::human_bytes;
use sysinfo::CpuExt;
use sysinfo::{System, SystemExt, DiskExt};

// Evaluate platform & environment information
pub fn evaluate_env() {
    let mut sys = System::new_all();
    sys.refresh_all();
    // Command line arguments 
    let args: Vec<String> = env::args().collect();
    log::info!("Command line flags FLAGS: {:?}", args);
    // OS
    log::info!("Operating system information OS: {} ARCH: {}", env::consts::OS, env::consts::ARCH);
    // System Names
    log::info!("System information NAME: {:?} KERNEL: {:?} OS_VER: {:?} HOSTNAME: {:?}",
    sys.name().unwrap(), sys.kernel_version().unwrap(), sys.os_version().unwrap(), sys.host_name().unwrap());
    // CPU
    log::info!("CPU information NUM_CORES: {} FREQUENCY: {:?} VENDOR: {:?}", 
    sys.cpus().len(), sys.cpus()[0].frequency(), sys.cpus()[0].vendor_id());
    // Memory
    log::info!("Memory information TOTAL: {:?} USED: {:?}", 
    human_bytes(sys.total_memory() as f64), human_bytes(sys.used_memory() as f64));
    // Hard disks
    for disk in sys.disks() {
        log::info!(
            "Hard disk NAME: {:?} FS_TYPE: {:?} MOUNT_POINT: {:?} AVAIL: {:?} TOTAL: {:?} REMOVABLE: {:?}", 
            disk.name(), 
            str::from_utf8(disk.file_system()).unwrap(), 
            disk.mount_point(), 
            human_bytes(disk.available_space() as f64),
            human_bytes(disk.total_space() as f64),
            disk.is_removable(),
        );
    }
}

pub fn get_hostname() -> String {
    let mut sys = System::new_all();
    sys.refresh_all();
    sys.host_name().unwrap()
}

pub fn get_os_type() -> String {
    env::consts::OS.to_string()
}