use std::env;
use std::str;
use human_bytes::human_bytes;
use sysinfo::{System, Disks, RefreshKind, CpuRefreshKind};

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
    System::name().unwrap(), System::kernel_version().unwrap(), System::os_version().unwrap(), System::host_name().unwrap());
    // CPU
    let s = System::new_with_specifics(
        RefreshKind::new().with_cpu(CpuRefreshKind::everything()),
    );
    /*for cpu in s.cpus() {
        println!("{}", cpu.frequency());
    }*/
    log::info!("CPU information NUM_CORES: {} FREQUENCY: {:?} VENDOR: {:?}", 
    s.cpus().len(), s.cpus()[0].frequency(), s.cpus()[0].vendor_id());
    // Memory
    log::info!("Memory information TOTAL: {:?} USED: {:?}", 
    human_bytes(sys.total_memory() as f64), human_bytes(sys.used_memory() as f64));
    // Hard disks
    let disks = Disks::new_with_refreshed_list();
    for disk in disks.list() {
        log::info!(
            "Hard disk NAME: {:?} FS_TYPE: {:?} MOUNT_POINT: {:?} AVAIL: {:?} TOTAL: {:?} REMOVABLE: {:?}", 
            disk.name(), 
            disk.file_system(), 
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
    System::host_name().unwrap()
}

pub fn get_os_type() -> String {
    env::consts::OS.to_string()
}