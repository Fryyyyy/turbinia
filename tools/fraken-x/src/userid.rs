use std::{fs::File, io::{BufRead, BufReader}};

pub fn get_usernames_from_passwd(file_path: &str) -> Result<Vec<(String, u32)>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut users = Vec::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {  // Ensure at least username, password, and UID exist
            let uid = parts[2].parse::<u32>()?;
            users.push((parts[0].to_string(), uid));
        }
    }
    println!("{:?}", users);
    Ok(users)
}