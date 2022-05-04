use std::path::Path;
use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305,
};
use rand::{rngs::OsRng, RngCore};
use std::{fs, env};

fn main() {

    let mut do_encrypt: bool = false;

    let args: Vec<String> = env::args().collect();

    if args.len() == 5 {

        if args[1].to_lowercase() == "decrypt" {
            do_encrypt = false;
        } else if args[1].to_lowercase() == "encrypt" {
            do_encrypt = true;
        } 
        
        else {
            println!("Error in Arg[1]: Expecting encrypt || decrypt");
            std::process::exit(0)
        }
    } else {
        println!("Usage: locker [encrypt || decrypt] [path] [key path] [nonce path]");
        std::process::exit(0);
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 24];

    if do_encrypt {

        OsRng.fill_bytes(&mut key);
        OsRng.fill_bytes(&mut nonce);

    } else {

        key = load_key(&mut key, &args, 3);
        nonce = load_nonce(&mut nonce, &args, 4);

    }

    let path = &args[2];
    let key_path = &args[3];
    let nonce_path = &args[4];

    if !Path::new(&path).exists() {
        println!("Path Does Not Exist");
        std::process::exit(0);
    }

    let path = Path::new(&path);

    if !do_encrypt {
        if !Path::new(&key_path).exists() {
            println!("Key Path Does Not Exist");
            std::process::exit(0);    
        }
        if !Path::new(&nonce_path).exists() {
            println!("Nonce Path Does Not Exist");
            std::process::exit(0);    
        }
    }

    let key_path = Path::new(&key_path);
    let nonce_path = Path::new(&nonce_path);

    dir_iterator(&path, &key, &nonce, do_encrypt).expect("Failed During Main Call");

    fs::write(key_path, key).expect("Writing Key To File Failed...WHOOPS");
    fs::write(nonce_path, nonce).expect("Writing Nonce To File Failed...WHOOPS");

}

fn dir_iterator(path: &Path, key: &[u8; 32], nonce: &[u8; 24],
    do_encrypt: bool) -> Result<(), anyhow::Error>{

    let final_path = get_locker_path(path);

    for module in fs::read_dir(path).expect("Unable To Get Directory") {
        let module = module.expect("Unable To Pull From Directory");

        if module.path().is_dir() {

            println!("Got Sub-Directory {}", module.path().display());
            dir_iterator(&module.path(), key, nonce, do_encrypt).expect("Failed During Recursion");
        
        } else {

            if String::from(module.path().to_string_lossy())
                .eq(&String::from(&final_path)) {
                    continue
            }

            println!("Got File {}", module.path().display());
            
            if do_encrypt {
                encrypt_file(&module.path(), key, nonce)
                    .expect("Error Loading File");                
            } else {
                decrypt_file(&module.path(), key, nonce)
                    .expect("Error Loading File");
            }
        }
    }

    println!("Finished");

    fs::write(Path::new(&final_path), "My Locker")
        .expect("Failed to Write to locker.txt");

    if do_encrypt {
        fs::write(Path::new(&final_path), "\nSTATUS - ENCRYPTED")
            .expect("Failed to Write to locker.txt");
        Ok(())
    } else {
        fs::write(Path::new(&final_path), "\nSTATUS - DECRYPTED")
            .expect("Failed to Write to locker.txt");
        Ok(())
    }

} 

fn encrypt_file(path: &Path, key: &[u8; 32],
     nonce: &[u8; 24] ) -> Result<(), anyhow::Error> {

        let cipher = XChaCha20Poly1305::new(key.into());

        let file_data = fs::read(path)?;

        let encrypted = cipher
            .encrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Encrypting File: {}", err))?;

        println!("Encrypted File: {}", path.display());

        fs::write(path, encrypted).expect("Error Writing Encrypted Contents");

        Ok(())
}

fn decrypt_file(path: &Path, key: &[u8; 32],
    nonce: &[u8; 24] ) -> Result<(), anyhow::Error> {

        let cipher = XChaCha20Poly1305::new(key.into());

        let file_data = fs::read(path)?;

        let decrypted = cipher
            .decrypt(nonce.into(), file_data.as_ref())
            .map_err(|err| anyhow!("Decrypting File: {}", err))?;

        println!("Dencrypted File: {}", path.display());

        fs::write(path, decrypted).expect("Error Writing Encrypted Contents");

        Ok(())
}

fn load_nonce(arr: &mut [u8; 24], arg: &Vec<String>, index: usize) -> [u8; 24] {
    let text = fs::read(&arg[index]);

    for i in text.iter() {
        for (j, k) in arr.iter_mut().zip(i.iter()) {
            *j = *k;
        }
    }

    *arr

}

fn load_key(arr: &mut [u8; 32], arg: &Vec<String>, index: usize) -> [u8; 32] {
    let text = fs::read(&arg[index]);

    for i in text.iter() {
        for (j, k) in arr.iter_mut().zip(i.iter()) {
            *j = *k;
        }
    }

    *arr

}

fn get_locker_path(path: &Path) -> String {

    let path = path.to_string_lossy();

    let mut str_vec = path.split("\\")
                        .collect::<Vec<&str>>();

    str_vec.push("locker.txt");
    str_vec.join("\\")

}