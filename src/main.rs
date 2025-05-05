use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{Error as PasswordHashError, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
pub struct CommandLineArguments {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate an argon2 password hash from password
    Argon2 {
        password: String,
    },
    Argon2Compare {
        password: String,
        hash: String,
    },
}

pub fn hash_password(password: String) -> Result<String, PasswordHashError> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2.hash_password(password.as_bytes(), &salt)?.to_string())
}

pub fn compare_argon2_passwords(password: String, hash: String) -> bool {
    let argon2 = Argon2::default();
    let hash = PasswordHash::new(&hash).unwrap();
    argon2.verify_password(password.as_bytes(), &hash).is_ok()
}

pub fn handle_command(command: Command) -> Result<String, PasswordHashError> {
    match command {
        Command::Argon2 { password } => hash_password(password),
        Command::Argon2Compare { password, hash } => {
            Ok(compare_argon2_passwords(password, hash).to_string())
        }
    }
}

fn main() -> Result<(), PasswordHashError> {
    let args = CommandLineArguments::parse();
    let result = handle_command(args.command)?;
    println!("{}", result);
    Ok(())
}
