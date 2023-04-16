use argon2::{
    password_hash::{rand_core::OsRng, Error as PasswordHashError, SaltString},
    Argon2, PasswordHasher,
};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
pub struct CommandLineArguments {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate an argon2 password hash from password
    Argon2 { password: String },
}

pub fn hash_password(password: String) -> Result<String, PasswordHashError> {
    let argon2 = Argon2::default();
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)?
        .to_string())
}

pub fn handle_command(command: Command) -> Result<String, PasswordHashError> {
    match command {
        Command::Argon2 { password } => hash_password(password),
    }
}

fn main() -> Result<(), PasswordHashError> {
    let args = CommandLineArguments::parse();
    let hashed_password = handle_command(args.command)?;

    println!("{}", hashed_password);

    Ok(())
}
