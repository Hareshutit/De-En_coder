#[derive(clap::Parser, Debug)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(clap::Subcommand, Debug)]
pub enum Command {
    ///Шифрование файла, аргумент - путь до файла
    Prepare {
        path_inner: String,
        #[arg(long)]
        path_outer: Option<String>,
        #[arg(long, default_value_t = String::from(""))]
        password: String,
        #[arg(long, default_value_t = crate::realisation::encryption::CryptoFormat::XOR)]
        cipher: crate::realisation::encryption::CryptoFormat,
    },
    ///Чтение файла, аргумент - путь до файла
    Read {
        path: String,
        #[arg(long, default_value_t = String::from(""))]
        password: String,
    },
    ///Расшифровка файла, аргумент - путь до файла
    Decrypt {
        path_inner: String,
        #[arg(long)]
        path_outer: Option<String>,
        #[arg(long, default_value_t = String::from(""))]
        password: String,
    },
}