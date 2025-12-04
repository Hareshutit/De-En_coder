use crate::abstraction::Application;

mod abstraction;
mod management;
mod realisation;

type Applicat = management::App<
    management::router::Router<realisation::object::file::FileResourceIdentifier>,
    management::scriber::Scriber<
        realisation::object::file::resource_type::ResourceType,
        realisation::encryption::CryptoFormat,
        realisation::derive_key::standard::salt::StandardSalt,
        realisation::derive_key::standard::nonce::StandardNonce,
    >,
    realisation::derive_key::standard::StandardKdf<32>,
    realisation::object::file::resource_type::ResourceType,
    realisation::derive_key::standard::salt::StandardSalt,
    realisation::derive_key::standard::nonce::StandardNonce,
>;

fn main() -> Result<(), crate::abstraction::error::Error<Applicat>> {
    let mut app = Applicat::new()?;

    app.run()
}
