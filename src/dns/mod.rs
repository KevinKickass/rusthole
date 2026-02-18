mod server;
mod upstream;
mod doh_server;
mod dot_server;
pub mod tls;

pub use server::DnsServer;
pub use server::handle_query;
pub use upstream::DohUpstream;
pub use doh_server::DohServer;
pub use dot_server::DotServer;
