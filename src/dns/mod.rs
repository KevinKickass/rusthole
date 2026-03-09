mod doh_server;
mod dot_server;
mod server;
pub mod tls;
mod upstream;

pub use doh_server::DohServer;
pub use dot_server::DotServer;
pub use server::DnsServer;
pub use server::handle_query;
pub use upstream::DohUpstream;
