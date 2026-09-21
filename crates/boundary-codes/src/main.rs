#![forbid(unsafe_code)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:4343").await?;
    println!(
        "Boundary code service listening on 127.0.0.1:4343. Use an HTTPS reverse proxy for remote clients."
    );
    axum::serve(
        listener,
        boundary_codes::server::Service::default()
            .router()
            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}
