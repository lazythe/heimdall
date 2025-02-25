use warp::Filter;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::collections::HashSet;
use reqwest::Client;
use bytes::Bytes;
use std::convert::Infallible;
use warp::http::{Response, StatusCode, Method};
use warp::hyper::{Body, HeaderMap};
use serde_json::json;
use std::sync::Arc;
use warp::Rejection;

#[tokio::main]
async fn main() {
    let whitelist: Arc<HashSet<IpAddr>> = Arc::new(vec![
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    ].into_iter().collect());

    let upstream_url = "";

    let whitelist = Arc::clone(&whitelist);
    let ip_whitelist_filter = warp::filters::addr::remote()
        .and_then(move |addr: Option<SocketAddr>| {
            let whitelist = Arc::clone(&whitelist);
            async move {
                if let Some(socket_addr) = addr {
                    if whitelist.contains(&socket_addr.ip()) {
                        Ok::<(), Rejection>(())
                    } else {
                        Err(warp::reject::custom(IpNotAllowed(socket_addr.ip())))
                    }
                } else {
                    Err(warp::reject::custom(NoIpAddress))
                }
            }
        });

    let client = Client::new();
    let proxy = warp::path("proxy")
        .and(ip_whitelist_filter)
        .and(warp::any().map(move || upstream_url.to_string()))
        .and(warp::method())
        .and(warp::filters::path::tail())
        .and(warp::body::bytes())
        .and(warp::header::headers_cloned())
        .and_then(move |_: (), 
                       upstream_url: String,
                       method: warp::http::Method,
                       path: warp::path::Tail,
                       body: Bytes,
                       headers: HeaderMap| {
            let client = client.clone();
            async move {
                let full_url = format!("{}/{}", upstream_url, path.as_str());
                let mut req = client.request(method, &full_url);
                
                for (name, value) in headers.iter() {
                    if name != "host" {
                        req = req.header(name, value);
                    }
                }
                
                req = req.body(body);
                
                match req.send().await {
                    Ok(response) => {
                        let status = response.status();
                        let body = response.bytes().await.unwrap_or_default();
                        
                        let mut res = Response::new(Body::from(body));
                        *res.status_mut() = status;
                        Ok::<Response<Body>, Rejection>(res)
                    },
                    Err(e) => {
                        eprintln!("Proxy error: {}", e);
                        let mut res = Response::new(Body::from("Failed to reach the upstream server"));
                        *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                        Ok::<Response<Body>, Rejection>(res)
                    }
                }
            }
        });

    let routes = proxy
        .with(warp::cors()
            .allow_any_origin()
            .allow_headers(vec!["content-type"])
            .allow_methods(&[
                Method::GET,
            ]))
        .recover(handle_rejection);

    println!("Forwarding requests to {}", upstream_url);
    
    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

#[derive(Debug)]
struct IpNotAllowed(IpAddr);
impl warp::reject::Reject for IpNotAllowed {}

#[derive(Debug)]
struct NoIpAddress;
impl warp::reject::Reject for NoIpAddress {}

async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    let (code, message) = if let Some(IpNotAllowed(ip)) = err.find() {
        (StatusCode::FORBIDDEN, format!("IP address {} is not allowed", ip))
    } else if let Some(NoIpAddress) = err.find() {
        (StatusCode::BAD_REQUEST, "Could not determine client IP address".to_string())
    } else if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else {
        eprintln!("unhandled rejection: {:?}", err);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error".to_string())
    };

    let json = json!({
        "status": code.as_u16(),
        "message": message
    });

    Ok(warp::reply::with_status(warp::reply::json(&json), code))
}
