use async_trait::async_trait;
use http::{Request, Response};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::client::conn::http2::SendRequest;
use reqwest::Body;
use std::io::{Error, ErrorKind};

#[async_trait]
pub trait HttpUnify: Send + Sync {
    async fn send_request_unify(&mut self, req: Request<Body>)
        -> Result<Response<Incoming>, Error>;
    fn is_closed_unify(&self) -> bool;
    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error>;
}

#[async_trait]
impl HttpUnify for SendRequest<Body> {
    async fn send_request_unify(
        &mut self,
        req: Request<Body>,
    ) -> Result<Response<Incoming>, Error> {
        self.send_request(req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }

    fn is_closed_unify(&self) -> bool {
        return self.is_closed();
    }

    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error> {
        Ok(Box::new(self.clone()))
    }
}

#[async_trait]
impl HttpUnify for http1::SendRequest<Body> {
    async fn send_request_unify(
        &mut self,
        req: Request<Body>,
    ) -> Result<Response<Incoming>, Error> {
        self.send_request(req)
            .await
            .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
    }
    fn is_closed_unify(&self) -> bool {
        return self.is_closed();
    }

    fn clone_unify(&self) -> Result<Box<dyn HttpUnify>, Error> {
        Err(Error::new(ErrorKind::Other, "Cannot clone http/1.1"))
    }
}
