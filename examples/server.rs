//! A simple example server with login and session.
#[macro_use] extern crate nickel;
extern crate nickel_jwt_session;
extern crate cookie;
extern crate hyper;

use nickel::{HttpRouter, Nickel, Request, Response, MiddlewareResult};
use nickel::status::StatusCode;
use nickel_jwt_session::{SessionMiddleware, SessionRequestExtensions, SessionResponseExtensions};
use std::collections::HashMap;

fn main() {
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("My very secret key"));

    server.get("/",   public);
    server.get("/login", login);
    server.get("/private", private);

    server.listen("127.0.0.1:6767");
}

fn public<'mw>(_req: &mut Request, res: Response<'mw>)
               -> MiddlewareResult<'mw>  {
    let mut data = HashMap::new();
    data.insert("who", "world");
    return res.render("templates/public.tpl", &data);
}

fn login<'mw>(_req: &mut Request, mut res: Response<'mw>)
               -> MiddlewareResult<'mw>  {
    let mut data = HashMap::new();
    data.insert("who", "world");
    res.set_jwt_user("kalle");
    return res.render("templates/public.tpl", &data);
}

fn private<'mw>(req: &mut Request, res: Response<'mw>)
                -> MiddlewareResult<'mw>  {
    if let Some(user) = req.authorized_user() {
        let mut data = HashMap::new();
        data.insert("who", user);
        return res.render("templates/private.tpl", &data);
    }
    res.error(StatusCode::Forbidden, "Permission denied")
}
