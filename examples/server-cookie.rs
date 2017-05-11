//! A simple example server with login and session.
extern crate cookie;
extern crate env_logger;
extern crate hyper;
extern crate nickel;
extern crate nickel_jwt_session;

use nickel::{HttpRouter, MiddlewareResult, Nickel, Request, Response};
use nickel::extensions::Redirect;
use nickel::status::StatusCode;
use nickel_jwt_session::*;
use std::collections::HashMap;

fn main() {
    env_logger::init().unwrap();
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("My very secret key")
                       .expiration_time(60)); // Short, to see expiration.

    server.get("/", public);
    server.get("/login", login);
    server.get("/logout", logout);
    server.get("/private", private);

    server.listen("127.0.0.1:6767").expect("listen");
}

fn public<'mw>(req: &mut Request, res: Response<'mw>) -> MiddlewareResult<'mw> {
    let mut data = HashMap::new();
    data.insert("who", req.authorized_user().unwrap_or("world".to_owned()));
    res.render("examples/templates/public.tpl", &data)
}

fn login<'mw>(_req: &mut Request,
              mut res: Response<'mw>)
              -> MiddlewareResult<'mw> {
    // A real login view would get a username/password pair or a CAS
    // ticket or something, but in this example, we just consider
    // "carl" logged in.
    res.set_jwt_user("carl");
    res.redirect("/")
}

fn logout<'mw>(_req: &mut Request,
               mut res: Response<'mw>)
               -> MiddlewareResult<'mw> {
    res.clear_jwt();
    res.redirect("/")
}

fn private<'mw>(req: &mut Request,
                res: Response<'mw>)
                -> MiddlewareResult<'mw> {
    match req.authorized_user() {
        Some(user) => {
            let mut data = HashMap::new();
            data.insert("full_name", user);
            res.render("examples/templates/private.tpl", &data)
        }
        None => res.error(StatusCode::Forbidden, "Permission denied"),
    }
}
