//! An experimental middleware for jwt-based login for nickel.
//!
//! When the `SessionMiddleware` is invoked, it checks if there is a "jwt"
//! cookie and if that contains a valid jwt token, signed with the
//! secret key.  If there is a properly signed token,
//! `SessionRequestExtensions` is added to the request, so furhter
//! middlewares and views can get the authorized user.
//!
//! Also, the response is extended with `SessionResponseExtensions`,
//! which can be used to set the user (login) or clear the user
//! (logout).
extern crate nickel;
extern crate plugin;
extern crate typemap;
extern crate jwt;
extern crate crypto;
extern crate cookie;
extern crate hyper;

use cookie::Cookie as CookiePair;
use crypto::sha2::Sha256;
use hyper::header::SetCookie;
use hyper::header;
use jwt::{Header, Registered, Token};
use nickel::{Continue, Middleware, MiddlewareResult, Request, Response};
use plugin::Extensible;
use std::default::Default;
use typemap::Key;

/// The middleware itself.
#[derive(Clone)]
pub struct SessionMiddleware {
    /// The key for signing jwts.  Should be kept private, but needs
    /// to be the same on multiple servers sharing a jwt domain.
    server_key: String,
}

impl SessionMiddleware {
    /// Create a new instance.
    ///
    /// The `server_key` is used for signing and validating the jwt token.
    pub fn new(server_key: &str) -> SessionMiddleware {
        SessionMiddleware { server_key: server_key.to_owned() }
    }
}

#[derive(Debug)]
struct Session {
    authorized_user: Option<String>,
}

impl Key for SessionMiddleware {
    type Value = SessionMiddleware;
}
impl Key for Session {
    type Value = Session;
}

fn get_cookie<'mw, 'conn, D>(req: &Request<'mw, 'conn, D>, name: &str)
                             -> Option<String> {
    if let Some(cookies) = req.origin.headers.get::<header::Cookie>() {
        for cookie in cookies.iter() {
            if cookie.name == name {
                return Some(cookie.value.to_string());
            }
        }
    }
    None
}

impl<D> Middleware<D> for SessionMiddleware {
    fn invoke<'mw, 'conn>(&self,
                          req: &mut Request<'mw, 'conn, D>,
                          mut res: Response<'mw, D>)
                          -> MiddlewareResult<'mw, D> {
        res.extensions_mut().insert::<SessionMiddleware>((*self).clone());
        if let Some(jwtstr) = get_cookie(req, "jwt") {
            match Token::<Header, Registered>::parse(&jwtstr) {
                Ok(token) => {
                    if token.verify(self.server_key.as_ref(), Sha256::new()) {
                        req.extensions_mut()
                           .insert::<Session>(Session { authorized_user: token.claims.sub });
                    } else {
                        println!("Invalid token {:?}", token);
                    }
                }
                Err(err) => {
                    println!("Bad jwt token: {:?}", err);
                }
            }
        }
        Ok(Continue(res))
    }
}

/// Extension trait for the request.
///
/// Import this trait and a nickel request will implement it.
pub trait SessionRequestExtensions {
    /// Check if there is an authorized user.
    ///
    /// If there is an authorized user, Some(username) is returned,
    /// otherwise, None is returned.
    fn authorized_user(&self) -> Option<String>;
}

/// Extension trait for the response.
///
/// Import this trait and a nickel response will implement it.
pub trait SessionResponseExtensions {
    /// Set the user.
    ///
    /// A jwt cookie signed with the secret key will be added to the
    /// response.
    /// It is the responsibility of the caller to actually validate
    /// the user (e.g. by password, or by CAS or some other mechanism)
    fn set_jwt_user(&mut self, user: &str);
    /// Clear the user.
    ///
    /// The jwt cookie will be cleared (set to empty with zero max_age).
    fn clear_jwt_user(&mut self);
}

impl<'a, 'b, D> SessionRequestExtensions for Request<'a, 'b, D> {
    fn authorized_user(&self) -> Option<String> {
        if let Some(session) = self.extensions().get::<Session>() {
            println!("Got a session: {:?}", session);
            if let Some(ref user) = session.authorized_user {
                return Some(user.clone());
            }
        }
        println!("authorized_user returning None");
        None
    }
}

impl<'a, 'b, D> SessionResponseExtensions for Response<'a, D> {
    fn set_jwt_user(&mut self, user: &str) {
        println!("Should set a user jwt for {}", user);
        let signed_token = {
            if let Some(sm) = self.extensions().get::<SessionMiddleware>() {
                let header: Header = Default::default();
                let claims = Registered {
                    sub: Some(user.into()),
                    ..Default::default()
                };
                let token = Token::new(header, claims);
                token.signed(sm.server_key.as_ref(), Sha256::new()).ok()
            } else {
                println!("No SessionMiddleware on response.  :-(");
                None
            }
        };
        if let Some(data) = signed_token {
            println!("Setting new token {}", data);
            // Note: We should set secure to true on the cookie
            // but the example server is only http.
            self.set(SetCookie(vec![CookiePair::new("jwt".to_owned(), data)]));
        }
    }
    fn clear_jwt_user(&mut self) {
        let mut gone = CookiePair::new("jwt".to_owned(), "".to_owned());
        gone.max_age = Some(0);
        self.set(SetCookie(vec![gone]));
    }
}


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
