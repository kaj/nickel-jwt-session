//! An experimental middleware for jwt-based login for nickel.
//!
//! When the `SessionMiddleware` is invoked, it checks if there is a "jwt"
//! cookie and if that contains a valid jwt token, signed with the
//! secret key.
//! If there is a properly signed token, a session is added to the
//! request.
//! Further middlewares and views can get the authorized user through
//! the `SessionRequestExtensions` method `authorized_user`.
//!
//! Also, the response is extended with `SessionResponseExtensions`,
//! which can be used to set the user (login) or clear the user
//! (logout).
//!
//! A working usage example exists in [the examples directory]
//! (https://github.com/kaj/nickel-jwt-session/tree/master/examples).

extern crate nickel;
extern crate plugin;
extern crate typemap;
extern crate jwt;
extern crate crypto;
extern crate cookie;
extern crate hyper;
#[macro_use]
extern crate log;

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
    /// Value for the iss (issuer) jwt claim.
    issuer: Option<String>,
    /// How long should a token be valid after creation?
    expiration_time: u64,
    /// Where to put the token to be returned
    location: TokenLocation,
}

/// Places the token could be located.
#[derive(Clone)]
pub enum TokenLocation {
    Cookie(String),
}

impl SessionMiddleware {
    /// Create a new instance.
    ///
    /// The `server_key` is used for signing and validating the jwt token.
    pub fn new(server_key: &str) -> SessionMiddleware {
        SessionMiddleware {
            server_key: server_key.to_owned(),
            issuer: None,
            expiration_time: 24 * 60 * 60,
            location: TokenLocation::Cookie("jwt".to_owned()),
        }
    }

    /// Set a value for the iss (issuer) jwt claim.
    pub fn issuer(mut self, issuer: &str) -> Self {
        self.issuer = Some(issuer.to_owned());
        self
    }

    /// Set how long a token should be valid after creation (in seconds).
    pub fn expiration_time(mut self, expiration_time: u64) -> Self {
        self.expiration_time = expiration_time;
        self
    }

    fn make_token(&self, user: &str) -> Option<String> {
        let header: Header = Default::default();
        let now = current_numeric_date();
        let claims = Registered {
            iss: self.issuer.clone(),
            sub: Some(user.into()),
            exp: Some(now + self.expiration_time),
            nbf: Some(now),
            ..Default::default()
        };
        let token = Token::new(header, claims);
        token.signed(self.server_key.as_ref(), Sha256::new()).ok()
    }
}

#[derive(Debug)]
struct Session {
    authorized_user: String,
}

impl Key for SessionMiddleware {
    type Value = SessionMiddleware;
}
impl Key for Session {
    type Value = Session;
}

fn get_cookie<'mw, 'conn, D>(req: &Request<'mw, 'conn, D>,
                             name: &str)
                             -> Option<String> {
    if let Some(cookies) = req.origin.headers.get::<header::Cookie>() {
        for cookie in cookies.iter() {
            if cookie.name == name {
                return Some(cookie.value.clone());
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

        let jwtstr = match self.location {
            TokenLocation::Cookie(ref name) => get_cookie(req, name),
        };

        if let Some(jwtstr) = jwtstr {
            match Token::<Header, Registered>::parse(&jwtstr) {
                Ok(token) => {
                    if token.verify(self.server_key.as_ref(), Sha256::new()) {
                        debug!("Verified token for: {:?}", token.claims);
                        let now = current_numeric_date();
                        if let Some(nbf) = token.claims.nbf {
                            if now < nbf {
                                warn!("Got a not-yet valid token: {:?}",
                                      token.claims);
                                return Ok(Continue(res));
                            }
                        }
                        if let Some(exp) = token.claims.exp {
                            if now > exp {
                                warn!("Got an expired token: {:?}",
                                      token.claims);
                                return Ok(Continue(res));
                            }
                        }
                        if let Some(user) = token.claims.sub {
                            info!("User {:?} is authorized for {} on {}",
                                  user,
                                  req.origin.remote_addr,
                                  req.origin.uri);
                            req.extensions_mut()
                               .insert::<Session>(Session {
                                   authorized_user: user,
                               });
                        }
                    } else {
                        info!("Invalid token {:?}", token);
                    }
                }
                Err(err) => {
                    info!("Bad jwt token: {:?}", err);
                }
            }
        }

        Ok(Continue(res))
    }
}

/// Extension trait for the request.
///
/// This trait is implemented for `nickel::Request`.
/// Use this trait to be able to get the authorized user for a nickel
/// request.
pub trait SessionRequestExtensions {
    /// Check if there is an authorized user.
    ///
    /// If there is an authorized user, Some(username) is returned,
    /// otherwise, None is returned.
    fn authorized_user(&self) -> Option<String>;
}

/// Extension trait for the response.
///
/// This trait is implemented for `nickel::Response`.
/// Use this trait to be able to set and clear a jwt token on a nickel
/// response.
pub trait SessionResponseExtensions {
    /// Set the user.
    ///
    /// A jwt cookie signed with the secret key will be added to the
    /// response.
    /// It is the responsibility of the caller to actually validate
    /// the user (e.g. by password, or by CAS or some other mechanism)
    /// before calling this method.
    /// The token will be valid for the expiration_time specified on
    /// the `SessionMiddleware` from the current time.
    fn set_jwt_user(&mut self, user: &str);
    /// Clear the user.
    ///
    /// The response will clear the jwt cookie (set it to empty with
    /// zero max_age).
    fn clear_jwt_user(&mut self);
}

impl<'a, 'b, D> SessionRequestExtensions for Request<'a, 'b, D> {
    fn authorized_user(&self) -> Option<String> {
        if let Some(session) = self.extensions().get::<Session>() {
            debug!("Got a session: {:?}", session);
            return Some(session.authorized_user.clone());
        }
        debug!("authorized_user returning None");
        None
    }
}

impl<'a, 'b, D> SessionResponseExtensions for Response<'a, D> {
    fn set_jwt_user(&mut self, user: &str) {
        debug!("Should set a user jwt for {}", user);
        let (location, token, expiration) =
            match self.extensions().get::<SessionMiddleware>() {
                Some(sm) => {
                    (Some(sm.location.clone()),
                     sm.make_token(user),
                     Some(sm.expiration_time))
                }
                None => {
                    warn!("No SessionMiddleware on response.  :-(");
                    (None, None, None)
                }
            };

        match (location, token, expiration) {
            (Some(TokenLocation::Cookie(name)),
             Some(token),
             Some(expiration)) => {
                // Note: We should set secure to true on the cookie
                // but the example server is only http.
                let mut cookie = CookiePair::new(name, token);
                cookie.max_age = Some(expiration);
                debug!("Setting new token {}", cookie);
                self.set(SetCookie(vec![cookie]));
            }
            (_, _, _) => {}
        }
    }
    fn clear_jwt_user(&mut self) {
        let location = match self.extensions().get::<SessionMiddleware>() {
            Some(sm) => Some(sm.location.clone()),
            None => None,
        };

        match location {
            Some(TokenLocation::Cookie(name)) => {
                let mut gone = CookiePair::new(name, "".to_owned());
                gone.max_age = Some(0);
                self.set(SetCookie(vec![gone]));
            }
            None => {}
        }
    }
}

/// Get the current value for jwt NumericDate.
///
/// Defined in RFC 7519 section 2 to be equivalent to POSIX.1 "Seconds
/// Since the Epoch".  The RFC allows a NumericDate to be non-integer
/// (for sub-second resolution), but the jwt crate uses u64.
fn current_numeric_date() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).ok().unwrap().as_secs()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
