# nickel-jwt-session

Experimental jwt-based user session for nickel.
Suggestions for improvements are welcome.

[![Build Status](https://travis-ci.org/kaj/nickel-jwt-session.svg?branch=master)]
(https://travis-ci.org/kaj/nickel-jwt-session)

## Configuration

By default, nickel-jwt-session will store and look for the token in a cookie named "jwt", and the token will expire in 24 hours. The only required argument to the constructor is a private signing key:

```rust
extern crate nickel;
extern crate nickel_jwt_session;

use nickel::Nickel;
use nickel_jwt_session::SessionMiddleware;

fn main() {
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("My very secret key"));
}
```

You can also customize the cookie name:

```rust
extern crate nickel;
extern crate nickel_jwt_session;

use nickel::Nickel;
use nickel_jwt_session::{SessionMiddleware, TokenLocation};

fn main() {
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("My very secret key")
                   .using(TokenLocation::Cookie("my-jwt-cookie".to_owned())));
}
```

Or use Authorization: Bearer headers instead of cookies:

```rust
extern crate nickel;
extern crate nickel_jwt_session;

use nickel::Nickel;
use nickel_jwt_session::{SessionMiddleware, TokenLocation};

fn main() {
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("My very secret key")
                   .using(TokenLocation::AuthorizationHeader));
}
```

And change the number of seconds the token will be valid for:

```rust
extern crate nickel;
extern crate nickel_jwt_session;

use nickel::Nickel;
use nickel_jwt_session::SessionMiddleware;

fn main() {
    let mut server = Nickel::new();
    server.utilize(SessionMiddleware::new("My very secret key")
                   .expiration_time(60 * 30)); // 30 min
}
```

## Usage

When you have a user that you have authenticated, use the `set_jwt_user()` method to put a new token for that user into the response:

```rust
fn login<'mw>(req: &mut Request, mut res: Response<'mw>)
              -> MiddlewareResult<'mw>  {
    let authenticated_user = your_authentication_method(req);
    match authenticated_user {
        Some(username) => {
            res.set_jwt_user(username);
            res.redirect("/")
        }
        None => {
            res.redirect("/login")
        }
    }
}
```

To check to see if you have an authenticated user, use the `authorized_user()` method:

```rust
fn private<'mw>(req: &mut Request, res: Response<'mw>)
                -> MiddlewareResult<'mw> {
    match req.authorized_user() {
        Some(user) => {
            // Whatever an authorized user is allowed to do
        },
        None => res.error(StatusCode::Forbidden, "Permission denied"),
    }
}
```

And to log a user out, call the `clear_jwt_user()` method:

```rust
fn logout<'mw>(_req: &mut Request, mut res: Response<'mw>)
               -> MiddlewareResult<'mw>  {
    res.clear_jwt_user();
    res.redirect("/")
}
```

## Examples

Full working examples can be found in the [examples](examples) directory.
Read the [API documentation]
(https://rasmus.krats.se/doc/nickel-jwt-session/0.3.0/nickel_jwt_session/).

## License

Licensed under either of

 * Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license (http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
