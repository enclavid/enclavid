use std::fmt;

#[derive(Debug, Clone)]
pub enum MediaRequest {
    Passport,
    IdCard,
    DriversLicense,
    Liveness,
}

#[derive(Debug)]
pub struct Suspend {
    pub request: MediaRequest,
}

impl fmt::Display for Suspend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "suspend: awaiting {:?}", self.request)
    }
}

impl std::error::Error for Suspend {}
