macro_rules! throw {
    ($code:expr, $msg:expr) => {
        throw!($code, $code, $msg)
    };
    ($code:expr, $res:expr, $msg:expr) => {{
        // set the error message and code
        $crate::exports::set_last_error($code, std::borrow::Cow::from($msg));

        // ... and return the result
        return $res;
    }};
}

macro_rules! try_result {
    ($code:expr, $ret:expr) => {
        try_result!($code, $code, $ret)
    };
    ($code:expr, $res:expr, $ret:expr) => {
        match $ret {
            Ok(ok) => ok,
            Err(err) => throw!($code, $res, err.to_string()),
        }
    };
}
