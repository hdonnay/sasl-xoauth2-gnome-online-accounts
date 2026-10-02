// SPDX-License-Identifier: LGPL-3.0-or-later

mod account;
mod mail;
mod oauth2_based;
mod sasl;

use std::{
    ffi::{CString, c_char, c_int, c_uint, c_void},
    mem, ptr, slice,
};

use async_executor::StaticExecutor;
use futures_lite::future;
use zbus::Connection;

use sasl::*;

// House style is to use `debug_assert` for checking incoming raw pointers that should not be NULL by API.

static EXECUTOR: StaticExecutor = StaticExecutor::new();

macro_rules! util_log {
    ($utils:ident, $lvl:ident, $fmt:literal) => {{
        let utils = unsafe { $utils.as_ref_unchecked() };
        let logfn = utils.log.expect("'log' funciton pointer is not null");
        unsafe { logfn(utils.conn, $lvl, $fmt.as_ptr().cast()) };
    }};
    ($utils:ident, $lvl:ident, $fmt:literal, $($arg:expr),*) => {{
        let utils = unsafe { $utils.as_ref_unchecked() };
        let logfn = utils.log.expect("'log' funciton pointer is not null");
        unsafe { logfn(utils.conn, $lvl, $fmt.as_ptr().cast(), $($arg),*) };
    }};
}

macro_rules! log {
    ($params:ident, $lvl:ident, $fmt:literal) => {{
        let utils = unsafe { $params.as_ref_unchecked().utils };
        util_log!(utils, $lvl, $fmt);
    }};
    ($params:ident, $lvl:ident, $fmt:literal, $($arg:expr),*) => {{
        let utils = unsafe { $params.as_ref_unchecked().utils };
        util_log!(utils, $lvl, $fmt, $($arg),* );
    }};
}

macro_rules! seterror {
    ($params:ident, $flags:expr, $fmt:expr) => {{
        let utils = unsafe { $params.as_ref_unchecked().utils.as_ref_unchecked() };
        let errfn = utils
            .seterror
            .expect("'seterror' funciton pointer is not null");
        unsafe { errfn(utils.conn, $flags, $fmt.as_ptr().cast()) };
    }};
}

#[unsafe(no_mangle)]
/// Sasl_client_plug_init implements the Cyrus-SASL client plugin interface.
///
/// The loaded plugin attempts to handle the `XOAUTH2` mechanism by requesting an oauth2 token from
/// GNOME Online Accounts via dbus.
///
/// # Safety
///
/// This function and the client callbacks try really hard to obey the rules.
pub unsafe extern "C" fn sasl_client_plug_init(
    utils: *const sasl_utils_t,
    max_version: c_int,
    out_version: *mut c_int,
    pluglist: *mut *const sasl_client_plug_t,
    plugcount: *mut c_int,
) -> c_int {
    debug_assert!(!utils.is_null());
    debug_assert!(!out_version.is_null());
    debug_assert!(!pluglist.is_null());
    debug_assert!(!plugcount.is_null());

    if max_version < SASL_CLIENT_PLUG_VERSION {
        return SASL_BADVERS;
    }
    unsafe {
        *out_version = SASL_CLIENT_PLUG_VERSION;
        *plugcount = PLUGINS.len() as c_int;
        *pluglist = &PLUGINS[0];
    };
    util_log!(utils, SASL_LOG_DEBUG, "xoauth2: init");
    SASL_OK
}

// This could be changed to have the executor created in [`sasl_client_plug_init`] (as the global
// context) and destroyed in `mech_free`, but it would require some borrow checker fighting.
const PLUGINS: [sasl_client_plug_t; 1] = [sasl_client_plug_t {
    mech_name: c"XOAUTH2".as_ptr(),
    max_ssf: 0,
    security_flags: SASL_SEC_NOANONYMOUS | SASL_SEC_PASS_CREDENTIALS,
    features: SASL_FEAT_WANT_CLIENT_FIRST | SASL_FEAT_ALLOWS_PROXY,
    required_prompts: ptr::null(),
    glob_context: ptr::null_mut(),
    mech_new: Some(mech_new),
    mech_step: Some(mech_step),
    mech_dispose: Some(mech_dispose),
    mech_free: None,
    idle: Some(idle),
    spare_fptr1: None,
    spare_fptr2: None,
}];

unsafe extern "C" fn mech_new(
    _glob_context: *mut c_void,
    cparams: *mut sasl_client_params_t,
    out: *mut *mut c_void,
) -> c_int {
    debug_assert!(!out.is_null());
    debug_assert!(!cparams.is_null());
    let ctx = Box::new(Context::default());

    log!(cparams, SASL_LOG_DEBUG, "xoauth2: mech_new");
    unsafe {
        *out = Box::into_raw(ctx).cast::<c_void>();
    };
    SASL_OK
}
unsafe extern "C" fn mech_step(
    context: *mut c_void,
    cparams: *mut sasl_client_params_t,
    serverin: *const c_char,
    serverlen: c_uint,
    prompt_need: *mut *mut sasl_interact_t,
    clientout: *mut *const c_char,
    clientoutlen: *mut c_uint,
    oparams: *mut sasl_out_params_t,
) -> c_int {
    debug_assert!(!context.is_null());
    debug_assert!(!cparams.is_null());
    let context = unsafe { context.cast::<Context>().as_mut_unchecked() };
    if !serverin.is_null()
        && let Ok(input) = CString::new(unsafe {
            slice::from_raw_parts(serverin.cast::<u8>(), serverlen as usize)
        })
    {
        log!(
            cparams,
            SASL_LOG_DEBUG,
            "xoauth2: mech_step: %s",
            input.as_ptr()
        );
    };

    match context.step {
        Step::Start => {
            log!(cparams, SASL_LOG_DEBUG, "xoauth2: mech_step: start");
            let mut prompt = vec![
                sasl_interact_t {
                    id: SASL_CB_AUTHNAME,
                    challenge: c"Authentication Name".as_ptr(),
                    prompt: c"Authentication ID".as_ptr(),
                    defresult: ptr::null(),
                    result: ptr::null(),
                    len: 0,
                },
                sasl_interact_t {
                    id: SASL_CB_LIST_END,
                    challenge: ptr::null(),
                    prompt: ptr::null(),
                    defresult: ptr::null(),
                    result: ptr::null(),
                    len: 0,
                },
            ];
            unsafe {
                *prompt_need = prompt.as_mut_ptr();
            };
            mem::forget(prompt);
            context.step = Step::User;
            SASL_INTERACT
        }
        Step::User => {
            debug_assert!(!prompt_need.is_null());
            debug_assert!(!oparams.is_null());

            log!(cparams, SASL_LOG_DEBUG, "xoauth2: mech_step: user");
            let prompt = unsafe { Vec::from_raw_parts(*prompt_need, 2, 2) };
            let prompt = &prompt[0];
            let username =
                unsafe { slice::from_raw_parts(prompt.result.cast::<u8>(), prompt.len as usize) };
            let cparams = unsafe { cparams.as_ref().expect("cparams is not null") };
            let utils = unsafe { cparams.utils.as_ref().expect("cparams->utils is not null") };
            let canon_user = cparams.canon_user.expect("canon_user is not null");

            let err = unsafe {
                canon_user(
                    utils.conn,
                    username.as_ptr().cast(),
                    username.len() as c_uint,
                    SASL_CU_AUTHID | SASL_CU_AUTHZID,
                    oparams,
                )
            };
            if err != SASL_OK {
                return err;
            }
            let username = String::from_utf8_lossy(username).to_string();

            context.step = Step::Token(username);
            SASL_CONTINUE
        }
        Step::Token(ref username) => {
            debug_assert!(!clientout.is_null());
            debug_assert!(!clientoutlen.is_null());

            log!(cparams, SASL_LOG_DEBUG, "xoauth2: mech_step: token");
            let res = future::block_on(EXECUTOR.run(find_token(username)));
            let token = match res {
                Ok(tok) => tok,
                Err(err) => {
                    if let zbus::Error::MethodError(name, more, _msg) = err {
                        let msg = match more {
                            Some(more) => format!("{name}: {more}"),
                            None => format!("{name}"),
                        };
                        let msg = CString::new(msg).expect("error message is CString-able");
                        seterror!(cparams, 0, msg.as_c_str());
                    } else {
                        let msg = err.to_string();
                        if let Ok(msg) = CString::new(msg) {
                            seterror!(cparams, 0, msg.as_c_str());
                        }
                    };
                    return SASL_FAIL;
                }
            };
            let input = format!("user={username}\x01auth=Bearer {token}\x01\x01");
            context.buf = Some(input);
            let buf = context.buf.as_ref().unwrap();

            unsafe {
                *clientoutlen = buf.len() as u32;
                *clientout = buf.as_ptr().cast();
            };
            context.step = Step::Done;
            SASL_OK
        }
        Step::Done => unreachable!("extra step???"),
    }
}
unsafe extern "C" fn mech_dispose(conn_context: *mut c_void, utils: *const sasl_utils_t) {
    debug_assert!(!conn_context.is_null());
    debug_assert!(!utils.is_null());

    util_log!(utils, SASL_LOG_DEBUG, "xoauth2: mech_dispose");
    let context = unsafe { Box::from_raw(conn_context.cast::<Context>()) };
    drop(context);
}
unsafe extern "C" fn idle(
    _global_context: *mut c_void,
    _conn_context: *mut c_void,
    cparams: *mut sasl_client_params_t,
) -> c_int {
    debug_assert!(!cparams.is_null());

    log!(cparams, SASL_LOG_DEBUG, "xoauth2: idle");
    if EXECUTOR.try_tick() { 1 } else { 0 }
}

async fn find_token(username: &str) -> Result<String, zbus::Error> {
    let conn = Connection::session().await?;
    let om = zbus::fdo::ObjectManagerProxy::new(
        &conn,
        "org.gnome.OnlineAccounts",
        "/org/gnome/OnlineAccounts",
    )
    .await?;
    let objs = om.get_managed_objects().await?;
    let path = objs
        .into_iter()
        .find(|(_, ifaces)| {
            ifaces.contains_key("org.gnome.OnlineAccounts.OAuth2Based")
                && ifaces
                    .get("org.gnome.OnlineAccounts.Mail")
                    .is_some_and(|mail| {
                        mail.get("ImapSupported")
                            .is_some_and(|v| v.downcast_ref().unwrap_or_default())
                            && mail.get("ImapUserName").is_some_and(|v| {
                                username.eq(v.downcast_ref::<&str>().unwrap_or(""))
                            })
                    })
        })
        .ok_or(zbus::Error::InterfaceNotFound)
        .map(|(path, _)| path)?;

    let oauth =
        oauth2_based::OAuth2BasedProxy::new(&conn, "org.gnome.OnlineAccounts", path).await?;
    let (tok, _expiry) = oauth.get_access_token().await?;

    Ok(tok)
}

#[allow(unused)]
#[derive(Debug, Default)]
struct Context {
    step: Step,
    buf: Option<String>,
}

#[derive(Default, Debug)]
enum Step {
    #[default]
    Start,
    User,
    Token(String),
    Done,
}

#[cfg(test)]
mod test {

    // TODO(hank) Write some tests.

    /*
    #[test]
    fn init() {
        const VERSION: c_int = 4;
        let mut version: c_int = -1;
        let mut pluglist = ptr::null();
        let mut plugcount: c_int = -1;
        let plugin = unsafe {
            let ok = sasl_client_plug_init(
                ptr::null(),
                VERSION,
                &mut version,
                &mut pluglist,
                &mut plugcount,
            );
            assert_eq!(ok, 0, "init failed: {ok}");
            assert_eq!(version, VERSION, "init failed: version mismatch");
            assert_eq!(plugcount, 1, "init failed: bad plugcount");
            pluglist.as_ref().expect("plugin is initialize")
        };
        let name = unsafe {
            CStr::from_ptr(plugin.mech_name)
                .to_str()
                .expect("valid utf-8")
        };
        assert_eq!(name, "XOAUTH2", "init failed: wrong mechanism name");
    }
    */
}
