use crate::networking::messages::*;
use sgx_types::sgx_enclave_id_t;
use futures::{Future, Stream};
use std::sync::Arc;
use tokio_zmq::prelude::*;
use tokio_zmq::{Error, Multipart, Rep};
use log::{info, warn};

use base64;
use common_u::errors;
use failure::Error;
use hex::FromHex;
use sgx_types::*;
use std::thread::sleep;
use std::{self, time};

pub struct IpcListener {
    _context: Arc<zmq::Context>,
    rep_future: Box<dyn Future<Item = Rep, Error = Error>>,
}

impl IpcListener {
    pub fn new(conn_str: &str) -> Self {
        let _context = Arc::new(zmq::Context::new());
        let rep_future = Rep::builder(_context.clone()).bind(conn_str).build();
        println!("Binded to socket: {}", conn_str);
        IpcListener { _context, rep_future }
    }

    pub fn run<F>(self, f: F) -> impl Future<Item = (), Error = Error>
    where F: FnMut(Multipart) -> Multipart {
        self.rep_future.and_then(|rep| {
            let (sink, stream) = rep.sink_stream(25).split();
            stream.map(f).forward(sink).map(|(_stream, _sink)| ())
        })
    }
}

pub fn handle_message(request: Multipart, spid: &str, api_key: &str, eid: sgx_enclave_id_t, retries: u32) -> Multipart {
    let mut responses = Multipart::new();
    for msg in request {
        let msg: IpcMessageRequest = msg.into();
        let id = msg.id.clone();
        let response_msg = match msg.request {
            IpcRequest::GetEnclaveReport => handling::get_enclave_report(eid, spid, api_key, retries),
            IpcRequest::NewTaskEncryptionKey { userPubKey } => handling::new_task_encryption_key(&userPubKey, eid),
            IpcRequest::AddPersonalData { input } => handling::add_personal_data(input, eid),
            IpcRequest::FindMatch { input } => handling::find_match(input, eid),
        };
        let msg = IpcMessageResponse::from_response(response_msg.unwrap_or_error(), id);
        responses.push_back(msg.into());
    }
    responses
}


pub(self) mod handling {
    use crate::networking::messages::*;
    use crate::attestation::{service::AttestationService, constants::ATTESTATION_SERVICE_URL};
    use crate::keys_u;
    use crate::esgx::equote;
    use failure::Error;
    use sgx_types::{sgx_enclave_id_t, sgx_status_t};
    use hex::{FromHex, ToHex};
    use std::str;
    use rmp_serde::Deserializer;
    use serde::Deserialize;
    use serde_json::Value;
    use enigma_tools_u::esgx::equote as equote_tools;


    extern {
        fn ecall_add_personal_data(
            eid: sgx_enclave_id_t,
            ret: *mut sgx_status_t,
            encryptedUserId: *const u8,
            encryptedUserId_len: usize,
            encryptedData: *const u8,
            encryptedData_len: usize,
            userPubKey: &[u8; 64]) -> sgx_status_t;
    }

    extern {
        fn ecall_find_match(
                eid: sgx_enclave_id_t,
                ret: *mut sgx_status_t,
                encryptedUserId: *const u8,
                encryptedUserId_len: usize,
                userPubKey: &[u8; 64],
                serialized_ptr: *mut u64
            ) -> sgx_status_t;
    }

    type ResponseResult = Result<IpcResponse, Error>;

    #[derive(Serialize, Deserialize)]
    struct PubkeyResult {
        pubkey: Vec<u8>
    }

    //#[logfn(TRACE)]
    pub fn get_enclave_report(eid: sgx_enclave_id_t, spid: &str, api_key: &str, retries: u32) -> ResponseResult {

        let signing_key = equote::get_register_signing_address(eid)?;
        let prod_quote = match produce_quote(eid, spid) {
            Ok(q) => q,
            Err(e) => {
                println!("problem with quote, trying again: {:?}", e);
                e.to_string()
            }
        };
        let enc_quote = equote_tools::retry_quote(eid, spid, 18)?;
        info!("{:?}", enc_quote);


        // *Important* `option_env!()` runs on *Compile* time.
        // This means that if you want Simulation mode you need to run `export SGX_MODE=SW` Before compiling.
        let (signature, report_hex) = if option_env!("SGX_MODE").unwrap_or_default() == "SW" { // Simulation Mode
            let report =  enc_quote.as_bytes().to_hex();
            let sig = String::new();
            (sig, report)
        } else { // Hardware Mode
            let service: AttestationService = AttestationService::new_with_retries(ATTESTATION_SERVICE_URL, retries);
            // get report from Intel's attestation service (IAS)
            let response = service.get_report(enc_quote, api_key)?;

            // TODO print statements is there to help troubleshoot issue with
            // signature validation failing
            // see https://github.com/sbellem/SafeTrace/tree/ias-dev/enclave/safetrace/app/src/attestation#known-issues
            println!("result of verify report: {:#?}", response.result.verify_report().unwrap());

            let report = response.result.report_string.as_bytes().to_hex();
            let sig = response.result.signature;
            (sig, report)
        };

        let result = IpcResults::EnclaveReport { signing_key: signing_key.to_hex(), report: report_hex, signature };

        Ok(IpcResponse::GetEnclaveReport { result })
    }

    // TODO
    //#[logfn(TRACE)]
    pub fn new_task_encryption_key(_user_pubkey: &str, eid: sgx_enclave_id_t) -> ResponseResult {
        let mut user_pubkey = [0u8; 64];
        user_pubkey.clone_from_slice(&_user_pubkey.from_hex().unwrap());

        let (msg, sig) = keys_u::get_user_key(eid, &user_pubkey)?;

        let mut des = Deserializer::new(&msg[..]);
        let res: Value = Deserialize::deserialize(&mut des).unwrap();
        let pubkey = serde_json::from_value::<Vec<u8>>(res["pubkey"].clone())?;

        let result = IpcResults::DHKey {taskPubKey: pubkey.to_hex(), sig: sig.to_hex() };

        Ok(IpcResponse::NewTaskEncryptionKey { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn add_personal_data(input: IpcInputData, eid: sgx_enclave_id_t) -> ResponseResult {

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let encrypted_userid = input.encrypted_userid.from_hex()?;
        let encrypted_data = input.encrypted_data.from_hex()?;
        let mut user_pub_key = [0u8; 64];
        user_pub_key.clone_from_slice(&input.user_pub_key.from_hex()?);

        unsafe { ecall_add_personal_data(eid,
                                         &mut ret as *mut sgx_status_t,
                                         encrypted_userid.as_ptr() as * const u8,
                                         encrypted_userid.len(),
                                         encrypted_data.as_ptr() as * const u8,
                                         encrypted_data.len(),
                                         &user_pub_key) };

        let result;
        if ret == sgx_status_t::SGX_SUCCESS {
            result = IpcResults::AddPersonalData { status: Status::Passed };
        } else {
            result = IpcResults::AddPersonalData { status: Status::Failed };
        }
        Ok(IpcResponse::AddPersonalData { result })
    }

    // TODO
    //#[logfn(DEBUG)]
    pub fn find_match( input: IpcInputMatch, eid: sgx_enclave_id_t) -> ResponseResult {

        let mut ret = sgx_status_t::SGX_SUCCESS;
        let mut serialized_ptr = 0u64;
        let encrypted_userid = input.encrypted_userid.from_hex()?;
        let mut user_pub_key = [0u8; 64];
        user_pub_key.clone_from_slice(&input.user_pub_key.from_hex()?);

        let status = unsafe {
            ecall_find_match(
                eid,
                &mut ret as *mut sgx_status_t,
                encrypted_userid.as_ptr() as * const u8,
                encrypted_userid.len(),
                &user_pub_key,
                &mut serialized_ptr as *mut u64
            )
        };

        println!("ecall_find_match status: {:#?}", status);

        let box_ptr = serialized_ptr as *mut Box<[u8]>;
        let part = unsafe { Box::from_raw(box_ptr) };

        let result;
        if ret == sgx_status_t::SGX_SUCCESS {
            result = IpcResults::FindMatch { status: Status::Passed, encryptedOutput: part.to_hex()};
        } else {
            result = IpcResults::FindMatch { status: Status::Failed, encryptedOutput: "".to_string() };
        }
        Ok(IpcResponse::FindMatch { result })
    }

pub fn produce_quote(eid: sgx_enclave_id_t, spid: &str) -> Result<String, Error> {
    let spid = spid.from_hex()?;
    let mut id = [0; 16];
    id.copy_from_slice(&spid);
    let spid: sgx_spid_t = sgx_spid_t { id };

    // create quote
    let (status, (target_info, _gid)) = check_busy(|| {
        let mut target_info = sgx_target_info_t::default();
        let mut gid = sgx_epid_group_id_t::default();
        let status = unsafe { sgx_init_quote(&mut target_info, &mut gid) };
        (status, (target_info, gid))
    });
    info!("status {} target {} gid {}",status,target_info, gid);
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(errors::SgxError { status, function: "sgx_init_quote" }.into());
    }

    // create report
    let (status, (report, retval)) = check_busy(move || {
        let mut report = sgx_report_t::default();
        let mut retval = sgx_status_t::SGX_SUCCESS;
        let status = unsafe { ecall_get_registration_quote(eid, &mut retval, &target_info, &mut report) };
        (status, (report, retval))
    });
    if status != sgx_status_t::SGX_SUCCESS || retval != sgx_status_t::SGX_SUCCESS {
        return Err(errors::SgxError { status, function: "ecall_get_registration_quote" }.into());
    }


    // calc quote size
    let (status, quote_size) = check_busy(|| {
        let mut quote_size: u32 = 0;
        let status = unsafe { sgx_calc_quote_size(std::ptr::null(), 0, &mut quote_size) };
        (status, quote_size)
    });
    if status != sgx_status_t::SGX_SUCCESS || quote_size == 0 {
        return Err(errors::SgxError { status, function: "sgx_calc_quote_size" }.into());
    }

    // get the actual quote
    let (status, the_quote) = check_busy(|| {
        let mut the_quote = vec![0u8; quote_size as usize].into_boxed_slice();
        // all of this is according to this: https://software.intel.com/en-us/sgx-sdk-dev-reference-sgx-get-quote
        // the `p_qe_report` is null together with the nonce because we don't have an ISV enclave that needs to verify this
        // and we don't care about replay attacks because the signing key will stay the same and that's what's important.
        let status = unsafe {
            sgx_get_quote(&report,
                          sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
                          &spid,
                          std::ptr::null(),
                          std::ptr::null(),
                          0,
                          std::ptr::null_mut(),
                          the_quote.as_mut_ptr() as *mut sgx_quote_t,
                          quote_size,
            )
        };
        (status, the_quote)
    });
    if status != sgx_status_t::SGX_SUCCESS {
        return Err(errors::SgxError { status, function: "sgx_get_quote" }.into());
    }

    let encoded_quote = base64::encode(&the_quote);
    Ok(encoded_quote)
}

}
