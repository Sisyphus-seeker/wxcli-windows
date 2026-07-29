/// Embedded LLDB Python script for capturing PBKDF2 calls during WeChat startup.
///
/// This is written to a temp file at runtime and imported into LLDB.
///
/// Hooks `CCKeyDerivationPBKDF` and prints password/salt for rounds=256000 calls.
pub const CAPTURE_KEY_SCRIPT: &str = r#"import lldb
import binascii

keys_found = []
call_count = 0
module_name = __name__

def pbkdf_callback(frame, bp_loc, dict):
    global call_count, keys_found
    call_count += 1
    process = frame.GetThread().GetProcess()
    gpr = frame.GetRegisters()[0]

    pwd_ptr = gpr.GetChildMemberWithName("x1").GetValueAsUnsigned()
    pwd_len = gpr.GetChildMemberWithName("x2").GetValueAsUnsigned()
    salt_ptr = gpr.GetChildMemberWithName("x3").GetValueAsUnsigned()
    salt_len = gpr.GetChildMemberWithName("x4").GetValueAsUnsigned()
    prf = gpr.GetChildMemberWithName("x5").GetValueAsUnsigned()
    rounds = gpr.GetChildMemberWithName("x6").GetValueAsUnsigned()

    error = lldb.SBError()
    pwd_hex, salt_hex = "", ""
    if 0 < pwd_len < 1024:
        d = process.ReadMemory(pwd_ptr, pwd_len, error)
        if error.Success(): pwd_hex = binascii.hexlify(d).decode()
    if 0 < salt_len < 1024:
        d = process.ReadMemory(salt_ptr, salt_len, error)
        if error.Success(): salt_hex = binascii.hexlify(d).decode()

    prf_names = {3: "SHA1", 4: "SHA256", 5: "SHA512"}
    print(f"[PBKDF2 #{call_count}] PRF={prf_names.get(prf, prf)} rounds={rounds} "
          f"pwdLen={pwd_len} saltLen={salt_len}", flush=True)
    print(f"  Password: {pwd_hex}", flush=True)
    print(f"  Salt:     {salt_hex}", flush=True)
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName("CCKeyDerivationPBKDF")
    bp.SetScriptCallbackFunction(f"{module_name}.pbkdf_callback")
    bp.SetAutoContinue(True)
    print(f"Breakpoint on CCKeyDerivationPBKDF (id={bp.GetID()})", flush=True)
    print("Resuming process...", flush=True)
    target.GetProcess().Continue()

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand(
        f'command script add -f {module_name}.setup capture_keys')
    print("Run: capture_keys", flush=True)
"#;
