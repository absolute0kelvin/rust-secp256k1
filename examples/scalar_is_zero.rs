use secp256k1_sys as sys;

fn main() {
    unsafe {
        let zero = [0u8; 32];
        let ret_zero = sys::secp256k1_scalar_is_zero_from32(zero.as_ptr());
        println!("zero -> {}", ret_zero);

        let mut nonzero = [0u8; 32];
        nonzero[31] = 1; // 0x...01
        let ret_nonzero = sys::secp256k1_scalar_is_zero_from32(nonzero.as_ptr());
        println!("nonzero -> {}", ret_nonzero);
    }
}


