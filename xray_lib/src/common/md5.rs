pub macro md5 {
    ($($x:expr),*) => {{
        use md5::{Md5, Digest};
        let mut digest = Md5::new();
        $(digest.update($x);)*
        let res:[u8;16]=digest.finalize().into();
        res
    }}
}
