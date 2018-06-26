# ope

This code implements the OPE algorithm.  It is based on
the following work:

```
Order-Preserving Symmetric Encryption
Boldyreva, 2009
```

## running

When run the following code is run:

```rust
    // pass OPE the key
    let mut ope = ope::OPE::new(String::from("my secret key"));

    let a = ope.encrypt(1529939373);
    let b = ope.encrypt(1529939377);
    let c = ope.encrypt(1529939378);

    println!("a: {}, b: {}, c: {}", a, b, c);
    assert!(a < b);
    assert!(b < c);
```

Seen above, we initialize the OPE with a secret key, then
encrypt three ascending numbers.  We then print the results
out and check that order has been preserved across the numbers.

Below is the output of this program:

```
a: 4294961016, b: 4294961545, c: 4294965783
```
