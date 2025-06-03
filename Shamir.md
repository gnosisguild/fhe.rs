**Parameters:**

*n*: Number of parties.

*N*: Ring dimension (In FHE.rs this is polynomial degree from BfvParameters struct, from the paper we are implementing this is `d`)

*Rq*: Ring of polynomials of coefficients in *Z<sub>q</sub>* with degree of polynomials equal
at most `N−1`.

*a*: a random polynomial from *R<sub>q</sub>*, known to all players

# Algorithm for generating the secret and public key shares


1. For each party *i*, where *i* ranges from `1` to `n`:
   1. Generate a random polynomialpiof degreeN−1 with coefficients in `{− 1 , 0 , 1 }` (so this polynomial is the contribution of party *i* to the secret key *s* of BFV).
   2. Sample a random polynomial *e<sub>i</sub>* from the error distribution (Note this *e<sub>i</sub>* is only used here. That is, it won’t be needed afterwards)
   3. Calculate the polynomial *ek<sub>i</sub> < ← − · a · p<sub>i</sub>+e<sub>i</sub>* (note computation here is in *R<sub>q</sub>*) and broadcast it. (So this polynomial is the public key share of party *i* of the public key *ek* of the BFV scheme. That is, *ek* is the sum of *ek<sub>i</sub>* for *i* from `1` to `n`.).
   4. **For each coefficient *p<sub>ij</sub>* of p<sub>i</sub>, where *j* ranges from `0` to `N− 1`:**
      1. Generate a random polynomial *f<sub>ij</sub>* of degree `floor((n-1)/2)` with coefficients in *Z<sub>q</sub>* and constant term *p<sub>ij</sub>*.
      2. For each party *k*, where *k* ranges from `1` to `n`, give party *k* the value *f<sub>ij</sub>(k)*.
2. The share of party *k* of the secret key *s* of BFV (note *s* is never constructed) is the share of each coefficient *s<sub>j</sub> of *s* for *j* from `0` to `N - 1`. That is, the shares *k<sub>j</sub> of party *k* of the coefficients *j* is the sum of *f<sub>ij</sub>(k)* for *i* from `1` to `n`. We are going to denote the share of party *k* of the secret key *s* as *sk = [sk<sub>0</sub> ,...,sk<sub>(N−1)</sub>]*

# Algorithm for generating shares of a smudging error es (in the paper they refer to it as *e<sub>sm</sub>*)


1. For each party *i*, where *i* ranges from `1` to *n*:
   1. Generate a random polynomial *h<sub>i</sub>* of degree `N−1` with coefficients in [*−B<sub>sm</sub>,B<sub>sm</sub>] (so this polynomial is the contribution of party *i* to the smudging error *es*. In the paper they refer to it as *e<sub>sm,i</sub>*)
   2. For each coefficient *h<sub>ij</sub>* of *h<sub>i</sub>*, where *j* ranges from `0` to `N−1`:
      1. Generate a random polynomial *o<sub>ij</sub>* of degree `floor((n-1)/2)` with coefficients in Z<sub>q</sub> and constant term *h<sub>ij</sub>*.
      2. For each party `k`, where `k` ranges from `1` to `n`, give party `k` the value *o<sub>ij</sub>(k)*.
2. The share of party `k` of the smudging error *es*(note *es* is never constructed) is the share of each coefficient *es<sub>j</sub>* of *es* for `j` from `0` to `N - 1`. That is, the share *es<sub>kj</sub>* of party `k` of the coefficient *es<sub>j</sub>* is the sum of *o<sub>ij</sub>(k)* for `i` from `1` to `n`. We are going to denote the share of party `k` of *es* as *es<sup>k</sup>* = [*es<sub>k0</sub>* ,...,*e<sub>sk(N−1)</sub>]

# Algorithm for distributed decryption

Let *c* = *(c<sub>0</sub> ,c<sub>1</sub>)* be the ciphertext to decrypt.
Let *es* one secret shared smudging error (note for every decryption we use a different *es*). Decryption happens
between a set *S* of *t + 1* parties, where *S ⊂ {1 ,...,n}*.


1. For each party *i* in *S*:
   1. Calculate *d<sup>i</sup> ← c<sub>0</sub> + c<sub>1</sub> · s<sup>i</sup> + es<sup>i</sup>* (note here multiplication between *c<sub>1</sub>* and *s<sup>i</sup> is not coefficient wise, it is multiplying two polynomials)
   2. Broadcast to the other *t* parties the value *d<sup>i</sup>
   3. Reconstruct *d = Dec(c)* as the sum of *λ<sub>j</sub> · d<sup>j</sup>* for *j* in *S*. *λ<sub>j</sub>* here are Lagrange coefficients, their values depends on the set *S* participating (e.g. say *t = 2*, *n = 5*, and the set was *{1,2,4}* , then the lagrange coefficients will be calculated as in [this link](https://en.wikipedia.org/wiki/Shamir%27s_secret_sharing#Reconstruction), with *x<sub>0</sub> = 1, x<sub>1</sub> = 2, x<sub>2</sub> = 4, y<sub>0</sub> = d<sup>1</sup> ,y<sub>1</sub> = d<sup>2</sup>, y<sub>2</sub> = d<sup>4</sup>*).