package vrf

/*
 * TODO: implement the vrf scheme in the case that the underlying curve
 *  is a pairing-friendly curve. In this case, there is no need to
 *  include a NIZK proof for it suffices to verify the equation
 *      e(vrf, g) = e(Hg(m), pk)
 */
