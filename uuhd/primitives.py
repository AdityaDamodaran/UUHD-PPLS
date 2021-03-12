'''
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2
Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
'''

from __future__ import print_function
import hashlib
import multiprocessing
import time
import sys

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.integergroup import (
    integer,
    lcm,
    IntegerGroup,
    RSAGroup,
    IntegerGroupQ,
)

from charm.core.math import integer as charminteger
from charm.toolbox.integergroup import lcm, integer
from uuhd.measurementutil import get_real_size

# Paillier Enc
from charm.schemes.pkenc import pkenc_paillier99

# DSA
from charm.schemes.pksig import pksig_dsa


def SHA256(bytes_):
    hash_ = hashlib.new("sha256")
    hash_.update(bytes_)
    return hash_.digest()


# Vector Commitments
class VectorCommitment:
    def __init__(self, pairing_group):
        self.pairing_group = pairing_group

    def setup(self, n_size):
        par_g = [0]
        par_h = [0]
        alpha = self.pairing_group.random(ZR)
        g = self.pairing_group.random(G1)
        h = self.pairing_group.random(G2)
        for i in range(1, 2 * n_size + 1):
            par_g.append(g ** (alpha ** i))
            if i <= n_size:
                par_h.append(h ** (alpha ** i))
        par = {
            "group": self.pairing_group,
            "g": g,
            "h": h,
            "par_g": par_g,
            "par_h": par_h,
        }

        # Uncomment for par size measurements
        # print("Par size in bytes= " + str(get_real_size(par)))
        return par

    def commit(self, par, x, r):
        # v_com_time_start = time.time()
        v_com = 1
        n = len(x) - 1
        l = len(par["par_h"]) - 1
        for i in range(1, n + 1):
            if x[i] == 0:
                pass
            else:
                v_com = v_com * (par["par_g"][(l) + 1 - i] ** x[i])
        v_com = v_com * (par["g"] ** r)
        # v_com_time_end = time.time()
        # print(
        #     "Com computed in " + str(v_com_time_end - v_com_time_start)
        # )

        # Uncomment for v_com size measurements
        # print("Vector commitment size in bytes= " + str(get_real_size(v_com)))
        return v_com

    def generate_witness(self, par, i, x, r):
        # v_com_wit_time_start = time.time()
        witness = 1
        n = len(x) - 1
        l = len(par["par_h"]) - 1
        for k in range(1, n + 1):
            if k != i:
                witness = witness * (par["par_g"][l + 1 - k + i] ** x[k])
        witness = witness * (par["par_g"][i] ** r)
        # v_com_wit_time_end = time.time()
        # print(
        #     "Witness generated in " + str(v_com_wit_time_end - v_com_wit_time_start)
        # )

        # Uncomment for v_com size measurements
        # print("Vcom witness size in bytes= " + str(get_real_size(witness)))
        return witness

    def verify(self, par, v_com, x, i, witness):
        l = len(par["par_h"]) - 1
        lhs = pair(v_com, par["par_h"][i])
        rhs = pair(witness, par["h"]) * (
            pair(par["par_g"][1], par["par_h"][l]) ** x
        )
        if lhs == rhs:
            return 1
        else:
            return 0

    def update_com(self, par, com, j, x, xd):
        # v_com_com_update_time_start = time.time()
        result = com * (
            par["par_g"][(len(par["par_h"]) - 1) + 1 - j] ** (xd - x)
        )
        # v_com_com_update_time_end = time.time()

        # print("Com updated in " + str(v_com_com_update_time_end - v_com_com_update_time_start))
        return result

    def update_witness(self, par, w, i, j, x, xd):
        v_com_witness_update_time_start = time.time()
        if i == j:
            result = w
        else:
            result = w * (
                par["par_g"][(len(par["par_h"]) - 1) + 1 - j + i] ** (xd - x)
            )
        v_com_witness_update_time_end = time.time()
        runtime = str(
            v_com_witness_update_time_end - v_com_witness_update_time_start
        )

        # print("Witness updated in " + runtime)
        return result, runtime

    def rerand_com(self, par, v_com, r):
        return v_com * (par["g"] ** r)


# Pedersen Commitment Scheme
class PedersenCommitment:
    def __init__(self, pairing_group):
        self.pairing_group = pairing_group

    def setup(self):
        g = self.pairing_group.random(G1)
        alpha = self.pairing_group.random(ZR)
        h = g ** alpha
        par = {"group": self.pairing_group, "g": g, "h": h}
        return par

    def commit(self, par, x):
        opening = self.pairing_group.random(ZR)
        commitment = (par["g"] ** x) * (par["h"] ** opening)
        return {"com": commitment, "open": opening}

    # No rand
    def commit_0(self, par, x):
        opening = 0
        commitment = (par["g"] ** x) * (par["h"] ** opening)
        return {"com": commitment, "open": opening}

    def verify(self, par, commitment, x, opening):
        temp_commitment = (par["g"] ** x) * (par["h"] ** opening)
        if temp_commitment == commitment:
            return 1
        else:
            return 0

    def rerand(self, par, commitment, r):
        return commitment * (par["h"] ** r)


# Integer Commitments
class IntegerCommitment:
    """
    def generate_keys(self):
        rsa_group = RSAGroup()
        (p, q, n) = rsa_group.paramgen(1024)
        pp = 2 * p + 1
        qq = 2 * q + 1
        x = rsa_group.random(pp * qq)
        H = (rsa_group.random(pp * qq)) ** 2
        G = H ** x
        return {"group": rsa_group, "p": p, "q": q, "n": n, "G": G, "H": H}

    def get_random(self, par):
        return par["group"].random(par["n"] / 4)

    def commit(self, par, m):
        msg = integer(SHA256(m))
        opening = par["group"].random(par["n"] / 4)
        commitment = ((par["G"] ** msg) * (par["H"] ** opening)) % par["n"]
        return {"com": commitment, "open": opening}

    def verify(self, par, commitment, m, opening):
        msg = integer(SHA256(m))
        temp_commitment = ((par["G"] ** msg) * (par["H"] ** opening)) % par["n"]
        if temp_commitment == commitment:
            return 1
        else:
            return 0

    def int_commit(self, par, m):
        opening = par["group"].random(par["n"] / 4)
        commitment = ((par["G"] ** m) * (par["H"] ** opening)) % par["n"]
        return {"com": commitment, "open": opening}

    def int_verify(self, par, commitment, m, opening):
        temp_commitment = ((par["G"] ** m) * (par["H"] ** opening)) % par["n"]
        if temp_commitment == commitment:
            return 1
        else:
            return 0
    """

    def __init__(self, p, q, keylength):
        self.keylength = keylength
        if p == 0 or q == 0:
            # (p, q, n) = rsa_group.paramgen(self.keylength)
            self.group = IntegerGroup()
            self.group.paramgen(keylength)
            p = self.group.p
            q = self.group.q
        self.n = p * q

    def setup(self):
        alpha = integer(charminteger.random(self.n))
        h = charminteger.random(self.n) ** 2
        g = h ** alpha
        return {"h": h, "g": g}

    def commit(self, par_ic, message):
        open = integer(charminteger.randomBits(self.keylength))
        com = ((par_ic["g"] ** message) * (par_ic["h"] ** open)) % self.n
        return (com, open)

    def decommit(self, par_ic, com, open, message):
        if ((par_ic["g"] ** message) * (par_ic["h"] ** open)) % self.n == com:
            return 1
        return 0


# Structure Preserving Signature Scheme
class StructurePreservingSignature:
    def __init__(self):
        pass

    def generate_keys(self, pairing_group, a, b):
        u = [0]
        gu = [0]
        for i in range(1, b + 1):
            u.append(pairing_group["group"].random(ZR))
            gu.append(pairing_group["g"] ** u[i])
        w = [0]
        gw = [0]
        for i in range(1, a + 1):
            w.append(pairing_group["group"].random(ZR))
            gw.append(pairing_group["h"] ** w[i])
        v = pairing_group["group"].random(ZR)
        z = pairing_group["group"].random(ZR)
        gv = pairing_group["h"] ** v
        gz = pairing_group["h"] ** z
        public_key = {"grp": pairing_group, "U": gu, "V": gv, "W": gw, "Z": gz}
        secret_key = {"pk": public_key, "u": u, "v": v, "w": w, "z": z}
        return public_key, secret_key

    def sign(self, secret_key, msg):
        public_key = secret_key["pk"]
        r = public_key["grp"]["group"].random(ZR)
        gr = public_key["grp"]["g"] ** r
        a = len(secret_key["w"]) - 1
        b = len(secret_key["u"]) - 1

        product_1 = 1
        for i in range(1, a + 1):
            product_1 = product_1 * (msg[i] ** (-secret_key["w"][i]))
        gs = (
            public_key["grp"]["g"] ** (secret_key["z"] - (r * secret_key["v"]))
        ) * product_1

        product_2 = 1
        for i in range(1, b + 1):
            product_2 = product_2 * msg[a + i] ** (-secret_key["u"][i])
        gt = (public_key["grp"]["h"] * product_2) ** ~r

        return gr, gs, gt

    def verify(self, public_key, signature, msg):
        l_1 = pair(signature["R"], public_key["V"])
        l_2 = pair(signature["S"], public_key["grp"]["h"])
        a = len(public_key["W"]) - 1
        b = len(public_key["U"]) - 1

        product_1 = 1
        for i in range(1, a + 1):
            product_1 = pair(msg[i], public_key["W"][i]) * product_1
        l_3 = product_1

        rhs_1 = pair(public_key["grp"]["g"], public_key["Z"])
        lhs_1 = l_1 * l_2 * l_3

        l_4 = pair(signature["R"], signature["T"])

        product_2 = 1
        for i in range(1, b + 1):
            product_2 = pair(public_key["U"][i], msg[a + i]) * product_2
        l_5 = product_2

        rhs_2 = pair(public_key["grp"]["g"], public_key["grp"]["h"])
        lhs_2 = l_4 * l_5

        if lhs_1 == rhs_1 and lhs_2 == rhs_2:
            return 1
        else:
            return 0


# Modified DSA
class DSA:
    def __init__(self, p=0, q=0):
        self.group = IntegerGroupQ()
        self.group.p, self.group.q, self.group.r = p, q, 2

    def generate_keys(self, k):
        if self.group.p == 0 or self.group.q == 0:
            self.group.paramgen(k)
        x = self.group.random()
        generator = self.group.randomGen()
        y = (generator ** x) % self.group.p
        return {"g": generator, "y": y}, x

    def generate_random(self):
        return self.group.random()


# Modified Paillier
class PaillierEncryption(pkenc_paillier99.Pai99):
    def __init__(self, group_object):
        self.group_object = group_object
        pkenc_paillier99.Pai99.__init__(self, self.group_object)

    def encrypt(self, pk, m):
        g, n, n2 = pk["g"], pk["n"], pk["n2"]
        r = self.group_object.random(pk["n"])
        c = ((g % n2) ** m) * ((r % n2) ** n)
        return pkenc_paillier99.Ciphertext({"c": c}, pk, "c"), r
