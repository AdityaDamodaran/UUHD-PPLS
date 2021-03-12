'''
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2
Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
'''

import json

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.pairinggroup import PairingGroup, pair, ZR
from charm.toolbox.integergroup import RSAGroup
from charm.core.engine.util import serializeList
from charm.core.math.integer import integer
from collections import namedtuple

from uuhd.jsonobjects import (
    ZKWitness,
    ZKInstance,
    SubWitnessRecord,
    dict_from_class,
)
from uuhd.primitives import DSA, PaillierEncryption, SHA256, IntegerCommitment

pairing_group = PairingGroup("BN256")


def get_record_by_index(index, list):
    for item in list:
        if item["index"] == index:
            return item


def generate_n_random_exponents(n):
    exponents = []
    for i in range(0, n):
        exponents.append(pairing_group.random(ZR))
    return exponents


class SigmaProtocol:
    def __init__(self, instance, pairing_group_string, keylength):

        self.r_d, self.s_d, self.t_d = (
            instance["bsig"]["Rd"],
            instance["bsig"]["Sd"],
            instance["bsig"]["Td"],
        )

        public_key = instance["pk"]

        self.v, self.w1, self.w2, self.z, self.u1 = (
            public_key["V"],
            public_key["W"][1],
            public_key["W"][2],
            public_key["Z"],
            public_key["U"][1],
        )

        self.keylength = keylength

        self.one = 1

        self.g, self.gt = instance["par"]["g"], instance["par"]["h"]
        self.h, self.ht = instance["bh"], instance["bht"]

        self.vcomd, self.comd = instance["vcomd"], instance["comd"]

        self.ped_h, self.ped_g = (
            instance["par_c"]["h"],
            instance["par_c"]["g"],
        )  # self.g

        self.sid = instance["sid"]

        self.instance = instance

        dsa_p = integer(
            156053402631691285300957066846581395905893621007563090607988086498527791650834395958624527746916581251903190331297268907675919283232442999706619659475326192111220545726433895802392432934926242553363253333261282122117343404703514696108330984423475697798156574052962658373571332699002716083130212467463571362679
        )

        dsa_q = integer(
            78026701315845642650478533423290697952946810503781545303994043249263895825417197979312263873458290625951595165648634453837959641616221499853309829737663096055610272863216947901196216467463121276681626666630641061058671702351757348054165492211737848899078287026481329186785666349501358041565106233731785681339
        )

        self.dsa = DSA(dsa_p, dsa_q)
        self.dsa_keys = self.dsa.generate_keys(keylength)

        rsa_group = RSAGroup()

        self.paillier_encryption = PaillierEncryption(rsa_group)
        (self.public_key, self.secret_key) = self.paillier_encryption.keygen(
            self.keylength
        )
        ic_p = integer(
            333437049425486136095925931727629203622119239282802038455917646172563395024265917241890473852501318262109839243221497854682815506880304349748481648877420618747530394310060738051284980323398797638078562462943477904211178707988798971266777314022673227003284335883622084916018185539789562312940907090712386355299
        )
        ic_q = integer(
            294092988306368388636535355362351220952777074915662080329740789451817968606482246364359892865057621298389179478994706465098262699509935804409002480293234947971872131356003427444279672200378079370695651721652248116723483318427208508192689675310517884904089979454005634358395042846262967137935407297336359215239
        )

        self.integer_commitment = IntegerCommitment(ic_p, ic_q, self.keylength)

        self.par_ic = self.integer_commitment.setup()

    def compute_ppe_1(self, d1, d2, d3, d4, side):
        if side == "lhs":
            return (
                (pair(self.r_d, self.v) ** self.one)
                * (pair(self.s_d, self.gt) ** self.one)
                * (pair(self.vcomd, self.w1) ** self.one)
                * (pair(self.comd, self.w2) ** self.one)
                * (pair(self.g, self.z) ** -1)
            )
        else:
            return (
                (pair(self.h, self.v) ** d1)
                * (pair(self.h, self.gt) ** d2)
                * (pair(self.g, self.w1) ** d3)
                * (pair(self.ped_h, self.w2) ** d4)
            )

    def compute_ppe_2(self, d1, d5, side):
        if side == "lhs":
            return (
                (pair(self.r_d, self.t_d) ** self.one)
                * (pair(self.u1, (self.gt ** self.sid)) ** self.one)
                * (pair(self.g, self.gt) ** -1)
                * (pair(self.h, self.ht) ** (d1 * d5))
            )
        else:
            return (pair(self.r_d, self.ht) ** d5) * (
                pair(self.h, self.t_d) ** d1
            )

    def compute_ppe_3(self, index, i, copen_i, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return pair(record["ccom_i"], self.gt) ** self.one
        else:
            return (pair(self.ped_g, self.gt) ** i) * (
                pair(self.ped_h, self.gt) ** copen_i
            )

    def compute_ppe_4(self, index, vr, copen_ri, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return pair(record["ccom_ri"], self.gt) ** self.one
        else:
            return (pair(self.ped_g, self.gt) ** vr) * (
                pair(self.ped_h, self.gt) ** copen_ri
            )

    def compute_ppe_5(self, index, di_1, di_2, i, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return (
                (pair(record["sig"]["R_id"], self.v) ** self.one)
                * (pair(record["sig"]["S_id"], self.gt) ** self.one)
                * (pair(self.g ** self.sid, self.w2) ** self.one)
                * (pair(self.g, self.z) ** -1)
            )
        else:
            return (
                (pair(self.h, self.v) ** di_1)
                * (pair(self.h, self.gt) ** di_2)
                * (pair(self.g, self.w1) ** -i)
            )

    def compute_ppe_6(self, index, di_1, di_3, di_4, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return (
                (
                    pair(record["sig"]["R_id"], record["sig"]["T_id"])
                    ** self.one
                )
                * (pair(self.u1, record["phd_i"]) ** self.one)
                * (pair(self.h, self.ht) ** (di_1 * di_3))
                * (pair(self.g, self.gt) ** -1)
            )

        else:
            return (
                (pair(record["sig"]["R_id"], self.ht) ** di_3)
                * (pair(self.h, record["sig"]["T_id"]) ** di_1)
                * (pair(self.u1, self.ht) ** di_4)
            )

    def compute_ppe_7(self, index, di_4, di_5, vr, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return (pair(self.vcomd, record["phd_i"]) ** 1) * (
                pair(record["witd_i"], self.gt) ** -self.one
            )
        else:
            return (
                (pair(self.vcomd, self.ht) ** di_4)
                * (pair(self.h, self.gt) ** -di_5)
                * (
                    pair(
                        self.instance["par"]["par_g"][1],
                        self.instance["par"]["par_h"][
                            len(self.instance["par"]["par_h"]) - 1
                        ],
                    )
                    ** vr
                )
            )

    def compute_s(self, random_witness, c, witness, random_ico, witness_ico):
        s_j = ZKWitness()
        hashes_j = ZKWitness()

        r1, r2, r3, r4, r5 = (
            random_witness["d1"],
            random_witness["d2"],
            random_witness["d3"],
            random_witness["d4"],
            random_witness["d5"],
        )
        r1h, r2h, r3h, r4h, r5h = (
            integer(SHA256(bytes(str(r1), "utf-8"))),
            integer(SHA256(bytes(str(r2), "utf-8"))),
            integer(SHA256(bytes(str(r3), "utf-8"))),
            integer(SHA256(bytes(str(r4), "utf-8"))),
            integer(SHA256(bytes(str(r5), "utf-8"))),
        )

        d1, d2, d3, d4, d5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )
        d1h, d2h, d3h, d4h, d5h = (
            integer(SHA256(bytes(str(d1), "utf-8"))),
            integer(SHA256(bytes(str(d2), "utf-8"))),
            integer(SHA256(bytes(str(d3), "utf-8"))),
            integer(SHA256(bytes(str(d4), "utf-8"))),
            integer(SHA256(bytes(str(d5), "utf-8"))),
        )

        hash_c = integer(SHA256(bytes(str(c), "utf-8")))

        s_j.set_d(
            r1 + (c * d1),
            r2 + (c * d2),
            r3 + (c * d3),
            r4 + (c * d4),
            r5 + (c * d5),
        )

        hashes_j.set_d(
            r1h + (hash_c * d1h),
            r2h + (hash_c * d2h),
            r3h + (hash_c * d3h),
            r4h + (hash_c * d4h),
            r5h + (hash_c * d5h),
        )

        for subwitness in witness["wit_i"]:
            random_subwitness_record = get_record_by_index(
                subwitness["index"], random_witness["wit_i"]
            )

            di_1, di_2, di_3, di_4, di_5 = (
                subwitness["di_1"],
                subwitness["di_2"],
                subwitness["di_3"],
                subwitness["di_4"],
                subwitness["di_5"],
            )

            di_1h, di_2h, di_3h, di_4h, di_5h = (
                integer(SHA256(bytes(str(di_1), "utf-8"))),
                integer(SHA256(bytes(str(di_2), "utf-8"))),
                integer(SHA256(bytes(str(di_3), "utf-8"))),
                integer(SHA256(bytes(str(di_4), "utf-8"))),
                integer(SHA256(bytes(str(di_5), "utf-8"))),
            )

            i, vr, copen_i, copen_ri = (
                subwitness["i"],
                subwitness["vr"],
                subwitness["copen_i"],
                subwitness["copen_ri"],
            )

            ih, vrh, copen_ih, copen_rih = (
                integer(subwitness["i"]),
                integer(subwitness["vr"]),
                integer(SHA256(bytes(str(subwitness["copen_i"]), "utf-8"))),
                integer(SHA256(bytes(str(subwitness["copen_ri"]), "utf-8"))),
            )

            rdi_1, rdi_2, rdi_3, rdi_4, rdi_5 = (
                random_subwitness_record["di_1"],
                random_subwitness_record["di_2"],
                random_subwitness_record["di_3"],
                random_subwitness_record["di_4"],
                random_subwitness_record["di_5"],
            )

            ri, rvr, rcopen_i, rcopen_ri = (
                random_subwitness_record["i"],
                random_subwitness_record["vr"],
                random_subwitness_record["copen_i"],
                random_subwitness_record["copen_ri"],
            )

            rdi_1h, rdi_2h, rdi_3h, rdi_4h, rdi_5h = (
                integer(
                    SHA256(
                        bytes(str(random_subwitness_record["di_1"]), "utf-8")
                    )
                ),
                integer(
                    SHA256(
                        bytes(str(random_subwitness_record["di_2"]), "utf-8")
                    )
                ),
                integer(
                    SHA256(
                        bytes(str(random_subwitness_record["di_3"]), "utf-8")
                    )
                ),
                integer(
                    SHA256(
                        bytes(str(random_subwitness_record["di_4"]), "utf-8")
                    )
                ),
                integer(
                    SHA256(
                        bytes(str(random_subwitness_record["di_5"]), "utf-8")
                    )
                ),
            )

            rih, rvrh, rcopen_ih, rcopen_rih = (
                integer(
                    SHA256(bytes(str(random_subwitness_record["i"]), "utf-8"))
                ),
                integer(
                    SHA256(bytes(str(random_subwitness_record["vr"]), "utf-8"))
                ),
                integer(
                    SHA256(
                        bytes(
                            str(random_subwitness_record["copen_i"]), "utf-8"
                        )
                    )
                ),
                integer(
                    SHA256(
                        bytes(
                            str(random_subwitness_record["copen_ri"]), "utf-8"
                        )
                    )
                ),
            )

            temp_s_j_i = SubWitnessRecord(
                subwitness["index"],
                ri + (c * i),
                rvr + (c * vr),
                rcopen_i + (c * copen_i),
                rcopen_ri + (c * copen_ri),
                rdi_1 + (c * di_1),
                rdi_2 + (c * di_2),
                rdi_3 + (c * di_3),
                rdi_4 + (c * di_4),
                rdi_5 + (c * di_5),
            )

            temp_hashes_j_i = SubWitnessRecord(
                subwitness["index"],
                rih + (hash_c * ih),
                rvrh + (hash_c * vrh),
                rcopen_ih + (hash_c * copen_ih),
                rcopen_rih + (hash_c * copen_rih),
                rdi_1h + (hash_c * di_1h),
                rdi_2h + (hash_c * di_2h),
                rdi_3h + (hash_c * di_3h),
                rdi_4h + (hash_c * di_4h),
                rdi_5h + (hash_c * di_5h),
            )

            s_j.append_subwitnesses(temp_s_j_i)
            hashes_j.append_subwitnesses(temp_hashes_j_i)

        s_o_j = ZKWitness()

        ro1, ro2, ro3, ro4, ro5 = (
            random_ico["d1"],
            random_ico["d2"],
            random_ico["d3"],
            random_ico["d4"],
            random_ico["d5"],
        )
        do1, do2, do3, do4, do5 = (
            witness_ico["d1"],
            witness_ico["d2"],
            witness_ico["d3"],
            witness_ico["d4"],
            witness_ico["d5"],
        )

        s_o_j.set_d(
            ro1 + (hash_c * do1),
            ro2 + (hash_c * do2),
            ro3 + (hash_c * do3),
            ro4 + (hash_c * do4),
            ro5 + (hash_c * do5),
        )

        for subwitness_ico_record in witness_ico["wit_i"]:
            random_ico_record = get_record_by_index(
                subwitness_ico_record["index"], random_ico["wit_i"]
            )

            di_1, di_2, di_3, di_4, di_5 = (
                subwitness_ico_record["di_1"],
                subwitness_ico_record["di_2"],
                subwitness_ico_record["di_3"],
                subwitness_ico_record["di_4"],
                subwitness_ico_record["di_5"],
            )

            i, vr, copen_i, copen_ri = (
                subwitness_ico_record["i"],
                subwitness_ico_record["vr"],
                subwitness_ico_record["copen_i"],
                subwitness_ico_record["copen_ri"],
            )

            rdi_1, rdi_2, rdi_3, rdi_4, rdi_5 = (
                random_ico_record["di_1"],
                random_ico_record["di_2"],
                random_ico_record["di_3"],
                random_ico_record["di_4"],
                random_ico_record["di_5"],
            )

            ri, rvr, rcopen_i, rcopen_ri = (
                random_ico_record["i"],
                random_ico_record["vr"],
                random_ico_record["copen_i"],
                random_ico_record["copen_ri"],
            )

            temp_s_j_i = SubWitnessRecord(
                subwitness_ico_record["index"],
                ri + (hash_c * i),
                rvr + (hash_c * vr),
                rcopen_i + (hash_c * copen_i),
                rcopen_ri + (hash_c * copen_ri),
                rdi_1 + (hash_c * di_1),
                rdi_2 + (hash_c * di_2),
                rdi_3 + (hash_c * di_3),
                rdi_4 + (hash_c * di_4),
                rdi_5 + (hash_c * di_5),
            )
            s_o_j.append_subwitnesses(temp_s_j_i)

        return s_j, hashes_j, hash_c

    def pe_check(self, index, hashes_j, random_pe, witness_pe, hash_c):
        g, n, n2 = (
            self.public_key["g"],
            self.public_key["n"],
            self.public_key["n2"],
        )
        temp_pe = {
            "c": random_pe[index][0]["c"]
            * (witness_pe[index][0]["c"] ** hash_c)
        }
        return (temp_pe["c"] % n2) == (
            (
                ((g % n2) ** (hashes_j[index]))
                * (
                    (
                        random_pe[index][1]
                        * (witness_pe[index][1] ** hash_c)
                        % n2
                    )
                    ** n
                )
            )
            % n2
        )

    def pe_sub_check(
        self, subindex, index, hashes_j, random_pe, witness_pe, hash_c
    ):

        g, n, n2 = (
            self.public_key["g"],
            self.public_key["n"],
            self.public_key["n2"],
        )

        random_record = get_record_by_index(subindex, random_pe["wit_i"])
        witness_record = get_record_by_index(subindex, witness_pe["wit_i"])
        hash_record = get_record_by_index(subindex, hashes_j["wit_i"])
        temp_pe = {
            "c": random_record[index][0]["c"]
            * (witness_record[index][0]["c"] ** hash_c)
        }
        return (temp_pe["c"] % n2) == (
            (
                ((g % n2) ** (hash_record[index]))
                * (
                    (
                        random_record[index][1]
                        * (witness_record[index][1] ** hash_c)
                        % n2
                    )
                    ** n
                )
            )
            % n2
        )

    def verify_paillier_ciphertexts(
        self,
        hash_c,
        random_paillier_ciphertexts,
        witness_paillier_ciphertexts,
        hashes_j,
    ):

        if (
            not (
                self.pe_check(
                    "d1",
                    hashes_j,
                    random_paillier_ciphertexts,
                    witness_paillier_ciphertexts,
                    hash_c,
                )
            )
            or not (
                self.pe_check(
                    "d2",
                    hashes_j,
                    random_paillier_ciphertexts,
                    witness_paillier_ciphertexts,
                    hash_c,
                )
            )
            or not (
                self.pe_check(
                    "d3",
                    hashes_j,
                    random_paillier_ciphertexts,
                    witness_paillier_ciphertexts,
                    hash_c,
                )
            )
            or not (
                self.pe_check(
                    "d4",
                    hashes_j,
                    random_paillier_ciphertexts,
                    witness_paillier_ciphertexts,
                    hash_c,
                )
            )
            or not (
                self.pe_check(
                    "d5",
                    hashes_j,
                    random_paillier_ciphertexts,
                    witness_paillier_ciphertexts,
                    hash_c,
                )
            )
        ):
            print(
                "Abort: (Sigma Protocol) Paillier ciphertext verification failed."
            )
            exit()
        for subwitness in witness_paillier_ciphertexts["wit_i"]:
            if (
                not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "di_1",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "di_2",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "di_3",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "di_4",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
            ):
                print(
                    "Abort: (Sigma Protocol) Paillier ciphertext verification failed."
                )
                exit()
            if (
                not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "di_5",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "i",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "vr",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "copen_i",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
                or not (
                    self.pe_sub_check(
                        subwitness["index"],
                        "copen_ri",
                        hashes_j,
                        random_paillier_ciphertexts,
                        witness_paillier_ciphertexts,
                        hash_c,
                    )
                )
            ):
                print(
                    "Abort: (Sigma Protocol) Paillier ciphertext verification failed."
                )
                exit()
        return 1

    def verify_integer_commitments(
        self,
        hash_c,
        random_integer_openings,
        witness_integer_openings,
        random_integer_commitments,
        witness_integer_commitments,
        hashes_j,
        par_ic,
    ):

        if (
            not (
                random_integer_commitments["d1"]
                * (witness_integer_commitments["d1"] ** hash_c)
                == (
                    (
                        (par_ic["g"] ** hashes_j["d1"])
                        * (
                            par_ic["h"]
                            ** (
                                random_integer_openings["d1"]
                                + (hash_c * witness_integer_openings["d1"])
                            )
                        )
                    )
                    % self.integer_commitment.n
                )
            )
            or not (
                random_integer_commitments["d2"]
                * (witness_integer_commitments["d2"] ** hash_c)
                == (
                    (
                        (par_ic["g"] ** hashes_j["d2"])
                        * (
                            par_ic["h"]
                            ** (
                                random_integer_openings["d2"]
                                + (hash_c * witness_integer_openings["d2"])
                            )
                        )
                    )
                    % self.integer_commitment.n
                )
            )
            or not (
                random_integer_commitments["d3"]
                * (witness_integer_commitments["d3"] ** hash_c)
                == (
                    (
                        (par_ic["g"] ** hashes_j["d3"])
                        * (
                            par_ic["h"]
                            ** (
                                random_integer_openings["d3"]
                                + (hash_c * witness_integer_openings["d3"])
                            )
                        )
                    )
                    % self.integer_commitment.n
                )
            )
            or not (
                random_integer_commitments["d4"]
                * (witness_integer_commitments["d4"] ** hash_c)
                == (
                    (
                        (par_ic["g"] ** hashes_j["d4"])
                        * (
                            par_ic["h"]
                            ** (
                                random_integer_openings["d4"]
                                + (hash_c * witness_integer_openings["d4"])
                            )
                        )
                    )
                    % self.integer_commitment.n
                )
            )
            or not (
                random_integer_commitments["d5"]
                * (witness_integer_commitments["d5"] ** hash_c)
                == (
                    (
                        (par_ic["g"] ** hashes_j["d5"])
                        * (
                            par_ic["h"]
                            ** (
                                random_integer_openings["d5"]
                                + (hash_c * witness_integer_openings["d5"])
                            )
                        )
                    )
                    % self.integer_commitment.n
                )
            )
        ):
            print("Abort: (Sigma Protocol) Integer commitment check failed.")
        for subwitness in witness_integer_commitments["wit_i"]:
            random_ic_record = get_record_by_index(
                subwitness["index"], random_integer_commitments["wit_i"]
            )
            random_ic_opening_record = get_record_by_index(
                subwitness["index"], random_integer_openings["wit_i"]
            )
            witnessopenrecord = get_record_by_index(
                subwitness["index"], witness_integer_openings["wit_i"]
            )
            hashrecord = get_record_by_index(
                subwitness["index"], hashes_j["wit_i"]
            )

            if (
                not (
                    random_ic_record["di_1"] * (subwitness["di_1"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["di_1"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["di_1"]
                                    + (hash_c * witnessopenrecord["di_1"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["di_2"] * (subwitness["di_2"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["di_2"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["di_2"]
                                    + (hash_c * witnessopenrecord["di_2"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["di_3"] * (subwitness["di_3"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["di_3"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["di_3"]
                                    + (hash_c * witnessopenrecord["di_3"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["di_4"] * (subwitness["di_4"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["di_4"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["di_4"]
                                    + (hash_c * witnessopenrecord["di_4"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["di_5"] * (subwitness["di_5"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["di_5"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["di_5"]
                                    + (hash_c * witnessopenrecord["di_5"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["i"] * (subwitness["i"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["i"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["i"]
                                    + (hash_c * witnessopenrecord["i"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["vr"] * (subwitness["vr"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["vr"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["vr"]
                                    + (hash_c * witnessopenrecord["vr"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["copen_i"]
                    * (subwitness["copen_i"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["copen_i"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["copen_i"]
                                    + (hash_c * witnessopenrecord["copen_i"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
                or not (
                    random_ic_record["copen_ri"]
                    * (subwitness["copen_ri"] ** hash_c)
                    == (
                        (
                            (par_ic["g"] ** hashrecord["copen_ri"])
                            * (
                                par_ic["h"]
                                ** (
                                    random_ic_opening_record["copen_ri"]
                                    + (hash_c * witnessopenrecord["copen_ri"])
                                )
                            )
                        )
                        % self.integer_commitment.n
                    )
                )
            ):
                print(
                    "Abort: (Sigma Protocol) Integer commitment check failed."
                )
                exit()

        return 1

    def prepare_paillier_ciphertexts(self, witness, is_random=0):
        d1, d2, d3, d4, d5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )

        paillier_ciphertexts = ZKWitness()
        d1c = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d1), "utf-8")))
        )
        d2c = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d2), "utf-8")))
        )
        d3c = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d3), "utf-8")))
        )
        d4c = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d4), "utf-8")))
        )
        d5c = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d5), "utf-8")))
        )
        paillier_ciphertexts.set_d(
            d1c,
            d2c,
            d3c,
            d4c,
            d5c,
        )

        for subwitness in witness["wit_i"]:
            #
            [di_1, di_2, di_3, di_4, di_5] = (
                subwitness["di_1"],
                subwitness["di_2"],
                subwitness["di_3"],
                subwitness["di_4"],
                subwitness["di_5"],
            )
            di_1c = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(di_1), "utf-8")))
            )
            di_2c = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(di_2), "utf-8")))
            )
            di_3c = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(di_3), "utf-8")))
            )
            di_4c = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(di_4), "utf-8")))
            )
            di_5c = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(di_5), "utf-8")))
            )
            if is_random:
                ic = self.paillier_encryption.encrypt(
                    self.public_key,
                    integer(SHA256(bytes(str(subwitness["i"]), "utf-8"))),
                )
                vrc = self.paillier_encryption.encrypt(
                    self.public_key,
                    integer(SHA256(bytes(str(subwitness["vr"]), "utf-8"))),
                )

            else:
                ic = self.paillier_encryption.encrypt(
                    self.public_key, integer(subwitness["i"])
                )
                vrc = self.paillier_encryption.encrypt(
                    self.public_key, integer(subwitness["vr"])
                )

            ico = self.paillier_encryption.encrypt(
                self.public_key,
                integer(SHA256(bytes(str(subwitness["copen_i"]), "utf-8"))),
            )
            vrco = self.paillier_encryption.encrypt(
                self.public_key,
                integer(SHA256(bytes(str(subwitness["copen_ri"]), "utf-8"))),
            )
            temp_sw_paillier_ciphertexts = SubWitnessRecord(
                subwitness["index"],
                ic,
                vrc,
                ico,
                vrco,
                di_1c,
                di_2c,
                di_3c,
                di_4c,
                di_5c,
            )
            paillier_ciphertexts.append_subwitnesses(
                temp_sw_paillier_ciphertexts
            )

        return paillier_ciphertexts

    def prepare_integer_commitments(self, witness, is_random=0):
        d1, d2, d3, d4, d5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )

        integer_commitments = ZKWitness()
        integer_openings = ZKWitness()

        d1c = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d1), "utf-8")))
        )
        d2c = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d2), "utf-8")))
        )
        d3c = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d3), "utf-8")))
        )
        d4c = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d4), "utf-8")))
        )
        d5c = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d5), "utf-8")))
        )
        integer_commitments.set_d(
            d1c[0],
            d2c[0],
            d3c[0],
            d4c[0],
            d5c[0],
        )
        integer_openings.set_d(d1c[1], d2c[1], d3c[1], d4c[1], d5c[1])
        for subwitness in witness["wit_i"]:
            #
            [di_1, di_2, di_3, di_4, di_5] = (
                subwitness["di_1"],
                subwitness["di_2"],
                subwitness["di_3"],
                subwitness["di_4"],
                subwitness["di_5"],
            )
            di_1c = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(di_1), "utf-8")))
            )
            di_2c = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(di_2), "utf-8")))
            )
            di_3c = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(di_3), "utf-8")))
            )
            di_4c = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(di_4), "utf-8")))
            )
            di_5c = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(di_5), "utf-8")))
            )
            if is_random:
                ic = self.integer_commitment.commit(
                    self.par_ic,
                    integer(SHA256(bytes(str(subwitness["i"]), "utf-8"))),
                )
                vrc = self.integer_commitment.commit(
                    self.par_ic,
                    integer(SHA256(bytes(str(subwitness["vr"]), "utf-8"))),
                )

            else:
                ic = self.integer_commitment.commit(
                    self.par_ic, integer(subwitness["i"])
                )
                vrc = self.integer_commitment.commit(
                    self.par_ic, integer(subwitness["vr"])
                )

            ico = self.integer_commitment.commit(
                self.par_ic,
                integer(SHA256(bytes(str(subwitness["copen_i"]), "utf-8"))),
            )
            vrco = self.integer_commitment.commit(
                self.par_ic,
                integer(SHA256(bytes(str(subwitness["copen_ri"]), "utf-8"))),
            )
            temp_sw_integer_commitments = SubWitnessRecord(
                subwitness["index"],
                ic[0],
                vrc[0],
                ico[0],
                vrco[0],
                di_1c[0],
                di_2c[0],
                di_3c[0],
                di_4c[0],
                di_5c[0],
            )
            temp_sw_integer_openings = SubWitnessRecord(
                subwitness["index"],
                ic[1],
                vrc[1],
                ico[1],
                vrco[1],
                di_1c[1],
                di_2c[1],
                di_3c[1],
                di_4c[1],
                di_5c[1],
            )
            integer_commitments.append_subwitnesses(
                temp_sw_integer_commitments
            )
            integer_openings.append_subwitnesses(temp_sw_integer_openings)
        return integer_commitments, integer_openings

    def prover_step_2(
        self, random_witness, c, witness, random_ico, witness_ico
    ):
        return self.compute_s(
            random_witness, c, witness, random_ico, witness_ico
        )

    def verifier_step_1(
        self,
    ):
        return pairing_group.random(ZR)

    def verifier_step_2(
        self, s_j, t, c, y, gd, dsa_c, dsa_b, witness_integer_commitments, sid
    ):
        lhs = self.compute_t(dict_from_class(s_j))
        if not (lhs["t1"] == (t["tj"]["t1"] * (y["y1"] ** c))) or not (
            lhs["t2"] == (t["tj"]["t2"] * (y["y2"] ** c))
        ):
            print("Abort: (Sigma Protocol) Verifier step 2 failed.")
            exit()

        for s_i in lhs["t_i"]:
            y_record = get_record_by_index(s_i["index"], y["yl"])
            t_record = get_record_by_index(s_i["index"], t["tj"]["t_i"])
            if (
                not (t_record["t3"] * (y_record["y3"] ** c) == (s_i["t3"]))
                or not (t_record["t4"] * (y_record["y4"] ** c) == s_i["t4"])
                or not (t_record["t5"] * (y_record["y5"] ** c) == s_i["t5"])
                or not (t_record["t6"] * (y_record["y6"] ** c) == s_i["t6"])
                or not (t_record["t7"] * (y_record["y7"] ** c) == s_i["t7"])
            ):
                print("Abort: (Sigma Protocol) Verifier step 2 failed.")
                exit()
        hash_m = SHA256(
            (
                str(y)
                + str(dict_from_class(witness_integer_commitments))
                + str(t)
            ).encode("utf-8")
        )
        dsa_h = (
            self.dsa_keys[0]["g"] ** integer(SHA256(str(sid).encode("utf-8")))
        ) * (self.dsa_keys[0]["y"] ** gd)

        if not (((gd ** dsa_b) * (dsa_h ** integer(hash_m))) == (dsa_c)):
            print("Abort: (Sigma Protocol) DSA check failed.")
            exit()

    def prepare_random_witnesses(self, witness):
        random_witnesses = ZKWitness()
        [r1, r2, r3, r4, r5] = generate_n_random_exponents(5)
        random_witnesses.set_d(r1, r2, r3, r4, r5)
        for subwitness in witness["wit_i"]:
            #
            [
                di_1,
                di_2,
                di_3,
                di_4,
                di_5,
                i,
                vr,
                copen_i,
                copen_ri,
            ] = generate_n_random_exponents(9)
            temp_random_witnesses = SubWitnessRecord(
                subwitness["index"],
                i,
                vr,
                copen_i,
                copen_ri,
                di_1,
                di_2,
                di_3,
                di_4,
                di_5,
            )
            random_witnesses.append_subwitnesses(temp_random_witnesses)
        return random_witnesses

    def compute_t(self, random_witness):

        d1, d2, d3, d4, d5 = (
            random_witness["d1"],
            random_witness["d2"],
            random_witness["d3"],
            random_witness["d4"],
            random_witness["d5"],
        )
        t1 = self.compute_ppe_1(d1, d2, d3, d4, "rhs")
        t2 = self.compute_ppe_2(d1, d5, "rhs")
        t_i = []
        for record in random_witness["wit_i"]:
            t3 = self.compute_ppe_3(
                record["index"], record["i"], record["copen_i"], "rhs"
            )
            t4 = self.compute_ppe_4(
                record["index"], record["vr"], record["copen_ri"], "rhs"
            )
            t5 = self.compute_ppe_5(
                record["index"],
                record["di_1"],
                record["di_2"],
                record["i"],
                "rhs",
            )
            t6 = self.compute_ppe_6(
                record["index"],
                record["di_1"],
                record["di_3"],
                record["di_4"],
                "rhs",
            )
            t7 = self.compute_ppe_7(
                record["index"],
                record["di_4"],
                record["di_5"],
                record["vr"],
                "rhs",
            )
            temp_t_i = {
                "index": record["index"],
                "t3": t3,
                "t4": t4,
                "t5": t5,
                "t6": t6,
                "t7": t7,
            }
            t_i.append(temp_t_i)
        tj = {"t1": t1, "t2": t2, "t_i": t_i}
        return tj

    def prepare_random_integer_commitments(self, random_witness):
        return self.prepare_integer_commitments(random_witness, 1)

    def prepare_random_paillier_ciphertexts(self, random_witness):
        return self.prepare_paillier_ciphertexts(random_witness, 1)
