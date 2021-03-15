"""
SPDX-FileCopyrightText: 2021 University of Luxembourg
SPDX-License-Identifier: GPL-3.0-or-later
SPDXVersion: SPDX-2.2

Authors: 
       Aditya Damodaran, aditya.damodaran@uni.lu
       Alfredo Rial, alfredo.rial@uni.lu
"""

import json
from collections import namedtuple

from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.pairinggroup import PairingGroup, pair, ZR, G2
from charm.toolbox.integergroup import RSAGroup
from charm.core.engine.util import serializeList
from charm.core.math.integer import integer

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


def get_record_by_i(index, list):
    for item in list:
        if item["i"] == index:
            return item


def generate_n_random_exponents(n):
    exponents = []
    for i in range(0, n):
        exponents.append(pairing_group.random(ZR))
    return exponents


def num_to_str(num, length):
    str_num = str(num)
    if len(str_num) < length:
        str_num = "0" * (length - len(str_num)) + str_num

    return str_num


def sign_u(i, g, x):
    return g ** ((x + i) ** -1)


class SigmaProtocol:
    def __init__(self, instance, pairing_group_string, keylength):

        self.r_d, self.s_d, self.t_d = (
            instance["bsig"]["Rd"],
            instance["bsig"]["Sd"],
            instance["bsig"]["Td"],
        )

        public_key = instance["pk"]

        self.v, self.w_1, self.w_2, self.z, self.u_1 = (
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

    def compute_ppe_1(self, d_1, d_2, d_3, d_4, side):
        if side == "lhs":
            return (
                (pair(self.r_d, self.v) ** self.one)
                * (pair(self.s_d, self.gt) ** self.one)
                * (pair(self.vcomd, self.w_1) ** self.one)
                * (pair(self.comd, self.w_2) ** self.one)
                * (pair(self.g, self.z) ** -1)
            )
        else:
            return (
                (pair(self.h, self.v) ** d_1)
                * (pair(self.h, self.gt) ** d_2)
                * (pair(self.g, self.w_1) ** d_3)
                * (pair(self.ped_h, self.w_2) ** d_4)
            )

    def compute_ppe_2(self, d_1, d_5, side):
        if side == "lhs":
            return (
                (pair(self.r_d, self.t_d) ** self.one)
                * (pair(self.u_1, (self.gt ** self.sid)) ** self.one)
                * (pair(self.g, self.gt) ** -1)
                * (pair(self.h, self.ht) ** (d_1 * d_5))
            )
        else:
            return (pair(self.r_d, self.ht) ** d_5) * (
                pair(self.h, self.t_d) ** d_1
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

    def compute_ppe_5(self, index, d_i_1, d_i_2, i, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return (
                (pair(record["sig"]["R_id"], self.v) ** self.one)
                * (pair(record["sig"]["S_id"], self.gt) ** self.one)
                * (pair(self.g ** self.sid, self.w_2) ** self.one)
                * (pair(self.g, self.z) ** -1)
            )
        else:
            return (
                (pair(self.h, self.v) ** d_i_1)
                * (pair(self.h, self.gt) ** d_i_2)
                * (pair(self.g, self.w_1) ** -i)
            )

    def compute_ppe_6(self, index, d_i_1, d_i_3, d_i_4, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return (
                (
                    pair(record["sig"]["R_id"], record["sig"]["T_id"])
                    ** self.one
                )
                * (pair(self.u_1, record["phd_i"]) ** self.one)
                * (pair(self.h, self.ht) ** (d_i_1 * d_i_3))
                * (pair(self.g, self.gt) ** -1)
            )

        else:
            return (
                (pair(record["sig"]["R_id"], self.ht) ** d_i_3)
                * (pair(self.h, record["sig"]["T_id"]) ** d_i_1)
                * (pair(self.u_1, self.ht) ** d_i_4)
            )

    def compute_ppe_7(self, index, d_i_4, d_i_5, vr, side):
        record = get_record_by_index(index, self.instance["ins_i"])
        if side == "lhs":
            return (pair(self.vcomd, record["phd_i"]) ** 1) * (
                pair(record["witd_i"], self.gt) ** -self.one
            )
        else:
            return (
                (pair(self.vcomd, self.ht) ** d_i_4)
                * (pair(self.h, self.gt) ** -d_i_5)
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

    def compute_s(
        self,
        random_witness,
        c,
        witness,
        random_integer_openings,
        witness_integer_openings,
    ):
        s_j = ZKWitness()
        hashes_j = ZKWitness()

        r_1, r_2, r_3, r_4, r_5 = (
            random_witness["d1"],
            random_witness["d2"],
            random_witness["d3"],
            random_witness["d4"],
            random_witness["d5"],
        )
        hash_r_1, hash_r_2, hash_r_3, hash_r_4, hash_r_5 = (
            integer(SHA256(bytes(str(r_1), "utf-8"))),
            integer(SHA256(bytes(str(r_2), "utf-8"))),
            integer(SHA256(bytes(str(r_3), "utf-8"))),
            integer(SHA256(bytes(str(r_4), "utf-8"))),
            integer(SHA256(bytes(str(r_5), "utf-8"))),
        )

        d_1, d_2, d_3, d_4, d_5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )
        hash_d_1, hash_d_2, hash_d_3, hash_d_4, hash_d_5 = (
            integer(SHA256(bytes(str(d_1), "utf-8"))),
            integer(SHA256(bytes(str(d_2), "utf-8"))),
            integer(SHA256(bytes(str(d_3), "utf-8"))),
            integer(SHA256(bytes(str(d_4), "utf-8"))),
            integer(SHA256(bytes(str(d_5), "utf-8"))),
        )

        hash_c = integer(SHA256(bytes(str(c), "utf-8")))

        s_j.set_d(
            r_1 + (c * d_1),
            r_2 + (c * d_2),
            r_3 + (c * d_3),
            r_4 + (c * d_4),
            r_5 + (c * d_5),
        )

        hashes_j.set_d(
            hash_r_1 + (hash_c * hash_d_1),
            hash_r_2 + (hash_c * hash_d_2),
            hash_r_3 + (hash_c * hash_d_3),
            hash_r_4 + (hash_c * hash_d_4),
            hash_r_5 + (hash_c * hash_d_5),
        )

        for subwitness in witness["wit_i"]:
            random_subwitness_record = get_record_by_index(
                subwitness["index"], random_witness["wit_i"]
            )

            d_i_1, d_i_2, d_i_3, d_i_4, d_i_5 = (
                subwitness["di_1"],
                subwitness["di_2"],
                subwitness["di_3"],
                subwitness["di_4"],
                subwitness["di_5"],
            )

            hash_d_i_1, hash_d_i_2, hash_d_i_3, hash_d_i_4, hash_d_i_5 = (
                integer(SHA256(bytes(str(d_i_1), "utf-8"))),
                integer(SHA256(bytes(str(d_i_2), "utf-8"))),
                integer(SHA256(bytes(str(d_i_3), "utf-8"))),
                integer(SHA256(bytes(str(d_i_4), "utf-8"))),
                integer(SHA256(bytes(str(d_i_5), "utf-8"))),
            )

            i, vr, copen_i, copen_ri = (
                subwitness["i"],
                subwitness["vr"],
                subwitness["copen_i"],
                subwitness["copen_ri"],
            )

            hash_i, hash_vr, hash_copen_i, hash_copen_ri = (
                integer(subwitness["i"]),
                integer(subwitness["vr"]),
                integer(SHA256(bytes(str(subwitness["copen_i"]), "utf-8"))),
                integer(SHA256(bytes(str(subwitness["copen_ri"]), "utf-8"))),
            )

            r_i_1, r_i_2, r_i_3, r_i_4, r_i_5 = (
                random_subwitness_record["di_1"],
                random_subwitness_record["di_2"],
                random_subwitness_record["di_3"],
                random_subwitness_record["di_4"],
                random_subwitness_record["di_5"],
            )

            random_i, random_vr, random_copen_i, random_copen_ri = (
                random_subwitness_record["i"],
                random_subwitness_record["vr"],
                random_subwitness_record["copen_i"],
                random_subwitness_record["copen_ri"],
            )

            hash_r_i_1, hash_r_i_2, hash_r_i_3, hash_r_i_4, hash_r_i_5 = (
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

            (
                hash_random_i,
                hash_random_vr,
                hash_random_copen_i,
                hash_random_copen_ri,
            ) = (
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
                random_i + (c * i),
                random_vr + (c * vr),
                random_copen_i + (c * copen_i),
                random_copen_ri + (c * copen_ri),
                r_i_1 + (c * d_i_1),
                r_i_2 + (c * d_i_2),
                r_i_3 + (c * d_i_3),
                r_i_4 + (c * d_i_4),
                r_i_5 + (c * d_i_5),
            )

            temp_hashes_j_i = SubWitnessRecord(
                subwitness["index"],
                hash_random_i + (hash_c * hash_i),
                hash_random_vr + (hash_c * hash_vr),
                hash_random_copen_i + (hash_c * hash_copen_i),
                hash_random_copen_ri + (hash_c * hash_copen_ri),
                hash_r_i_1 + (hash_c * hash_d_i_1),
                hash_r_i_2 + (hash_c * hash_d_i_2),
                hash_r_i_3 + (hash_c * hash_d_i_3),
                hash_r_i_4 + (hash_c * hash_d_i_4),
                hash_r_i_5 + (hash_c * hash_d_i_5),
            )

            s_j.append_subwitnesses(temp_s_j_i)
            hashes_j.append_subwitnesses(temp_hashes_j_i)

        s_o_j = ZKWitness()

        (
            random_opening_1,
            random_opening_2,
            random_opening_3,
            random_opening_4,
            random_opening_5,
        ) = (
            random_integer_openings["d1"],
            random_integer_openings["d2"],
            random_integer_openings["d3"],
            random_integer_openings["d4"],
            random_integer_openings["d5"],
        )
        opening_1, opening_2, opening_3, opening_4, opening_5 = (
            witness_integer_openings["d1"],
            witness_integer_openings["d2"],
            witness_integer_openings["d3"],
            witness_integer_openings["d4"],
            witness_integer_openings["d5"],
        )

        s_o_j.set_d(
            random_opening_1 + (hash_c * opening_1),
            random_opening_2 + (hash_c * opening_2),
            random_opening_3 + (hash_c * opening_3),
            random_opening_4 + (hash_c * opening_4),
            random_opening_5 + (hash_c * opening_5),
        )

        for subwitness_integer_opening_record in witness_integer_openings[
            "wit_i"
        ]:
            random_integer_opening_record = get_record_by_index(
                subwitness_integer_opening_record["index"],
                random_integer_openings["wit_i"],
            )

            d_i_1, d_i_2, d_i_3, d_i_4, d_i_5 = (
                subwitness_integer_opening_record["di_1"],
                subwitness_integer_opening_record["di_2"],
                subwitness_integer_opening_record["di_3"],
                subwitness_integer_opening_record["di_4"],
                subwitness_integer_opening_record["di_5"],
            )

            i, vr, copen_i, copen_ri = (
                subwitness_integer_opening_record["i"],
                subwitness_integer_opening_record["vr"],
                subwitness_integer_opening_record["copen_i"],
                subwitness_integer_opening_record["copen_ri"],
            )

            r_i_1, r_i_2, r_i_3, r_i_4, r_i_5 = (
                random_integer_opening_record["di_1"],
                random_integer_opening_record["di_2"],
                random_integer_opening_record["di_3"],
                random_integer_opening_record["di_4"],
                random_integer_opening_record["di_5"],
            )

            random_i, random_vr, random_copen_i, random_copen_ri = (
                random_integer_opening_record["i"],
                random_integer_opening_record["vr"],
                random_integer_opening_record["copen_i"],
                random_integer_opening_record["copen_ri"],
            )

            temp_s_j_i = SubWitnessRecord(
                subwitness_integer_opening_record["index"],
                random_i + (hash_c * i),
                random_vr + (hash_c * vr),
                random_copen_i + (hash_c * copen_i),
                random_copen_ri + (hash_c * copen_ri),
                r_i_1 + (hash_c * d_i_1),
                r_i_2 + (hash_c * d_i_2),
                r_i_3 + (hash_c * d_i_3),
                r_i_4 + (hash_c * d_i_4),
                r_i_5 + (hash_c * d_i_5),
            )
            s_o_j.append_subwitnesses(temp_s_j_i)

        return s_j, hashes_j, hash_c

    def pe_check(
        self,
        index,
        hashes_j,
        random_paillier_ciphertexts,
        witness_paillier_ciphertexts,
        hash_c,
    ):
        g, n, n2 = (
            self.public_key["g"],
            self.public_key["n"],
            self.public_key["n2"],
        )
        temp_paillier_ciphertext = {
            "c": random_paillier_ciphertexts[index][0]["c"]
            * (witness_paillier_ciphertexts[index][0]["c"] ** hash_c)
        }
        return (temp_paillier_ciphertext["c"] % n2) == (
            (
                ((g % n2) ** (hashes_j[index]))
                * (
                    (
                        random_paillier_ciphertexts[index][1]
                        * (witness_paillier_ciphertexts[index][1] ** hash_c)
                        % n2
                    )
                    ** n
                )
            )
            % n2
        )

    def pe_sub_check(
        self,
        subindex,
        index,
        hashes_j,
        random_paillier_ciphertexts,
        witness_paillier_ciphertexts,
        hash_c,
    ):

        g, n, n2 = (
            self.public_key["g"],
            self.public_key["n"],
            self.public_key["n2"],
        )

        random_ciphertext_record = get_record_by_index(
            subindex, random_paillier_ciphertexts["wit_i"]
        )
        witness_ciphertext_record = get_record_by_index(
            subindex, witness_paillier_ciphertexts["wit_i"]
        )
        hash_record = get_record_by_index(subindex, hashes_j["wit_i"])
        temp_paillier_ciphertext = {
            "c": random_ciphertext_record[index][0]["c"]
            * (witness_ciphertext_record[index][0]["c"] ** hash_c)
        }
        return (temp_paillier_ciphertext["c"] % n2) == (
            (
                ((g % n2) ** (hash_record[index]))
                * (
                    (
                        random_ciphertext_record[index][1]
                        * (witness_ciphertext_record[index][1] ** hash_c)
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
        d_1, d_2, d_3, d_4, d_5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )

        paillier_ciphertexts = ZKWitness()
        ciphertext_d_1 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d_1), "utf-8")))
        )
        ciphertext_d_2 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d_2), "utf-8")))
        )
        ciphertext_d_3 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d_3), "utf-8")))
        )
        ciphertext_d_4 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d_4), "utf-8")))
        )
        ciphertext_d_5 = self.paillier_encryption.encrypt(
            self.public_key, integer(SHA256(bytes(str(d_5), "utf-8")))
        )
        paillier_ciphertexts.set_d(
            ciphertext_d_1,
            ciphertext_d_2,
            ciphertext_d_3,
            ciphertext_d_4,
            ciphertext_d_5,
        )

        for subwitness in witness["wit_i"]:
            #
            [d_i_1, d_i_2, d_i_3, d_i_4, d_i_5] = (
                subwitness["di_1"],
                subwitness["di_2"],
                subwitness["di_3"],
                subwitness["di_4"],
                subwitness["di_5"],
            )
            ciphertext_d_i_1 = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(d_i_1), "utf-8")))
            )
            ciphertext_d_i_2 = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(d_i_2), "utf-8")))
            )
            ciphertext_d_i_3 = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(d_i_3), "utf-8")))
            )
            ciphertext_d_i_4 = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(d_i_4), "utf-8")))
            )
            ciphertext_d_i_5 = self.paillier_encryption.encrypt(
                self.public_key, integer(SHA256(bytes(str(d_i_5), "utf-8")))
            )
            if is_random:
                ciphertext_i = self.paillier_encryption.encrypt(
                    self.public_key,
                    integer(SHA256(bytes(str(subwitness["i"]), "utf-8"))),
                )
                ciphertext_vr = self.paillier_encryption.encrypt(
                    self.public_key,
                    integer(SHA256(bytes(str(subwitness["vr"]), "utf-8"))),
                )

            else:
                ciphertext_i = self.paillier_encryption.encrypt(
                    self.public_key, integer(subwitness["i"])
                )
                ciphertext_vr = self.paillier_encryption.encrypt(
                    self.public_key, integer(subwitness["vr"])
                )

            ciphertext_copen_i = self.paillier_encryption.encrypt(
                self.public_key,
                integer(SHA256(bytes(str(subwitness["copen_i"]), "utf-8"))),
            )
            ciphertext_copen_ri = self.paillier_encryption.encrypt(
                self.public_key,
                integer(SHA256(bytes(str(subwitness["copen_ri"]), "utf-8"))),
            )
            temp_sw_paillier_ciphertexts = SubWitnessRecord(
                subwitness["index"],
                ciphertext_i,
                ciphertext_vr,
                ciphertext_copen_i,
                ciphertext_copen_ri,
                ciphertext_d_i_1,
                ciphertext_d_i_2,
                ciphertext_d_i_3,
                ciphertext_d_i_4,
                ciphertext_d_i_5,
            )
            paillier_ciphertexts.append_subwitnesses(
                temp_sw_paillier_ciphertexts
            )

        return paillier_ciphertexts

    def prepare_integer_commitments(self, witness, is_random=0):
        d_1, d_2, d_3, d_4, d_5 = (
            witness["d1"],
            witness["d2"],
            witness["d3"],
            witness["d4"],
            witness["d5"],
        )

        integer_commitments = ZKWitness()
        integer_openings = ZKWitness()

        commitment_d_1 = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d_1), "utf-8")))
        )
        commitment_d_2 = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d_2), "utf-8")))
        )
        commitment_d_3 = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d_3), "utf-8")))
        )
        commitment_d_4 = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d_4), "utf-8")))
        )
        commitment_d_5 = self.integer_commitment.commit(
            self.par_ic, integer(SHA256(bytes(str(d_5), "utf-8")))
        )

        integer_commitments.set_d(
            commitment_d_1[0],
            commitment_d_2[0],
            commitment_d_3[0],
            commitment_d_4[0],
            commitment_d_5[0],
        )

        integer_openings.set_d(
            commitment_d_1[1],
            commitment_d_2[1],
            commitment_d_3[1],
            commitment_d_4[1],
            commitment_d_5[1],
        )
        for subwitness in witness["wit_i"]:
            #
            [d_i_1, d_i_2, d_i_3, d_i_4, d_i_5] = (
                subwitness["di_1"],
                subwitness["di_2"],
                subwitness["di_3"],
                subwitness["di_4"],
                subwitness["di_5"],
            )
            commitment_d_i_1 = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(d_i_1), "utf-8")))
            )
            commitment_d_i_2 = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(d_i_2), "utf-8")))
            )
            commitment_d_i_3 = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(d_i_3), "utf-8")))
            )
            commitment_d_i_4 = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(d_i_4), "utf-8")))
            )
            commitment_d_i_5 = self.integer_commitment.commit(
                self.par_ic, integer(SHA256(bytes(str(d_i_5), "utf-8")))
            )
            if is_random:
                commitment_i = self.integer_commitment.commit(
                    self.par_ic,
                    integer(SHA256(bytes(str(subwitness["i"]), "utf-8"))),
                )
                commitment_vr = self.integer_commitment.commit(
                    self.par_ic,
                    integer(SHA256(bytes(str(subwitness["vr"]), "utf-8"))),
                )

            else:
                commitment_i = self.integer_commitment.commit(
                    self.par_ic, integer(subwitness["i"])
                )
                commitment_vr = self.integer_commitment.commit(
                    self.par_ic, integer(subwitness["vr"])
                )

            commitment_copen_i = self.integer_commitment.commit(
                self.par_ic,
                integer(SHA256(bytes(str(subwitness["copen_i"]), "utf-8"))),
            )
            commitment_copen_ri = self.integer_commitment.commit(
                self.par_ic,
                integer(SHA256(bytes(str(subwitness["copen_ri"]), "utf-8"))),
            )

            temp_sw_integer_commitments = SubWitnessRecord(
                subwitness["index"],
                commitment_i[0],
                commitment_vr[0],
                commitment_copen_i[0],
                commitment_copen_ri[0],
                commitment_d_i_1[0],
                commitment_d_i_2[0],
                commitment_d_i_3[0],
                commitment_d_i_4[0],
                commitment_d_i_5[0],
            )

            temp_sw_integer_openings = SubWitnessRecord(
                subwitness["index"],
                commitment_i[1],
                commitment_vr[1],
                commitment_copen_i[1],
                commitment_copen_ri[1],
                commitment_d_i_1[1],
                commitment_d_i_2[1],
                commitment_d_i_3[1],
                commitment_d_i_4[1],
                commitment_d_i_5[1],
            )

            integer_commitments.append_subwitnesses(
                temp_sw_integer_commitments
            )
            integer_openings.append_subwitnesses(temp_sw_integer_openings)
        return integer_commitments, integer_openings

    def prover_step_2(
        self,
        random_witness,
        c,
        witness,
        random_integer_openings,
        witness_integer_openings,
    ):
        return self.compute_s(
            random_witness,
            c,
            witness,
            random_integer_openings,
            witness_integer_openings,
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
        [r_1, r_2, r_3, r_4, r_5] = generate_n_random_exponents(5)
        random_witnesses.set_d(r_1, r_2, r_3, r_4, r_5)
        for subwitness in witness["wit_i"]:
            #
            [
                d_i_1,
                d_i_2,
                d_i_3,
                d_i_4,
                d_i_5,
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
                d_i_1,
                d_i_2,
                d_i_3,
                d_i_4,
                d_i_5,
            )
            random_witnesses.append_subwitnesses(temp_random_witnesses)
        return random_witnesses

    def compute_t(self, random_witness):

        d_1, d_2, d_3, d_4, d_5 = (
            random_witness["d1"],
            random_witness["d2"],
            random_witness["d3"],
            random_witness["d4"],
            random_witness["d5"],
        )
        t_1 = self.compute_ppe_1(d_1, d_2, d_3, d_4, "rhs")
        t_2 = self.compute_ppe_2(d_1, d_5, "rhs")
        t_i = []
        for record in random_witness["wit_i"]:
            t_3 = self.compute_ppe_3(
                record["index"], record["i"], record["copen_i"], "rhs"
            )
            t_4 = self.compute_ppe_4(
                record["index"], record["vr"], record["copen_ri"], "rhs"
            )
            t_5 = self.compute_ppe_5(
                record["index"],
                record["di_1"],
                record["di_2"],
                record["i"],
                "rhs",
            )
            t_6 = self.compute_ppe_6(
                record["index"],
                record["di_1"],
                record["di_3"],
                record["di_4"],
                "rhs",
            )
            t_7 = self.compute_ppe_7(
                record["index"],
                record["di_4"],
                record["di_5"],
                record["vr"],
                "rhs",
            )
            temp_t_i = {
                "index": record["index"],
                "t3": t_3,
                "t4": t_4,
                "t5": t_5,
                "t6": t_6,
                "t7": t_7,
            }
            t_i.append(temp_t_i)

        return {"t1": t_1, "t2": t_2, "t_i": t_i}

    def prepare_random_integer_commitments(self, random_witness):
        return self.prepare_integer_commitments(random_witness, 1)

    def prepare_random_paillier_ciphertexts(self, random_witness):
        return self.prepare_paillier_ciphertexts(random_witness, 1)

    def range_proof(value, commitment, opening, limit, ped_g, ped_h, group):
        # Verifier picks x rand
        x = group.random(ZR)
        y = ped_h ** x
        u_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        a_i = [
            sign_u(0, ped_g, x),
            sign_u(1, ped_g, x),
            sign_u(2, ped_g, x),
            sign_u(3, ped_g, x),
            sign_u(4, ped_g, x),
            sign_u(5, ped_g, x),
            sign_u(6, ped_g, x),
            sign_u(7, ped_g, x),
            sign_u(8, ped_g, x),
            sign_u(9, ped_g, x),
        ]
        str_num = num_to_str(value, 4)

        # Verifier selects V_j at random
        v_0 = group.random(ZR)
        v_1 = group.random(ZR)
        v_2 = group.random(ZR)
        v_3 = group.random(ZR)

        v_j = [
            a_i[int(str_num[3])] ** v_0,
            a_i[int(str_num[2])] ** v_1,
            a_i[int(str_num[1])] ** v_2,
            a_i[int(str_num[0])] ** v_3,
        ]

        # v_j = [a_i[0]**v0,a_i[0]**v1,a_i[1]**v2,a_i[0]**v3]

        # Prover
        s_0 = group.random(ZR)
        t_0 = group.random(ZR)
        m_0 = group.random(ZR)

        s_1 = group.random(ZR)
        t_1 = group.random(ZR)
        m_1 = group.random(ZR)

        s_2 = group.random(ZR)
        t_2 = group.random(ZR)
        m_2 = group.random(ZR)

        s_3 = group.random(ZR)
        t_3 = group.random(ZR)
        m_3 = group.random(ZR)

        gt = group.random(G2)

        a_0 = (pair(v_j[0], gt) ** (-s_0)) * (pair(ped_g, gt) ** t_0)
        a_1 = (pair(v_j[1], gt) ** (-s_1)) * (pair(ped_g, gt) ** t_1)
        a_2 = (pair(v_j[2], gt) ** (-s_2)) * (pair(ped_g, gt) ** t_2)
        a_3 = (pair(v_j[3], gt) ** (-s_3)) * (pair(ped_g, gt) ** t_3)

        d = (
            ((ped_g ** ((10 ** 0) * s_0)) * (ped_h ** m_0))
            * ((ped_g ** ((10 ** 1) * s_1)) * (ped_h ** m_1))
            * ((ped_g ** ((10 ** 2) * s_2)) * (ped_h ** m_2))
            * ((ped_g ** ((10 ** 3) * s_3)) * (ped_h ** m_3))
        )

        # Verifier picks a random challenge c
        c = group.random(ZR)

        # Prover does the following
        z_s_0 = s_0 - (int(str_num[3]) * c)
        z_v_0 = t_0 - (v_0 * c)
        z_r_0 = m_0 - (opening * c)

        z_s_1 = s_1 - (int(str_num[2]) * c)
        z_v_1 = t_1 - (v_1 * c)
        z_r_1 = m_1 - (opening * c)

        z_s_2 = s_2 - (int(str_num[1]) * c)
        z_v_2 = t_2 - (v_2 * c)
        z_r_2 = m_2 - (opening * c)

        z_s_3 = s_3 - (int(str_num[0]) * c)
        z_v_3 = t_3 - (v_3 * c)
        z_r_3 = m_3 - (opening * c)
        y = gt ** x
        z_r = (m_0 + m_1 + m_2 + m_3) - (opening * c)
        if not (
            a_0
            == (pair(v_j[0], y) ** c)
            * (pair(v_j[0], gt) ** -z_s_0)
            * (pair(ped_g, gt) ** z_v_0)
        ):
            print("Abort: (FZK_PR) A0 check failed.")
        if not (
            a_1
            == (pair(v_j[1], y) ** c)
            * (pair(v_j[1], gt) ** -z_s_1)
            * (pair(ped_g, gt) ** z_v_1)
        ):
            print("Abort: (FZK_PR) A1 check failed.")
        if not (
            a_2
            == (pair(v_j[2], y) ** c)
            * (pair(v_j[2], gt) ** -z_s_2)
            * (pair(ped_g, gt) ** z_v_2)
        ):
            print("Abort: (FZK_PR) A2 check failed.")
        if not (
            a_3
            == (pair(v_j[3], y) ** c)
            * (pair(v_j[3], gt) ** -z_s_3)
            * (pair(ped_g, gt) ** z_v_3)
        ):
            print("Abort: (FZK_PR) A3 check failed.")
        if not (
            d
            == (commitment ** c)
            * (~(ped_g ** (limit * c)))
            * (ped_h ** (z_r))
            * ((ped_g ** ((10 ** 0) * z_s_0)))
            * ((ped_g ** ((10 ** 1) * z_s_1)))
            * ((ped_g ** ((10 ** 2) * z_s_2)))
            * ((ped_g ** ((10 ** 3) * z_s_3)))
        ):
            print("Abort: (FZK_PR) D check failed.")
        return c, y
